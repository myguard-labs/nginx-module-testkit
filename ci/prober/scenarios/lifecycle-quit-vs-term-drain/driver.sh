#!/usr/bin/env bash
#
# Scenario: L-1 remainder (b) -- graceful QUIT vs fast TERM, contrasted
# around the SAME setup: a request actively in flight when the signal lands.
#
# THE CONTRAST IS THE POINT. lifecycle-journal (PR #238) already proves QUIT
# and TERM both eventually emit the SAME terminal journal record ("exiting"),
# by two different log paths in the traced binary -- but it never puts a
# request in flight while either signal is delivered, so it cannot show what
# happens to that request. This scenario adds exactly that: the same slow
# upload, in flight, under each signal in turn, and asks the one question
# lifecycle-journal cannot answer -- does the terminal journal event happen
# BEFORE or AFTER the in-flight work finishes.
#
#   QUIT  (graceful): drains. The upload's own response must arrive, and only
#         THEN does the worker's terminal journal event get emitted -- so
#         reading the two off the SAME journal (see the ordering oracle
#         below), request-done comes strictly before signal-done.
#   TERM  (fast/immediate shutdown, ngx_process_cycle.c's `ngx_terminate`
#         path -- see lifecycle-journal's own header comment on why this is a
#         genuinely different code path from QUIT's, not just a different
#         signal number): does not wait. The stalled upload is cut off
#         (its connection is torn down, so `cat` on that socket sees a
#         non-graceful end rather than a completed 200) and the worker's
#         terminal event lands without ever waiting on it.
#
# WHY A DRIVER AND NOT A .rule FILE: same reason as lifecycle-journal and
# reload-worker-shutdown-timeout -- this proof spans a signal delivered to a
# live master while a separate backgrounded connection is held open on the
# wire, with a journal read back across the boundary. None of that fits the
# prober's synchronous single-request model.
#
# THE ORDERING ORACLE. Both legs read the SAME lifecycle journal
# prober_journal_start (lib.sh, shared with lifecycle-journal) already
# produces -- a strictly increasing, contiguous "seq" per event. This driver:
#   1. drains the journal's seq counter to a per-phase BASELINE (the ready
#      handshake record already establishes the watcher is live and reading);
#   2. records the seq of the upload's OWN completion (success for QUIT,
#      failure/cutoff for TERM) by taking a fresh read of the journal
#      from INSIDE the upload client, the instant it has the whole response
#      in hand -- i.e. "how many journal lines existed when the client
#      observed its request complete". Sampling after the foreground `wait`
#      instead would be racy: `wait` returns only once the subshell has
#      exited, and the worker's terminal record is emitted as a consequence
#      of this same drain, so it can land inside that window and red a
#      correctly-draining QUIT;
#   3. polls for the worker's terminal record and reads ITS seq.
# QUIT's claim is `upload_seq < terminal_seq` (the upload's own finish
# happened-before the journal saw the worker's terminal event). TERM's claim
# is the same journal, opposite requirement: the terminal record must NOT be
# gated behind the upload finishing -- proven by requiring the upload to be
# CUT OFF (never reaches a clean 200) rather than by a seq race, because a
# fast worker could in principle still answer a slow client before it dies;
# the only way to positively distinguish "did not wait" from "was lucky" is
# to observe the connection actually die non-gracefully.
#
# NEGATIVE CONTROL BY CONSTRUCTION: the QUIT leg's own ordering assertion is
# vacuous unless the upload is proven to still be IN FLIGHT (kill -0 alive)
# immediately before the signal is sent -- reload-mid-upload's own liveness
# gate, reused here verbatim for the same reason (see its header). Without
# that gate, an upload that had already finished before QUIT was even sent
# would trivially satisfy "upload finished before the terminal record" for
# the wrong reason.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

# See lifecycle-journal's own driver.sh comment: this scenario also calls
# prober_boot a second time from inside driver.sh (a separate process from
# run-scenario.sh), so the env file's PROBER_DAEMON_MODE=on -- sourced only
# into run-scenario.sh's OWN shell -- needs to be visible here too, or the
# second boot silently falls back to $!-based tracking and the very next
# liveness check reports a false "server failed to start".
export PROBER_DAEMON_MODE=on

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
JOURNAL="$PROBER_PREFIX/lifecycle.jsonl"
PIDFILE="$PROBER_PREFIX/nginx.pid"

trap 'prober_journal_stop || true' EXIT

FAILED=0

read_pidfile() {
    [ -s "$PIDFILE" ] || return 0
    local p
    p="$( { tr -d '[:space:]' <"$PIDFILE"; } 2>/dev/null )"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
    return 0
}

wait_master_gone() {
    local pid="$1" n="$2" i
    for ((i = 0; i < n; i++)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.05
    done
    return 1
}

wait_journal_lines() {   # $1 = pattern (grep -E), $2 = timeout steps of 50ms
    local pattern="$1" n="$2" i
    for ((i = 0; i < n; i++)); do
        [ -s "$JOURNAL" ] && grep -qE "$pattern" "$JOURNAL" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# seq_of_line N -- the "seq" field of the Nth journal line, or empty.
seq_of_line() {
    local n="$1"
    sed -n "${n}p" "$JOURNAL" 2>/dev/null | sed -nE 's/.*"seq":([0-9]+).*/\1/p'
}

wait_port_free() {
    local i
    for ((i = 0; i < 100; i++)); do
        prober_port_owner_pids 127.0.0.1 "$PORT" >/dev/null 2>&1 || return 0
        sleep 0.05
    done
    return 1
}

start_phase() {
    local reboot="${1:-0}"
    if [ "$reboot" = "1" ]; then
        prober_normalize_timeout_scale
        prober_boot
    fi
    prober_journal_start "$ELOG" "$JOURNAL"
}

stop_phase() {
    local m="${1:-}"
    prober_stop
    if [ -n "$m" ]; then
        wait_journal_lines "\"role\":\"master\",\"pid\":$m,\"gen\":[0-9]+,\"ev\":\"exit\"" 60 || true
    fi
    prober_journal_stop
    wait_port_free || true
}

# --- slow-upload helper (reload-mid-upload's own idiom, reused verbatim) --
# Content-Length is FIXED and every byte is eventually written (unless the
# peer kills the connection first) -- a short body would hang the driver, not
# just the request. Output (the raw HTTP response, if any) lands in $2; the
# backgrounded pid is handed back through the out-param $3, never via command
# substitution (see reload-mid-upload/driver.sh's header for why command
# substitution breaks `wait`/`kill -0` addressability here).
BODY="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0123456789abcdefghij"   # 200 bytes
BODY_LEN=${#BODY}
CHUNK=4

# $4 (optional) -- a "done stamp" path, and $5 the terminal-record regex to
# look for. The INSTANT the response bytes are in hand, and before the
# subshell tears down, the client records whether the worker's terminal
# record was ALREADY in the journal: "seen" or "absent".
#
# Deliberately a boolean about that one event, not a line count. A count is
# not race-free no matter how early it is sampled -- between `cat` returning
# and the sampling command being scheduled, the terminal record can land, and
# a count that absorbs it reds a correctly-draining QUIT. The question the
# oracle actually asks is only "had the worker already terminated when the
# upload completed?", so recording the answer to THAT question is immune:
# a terminal record written after the grep is exactly the ordering the test
# wants to pass, and it can no longer perturb the recorded value.
start_upload() {
    local step_sleep=$1 out=$2 pidvar=$3 stamp=${4:-} termre=${5:-}
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1

        # The reader runs CONCURRENTLY with the writes, not after them.
        # Sequencing it after the drip loop makes the response file's
        # emptiness ambiguous: if the server answers early and closes -- a
        # 502, say -- while the body is still being dripped, the next
        # `printf >&3` takes SIGPIPE and kills this subshell before any read
        # happens, leaving the file empty. Assertion 6 reads empty as "the
        # connection was torn down", so a server that ANSWERED would be
        # recorded as a cutoff: the exact false pass that assertion exists to
        # exclude. Measured: against a server replying 502 mid-upload, the
        # sequential form exits 141 (SIGPIPE) with a 0-byte file, identical
        # to a genuine cutoff. Reading in parallel makes the file hold
        # whatever the server actually sent, whenever it sent it, so
        # emptiness means only one thing.
        timeout 45 cat <&3 >&1 2>/dev/null &
        reader=$!

        # SIGPIPE must not kill this subshell before the reader is joined:
        # the write failing is expected in the TERM leg and is not itself the
        # observation. Ignoring it lets the failed write fall through to the
        # wait below, which is what preserves the response.
        trap '' PIPE

        printf 'POST /upload HTTP/1.1\r\nHost: prober\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' \
            "$BODY_LEN" >&3 2>/dev/null || true

        off=0
        while [ "$off" -lt "$BODY_LEN" ]; do
            len=$CHUNK
            remaining=$((BODY_LEN - off))
            [ "$len" -gt "$remaining" ] && len=$remaining

            # THE ORDERING SAMPLE, taken immediately before the FINAL body
            # chunk -- the last moment at which the worker is provably still
            # mid-request.
            #
            # Read the ERROR LOG, never $JOURNAL. The journal is transcribed
            # from this same log by an asynchronous `tail -F` watcher subshell
            # (lib.sh, prober_journal_start), so a record can be absent from
            # the journal purely because the watcher has not been scheduled
            # yet, while nginx has already written it. That artefact would
            # make this assertion falsely GREEN. nginx writes the log itself,
            # synchronously and in order.
            #
            # The POSITION is what makes the ordering sound, and both later
            # positions are races. Sampling after `cat` returns races the
            # worker's shutdown path directly -- measured landing in the same
            # second as the grep. Sampling after the final write but before
            # the read is also a race: the response here is 9 bytes, so nginx
            # can push it entirely into the socket buffer, finish the request
            # and drop its connection count to zero without the client ever
            # reading, and exit before the sample runs.
            #
            # Here, $CHUNK bytes of the declared Content-Length are still
            # unsent. The worker cannot have finished the request, because it
            # is still waiting on body bytes that have not been written; with
            # a connection outstanding it cannot reach its exit path at all.
            # The absence is therefore forced by the property under test
            # rather than sampled against a race. A worker that abandoned the
            # request instead -- the failure this exists to catch -- has
            # already dropped the connection and logged its exit, so this
            # still reads "seen".
            if [ -n "$stamp" ] && [ "$((off + len))" -ge "$BODY_LEN" ]; then
                if [ -n "$termre" ] && grep -qE "$termre" "$ELOG" 2>/dev/null; then
                    printf 'seen\n' >"$stamp" 2>/dev/null || true
                else
                    printf 'absent\n' >"$stamp" 2>/dev/null || true
                fi
            fi

            printf '%s' "${BODY:$off:$len}" >&3 2>/dev/null || break
            off=$((off + len))
            if [ "$off" -lt "$BODY_LEN" ] && [ "$step_sleep" != 0 ]; then
                sleep "$step_sleep"
            fi
        done

        # Half-close the write side so a drained server sees the body end
        # and can finish its response, then join the reader. The reader
        # carries the 45s bound (worker_shutdown_timeout is 30s and a
        # legitimate drain finishes in ~7.5s of drip), so a worker that never
        # completes reds here instead of hanging: run-scenario.sh imposes no
        # timeout of its own, and an unbounded read would make the very
        # regression this driver detects unreachable.
        exec 3>&-
        wait "$reader" 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    printf -v "$pidvar" '%s' "$!"
}

# STEP_SLEEP sized against worker_shutdown_timeout (30s in nginx.conf), not
# against the signal-delivery instant: the QUIT leg needs the upload to still
# be mid-drip when the signal is sent (so the settle gate below has margin
# under a loaded runner -- the fixed-step-count lesson from mem_22d90a4d,
# already applied by reload-mid-upload's own 60B->200B widening) while
# finishing comfortably inside worker_shutdown_timeout so QUIT's drain is
# what completes it, never the shutdown timer force-closing it -- a
# timer-forced close would look identical to TERM's cutoff and destroy the
# contrast. 200B/4B-per-write * 0.15s = ~7.5s total drip: several times the
# settle window below, and well under the 30s ceiling.
STEP_SLEEP=0.15

echo "1..8"

# ================= PHASE A: QUIT drains the in-flight request =============
start_phase 0
WPID_Q=""
for ((i = 0; i < 100; i++)); do
    body="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID_Q="$(prober_probe_field "$body" pid 2>/dev/null || true)"
    [ -n "$WPID_Q" ] && break
    sleep 0.05
done
MASTER_Q="$(read_pidfile)"
if [ -z "$WPID_Q" ] || [ -z "$MASTER_Q" ]; then
    echo "Bail out! phase QUIT never got a live worker/master pid to target"
    exit 1
fi

UPLOAD_Q_OUT="$PROBER_PREFIX/upload-quit.out"
UPLOAD_Q_STAMP="$PROBER_PREFIX/upload-quit.stamp"
rm -f "$UPLOAD_Q_STAMP"
# The QUIT worker's terminal record, pinned to the pid resolved above. Defined
# ONCE and reused by both readers -- the client's completion stamp below and
# the ordering oracle's own lookup. The two must ask about the SAME record or
# the ordering claim compares a stamp about one event against a line number
# from another, which no assertion here would notice.
TERM_RE_Q="\"role\":\"worker\",\"pid\":$WPID_Q,\"gen\":[0-9]+,\"ev\":\"exiting\""

# The SAME terminal event as TERM_RE_Q, matched in nginx's own error_log
# rather than in the transcribed journal. The log line is what the watcher
# parses into that journal record (lib.sh keys on the anchored shape
# "<pid>#<slot>: exiting"), so the two name one event; only the surface and
# therefore the delivery guarantee differ. The client stamp uses THIS one
# because only the log is written synchronously by nginx -- see start_upload.
TERM_LOG_RE_Q="$WPID_Q#[0-9]+: exiting$"
start_upload "$STEP_SLEEP" "$UPLOAD_Q_OUT" UPLOAD_Q_PID "$UPLOAD_Q_STAMP" "$TERM_LOG_RE_Q"

# In-flight liveness gate (reload-mid-upload's own idiom): the ordering claim
# below is vacuous unless the upload was genuinely still open when QUIT was
# sent.
alive=0
for ((i = 0; i < 20; i++)); do   # 20 * 50ms = 1s settle, well under the ~7.5s drip
    if kill -0 "$UPLOAD_Q_PID" 2>/dev/null; then alive=1; else alive=0; break; fi
    sleep 0.05
done
if [ "$alive" -eq 1 ] && kill -0 "$UPLOAD_Q_PID" 2>/dev/null; then
    echo "ok 1 - QUIT leg: the upload was still in flight immediately before the signal"
else
    echo "not ok 1 - QUIT leg: the upload was not in flight before the signal; the ordering claim below would be vacuous"
    echo "# LIFECYCLE-DRAIN-RED-QUIT-NOT-INFLIGHT"
    FAILED=$((FAILED + 1))
fi


kill -QUIT "$MASTER_Q" 2>/dev/null || true

# Join the upload: for QUIT this MUST return with a clean 200, because the
# draining worker keeps reading the stalled body rather than abandoning it.
# The subshell bounds its own read (see start_upload), so this `wait` cannot
# outlast that ceiling even if the worker never completes the response.
wait "$UPLOAD_Q_PID" 2>/dev/null || true
UPLOAD_TERM_SEEN_Q="$( { tr -d '[:space:]' <"$UPLOAD_Q_STAMP"; } 2>/dev/null )" || UPLOAD_TERM_SEEN_Q=""

if grep -q '^HTTP/1\.1 200' "$UPLOAD_Q_OUT" 2>/dev/null && grep -q 'UPLOADED' "$UPLOAD_Q_OUT" 2>/dev/null; then
    echo "ok 2 - QUIT leg: the in-flight upload completed with a clean 200 (drained, not dropped)"
else
    echo "not ok 2 - QUIT leg: the in-flight upload did not complete cleanly after QUIT"
    echo "# LIFECYCLE-DRAIN-RED-QUIT-NOT-DRAINED"
    sed 's/^/# /' "$UPLOAD_Q_OUT" 2>/dev/null || true
    FAILED=$((FAILED + 1))
fi

wait_master_gone "$MASTER_Q" 200 || true

if wait_journal_lines "$TERM_RE_Q" 100; then
    TERM_LINE_Q="$(grep -nE "$TERM_RE_Q" "$JOURNAL" | tail -1 | cut -d: -f1)"
    TERM_SEQ_Q="$(seq_of_line "$TERM_LINE_Q")"
    echo "ok 3 - QUIT leg: the worker's terminal journal event was emitted (seq $TERM_SEQ_Q)"
else
    echo "not ok 3 - QUIT leg: no terminal journal record for worker $WPID_Q after QUIT"
    echo "# LIFECYCLE-DRAIN-RED-QUIT-NO-TERMINAL"
    TERM_LINE_Q=""
    FAILED=$((FAILED + 1))
fi

# THE ORDERING ORACLE for QUIT: while the client's request was still
# unfinished -- the final body chunk not yet written, so the worker was still
# waiting on body bytes -- the worker's terminal record must NOT yet have been
# written. That is the drain claim stated directly: a draining QUIT keeps
# serving the outstanding request and only exits once it has no connections
# left.
#
# Recorded by the client itself (start_upload's stamp), as a boolean about
# that one record rather than a line count. A count sampled here in the
# foreground can absorb a terminal record that lands during the gap before the
# sample runs. The boolean, taken at a moment when the property under test
# forces the record's absence, has no such gap -- see the sampling comment in
# start_upload for why its position, not merely its shape, is what closes the
# race, and why the two later positions do not.
if [ -n "$TERM_LINE_Q" ]; then
    if [ -z "$UPLOAD_TERM_SEEN_Q" ]; then
        # No stamp at all: the client never reached its final body chunk, so
        # it never evaluated the question. Checked FIRST and separately from
        # the verdict below, so that "no evidence" can never be confused with
        # either answer -- and so a mutation of the verdict lands on the
        # verdict's own red marker rather than being absorbed by this arm.
        echo "not ok 4 - QUIT leg: the upload never recorded a mid-body stamp, so the ordering claim has no evidence"
        echo "# LIFECYCLE-DRAIN-RED-QUIT-NO-STAMP"
        FAILED=$((FAILED + 1))
    elif [ "$UPLOAD_TERM_SEEN_Q" = "absent" ]; then
        echo "ok 4 - QUIT leg: the worker had not logged its exit while it was still awaiting body bytes (the record landed later, at line $TERM_LINE_Q) -- QUIT drained first"
    else
        echo "not ok 4 - QUIT leg: the worker had ALREADY logged its exit (record at line $TERM_LINE_Q) while it was still awaiting body bytes -- QUIT did not drain"
        echo "# LIFECYCLE-DRAIN-RED-QUIT-ORDER"
        FAILED=$((FAILED + 1))
    fi
else
    echo "not ok 4 - QUIT leg: no terminal record to order against (see assertion 3)"
    echo "# LIFECYCLE-DRAIN-RED-QUIT-ORDER"
    FAILED=$((FAILED + 1))
fi

stop_phase "$MASTER_Q"

# ================= PHASE B: TERM does not wait =============================
start_phase 1
WPID_T=""
for ((i = 0; i < 100; i++)); do
    body="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID_T="$(prober_probe_field "$body" pid 2>/dev/null || true)"
    [ -n "$WPID_T" ] && break
    sleep 0.05
done
MASTER_T="$(read_pidfile)"
if [ -z "$WPID_T" ] || [ -z "$MASTER_T" ]; then
    echo "Bail out! phase TERM never got a live worker/master pid to target"
    exit 1
fi

UPLOAD_T_OUT="$PROBER_PREFIX/upload-term.out"
start_upload "$STEP_SLEEP" "$UPLOAD_T_OUT" UPLOAD_T_PID

alive=0
for ((i = 0; i < 20; i++)); do
    if kill -0 "$UPLOAD_T_PID" 2>/dev/null; then alive=1; else alive=0; break; fi
    sleep 0.05
done
if [ "$alive" -eq 1 ] && kill -0 "$UPLOAD_T_PID" 2>/dev/null; then
    echo "ok 5 - TERM leg: the upload was still in flight immediately before the signal"
else
    echo "not ok 5 - TERM leg: the upload was not in flight before the signal; the cutoff claim below would be vacuous"
    echo "# LIFECYCLE-DRAIN-RED-TERM-NOT-INFLIGHT"
    FAILED=$((FAILED + 1))
fi

kill -TERM "$MASTER_T" 2>/dev/null || true

wait "$UPLOAD_T_PID" 2>/dev/null || true

# TERM's claim: the connection was torn down WITHOUT a clean 200 -- the
# fast/immediate path never finishes reading the stalled body. This is the
# positive, falsifiable observation the header promises: not "the terminal
# record arrived first" (a fast worker could in principle still answer a
# slow client before dying, so a seq race alone would not distinguish "did
# not wait" from "got lucky"), but "the client-visible outcome is a cutoff,
# never a completed upload".
# Asserted POSITIVELY, on the shape a cutoff actually has, rather than as
# the negation of the happy path. "No clean 200" is satisfied by far more
# than a cutoff: a complete HTTP 502, a truncated header, or an empty file
# produced by a driver bug all pass it, so the negation admits outcomes in
# which the worker kept serving the request and never tore the connection
# down -- the very thing the contrast claims to have observed. Measured: a
# real TERM cutoff on this scenario leaves the response file EMPTY (the
# connection dies before any status line), against 125 bytes and a
# "HTTP/1.1 200 ... UPLOADED" for the QUIT leg. The claim is therefore that
# no response status line was ever received, which a 502 or any other
# server-generated reply would falsify.
TERM_BYTES="$(stat -c '%s' "$UPLOAD_T_OUT" 2>/dev/null || echo 0)"
if grep -q '^HTTP/1\.1 200' "$UPLOAD_T_OUT" 2>/dev/null && grep -q 'UPLOADED' "$UPLOAD_T_OUT" 2>/dev/null; then
    echo "not ok 6 - TERM leg: the in-flight upload completed with a clean 200 (TERM waited for it, contrary to claim)"
    echo "# LIFECYCLE-DRAIN-RED-TERM-DID-NOT-CUT"
    FAILED=$((FAILED + 1))
elif grep -q '^HTTP/1\.[01] [0-9][0-9][0-9]' "$UPLOAD_T_OUT" 2>/dev/null; then
    echo "not ok 6 - TERM leg: the client received a complete response status line ($(grep -m1 -o '^HTTP/1\.[01] [0-9][0-9][0-9]' "$UPLOAD_T_OUT" 2>/dev/null)) rather than a torn-down connection -- the worker answered the request instead of being cut off"
    echo "# LIFECYCLE-DRAIN-RED-TERM-DID-NOT-CUT"
    FAILED=$((FAILED + 1))
else
    echo "ok 6 - TERM leg: the in-flight upload was cut off, not drained (no response status line reached the client; $TERM_BYTES bytes received)"
fi

wait_master_gone "$MASTER_T" 200 || true

if wait_journal_lines "\"role\":\"worker\",\"pid\":$WPID_T,\"gen\":[0-9]+,\"ev\":\"exiting\"" 100; then
    echo "ok 7 - TERM leg: the worker's terminal journal event was emitted (same 'exiting' record QUIT produces, by the different ngx_terminate code path)"
else
    echo "not ok 7 - TERM leg: no terminal journal record for worker $WPID_T after TERM"
    echo "# LIFECYCLE-DRAIN-RED-TERM-NO-TERMINAL"
    FAILED=$((FAILED + 1))
fi

# THE FULL CONTRAST, restated as its own assertion: the two legs above are
# not just two scenarios that happen to be adjacent in this file -- assertion
# 8 requires BOTH outcomes to have actually diverged in this run (QUIT
# drained per assertion 2, TERM did not per assertion 6). A driver bug that
# accidentally made both legs behave identically (e.g. sending the same
# signal twice by a copy-paste mistake) would still pass assertions 2..7
# individually in the degenerate case where both drained or both cut off;
# this is the row that catches THAT.
Q_DRAINED=0
grep -q '^HTTP/1\.1 200' "$UPLOAD_Q_OUT" 2>/dev/null && grep -q 'UPLOADED' "$UPLOAD_Q_OUT" 2>/dev/null && Q_DRAINED=1
T_DRAINED=0
grep -q '^HTTP/1\.1 200' "$UPLOAD_T_OUT" 2>/dev/null && grep -q 'UPLOADED' "$UPLOAD_T_OUT" 2>/dev/null && T_DRAINED=1

if [ "$Q_DRAINED" = "1" ] && [ "$T_DRAINED" = "0" ]; then
    echo "ok 8 - the contrast holds: QUIT drained the in-flight request, TERM did not"
else
    echo "not ok 8 - the contrast did not hold (QUIT drained=$Q_DRAINED, TERM drained=$T_DRAINED); QUIT and TERM must diverge"
    echo "# LIFECYCLE-DRAIN-RED-CONTRAST"
    FAILED=$((FAILED + 1))
fi

stop_phase "$MASTER_T"

[ "$FAILED" -eq 0 ] || exit 1
exit 0
