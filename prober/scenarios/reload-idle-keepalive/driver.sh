#!/usr/bin/env bash
#
# Scenario: a client opens an HTTP/1.1 KEEPALIVE connection, sends ONE
# request, reads the full response, and then holds the connection IDLE -- no
# further request in flight, just an open, quiescent client<->nginx socket.
# A reload (SIGHUP) is then delivered. The old worker enters graceful
# shutdown and MUST close that idle client keepalive connection: it cannot be
# carried into the new worker's accept cycle. The client observes the
# server-side FIN (its read returns EOF).
#
# This is DISTINCT from backend-idle-close-reload: that scenario is about an
# UPSTREAM (memcached) keepalive pool connection nginx holds to a backend.
# This one is the CLIENT-facing keepalive connection nginx holds open to a
# browser/curl-like peer. Different direction, different pool, different code
# path (event_pipe/upstream keepalive vs. the core HTTP keepalive state
# machine and lingering-close-on-shutdown handling).
#
# Why a driver and not a plain .rule file: the prober runs each case
# synchronously to completion (connect, send, read, disconnect) and so cannot
# hold a connection open and IDLE while a signal is delivered to the master
# out from under it. This driver keeps the idle connection open in a
# background subshell, delivers the SIGHUP underneath it, waits for the
# reload to land, and only then checks whether the idle connection was
# closed.
#
# THE CLOSE ORACLE AND ITS HONEST STRENGTH: after the one response is fully
# read, the subshell blocks on a further read from the socket (nothing else
# is ever sent on it). A live TCP peer that never writes and never closes
# leaves that read blocked indefinitely -- so if the subshell ever exits, it
# is because the read returned EOF, which happens if and only if the peer
# (nginx) closed its end. This is a strong, direct proof: "subshell exited"
# is equivalent to "server closed the connection", not a proxy for it. The
# negative control (assertion 1) additionally proves the converse direction
# that matters for calibration: absent a reload, with a 3600s keepalive
# timeout, the connection does NOT close on its own within a settle window
# far longer than a healthy drain takes -- so a close seen after the reload
# is attributable to the reload, not to some other timer or accident of this
# harness.
#
# THE DEADLINE IS AN EVENT, NOT A CLOCK (s181). Assertion 4 used to wait a
# fixed 100 * 50 ms for the close, and that ceiling was crossed once on a
# loaded builder (s169) by a scenario with no defect. A promptness claim
# denominated in wall-clock is not assertable on a shared runner, and the
# repair is NOT a bigger number: the same constant also bounds assertion 1's
# negative control, which requires the conn to STAY open, so widening it
# weakens the control in exact proportion (the disable-the-oracle shape this
# repo keeps re-learning). Instead assertion 4 now asserts the ORDERING that
# the close actually owes: the draining old worker must close the idle conn
# no later than its own exit. That deadline is derived from the subject's own
# progress (the master's child set returning to the configured worker count),
# so it stretches exactly as far as a loaded box makes the drain take, and it
# still fails hard on the defect this scenario exists to catch -- an idle
# client keepalive conn carried past the old worker into the new cycle. The
# remaining fixed count is a hang-guard, not the deadline, and it is no longer
# shared with the control.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"
WORKERS=1                # matches worker_processes in nginx.conf (drain target)

# The prober leg's no_error_log directive needs this; run-scenario.sh exports
# it only for a rules run, so a driver that runs the prober exports it itself.
export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing driver assertion. test-scenarios.sh keys
# the scenario verdict off the EXIT STATUS, not the inner TAP text -- so a
# `not ok` that did not also raise FAILED (and thus the exit status) would be
# a vacuous assertion that never fails the suite. Every branch that prints
# `not ok` also bumps FAILED, and the final exit is nonzero if FAILED>0 or
# the prober leg went red.
FAILED=0

# TAP plan: (1) NEGATIVE CONTROL -- an idle keepalive conn opened WITHOUT any
# reload must stay open through the settle window (proves the close oracle in
# assertion 4 discriminates: a close seen there is reload-caused, not
# spontaneous), (2) the real idle conn is established and idle before the
# signal is sent, (3) the reload was absorbed, (4) the close oracle -- the
# draining old worker closed the idle client keepalive conn, (5) no worker
# died by signal, (6) the post-reload prober leg folded in as diagnostics.
echo "1..6"

# --- idle-keepalive-connection helper ---------------------------------------
# Opens a raw HTTP/1.1 keepalive connection over /dev/tcp, sends exactly ONE
# request, reads the one Content-Length-delimited response, drops a READY
# marker the instant the full response is in hand (so the caller can wait for
# "established and idle" without sleeping blind), and then blocks reading
# further from the socket. Because nothing else is ever written on this
# connection, that trailing read can only return by EOF -- i.e. the peer
# closed -- at which point the subshell exits. So: subshell alive == conn
# still open; subshell exited == conn closed by the server. This mirrors the
# kill -0 liveness pattern reload-mid-upload/driver.sh uses for its upload
# subshell, just for a close instead of a hang.
#
# The response has a known, fixed body ("OK\n", see nginx.conf's `return 200
# "OK\n";`), so the response is read to completion with a small counted
# read-loop over headers + the exact body length rather than blocking on a
# read that would never return end-of-response on a keepalive socket (there
# is no EOF at the end of a keepalive response -- only at the end of the
# WHOLE connection, which is exactly the event this driver is trying to
# distinguish from "response finished").
#
# $1 = ready-marker file path (created once the response is fully read)
# $2 = pidvar (out-param name to receive the background PID)
#
# WHY THE OUT-PARAM AND NOT `pid=$(open_keepalive_conn ...)`: command
# substitution runs the function body in a SUBSHELL, so the `( ... ) &`
# backgrounded job inside it becomes a child of THAT subshell, not of this
# driver. Bash `wait`/`kill -0` only address direct children (or at least a
# job bash's own job table knows about); a pid obtained via command
# substitution can end up referring to a process this shell never forked as a
# direct child, so `kill -0`/`wait` on it becomes unreliable ("not a child of
# this shell"). Backgrounding directly in the driver's own shell and handing
# the pid back through a caller-named variable (`printf -v "$pidvar" '%s'
# "$!"`) keeps the job a true, addressable child. This exact trap is
# documented at length in reload-mid-upload/driver.sh lines ~99-142; the
# reasoning is identical here, just applied to a read instead of a write.
open_keepalive_conn() {
    local marker=$1 pidvar=$2 closedmarker=$3
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: keep-alive\r\n\r\n' >&3

        # Read the response headers line by line until the blank
        # (CRLF-only) line that separates headers from body.
        content_length=0
        while IFS= read -r -u3 line; do
            line=${line%$'\r'}
            if [ -z "$line" ]; then
                break
            fi
            case "$line" in
                [Cc]ontent-[Ll]ength:*)
                    content_length=${line#*:}
                    content_length=${content_length## }
                    ;;
            esac
        done

        # Read exactly content_length body bytes -- no more, no less -- so
        # the socket is left positioned exactly at "response fully
        # consumed, connection now idle" with nothing of the next
        # (nonexistent) response accidentally buffered or blocked on.
        if [ "$content_length" -gt 0 ]; then
            body=$(dd bs=1 count="$content_length" <&3 2>/dev/null)
            : "$body"   # body content itself is not asserted here
        fi

        # The one response is now fully in hand and the connection is
        # idle: drop the ready marker so the caller can stop polling.
        : >"$marker"

        # Block reading further. Nothing else is ever sent on this
        # connection, so this read can only return when the peer closes its
        # end, at which point this subshell exits.
        #
        # PRESERVE the reader's exit status rather than swallowing it with
        # `|| true`: a graceful nginx keepalive close on worker shutdown is a
        # FIN, so `cat` sees a clean end-of-file and exits 0. A socket-read
        # FAILURE (e.g. an RST, or the fd going bad for another reason) makes
        # `cat` exit nonzero. We must not let those two look alike, or
        # assertion 4 would print `ok` for a reader that failed rather than
        # for the intended close/EOF path. So drop the `|| true` (this is the
        # exit-status-swallowing pitfall the up/download drivers accept only
        # because their oracle is liveness, not close-classification) and, on
        # a clean EOF only, drop a CLOSED marker the caller can gate `ok 4`
        # on. If `cat` exits nonzero, no marker is written and the subshell's
        # own nonzero status is preserved.
        if cat <&3 >/dev/null 2>/dev/null; then
            : >"$closedmarker"
        fi
    ) &
    printf -v "$pidvar" '%s' "$!"
}

# Fixed-step counted settle for the two things that ARE wall-clock questions:
# readiness (has the conn become idle yet) and the negative control's liveness
# window (does an idle conn stay open on its own). Counted iterations, never a
# wall-clock diff -- same discipline as prober_signal_wait / prober_wait_listen.
#
# This constant NO LONGER bounds assertion 4. It used to, and that coupling was
# the s169 finding: one number could not simultaneously be a floor for the
# control ("stay open at least this long") and a ceiling for the close ("close
# within this long"), because moving it to relieve one weakens the other.
# Assertion 4 now waits on an event (see DRAIN_* below), so this number is free
# to mean only what its name says.
SETTLE_ITERS=100     # 100 * 50 ms = 5 s

# Assertion 4's hang-guard, NOT its deadline. In a healthy run the ordering
# wait ends in milliseconds, when the reader sees EOF; this budget exists only
# so a genuinely stuck drain terminates the scenario instead of hanging the
# suite. Deliberately far larger than the old 5 s ceiling, which it is safe to
# be precisely because it is no longer the thing being asserted -- crossing it
# means the old worker neither closed the conn nor finished draining for a
# minute, which is a real failure on any box under any load.
DRAIN_CEILING_ITERS=1200        # 1200 * 50 ms = 60 s hang-guard

# Once the master's child set is back to WORKERS the old worker is gone, and
# its fds went with it -- so the reader's EOF is already in flight and this is
# pure observation lag, not waiting on the server. Bounded small: an idle conn
# that is STILL open a second after the worker holding it exited was not being
# held by that worker, which is the carried-into-the-new-cycle defect.
POST_DRAIN_GRACE_ITERS=20       # 20 * 50 ms = 1 s

# --- assertion 1: NEGATIVE CONTROL -- an idle conn must NOT close itself ----
# Runs FIRST, fully reaped before the real conn is opened (mirrors
# reload-mid-upload: its fast neg-control upload runs and is reaped before
# the real slow upload starts -- never concurrently). Opens an idle
# keepalive conn, sends NO signal, and holds it for SETTLE_ITERS. With
# keepalive_timeout 3600s, nothing in this harness should close it. If it
# closes anyway, the close oracle in assertion 4 would not discriminate a
# reload-caused close from ambient noise, and this scenario would prove
# nothing.
#
# WHY 5 s IS THE RIGHT CALIBRATION WINDOW NOW THAT ASSERTION 4 NO LONGER
# SHARES IT. The close that assertion 4 credits is one that happened while
# the old worker was still draining -- milliseconds, on a healthy run. This
# control shows that an idle conn survives three orders of magnitude longer
# than that with no reload in play, which is what "the close came from the
# reload" needs. It is a calibration ratio, not an equality: the two windows
# do not have to match, they have to be far apart in the right direction.
# Assertion 4 prints a TAP diagnostic (never a failure) if a run ever
# inverts that -- a close observed later than this control window is still a
# correct close, but it is one this control no longer covers, and that is
# worth seeing in the log rather than silently crediting.
CONTROL_MARKER="$PROBER_PREFIX/control.ready"
CONTROL_CLOSED="$PROBER_PREFIX/control.closed"
open_keepalive_conn "$CONTROL_MARKER" CONTROL_PID "$CONTROL_CLOSED"

# Wait for the control conn to become IDLE (its one response fully read, ready
# marker dropped) BEFORE starting the liveness window. Without this gate the
# window could elapse while the child is still connecting or reading the first
# response -- then "stayed alive" would say nothing about an *idle* keepalive
# socket, and the discrimination claim (an idle conn does not close on its own)
# would be unproven. Fixed-step counted iterations, never a sleep. The child
# must still be alive when the marker appears; if it died before ever reaching
# the marker, readiness failed.
control_ready=0
for ((i = 0; i < SETTLE_ITERS; i++)); do
    if [ -e "$CONTROL_MARKER" ]; then
        control_ready=1
        break
    fi
    if ! kill -0 "$CONTROL_PID" 2>/dev/null; then
        break
    fi
    sleep 0.05
done

control_alive=0
if [ "$control_ready" -eq 1 ] && kill -0 "$CONTROL_PID" 2>/dev/null; then
    # Now, and only now, time the idle socket across the full settle window.
    for ((i = 0; i < SETTLE_ITERS; i++)); do
        if kill -0 "$CONTROL_PID" 2>/dev/null; then
            control_alive=1
        else
            control_alive=0
            break
        fi
        sleep 0.05
    done
fi

# Reap the control connection's subtree so it cannot linger into the real
# run -- job control is off in a script (no process group to signal), so the
# child (`cat`, or `dd` if still mid-read) is killed explicitly before the
# subshell itself.
pkill -P "$CONTROL_PID" 2>/dev/null || true
kill "$CONTROL_PID" 2>/dev/null || true
wait "$CONTROL_PID" 2>/dev/null || true

if [ "$control_ready" -eq 0 ]; then
    echo "not ok 1 - the control idle keepalive conn was never established/idle in time"
    FAILED=$((FAILED + 1))
elif [ "$control_alive" -eq 1 ]; then
    echo "ok 1 - an idle keepalive conn stayed open on its own (close oracle discriminates)"
else
    echo "not ok 1 - the idle keepalive conn closed itself with no reload (close oracle cannot discriminate)"
    FAILED=$((FAILED + 1))
fi

# --- open the REAL idle keepalive connection --------------------------------
REAL_MARKER="$PROBER_PREFIX/real.ready"
REAL_CLOSED="$PROBER_PREFIX/real.closed"
open_keepalive_conn "$REAL_MARKER" REAL_PID "$REAL_CLOSED"

# --- assertion 2: established and idle BEFORE signalling -------------------
# Poll for the ready marker with fixed-step counted iterations, never a
# sleep -- same discipline as prober_signal_wait / prober_wait_listen. This
# is a hard gate, not a soft assertion: if the marker never appears (or the
# subshell already exited) within the window, the run must not proceed to
# certify a span that was never actually established.
marker_seen=0
for ((i = 0; i < SETTLE_ITERS; i++)); do
    if [ -e "$REAL_MARKER" ]; then
        marker_seen=1
        break
    fi
    if ! kill -0 "$REAL_PID" 2>/dev/null; then
        # subshell already gone without ever reaching the marker -- a hard
        # failure, not a race to keep polling through.
        break
    fi
    sleep 0.05
done

READY_OK=0
if [ "$marker_seen" -eq 1 ] && kill -0 "$REAL_PID" 2>/dev/null; then
    READY_OK=1
    echo "ok 2 - the real idle keepalive conn is established and idle before the reload"
else
    echo "not ok 2 - the real idle keepalive conn was never established/idle in time"
    FAILED=$((FAILED + 1))
fi

# READINESS IS A HARD GATE. If assertion 2 failed, the idle conn was never
# established -- so sending the reload and then watching the (already-dead or
# never-idle) subshell "exit" would let assertion 4 print `ok` for a close
# that has nothing to do with the reload. Reap the child and mark the
# dependent assertions 3+4 as failures rather than running them against an
# unestablished conn. FAILED is already bumped for the not-ok-2 above.
if [ "$READY_OK" -eq 0 ]; then
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    echo "not ok 3 - skipped: the idle conn was never established (see not ok 2)"
    echo "not ok 4 - skipped: the idle conn was never established (see not ok 2)"
    FAILED=$((FAILED + 2))
else
# --- assertion 3: the reload is absorbed ------------------------------------
# prober_signal_wait probes via /__probe on its OWN fresh connections --
# independent of our idle conn -- and blocks until a different worker pid
# answers, or times out (a real failure).
if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" 5000; then
    echo "ok 3 - the reload was absorbed"
else
    echo "not ok 3 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- assertion 4: THE CLOSE ORACLE ------------------------------------------
# After the reload has landed, the draining old worker must close the idle
# client keepalive connection it was still holding -- it cannot carry that
# connection into the new worker's accept cycle. The deadline for that close
# is the old worker's OWN EXIT, observed as the master's direct-child count
# returning to WORKERS (the same oracle prober_drain_wait uses; open-coded
# here because this loop must watch the reader and the child set in the SAME
# iteration, and prober_drain_wait blocks until one of them alone resolves).
#
# The loop ends on whichever comes first:
#   - the reader exits            -> the conn closed; classify it below;
#   - the old worker is gone      -> keep looking POST_DRAIN_GRACE_ITERS more,
#                                    since the exit itself closes the fd and
#                                    the EOF is merely in flight, then stop;
#   - DRAIN_CEILING_ITERS         -> hang-guard; a drain that has neither
#                                    closed the conn nor finished in 60 s.
# The reader is checked FIRST each iteration so a close observed during the
# grace window is credited, not raced away.
#
# WITHOUT pgrep the child set cannot be observed at all (the return-2 case in
# prober_drain_wait). That does not make this assertion skippable -- it only
# removes the early verdict, leaving the hang-guard as the bound. A conn still
# open at the ceiling is a failure on any host; the message names the fallback
# so a reader of the log knows which bound actually fired.
#
# The subshell writes REAL_CLOSED only on a CLEAN EOF (`cat` exit 0 -- a FIN
# from a graceful worker shutdown). Gating `ok 4` on that marker, not merely
# on the subshell being gone, means a subshell that exited because its read
# FAILED (a nonzero `cat`, e.g. an RST or a bad fd) does NOT certify the
# close/EOF path this oracle exists to prove.
have_pgrep=1
command -v pgrep >/dev/null 2>&1 || have_pgrep=0

closed=0
closed_at=-1
drained_at=-1
for ((i = 0; i < DRAIN_CEILING_ITERS; i++)); do
    if ! kill -0 "$REAL_PID" 2>/dev/null; then
        closed=1
        closed_at=$i
        break
    fi

    if [ "$have_pgrep" -eq 1 ] && [ "$drained_at" -lt 0 ]; then
        # `|| kids=0`: pgrep exits 1 when it matches nothing, and under
        # `pipefail` that would propagate out of the substitution and abort the
        # driver on `set -e`. Zero children is data here (the master itself
        # died), not an error to die on -- it simply never equals WORKERS.
        kids="$(pgrep -P "$MASTER" 2>/dev/null | wc -l)" || kids=0
        # Spelled as if/then, not `[ ... ] && drained_at=$i`: the && form is
        # the LAST command of this if-block, so on the (usual) not-yet-drained
        # iteration it would make the block exit nonzero and `set -e` would
        # abort the driver mid-wait.
        if [ "$kids" -eq "$WORKERS" ]; then
            drained_at=$i
        fi
    fi

    if [ "$drained_at" -ge 0 ] && [ $((i - drained_at)) -ge "$POST_DRAIN_GRACE_ITERS" ]; then
        break
    fi

    sleep 0.05
done

# Reap ONLY on the close path. `wait` on a child that is still blocked in its
# read never returns, so the timeout path must kill the subtree BEFORE waiting
# (it does, in the else branch below) -- reaping unconditionally here would
# hang the driver on exactly the failure this assertion exists to report.
if [ "$closed" -eq 1 ]; then
    wait "$REAL_PID" 2>/dev/null || true
fi

if [ "$closed" -eq 1 ] && [ -e "$REAL_CLOSED" ]; then
    echo "ok 4 - the draining old worker closed the idle client keepalive conn (clean EOF)"
    # Non-fatal calibration note: the close is correct either way, but past
    # SETTLE_ITERS it sits outside the window assertion 1 measured, so say so
    # in the log rather than crediting it silently. See assertion 1's header.
    if [ "$closed_at" -ge "$SETTLE_ITERS" ]; then
        # Counted in ITERATIONS, and reported as such: a loaded box makes each
        # 50 ms step take longer, so the nominal figure is a floor on the real
        # wall-clock, not a measurement of it. Both sides of the comparison are
        # the same counted unit, which is the only reason it is meaningful.
        echo "# note: close observed at iteration $closed_at (>= ${SETTLE_ITERS}," \
             "the window assertion 1 calibrated); still a correct close, but one" \
             "the negative control no longer covers"
    fi
elif [ "$closed" -eq 1 ]; then
    echo "not ok 4 - the idle conn's reader exited without a clean EOF (read error, not a graceful close)"
    FAILED=$((FAILED + 1))
else
    if [ "$drained_at" -ge 0 ]; then
        echo "not ok 4 - the idle client keepalive conn outlived the draining worker:" \
             "still open $((POST_DRAIN_GRACE_ITERS * 50))ms after the master's child set" \
             "returned to $WORKERS, so it was carried past the old cycle"
    elif [ "$have_pgrep" -eq 0 ]; then
        echo "not ok 4 - the idle client keepalive conn was still open" \
             "$((DRAIN_CEILING_ITERS * 50))ms after the reload (no pgrep on this host," \
             "so the hang-guard bound this wait, not the old worker's exit)"
    else
        echo "not ok 4 - the old worker neither closed the idle client keepalive conn nor" \
             "finished draining within $((DRAIN_CEILING_ITERS * 50))ms of the reload"
    fi
    # Kill the subtree so nothing lingers past this driver's exit.
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    FAILED=$((FAILED + 1))
fi
fi   # end READY_OK gate (assertions 3+4)

# --- assertion 5: no worker died by signal ----------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit
# path is asserted separately: a clean reload logs the old worker leaving via
# "gracefully shutting down" / "exiting", never a signal-death line.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the reload"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the reload"
fi

# --- assertion 6: post-reload coherence (prober, folded in as diagnostics) --
# A plain strict case AFTER the reload: the new worker serves a correct 200,
# leaks no descriptor, and logs nothing on the error path around the
# request. The pid oracle in post-reload.rule is STRICT on purpose -- see
# that file's header. The reload-survival claim this scenario exists to make
# is ok 4 above (the idle client keepalive conn was closed by the draining
# worker), not this leg.
STATUS=0
# PIPESTATUS, not $?: a bare `./prober | sed` would report sed's exit status
# (always 0), silently discarding a red prober leg -- the exact vacuous shape
# this driver guards against elsewhere.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
