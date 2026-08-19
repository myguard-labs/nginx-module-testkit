#!/usr/bin/env bash
#
# Scenario: a client is streaming a LARGE request BODY (an upload, client ->
# server direction) slowly when the master is told to reload. The reload must
# be absorbed WITHOUT dropping the in-flight upload: the old worker finishes
# reading the whole body and returns a clean 200, no worker dies by signal, no
# descriptor is leaked across the boundary.
#
# This is the UPLOAD mirror of backend-reload-inflight (a download drip). The
# key difference: the slow drip is on the CLIENT's write side (the request
# body), and there is NO backend -- nginx itself must read+buffer the whole
# body. The mechanism is proxy_pass with proxy_request_buffering on (the
# default; see nginx.conf) -- nginx cannot open the upstream connection, and
# therefore cannot produce a response, until the ENTIRE request body has been
# buffered. A bare `return 200` does NOT do this (verified: it short-circuits
# in the rewrite phase before the body is read at all -- see nginx.conf's
# comment), which is why this scenario proxies to a same-server sink instead.
# Because the 200 is gated on the LAST body byte, assertion 3 below is a
# genuinely strong proof, not a weak one: the ~4.5s drip cannot finish before
# the sub-second reload lands, so a clean 200 is direct evidence the response
# was produced only after the full slow body -- spanning the reload -- was
# read.
#
# Why a driver and not a plain .rule file: same reason as backend-reload-
# inflight -- the prober runs each case synchronously to completion, so it
# cannot hold one request's body open on the wire while a signal is delivered
# to the master. This driver keeps the slow upload open in a background shell,
# delivers the SIGHUP underneath it, waits for the reload to actually land (a
# new worker answering, prober_signal_wait), and only then joins the upload to
# check it survived.
#
# ON THE ORDERING ORACLE (assertion 2, the mid-flight liveness gate; assertion
# 1 is its in-scenario negative control -- a fast upload that must fail it)
# AND WHY IT IS WEAKER HERE:
# backend-reload-inflight proves "in flight" with a backend JOURNAL -- a
# {"ev":"send"} record the fake backend flushes the instant it starts writing
# the reply, which is a genuine per-byte server-side event. This scenario has
# NO backend: the upload is consumed directly by nginx, and nginx emits no
# per-chunk "body byte received" event at any log level this harness scrapes.
# So there is no equivalently strong falsifiable oracle available here. The
# best available signal, honestly weaker, is: the background upload subshell
# is STILL ALIVE (kill -0) after a bounded, counted settle -- i.e. it has not
# yet finished sending (a finished send would have closed and exited the
# subshell) and enough fixed steps have elapsed that the headers plus first
# body chunk are provably on the wire. This does NOT prove nginx has started
# READING the body (no such observable exists without instrumenting nginx
# itself), only that the client has not yet finished WRITING it.
#
# The actual load-bearing proof that the upload SPANNED the reload is not
# assertion 2 at all -- it is the conjunction of: UPLOAD_PID is re-checked
# alive immediately before prober_signal_wait is called (a hard gate, not a
# soft assertion: if it already exited, the run aborts assertion 2 as a
# mistimed `not ok` rather than certifying a false span), and the total body
# (60 bytes @ 4 bytes/300ms ~= 4.5s) is many times longer than a reload takes
# to absorb, so on any host where the pre-signal liveness gate passes, the
# upload is still sending when the HUP lands. This mirrors the timing-margin
# argument backend-reload-inflight uses for its drip, just without a journal
# to make it a hard per-byte proof.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

# The prober needs the error-log path to satisfy the post-reload case's
# no_error_log directive. run-scenario.sh exports this only for the rules
# branch, so a driver that runs the prober must export it itself.
export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing assertion this driver makes. The verdict a
# consumer (test-scenarios.sh) keys off is the EXIT STATUS, not the inner TAP
# text -- so a `not ok` that did not also raise FAILED (and thus the exit
# status) would be a vacuous assertion that never fails the suite. Every
# branch that prints `not ok` also bumps FAILED, and the final exit is nonzero
# if FAILED > 0 OR the prober leg went red.
FAILED=0

# TAP plan: (1) NEGATIVE CONTROL -- a fast upload that finishes before the
# settle window MUST fail the mid-flight liveness gate (proves assertion 2's
# gate actually discriminates; without this the gate can pass an
# already-completed upload and certify a span that never happened), (2) the
# real slow upload was provably mid-flight before the reload (the ordering
# precondition, honestly weaker here -- see comment above), (3) the reload was
# absorbed while the upload was in flight, (4) the upload completed intact
# across the reload, (5) no worker died by signal, (6) the post-reload prober
# leg folded in as diagnostics.
echo "1..6"

# --- upload subshell factory ------------------------------------------------
# Fires a raw HTTP/1.1 POST over /dev/tcp to /upload, dripping the body a few
# bytes at a time with $1 seconds between writes ($1=0 means send the whole
# body in one shot, i.e. finish fast). The Content-Length is FIXED and the
# total bytes written MUST exactly equal it -- a short body would leave nginx
# waiting forever for the rest and hang this driver, not just the request.
# Output lands in the file named by $2; the background PID is written back into
# the caller's variable named by $3 (an out-param, NOT command substitution).
#
# WHY NOT `pid=$(start_upload ...)`: command substitution runs the function body
# in a subshell, so the `( ... ) &` job would be a child of THAT subshell, not of
# this driver. Bash `wait` only reaps direct children, so a later
# `wait "$UPLOAD_PID"` would be waiting on a non-child (undefined/"not a child of
# this shell") and could leave the upload running past the intended cleanup
# boundary. Backgrounding in the driver's own shell (out-param via `printf -v`)
# keeps the job a true child, so wait/kill/kill -0 all address it correctly.
BODY="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"   # 60 bytes
BODY_LEN=${#BODY}
CHUNK=4          # bytes per write

start_upload() {
    local step_sleep=$1 out=$2 pidvar=$3
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'POST /upload HTTP/1.1\r\nHost: prober\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' \
            "$BODY_LEN" >&3

        off=0
        while [ "$off" -lt "$BODY_LEN" ]; do
            len=$CHUNK
            remaining=$((BODY_LEN - off))
            [ "$len" -gt "$remaining" ] && len=$remaining
            printf '%s' "${BODY:$off:$len}" >&3
            off=$((off + len))
            # $step_sleep=0 -> no inter-chunk delay, the whole body streams out
            # in one pass and the request finishes well inside the settle loop.
            if [ "$off" -lt "$BODY_LEN" ] && [ "$step_sleep" != 0 ]; then
                sleep "$step_sleep"
            fi
        done

        # Ignore cat's exit status: a Connection: close response commonly ends
        # in an RST once the server has sent everything, and cat then exits
        # non-zero having already delivered a complete body (documented in
        # prober_probe_pid).
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    # The `&` above runs in THIS shell (start_upload is called directly, not in a
    # command substitution), so $! is a real child of the driver. Hand it back
    # through the caller-named variable.
    printf -v "$pidvar" '%s' "$!"
}

# --- assertion 1: NEGATIVE CONTROL -- a fast upload must NOT pass the gate ----
# The whole scenario's span-proof rests on the liveness gate (assertion 2)
# distinguishing "still uploading" from "already finished". If that gate would
# also pass an upload that has already completed, it proves nothing. So before
# the real run, fire a fast upload (no inter-chunk drip) that finishes inside
# the same settle window, and assert it is NOT alive afterwards -- i.e. the
# gate reds for it. This is the in-scenario control the manual mutation used to
# stand in for; baking it in makes the scenario self-falsifying.
NEG_OUT="$PROBER_PREFIX/upload-fast.out"
start_upload 0 "$NEG_OUT" NEG_PID
neg_alive=0
for ((i = 0; i < 20; i++)); do   # same 20 * 50 ms = 1 s settle as the real gate
    if kill -0 "$NEG_PID" 2>/dev/null; then
        neg_alive=1
    else
        neg_alive=0
        break
    fi
    sleep 0.05
done
# Reap it either way so it cannot linger into the real run.
wait "$NEG_PID" 2>/dev/null || true
if [ "$neg_alive" -eq 0 ]; then
    echo "ok 1 - a fast upload finished before the settle window (liveness gate discriminates)"
else
    echo "not ok 1 - a fast upload was still 'alive' after the settle window (gate cannot tell finished from in-flight)"
    FAILED=$((FAILED + 1))
fi

# --- fire the slow upload ---------------------------------------------------
STEP_SLEEP=0.3   # seconds between writes -> ~(60/4)*0.3 = 4.5s total drip,
                 # many times a reload's absorb time.

UPLOAD_OUT="$PROBER_PREFIX/upload.out"
start_upload "$STEP_SLEEP" "$UPLOAD_OUT" UPLOAD_PID

# --- ordering oracle (assertion 2, honestly weaker -- see header) ----------
# Fixed-step counted iterations, never a wall-clock diff (same discipline as
# prober_signal_wait / prober_wait_listen): a loaded runner performs the same
# number of attempts. This only proves the subshell is alive and a bounded
# settle has elapsed -- NOT a per-byte server event, since none exists for a
# direct upload with no backend. See the header comment for the honest caveat
# and for where the real span-proof actually lives (the pre-signal liveness
# gate below).
ALIVE_SEEN=0
for ((i = 0; i < 20; i++)); do   # 20 * 50 ms = 1 s settle, well under the 4.5s drip
    if kill -0 "$UPLOAD_PID" 2>/dev/null; then
        ALIVE_SEEN=1
    else
        ALIVE_SEEN=0
        break
    fi
    sleep 0.05
done

# CRITICAL gate, folded into the same assertion: if the upload already
# finished (either during the settle loop above, or in the instant after it),
# the scenario would NOT span the reload and assertion 2 would certify a
# vacuous "in flight" that never was. Re-check liveness immediately before
# printing the verdict / sending the signal, not just after the settle loop.
if [ "$ALIVE_SEEN" -eq 1 ] && kill -0 "$UPLOAD_PID" 2>/dev/null; then
    echo "ok 2 - the upload was still sending (alive, mid-drip) before the reload"
else
    echo "not ok 2 - the upload subshell was not alive through the settle window (mistimed or finished early)"
    FAILED=$((FAILED + 1))
fi

if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" 5000; then
    echo "ok 3 - the reload was absorbed while the upload was in flight"
else
    echo "not ok 3 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- join the upload ---------------------------------------------------------
# A bare `wait` on a hung upload would never return: if the reload dropped the
# connection and nginx never closes, the background client blocks forever and
# so does this driver, consuming the whole CI job instead of reporting a
# bounded failure. Poll for the background shell to exit within a deadline; if
# it overruns, KILL it and fall through -- the truncated/empty $UPLOAD_OUT then
# fails the assertion below, which is the correct verdict for an upload that
# never completed.
join_deadline=$(( SECONDS + 15 ))
while kill -0 "$UPLOAD_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        # Kill the whole subtree, not just the subshell. The background job is
        # `( ... cat <&3 ) &`, and `cat` is a CHILD of that subshell blocked on
        # the socket read; killing only $UPLOAD_PID would orphan the cat, which
        # keeps the fd open and can go on writing to $UPLOAD_OUT. Reap the
        # children first (job control is off in a script, so there is no
        # process group to signal), then the subshell.
        pkill -P "$UPLOAD_PID" 2>/dev/null || true
        kill "$UPLOAD_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$UPLOAD_PID" 2>/dev/null || true

# The response must be a complete, correct 200 carrying the UPLOADED body. A
# reload that dropped the in-flight upload would leave a truncated/absent
# response, a 4xx/5xx, or an empty file -- each of which fails this check.
if grep -q '^HTTP/1.1 200' "$UPLOAD_OUT" \
   && grep -q 'UPLOADED' "$UPLOAD_OUT"; then
    echo "ok 4 - the upload completed intact across the reload"
else
    echo "not ok 4 - the upload was dropped or truncated by the reload"
    sed 's/^/# /' "$UPLOAD_OUT" | head -20
    FAILED=$((FAILED + 1))
fi

# --- the reload did not crash a worker --------------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit path
# is asserted separately here: a clean reload logs the old worker leaving via
# "gracefully shutting down" / "exiting", never a signal-death line.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the reload"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the reload"
fi

# --- post-reload coherence (prober, folded in as diagnostics) ---------------
# Runs a plain strict case AFTER the reload has been absorbed: the new worker
# serves a correct 200, leaks no descriptor, and logs nothing on the error path
# in the window around the request. The pid oracle in post-reload.rule is
# STRICT on purpose -- see that file's header for why pid_may_change would be a
# no-op here. The reload-survival claims this scenario exists to make are the
# driver's ok 2-4 above, which hold the upload open across the signal.
STATUS=0
# PIPESTATUS, not $?: a bare `./prober | sed` would report sed's exit, which is
# always 0, silently discarding a red prober leg -- the exact vacuous shape
# this driver guards against elsewhere.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

# The scenario is red if ANY driver assertion failed OR the prober leg did.
if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
