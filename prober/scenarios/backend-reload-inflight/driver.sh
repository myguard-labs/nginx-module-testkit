#!/usr/bin/env bash
#
# Scenario: a client request is in flight -- its upstream reply still dripping
# out of the fake backend -- when the master is told to reload. The reload must
# be absorbed WITHOUT dropping the in-flight request: it completes with the
# full, correct body and status 200, and no descriptor is leaked across the
# boundary.
#
# Why a driver and not a plain .rule file: the prober runs each case
# synchronously to completion, so it cannot hold one request open on the wire
# while a signal is delivered to the master. This driver keeps the slow request
# open in a background shell, delivers the SIGHUP underneath it, waits for the
# reload to actually land (a new worker answering, prober_signal_wait), and only
# then joins the slow request to check it survived.
#
# The reload is proven to land by prober_signal_wait polling the probe endpoint
# for a NEW worker pid -- not by a sleep. The in-flight request is kept open by
# the backend's drip fault (4 bytes / 300 ms over a 40-byte value ~= 3 s), which
# is many times longer than a reload takes to absorb, so the ordering does not
# depend on wall-clock timing on any particular host: the request is provably
# still open when the signal is sent because the backend has not finished
# writing it.
#
# On pid oracles and why this scenario does not use pid_may_change: the reload
# happens between prober invocations, not within one prober case's before/after
# probe window, so no single case straddles the signal -- eval_pid_stable never
# sees a pid change to relax, and pid_may_change would be a vacuous no-op here
# (confirmed: stripping it from post-reload.rule leaves the scenario green). The
# assertions that DO straddle the reload are this driver's ok 1-3, which hold a
# request open across the signal; post-reload.rule only proves the server came
# back healthy afterwards, under the correct STRICT oracle.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

# The prober needs the error-log path to satisfy the spanning case's
# no_error_log directive. run-scenario.sh exports this only for the rules
# branch, so a driver that runs the prober must export it itself.
export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing assertion this driver makes. The driver's
# own `not ok` lines are printed for a human, but TAP a consumer folds as one
# indented block per scenario keys the scenario's verdict off the EXIT STATUS
# (test-scenarios.sh), not off parsing the inner plan -- so a `not ok` that did
# not also raise the exit status would be a vacuous assertion that never fails
# the suite. Every branch that prints `not ok` also bumps FAILED, and the final
# exit is nonzero if FAILED > 0 OR the prober leg went red.
FAILED=0

# TAP plan: five prober-independent assertions the driver makes itself --
# (1) the reply was provably dripping from the upstream before the reload
# (ordering oracle, the precondition that makes "in flight" true rather than
# hoped), (2) the reload was absorbed, (3) the in-flight response completed
# intact, (4) no worker died by signal, (5) the backend served the in-flight
# request exactly once -- i.e. the request survived the reload rather than being
# re-issued to the upstream after it -- plus the prober's own verdict folded in
# as diagnostics.
echo "1..5"

# --- fire the in-flight request -------------------------------------------
# A raw HTTP/1.1 GET over /dev/tcp (bash's client, for the same reason lib.sh
# uses it -- nc variants differ). Its full response is captured to a file; the
# request will still be receiving its dripped upstream reply when the HUP fires.
INFLIGHT="$PROBER_PREFIX/inflight.out"
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET /mc?key=slow HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
    # Ignore cat's exit status: a Connection: close response commonly ends in an
    # RST once the server has sent everything, and cat then exits non-zero
    # having already delivered a complete body (documented in prober_probe_pid).
    cat <&3 2>/dev/null || true
) >"$INFLIGHT" 2>/dev/null &
INFLIGHT_PID=$!

# The HUP must not be sent until the request has PROVABLY reached the upstream
# and the drip has begun -- otherwise, on a loaded runner, the request could
# arrive at nginx AFTER the reload and still return the expected 200/body,
# certifying "a request spanned the reload" while none did. A bare sleep cannot
# prove this: it is a wall-clock guess that races the request on exactly the
# hosts where the ordering is fragile.
#
# The falsifiable ordering oracle is the backend JOURNAL. fakesrv writes a
# {"ev":"send",...} record (flushed per record) the moment it puts the FIRST
# byte of the reply on the wire back toward nginx -- a strictly stronger event
# than {"ev":"cmd",...,"cmd":"get",...}, which proves only that the get was
# RECEIVED. Waiting for "send" proves the dripped reply is genuinely in flight
# before the HUP: the backend has begun writing a body it will take ~3 s to
# finish, so the request is provably still open when the signal lands. (AUD-10:
# the old "cmd" oracle could go green on a get that arrived a moment before the
# drip could start, so no reply was actually mid-flight across the reload.)
#
# Fixed-step counted iterations, never a wall-clock diff (same discipline as
# prober_wait_listen): a loaded runner performs the same number of attempts.
SEND_SEEN=0
for ((i = 0; i < 100; i++)); do            # 100 * 50 ms = 5 s ceiling
    if [ -n "$PROBER_BACKEND_JOURNAL" ] \
       && grep -q '"ev":"send"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null; then
        SEND_SEEN=1
        break
    fi
    sleep 0.05
done
# The "send" journal record is append-only: it proves a reply STARTED dripping
# at some point this run, but not that the request is STILL in flight right now,
# at the instant before the HUP. A mutation that fully joined the request before
# reloading would leave that record in place and still pass every downstream
# oracle -- certifying a reload-survival that never straddled the signal (the
# latent vacuity fixed in G6d's usr2-mid-transfer by ALSO asserting the in-flight
# bg pid is alive at signal-delivery time). So ok 1 requires BOTH: the send began
# AND the background client is still running (has not yet received the full
# dripped body) at the moment we are about to send the HUP. The drip takes ~3 s;
# the client cannot have completed unless the reply was NOT actually in flight.
INFLIGHT_ALIVE=0
if kill -0 "$INFLIGHT_PID" 2>/dev/null; then
    INFLIGHT_ALIVE=1
fi
if [ "$SEND_SEEN" -eq 1 ] && [ "$INFLIGHT_ALIVE" -eq 1 ]; then
    echo "ok 1 - the in-flight reply was dripping AND the request was still open at reload time"
elif [ "$SEND_SEEN" -ne 1 ]; then
    echo "not ok 1 - the upstream never started dripping its reply before the reload"
    echo "# backend journal recorded no send within 5 s; ordering precondition unmet"
    FAILED=$((FAILED + 1))
else
    echo "not ok 1 - the in-flight request had already completed before the reload was sent"
    echo "# the background client exited before the HUP: nothing straddled the signal"
    FAILED=$((FAILED + 1))
fi

# --- reload underneath the in-flight request ------------------------------
# prober_signal_wait sends SIGHUP to the master and blocks until a DIFFERENT
# worker pid answers the probe -- i.e. the reload has been fully absorbed --
# or times out. A timeout here is a real failure: the reload never landed.
if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" 5000; then
    echo "ok 2 - the reload was absorbed while a request was in flight"
else
    echo "not ok 2 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- join the in-flight request -------------------------------------------
# It must have completed. The body check below is the real assertion, but a
# bare `wait` on a hung request would never reach it (AUD-09): if the reload
# dropped the request and the upstream never closes, the background client
# blocks forever and so does this driver, consuming the whole CI job instead of
# reporting a bounded failure. Poll for the background shell to exit within a
# deadline; if it overruns, KILL it and fall through -- the truncated/empty
# $INFLIGHT then fails the assertion below, which is the correct verdict for a
# request that never completed.
join_deadline=$(( SECONDS + 10 ))
while kill -0 "$INFLIGHT_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        # Kill the whole subtree, not just the subshell. The background job is
        # `( ... cat <&3 ) &`, and `cat` is a CHILD of that subshell blocked on
        # the socket read; killing only $INFLIGHT_PID would orphan the cat,
        # which keeps the fd open and can go on writing to $INFLIGHT. Reap the
        # children first (job control is off in a script, so there is no process
        # group to signal), then the subshell.
        pkill -P "$INFLIGHT_PID" 2>/dev/null || true
        kill "$INFLIGHT_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$INFLIGHT_PID" 2>/dev/null || true

# The response must be a complete, correct 200 carrying the full seeded value.
# A reload that dropped the in-flight request would leave a truncated body, a
# 502, or an empty file -- each of which fails this single check.
if grep -q '^HTTP/1.1 200' "$INFLIGHT" \
   && grep -q '0123456789abcdefghijklmnopqrstuvwxyzABCD' "$INFLIGHT"; then
    echo "ok 3 - the in-flight response completed intact across the reload"
else
    echo "not ok 3 - the in-flight response was dropped or truncated by the reload"
    sed 's/^/# /' "$INFLIGHT" | head -20
    FAILED=$((FAILED + 1))
fi

# --- the reload did not crash a worker ------------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit path
# is asserted separately here: a clean reload logs the old worker leaving via
# "gracefully shutting down" / "exiting", never a signal-death line.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 4 - a worker died by signal during the reload"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 4 - no worker died by signal across the reload"
fi

# --- the in-flight request hit the upstream exactly once ------------------
# Counted BEFORE the post-reload prober leg runs (that leg issues its own get,
# which would inflate the tally). If the reload had dropped the in-flight
# request and nginx re-issued it upstream -- or retried it after the new worker
# came up -- the backend journal would carry a SECOND {"ev":"cmd",...,"cmd":
# "get",...}. Exactly one proves the single client request crossed the reload as
# one upstream exchange, not two. A zero here is impossible once ok 1 passed (it
# required a send, which requires a received get); the guard is against >1.
GET_CMDS=0
if [ -n "$PROBER_BACKEND_JOURNAL" ]; then
    GET_CMDS=$(grep -c '"ev":"cmd"[^}]*"cmd":"get"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null || true)
fi
if [ "$GET_CMDS" -eq 1 ]; then
    echo "ok 5 - the backend served the in-flight request exactly once across the reload"
else
    echo "not ok 5 - the backend saw the in-flight get $GET_CMDS times (expected 1: re-issued across the reload?)"
    FAILED=$((FAILED + 1))
fi

# --- post-reload coherence (prober, folded in as diagnostics) -------------
# Runs a plain strict case AFTER the reload has been absorbed: the new worker
# serves a correct 200, leaks no descriptor, and logs nothing on the error path
# in the window around the request. The pid oracle here is STRICT on purpose --
# by the time this runs a single post-reload worker is answering, so both of
# the case's probe snapshots see that same worker and "same worker pid" is the
# correct, stronger assertion. pid_may_change would be a no-op here (there is no
# reload WITHIN this case's before/after window), so it is deliberately absent:
# the reload-survival claims this scenario exists to make are the driver's ok
# 1-3 above, which straddle the signal; the prober leg only proves the server
# came back HEALTHY, not that a single case spanned the reload.
STATUS=0
# PIPESTATUS, not $?: a bare `./prober | sed` would have $? report sed's exit,
# which is always 0, silently discarding a red prober leg -- the exact vacuous
# shape this driver guards against elsewhere.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

# The scenario is red if ANY driver assertion failed OR the prober leg did.
if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
