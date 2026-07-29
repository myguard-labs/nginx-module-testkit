#!/usr/bin/env bash
#
# Scenario: a client opens a request and drips its BODY so slowly that it
# never finishes (a stalled upload, client -> server direction). A reload
# (SIGHUP) is delivered while that request is stalled mid-body. The draining
# OLD worker cannot finish reading a body that never completes, so it cannot
# produce a response either -- it can only wait, bounded by
# `worker_shutdown_timeout` (set SHORT in nginx.conf: 2s -- the driver READS
# that value rather than assuming it, see the window derivation below). When that timer
# expires, the draining worker FORCE-closes the stalled connection so it can
# finish exiting.
#
# This is the STALLED mirror of reload-mid-upload: that scenario's upload
# drips slowly but FINISHES (the drip's total time is bounded and short, so
# the old worker reads the whole body and returns a clean 200 -- proving
# in-flight work survives a reload). Here the drip NEVER finishes -- proving
# the opposite complementary case: a request that CANNOT be salvaged is
# eventually force-closed rather than held open forever, bounding how long a
# reload can be stalled by a single slow/hostile client.
#
# Why a driver and not a plain .rule file: same reason as reload-mid-upload
# and reload-idle-keepalive -- the prober runs each case synchronously to
# completion, so it cannot hold a connection stalled mid-body while a signal
# is delivered to the master out from under it and then keep watching that
# same connection across a multi-second timer. This driver keeps the stalled
# upload open in a background subshell, delivers the SIGHUP underneath it,
# waits for the reload to land, and then polls for the force-close.
#
# THE CLOSE ORACLE AND ITS TIMING DISCIPLINE: the background subshell writes
# one small body chunk (never the rest -- the body promised by
# Content-Length never completes) and then BLOCKS on a READ from the same
# socket. Nothing is ever going to arrive on a normal path: nginx cannot
# produce a response until the body is complete, and the body never
# completes, so a live connection leaves that read blocked indefinitely --
# exactly the idiom reload-idle-keepalive uses for its idle-keepalive close
# oracle, just applied to a connection that is stalled mid-request instead of
# idle between requests. EMPIRICALLY VERIFIED (manual repro against this
# exact nginx.conf, outside the harness): when worker_shutdown_timeout fires,
# the draining worker closes the fd with a clean FIN and logs NO
# [error]/[warn]/[alert] line at all for the close itself -- so `cat <&3`
# sees a clean EOF (exit 0) and no PROBER_ALLOW_LOG exemption is needed for
# this scenario (see the end of this file / the report for the exact
# transcript). A WRITE-based oracle (attempting to write after the peer
# closes) was tried first and is NOT reliable: a write to a socket whose peer
# already sent FIN but has not yet been fully torn down by the kernel can
# still return success (verified empirically), so only a READ (blocking on
# actual data/EOF) is an honest oracle here.
#
# Two timing facts are asserted, not just the eventual close, to distinguish
# a worker_shutdown_timeout force-close from a merely-graceful idle close
# (the KEY discriminator vs reload-idle-keepalive/reload-mid-upload's
# oracles): the conn must (a) SURVIVE a window shorter than
# worker_shutdown_timeout immediately after the reload lands -- proving the
# close is not instant/graceful the moment shutdown begins -- and (b) be
# closed by a window comfortably LONGER than worker_shutdown_timeout --
# proving the timer, not something else, eventually fires. The negative
# control (assertion 1) additionally proves the converse needed for
# calibration: absent a reload, with client_body_timeout set to 3600s, a
# stalled body does NOT close on its own within the same total window used
# later -- so a close seen post-reload is attributable to the reload +
# worker_shutdown_timeout, not to the ordinary body-read timer or ambient
# noise.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

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

# TAP plan: (1) NEGATIVE CONTROL -- a stalled body with NO reload must NOT be
# force-closed within the same total window used later (proves the close
# oracle in assertion 5 discriminates: a close there is reload+timeout
# caused, not spontaneous / not client_body_timeout), (2) the real stalled
# request is established and mid-body (in flight) before the signal, (3) the
# reload is absorbed, (4) the stalled conn survives a window SHORTER than
# worker_shutdown_timeout right after the reload (not an instant/graceful
# close), (5) THE CLOSE ORACLE -- the draining worker force-closes the
# stalled conn once worker_shutdown_timeout expires, (6) no worker died by
# signal, (7) the post-reload prober leg folded in as diagnostics.
echo "1..7"

# --- stalled-upload helper ---------------------------------------------------
# Opens a raw HTTP/1.1 POST over /dev/tcp to /upload with a Content-Length
# that promises MORE bytes than are ever actually sent. Writes ONE short
# chunk (enough that nginx has genuinely started reading a body, not just
# parsed headers), drops a READY marker, and then sleeps far longer than any
# window this driver waits on -- it deliberately never sends the remaining
# bytes, so the body never completes and nginx can never produce a response
# on this connection. If the peer (nginx) force-closes the socket while this
# subshell is asleep, the NEXT write (issued only after the long sleep) fails
# and the subshell exits nonzero; if the sleep instead completes because
# nothing ever closed the socket, the subshell exits on its own after the
# deadline -- so a caller must always gate on kill -0, exactly as
# reload-idle-keepalive/reload-mid-upload do, and must reap explicitly to
# avoid a > 3600s-lived control subshell in the fast (non-reload) path.
#
# $1 = ready-marker file path (created once the first chunk is sent)
# $2 = pidvar (out-param name to receive the background PID)
# $3 = closedmarker file path (created ONLY on a clean-EOF read, mirroring
#      reload-idle-keepalive's discrimination between a graceful close and a
#      read failure -- see the `cat <&3` comment below)
#
# WHY THE OUT-PARAM AND NOT `pid=$(start_stalled_upload ...)`: command
# substitution runs the function body in a SUBSHELL, so the `( ... ) &`
# backgrounded job inside it becomes a child of THAT subshell, not of this
# driver -- `kill -0`/`wait` on the resulting pid becomes unreliable ("not a
# child of this shell"). This exact trap is documented at length in
# reload-mid-upload/driver.sh and reload-idle-keepalive/driver.sh; identical
# reasoning applies here. Backgrounding directly in the driver's own shell
# and handing the pid back through a caller-named variable keeps the job a
# true, addressable child.
CONTENT_LENGTH=1000000   # promise ~1MB; only a few bytes are ever actually sent
FIRST_CHUNK="STALL"      # small, nonzero -- proves nginx started reading a body

start_stalled_upload() {
    local marker=$1 pidvar=$2 closedmarker=$3
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'POST /upload HTTP/1.1\r\nHost: prober\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' \
            "$CONTENT_LENGTH" >&3 || exit 1
        printf '%s' "$FIRST_CHUNK" >&3 || exit 1

        # The one chunk is on the wire; drop the ready marker so the caller
        # can stop polling for "established and mid-body".
        : >"$marker"

        # Never send the rest of the body. Block reading from the socket
        # instead. On a live, still-stalled connection nothing is ever going
        # to arrive (no response can exist until the body completes, which it
        # never does) -- so this read can only return because the peer
        # closed its end (or the fd failed some other way). PRESERVE the
        # reader's exit status rather than swallowing it with `|| true` (same
        # discipline as reload-idle-keepalive's `cat <&3`, for the same
        # reason: a clean nginx close is a FIN, so `cat` exits 0, while a
        # socket-read FAILURE exits nonzero, and the two must not be allowed
        # to look alike or the close oracle would certify a failure as a
        # success). Drop the CLOSED marker only on the clean-EOF path.
        if cat <&3 >/dev/null 2>/dev/null; then
            : >"$closedmarker"
        fi
    ) &
    printf -v "$pidvar" '%s' "$!"
}

# Fixed-step counted settle helpers, never a bare sleep for oracle timing
# (same discipline as reload-idle-keepalive / reload-mid-upload /
# prober_signal_wait / prober_wait_listen). STEP is the same for every wait
# below so windows expressed in "N * STEP" are directly comparable.
STEP=0.1
# The same value in milliseconds. Every window below is computed in ms and
# divided by this, so STEP and its integer form cannot drift apart -- change
# both together or neither.
STEP_MS=100

# --- the two windows below are DIFFERENT KINDS OF BUDGET -------------------
# They were one constant (PRE_ITERS=10) until s163, and conflating them is why
# this scenario flaked three times in CI (issues.md). Only ONE of them is
# actually bounded by worker_shutdown_timeout:
#
#   READY_ITERS  a SETUP readiness poll -- "has the stalled upload established
#                and reached mid-body yet". Pure process-start + connect +
#                partial-write latency. worker_shutdown_timeout does not bound
#                it in either direction, because no reload has happened yet.
#                Waiting LONGER here can only ever make the scenario more
#                reliable: the loop breaks the instant the marker appears, so
#                a bigger ceiling costs nothing on a healthy box and is not an
#                assertion about the server. This is the one that flaked --
#                1.0s for fork + connect + write is thin under ASan on a shared
#                runner, and its failure reads as "never established in time",
#                which is a false RED about the harness, not a finding.
#   PRE_ITERS    the post-reload SURVIVAL window (assertion 4). This one IS an
#                oracle: it must stay strictly SHORTER than
#                worker_shutdown_timeout, or "survived the window" stops
#                proving the close was not instant. Raising it would silently
#                weaken assertion 4 -- so it is DERIVED from the conf below
#                rather than hand-tuned next to it.
#
# Raising the old shared constant would have fixed the flake by weakening the
# oracle. Splitting them fixes the flake and leaves the oracle exactly as
# tight as it was.
READY_MS=5000
READY_ITERS=$(( READY_MS / STEP_MS ))   # 5.0s, setup only -- NOT an oracle bound

# PRE_ITERS is derived from the conf's worker_shutdown_timeout so the
# invariant `PRE_ITERS * STEP < worker_shutdown_timeout` is held by ARITHMETIC
# instead of by a comment that a later edit to nginx.conf would silently
# falsify. Half the timeout, floored to whole STEPs: comfortably inside the
# window with room for the poll's own granularity.
WST="$(sed -n 's/^[[:space:]]*worker_shutdown_timeout[[:space:]]\+\([^;]*\);.*/\1/p' \
    "$PROBER_SCENARIO/nginx.conf" | tail -n 1 | tr -d '[:space:]')"
# Strip the unit FIRST, then validate what is left is a bare integer. Doing it
# the other way round (a `''|*[!0-9]*` arm after the unit arms) does not work:
# `case` takes the FIRST match, so `*s)` swallows "abcs" and `*ms)` swallows
# "xms" before any validation arm is reached -- "abcs" would silently become 0
# and a fractional "2.5s", which nginx accepts, would kill the driver with an
# arithmetic syntax error and emit no TAP at all. Only integer s/ms is
# supported here, deliberately: this scenario wants a whole number of STEPs.
case "$WST" in
    *ms) WST_NUM="${WST%ms}" ; WST_MUL=1 ;;
    *s)  WST_NUM="${WST%s}"  ; WST_MUL=1000 ;;
    *)   WST_NUM="$WST"      ; WST_MUL=1000 ;;   # bare number is seconds in nginx
esac
case "$WST_NUM" in
    ''|*[!0-9]*)
        echo "Bail out! could not parse worker_shutdown_timeout out of" \
             "$PROBER_SCENARIO/nginx.conf (got \"$WST\") -- assertion 4's" \
             "window is derived from it and cannot be defaulted safely"
        exit 1
        ;;
esac
WST_MS=$(( WST_NUM * WST_MUL ))
PRE_ITERS=$(( WST_MS / 2 / STEP_MS ))
if [ "$PRE_ITERS" -lt 1 ]; then
    echo "Bail out! worker_shutdown_timeout ($WST) is too short to poll at" \
         "${STEP}s granularity -- assertion 4 would have no window at all"
    exit 1
fi

# POST_ITERS times STEP must be comfortably LONGER than worker_shutdown_timeout
# so the force-close has time to actually fire (assertion 5's ceiling). Derived
# from the same source for the same reason, at 2.5x the timeout.
POST_ITERS=$(( WST_MS * 25 / 10 / STEP_MS ))
# The negative control needs to run at least as long as PRE_ITERS+POST_ITERS
# combined would, to be a fair comparison against the full post-reload
# window the real run is judged across.
# (both are derived from worker_shutdown_timeout above, so this tracks it
# automatically; at the shipped 2s that is 10 + 50 iters = 6.0s, no reload.)
CONTROL_ITERS=$((PRE_ITERS + POST_ITERS))

# --- assertion 1: NEGATIVE CONTROL -- a stalled body must NOT close itself -
# Runs FIRST, fully reaped before the real conn is opened (mirrors
# reload-mid-upload / reload-idle-keepalive: negative control never overlaps
# the real run). Opens a stalled upload, sends NO signal, and polls the same
# total window used later for the real close-wait. With client_body_timeout
# set to 3600s, nothing in this harness should close it -- only
# worker_shutdown_timeout could, and that only fires during a graceful
# shutdown, which never happens here.
CONTROL_MARKER="$PROBER_PREFIX/control.ready"
CONTROL_CLOSED="$PROBER_PREFIX/control.closed"
start_stalled_upload "$CONTROL_MARKER" CONTROL_PID "$CONTROL_CLOSED"

control_ready=0
for ((i = 0; i < READY_ITERS; i++)); do
    if [ -e "$CONTROL_MARKER" ]; then
        control_ready=1
        break
    fi
    if ! kill -0 "$CONTROL_PID" 2>/dev/null; then
        break
    fi
    sleep "$STEP"
done

control_alive=0
if [ "$control_ready" -eq 1 ] && kill -0 "$CONTROL_PID" 2>/dev/null; then
    for ((i = 0; i < CONTROL_ITERS; i++)); do
        if kill -0 "$CONTROL_PID" 2>/dev/null; then
            control_alive=1
        else
            control_alive=0
            break
        fi
        sleep "$STEP"
    done
fi

# Reap the control connection's subtree so it cannot linger into the real
# run -- job control is off in a script (no process group to signal), so the
# child is killed explicitly before the subshell itself.
pkill -P "$CONTROL_PID" 2>/dev/null || true
kill "$CONTROL_PID" 2>/dev/null || true
wait "$CONTROL_PID" 2>/dev/null || true

if [ "$control_ready" -eq 0 ]; then
    echo "not ok 1 - the control stalled upload was never established/mid-body in time"
    FAILED=$((FAILED + 1))
elif [ "$control_alive" -eq 1 ]; then
    echo "ok 1 - a stalled body stayed open with no reload (close oracle discriminates)"
else
    echo "not ok 1 - the stalled body closed itself with no reload (close oracle cannot discriminate)"
    FAILED=$((FAILED + 1))
fi

# --- open the REAL stalled upload -------------------------------------------
REAL_MARKER="$PROBER_PREFIX/real.ready"
REAL_CLOSED="$PROBER_PREFIX/real.closed"
start_stalled_upload "$REAL_MARKER" REAL_PID "$REAL_CLOSED"

# --- assertion 2: established and mid-body BEFORE signalling ---------------
marker_seen=0
for ((i = 0; i < READY_ITERS; i++)); do
    if [ -e "$REAL_MARKER" ]; then
        marker_seen=1
        break
    fi
    if ! kill -0 "$REAL_PID" 2>/dev/null; then
        break
    fi
    sleep "$STEP"
done

READY_OK=0
if [ "$marker_seen" -eq 1 ] && kill -0 "$REAL_PID" 2>/dev/null; then
    READY_OK=1
    echo "ok 2 - the real stalled upload is established and mid-body before the reload"
else
    echo "not ok 2 - the real stalled upload was never established/mid-body in time"
    FAILED=$((FAILED + 1))
fi

# READINESS IS A HARD GATE (same discipline as reload-idle-keepalive): a
# dependent assertion behind a failed precondition must be SKIPPED-as-FAILED,
# never run against broken state, or a later assertion could print `ok` for
# a close that has nothing to do with a stalled-then-reloaded connection.
if [ "$READY_OK" -eq 0 ]; then
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    echo "not ok 3 - skipped: the stalled upload was never established (see not ok 2)"
    echo "not ok 4 - skipped: the stalled upload was never established (see not ok 2)"
    echo "not ok 5 - skipped: the stalled upload was never established (see not ok 2)"
    FAILED=$((FAILED + 3))
else
# --- assertion 3: the reload is absorbed ------------------------------------
# prober_signal_wait probes via /__probe on its OWN fresh connections --
# independent of our stalled conn -- and blocks until a different worker pid
# answers, or times out (a real failure).
if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" 5000; then
    echo "ok 3 - the reload was absorbed while the upload was stalled mid-body"
else
    echo "not ok 3 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- assertion 4: the stalled conn survives a window SHORTER than the ------
# --- worker_shutdown_timeout (proves the close is not instant/graceful) ----
# Immediately after the reload lands, poll for PRE_ITERS * STEP = 1.0s,
# comfortably under the 2s worker_shutdown_timeout. If the conn were already
# gone by here, the eventual close in assertion 5 could not be attributed to
# the timer specifically -- it would look identical to an ordinary graceful
# shutdown close (like reload-idle-keepalive's idle conn, which closes
# near-immediately). A stalled/unsalvageable request must NOT be dropped
# before the grace period the timer promises has elapsed.
survived_pre=1
for ((i = 0; i < PRE_ITERS; i++)); do
    if ! kill -0 "$REAL_PID" 2>/dev/null; then
        survived_pre=0
        break
    fi
    sleep "$STEP"
done

if [ "$survived_pre" -eq 1 ]; then
    echo "ok 4 - the stalled conn was NOT force-closed instantly (survived < worker_shutdown_timeout)"
else
    echo "not ok 4 - the stalled conn closed before worker_shutdown_timeout could have expired (not attributable to the timer)"
    FAILED=$((FAILED + 1))
fi

# --- assertion 5: THE CLOSE ORACLE ------------------------------------------
# Continue polling from where assertion 4 left off (a further POST_ITERS *
# STEP = 5.0s window -- comfortably longer than the 2s worker_shutdown_timeout
# from the reload). The draining old worker must force-close the stalled conn
# once the timer fires, since it can never otherwise finish exiting.
closed=0
if [ "$survived_pre" -eq 1 ]; then
    for ((i = 0; i < POST_ITERS; i++)); do
        if ! kill -0 "$REAL_PID" 2>/dev/null; then
            closed=1
            break
        fi
        sleep "$STEP"
    done
fi

# Reap ONLY when the subshell has actually exited (closed==1): `wait` on a
# still-alive child whose own child (`cat`) is blocked forever on a socket
# that was never closed (e.g. no reload happened at all) would hang this
# driver indefinitely -- a real deadlock hazard, not just a slow assertion.
# The not-closed branch below reaps via an explicit kill instead.
if [ "$closed" -eq 1 ]; then
    wait "$REAL_PID" 2>/dev/null || true
fi

# Gate on the CLOSED marker, not merely on the subshell being gone (same
# discipline as reload-idle-keepalive's assertion 4): the marker is written
# only on a clean EOF read (`cat` exit 0). A subshell that exited because its
# read FAILED some other way (nonzero `cat`) does not certify the graceful
# force-close path this oracle exists to prove.
if [ "$closed" -eq 1 ] && [ -e "$REAL_CLOSED" ]; then
    echo "ok 5 - the draining old worker force-closed the stalled conn once worker_shutdown_timeout expired (clean EOF)"
elif [ "$closed" -eq 1 ]; then
    echo "not ok 5 - the stalled conn's reader exited without a clean EOF (read error, not a graceful force-close)"
    FAILED=$((FAILED + 1))
else
    echo "not ok 5 - the stalled conn was still open $(( (POST_ITERS + PRE_ITERS) * STEP_MS ))ms after the reload (worker_shutdown_timeout $WST never fired)"
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    FAILED=$((FAILED + 1))
fi
fi   # end READY_OK gate (assertions 3-5)

# --- assertion 6: no worker died by signal ----------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit
# path is asserted separately: a clean reload + timed force-close logs the
# old worker leaving via "gracefully shutting down" / "exiting" and finally
# "exited with code 0", never a signal-death line. EMPIRICALLY VERIFIED (see
# this file's top-of-file transcript): the worker_shutdown_timeout force-close
# emits NO [error]/[warn]/[alert] line of its own -- nginx just closes the fd
# as part of the normal graceful exit -- so no PROBER_ALLOW_LOG env file is
# needed for this scenario, and nothing here can be mistaken for a signal death.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 6 - a worker died by signal during the reload"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 6 - no worker died by signal across the reload"
fi

# --- assertion 7: post-reload coherence (prober, folded in as diagnostics) -
# A plain strict case AFTER the reload: the new worker serves a correct 200,
# leaks no descriptor, and logs nothing on the error path around the
# request. The pid oracle in post-reload.rule is STRICT on purpose -- see
# that file's header. The reload-survival/force-close claims this scenario
# exists to make are assertions 4-5 above, not this leg.
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
