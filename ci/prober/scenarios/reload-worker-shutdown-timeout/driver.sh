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
# Two INDEPENDENT facts are asserted, not just the eventual close, to
# distinguish a worker_shutdown_timeout force-close from a merely-graceful idle
# close (the KEY discriminator vs reload-idle-keepalive/reload-mid-upload's
# oracles), one from each side of the connection:
#   (a) SERVER side, assertion 4 -- the old worker's own error-log lines say it
#       held the shutdown open for ~worker_shutdown_timeout: neither exiting in
#       the same second it began draining (an ordinary graceful close) nor
#       running past a ceiling derived from the configured timeout (some other
#       cause, or none). This is read from nginx's clock, so runner load cannot
#       perturb it -- see assertion 4's header for why that replaced a
#       driver-side survival window in s171.
#   (b) CLIENT side, assertion 5 -- the stalled socket comes back with a clean
#       EOF inside a window comfortably LONGER than worker_shutdown_timeout,
#       proving the force-close actually reached the peer.
# The negative
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
# reload is absorbed, (4) THE ATTRIBUTION ORACLE -- the old worker's own log
# lines show it held the shutdown open for ~worker_shutdown_timeout, which is
# neither an instant graceful drain nor an unbounded wait, (5) THE CLOSE
# ORACLE -- the stalled conn comes back with a clean EOF, so the force-close
# reached the client, (6) no worker died by signal, (7) the post-reload prober
# leg folded in as diagnostics.
#
# Assertion 5 DEPENDS on assertion 4: its polling window only opens once the
# shutdown has been attributed to the timer. If assertion 4 failed, 5 reports
# "not measured" rather than a duration, because nothing was polled -- the two
# failures are then ONE event, not two independent ones.
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
#   PRE_ITERS    HISTORICALLY the post-reload SURVIVAL window and the whole of
#                assertion 4's attribution: the conn had to still be alive after
#                PRE_ITERS*STEP for the eventual close to count as the timer's.
#                That is no longer what assertion 4 asserts (s171 -- see its
#                header): attribution now comes from nginx's own shutdown log
#                lines, so no driver-side wall-clock window carries an oracle
#                any more. PRE_ITERS survives ONLY as half of the poll budget
#                assertions 4 and 5 spend waiting for those lines and for the
#                reader to return. It is still derived from the conf rather than
#                hand-tuned, because a budget that did not track
#                worker_shutdown_timeout would start timing out the moment
#                someone raised the timeout.
#
# Raising the old shared constant would have fixed the first flake by weakening
# the oracle. Splitting them fixed that one without loosening anything; moving
# attribution off the wall clock entirely is what fixed the second.
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
# `10#` forces base 10. Without it bash reads a leading-zero literal as OCTAL,
# and nginx accepts both spellings -- verified with `nginx -t`, so each of these
# reaches this line through a conf the harness booted happily:
#   `08s` / `09s` -> "value too great for base", killing the driver under
#                    `set -e` with no TAP output at all;
#   `010s`        -> WORSE, because it does not error: nginx reads 10 seconds,
#                    this would read 8, and every window below would derive
#                    from a number the server never used.
# The digit-only check above cannot catch either -- both are digit-only.
WST_MS=$(( 10#$WST_NUM * WST_MUL ))
PRE_ITERS=$(( WST_MS / 2 / STEP_MS ))
if [ "$PRE_ITERS" -lt 1 ]; then
    echo "Bail out! worker_shutdown_timeout ($WST) is too short to poll at" \
         "${STEP}s granularity -- assertions 4 and 5 would have no poll budget" \
         "to wait for the shutdown log lines in"
    exit 1
fi
# Assertion 4 compares whole-second log timestamps, so a sub-second
# worker_shutdown_timeout cannot be told from an instant graceful drain: both
# land in the same second and both read as delta 0. Refuse rather than emit an
# assertion whose failure would be a resolution artifact of the error log.
if [ "$WST_MS" -lt 1000 ]; then
    echo "Bail out! worker_shutdown_timeout ($WST) is under 1s, but nginx's" \
         "error log timestamps are whole seconds only -- assertion 4 could not" \
         "distinguish the timer firing from an ordinary graceful drain"
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

# --- assertion 4: the OLD WORKER'S OWN SHUTDOWN took ~worker_shutdown_timeout
# --- (attribution: the close came from the timer, not from anything else) ---
#
# WHY THIS IS NOT A LIVENESS POLL ANY MORE (s171). Until this revision assertion
# 4 asked "is $REAL_PID still alive PRE_ITERS*STEP (=1.0s) after
# prober_signal_wait returned?" and inferred attribution from a survival floor.
# That oracle was BOTH flaky and weaker than it looked:
#
#   * It measured the DRIVER's wall clock, not the server's. The 1.0s floor and
#     the 2s timer do not even share a start point -- the timer is armed when the
#     old worker processes SIGQUIT, while the floor starts whenever the driver
#     got scheduled after prober_signal_wait returned. On a loaded shared runner
#     the gap between those two moments eats the margin and the conn is observed
#     gone inside the floor, so the scenario went red with a byte-identical
#     signature on source that was PROVEN good (PR #210 carried PR #207's diff
#     verbatim and passed the same cell in the same hour that #207 and #211
#     failed it). A scheduling flake, definitively -- issues.md.
#   * Widening the floor was the obvious fix and is the WRONG one: the floor IS
#     the attribution, so a wider floor against the same 2s timer buys stability
#     by deleting the property being asserted. Stable-but-vacuous is the exact
#     failure class this repo exists to catch.
#
# So attribution moves to the ONE clock that cannot be perturbed by runner load:
# nginx's own. Two notice lines from the OLD WORKER'S OWN PID bracket the timer
# exactly, and reading them is reading the server's account of its own shutdown:
#
#   "<pid>#0: gracefully shutting down"  -- logged by ngx_worker_process_cycle()
#       on the SAME statement that calls ngx_set_shutdown_timer(), which is what
#       arms worker_shutdown_timeout. This line IS the timer's start, not an
#       approximation of it.
#   "<pid>#0: exiting"                   -- logged once ngx_event_no_timers_left()
#       goes NGX_OK. For a stalled, unsalvageable request that only becomes true
#       after ngx_shutdown_timer_handler() has force-closed the connection. This
#       line IS the timer having fired.
#
# (Both verified against the 1.31.4 source this scenario builds:
# src/os/unix/ngx_process_cycle.c and ngx_set_shutdown_timer/
# ngx_shutdown_timer_handler in src/core/ngx_cycle.c.)
#
# The interval between them is therefore worker_shutdown_timeout as the SERVER
# measured it. A descheduled driver cannot corrupt it: the timestamps were
# written before this code looked at them, so a late read yields the same two
# numbers. That removes the flake at its root instead of padding around it.
#
# THE ORACLE IS TWO-SIDED, AND THAT IS LOAD-BEARING -- a lower bound alone is
# vacuous, verified rather than assumed. With `worker_shutdown_timeout 0`
# nginx's `if (ccf->shutdown_timeout)` arms NO timer at all, the stalled conn is
# never force-closed, and the old worker sat in "gracefully shutting down" for
# 6s until the harness tore the socket down -- a delta of SIX seconds. A
# "delta >= 1s" oracle would have called that a pass. So both ends are asserted:
#
#   lower  the shutdown must not be INSTANT. An ordinary graceful drain (nothing
#          unsalvageable in flight) reaches ngx_event_no_timers_left() on its
#          first loop pass and logs "exiting" in the SAME second -- delta 0.
#          Observed in this scenario's own log every run: the NEW worker, which
#          never held a stalled conn, does exactly that. Delta > 0 is what
#          separates "the timer held the shutdown open" from "there was nothing
#          to wait for".
#   upper  the shutdown must not be UNBOUNDED. The timer promises the worker
#          leaves at ~worker_shutdown_timeout; a delta far past it means
#          something other than this timer ended the wait (or nothing did).
#
# GRANULARITY IS WHY THE BOUNDS ARE WHOLE SECONDS AND NOT A TOLERANCE BAND.
# nginx's error log carries whole-second timestamps only -- ngx_cached_err_log_time
# is formatted "%4d/%02d/%02d %02d:%02d:%02d" with no msec field (src/core/ngx_times.c),
# so a true 2s interval reads as 1, 2 or 3 depending purely on where the second
# boundaries fell. Asserting an exact value against that would manufacture a NEW
# flake out of rounding. The bounds below are the widest pair that still
# excludes both failure modes, and they are DERIVED from the conf's own
# WST_MS so a later edit to nginx.conf moves them automatically:
#
#   delta >= 1                      not instant (excludes the graceful path,
#                                   whose delta is 0)
#   delta <= WST seconds + 2        not unbounded (excludes the timer-disabled
#                                   path, whose delta ran to 6s at WST=2s where
#                                   this ceiling is 4)
#
# WHAT ATTRIBUTION IS KEPT vs THE OLD ORACLE: strictly more. The old form proved
# only "the conn outlived a driver-side 1.0s floor" and inferred the rest. This
# form reads the server's own start-of-timer and end-of-timer records for the
# specific worker that was draining, and requires the interval between them to
# be consistent with the configured timeout and inconsistent with both an
# immediate drain and a never-firing timer. Nothing was traded away for
# stability.
WST_S=$(( WST_MS / 1000 ))
# Ceiling in whole seconds. +2 absorbs the two second-boundary roundings (one at
# each timestamp) that the log's whole-second resolution can introduce.
DELTA_MAX=$(( WST_S + 2 ))

# Wait for BOTH lines to exist before measuring -- the old worker is still
# draining when prober_signal_wait returns (its verdict is only "a NEW worker
# answers"), so "exiting" has certainly not been written yet. Poll on the same
# fixed-step counted budget as every other wait here, bounded by the same
# POST_ITERS window assertion 5 uses for the close itself.
#
# The pid is taken from the "gracefully shutting down" line rather than assumed,
# so the two timestamps are guaranteed to describe ONE worker's shutdown. Two
# different workers' lines would otherwise be subtractable into a meaningless
# interval.
OLD_WORKER=""
GRACE_T=""
EXIT_T=""
for ((i = 0; i < PRE_ITERS + POST_ITERS; i++)); do
    if [ -z "$OLD_WORKER" ]; then
        # `|| true`: no match yet is "not yet", not a failure -- and under
        # `set -o pipefail` a bare non-matching sed/grep would kill the driver.
        OLD_WORKER="$(sed -n 's/^[0-9\/]\{10\} [0-9:]\{8\} \[notice\] \([0-9]\{1,\}\)#[0-9]\{1,\}: gracefully shutting down$/\1/p' \
            "$ELOG" 2>/dev/null | head -n 1 || true)"
        if [ -n "$OLD_WORKER" ]; then
            GRACE_T="$(sed -n "s/^[0-9\/]\{10\} \([0-9:]\{8\}\) \[notice\] $OLD_WORKER#[0-9]\{1,\}: gracefully shutting down$/\1/p" \
                "$ELOG" 2>/dev/null | head -n 1 || true)"
        fi
    fi
    if [ -n "$OLD_WORKER" ]; then
        EXIT_T="$(sed -n "s/^[0-9\/]\{10\} \([0-9:]\{8\}\) \[notice\] $OLD_WORKER#[0-9]\{1,\}: exiting$/\1/p" \
            "$ELOG" 2>/dev/null | head -n 1 || true)"
        # A plain `[ -n "$EXIT_T" ] && break` here would be the LAST statement
        # of this `if` block, so on the not-yet path the false test makes the
        # block's status 1 -- which under `set -e` kills the driver mid-TAP, and
        # a shell that dies mid-stream reads as a PASS to a runner keying off
        # the plan. Spelled as a full if/fi so no branch can leave a nonzero
        # status behind. shellcheck cannot see this class at all.
        if [ -n "$EXIT_T" ]; then
            break
        fi
    fi
    sleep "$STEP"
done

# HH:MM:SS -> seconds since midnight. `10#` on every field for the same
# leading-zero-is-octal reason the timeout parse above documents: "08" and "09"
# are ordinary in a timestamp and would otherwise abort the driver under set -e.
hms_to_s() {
    local hms=$1
    printf '%s' "$(( 10#${hms:0:2} * 3600 + 10#${hms:3:2} * 60 + 10#${hms:6:2} ))"
}

survived_pre=0
if [ -z "$OLD_WORKER" ] || [ -z "$GRACE_T" ]; then
    echo "not ok 4 - the old worker never logged \"gracefully shutting down\" (no reload reached it; nothing to attribute)"
    FAILED=$((FAILED + 1))
elif [ -z "$EXIT_T" ]; then
    echo "not ok 4 - the old worker ($OLD_WORKER) began shutting down at $GRACE_T but never logged \"exiting\" within $(( (PRE_ITERS + POST_ITERS) * STEP_MS ))ms (worker_shutdown_timeout $WST never fired)"
    FAILED=$((FAILED + 1))
else
    GRACE_S=$(hms_to_s "$GRACE_T")
    EXIT_S=$(hms_to_s "$EXIT_T")
    DELTA=$(( EXIT_S - GRACE_S ))
    # Midnight wrap: the two lines are at most a few seconds apart, so a
    # negative delta can only mean the clock rolled over 00:00:00 between them.
    # if/fi, not `[ ] && x`, for the set -e reason documented in the poll loop.
    if [ "$DELTA" -lt 0 ]; then
        DELTA=$(( DELTA + 86400 ))
    fi

    if [ "$DELTA" -lt 1 ]; then
        echo "not ok 4 - the old worker ($OLD_WORKER) exited in the same second it began shutting down ($GRACE_T -> $EXIT_T, ${DELTA}s): an ordinary graceful drain, NOT worker_shutdown_timeout $WST"
        FAILED=$((FAILED + 1))
    elif [ "$DELTA" -gt "$DELTA_MAX" ]; then
        echo "not ok 4 - the old worker ($OLD_WORKER) took ${DELTA}s to exit ($GRACE_T -> $EXIT_T), past the ${DELTA_MAX}s ceiling for worker_shutdown_timeout $WST: the close is not attributable to that timer"
        FAILED=$((FAILED + 1))
    else
        survived_pre=1
        echo "ok 4 - the old worker ($OLD_WORKER) held the shutdown open ${DELTA}s ($GRACE_T -> $EXIT_T), consistent with worker_shutdown_timeout $WST and not with an instant graceful drain"
    fi
fi

# --- assertion 5: THE CLOSE ORACLE ------------------------------------------
# Assertion 4 is the SERVER's account of the timer (its own two log lines);
# this is the CLIENT's, and they are deliberately independent. Poll up to a
# further POST_ITERS * STEP = 5.0s for the stalled reader to come back, then
# require it came back on a clean EOF. The draining old worker must force-close
# the stalled conn once the timer fires, since it can never otherwise finish
# exiting -- so a worker that logged the timer interval in assertion 4 while the
# client's socket stayed open would be a real contradiction worth failing on.
#
# By the time assertion 4 passed, the old worker has already logged "exiting",
# so this loop normally finds the reader gone on its first pass; the window
# stays wide because the reader's own wakeup is a separate scheduling event.
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
if [ "$survived_pre" -eq 0 ]; then
    # Assertion 4 could not attribute the shutdown to worker_shutdown_timeout,
    # so the polling loop above never ran and NOTHING here was measured. Naming
    # a duration in this branch would be arithmetic dressed up as an
    # observation, contradicting assertion 4 and sending a reader hunting a hang
    # that never happened. Report the dependency instead.
    echo "not ok 5 - not measured: the shutdown was not attributable to worker_shutdown_timeout, so the close window never opened (see not ok 4)"
    # The reader subshell may still be alive here (unlike the old liveness-poll
    # form of assertion 4, a failed attribution says nothing about the socket),
    # and its `cat` child can outlive it as an orphan holding the fd. Reap the
    # subtree, and kill the subshell itself rather than `wait`-ing on a child
    # that may be blocked forever on a socket nobody closed.
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    FAILED=$((FAILED + 1))
elif [ "$closed" -eq 1 ] && [ -e "$REAL_CLOSED" ]; then
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
