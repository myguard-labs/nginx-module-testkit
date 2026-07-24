#!/usr/bin/env bash
#
# Scenario: reload SOAK -- the server is reloaded (SIGHUP) 100 times in a row
# WHILE a background load loop keeps a stream of requests in flight. This is the
# reload-cycle scenario's idle series pushed to two extremes at once: the
# reload count (8 -> 100, so a per-cycle leak is an unmistakable climb rather
# than a handful of steps that noise could hide) and CONCURRENT TRAFFIC across
# every signal (reload-cycle reloads an otherwise-idle server, and a cycle that
# is torn down with connections mid-flight exercises paths -- request cleanup on
# the retiring worker, the handover of the listen socket while it is being
# accept()ed on -- that an idle reload never touches).
#
# THE ORACLES, and why each is the shape it is:
#
#   Worker cycle-pool counters (cycle_used / cycle_blocks / cycle_large),
#   EXACT-equal across the whole 100-reload series. Each reload's worker parses
#   the SAME config with the SAME binary, so a healthy series produces identical
#   cycle-pool counters once each old cycle has DRAINED -- the same claim
#   reload-cycle makes, and true for the same reason. The snapshot is taken only
#   after prober_drain_wait confirms the previous cycle's worker is gone: a
#   reload is not finished when a new worker merely answers (the old worker is
#   still alive, and both it and the master hold handover-channel fds that
#   belong to no cycle -- see prober_drain_wait and reload-cycle's header). A
#   module leaking into ngx_cycle->pool per reload moves these monotonically;
#   the load makes no difference to the healthy value because per-REQUEST
#   allocations are freed back to the request pool, not the cycle pool.
#
#   NOTE the worker fd count is deliberately NOT in this exact-equal set, and
#   that is the one difference from reload-cycle's idle series. Under concurrent
#   load a background connection can be mid-flight on the freshly-drained worker
#   at snapshot time (10 vs 11 fds, observed on ~4 of 100 reloads), so an
#   exact-equal fd assertion would flake -- the drift would be one in-flight
#   request, not a leaked descriptor. A per-cycle fd LEAK still surfaces: it
#   climbs the MASTER fd count (oracle 6, taken while idle before and after) one
#   per reload, which neg-control B confirms. The worker-fd exactness is
#   reload-cycle's job precisely because it reloads idle; this scenario trades
#   it for the load coverage and leans on the master-side fd oracle instead.
#
#   MASTER descriptor count, flat before vs after the series. The worker-side
#   counters only ever see the cycle their worker was forked into; a cycle
#   leaked in the MASTER (which holds each old cycle alive until its workers
#   exit) is invisible to them. A leaked listening socket or old-cycle fd in the
#   master is deterministic and countable. Linux-only: skipped VISIBLY where
#   /proc is unreadable, never silently dropped.
#
#   No worker died by signal. prober_signal_wait cannot tell a reload from a
#   crash (a respawned worker has the same master as a reloaded one), so a
#   SIGSEGV/ABRT/BUS or "exited on signal" -- which is exactly what a reload
#   under load might trip that an idle reload would not -- is asserted from the
#   error log separately.
#
#   The load loop itself saw no failed request. A reload that dropped an
#   in-flight connection, or a worker that refused accept during the handover,
#   would show as a non-2xx or a connection error in the background stream. This
#   is the assertion that gives "under load" its teeth: without it the scenario
#   would be reload-cycle with a bigger count and some idle traffic alongside.
#
# Why a driver and not a .rule file: a reload happens BETWEEN prober
# invocations, and the state that matters is a comparison of probe snapshots
# taken on either side of a signal that no single prober case can straddle.
# Same rationale as reload-cycle.
#
# NEGATIVE CONTROLS. This scenario's leak oracles (cycle_used/blocks/large exact
# across the series, oracle 3; master fd flat, oracle 6) are the SAME probe
# fields, judged the same way, against the same t/module config-load site, as
# reload-cycle's -- only the reload count and the concurrent load differ. The
# two ref-.so leak controls that prove those gates fire are therefore inherited
# from reload-cycle (see its header + the s107 handoff):
#   A. static counter + ngx_palloc(cf->pool, 64 * n) per config load -> cycle_used
#      climbs +64 per reload, every other oracle green.
#   B. ngx_open_file("/dev/null") per config load, never closed -> worker fds and
#      the master fd count both climb, one per reload (oracle 6 here).
# What is NEW to this scenario is the load oracle (7) and the raised count, and
# those were proven here by DRIVER mutation (no .so rebuild needed), fixture
# restored after:
#   * force the load loop to record every request "bad" -> oracle 7 reds
#     (43459/43459 failed, exit 1); confirms it is not vacuously green.
#   * corrupt USED_REF to a value the series cannot match -> oracle 3 reds;
#     confirms the exact-equal comparison is live at 100 reloads under load.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="$ELOG"

# 100 reloads: enough that a per-cycle leak is a stark climb, and the series is
# still bounded work -- each reload costs a prober_signal_wait (returns when a
# new worker answers) plus a prober_drain_wait (returns when the old one exits),
# never a fixed sleep, so a fast box runs the whole soak in a few seconds.
RELOADS=100
WORKERS=1              # matches worker_processes in nginx.conf (drain target)

# FAILED accumulates every failing assertion; the verdict is the EXIT STATUS, so
# a `not ok` that did not also raise it would be vacuous.
FAILED=0

# --- helpers ---------------------------------------------------------------

snapshot() {           # read one probe snapshot into SNAP_* globals
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_PPID="$(prober_probe_field "$body" ppid || true)"
    # fds is deliberately not captured: it is not part of this scenario's
    # exact-equal set (see the header NOTE -- in-flight load makes it
    # non-deterministic), and the cycle-pool fields below already prove the
    # probe answered with a well-formed body.
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
}

warm() {               # a few plain requests so the worker pool has cycled
    local i
    for ((i = 0; i < 3; i++)); do
        (
            exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 0
            printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
            timeout 2 cat <&3 >/dev/null 2>&1 || true
        ) || true
    done
}

master_fds() {
    [ -r "/proc/$MASTER/fd" ] || return 1
    # shellcheck disable=SC2012  # /proc fd names are decimal ints, ls|wc is exact
    ls "/proc/$MASTER/fd" 2>/dev/null | wc -l
}

# --- background load loop --------------------------------------------------
# A shell loop firing serial keepalive-close requests, writing one line per
# request to $LOADLOG: "ok" for a 200, "bad" for anything else (non-200 or a
# connection error). Serial not parallel: this needs to keep SOME request in
# flight across each reload, not to benchmark throughput, and a serial loop is
# deterministic and cannot itself exhaust worker_connections. Torn down via its
# pid after the series.
LOADLOG="$PROBER_PREFIX/load.log"
: > "$LOADLOG"
LOAD_STOP="$PROBER_PREFIX/load.stop"
rm -f "$LOAD_STOP"

load_loop() {
    while [ ! -e "$LOAD_STOP" ]; do
        if (
            exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
            printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null || exit 1
            timeout 2 head -n1 <&3 2>/dev/null | grep -q '^HTTP/1.1 200'
        ); then
            echo ok  >> "$LOADLOG"
        else
            echo bad >> "$LOADLOG"
        fi
    done
}

load_loop &
LOAD_PID=$!

# Stop the load loop no matter how the driver exits (a bailed snapshot, a signal)
# so it cannot outlive the server and spin against a dead port.
# shellcheck disable=SC2064  # expand LOAD_PID/LOAD_STOP now, at trap-set time
trap "touch '$LOAD_STOP' 2>/dev/null; kill $LOAD_PID 2>/dev/null || true" EXIT

# TAP plan:
#  1 all reloads absorbed
#  2 comparable snapshots were collected
#  3 worker cycle-pool counters identical across the series
#  4 every worker stayed a child of the same master
#  5 no worker died by signal
#  6 the master leaked no descriptor
#  7 the background load stream saw no failed request
echo "1..7"

# --- baseline --------------------------------------------------------------
warm
if ! snapshot; then
    echo "Bail out! the probe endpoint did not answer before the first reload"
    exit 1
fi
BASE_PPID="$SNAP_PPID"
M_FDS_BASE="$(master_fds || true)"

# --- the soak series -------------------------------------------------------
ABSORBED=0
PPID_STABLE=1
FIRST_SET=0
USED_REF=; BLOCKS_REF=; LARGE_REF=
DRIFT=""

for ((r = 1; r <= RELOADS; r++)); do
    if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" 5000; then
        ABSORBED=$((ABSORBED + 1))
    else
        echo "# reload $r was not absorbed within 5 s (no new worker answered)"
        continue
    fi

    # Wait for the previous cycle's worker to exit before any snapshot: a new
    # worker answering does not mean the old cycle is gone, and measuring during
    # the overlap reads handover fds as a leak. A drain timeout is a real failure.
    DRC=0
    prober_drain_wait "$MASTER" "$WORKERS" 10000 || DRC=$?
    if [ "$DRC" -ne 0 ] && [ "$DRC" -ne 2 ]; then
        echo "# reload $r: the previous cycle's workers had not drained after 10 s"
        DRIFT="$DRIFT
reload $r: drain-timeout"
    fi

    warm
    if ! snapshot; then
        echo "# reload $r: the probe endpoint did not answer afterwards"
        DRIFT="$DRIFT
reload $r: no-snapshot"
        continue
    fi

    if [ -n "$BASE_PPID" ] && [ "$SNAP_PPID" != "$BASE_PPID" ]; then
        PPID_STABLE=0
    fi

    if [ "$FIRST_SET" -eq 0 ]; then
        # The FIRST post-reload snapshot is the reference, not the pre-reload
        # baseline: a one-off startup allocation not repeated per reload would
        # otherwise read as a leak in reverse. The claim is reload K costs the
        # same as reload 1 for every K.
        USED_REF="$SNAP_USED"
        BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
        FIRST_SET=1
        continue
    fi

    drift_if() {   # NAME GOT WANT
        [ "$2" = "$3" ] && return 0
        DRIFT="$DRIFT
reload $r: $1 = $2, want $3"
    }
    drift_if cycle_used   "$SNAP_USED"   "$USED_REF"
    drift_if cycle_blocks "$SNAP_BLOCKS" "$BLOCKS_REF"
    drift_if cycle_large  "$SNAP_LARGE"  "$LARGE_REF"
done

# --- stop the load loop and settle it -------------------------------------
touch "$LOAD_STOP"
kill "$LOAD_PID" 2>/dev/null || true
wait "$LOAD_PID" 2>/dev/null || true

# --- 1: every reload landed -----------------------------------------------
if [ "$ABSORBED" -eq "$RELOADS" ]; then
    echo "ok 1 - all $RELOADS reloads were absorbed under load"
else
    echo "not ok 1 - only $ABSORBED of $RELOADS reloads were absorbed"
    FAILED=$((FAILED + 1))
fi

# --- 2: comparable snapshots exist -----------------------------------------
if [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 2 - post-reload snapshots were collected for comparison"
else
    echo "not ok 2 - no post-reload snapshot could be taken; the comparisons below prove nothing"
    FAILED=$((FAILED + 1))
fi

# --- 3: worker cycle-pool counters flat across the series -----------------
if [ -z "$DRIFT" ] && [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 3 - worker cycle-pool counters identical across all $RELOADS reloads"
    echo "# cycle_used=$USED_REF cycle_blocks=$BLOCKS_REF cycle_large=$LARGE_REF"
else
    echo "not ok 3 - worker state drifted across reloads (per-cycle leak?)"
    printf '%s\n' "$DRIFT" | sed '/^$/d; s/^/# /'
    FAILED=$((FAILED + 1))
fi

# --- 4: every worker stayed a child of the same master --------------------
if [ -z "$BASE_PPID" ]; then
    echo "ok 4 - master parentage # SKIP this module .so emits no \"ppid\" field"
elif [ "$PPID_STABLE" -eq 1 ]; then
    echo "ok 4 - every post-reload worker was a child of the original master"
else
    echo "not ok 4 - a post-reload worker reported a different master (ppid changed from $BASE_PPID)"
    FAILED=$((FAILED + 1))
fi

# --- 5: no worker died by signal ------------------------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the soak"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the soak"
fi

# --- 6: the master leaked no descriptor -----------------------------------
M_FDS_END="$(master_fds || true)"
if [ -z "$M_FDS_BASE" ] || [ -z "$M_FDS_END" ]; then
    echo "ok 6 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$M_FDS_END" -eq "$M_FDS_BASE" ]; then
    echo "ok 6 - the master held $M_FDS_END descriptors before and after $RELOADS reloads"
else
    echo "not ok 6 - the master's descriptor count moved $M_FDS_BASE -> $M_FDS_END across $RELOADS reloads"
    FAILED=$((FAILED + 1))
fi

# --- 7: the background load stream saw no failed request ------------------
# This is what makes the scenario "under load" rather than reload-cycle with a
# bigger count: a reload that dropped an in-flight connection or refused accept
# during the handover shows here as a "bad" line. A run that recorded NO
# requests at all is a failure too -- an empty stream cannot have proven the
# server stayed up under it.
TOTAL="$(wc -l < "$LOADLOG" 2>/dev/null || echo 0)"
BAD="$(grep -c '^bad$' "$LOADLOG" 2>/dev/null || true)"
[ -n "$BAD" ] || BAD=0
if [ "$TOTAL" -gt 0 ] && [ "$BAD" -eq 0 ]; then
    echo "ok 7 - all $TOTAL background requests succeeded across the soak"
elif [ "$TOTAL" -eq 0 ]; then
    echo "not ok 7 - the background load stream recorded no requests; it proved nothing"
    FAILED=$((FAILED + 1))
else
    echo "not ok 7 - $BAD of $TOTAL background requests failed during the soak"
    FAILED=$((FAILED + 1))
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
