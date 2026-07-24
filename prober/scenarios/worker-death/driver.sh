#!/usr/bin/env bash
#
# Scenario: worker-death blast radius -- the single worker is SIGKILLed while
# it is the one serving the probe, the master respawns it, and we assert that
# the death was contained: the master lived, the replacement runs the same
# config with the same cycle-pool footprint, and nothing ELSE died.
#
# This is the mirror image of every reload scenario in this tree. Those send
# SIGHUP and assert that NO worker died by signal; this one sends SIGKILL and
# asserts that EXACTLY ONE did -- the one we killed, by signal 9, and no other.
#
# THE ORACLES, and why each is the shape it is:
#
#   The kill actually landed (oracle 2, the NON-VACUITY control). A crash-
#   respawned worker keeps its master's pid -- MEASURED, not assumed (s74,
#   pid_may_change): SIGKILLing a worker of master M yields a replacement whose
#   ppid is still M, indistinguishable from a SIGHUP-respawned one. So "a
#   different pid answers" (oracle 1) canNOT tell a crash from a reload, and
#   "still a child of the same master" (oracle 6) is satisfied by a respawn.
#   Without a POSITIVE assertion that a worker exited on signal 9, every other
#   oracle here passes on a server that was never killed at all -- the whole
#   scenario would certify a no-op. Oracle 2 reads the exit-on-signal line out
#   of the error log and is what gives the scenario its teeth. It is asserted
#   from the log, SEPARATELY from any pid/ppid oracle, precisely because the
#   process-identity oracles are blind to it (s74 lesson).
#
#   No OTHER signal death (oracle 3). A contained kill produces exactly one
#   "exited on signal 9" line -- the worker we named. A SIGSEGV/ABRT/BUS, or a
#   SECOND signal-9 we did not send, means the death cascaded (the master
#   faulting while reaping, a respawn crashing on the inherited state). Oracle 2
#   proves a kill happened; oracle 3 proves nothing beyond the one we intended
#   did.
#
#   Cycle-pool footprint identical across the death (oracle 4). The replacement
#   worker is a fresh fork of the SAME master parsing the SAME already-loaded
#   config -- no reload, no reparse -- so its cycle_used/cycle_blocks/cycle_large
#   must equal the killed worker's. A replacement that inherited corrupted or
#   leaked cycle state (the master's cycle is what it forks from) would move
#   them. Snapshot taken only after the replacement is drained-in and answering.
#
#   Master descriptor count flat (oracle 5). The master owns each worker's
#   channel socketpair. Reaping a killed worker must close its channel fd; a
#   master that leaked the dead worker's descriptor climbs this count. Taken
#   while idle before the kill and after the replacement settled. Linux-only:
#   skipped VISIBLY where /proc is unreadable.
#
#   The replacement is a child of the original master (oracle 6). If the MASTER
#   died (a kill that took the process group, or a master fault while reaping)
#   the port would be served by nothing, or by a different master -- ppid would
#   move or the probe would stop answering. A stable ppid says the master rode
#   the worker's death out.
#
#   The replacement serves cleanly (oracle 7, the post-death .rule). A worker
#   that came back but mis-serves -- wrong status, a descriptor leaked within
#   the request, an error logged on the request path -- fails the strict prober
#   case run after the series. See post-death.rule.
#
# Why a driver and not a .rule file: the kill happens BETWEEN prober invocations
# and the state that matters is a comparison of probe snapshots taken on either
# side of a signal that no single prober case can straddle. Same rationale as
# reload-cycle/reload-soak.
#
# NEGATIVE CONTROLS (driver mutation, no .so rebuild; fixture restored after):
#   * replace `kill -9 $W` with `kill -0 $W` (a liveness check, kills nothing)
#     -> oracle 2 reds ("no worker exited on signal 9"): confirms oracle 2 is a
#     live assertion and not vacuously satisfied by the log's normal content.
#   * corrupt USED_REF to a value the replacement cannot match -> oracle 4 reds:
#     confirms the cycle-pool comparison is live across the death.
# The crash-CASCADE controls (oracle 3) cannot be planted from the driver -- a
# real second death needs a faulting binary -- so oracle 3 is a guard whose
# non-vacuity rests on oracle 2 proving the log scan sees signal-9 lines at all;
# the two share the one grep.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"
WORKERS=1              # matches worker_processes in nginx.conf

export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing assertion; the verdict is the EXIT STATUS, so
# a `not ok` that did not also raise it would be vacuous.
FAILED=0

# --- helpers ---------------------------------------------------------------

snapshot() {           # read one probe snapshot into SNAP_* globals
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_PID="$(prober_probe_field "$body" pid)"       || return 1
    SNAP_PPID="$(prober_probe_field "$body" ppid || true)"
    SNAP_USED="$(prober_probe_field "$body" cycle_used)"   || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)"   || return 1
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

# Wait until a worker OTHER than $1 is answering the probe, i.e. the master has
# respawned the one we killed. Fixed 50 ms steps with a counted budget, never a
# wall-clock diff -- same discipline as prober_signal_wait, and for the same
# reason (a clock-budget loop runs a different program on a loaded runner). A
# failed probe read is "not yet", not a verdict: during the reap+refork window
# no worker answers. Echoes the new pid, returns 1 on timeout.
wait_new_worker() {    # DEAD_PID TIMEOUT_MS
    local dead="$1" timeout_ms="$2" step_ms=50 attempts i now
    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1
    for ((i = 0; i < attempts; i++)); do
        sleep 0.05
        now="$(prober_probe_pid "$HOST" "$PORT")" || continue
        if [ "$now" != "$dead" ]; then
            printf '%s\n' "$now"
            return 0
        fi
    done
    return 1
}

# TAP plan:
#  1 the killed worker was replaced (a different pid answers)
#  2 a worker exited on signal 9 (the kill landed -- non-vacuity)
#  3 no OTHER signal death occurred
#  4 the replacement's cycle-pool footprint matches the killed worker's
#  5 the master leaked no descriptor
#  6 the replacement is a child of the original master
#  7 the replacement serves cleanly (post-death.rule, run by the engine)
echo "1..7"

# --- baseline: identify the worker we are about to kill --------------------
warm
if ! snapshot; then
    echo "Bail out! the probe endpoint did not answer before the kill"
    exit 1
fi
VICTIM_PID="$SNAP_PID"
BASE_PPID="$SNAP_PPID"
USED_REF="$SNAP_USED"; BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
M_FDS_BASE="$(master_fds || true)"

# The victim must be a real child of the master we are tracking, or the kill
# would land on the wrong process (a stale worker from an earlier scenario, a
# pid reused by the OS). The probe reported it as the server on this port; the
# master owns it; kill it.
if ! kill -0 "$VICTIM_PID" 2>/dev/null; then
    echo "Bail out! the worker pid $VICTIM_PID from the probe is not alive to kill"
    exit 1
fi

# --- the kill --------------------------------------------------------------
kill -9 "$VICTIM_PID" 2>/dev/null || true

# --- 1: the killed worker was replaced -------------------------------------
NEW_PID="$(wait_new_worker "$VICTIM_PID" 5000 || true)"
if [ -n "$NEW_PID" ] && [ "$NEW_PID" != "$VICTIM_PID" ]; then
    echo "ok 1 - the killed worker ($VICTIM_PID) was replaced by $NEW_PID"
else
    echo "not ok 1 - no replacement worker answered within 5 s after the kill"
    FAILED=$((FAILED + 1))
fi

# Let the replacement drain in before measuring: a worker answering does not
# mean the reap of the dead one is complete, and the master's fd count is only
# flat once the dead worker's channel has been closed. A drain timeout is a real
# failure, but "no pgrep on this host" (rc 2) is a visible skip, not a red.
DRC=0
prober_drain_wait "$MASTER" "$WORKERS" 10000 || DRC=$?
if [ "$DRC" -ne 0 ] && [ "$DRC" -ne 2 ]; then
    # A drain timeout is a real failure: the replacement never settled to the
    # required $WORKERS-child steady state, so the oracles below (cycle-pool,
    # master fd, ppid) would measure an unsettled cycle. Not one of the seven
    # planned oracles, so it stays a diagnostic line -- but it MUST fail the
    # scenario, or a never-settling replacement passes silently. rc 2 = "no
    # pgrep on this host" is a visible skip, not a red.
    echo "# FAIL: the replacement worker had not settled to $WORKERS child after 10 s"
    FAILED=$((FAILED + 1))
fi

warm

# --- 2: a worker exited on signal 9 (the kill landed) ----------------------
# This is the non-vacuity control. Every other oracle here is satisfied by a
# server that was never killed; only this one proves the SIGKILL reached a live
# worker. Asserted from the log because the pid/ppid oracles are blind to a
# crash (a respawn has the same master -- s74). nginx logs "worker process NNNN
# exited on signal 9"; angie's wording is the same for the signal clause.
if grep -qE 'worker process [0-9]+ exited on signal 9' "$ELOG"; then
    echo "ok 2 - a worker exited on signal 9 (the kill was delivered)"
else
    echo "not ok 2 - no worker exited on signal 9; the kill did not land, so every oracle below is vacuous"
    FAILED=$((FAILED + 1))
fi

# --- 3: no OTHER signal death ----------------------------------------------
# A contained kill leaves exactly one signal-9 exit and no fault signals. More
# than one signal-9, or any SEGV/ABRT/BUS, means the death cascaded.
N_SIG9="$(grep -cE 'worker process [0-9]+ exited on signal 9' "$ELOG" 2>/dev/null || true)"
[ -n "$N_SIG9" ] || N_SIG9=0
if grep -qE 'exited on signal (11|6|7)|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 3 - a worker died by a FAULT signal; the kill cascaded"
    grep -nE 'exited on signal (11|6|7)|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
elif [ "$N_SIG9" -gt 1 ]; then
    echo "not ok 3 - $N_SIG9 workers exited on signal 9; only the one we sent was expected"
    FAILED=$((FAILED + 1))
else
    echo "ok 3 - no signal death beyond the single kill we sent"
fi

# --- 4: cycle-pool footprint identical across the death --------------------
# This post-death snapshot also refreshes SNAP_PPID for oracle 6. If it fails,
# SNAP_PPID still holds the PRE-KILL baseline value (snapshot() leaves it
# untouched on an early return), which equals BASE_PPID and would let oracle 6
# pass without ever reading the replacement -- so gate oracle 6 on SNAP_OK.
SNAP_OK=0
if ! snapshot; then
    echo "not ok 4 - the probe did not answer after the replacement settled"
    FAILED=$((FAILED + 1))
else
    SNAP_OK=1
    DRIFT=""
    [ "$SNAP_USED"   = "$USED_REF"   ] || DRIFT="$DRIFT cycle_used=$SNAP_USED/want-$USED_REF"
    [ "$SNAP_BLOCKS" = "$BLOCKS_REF" ] || DRIFT="$DRIFT cycle_blocks=$SNAP_BLOCKS/want-$BLOCKS_REF"
    [ "$SNAP_LARGE"  = "$LARGE_REF"  ] || DRIFT="$DRIFT cycle_large=$SNAP_LARGE/want-$LARGE_REF"
    if [ -z "$DRIFT" ]; then
        echo "ok 4 - the replacement's cycle-pool footprint matches the killed worker's"
        echo "# cycle_used=$USED_REF cycle_blocks=$BLOCKS_REF cycle_large=$LARGE_REF"
    else
        echo "not ok 4 - the replacement's cycle-pool footprint drifted:$DRIFT"
        FAILED=$((FAILED + 1))
    fi
fi

# --- 5: the master leaked no descriptor ------------------------------------
M_FDS_END="$(master_fds || true)"
if [ -z "$M_FDS_BASE" ] || [ -z "$M_FDS_END" ]; then
    echo "ok 5 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$M_FDS_END" -eq "$M_FDS_BASE" ]; then
    echo "ok 5 - the master held $M_FDS_END descriptors before and after the kill"
else
    echo "not ok 5 - the master's descriptor count moved $M_FDS_BASE -> $M_FDS_END across the kill"
    FAILED=$((FAILED + 1))
fi

# --- 6: the replacement is a child of the original master ------------------
if [ -z "$BASE_PPID" ]; then
    echo "ok 6 - master parentage # SKIP this module .so emits no \"ppid\" field"
elif [ "$SNAP_OK" -ne 1 ]; then
    # oracle 4's post-death snapshot failed -- SNAP_PPID is the stale pre-kill
    # baseline, not the replacement's. Cannot validate parentage; fail loud.
    echo "not ok 6 - no post-death snapshot; cannot read the replacement's master"
    FAILED=$((FAILED + 1))
elif [ -n "${SNAP_PPID:-}" ] && [ "$SNAP_PPID" = "$BASE_PPID" ]; then
    echo "ok 6 - the replacement worker is a child of the original master ($BASE_PPID)"
else
    echo "not ok 6 - the replacement reported master ${SNAP_PPID:-<none>}, was $BASE_PPID (the master itself may have died)"
    FAILED=$((FAILED + 1))
fi

# --- 7: the replacement serves cleanly (prober, folded in) -----------------
# PIPESTATUS, not $?: a bare `./prober | sed` reports sed's status, which is
# always 0, silently discarding a red prober leg. Same pattern as reload-cycle.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-death.rule" | sed 's/^/# prober: /'
RULE_STATUS=${PIPESTATUS[0]}
if [ "$RULE_STATUS" -eq 0 ]; then
    echo "ok 7 - the replacement worker serves cleanly after the kill"
else
    echo "not ok 7 - the replacement worker mis-served after the kill (prober rc $RULE_STATUS)"
    FAILED=$((FAILED + 1))
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
