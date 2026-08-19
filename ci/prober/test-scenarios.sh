#!/usr/bin/env bash
#
# Run every scenario and aggregate to one TAP stream, so `prove` consumes the
# whole scenario tree as a single test file.
#
#   ci/prober/test-scenarios.sh [flavor] [version]
#
#   PROBER_SCENARIOS  glob of scenario directories
#                     (default: ./scenarios/*/ relative to this directory;
#                     consumers pass an absolute glob, same as PROBER_RULES)
#   PROBER_SCENARIO_JOBS
#                     how many scenarios to run concurrently (default: all
#                     cores, capped at the scenario count). 1 forces the old
#                     strictly-serial path -- use it to debug a scenario or to
#                     bisect a suspected cross-scenario interaction.
#
# One TAP test per scenario: the scenario's own TAP output (run-scenario.sh)
# is indented as a TAP-13 subtest block, then summarized as ok / not ok. A
# scenario whose requires gate declined is reported as an explicit SKIP --
# visible in the output, not silently absent, because a scenario that stops
# running on every box is a hole in coverage someone has to notice.
#
# WHY PARALLEL IS SAFE, AND ITS ONE PRECONDITION
# ----------------------------------------------
# Scenarios are wait-dominated, not CPU-dominated: a single one drips a body
# for ~26s, storms a worker with ten HUPs, or waits out a ~90s negative-control
# settle window. Run serially the stage costs the SUM of every scenario's
# waits; run concurrently it costs the slowest single chain, and the idle waits
# overlap. The only shared resource two scenarios contend for is the nginx
# LISTEN port: each scenario already gets its own mktemp PROBER_PREFIX (fresh
# logs/pidfile/conf) and its fake upstream already binds an ephemeral :0 port,
# so the prefix and backend are isolated for free. The listen port is the
# exception -- it defaults to a fixed 18099 (prober.c / prober_resolve), and
# two servers on one port fail on bind. So each concurrency SLOT is handed a
# distinct PROBER_PORT here (BASE + slot); run-scenario.sh's env-file sourcing
# still lets a scenario override it, so a scenario that genuinely needs a fixed
# port keeps working -- but if TWO scenarios pin the SAME fixed port they will
# collide under parallelism. None do today; a new one that must should either
# not pin a port (take the slot default) or carry `PROBER_SCENARIO_JOBS=1`
# intent in its own runner, not here. TAP output stays in scenario-list order
# regardless of finish order: each scenario's stream is captured to a temp file
# and the aggregate lines are emitted in order after the join, so `prove` and a
# human read an identical, deterministic report either way.
set -euo pipefail

cd "$(dirname "$0")"

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.3}"

GLOB="${PROBER_SCENARIOS:-./scenarios/*/}"

# Source the allowlist of permitted SKIP scenarios for this flavor/version.
# shellcheck source=skip-allowlist.sh
. ./skip-allowlist.sh "$FLAVOR" "$VERSION"

# Array to track which allowlisted scenarios actually skipped (for reporting).
ACTUALLY_SKIPPED=()

# Array to track disallowed skips (scenarios that skipped but are NOT in the
# allowlist). This is what makes the job fail: an unexpected skip is a coverage
# regression.
DISALLOWED_SKIPS=()

# Zero discovered scenarios is a failure, not a pass -- a typo'd glob would
# otherwise turn the whole stage into a silent no-op that reports green. Same
# rule test.sh applies to *_test.c discovery, for the same reason.
# shellcheck disable=SC2086
if ! compgen -G $GLOB >/dev/null; then
    echo "Bail out! no scenarios match $GLOB"
    exit 1
fi

SCENARIOS=()
# shellcheck disable=SC2086
for DIR in $GLOB; do
    [ -d "$DIR" ] && SCENARIOS+=("${DIR%/}")
done

COUNT=${#SCENARIOS[@]}
echo "1..$COUNT"

# Concurrency: default to core count, never more than there are scenarios.
JOBS="${PROBER_SCENARIO_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"
[ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1
[ "$JOBS" -gt "$COUNT" ] && JOBS=$COUNT

# Base listen port for the per-slot offset. Kept clear of the 18099 default so
# a stray un-slotted server (a scenario that unsets PROBER_PORT) does not alias
# a slot. Backends bind :0 and are unaffected.
PORT_BASE="${PROBER_SCENARIO_PORT_BASE:-18120}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/prober-scenarios.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Run scenario index $1 in concurrency slot $2, capturing its stream and exit
# status to files the aggregator reads in order after the join.
run_one() {
    local idx="$1" slot="$2"
    local dir="${SCENARIOS[$idx]}"
    local rc=0
    # A distinct port per SLOT (not per scenario): only $JOBS run at once, so
    # BASE..BASE+JOBS-1 is collision-free among the live set, and a finished
    # slot's port is free for the next scenario that reuses it.
    PROBER_PORT="$((PORT_BASE + slot))" \
        ./run-scenario.sh "$dir" "$FLAVOR" "$VERSION" >"$WORK/out.$idx" 2>&1 || rc=$?
    echo "$rc" >"$WORK/rc.$idx"
}

if [ "$JOBS" -le 1 ]; then
    # Strictly-serial path, byte-for-byte the original behaviour (slot 0 = the
    # 18120 base; scenarios that don't pin a port are unaffected by the number).
    for ((i = 0; i < COUNT; i++)); do
        run_one "$i" 0
    done
else
    # Bounded worker pool. `slots[s]` holds the pid running in slot s, or empty.
    # A dispatched scenario takes the first free slot; when all slots are busy
    # we `wait -n` for any to finish, free its slot, and reap by matching pid.
    declare -a slots
    for ((s = 0; s < JOBS; s++)); do slots[s]=""; done

    # Echoes a free slot index or nothing. `|| true` keeps a no-free-slot scan
    # (which ends with the loop condition false, a nonzero status) from tripping
    # set -e in the command substitution that calls it.
    free_slot() {
        local s
        for ((s = 0; s < JOBS; s++)); do
            [ -z "${slots[s]}" ] && { printf '%s' "$s"; return 0; }
        done
        return 0
    }
    # Clear every slot whose pid is no longer alive. Scans rather than trusting a
    # single reaped pid, so it is correct on any bash and never leaves a dead
    # pid latched in a slot. Always returns 0 -- a "nothing to reap" scan must
    # not abort the caller under set -e.
    reap_dead() {
        local s
        for ((s = 0; s < JOBS; s++)); do
            [ -n "${slots[s]}" ] && ! kill -0 "${slots[s]}" 2>/dev/null && slots[s]=""
        done
        return 0
    }

    for ((i = 0; i < COUNT; i++)); do
        slot="$(free_slot)"
        while [ -z "$slot" ]; do
            # All slots busy: block until any one job ends, then reap the dead
            # slot(s) and retry. `wait -n` returns nonzero when the job it reaps
            # exited nonzero (a failing scenario), so it is guarded -- the exit
            # status is recorded per-scenario in rc.$idx, not here.
            wait -n 2>/dev/null || true
            reap_dead
            slot="$(free_slot)"
        done
        run_one "$i" "$slot" &
        slots[slot]=$!
    done

    # Drain the remaining in-flight scenarios. A failing scenario makes wait
    # return nonzero; its verdict is in rc.$idx, so do not let it abort here.
    wait || true
fi

# Emit the aggregate TAP in scenario-list order, reading each captured stream
# and its exit status. Deterministic regardless of finish order.
# Simultaneously validate that scenarios only skip if they are in the allowlist.
STATUS=0
for ((i = 0; i < COUNT; i++)); do
    N=$((i + 1))
    NAME="$(basename "${SCENARIOS[$i]}")"
    OUT="$(cat "$WORK/out.$i" 2>/dev/null || true)"
    RC="$(cat "$WORK/rc.$i" 2>/dev/null || echo 1)"

    printf '%s\n' "$OUT" | sed 's/^/    /'

    if [ "$RC" -eq 0 ]; then
        case "$OUT" in
            "1..0 # SKIP"*)
                # This scenario skipped. Check if it is in the allowlist.
                # Membership is tested with a glob, not =~: under =~ the
                # scenario NAME is a regex, so `.` and `-` in a name would
                # match characters they should not and quietly allowlist a
                # neighbour. The surrounding spaces make it whole-word.
                SKIP_REASON="${OUT#1..0 # SKIP }"
                if [[ " ${PROBER_EXPECTED_SKIPS[*]} " == *" $NAME "* ]]; then
                    # Scenario is allowlisted, propagate the skip normally.
                    ACTUALLY_SKIPPED+=("$NAME")
                    echo "ok $N - $NAME # SKIP $SKIP_REASON"
                else
                    # Scenario is NOT in the allowlist: this is an unexpected
                    # skip, a coverage regression. Fail the job.
                    # No `# SKIP` directive on this line, deliberately. In TAP a
                    # trailing `# SKIP` marks the point as skipped rather than
                    # failed, so `not ok ... # SKIP` is self-contradictory and
                    # some consumers resolve it toward "skipped" -- swallowing
                    # the one verdict this gate exists to raise. The reason is
                    # kept as plain description text instead.
                    DISALLOWED_SKIPS+=("$NAME")
                    echo "not ok $N - $NAME (skipped but not allowlisted: $SKIP_REASON)"
                    STATUS=1
                fi
                ;;
            *)
                echo "ok $N - $NAME" ;;
        esac
    else
        echo "not ok $N - $NAME"
        STATUS=1
    fi
done

# Summary: report which allowlisted scenarios actually skipped.
if [ "${#ACTUALLY_SKIPPED[@]}" -gt 0 ]; then
    echo "# Note: ${#ACTUALLY_SKIPPED[@]} allowlisted scenarios skipped:" >&2
    printf '#   - %s\n' "${ACTUALLY_SKIPPED[@]}" >&2
fi

# The other direction, and the one that rots silently: an allowlisted scenario
# that DID run. The entry is now stale, and a stale entry is a standing licence
# for that scenario to start skipping again later without anyone noticing --
# the exact hole this allowlist exists to close. Reported, not fatal: a
# scenario becoming runnable is good news and must not red an otherwise green
# job, but it has to be visible enough to prune.
STALE_ALLOWLIST=()
for EXPECTED in "${PROBER_EXPECTED_SKIPS[@]}"; do
    if [[ " ${ACTUALLY_SKIPPED[*]} " != *" $EXPECTED "* ]]; then
        STALE_ALLOWLIST+=("$EXPECTED")
    fi
done
if [ "${#STALE_ALLOWLIST[@]}" -gt 0 ]; then
    echo "# Note: ${#STALE_ALLOWLIST[@]} allowlisted scenario(s) did NOT skip -- drop them from" >&2
    echo "# PROBER_EXPECTED_SKIPS in skip-allowlist.sh so a future skip is caught:" >&2
    printf '#   - %s\n' "${STALE_ALLOWLIST[@]}" >&2
fi

# If there were disallowed skips, the job already failed (STATUS=1 set above).
# Report them for troubleshooting.
if [ "${#DISALLOWED_SKIPS[@]}" -gt 0 ]; then
    echo "# ERROR: ${#DISALLOWED_SKIPS[@]} scenario(s) skipped but are NOT in the allowlist for $FLAVOR:$VERSION" >&2
    printf '# (add to PROBER_EXPECTED_SKIPS in skip-allowlist.sh if intentional)\n' >&2
    printf '#   - %s\n' "${DISALLOWED_SKIPS[@]}" >&2
fi

exit $STATUS
