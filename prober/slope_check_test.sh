#!/usr/bin/env bash
#
# TAP self-test for prober_slope_check (lib.sh), the growth oracle every
# resource scenario asserts through (rss-slope, stateful-property-fuzz,
# deploy-canary).
#
# WHY IT NEEDS ITS OWN TEST rather than being covered by those three scenarios:
# the defect this test was written for was PURE ARITHMETIC, and a scenario
# running against a healthy server cannot see it. The original implementation
# computed `slope=$(( (last - baseline) / samples ))` -- integer division
# truncating toward zero -- so any total growth smaller than SAMPLES floored to
# 0/op. With the standard SAMPLES=30, an oracle whose own comment says "EXACTLY
# flat, 0/op" accepted up to 29 units of real growth, and the 4 kB/op RSS bound
# accepted 4 + 29/30 per op. Every consumer went green on the leak it existed to
# catch. A live scenario can only distinguish those two if the planted leak
# happens to be bigger than SAMPLES -- which the rss-slope control's leak is
# (439/op), so it kept passing and proved nothing about the boundary. Only a
# test that can DICTATE the exact sequence of readings can hold the bound at its
# edge.
#
# HOW THE SERVER IS STUBBED. prober_slope_check reads the world through exactly
# two helpers -- prober_stimulus_get (one operation) and prober_probe_body (one
# snapshot) -- plus prober_probe_field to extract from that body. Overriding the
# first two after sourcing lib.sh lets the test feed a scripted series of values
# with no nginx, no port and no timing, so the boundary cases below are exact
# and cannot flake. prober_probe_field is deliberately NOT stubbed: the real
# extractor runs, so the test also covers the body-shape contract the callers
# rely on.
set -euo pipefail

cd "$(dirname "$0")"

# Sourced by literal path so shellcheck can follow it; PROBER_LIB is exported
# for parity with how run-scenario.sh hands lib.sh to a driver.
PROBER_LIB="$PWD/lib.sh"
export PROBER_LIB
# shellcheck source=lib.sh
. ./lib.sh

echo "1..13"

n=0
FAILED=0

# ok NAME EXPECTED ACTUAL -- one comparison, one TAP line.
check() {
    n=$((n + 1))
    if [ "$2" = "$3" ]; then
        echo "ok $n - $1"
    else
        echo "not ok $n - $1"
        echo "# expected [$2], got [$3]"
        FAILED=$((FAILED + 1))
    fi
}

# --- the stub -------------------------------------------------------------
#
# SERIES is the list of `used` values prober_probe_body will hand back, one per
# call, in order. The first reading after the warmup loop is the baseline, and
# the SAMPLES readings after it are the sweep -- so a run needs 1 + SAMPLES
# entries. The warmup operations themselves take no reading (the helper
# discards them by construction), which this stub therefore does not have to
# model.
#
# THE CURSOR LIVES IN A FILE, NOT A VARIABLE, and this is not incidental:
# prober_slope_check reads every body through a `$( )` command substitution, so
# the stub runs in a SUBSHELL and any counter it increments dies with that
# subshell. A variable cursor silently stays at 0 and replays the first reading
# forever, which makes every series look dead flat -- a stub that reports the
# healthy answer to every question, i.e. exactly the vacuous green this file
# exists to prevent. The file cursor is the only part of the stub state that
# has to survive the subshell, so it is the only part kept out of the shell.
SERIES_FILE="$(mktemp)"
CURSOR_FILE="$(mktemp)"
trap 'rm -f "$SERIES_FILE" "$CURSOR_FILE"' EXIT

prober_stimulus_get() {
    :
}

# Emits a body in the shape ngx_test_probe.c produces, carrying the next value
# from SERIES as pool.used. A literal `-` entry emits the -1 sentinel the
# /proc-derived fields render when unreadable, so the fail-closed path can be
# driven the same way. Reading past the end of the series is a BUG IN A TEST
# CASE (a series shorter than 1+SAMPLES), so it aborts loudly instead of
# emitting one more plausible number.
prober_probe_body() {
    local idx v
    idx="$(cat "$CURSOR_FILE")"
    echo "$((idx + 1))" > "$CURSOR_FILE"
    v="$(sed -n "$((idx + 1))p" "$SERIES_FILE")"
    if [ -z "$v" ]; then
        echo "slope_check_test: series exhausted at read $((idx + 1))" >&2
        exit 99
    fi
    [ "$v" = "-" ] && v=-1
    printf '{"pid":4242,"pool":{"used":%s},"zone":{"present":true}}' "$v"
}

# run WARMUP SAMPLES MAX_PER_OP SPEC... -- reset the stub, run one check over
# the series the SPECs describe, echo its exit status. Output is captured (and
# dropped) so a failing case does not pollute the TAP stream.
#
# A SPEC is either a literal reading (`1000`, or `-` for the sentinel) or a
# repeat of the form `COUNTxVALUE` (`29x1000`). The repeats are expanded HERE
# rather than by a command substitution at the call site so no case has to
# word-split an unquoted `$( )` into the argument list -- the series stay
# readable and the file stays clean under shellcheck.
run() {
    local warmup="$1" samples="$2" max="$3"
    shift 3
    local spec count value i
    : > "$SERIES_FILE"
    for spec in "$@"; do
        if [[ "$spec" =~ ^([0-9]+)x(.+)$ ]]; then
            count="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            for (( i = 0; i < count; i++ )); do
                echo "$value" >> "$SERIES_FILE"
            done
        else
            echo "$spec" >> "$SERIES_FILE"
        fi
    done
    echo 0 > "$CURSOR_FILE"
    local rc=0
    SLOPE_OUT="$(prober_slope_check host 1 used / "$warmup" "$samples" "$max")" || rc=$?
    echo "$rc"
}

# --- the boundary the bug lived on ----------------------------------------
#
# SAMPLES=30, MAX_PER_OP=0 -- the "exactly flat" contract rss-slope oracle 1 and
# deploy-canary O5 both assert. Baseline 1000, and the field climbs by ONE unit
# in total across the whole sweep. Under the old truncating division that was
# 1/30 == 0/op and passed. It is real growth against a bound of zero, so it must
# fail.
check "one unit of total growth reds a MAX_PER_OP=0 bound (the floor bug)" \
    "1" "$(run 10 30 0 1000 29x1000 1001)"

# The same shape one unit lower: dead flat for the whole sweep is the healthy
# case and must stay green, or the fix above would have been bought by turning
# every passing consumer red.
check "a genuinely flat field passes the MAX_PER_OP=0 bound" \
    "0" "$(run 10 30 0 1000 30x1000)"

# SAMPLES-1 units of growth: the worst case the old code hid, one unit below
# the point where truncation would finally have surfaced it as 1/op.
check "SAMPLES-1 units of total growth reds a MAX_PER_OP=0 bound" \
    "1" "$(run 10 30 0 1000 29x1000 1029)"

# --- the budget boundary for a nonzero bound ------------------------------
#
# MAX_PER_OP=4 over SAMPLES=10 is a budget of exactly 40 total. 40 is inside the
# bound and 41 is outside it; the pair pins the comparison as <= and not <, so a
# later edit cannot quietly move the edge by one.
check "total growth exactly equal to MAX_PER_OP*SAMPLES passes" \
    "0" "$(run 3 10 4 1000 9x1000 1040)"

check "total growth one unit over MAX_PER_OP*SAMPLES reds" \
    "1" "$(run 3 10 4 1000 9x1000 1041)"

# Sub-bound growth that the old division also floored: 4 kB/op nominal with an
# extra 9 units riding under the truncation. 49 > 40, so it must red.
check "growth inside the truncation remainder of a nonzero bound still reds" \
    "1" "$(run 3 10 4 1000 9x1000 1049)"

# --- the oracle-corruption control the scenarios mutate on ----------------
#
# deploy-canary's mutate.sh row flips SLOPE_CEIL_ADJUST 0 -> -1, turning "grows
# by no more than 0" into "must shrink", which the monotonic cycle pool cannot
# satisfy. That row is the automated proof O7 is load-bearing, so the arithmetic
# change must keep it red: with MAX_PER_OP=-1 the budget is -SAMPLES, and a flat
# field's growth of 0 exceeds it.
check "MAX_PER_OP=-1 reds a flat field (deploy-canary's mutate row stays valid)" \
    "1" "$(run 10 30 -1 1000 30x1000)"

# A field that really does shrink satisfies a negative bound -- so the row above
# reds for the documented reason (the pool is monotonic), not because a negative
# bound is unsatisfiable by construction.
check "MAX_PER_OP=-1 passes a field that actually shrinks" \
    "0" "$(run 10 30 -1 1000 29x1000 900)"

# --- the reported figures on a shrinking field ----------------------------
#
# Growth is negative whenever the field shrank, which only a negative bound can
# reach -- i.e. the mutate row above. Two things have to hold on that line, and
# neither affects the verdict, which is why they are easy to get wrong: the
# total must not render as "+-5" (a hardcoded sign meeting a negative number),
# and the per-op figure must round AWAY from zero. Truncating -5/10 toward zero
# prints "~0/op" beside "want <= -1/op" on a line that FAILED, which reads as a
# broken harness rather than as the verdict it is.
run 2 10 -1 1000 9x1000 995 >/dev/null
case "$SLOPE_OUT" in
    *'+-'*)      got="rendered a doubled sign: $SLOPE_OUT" ;;
    *'~-1/op'*)  got=ok ;;
    *)           got="$SLOPE_OUT" ;;
esac
check "a failing shrink reports a signed total and rounds per-op away from zero" \
    "ok" "$got"

# --- fail-closed paths ----------------------------------------------------
#
# A /proc-derived field that reads the -1 sentinel must fail CLOSED and name
# itself, never subtract to a passing zero. Once at the baseline, once mid-sweep
# -- the two are separate returns in the helper.
check "the -1 sentinel at the baseline fails closed" \
    "1" "$(run 10 30 0 - 30x1000)"

check "the -1 sentinel mid-sweep fails closed" \
    "1" "$(run 2 5 0 1000 1000 1000 - 1000 1000)"

# The sentinel failure must SAY which field it could not read; a bare nonzero
# exit would leave a scenario reporting a leak it never measured.
run 10 30 0 - 30x1000 >/dev/null
case "$SLOPE_OUT" in
    *'"used"'*) got=named ;;
    *)          got="$SLOPE_OUT" ;;
esac
check "the sentinel failure names the unreadable field" "named" "$got"

# SAMPLES < 1 is a caller bug (it would divide the budget to nothing and assert
# on an empty window); the helper rejects it rather than reporting a vacuous ok.
check "SAMPLES=0 is rejected rather than passing vacuously" \
    "1" "$(run 10 0 0 1000)"

exit "$FAILED"
