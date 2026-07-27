#!/usr/bin/env bash
#
# TAP self-test for prober_stale_so_check (lib.sh) -- the pre-boot gate that
# bails when the reference module .so is older than the probe source it was
# built from.
#
# Why this gate exists, and why it is tested here rather than through a scenario:
# a stale .so is SILENT. The module loads, the directive is present, the server
# boots, and the probe simply omits whichever field was added after the artifact
# was built. The oracle reading that field sees the absent-field sentinel and
# fails closed, so the red surfaces on whichever flavor happens to hold the older
# artifact -- reading as a flavor-specific bug in the diff under test. It cost a
# full session twice (s108, s140) and CI cannot reproduce it, because CI rebuilds
# every flavor from source on every run. So the only place this can be pinned is
# a unit test with no server involved.
#
# The load-bearing properties, each with a paired assertion so neither is vacuous:
#   - a .so OLDER than a probe source bails, and the bail NAMES the stale path
#     (a downstream bail answering for a deleted guard is the vacuous shape this
#     repo has hit before -- s71/B3, where a missing-script gate was satisfied by
#     an unrelated failure further down),
#   - a .so NEWER than every probe source passes,
#   - PROBER_ALLOW_STALE_SO=1 lifts exactly that bail and nothing else,
#   - a missing src/ is silence, not a bail (the consumer-repo case: a vendored
#     harness has no probe source to compare against).
#
# prober_stale_so_check calls `exit 1` on a bail, so every invocation here runs
# in a SUBSHELL: the subshell's exit status is the gate's verdict and the parent
# test process survives to make the next assertion.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=9
tests_run=0
failures=0

echo "1..$PLANNED"

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
    fi
}

# shellcheck source=lib.sh
. ./lib.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/stale_so_test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Stage a fake tree shaped like the real one: <root>/src/ holds the probe
# sources, <root>/.build/<flavor>-<version>/objs/ holds the artifact. Only the
# two paths the gate reads matter, so the files' CONTENTS are irrelevant --
# every assertion here is about mtime ordering.
ROOT="$WORK/root"
mkdir -p "$ROOT/src" "$ROOT/objs"
SO="$ROOT/objs/ngx_http_test_ref_module.so"

PROBER_RESOLVED_ROOT="$ROOT"
PROBER_MODULE_PATH="$SO"
PROBER_FLAVOR="nginx"
PROBER_VERSION="1.29.0"

# Order mtimes explicitly with touch -d rather than by write order + sleep: a
# wall-clock sleep makes this suite slower for no gain and, on a loaded box,
# still races. Fixed timestamps make the ordering the test asserts exact.
old() { touch -d '2026-07-25 12:00:00' "$@"; }
new() { touch -d '2026-07-27 12:00:00' "$@"; }

# ---- the stale case: .so older than a probe source --------------------------
# The core regression guard. This is precisely the s140 shape: the .c grew a
# field after the artifact was built.
: >"$ROOT/src/ngx_test_probe.c"
: >"$SO"
old "$SO"
new "$ROOT/src/ngx_test_probe.c"
( prober_stale_so_check ) >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "a .so older than ngx_test_probe.c bails"

# ---- the bail NAMES the stale artifact --------------------------------------
# Paired with the case above and load-bearing on its own: a gate that bails for
# the right reason but prints something else sends the next session hunting the
# wrong file, which is the exact cost this gate exists to remove. Assert the
# message carries the artifact path, not merely that something failed.
msg="$( ( prober_stale_so_check ) 2>&1 || true )"
case "$msg" in
    *"$SO"*) s=0 ;;
    *)       s=1 ;;
esac
ok "$s" "the bail message names the stale .so path"

# ---- and names the source that outranks it ----------------------------------
# The other half of a useful message: which file made it stale, so the rebuild
# is obviously the fix.
case "$msg" in
    *ngx_test_probe.c*) s=0 ;;
    *)                  s=1 ;;
esac
ok "$s" "the bail message names the newer probe source"

# ---- the fresh case: .so newer than every probe source ----------------------
# Paired with the stale case: if the gate ignored mtime entirely both would
# pass, and if it bailed unconditionally both would fail. Only a real comparison
# satisfies the pair.
new "$SO"
( prober_stale_so_check ) >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "a .so newer than every probe source passes"

# ---- a .h newer than the .so is also stale ----------------------------------
# The s108/s140 incidents spanned the .c and the .h, so the gate compares
# against the newest of BOTH. Pinning one filename would catch one incident and
# miss the other; this asserts the glob really covers the header.
#
# The .c must be made OLD for this to mean anything. Leaving it new lets it
# satisfy the bail on its own, and the assertion passes whether or not the glob
# covers headers at all -- verified vacuous when first written: mutating the
# glob to '*.c' left this case green.
: >"$ROOT/src/ngx_test_probe.h"
old "$ROOT/src/ngx_test_probe.c"
new "$ROOT/src/ngx_test_probe.h"
old "$SO"
( prober_stale_so_check ) >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "a .so older than ngx_test_probe.h bails too"

# ---- the opt-in lifts exactly that bail -------------------------------------
# Same stale tree as the case above, PROBER_ALLOW_STALE_SO=1 set: must pass.
( PROBER_ALLOW_STALE_SO=1 prober_stale_so_check ) >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "PROBER_ALLOW_STALE_SO=1 drives a stale .so anyway"

# ---- the opt-in is scoped to the value 1 ------------------------------------
# Guards against the gate being read as "any non-empty value disables me", which
# would make a stray PROBER_ALLOW_STALE_SO=0 in a scenario env silently disable
# it -- the blanket off-switch shape this repo scopes every opt-in against.
( PROBER_ALLOW_STALE_SO=0 prober_stale_so_check ) >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "PROBER_ALLOW_STALE_SO=0 does not lift the bail"

# ---- no src/ is silence, not a bail -----------------------------------------
# The consumer case: a vendored harness has no probe source of its own, so there
# is nothing to be stale against. A bail here would break every consumer repo.
rm -rf "$ROOT/src"
( prober_stale_so_check ) >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "a tree with no src/ passes (the consumer case)"

# ---- the guard runs BEFORE the scenario env is sourced ----------------------
# The docs promise that PROBER_ALLOW_STALE_SO must come from the caller's
# environment and NOT from a scenario `env` file, unlike its two siblings. That
# asymmetry is a consequence of call order in run-scenario.sh -- prober_detect_load
# (which calls this guard) runs several lines before the `. "$SCENARIO/env"`, while
# prober_check_conf and prober_scrape_log run after it.
#
# Assert the order directly against the script, so the day someone reorders
# run-scenario.sh the docs stop being quietly wrong instead of loudly wrong.
# `|| true` on each grep is load-bearing under `set -e`: a grep that matches
# nothing exits 1, and an unguarded $( ) assignment would kill this script
# outright -- the TAP stream would stop at 8 with no `not ok` printed, which
# reads as a pass to anything counting failures. Verified: without the guards,
# reordering run-scenario.sh truncated the stream instead of failing test 9.
# Matching `prober_detect_load` anywhere on the line (not anchored to column 0)
# is deliberate for the same reason -- an indented call is still a call, and
# anchoring would make the assertion silently unable to find a relocated one.
detect_ln="$(grep -n 'prober_detect_load' run-scenario.sh | head -1 | cut -d: -f1 || true)"
# SC2016: the single quotes are the point -- this greps for the LITERAL text
# `. "$SCENARIO/env"` in another script's source, so expanding it here would
# search for this test's own (empty) $SCENARIO instead.
# shellcheck disable=SC2016
env_ln="$(grep -n '\. "\$SCENARIO/env"' run-scenario.sh | head -1 | cut -d: -f1 || true)"
if [ -n "$detect_ln" ] && [ -n "$env_ln" ] && [ "$detect_ln" -lt "$env_ln" ]; then
    s=0
else
    s=1
fi
ok "$s" "prober_detect_load runs before the scenario env is sourced (docs claim)"

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# PLAN MISMATCH: ran $tests_run, planned $PLANNED"
    exit 1
fi

exit $((failures > 0 ? 1 : 0))
