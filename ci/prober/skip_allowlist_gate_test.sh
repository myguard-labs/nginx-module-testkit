#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# TAP self-test for the SKIP-allowlist gate in test-scenarios.sh (PR #185).
#
# That logic has never had automated coverage -- PR #185 landed it with only
# MANUAL controls described in the PR body. This closes the gap.
#
# WHY A THROWAWAY FIXTURE TREE, NOT REAL SCENARIOS. Every real scenario needs a
# built nginx/angie tree to boot against, which this suite must not depend on
# (it runs on every `./test.sh`, plain and SAN=1, no server involved -- see
# test.sh's own header). test-scenarios.sh's only real dependency on a
# scenario is run-scenario.sh's TAP output and exit status, so the fixture
# supplies a stub run-scenario.sh that emits canned TAP for a scenario name
# instead of booting anything, plus a copy of the real test-scenarios.sh and
# skip-allowlist.sh (mirroring pr_impact_test.sh's own copy-the-real-driver
# pattern). Scenario "content" is nothing but a directory name under
# ./scenarios/ -- test-scenarios.sh never looks inside one itself, that is
# entirely run-scenario.sh's job, which is exactly what is stubbed here.
#
# FOUR PROPERTIES, EACH WITH A FALSIFYING MUTATION (verified by hand while
# authoring this file, then reverted -- see the PR description for the
# mutate/revert transcript):
#   1. allowlisted skip -> "ok N ... # SKIP", overall exit 0.
#   2. non-allowlisted skip -> "not ok N ...", overall exit nonzero.
#   3. whole-word globbing: a near-miss name (shares a prefix, or differs only
#      where a regex metachar like `.` or `-` sits) must NOT be treated as
#      allowlisted, even though it would match under `=~`. This is the exact
#      bug `" ${arr[*]} " == *" $NAME "*` (glob, not regex) defends against.
#   4. an ordinary passing scenario still reports "ok", and a genuinely
#      failing one still reports "not ok" -- the gate must not perturb the
#      non-skip cases it does not own.
set -euo pipefail

cd "$(dirname "$0")"
REAL_DIR="$PWD"

PLANNED=7
tests_run=0
failures=0

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
    fi
}

diag() { printf '# %s\n' "$1"; }

echo "1..$PLANNED"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/skip_allowlist_gate_test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

FIX="$WORK/fixture"
mkdir -p "$FIX/scenarios"

cp "$REAL_DIR/test-scenarios.sh" "$FIX/test-scenarios.sh"
chmod +x "$FIX/test-scenarios.sh"

# Stub run-scenario.sh: emits TAP for the scenario NAME (basename of $1)
# without booting anything. The verdict for each name is driven by a file the
# test writes into the fixture's own control directory below, so each case
# controls exactly what its scenario "does" without touching the real
# run-scenario.sh or nginx at all.
cat >"$FIX/run-scenario.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
DIR="$1"
NAME="$(basename "$DIR")"
CTRL="$(dirname "$0")/ctrl/$NAME"
if [ -f "$CTRL/skip" ]; then
    echo "1..0 # SKIP $(cat "$CTRL/skip")"
    exit 0
elif [ -f "$CTRL/fail" ]; then
    echo "1..1"
    echo "not ok 1 - stub failure"
    exit 1
else
    echo "1..1"
    echo "ok 1 - stub pass"
    exit 0
fi
STUB
chmod +x "$FIX/run-scenario.sh"

mkdir -p "$FIX/ctrl"

# make_scenario NAME [skip|fail|pass]
make_scenario() {
    local name="$1" mode="${2:-pass}"
    mkdir -p "$FIX/scenarios/$name" "$FIX/ctrl/$name"
    case "$mode" in
        skip) printf 'stub skip reason\n' >"$FIX/ctrl/$name/skip" ;;
        fail) : >"$FIX/ctrl/$name/fail" ;;
        pass) : ;;
    esac
}

# A minimal allowlist naming exactly the two probe scenarios this suite needs
# allowlisted -- reusing the real _PROBER_SKIPS_COMMON list would tie every
# property's pass/fail to whatever the real repo currently allowlists, which
# is precisely the coupling a dedicated regression test must not have.
cat >"$FIX/skip-allowlist.sh" <<'ALLOW'
#!/usr/bin/env bash
# shellcheck disable=SC2034
_TEST_SKIPS_COMMON=(
    allowed-skip
    weird.name
)
case "${1:-}:${2:-}" in
    fixture:1)
        PROBER_EXPECTED_SKIPS=("${_TEST_SKIPS_COMMON[@]}")
        ;;
    *)
        echo "skip-allowlist: no allowlist for '${1:-?}:${2:-?}'" >&2
        exit 1
        ;;
esac
ALLOW

run_fixture() {   # runs test-scenarios.sh in the fixture, single job (deterministic order)
    ( cd "$FIX" && PROBER_SCENARIO_JOBS=1 ./test-scenarios.sh fixture 1 )
}

reset_scenarios() {
    rm -rf "$FIX/scenarios" "$FIX/ctrl"
    mkdir -p "$FIX/scenarios" "$FIX/ctrl"
}

# ===================== property 1: allowlisted skip is ok ====================
reset_scenarios
make_scenario allowed-skip skip
set +e
OUT="$(run_fixture)"; STATUS=$?
set -e
if printf '%s\n' "$OUT" | grep -qE '^ok 1 - allowed-skip # SKIP' && [ "$STATUS" -eq 0 ]; then
    ok 0 "allowlisted skip: ok N ... # SKIP, overall exit 0"
else
    ok 1 "allowlisted skip: ok N ... # SKIP, overall exit 0"
    diag "status=$STATUS"; diag "$OUT"
fi

# ================ property 2: non-allowlisted skip is not ok =================
reset_scenarios
make_scenario rogue-skip skip
set +e
OUT="$(run_fixture)"; STATUS=$?
set -e
if printf '%s\n' "$OUT" | grep -qE '^not ok 1 - rogue-skip \(skipped but not allowlisted' \
   && [ "$STATUS" -ne 0 ]; then
    ok 0 "non-allowlisted skip: not ok N ..., overall exit nonzero"
else
    ok 1 "non-allowlisted skip: not ok N ..., overall exit nonzero"
    diag "status=$STATUS"; diag "$OUT"
fi

# A non-allowlisted skip must NEVER carry a trailing # SKIP directive on its
# "not ok" line -- that is the self-contradictory TAP shape the real
# test-scenarios.sh comment calls out (some consumers resolve it toward
# "skipped", swallowing the one verdict this gate exists to raise).
if printf '%s\n' "$OUT" | grep -E '^not ok 1 - rogue-skip' | grep -qv '# SKIP'; then
    ok 0 "non-allowlisted skip: 'not ok' line carries no # SKIP directive"
else
    ok 1 "non-allowlisted skip: 'not ok' line carries no # SKIP directive"
    diag "$OUT"
fi

# ===== property 3: whole-word globbing rejects a near-miss allowlist entry ===
# "allowed-skip-extra" shares the allowlisted name's PREFIX but is a distinct
# scenario; under a regex membership test (`=~`) "allowed-skip" as a pattern
# would match here because `-` has no special regex meaning and the string is
# a literal prefix match. The real gate uses glob membership on
# " ${arr[*]} " == *" $NAME "* (whole-word, space-delimited), which must
# reject this.
reset_scenarios
make_scenario allowed-skip-extra skip
set +e
OUT="$(run_fixture)"; STATUS=$?
set -e
if printf '%s\n' "$OUT" | grep -qE '^not ok 1 - allowed-skip-extra \(skipped but not allowlisted' \
   && [ "$STATUS" -ne 0 ]; then
    ok 0 "whole-word gate: a prefix near-miss of an allowlisted name is NOT allowlisted"
else
    ok 1 "whole-word gate: a prefix near-miss of an allowlisted name is NOT allowlisted"
    diag "status=$STATUS"; diag "$OUT"
fi

# "weird-name" (hyphen) against the allowlisted "weird.name" (dot): under
# `=~`, "weird.name" as a PATTERN has its `.` match ANY character, so
# "weird-name" would wrongly satisfy it. The glob-based whole-word test must
# not conflate the two literal strings.
reset_scenarios
make_scenario weird-name skip
set +e
OUT="$(run_fixture)"; STATUS=$?
set -e
if printf '%s\n' "$OUT" | grep -qE '^not ok 1 - weird-name \(skipped but not allowlisted' \
   && [ "$STATUS" -ne 0 ]; then
    ok 0 "whole-word gate: a regex-metachar near-miss ('.' vs '-') is NOT allowlisted"
else
    ok 1 "whole-word gate: a regex-metachar near-miss ('.' vs '-') is NOT allowlisted"
    diag "status=$STATUS"; diag "$OUT"
fi

# ================= property 4: gate leaves pass/fail untouched ===============
reset_scenarios
make_scenario normal-pass pass
set +e
OUT="$(run_fixture)"; STATUS=$?
set -e
if printf '%s\n' "$OUT" | grep -qE '^ok 1 - normal-pass$' && [ "$STATUS" -eq 0 ]; then
    ok 0 "ordinary passing scenario still reports ok, exit 0"
else
    ok 1 "ordinary passing scenario still reports ok, exit 0"
    diag "status=$STATUS"; diag "$OUT"
fi

reset_scenarios
make_scenario normal-fail fail
set +e
OUT="$(run_fixture)"; STATUS=$?
set -e
if printf '%s\n' "$OUT" | grep -qE '^not ok 1 - normal-fail$' && [ "$STATUS" -ne 0 ]; then
    ok 0 "genuinely failing scenario still reports not ok, exit nonzero"
else
    ok 1 "genuinely failing scenario still reports not ok, exit nonzero"
    diag "status=$STATUS"; diag "$OUT"
fi

# ---- plan reconciliation ----------------------------------------------------
if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    diag "$failures of $tests_run self-tests failed"
    exit 1
fi
