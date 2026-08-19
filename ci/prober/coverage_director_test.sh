#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# TAP self-test for ci/prober/coverage-director.sh and its consumer, the
# coverage-map.json layer in ci/prober/verify-impact.
#
# WHY A THROWAWAY GIT REPO + FIXTURE LIB. coverage-director.sh rebuilds
# *_test.c against a LIB and attributes lines by which test binary executed
# them, so the fixture has to be a real, tiny, compilable LIB+tests pair --
# not a canned JSON blob -- or the test would only prove the JSON-folding
# code, not the actual per-test .gcda isolation this tool exists for.
# verify-impact's own coverage-map.json consumption is exercised against a
# throwaway git repo, mirroring verify_impact_test.sh's own pattern (a copy of
# THIS repo's real verify-impact, seeded with a minimal impact.map).
#
# NON-VACUITY. Every assertion is paired with a mutated fixture that proves
# the same assertion would have failed had the behaviour been broken:
#   - attribution:    test A's map entries name only A for fn1's lines       -- vs
#                     swapping which test calls which fn, which must flip
#                     the attribution (proves it's not hardcoded to a name).
#   - selector:       verify-impact selects the covering test for a changed
#                     covered line                                          -- vs
#                     the same line attributed to a DIFFERENT test in the
#                     map, which must select THAT other test instead (proves
#                     it reads the map, not a fixed answer).
#   - fail-closed:    a changed executable line with no impact.map row and no
#                     coverage-map.json entry still exits nonzero            -- vs
#                     the same line WITH a coverage-map.json entry, which
#                     must then exit zero (already covered by the selector
#                     pair above, restated here against the no-map case to
#                     close the loop).
set -euo pipefail

cd "$(dirname "$0")"
COVERAGE_DIRECTOR="$PWD/coverage-director.sh"
VERIFY_IMPACT_SRC="$PWD/verify-impact"

PLANNED=6
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

diag() { printf '# %s\n' "$1"; }

# coverage-director.sh is gcc/gcovr-specific (it self-selects a gcov-compatible
# compiler regardless of the ambient $CC -- CI runs one selftest leg with
# CC=clang, under which the director SKIPs). This test exercises real
# attribution, so it needs the same gcc+gcovr the director does; skip the
# whole suite (never fake-pass) when they are absent. jq is needed to read the
# emitted map.
COVERAGE_CC="${COVERAGE_CC:-gcc}"
if ! command -v "$COVERAGE_CC" >/dev/null 2>&1 || ! command -v gcovr >/dev/null 2>&1 \
   || ! command -v jq >/dev/null 2>&1; then
    echo "1..0 # SKIP coverage_director_test.sh needs gcc (gcov-compatible), gcovr and jq"
    exit 0
fi
export COVERAGE_CC

WORK="$(mktemp -d "${TMPDIR:-/tmp}/coverage_director_test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- fixture: a tiny 2-function LIB + 2 tests, each calling ONE function ----
#
# Rebuilt fresh per case (attribution is swapped between cases 1 and 2), each
# in its own ci/prober/ directory so coverage-director.sh's glob-based discovery
# (`*_test.c`, LIB hardcoded to `lib.c` here) sees exactly this fixture's
# files and nothing from the real repo.
build_fixture() {   # $1 = dir, $2 = "a-calls-1" | "a-calls-2" (which fn A's test calls)
    local dir="$1" variant="$2"
    mkdir -p "$dir"
    cat >"$dir/lib.c" <<'EOF'
int fn1(void) { return 1; }
int fn2(void) { return 2; }
EOF
    if [ "$variant" = "a-calls-1" ]; then
        printf 'int fn1(void);\nint main(void){ return fn1(); }\n' >"$dir/a_test.c"
        printf 'int fn2(void);\nint main(void){ return fn2(); }\n' >"$dir/b_test.c"
    else
        printf 'int fn2(void);\nint main(void){ return fn2(); }\n' >"$dir/a_test.c"
        printf 'int fn1(void);\nint main(void){ return fn1(); }\n' >"$dir/b_test.c"
    fi
}

# coverage-director.sh discovers *_test.c and a hardcoded `LIB` variable in
# its own script body -- point it at our fixture's single lib.c by running a
# copy of the script with LIB overridden, rather than editing the real
# script's LIB list for a 2-function fixture. sed swaps the one line; the
# rest of the script (isolation, jq folding, determinism) runs unmodified.
make_director_copy() {   # $1 = dest path
    sed 's/^LIB="json\.c http\.c util\.c rules\.c assert\.c backend\.c"$/LIB="lib.c"/' \
        "$COVERAGE_DIRECTOR" >"$1"
    chmod +x "$1"
}

# ---- case 1: attribution -- test A (calls fn1) shows only in fn1's lines --
DIR1="$WORK/fixture1"
build_fixture "$DIR1" "a-calls-1"
make_director_copy "$DIR1/coverage-director.sh"
( cd "$DIR1" && ./coverage-director.sh >/dev/null 2>&1 )

a_only_fn1=1
if jq -e '.["ci/prober/lib.c"]["1"] // [] | index("a_test")' "$DIR1/coverage-map.json" >/dev/null 2>&1 \
   && ! jq -e '.["ci/prober/lib.c"]["2"] // [] | index("a_test")' "$DIR1/coverage-map.json" >/dev/null 2>&1; then
    :
else
    a_only_fn1=0
fi
ok "$((a_only_fn1 == 1 ? 0 : 1))" \
    "a_test (calls fn1) is attributed fn1's line, not fn2's"

# non-vacuity pair: swap which test calls which fn; attribution must flip.
DIR2="$WORK/fixture2"
build_fixture "$DIR2" "a-calls-2"
make_director_copy "$DIR2/coverage-director.sh"
( cd "$DIR2" && ./coverage-director.sh >/dev/null 2>&1 )

flipped=1
if jq -e '.["ci/prober/lib.c"]["2"] // [] | index("a_test")' "$DIR2/coverage-map.json" >/dev/null 2>&1 \
   && ! jq -e '.["ci/prober/lib.c"]["1"] // [] | index("a_test")' "$DIR2/coverage-map.json" >/dev/null 2>&1; then
    :
else
    flipped=0
fi
ok "$((flipped == 1 ? 0 : 1))" \
    "swapping which test calls which fn flips the attribution (proves it's not hardcoded)"

# ---- case: determinism -- same tests + same source => byte-identical JSON -
DIR3="$WORK/fixture3"
build_fixture "$DIR3" "a-calls-1"
make_director_copy "$DIR3/coverage-director.sh"
( cd "$DIR3" && ./coverage-director.sh >/dev/null 2>&1 )
cp "$DIR3/coverage-map.json" "$WORK/run1.json"
( cd "$DIR3" && ./coverage-director.sh >/dev/null 2>&1 )
ok "$(cmp -s "$WORK/run1.json" "$DIR3/coverage-map.json" && echo 0 || echo 1)" \
    "same tests + same source produce byte-identical coverage-map.json"

# ---- verify-impact selector: reads coverage-map.json, doesn't hardcode -----
#
# Throwaway git repo seeded with the real verify-impact + a minimal
# impact.map (json.c intentionally has NO row, so any selection can only
# come from coverage-map.json).
REPO="$WORK/repo"
mkdir -p "$REPO/ci/prober"
git -C "$REPO" init -q
git -C "$REPO" config user.email "test@example.invalid"
git -C "$REPO" config user.name "coverage-director self-test"
cp "$VERIFY_IMPACT_SRC" "$REPO/ci/prober/verify-impact"
chmod +x "$REPO/ci/prober/verify-impact"
printf '# empty map -- json.c deliberately has no row\n' >"$REPO/ci/prober/impact.map"
printf 'int json_a(void) { return 1; }\n' >"$REPO/ci/prober/json.c"
printf '{"ci/prober/json.c": {"1": ["json_test"]}}\n' >"$REPO/ci/prober/coverage-map.json"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m base
BASE_SHA="$(git -C "$REPO" rev-parse HEAD)"

printf 'int json_a(void) { return 2; }\n' >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "edit json.c line 1, covered only by json_test"

set +e
out="$(cd "$REPO" && ./ci/prober/verify-impact --base "$BASE_SHA" --explain)"
s=$?
set -e
ok "$((s == 0 && $(printf '%s\n' "$out" | grep -c '^json_test') > 0 ? 0 : 1))" \
    "verify-impact selects the covering test from coverage-map.json for an unmapped-in-impact.map line"

# non-vacuity pair: re-attribute line 1 to a DIFFERENT test name in the map;
# verify-impact must select THAT test instead, proving it reads the map
# rather than always answering "json_test".
git -C "$REPO" checkout -q -b other-test "$BASE_SHA"
printf '{"ci/prober/json.c": {"1": ["other_test"]}}\n' >"$REPO/ci/prober/coverage-map.json"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "re-map line 1 to other_test"
OTHER_BASE="$(git -C "$REPO" rev-parse HEAD)"
printf 'int json_a(void) { return 3; }\n' >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "edit json.c line 1 again"
set +e
out2="$(cd "$REPO" && ./ci/prober/verify-impact --base "$OTHER_BASE" --explain)"
s2=$?
set -e
other_ok=1
[ "$s2" -eq 0 ] || other_ok=0
grep -q '^other_test' <<<"$out2" || other_ok=0
grep -q '^json_test' <<<"$out2" && other_ok=0
ok "$((other_ok == 1 ? 0 : 1))" \
    "re-mapping the same line to a different test name selects THAT test (proves it reads the map, not a fixed name)"

# ---- fail-closed contract still holds with no impact.map row and no
# coverage-map.json entry for the changed line ------------------------------
git -C "$REPO" checkout -q -b unmapped-uncovered "$BASE_SHA"
printf '{"ci/prober/json.c": {"99": ["json_test"]}}\n' >"$REPO/ci/prober/coverage-map.json"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "coverage map only covers an unrelated line"
UNCOV_BASE="$(git -C "$REPO" rev-parse HEAD)"
printf 'int json_a(void) { return 4; }\n' >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "edit line 1, which the map does not cover"
set +e
cd "$REPO" && ./ci/prober/verify-impact --base "$UNCOV_BASE" >/dev/null 2>&1
s3=$?
cd - >/dev/null
set -e
ok "$((s3 != 0 ? 0 : 1))" \
    "a changed line with no impact.map row and no coverage-map.json entry for THAT line still fails closed"

# ---- plan reconciliation ----------------------------------------------------
if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    diag "$failures of $tests_run self-tests failed"
    exit 1
fi
