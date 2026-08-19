#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# TAP self-test for ci/prober/verify-impact.
#
# WHY A THROWAWAY GIT REPO. verify-impact's whole job is to diff <base>..HEAD
# and classify the changed paths, so its fixtures have to BE git history. This
# test never touches the real working tree or its history -- every fixture is
# built inside its own `mktemp -d` repo, seeded with a copy of THIS repo's
# ci/prober/impact.map and ci/prober/verify-impact so the tool under test runs
# against the same map it ships with, then torn down on exit.
#
# NON-VACUITY. Every assertion here is paired: the case that must pass, and a
# mutated fixture that proves the SAME assertion would have failed had the
# behaviour been broken. Per repo culture (see mutate.sh's own rationale), a
# test that cannot go red proves nothing. The pairing for each classification:
#   - unmapped new file:      must exit nonzero (fail-closed)              -- vs
#                             the same file ALSO added as a row in impact.map,
#                             which must then exit zero.
#   - rename:                 old path's target still selected under the new
#                             path                                        -- vs
#                             renaming to a path with NO map row, which must
#                             fail-closed instead of silently keeping the edge.
#   - delete:                 exits zero, selects nothing for the deleted path
#                                                                          -- vs
#                             the same file's *content* edited instead of
#                             deleted, which must still select its owner.
#   - header fanout:          a changed .h selects its .d-declared dependents'
#                             owners                                       -- vs
#                             the same run with no .d files present, which
#                             must WARN and FAIL-CLOSED (nonzero) -- with no
#                             dep evidence and no direct row the tool cannot
#                             prove what the header reaches.
#   - empty/docs-only diff:   exits zero, selects nothing                  -- vs
#                             the same diff with one real code line added,
#                             which must then select a target (proves the
#                             docs-only path is not just "always exit 0").
set -euo pipefail

cd "$(dirname "$0")"
VERIFY_IMPACT="$PWD/verify-impact"

PLANNED=13
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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify_impact_test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# One throwaway repo, reused across cases via branches/commits so each case
# pays no re-clone cost; each case still starts from a clean known commit.
REPO="$WORK/repo"
mkdir -p "$REPO/ci/prober/scenarios/backend-smoke"
git -C "$REPO" init -q
git -C "$REPO" config user.email "test@example.invalid"
git -C "$REPO" config user.name "verify-impact self-test"

cp "$PWD/impact.map" "$REPO/ci/prober/impact.map"
cp "$VERIFY_IMPACT" "$REPO/ci/prober/verify-impact"
chmod +x "$REPO/ci/prober/verify-impact"
printf 'int json_a(void) { return 1; }\n' >"$REPO/ci/prober/json.c"
printf 'int rules_a(void) { return 1; }\n' >"$REPO/ci/prober/rules.c"
printf 'int json_a(void);\n' >"$REPO/ci/prober/json.h"
printf 'notes\n' >"$REPO/README.md"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "base"
BASE_SHA="$(git -C "$REPO" rev-parse HEAD)"

run_vi() (
    cd "$REPO" || exit 99
    "$REPO/ci/prober/verify-impact" --base "$BASE_SHA"
)

# ---- case 1: a brand-new file with NO impact.map row must fail-closed ------
git -C "$REPO" checkout -q -b case-unmapped "$BASE_SHA"
printf 'int surprise(void) { return 1; }\n' >"$REPO/ci/prober/newthing.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "add unmapped source"
set +e
out="$(run_vi 2>"$WORK/vi_err")"
s=$?
set -e
ok "$((s != 0 ? 0 : 1))" "unmapped new source file fails closed (nonzero exit)"

# non-vacuity pair: the SAME file, but now WITH a map row, must pass. If the
# tool ignored impact.map entirely and always failed on new files, this would
# also fail and expose the vacuity.
git -C "$REPO" checkout -q -b case-mapped case-unmapped
{
    echo "PRIMARY	ci/prober/newthing.c	newthing_test	fast"
} >>"$REPO/ci/prober/impact.map"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "map the new source"
set +e
out="$(run_vi 2>"$WORK/vi_err2")"
s=$?
set -e
ok "$s" "the same file, once mapped in impact.map, no longer fails"
if [ "$s" -eq 0 ] && ! grep -q "newthing_test" <<<"$out"; then
    diag "expected newthing_test in output, got: $out"
    failures=$((failures + 1))
fi

# ---- case 2: rename carries the old path's edges to the new path ----------
git -C "$REPO" checkout -q -b case-rename "$BASE_SHA"
git -C "$REPO" mv ci/prober/json.c ci/prober/json_renamed.c
{
    echo "PRIMARY	ci/prober/json_renamed.c	json_test	fast"
} >>"$REPO/ci/prober/impact.map"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "rename json.c"
set +e
out="$(run_vi)"
s=$?
set -e
ok "$((s == 0 && $(printf '%s\n' "$out" | grep -c json_test) > 0 ? 0 : 1))" \
    "rename carries the owning target under the NEW path"

# non-vacuity pair: rename to a path with NO row must fail-closed, proving
# the pass above is not just "renames always succeed".
git -C "$REPO" checkout -q -b case-rename-unmapped "$BASE_SHA"
git -C "$REPO" mv ci/prober/json.c ci/prober/json_gone_astray.c
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "rename json.c to an unmapped path"
set +e
run_vi >/dev/null 2>&1
s=$?
set -e
ok "$((s != 0 ? 0 : 1))" "rename to an UNMAPPED new path still fails closed"

# ---- case 3: delete drops edges, no orphan target, exit 0 ------------------
git -C "$REPO" checkout -q -b case-delete "$BASE_SHA"
git -C "$REPO" rm -q ci/prober/rules.c
git -C "$REPO" commit -q -m "delete rules.c"
set +e
out="$(run_vi)"
s=$?
set -e
clean_no_rules=1
grep -q "rules_test" <<<"$out" && clean_no_rules=0
ok "$((s == 0 && clean_no_rules == 1 ? 0 : 1))" \
    "deleting rules.c exits 0 and selects no orphan target"

# non-vacuity pair: editing (not deleting) the same file must still select
# its owner -- proves the empty selection above is the DELETE path, not a
# blanket "rules.c never selects anything" bug.
git -C "$REPO" checkout -q -b case-edit-not-delete "$BASE_SHA"
printf 'int rules_a(void) { return 2; }\n' >"$REPO/ci/prober/rules.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "edit rules.c"
set +e
out="$(run_vi)"
s=$?
set -e
ok "$((s == 0 && $(printf '%s\n' "$out" | grep -c rules_test) > 0 ? 0 : 1))" \
    "editing (not deleting) rules.c still selects rules_test"

# ---- case 4: header fanout selects a .h's dependents' owners ---------------
# Build ci/prober/*.d for the base commit's own tree so `have_dep_files` sees
# real generated-dep data, mirroring a PROBER_EMIT_DEPS=1 build.sh run.
git -C "$REPO" checkout -q -b case-header-fanout "$BASE_SHA"
printf 'json.o: json.c json.h\n' >"$REPO/ci/prober/json.d"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "seed generated deps"
HFAN_BASE="$(git -C "$REPO" rev-parse HEAD)"
printf 'int json_a(void); int json_b(void);\n' >"$REPO/ci/prober/json.h"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "change json.h"
set +e
out="$(cd "$REPO" && ./ci/prober/verify-impact --base "$HFAN_BASE")"
s=$?
set -e
ok "$((s == 0 && $(printf '%s\n' "$out" | grep -c json_test) > 0 ? 0 : 1))" \
    "changing json.h fans out to json_test via the generated .d dependents"

# non-vacuity pair: the SAME .h change with no .d files present must WARN,
# not silently claim the same coverage -- proves the fanout above genuinely
# read the .d file rather than hard-coding json.h -> json_test.
git -C "$REPO" checkout -q -b case-header-fanout-nodeps "$BASE_SHA"
git -C "$REPO" rm -q --cached ci/prober/json.d 2>/dev/null || true
rm -f "$REPO/ci/prober/json.d"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "no generated deps" --allow-empty
NODEP_BASE="$(git -C "$REPO" rev-parse HEAD)"
printf 'int json_a(void); int json_b(void);\n' >"$REPO/ci/prober/json.h"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "change json.h with no .d present"
set +e
errout="$(cd "$REPO" && ./ci/prober/verify-impact --base "$NODEP_BASE" 2>&1 >/dev/null)"
s=$?
set -e
warned=1
grep -qi "WARNING" <<<"$errout" || warned=0
# The header has no direct impact.map row AND no .d evidence exists to compute
# its dependents -- the tool cannot prove what it reaches, so it must both WARN
# and FAIL-CLOSED (nonzero). Asserting only the WARNING would let the inverse
# vacuity trap (WARN-then-exit-0) pass (CR #122 Major).
ok "$((warned == 1 && s != 0 ? 0 : 1))" \
    "a header change with no .d files present WARNS and fails closed (nonzero exit)"

# ---- case 5: empty/docs-only diff selects nothing, exit 0 ------------------
git -C "$REPO" checkout -q -b case-docs "$BASE_SHA"
printf 'more notes\n' >>"$REPO/README.md"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "docs only"
set +e
out="$(run_vi)"
s=$?
set -e
docs_ok=1
[ "$s" -eq 0 ] || docs_ok=0
[ -z "$out" ] || docs_ok=0
ok "$((docs_ok == 1 ? 0 : 1))" \
    "a docs-only diff (README.md) exits 0 and selects nothing"

# non-vacuity pair: the same commit ALSO touching a real source line must
# select a target -- proves the empty selection above is really "docs-only",
# not "this tool always selects nothing".
git -C "$REPO" checkout -q -b case-docs-plus-code "$BASE_SHA"
printf 'more notes\n' >>"$REPO/README.md"
printf 'int json_a(void) { return 3; }\n' >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "docs plus a real code change"
set +e
out="$(run_vi)"
s=$?
set -e
ok "$((s == 0 && $(printf '%s\n' "$out" | grep -c json_test) > 0 ? 0 : 1))" \
    "the same diff, with a real code line added, DOES select a target"

# ---- case 6: a `#`-prefixed line in a .c file is a preprocessor directive,
# NOT a comment -- it must count as executable and select the file's owner.
# This is the CR #122 CRITICAL: the shell-`#`-comment heuristic must never
# exempt a changed #include/#define in C, or a fail-closed gate fails OPEN.
git -C "$REPO" checkout -q -b case-c-preprocessor "$BASE_SHA"
printf '#include <string.h>\nint json_a(void) { return 1; }\n' >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "add an #include to json.c"
set +e
out="$(run_vi)"
s=$?
set -e
ok "$((s == 0 && $(printf '%s\n' "$out" | grep -c json_test) > 0 ? 0 : 1))" \
    "a changed #include in a .c file is executable (selects json_test), not a comment"

# non-vacuity pair: a real whole-line C comment (// ...) added to the SAME file
# IS exempt -- proves case 6's selection is the `#`-is-executable rule, not
# "any change to json.c always selects".
git -C "$REPO" checkout -q -b case-c-comment "$BASE_SHA"
printf '// a genuine comment\nint json_a(void) { return 1; }\n' >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "add a // comment to json.c"
set +e
out="$(run_vi)"
s=$?
set -e
comment_exempt=1
[ "$s" -eq 0 ] || comment_exempt=0
[ -z "$out" ] || comment_exempt=0
ok "$((comment_exempt == 1 ? 0 : 1))" \
    "a whole-line // comment added to json.c IS exempt (selects nothing)"

# ---- case 8: a LARGE executable diff must classify, not die of SIGPIPE -----
# The exemption test reads the changed lines with `grep -qvE <<<"$changed"`.
# It used to be `printf '%s\n' "$changed" | grep -qvE`, and `grep -q` exits on
# its FIRST match without draining stdin -- so once the diff passes the 64KiB
# pipe buffer the writing printf takes SIGPIPE and `set -o pipefail` turns
# rc=141 into a failure of verify-impact itself. Measured: clean at 100 changed
# lines, rc=141 at 20000. That is fail-CLOSED-by-accident on exactly the large
# refactor a selector is most needed for, and it is invisible to every small
# fixture above. Sibling of the `find ... | head -1` SIGPIPE fix in lib.sh.
#
# 40000 executable lines is ~600KiB, comfortably past the buffer. json.c is
# already mapped in impact.map, so a correct run selects json_test and exits 0.
git -C "$REPO" checkout -q -b case-bigdiff "$BASE_SHA"
{
    for i in $(seq 1 40000); do printf 'int json_big_%s(void) { return %s; }\n' "$i" "$i"; done
} >"$REPO/ci/prober/json.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "a very large executable change to json.c"
set +e
out="$(run_vi 2>"$WORK/vi_err_big")"
s=$?
set -e
bigdiff_ok=1
[ "$s" -eq 0 ] || bigdiff_ok=0
grep -q json_test <<<"$out" || bigdiff_ok=0
[ "$bigdiff_ok" -eq 1 ] || diag "large diff: exit=$s out=$(printf '%s' "$out" | head -c 200)"
ok "$((bigdiff_ok == 1 ? 0 : 1))" \
    "a 40k-line executable diff selects json_test instead of dying on SIGPIPE"

# ---- plan reconciliation ----------------------------------------------------
if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    diag "$failures of $tests_run self-tests failed"
    exit 1
fi
