#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# TAP self-test for prober/pr-memcheck (P2-F half 2).
#
# WHY A STUB verify-impact, NOT A GIT-DIFF FIXTURE. pr-memcheck's OWN logic is:
# classify verify-impact's TSV rows into direct-callable (memcheck them) vs
# boot-required (REFUSE them), enforce the budget, and emit non-vacuous TAP. That
# classification + refusal + verdict is what this file must prove, and it is
# independent of HOW the selection was computed. verify_impact_test.sh already
# proves the git-diff selection end to end; re-deriving it here would test
# verify-impact twice and pr-memcheck's own behaviour only incidentally. So each
# case installs a tiny STUB verify-impact that prints a controlled row set, and
# pr-memcheck runs against it -- letting a single case drive exactly the
# selection (a leaking unit test, a clean one, a scenario to refuse, an empty
# diff) that case is about.
#
# THE FIXTURE LIB. pr-memcheck compiles each selected *_test.c against a LIB
# constant (the real repo's 6-file LIB). A throwaway tree cannot carry those, so
# the pr-memcheck copy under test has its VG_LIB swapped to the fixture's single
# lib.c via sed -- the same idiom pr_impact_test.sh/coverage_director_test.sh use
# -- with a fail-loud check that the swap actually matched.
#
# NON-VACUITY. Every claim gets a control that fails BY THAT assertion:
#   - a genuinely LEAKING unit test reds its memcheck line; the SAME test with
#     the leak removed greens it (the memcheck verdict is load-bearing, not a
#     rubber stamp).
#   - a REFUSED scenario line is `ok` AND names both the native PR oracle and
#     the weekly memcheck owner; a pr-memcheck with those two strings blanked
#     reds the same line (proving the refusal is not a bare silent skip).
#   - a tiny --budget reds the target with a "budget exhausted" classification
#     (the budget is enforced, not decorative).
#   - an empty selection is a single explained ok line (not zero lines, not a
#     silent skip).
set -euo pipefail

cd "$(dirname "$0")"
PR_MEMCHECK_SRC="$PWD/pr-memcheck"

PLANNED=8
tests_run=0
failures=0

diag() { printf '# %s\n' "$1"; }

# Guard BEFORE the plan line: pr-memcheck's memcheck legs SKIP without valgrind,
# so the leak/clean/fuzz pairs cannot be proven here -- reporting the non-valgrind
# legs alone would misreport a partial run as a full pass. Skip the whole file
# the harness way, and do it before "1..$PLANNED" so the stream carries exactly
# ONE plan line (a second plan line is malformed TAP -- the pr_impact_test.sh:54
# double-plan class).
if ! command -v valgrind >/dev/null 2>&1; then
    echo "1..0 # SKIP pr_memcheck_test.sh needs valgrind"
    exit 0
fi

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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pr_memcheck_test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

REPO="$WORK/repo/prober"
mkdir -p "$REPO/fuzz/corpus/lib"

# --- fixture LIB: one function, and two *_test.c variants -------------------
cat >"$REPO/lib.h" <<'EOF'
#ifndef FIXTURE_LIB_H
#define FIXTURE_LIB_H
int add_one(int x);
#endif
EOF
cat >"$REPO/lib.c" <<'EOF'
#include "lib.h"
int add_one(int x) { return x + 1; }
EOF

# clean_test.c: allocates, uses, frees -- memcheck-clean.
cat >"$REPO/clean_test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"
int main(void) {
    int *p = malloc(sizeof *p);
    if (p == NULL) { return 2; }
    *p = add_one(1);
    if (*p != 2) { free(p); return 1; }
    free(p);
    printf("ok\n");
    return 0;
}
EOF

# leaky_test.c: mallocs a block, uses it (so -O0/-O1 cannot fold it away), and
# never frees it -- a "definitely lost" leak memcheck must catch. Exit status 0
# so the verdict comes from --error-exitcode / the log grep, not the program.
cat >"$REPO/leaky_test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"
int main(void) {
    int *p = malloc(sizeof *p);
    volatile int *vp = p;
    if (vp == NULL) { return 2; }
    vp[0] = add_one(1);
    /* deliberately never free(p): a definitely-lost leak. */
    printf("ok %d\n", (int) vp[0]);
    return 0;
}
EOF

# --- pr-memcheck under test, VG_LIB swapped to the fixture's single lib.c ----
make_pr_memcheck_copy() {   # $1 = dest path
    sed -e 's/^\([[:space:]]*\)VG_LIB="json\.c http\.c util\.c rules\.c assert\.c backend\.c"$/\1VG_LIB="lib.c"/' \
        "$PR_MEMCHECK_SRC" >"$1"
    grep -qE '^[[:space:]]*VG_LIB="lib\.c"$' "$1" || {
        echo "make_pr_memcheck_copy: VG_LIB= substitution did not match pr-memcheck's source -- fixture out of sync" >&2
        exit 1
    }
    chmod +x "$1"
}
make_pr_memcheck_copy "$REPO/pr-memcheck"

# a valgrind.supp is optional; provide an empty one so the copy's
# --suppressions path (if the file exists) is the same shape as production.
: >"$REPO/valgrind.supp"

# --- stub verify-impact: prints the row set the current case wants ----------
# Controlled via an environment file the stub sources. Each case writes ROWS
# (tab-separated TARGET<TAB>LANE lines) and VI_RC, then runs pr-memcheck.
write_stub_vi() {   # writes $REPO/verify-impact reading $REPO/vi_rows + $REPO/vi_rc
    cat >"$REPO/verify-impact" <<'EOF'
#!/usr/bin/env bash
# stub verify-impact for pr_memcheck_test.sh: echo the fixed rows, exit fixed rc.
cd "$(dirname "$0")"
[ -f vi_rows ] && cat vi_rows
exit "$(cat vi_rc 2>/dev/null || echo 0)"
EOF
    chmod +x "$REPO/verify-impact"
}
write_stub_vi

set_rows() { printf '%s\n' "$1" >"$REPO/vi_rows"; }
set_vi_rc() { printf '%s\n' "$1" >"$REPO/vi_rc"; }

LAST_OUT=""
run_prm() {   # extra args forwarded (e.g. --budget 1)
    # pr-memcheck exits nonzero on a caught leak / refusal red -- which is
    # exactly what several cases assert -- so the command substitution must not
    # abort this script under set -e. `|| true` keeps LAST_OUT populated; the
    # per-case TAP-line checks read the verdict, not pr-memcheck's exit code.
    LAST_OUT="$( cd "$REPO"; ./pr-memcheck "$@" 2>/dev/null || true )"
}

tap_line_matching() {   # $1 = extended-regex; prints the matching TAP line
    printf '%s\n' "$LAST_OUT" | grep -E "$1" || true
}

# =========================== 1/2: memcheck verdict is load-bearing ==========
# A leaking unit test must red its line; the clean one must green its line. Same
# selection shape, only the leak differs -> proves the memcheck run, not the
# formatting, decides.
set_vi_rc 0
set_rows "$(printf 'leaky_test\tfast')"
run_prm --budget 45
line="$(tap_line_matching 'leaky_test')"
case "$line" in
    "not ok"*) ok 0 "a leaking unit test is caught (not ok) under memcheck" ;;
    *) ok 1 "a leaking unit test is caught (not ok) under memcheck"; diag "got: $line" ;;
esac

set_rows "$(printf 'clean_test\tfast')"
run_prm --budget 45
line="$(tap_line_matching 'clean_test')"
case "$line" in
    "ok"*) ok 0 "NEG-CONTROL: a memcheck-clean unit test greens its line" ;;
    *) ok 1 "NEG-CONTROL: a memcheck-clean unit test greens its line"; diag "got: $line" ;;
esac

# =========================== 3/4: scenario REFUSAL is non-vacuous ============
# A scenario target is REFUSED (ok) and the refusal names BOTH the native PR
# oracle and the weekly memcheck owner.
set_rows "$(printf 'scenarios/reload-soak\tslow')"
run_prm --budget 45
line="$(tap_line_matching 'scenarios/reload-soak')"
if printf '%s' "$line" | grep -q '^ok' \
   && printf '%s' "$line" | grep -q 'REFUSED' \
   && printf '%s' "$line" | grep -q 'test-scenarios.sh' \
   && printf '%s' "$line" | grep -q 'valgrind-scenarios.sh'; then
    ok 0 "a boot-required scenario is REFUSED (ok) and names native oracle + weekly owner"
else
    ok 1 "a boot-required scenario is REFUSED (ok) and names native oracle + weekly owner"
    diag "got: $line"
fi

# NEG-CONTROL for the refusal: a pr-memcheck copy whose NATIVE_ORACLE and
# WEEKLY_OWNER are blanked must RED the same scenario line (proving the refusal
# is a real "here is where the coverage lives" pointer, not a bare ok that would
# pass no matter what it said).
BLANKED="$REPO/pr-memcheck-blanked"
sed -e 's/^\([[:space:]]*\)VG_LIB="json\.c http\.c util\.c rules\.c assert\.c backend\.c"$/\1VG_LIB="lib.c"/' \
    -e 's/^NATIVE_ORACLE=.*/NATIVE_ORACLE=""/' \
    -e 's/^WEEKLY_OWNER=.*/WEEKLY_OWNER=""/' \
    "$PR_MEMCHECK_SRC" >"$BLANKED"
chmod +x "$BLANKED"
LAST_OUT="$( cd "$REPO"; "$BLANKED" --budget 45 2>/dev/null || true )"
line="$(tap_line_matching 'scenarios/reload-soak')"
case "$line" in
    "not ok"*) ok 0 "NEG-CONTROL: blanking the oracle/owner reds the refusal (no silent skip)" ;;
    *) ok 1 "NEG-CONTROL: blanking the oracle/owner reds the refusal (no silent skip)"; diag "got: $line" ;;
esac

# =========================== 5: budget refusal is enforced ==================
# A tiny --budget must red the memcheck target with a budget-exhausted
# classification, not run it unbounded. (--budget 0 is the boundary the GNU
# `timeout 0` note in pr-memcheck guards; here 0 means "no time at all".)
set_rows "$(printf 'clean_test\tfast')"
run_prm --budget 0
line="$(tap_line_matching 'clean_test')"
if printf '%s' "$line" | grep -q '^not ok' \
   && printf '%s' "$line" | grep -qi 'budget'; then
    ok 0 "a zero budget reds the target with a budget-exhausted classification"
else
    ok 1 "a zero budget reds the target with a budget-exhausted classification"
    diag "got: $line"
fi

# =========================== 6: empty selection =============================
# No rows selected -> a single explained ok line, never zero lines / silent skip.
set_rows ""
run_prm --budget 45
plan_ran="$(printf '%s\n' "$LAST_OUT" | grep -cE '^(ok|not ok) ')"
line="$(printf '%s\n' "$LAST_OUT" | grep -E '^ok 1 ' || true)"
if [ "$plan_ran" -eq 1 ] && printf '%s' "$line" | grep -qi 'nothing to run or refuse'; then
    ok 0 "an empty selection emits exactly one explained ok line"
else
    ok 1 "an empty selection emits exactly one explained ok line"
    diag "ran=$plan_ran line=$line"
fi

# =========================== 7: fuzz targets are direct, not refused ========
# A fuzz/* row is direct-callable (a pure entry point) -> memchecked, not
# refused. Prove it lands on a memcheck line (ok/not ok fuzz/...), not a REFUSED
# line. Fixture fuzz target + corpus so the replay actually runs clean.
cat >"$REPO/fuzz/fuzz_lib.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
#include "../lib.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void) data; (void) size;
    (void) add_one(1);
    return 0;
}
EOF
cp "$PWD/fuzz/fuzz_standalone.c" "$REPO/fuzz/fuzz_standalone.c"
printf 'seed\n' >"$REPO/fuzz/corpus/lib/seed"
set_rows "$(printf 'fuzz/fuzz_lib\tfast')"
run_prm --budget 45
line="$(tap_line_matching 'fuzz/fuzz_lib')"
if printf '%s' "$line" | grep -q '^ok' \
   && ! printf '%s' "$line" | grep -q 'REFUSED'; then
    ok 0 "a fuzz target is memchecked directly (ok, not refused)"
else
    ok 1 "a fuzz target is memchecked directly (ok, not refused)"
    diag "got: $line"
fi

# =========================== 8: verify-impact fail-closed propagates ========
# verify-impact exiting nonzero (an unmapped executable line) must make
# pr-memcheck exit nonzero too, not read as "no targets, all green".
set_rows ""
set_vi_rc 2
prm_rc=0
( cd "$REPO" && ./pr-memcheck --budget 45 >/dev/null 2>&1 ) || prm_rc=$?
set_vi_rc 0
if [ "$prm_rc" -ne 0 ]; then
    ok 0 "verify-impact fail-closed exit propagates through pr-memcheck"
else
    ok 1 "verify-impact fail-closed exit propagates through pr-memcheck"
    diag "pr-memcheck rc=$prm_rc (expected nonzero)"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
