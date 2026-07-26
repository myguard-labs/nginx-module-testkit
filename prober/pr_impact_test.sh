#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# TAP self-test for prober/pr-impact (P2-C).
#
# WHY A THROWAWAY FIXTURE TREE. pr-impact drives verify-impact (git diff
# classification), builds+runs a unit test binary, replays a fuzz target under
# ASan/UBSan, runs a unit test under Memcheck, checks coverage-map.json, and
# reinvokes mutate.sh -- so a fixture that is not a real, compilable, tiny
# prober-shaped tree would only prove the JSON-formatting code, not the actual
# phase runners. Every fixture below is a throwaway git repo (mirroring
# verify_impact_test.sh's and coverage_director_test.sh's own pattern) with a
# minimal 1-function LIB, one *_test.c, one fuzz_<t> pair, a tiny mutate.sh, a
# copy of the real verify-impact + impact.map, and a copy of THIS repo's real
# pr-impact (its LIB list is swapped to the fixture's single lib.c via sed,
# exactly as coverage_director_test.sh does for coverage-director.sh's own LIB
# constant).
#
# NON-VACUITY. Per repo culture (mutate.sh's own header, verify_impact_test.sh's
# own header): a phase that stays green with its mutant restored is dead
# weight. Every one of the 5 phases gets a PAIR -- inject one fault that phase
# alone should catch (assert "not ok N <phase>"), then revert it and assert the
# SAME phase reports "ok N <phase>" on the clean run (the negative control).
# Two additional un-paired fixtures close the acceptance bar: a docs-only diff
# (selects nothing, all 5 phases empty-with-classification, exit 0) and an
# unmapped-executable-line diff (verify-impact's own fail-closed exit,
# propagated through pr-impact's own exit status, not swallowed as "empty").
set -euo pipefail

cd "$(dirname "$0")"
PR_IMPACT_SRC="$PWD/pr-impact"
VERIFY_IMPACT_SRC="$PWD/verify-impact"

PLANNED=12
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

command -v jq >/dev/null 2>&1 || { echo "1..0 # SKIP pr_impact_test.sh needs jq"; exit 0; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pr_impact_test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- build ONE fixture repo, reused (via branches) across every case --------
#
# Layout: prober/{lib.c,lib.h,lib_test.c,verify-impact,impact.map,pr-impact,
#         mutate.sh,build.sh,test.sh}, prober/fuzz/{fuzz_lib.c,fuzz_standalone.c,
#         corpus/lib/seed}. lib.c holds ONE function, add_one(), whose behaviour
#         each phase's fault targets independently:
#   phase 1 (unit_test):    lib_test.c asserts add_one(1)==2 -- a fault flips
#                            the operator so the test's own assertion goes red.
#   phase 2 (fuzz_replay):  fuzz_lib.c calls add_one() and aborts (calls
#                            abort()) when fed a byte-length input mirroring a
#                            genuine crash-on-bad-input; the fault is a
#                            corpus seed that reaches that path, reverted by
#                            restoring a seed that does not.
#   phase 3 (memcheck):     the fault rewrites lib_test.c to malloc an int and
#                            never free it (still asserting add_one's value
#                            correctly, so phase 1's unit_test stays green) --
#                            memcheck must catch the leak regardless of what
#                            the test itself asserts. This is deliberately a
#                            SOURCE edit to lib_test.c (which pr-impact's
#                            phase 1 compiles directly), not a build.sh knob:
#                            pr-impact's own phase 1 never invokes the
#                            project's build.sh, it compiles unit tests with
#                            its own hardcoded command line, so a fault routed
#                            through build.sh would prove nothing about the
#                            binary phase 3 actually memchecks.
#   phase 4 (changed_coverage): a coverage-map.json fixture is written by hand
#                            (not by the real coverage-director.sh, which does
#                            not know this fixture's files) naming lib_test as
#                            the coverer of lib.c's one line; the fault is
#                            REMOVING that line's entry, which must make
#                            pr-impact report the changed line as uncovered.
#   phase 5 (mapped_mutation): a tiny mutate.sh-style mutation case is wired
#                            for add_one(); a fault BREAKS the mutation's own
#                            anchor (mirrors mutate.sh's own "BROKEN" class)
#                            by editing the mutation's expected suite so it no
#                            longer catches the change -- reported by mutate.sh
#                            as SURVIVED, which pr-impact's phase 5 must
#                            propagate as "not ok".
REPO="$WORK/repo"
mkdir -p "$REPO/prober/fuzz/corpus/lib"
git -C "$REPO" init -q
git -C "$REPO" config user.email "test@example.invalid"
git -C "$REPO" config user.name "pr-impact self-test"

write_lib_c() {   # $1 = 1 (correct) | 2 (broken add_one)
    if [ "$1" = "1" ]; then
        cat >"$REPO/prober/lib.c" <<'EOF'
#include "lib.h"
int add_one(int x) { return x + 1; }
EOF
    else
        cat >"$REPO/prober/lib.c" <<'EOF'
#include "lib.h"
int add_one(int x) { return x + 2; }
EOF
    fi
}

cat >"$REPO/prober/lib.h" <<'EOF'
#ifndef FIXTURE_LIB_H
#define FIXTURE_LIB_H
int add_one(int x);
#endif
EOF

write_lib_c 1

cat >"$REPO/prober/lib_test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"
int main(void) {
    if (add_one(1) != 2) { fprintf(stderr, "not ok\n"); return 1; }
    printf("ok\n");
    return 0;
}
EOF

# Fuzz target: aborts iff fed a payload starting with the byte 'X' -- a real,
# input-driven crash path a corpus seed can either reach or not.
cat >"$REPO/prober/fuzz/fuzz_lib.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "../lib.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'X') {
        abort();
    }
    (void) add_one(1);
    return 0;
}
EOF
cp "$PWD/fuzz/fuzz_standalone.c" "$REPO/prober/fuzz/fuzz_standalone.c"
printf 'safe seed\n' >"$REPO/prober/fuzz/corpus/lib/seed"

# Minimal build.sh so phase 1/3's "reuse fresh binary" mtime path and a plain
# `./build.sh` both work the way the real one does structurally, without
# pulling in the real repo's OpenSSL/zlib link deps this fixture does not use.
cat >"$REPO/prober/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O0 -g -std=c11}"
"$CC" $CFLAGS -o lib_test lib_test.c lib.c
EOF
chmod +x "$REPO/prober/build.sh"

# Tiny mutate.sh: ONE mutation, add_one's `+ 1` flipped to `+ 2`, asserted
# against lib_test. Mirrors the real mutate.sh's mutate()/summarise() contract
# closely enough that pr-impact's phase 5 (a real `./mutate.sh <filter>` call)
# exercises the genuine caught/survived/broken classification, not a stub.
cat >"$REPO/prober/mutate.sh" <<'MUTEOF'
#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")" || exit 1
FILTER="${1:-}"
work=$(mktemp -d)
pass=0; fail=0; broken=0
mutate() {
    local name="$1" file="$2" old="$3" new="$4" suite="$5"
    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then return; fi
    cp "$file" "$work/orig"
    if ! MUT_FILE="$file" MUT_OLD="$old" MUT_NEW="$new" python3 - <<'PY'
import os, sys
path, old, new = os.environ['MUT_FILE'], os.environ['MUT_OLD'], os.environ['MUT_NEW']
s = open(path).read()
if s.count(old) != 1:
    sys.exit(1)
open(path, 'w').write(s.replace(old, new))
PY
    then
        echo "BROKEN  $name -- anchor did not match uniquely"
        cp "$work/orig" "$file"; broken=$((broken + 1)); return
    fi
    if ! ./build.sh >"$work/build.log" 2>&1; then
        echo "BROKEN  $name -- did not compile"
        cp "$work/orig" "$file"; broken=$((broken + 1)); return
    fi
    if ./"$suite" >/dev/null 2>&1; then
        echo "SURVIVED $name -- $suite still passes"
        fail=$((fail + 1))
    else
        echo "caught   $name ($suite)"
        pass=$((pass + 1))
    fi
    cp "$work/orig" "$file"
}
mutate "add_one: increment doubled" lib.c 'x + 1' 'x + 2' lib_test
echo
echo "caught $pass, survived $fail, broken $broken"
rc=0
[ "$fail" -gt 0 ] || [ "$broken" -gt 0 ] && rc=1
rm -rf "$work"
exit "$rc"
MUTEOF
chmod +x "$REPO/prober/mutate.sh"

# test.sh, mirroring the real one closely enough for phase 3's memcheck path
# to find a binary already built (phase 1 built it) and for the harness's own
# "discovered, not listed" contract.
cat >"$REPO/prober/test.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null
./lib_test
EOF
chmod +x "$REPO/prober/test.sh"

cp "$VERIFY_IMPACT_SRC" "$REPO/prober/verify-impact"
chmod +x "$REPO/prober/verify-impact"

cat >"$REPO/prober/impact.map" <<'EOF'
PRIMARY	prober/lib.c	lib_test	fast
SEMANTIC	prober/fuzz/fuzz_lib.c	fuzz/fuzz_lib	fast
SEMANTIC	prober/lib.c	fuzz/fuzz_lib	fast
SEMANTIC	prober/fuzz/corpus/lib	fuzz/fuzz_lib	fast
SEMANTIC	prober/lib.c	mutate:add_one	fast
SEMANTIC	prober/build.sh	lib_test	fast
SEMANTIC	prober/mutate.sh	lib_test	fast
SEMANTIC	prober/lib_test.c	lib_test	fast
EOF

# pr-impact under test, LIB list swapped to the fixture's single lib.c --
# mirrors coverage_director_test.sh's own sed-swap of coverage-director.sh's
# LIB constant, so the phase-1/2 build commands compile the fixture's LIB
# instead of the real repo's 6-file LIB (which does not exist in this
# throwaway tree).
make_pr_impact_copy() {   # $1 = dest path
    # Two occurrences in pr-impact share this literal LIB="..." assignment
    # (phase 1's unit-test build and phase 2's fuzz-replay build) at DIFFERENT
    # indentation levels -- match on the assignment text only, not indentation,
    # so both get swapped to the fixture's single lib.c.
    sed 's/^\([[:space:]]*\)LIB="json\.c http\.c util\.c rules\.c assert\.c backend\.c"$/\1LIB="lib.c"/' \
        "$PR_IMPACT_SRC" >"$1"
    chmod +x "$1"
}
make_pr_impact_copy "$REPO/prober/pr-impact"

git -C "$REPO" add -A
git -C "$REPO" commit -q -m base
BASE_SHA="$(git -C "$REPO" rev-parse HEAD)"

run_pri() {
    ( cd "$REPO/prober" && ./pr-impact --base "$BASE_SHA" --budget 45 \
        --junit "$WORK/junit.xml" --summary "$WORK/summary.json" )
}

tap_line_for() {   # $1 = phase name -> prints its TAP line from the last run's stdout
    printf '%s\n' "$LAST_OUT" | grep -E "(ok|not ok) [0-9]+ $1( |$)"
}

phase_is_ok() {   # $1 = phase name; 0 if "ok N <phase>" (not "not ok")
    local line
    line="$(tap_line_for "$1")"
    case "$line" in
        "not ok"*) return 1 ;;
        "ok"*) return 0 ;;
        *) return 1 ;;
    esac
}

# =========================== PHASE 1: unit_test =============================
# clean baseline
set +e
LAST_OUT="$(run_pri)"; LAST_STATUS=$?
set -e
if phase_is_ok unit_test; then
    ok 0 "phase1 unit_test: clean lib.c reports ok"
else
    ok 1 "phase1 unit_test: clean lib.c reports ok"
    diag "$LAST_OUT"
fi

# fault: break add_one's own logic AND its owning test's expectation stays the
# same, so the test itself (not just the phase runner) goes red.
git -C "$REPO" checkout -q -b case-p1-fault "$BASE_SHA"
write_lib_c 2
git -C "$REPO" -C prober 2>/dev/null add -A || git -C "$REPO" add -A
git -C "$REPO" commit -q -m "fault: add_one returns x+2"
set +e
LAST_OUT="$(run_pri)"; LAST_STATUS=$?
set -e
if ! phase_is_ok unit_test; then
    ok 0 "phase1 unit_test: faulted add_one() is caught (not ok)"
else
    ok 1 "phase1 unit_test: faulted add_one() is caught (not ok)"
    diag "$LAST_OUT"
fi
git -C "$REPO" checkout -q "$BASE_SHA"
git -C "$REPO" branch -q -D case-p1-fault

# =========================== PHASE 2: fuzz_replay ===========================
# clean baseline: seed corpus does not start with 'X', fuzz_lib.c added.
git -C "$REPO" checkout -q -b case-p2-clean "$BASE_SHA"
git -C "$REPO" commit -q --allow-empty -m "p2 baseline (fuzz already wired)"
BASE_P2="$(git -C "$REPO" rev-parse HEAD)"
set +e
LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$BASE_P2" --budget 45 \
    --junit "$WORK/junit2.xml" --summary "$WORK/summary2.json" )"
LAST_STATUS=$?
set -e
if phase_is_ok fuzz_replay; then
    ok 0 "phase2 fuzz_replay: safe corpus seed reports ok"
else
    ok 1 "phase2 fuzz_replay: safe corpus seed reports ok"
    diag "$LAST_OUT"
fi

# fault: a corpus seed that starts with 'X' reaches the abort() path.
printf 'Xtrigger\n' >"$REPO/prober/fuzz/corpus/lib/crash_seed"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "fault: add a corpus seed that triggers abort()"
set +e
LAST_OUT="$(run_pri)"; LAST_STATUS=$?
set -e
if ! phase_is_ok fuzz_replay; then
    ok 0 "phase2 fuzz_replay: crash-triggering seed is caught (not ok)"
else
    ok 1 "phase2 fuzz_replay: crash-triggering seed is caught (not ok)"
    diag "$LAST_OUT"
fi
git -C "$REPO" checkout -q "$BASE_SHA"
git -C "$REPO" branch -q -D case-p2-clean

# ======================= PHASE 3: memcheck_microtarget =======================
# clean baseline (no leak define).
git -C "$REPO" checkout -q -b case-p3-clean "$BASE_SHA"
git -C "$REPO" commit -q --allow-empty -m "p3 baseline"
BASE_P3="$(git -C "$REPO" rev-parse HEAD)"
if command -v valgrind >/dev/null 2>&1; then
    set +e
    LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$BASE_P3" --budget 45 \
        --junit "$WORK/junit3.xml" --summary "$WORK/summary3.json" )"
    LAST_STATUS=$?
    set -e
    if phase_is_ok memcheck_microtarget; then
        ok 0 "phase3 memcheck: clean lib_test reports ok under Memcheck"
    else
        ok 1 "phase3 memcheck: clean lib_test reports ok under Memcheck"
        diag "$LAST_OUT"
    fi

    # fault: lib_test.c itself leaks a malloc'd int -- still asserts
    # add_one()'s value correctly (phase 1's unit_test must stay green), so
    # only phase 3's OWN memcheck run is what can catch this, not a
    # coincidental unit-test failure. Source edit only, no build.sh
    # involvement: pr-impact's phase 1 compiles lib_test.c with its own
    # hardcoded command line, never via the fixture's build.sh.
    git -C "$REPO" checkout -q -b case-p3-fault "$BASE_SHA"
    cat >"$REPO/prober/lib_test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"
int main(void) {
    int *leaked = malloc(sizeof(int));
    *leaked = add_one(1);
    if (*leaked != 2) { fprintf(stderr, "not ok\n"); return 1; }
    printf("ok\n");
    return 0;
}
EOF
    git -C "$REPO" add -A
    git -C "$REPO" commit -q -m "fault: lib_test.c leaks a malloc'd int"
    rm -f "$REPO/prober/lib_test"
    set +e
    LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$BASE_P3" --budget 45 \
        --junit "$WORK/junit3b.xml" --summary "$WORK/summary3b.json" )"
    LAST_STATUS=$?
    set -e
    if ! phase_is_ok memcheck_microtarget; then
        ok 0 "phase3 memcheck: a baked-in leak is caught (not ok) under Memcheck"
    else
        ok 1 "phase3 memcheck: a baked-in leak is caught (not ok) under Memcheck"
        diag "$LAST_OUT"
    fi
    git -C "$REPO" checkout -q "$BASE_SHA"
    git -C "$REPO" branch -q -D case-p3-clean case-p3-fault
else
    diag "valgrind not present -- phase3 pair reported via classification-only check"
    set +e
    LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$BASE_P3" --budget 45 \
        --junit "$WORK/junit3.xml" --summary "$WORK/summary3.json" )"
    LAST_STATUS=$?
    set -e
    class3="$(jq -r '.phases.memcheck_microtarget.classification' "$WORK/summary3.json")"
    case3_skipped=1
    case "$class3" in *valgrind*) ;; *) case3_skipped=0 ;; esac
    ok "$((case3_skipped == 1 ? 0 : 1))" \
        "phase3 memcheck: SKIP classification when valgrind absent (clean run)"
    ok 0 "phase3 memcheck: fault pair skipped (no valgrind on this box)"
    git -C "$REPO" checkout -q "$BASE_SHA"
    git -C "$REPO" branch -q -D case-p3-clean
fi

# ======================== PHASE 4: changed_coverage ==========================
# clean baseline: coverage-map.json names lib_test as covering lib.c line 2
# (the `return x + 1;` line -- actually the whole one-liner is line 2 in the
# fixture's lib.c: line1 #include, line2 the function).
git -C "$REPO" checkout -q -b case-p4-clean "$BASE_SHA"
printf '{"prober/lib.c": {"2": ["lib_test"]}}\n' >"$REPO/prober/coverage-map.json"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "p4 baseline: coverage-map.json covers line 2"
BASE_P4="$(git -C "$REPO" rev-parse HEAD)"
printf '#include "lib.h"\nint add_one(int x) { return (x + 1); }\n' >"$REPO/prober/lib.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "edit line 2, covered by lib_test in the map"
set +e
LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$BASE_P4" --budget 45 \
    --junit "$WORK/junit4.xml" --summary "$WORK/summary4.json" )"
LAST_STATUS=$?
set -e
if phase_is_ok changed_coverage; then
    ok 0 "phase4 changed_coverage: a changed line covered by a selected test reports ok"
else
    ok 1 "phase4 changed_coverage: a changed line covered by a selected test reports ok"
    diag "$LAST_OUT"
fi

# fault: remove line 2's entry from coverage-map.json (the changed line is now
# uncovered by ANY selected test) at the same base commit.
git -C "$REPO" checkout -q -b case-p4-fault "$BASE_P4"
printf '{"prober/lib.c": {"1": ["lib_test"]}}\n' >"$REPO/prober/coverage-map.json"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "fault: coverage-map.json no longer covers line 2"
FAULT_P4="$(git -C "$REPO" rev-parse HEAD)"
printf '#include "lib.h"\nint add_one(int x) { return (x + 1); }\n' >"$REPO/prober/lib.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "edit line 2, now UNCOVERED per the map"
set +e
LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$FAULT_P4" --budget 45 \
    --junit "$WORK/junit4b.xml" --summary "$WORK/summary4b.json" )"
LAST_STATUS=$?
set -e
if ! phase_is_ok changed_coverage; then
    ok 0 "phase4 changed_coverage: an uncovered changed line is caught (not ok)"
else
    ok 1 "phase4 changed_coverage: an uncovered changed line is caught (not ok)"
    diag "$LAST_OUT"
fi
git -C "$REPO" checkout -q "$BASE_SHA"
git -C "$REPO" branch -q -D case-p4-clean case-p4-fault

# ======================== PHASE 5: mapped_mutation ============================
# clean baseline: the mutate.sh case as wired (caught).
git -C "$REPO" checkout -q -b case-p5-clean "$BASE_SHA"
git -C "$REPO" commit -q --allow-empty -m "p5 baseline"
BASE_P5="$(git -C "$REPO" rev-parse HEAD)"
set +e
LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$BASE_P5" --budget 45 \
    --junit "$WORK/junit5.xml" --summary "$WORK/summary5.json" )"
LAST_STATUS=$?
set -e
if phase_is_ok mapped_mutation; then
    ok 0 "phase5 mapped_mutation: the wired mutation case is caught (reports ok)"
else
    ok 1 "phase5 mapped_mutation: the wired mutation case is caught (reports ok)"
    diag "$LAST_OUT"
fi

# fault: widen lib_test's own assertion so the mutation SURVIVES -- mutate.sh
# itself must then report SURVIVED and exit nonzero, which pr-impact's phase 5
# must propagate as "not ok".
git -C "$REPO" checkout -q -b case-p5-fault "$BASE_SHA"
cat >"$REPO/prober/lib_test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "lib.h"
int main(void) {
    /* fault: no longer asserts the exact value, so add_one()'s mutation
     * (x+1 -> x+2) can never be caught by this suite. */
    (void) add_one(1);
    printf("ok\n");
    return 0;
}
EOF
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "fault: lib_test no longer asserts add_one's value"
FAULT_P5_BASE="$(git -C "$REPO" rev-parse HEAD)"
# The diff for THIS run must also touch lib.c (impact.map's mutate:add_one
# owner), or verify-impact selects only lib_test (a unit-test target) and
# phase 5 never runs -- an empty phase would trivially "not fire", which is
# not the same claim as "mutate.sh reports SURVIVED and phase 5 propagates
# it". A no-op-behaviourally reformat of lib.c (mirrors phase 4's own
# no-op-value edit) puts lib.c in the diff without changing add_one's value.
printf '#include "lib.h"\nint add_one(int x) { return (x + 1); }\n' >"$REPO/prober/lib.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "touch lib.c so mutate:add_one is selected too"
set +e
LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$FAULT_P5_BASE" --budget 45 \
    --junit "$WORK/junit5b.xml" --summary "$WORK/summary5b.json" )"
LAST_STATUS=$?
set -e
if ! phase_is_ok mapped_mutation; then
    ok 0 "phase5 mapped_mutation: a weakened suite lets the mutant SURVIVE (not ok)"
else
    ok 1 "phase5 mapped_mutation: a weakened suite lets the mutant SURVIVE (not ok)"
    diag "$LAST_OUT"
fi
git -C "$REPO" checkout -q "$BASE_SHA"
git -C "$REPO" branch -q -D case-p5-clean case-p5-fault

# ---- docs-only diff: selects nothing, exits 0, all 5 phases empty ----------
git -C "$REPO" checkout -q -b case-docs "$BASE_SHA"
printf 'notes\n' >"$REPO/README.md"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "docs only"
DOCS_PARENT="$(git -C "$REPO" rev-parse HEAD^)"
set +e
LAST_OUT="$( cd "$REPO/prober" && ./pr-impact --base "$DOCS_PARENT" --budget 45 \
    --junit "$WORK/junit_docs.xml" --summary "$WORK/summary_docs.json" )"
LAST_STATUS=$?
set -e
docs_ok=1
[ "$LAST_STATUS" -eq 0 ] || docs_ok=0
for p in unit_test fuzz_replay memcheck_microtarget changed_coverage mapped_mutation; do
    sel="$(jq -r ".phases.\"$p\".selected | length" "$WORK/summary_docs.json" 2>/dev/null || echo 1)"
    [ "$sel" = "0" ] || docs_ok=0
    cls="$(jq -r ".phases.\"$p\".classification" "$WORK/summary_docs.json" 2>/dev/null || echo "")"
    [ -n "$cls" ] || docs_ok=0
done
ok "$((docs_ok == 1 ? 0 : 1))" \
    "a docs-only diff exits 0 and every phase is empty with a classification"
git -C "$REPO" checkout -q "$BASE_SHA"
git -C "$REPO" branch -q -D case-docs

# ---- unmapped executable diff: verify-impact's fail-closed exit propagates -
git -C "$REPO" checkout -q -b case-unmapped "$BASE_SHA"
printf 'int surprise(void) { return 1; }\n' >"$REPO/prober/newthing.c"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "add an unmapped source file"
set +e
( cd "$REPO/prober" && ./pr-impact --base "$BASE_SHA" --budget 45 \
    --junit "$WORK/junit_unmapped.xml" --summary "$WORK/summary_unmapped.json" ) \
    >"$WORK/unmapped.out" 2>"$WORK/unmapped.err"
UNMAPPED_STATUS=$?
set -e
# Must match verify-impact's OWN exit status for this fixture (fail-closed),
# not merely "some nonzero" -- and must NOT be swallowed as "5 empty phases,
# exit 0".
set +e
( cd "$REPO/prober" && ./verify-impact --base "$BASE_SHA" ) >/dev/null 2>/dev/null
VI_EXPECTED=$?
set -e
ok "$((UNMAPPED_STATUS != 0 && UNMAPPED_STATUS == VI_EXPECTED ? 0 : 1))" \
    "an unmapped executable diff propagates verify-impact's own fail-closed exit status ($VI_EXPECTED), not a swallowed 0"
git -C "$REPO" checkout -q "$BASE_SHA"
git -C "$REPO" branch -q -D case-unmapped

# ---- plan reconciliation ----------------------------------------------------
if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    diag "$failures of $tests_run self-tests failed"
    exit 1
fi
