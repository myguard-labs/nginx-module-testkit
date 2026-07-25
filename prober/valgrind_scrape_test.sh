#!/usr/bin/env bash
#
# TAP self-test: proves the valgrind gate is NOT vacuous.
#
# `valgrind --error-exitcode=N` is the belt: without it memcheck exits 0 by
# DEFAULT even when it reported errors -- exit status alone answers "did the
# child crash", not "did memcheck find anything". A gate that trusted only the
# exit code would therefore stay green on any build that forgot the flag, or
# on a log written by a valgrind process that was never told to fail the exit
# code at all. prober_scrape_valgrind (lib.sh) is the suspenders: it greps the
# log text regardless of what the exit code says, which is what makes the
# combination non-vacuous. This file proves BOTH halves, and proves them
# against the SAME planted error so neither claim is asserted in isolation:
#
#   1. --error-exitcode=99 DOES make a real memcheck finding fail the process.
#   2. Exit 0 WITHOUT that flag on the identical finding proves the flag was
#      necessary -- the vacuity this whole leg exists to rule out.
#   3. prober_scrape_valgrind() itself returns 1 on the error log, 0 on a
#      clean one -- the function the engine actually calls, not a proxy for it.
#
# No server, no nginx build: this compiles two tiny throwaway C programs and
# runs them under the system valgrind, so it costs seconds, not the minutes a
# real scenario run under memcheck costs, and runs on every `./test.sh`
# invocation rather than only in the weekly valgrind job.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v valgrind >/dev/null 2>&1; then
    echo "1..0 # SKIP no valgrind on this box"
    exit 0
fi

CC="${CC:-cc}"

# valgrind on a 32-bit target needs glibc's 32-bit debuginfo (libc6-dbg:i386) to
# resolve ld-linux.so.2 symbols; without it memcheck aborts ("Cannot continue")
# rather than running. That debuginfo is an orthogonal dependency the 32-bit
# build leg does not carry, and this test's job -- proving prober_scrape_valgrind
# is non-vacuous -- is fully exercised on the native leg. SKIP under -m32.
case " $CC " in
    *" -m32 "*)
        echo "1..0 # SKIP valgrind gate proven on the native leg; -m32 needs libc6-dbg:i386"
        exit 0
        ;;
esac

export TMPDIR
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/valgrind_scrape_test.XXXXXX")"
SCRATCH="$TMPDIR"
cleanup() {
    [ -n "${SCRATCH:-}" ] && rm -rf "$SCRATCH"
    return 0
}
trap cleanup EXIT

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

# shellcheck source=lib.sh
. ./lib.sh

# --- fixtures -----------------------------------------------------------
#
# leaky.c: mallocs a buffer and never frees it, and reads its first byte back
# through a `volatile` pointer so the compiler cannot prove the block dead and
# fold the whole allocation away at -O1 (build.sh's floor). A never-freed,
# never-again-referenced block is exactly a "definitely lost" leak -- the
# deterministic finding class this test wants, unlike an uninitialised-read
# report whose exact wording can vary across memcheck versions.
cat > "$SCRATCH/leaky.c" <<'EOF'
#include <stdlib.h>
int main(void) {
    char *p = malloc(32);
    volatile char *vp = p;
    if (vp == NULL) { return 1; }
    /* WRITE through the volatile pointer (not read an uninit byte): the write
     * keeps the compiler from folding the never-freed block away at -O1, and
     * returning a constant 0 keeps the exit status deterministic. Reading
     * vp[0] instead would (a) add an uninitialised-read finding that muddies
     * the "definitely lost" isolation and (b) make the ungated run's exit
     * status depend on whether the uninit byte happened to be 42 -- a ~1/256
     * false failure of the exit-0 assertion. */
    vp[0] = 42;
    return 0;
}
EOF

# clean.c: the negative control for prober_scrape_valgrind itself -- a program
# valgrind has nothing to say about, so the function's "0 on a clean log"
# claim is checked against a REAL valgrind log, not a hand-written fixture.
cat > "$SCRATCH/clean.c" <<'EOF'
int main(void) { return 0; }
EOF

# shellcheck disable=SC2086  # CC may carry flags (e.g. "gcc -m32"); word-split like build.sh
$CC -O0 -g -o "$SCRATCH/leaky" "$SCRATCH/leaky.c"
# shellcheck disable=SC2086
$CC -O0 -g -o "$SCRATCH/clean" "$SCRATCH/clean.c"

# --- 1/2: --error-exitcode DOES turn a real finding into a failing exit -----
# `|| rc=$?` rather than a bare call: under `set -e` a plain nonzero-exit
# command not inside an if/while/&&/|| condition aborts the script on the
# spot, which would kill this test before it ever inspected the very exit
# code it exists to check.
rc=0
valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite \
    --log-file="$SCRATCH/vg_gated.log" "$SCRATCH/leaky" >/dev/null 2>&1 || rc=$?

if [ "$rc" -eq 99 ]; then
    ok 0 "--error-exitcode=99 fails the exit status on a real leak"
else
    ok 1 "--error-exitcode=99 fails the exit status on a real leak (got rc=$rc)"
fi

if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' "$SCRATCH/vg_gated.log"; then
    ok 0 "the gated run's log carries the finding"
else
    ok 1 "the gated run's log carries the finding"
    diag "log contents:"
    sed 's/^/# /' "$SCRATCH/vg_gated.log"
fi

# --- 3/4: THE VACUITY PROOF -- the identical finding, WITHOUT the flag ------
#
# This is the load-bearing pair. memcheck's default behaviour is to report
# everything it finds and still exit 0 -- the finding does not fail the
# process unless something (here, --error-exitcode) says it should. A gate
# built on exit code alone is therefore vacuous by default: it is testing
# "did valgrind itself crash", not "did valgrind find anything". Any consumer
# who runs `valgrind ./server; echo $?` and trusts a 0 is reading a result
# that says nothing about leaks.
rc=0
valgrind --leak-check=full --errors-for-leak-kinds=definite \
    --log-file="$SCRATCH/vg_ungated.log" "$SCRATCH/leaky" >/dev/null 2>&1 || rc=$?

if [ "$rc" -eq 0 ]; then
    ok 0 "VACUITY PROOF: memcheck exits 0 by default even WITH a real leak"
else
    ok 1 "VACUITY PROOF: memcheck exits 0 by default even WITH a real leak (got rc=$rc)"
fi

if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' "$SCRATCH/vg_ungated.log"; then
    ok 0 "...yet the log STILL carries the finding (the belt-and-suspenders case)"
else
    ok 1 "...yet the log STILL carries the finding (the belt-and-suspenders case)"
    diag "log contents:"
    sed 's/^/# /' "$SCRATCH/vg_ungated.log"
fi

# --- 5/6: prober_scrape_valgrind() itself, against the ungated log's exit 0
#
# Reusing the exit-0 (ungated) log is deliberate: it is the exact shape a
# consumer's run would leave behind if they forgot --error-exitcode, and it
# is the log this function has to catch for the gate to be non-vacuous. The
# clean run is the negative control -- a real valgrind log with nothing to
# report, proving the function does not just always return 1.
PROBER_PREFIX="$SCRATCH/prefix1"
mkdir -p "$PROBER_PREFIX/logs"
cp "$SCRATCH/vg_ungated.log" "$PROBER_PREFIX/logs/valgrind.99999"

if prober_scrape_valgrind >"$SCRATCH/scrape.out" 2>&1; then
    ok 1 "prober_scrape_valgrind returns 1 on a log carrying a real leak"
else
    ok 0 "prober_scrape_valgrind returns 1 on a log carrying a real leak"
fi

PROBER_PREFIX="$SCRATCH/prefix2"
mkdir -p "$PROBER_PREFIX/logs"
valgrind --leak-check=full --errors-for-leak-kinds=definite \
    --log-file="$PROBER_PREFIX/logs/valgrind.%p" "$SCRATCH/clean" >/dev/null 2>&1

if prober_scrape_valgrind >/dev/null 2>&1; then
    ok 0 "prober_scrape_valgrind returns 0 on a clean valgrind log"
else
    ok 1 "prober_scrape_valgrind returns 0 on a clean valgrind log"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
