#!/usr/bin/env bash
#
# Build and run every TAP self-test in this directory.
#
# These tests need no server: they exercise the harness's own parsers and
# assertion evaluators as pure functions. That is deliberate -- the harness
# decides whether a module's test run is green, so a defect in the harness turns
# every rule that depends on it into a test that cannot fail, which is worse
# than a missing test because the run still reports success. Those defects have
# to be catchable without booting nginx, or CI will not catch them at all.
#
# run.sh runs this before it boots a server. CI runs it standalone, twice
# (plain and SAN=1).
set -euo pipefail

cd "$(dirname "$0")"

./build.sh >/dev/null

# glibc's own cheap heap checks, for the harness's OWN test binaries -- the
# same coverage lib.sh:prober_heap_env gives the server, for the class the TAP
# suites otherwise cannot see: an uninitialised read or a use-after-free gets a
# garbage value (165: unmapped as a pointer, implausible as a length, not '\0')
# instead of the zeroes a quiet heap hands back, and MALLOC_CHECK_=3 aborts on
# heap corruption. Excluded on a sanitized build, not merely redundant: ASan
# replaces the allocator and ignores these, and MALLOC_CHECK_'s abort path can
# fire inside ASan's own bookkeeping (lib.sh:88). build.sh built every binary
# below with one SAN flag, so probing any one settles it for all.
probe_bin="$(printf '%s\n' *_test.c ../../t/*_test.c | sed -n 's/\.c$//p;q')"
if [ -n "${probe_bin:-}" ] && [ -e "$probe_bin" ] \
   && ! grep -qa '__asan_\|__ubsan_' "$probe_bin"; then
    export MALLOC_PERTURB_=165
    export MALLOC_CHECK_=3
fi

found=0
failed=0
# Names of the failing suites, accumulated so the summary can print them. A
# suite can exit nonzero with EVERY assertion green -- a plan-count mismatch
# ("ran 39 tests but the plan says 38") is the shape -- and then grepping the
# output for `not ok`, which is the reflex, finds nothing at all. Reporting
# only a COUNT sends the reader hunting for an assertion that does not exist.
failed_names=""

for src in *_test.c ../../t/*_test.c; do
    [ -e "$src" ] || continue

    bin="${src%.c}"
    case "$bin" in
        /*|../*) ;;
        *) bin="./$bin" ;;
    esac
    found=$((found + 1))

    echo "# --- $bin"

    # Not `set -e`-fatal: one failing suite must not hide the ones after it,
    # and the aggregate exit status below is what the caller gates on.
    if ! "$bin"; then
        failed=$((failed + 1))
        failed_names="$failed_names $bin"
        echo "# $bin FAILED"
    fi
done

# Shell-level suites, for behaviour that has no C entry point to call: the
# prober's own CLI. *_test.sh is a separate glob from *_test.c because these
# are run, not built, and this file is one of the matches to skip.
for sh_test in *_test.sh; do
    [ -e "$sh_test" ] || continue

    found=$((found + 1))

    echo "# --- ./$sh_test"

    if ! "./$sh_test"; then
        failed=$((failed + 1))
        failed_names="$failed_names ./$sh_test"
        echo "# ./$sh_test FAILED"
    fi
done

# Zero discovered suites is a failure, not a pass. A rename or a build-script
# regression that stops matching *_test.c would otherwise turn the whole
# self-test stage into a silent no-op that reports green.
if [ "$found" -eq 0 ]; then
    echo "# no self-tests found -- refusing to report success" >&2
    exit 1
fi

if [ "$failed" -gt 0 ]; then
    echo "# $failed of $found self-test suites failed:$failed_names" >&2
    echo "# a suite can fail with no \`not ok\` line (plan-count mismatch) --" >&2
    echo "# re-run the named suite alone and read its exit code" >&2
    exit 1
fi

echo "# $found self-test suites passed"
