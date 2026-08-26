#!/usr/bin/env bash
#
# Build the rule-driven prober and every TAP self-test beside it. Strict by
# default: this is test infrastructure, and a harness that compiles with
# warnings is a harness nobody trusts.
set -euo pipefail

cd "$(dirname "$0")"

CC="${CC:-cc}"

# The warning wall. -Wconversion/-Wsign-conversion are the load-bearing pair:
# this code does size_t/int/ssize_t arithmetic on lengths taken off a socket,
# and an implicit narrowing or sign flip in that arithmetic is the mechanical
# form of roughly half the findings a parser-lens audit turns up by reading.
# Making them -Werror means the compiler catches that class before review does.
#
# -Wdeclaration-after-statement is not pedantry either: the probe half of this
# repo compiles INTO nginx and angie, whose house style is C89 declarations. A
# declaration that builds here but not in a consumer's tree is a break we would
# otherwise discover in the consumer.
WARN="-Wall -Wextra -Werror"
WARN="$WARN -Wconversion -Wsign-conversion -Wshadow -Wvla -Wformat=2"
WARN="$WARN -Wwrite-strings -Wcast-qual -Wpointer-arith"
WARN="$WARN -Wdeclaration-after-statement"

# Canary + fortify, on by default rather than only in the dedicated CI gate
# (build-flags-canary in ci.yml): a flag that only CI passes is a flag nobody
# develops against, and the reproducible-build/analyzers jobs both invoke this
# script, so they get the same instrumentation for free rather than drifting
# from what actually ships. -D_FORTIFY_SOURCE=3 needs -O1 or higher to have
# any effect (already the floor here) and rewrites bounded-length libc calls
# (memcpy/snprintf/read/...) to their _chk form when the compiler can see a
# destination size at the call site. -fstack-protector-strong instruments
# every function with a local array or an address-taken local with a stack
# canary. Real checksec (RELRO/NX/RPATH on a linked .so) is left to
# consumers -- this repo builds relocatable .o objects, not a .so, so those
# properties do not exist here to check; see the build-flags-canary job
# comment in ci.yml for the full reasoning.
HARDEN="-D_FORTIFY_SOURCE=3 -fstack-protector-strong"

CFLAGS="${CFLAGS:--O1 -g -std=c11 $WARN $HARDEN}"

# SAN=1 builds the prober itself under ASan/UBSan. The prober parses attacker-
# shaped text from rule files and untrusted-shaped bytes off the socket, so it
# gets the same treatment the module under test does.
if [ "${SAN:-0}" = "1" ]; then
    CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
    # -fno-sanitize-recover=undefined is what actually enforces halting: it is
    # a compile-time property baked into the binary, so it survives any
    # caller that runs the binary without carrying UBSAN_OPTIONS through --
    # test.sh, mutate.sh and the CI workflow all invoke build.sh's output
    # without setting it themselves. Without this flag UBSan defaults to
    # printing and continuing, so every finding in a sanitizer run is
    # advisory and the run still exits 0.
    #
    # The export below is NOT what enforces halting (that used to be the
    # claim here, and it was wrong: UBSAN_OPTIONS lives in this script's own
    # process and dies with it, never reaching the test binary in a fresh
    # shell). It is kept because it still improves the trace when the flag
    # above does trip: print_stacktrace=1 works whenever a caller's
    # environment happens to inherit this export, e.g. fuzz.sh re-exports it
    # itself before replaying a crash.
    CFLAGS="$CFLAGS -fno-sanitize-recover=undefined"
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
fi

# Every translation unit except the one holding main(). Test binaries link the
# whole set rather than a hand-maintained per-test list, so adding a module does
# not mean editing N link lines -- and a test that reaches into another unit
# keeps working instead of failing at link time for a bookkeeping reason.
LIB="json.c http.c util.c rules.c assert.c backend.c"

# body_sha256 oracle uses OpenSSL for SHA256 hashing; the gunzip oracle uses
# zlib for inflate.
LDFLAGS="${LDFLAGS:-}"
if command -v pkg-config >/dev/null 2>&1; then
    LDFLAGS="$LDFLAGS $(pkg-config --libs openssl 2>/dev/null || echo '-lssl -lcrypto')"
    LDFLAGS="$LDFLAGS $(pkg-config --libs zlib 2>/dev/null || echo '-lz')"
else
    LDFLAGS="$LDFLAGS -lssl -lcrypto -lz"
fi

# Every $CC invocation below is independent -- each links a self-contained
# binary from source, none reads another's output -- so they run concurrently
# and are joined at the end. This is the load-bearing speedup for the mutation
# job, which reinvokes this script once per mutant (89x): serialised, the ten
# compile-and-link commands dominated its wall clock. `pids` collects each
# background job; the final wait loop makes ANY compile failure fail the whole
# script with a nonzero exit, preserving mutate.sh's BROKEN-on-noncompile
# contract. There are only ~10 short compiles, so they are all launched at once
# rather than throttled -- ten concurrent cc processes is well within any real
# runner. PROBER_BUILD_JOBS=1 forces the old serial behaviour (a tiny or
# heavily-loaded runner, or bisecting a build race).
serial=0
[ "${PROBER_BUILD_JOBS:-0}" = "1" ] && serial=1

pids=""

compile() {   # all args = one full $CC command line
    if [ "$serial" = "1" ]; then
        "$@"
    else
        "$@" &
        pids="$pids $!"
    fi
}

# shellcheck disable=SC2086
compile $CC $CFLAGS -o prober prober.c $LIB $LDFLAGS
built="$PWD/prober"

# The fake upstream daemon. Its own link line rather than a member of $LIB
# because it has a main(): adding it there would give every test binary two.
# It is also not named *_test.c, which keeps the discovery loop below from
# treating a daemon as a self-test and running it with no arguments.
# shellcheck disable=SC2086
compile $CC $CFLAGS -o fakesrv fakesrv.c $LIB $LDFLAGS
built="$built $PWD/fakesrv"

# Self-tests are discovered, not listed: dropping a new *_test.c in this
# directory is enough to get it built and (via test.sh) run. A test that has to
# be registered in two places is a test that eventually is not run at all.
for src in *_test.c; do
    [ -e "$src" ] || continue

    bin="${src%.c}"

    # shellcheck disable=SC2086
    compile $CC $CFLAGS -o "$bin" "$src" $LIB $LDFLAGS

    built="$built $PWD/$bin"
done

# The probe's own self-tests live in ../../t and build differently: they compile a
# translation unit from src/ against the small shim in t/ instead of linking the
# prober's units, so they get their own loop rather than a special case inside
# the one above.
#
# Three units are reachable this way: ngx_test_probe_arm.c (a query parser,
# which needs nothing but the query bytes), ngx_test_probe_redzone.c (a pool
# allocator wrapper) and ngx_test_probe_canary.c (a slab allocator wrapper).
# Both allocator wrappers get REAL allocators from t/ngx_pool_shim.h rather
# than malloc-per-object stubs, because the bug classes they catch are created
# by the allocators' own behaviour: bump allocation makes objects adjacent, and
# slab's power-of-two rounding creates the slack an overflow hides in. A stub
# would make those tests pass for the wrong reason.
#
# The renderer beside them is NOT reachable: it reads ngx_cycle, the slab pool
# and /proc/self/fd, so shimming it would mean reimplementing the server. It is
# covered by the compile-against-real-nginx and real-angie jobs in CI, and by
# the live prober run.
for src in ../../t/*_test.c; do
    [ -e "$src" ] || continue

    bin="${src%.c}"

    # Which src/ unit a suite links, and any extra defines it needs, is a
    # property of the SUITE, not of this loop -- so it is selected per file
    # rather than hardcoded. Adding a third shimmable unit means adding a case
    # here, which is the point at which someone has to state what it links.
    case "$(basename "$src")" in
        probe_canary_test.c)
            # Same shim, different unit: the canary guards SLAB allocations,
            # so the shim additionally supplies a power-of-two-rounding slab
            # arena (an exact-fit stub would leave no slack to overflow into,
            # and the slack is the bug class under test).
            unit=../../src/ngx_test_probe_canary.c
            extra=-DNGX_TEST_PROBE_POOL_SHIM
            ;;
        probe_redzone_test.c)
            # The redzone allocator needs a working pool, which ngx_shim.h
            # deliberately does not provide. NGX_TEST_PROBE_POOL_SHIM selects
            # t/ngx_pool_shim.h inside the unit under test; a real build
            # defines nothing and takes the pool from ngx_core.h.
            unit=../../src/ngx_test_probe_redzone.c
            extra=-DNGX_TEST_PROBE_POOL_SHIM
            ;;
        *)
            unit=../../src/ngx_test_probe_arm.c
            extra=
            ;;
    esac

    # shellcheck disable=SC2086
    compile $CC $CFLAGS -DNGX_TEST_HARNESS $extra -I ../../t -I ../../src \
        -o "$bin" "$src" "$unit"

    built="$built $(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
done

# Join every background compile. A nonzero from any one must fail the script:
# `set -e` does not fire on a plain aggregate `wait`, so each pid is waited
# individually and `set -e` aborts on the first nonzero status. Preserves the
# noncompile=BROKEN contract mutate.sh depends on. Waiting each pid exactly once
# (none was reaped earlier -- there is no throttling `wait -n`) keeps every
# status retrievable.
for pid in $pids; do
    wait "$pid"
done

echo "built: $built"
