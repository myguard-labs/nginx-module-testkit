#!/usr/bin/env bash
#
# Build and run the prober's parser fuzz targets, in one of two modes.
#
#   ./fuzz.sh replay              corpus replay under gcc + ASan/UBSan (PR path)
#   ./fuzz.sh fuzz [SECONDS]      libFuzzer discovery under clang (scheduled)
#
# replay is deterministic and engine-free: it links each fuzz_<t>.c with the
# standalone driver, feeds the checked-in corpus/<t>/ once, and exits nonzero on
# the first crash or sanitizer abort. That is the vacuous-gate defence -- there
# is no "report and continue" path, only the process living or dying.
#
# fuzz needs clang (-fsanitize=fuzzer) and mutates unbounded, so it is a
# scheduled discovery job, never on the per-commit path. It writes new crashers
# to crashes/<t>/ for triage.
set -euo pipefail

cd "$(dirname "$0")"
here="$PWD"
proot="$here/.."          # prober/ -- holds the library .c files

# The same library set build.sh links, minus prober.c/fakesrv.c (they hold
# main()). Fuzz targets bring their own entry point.
LIB="json.c http.c util.c rules.c assert.c backend.c"
LIBPATHS=""
for f in $LIB; do
    LIBPATHS="$LIBPATHS $proot/$f"
done

# Match build.sh's link deps (OpenSSL for body_sha256, zlib for gunzip) so the
# whole library links even though these targets do not exercise those paths.
if command -v pkg-config >/dev/null 2>&1; then
    LDLIBS="$(pkg-config --libs openssl 2>/dev/null || echo '-lssl -lcrypto')"
    LDLIBS="$LDLIBS $(pkg-config --libs zlib 2>/dev/null || echo '-lz')"
else
    LDLIBS="-lssl -lcrypto -lz"
fi

TARGETS="json http memcached resp rules backend"

SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"

mode="${1:-replay}"

case "$mode" in
replay)
    CC="${CC:-cc}"
    rc=0
    for t in $TARGETS; do
        bin="replay_$t"
        # shellcheck disable=SC2086
        "$CC" -O1 -g -std=c11 $SAN \
            -o "$bin" "fuzz_$t.c" fuzz_standalone.c $LIBPATHS $LDLIBS
        echo "== replay $t =="
        # A target with an empty corpus dir still runs (the dir exists, readdir
        # yields nothing, driver reports 0 paths and exits clean); a seed file
        # that crashes exits nonzero and fails the whole run via set -e.
        if ! ./"$bin" "corpus/$t"; then
            echo "!! replay $t FAILED" >&2
            rc=1
        fi
    done
    exit "$rc"
    ;;
fuzz)
    secs="${2:-60}"
    if ! command -v clang >/dev/null 2>&1; then
        echo "fuzz mode needs clang (-fsanitize=fuzzer); not found" >&2
        exit 2
    fi
    for t in $TARGETS; do
        bin="fuzz_$t.bin"
        mkdir -p "crashes/$t"
        # shellcheck disable=SC2086
        clang -O1 -g -std=c11 -fsanitize=fuzzer,address,undefined \
            -fno-omit-frame-pointer \
            -o "$bin" "fuzz_$t.c" $LIBPATHS $LDLIBS
        echo "== fuzz $t (${secs}s) =="
        # -artifact_prefix routes any crasher into the per-target dir. A crash
        # returns nonzero; run every target rather than bailing on the first so
        # one clean target does not mask a dirty one -- ci collects the dirs.
        ./"$bin" -max_total_time="$secs" -artifact_prefix="crashes/$t/" \
            "corpus/$t" || true
    done
    ;;
*)
    echo "usage: $0 {replay|fuzz [seconds]}" >&2
    exit 2
    ;;
esac
