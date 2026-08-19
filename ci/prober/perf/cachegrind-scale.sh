#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Deterministic algorithmic-cost gate for the response-body JSON parser.
#
# It asserts a SHAPE, not a speed: parsing an 8x larger document must cost about
# 8x the instructions, never ~64x. Cachegrind counts instructions exactly and
# reproducibly (same binary + same input => identical Ir, no wall-clock flake),
# so an instruction-count RATIO is a stable, machine-independent proxy for
# asymptotic complexity -- which a wall-clock `expect time<ms` never was (it is
# load- and host-dependent, and was rejected for exactly that reason).
#
# For each size the harness is run twice, `gen` (build the input only) and
# `parse` (build + json_parse_n + json_free). Ir(parse) - Ir(gen) is the
# parser's own instruction count: process startup, libc init and the O(N) input
# generation appear in both and cancel, leaving json_parse_n. The gate takes
# that marginal at N and 8N and checks the ratio sits in a linear band. A
# regression that turns any per-element scan quadratic (a duplicate check, a
# tail-walking append, a naive insert) drives the ratio toward 64 and reds.
#
# TAP, two tests:
#   1  the parser did measurable work at both sizes (guards a broken/zero
#      measurement passing test 2 vacuously)
#   2  the 8x-input instruction ratio is inside the linear band
#
# Standalone by necessity: Cachegrind must launch the process it measures, so
# unlike the strace-based syscall-allowlist scenario it cannot attach to a live
# nginx worker. It therefore drives json_parse_n directly, the same engine-
# neutral entry the fuzz targets use, rather than booting a server.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$PWD"
PROOT="$HERE/.."

# --- tuning --------------------------------------------------------------
# N and 8N are large enough that the parser marginal dwarfs measurement grain
# yet small enough to stay a few seconds under Cachegrind's ~20-50x slowdown.
# The band brackets the linear ratio (~8, measured 8.09-8.18 across the object
# and number workloads) with slack for toolchain drift, and sits far below the
# quadratic ratio (~64) it must catch. Cachegrind is deterministic, so the
# linear value does not vary run to run; only the compiler can move it, and not
# by the factor the band leaves.
N=2000
FACTOR=8
BIG=$((N * FACTOR))
RATIO_LO=6.0
RATIO_HI=16.0

# --- precondition: valgrind present --------------------------------------
# Harness-native skip (a lone `1..0 # SKIP` plan, which the aggregator renders
# as an explicit skip) rather than a synthetic pass, so a box without valgrind
# reports SKIPPED, not two vacuous oks.
if ! command -v valgrind >/dev/null 2>&1; then
    echo "1..0 # SKIP valgrind not installed (cachegrind scaling gate needs it)"
    exit 0
fi

# --- build ---------------------------------------------------------------
# The same library set build.sh links, minus the files carrying main(); the
# harness brings its own. OpenSSL (body_sha256) and zlib (gunzip) are link deps
# of the library even though this workload exercises neither.
LIB="json.c http.c util.c rules.c assert.c backend.c"
LIBPATHS=""
for f in $LIB; do
    LIBPATHS="$LIBPATHS $PROOT/$f"
done
if command -v pkg-config >/dev/null 2>&1; then
    LDLIBS="$(pkg-config --libs openssl 2>/dev/null || echo '-lssl -lcrypto')"
    LDLIBS="$LDLIBS $(pkg-config --libs zlib 2>/dev/null || echo '-lz')"
else
    LDLIBS="-lssl -lcrypto -lz"
fi
CC="${CC:-cc}"
BIN="$HERE/cg_scale.bin"

# -O1 (not -O2): enough to be representative without so much inlining that the
# per-element cost the ratio depends on becomes unstable across compilers. No
# sanitizers -- ASan/UBSan add their own per-op instrumentation whose cost can
# itself scale non-linearly and would pollute the shape under test.
# shellcheck disable=SC2086
"$CC" -O1 -g -std=c11 -o "$BIN" "$HERE/cg_scale.c" $LIBPATHS $LDLIBS

# --- measure -------------------------------------------------------------
# Cachegrind's summary Ir goes to stderr as "I refs: N,NNN,NNN"; the profile
# file is discarded. Deterministic, so one run per (size,mode) is exact.
ir() {
    valgrind --tool=cachegrind --cachegrind-out-file=/dev/null "$BIN" "$1" "$2" 2>&1 \
        | sed -n 's/.*I refs:[^0-9]*//p' | tr -d ','
}

echo "1..2"

g_n=$(ir "$N" gen);    p_n=$(ir "$N" parse)
g_b=$(ir "$BIG" gen);  p_b=$(ir "$BIG" parse)

# Parser-only marginal at each size (cancels startup + input generation).
m_n=$((p_n - g_n))
m_b=$((p_b - g_b))

if [ "$m_n" -gt 0 ] && [ "$m_b" -gt 0 ]; then
    echo "ok 1 - parser did measurable work at both sizes (N=$m_n 8N=$m_b Ir)"
else
    echo "not ok 1 - parser marginal non-positive (N=$m_n 8N=$m_b) -- measurement broke"
    echo "# raw: gen(N)=$g_n parse(N)=$p_n gen(8N)=$g_b parse(8N)=$p_b"
    echo "not ok 2 - no usable marginal to check scaling against"
    exit 1
fi

# ratio = m_b / m_n. Its exit status is the scenario verdict.
awk -v mn="$m_n" -v mb="$m_b" -v f="$FACTOR" -v lo="$RATIO_LO" -v hi="$RATIO_HI" '
BEGIN {
    r = mb / mn;
    printf("# 8x-input instruction ratio = %.3f (linear ~= %d, quadratic ~= %d; band [%.1f, %.1f])\n",
           r, f, f * f, lo, hi);
    if (r >= lo && r <= hi) {
        printf("ok 2 - parser scales linearly (ratio %.3f in [%.1f, %.1f])\n", r, lo, hi);
        exit 0;
    }
    printf("not ok 2 - parser scaling outside linear band (ratio %.3f, expected [%.1f, %.1f])\n",
           r, lo, hi);
    printf("#   a ratio near %d is the fingerprint of an O(n^2) regression in json_parse_n\n", f * f);
    exit 1;
}'
