#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# coverage-director.sh -- OPT-IN generator for ci/prober/coverage-map.json, a
# reverse-impact COVERAGE DATA file: for each *_test.c unit test, which LIB
# source lines does it actually execute. This is a REACHABILITY SIGNAL that
# feeds verify-impact's selector as a SUPPLEMENT to impact.map -- there is no
# coverage-percent threshold and no merge gate on a number anywhere in this
# script or its consumer (repo stance: mutation score over coverage%, see
# CLAUDE.md "coverage-badge-vs-test-integrity").
#
# WHY PER-TEST ISOLATION. Every *_test.c links the whole LIB (build.sh:58), so
# a single instrumented build run would attribute EVERY line to EVERY test --
# true of the link, useless for selection. Each test is rebuilt and run ALONE,
# with .gcda cleared first, so gcovr's counts for that run reflect only what
# THAT test executed.
#
# An ordinary `build.sh` run is completely unchanged: this script is invoked
# on its own, never from build.sh, and does all its instrumented compiling in
# an isolated build dir that is removed on exit.
set -euo pipefail

cd "$(dirname "$0")"

# Coverage instrumentation here is gcc/gcovr-specific: gcovr reads the
# .gcno/.gcda gcc emits under --coverage. clang's --coverage needs
# llvm-cov/llvm-profdata (a different, often-absent toolchain), so this
# director does NOT follow the ambient $CC (CI sets CC=clang for one selftest
# leg -- see ci.yml). It picks a gcov-compatible compiler explicitly:
# COVERAGE_CC if set, else gcc, else the ambient CC only if it is itself gcc.
# If no gcov-compatible compiler AND gcovr are available, the map is optional
# infra, so skip cleanly (exit 0) rather than fail the build.
GCOVR="${GCOVR:-gcovr}"
if [ -n "${COVERAGE_CC:-}" ]; then
    CC="$COVERAGE_CC"
elif command -v gcc >/dev/null 2>&1; then
    CC="gcc"
else
    CC="${CC:-cc}"
fi
case "$("$CC" --version 2>/dev/null | head -1)" in
    *[Cc]lang*)
        echo "coverage-director: SKIP -- $CC is clang; need a gcov-compatible compiler (gcc). Set COVERAGE_CC or install gcc." >&2
        exit 0
        ;;
esac
if ! command -v "$CC" >/dev/null 2>&1 || ! command -v "$GCOVR" >/dev/null 2>&1; then
    echo "coverage-director: SKIP -- need gcc + gcovr (have CC=$CC GCOVR=$GCOVR)" >&2
    exit 0
fi

LIB="json.c http.c h2.c util.c rules.c assert.c backend.c"
OUT_JSON="coverage-map.json"

# CWE-59: refuse to write the map through a pre-existing symlink or other
# irregular target, mirroring verify-impact --regen-deps's own guard for
# ci/prober/*.d (verify-impact:79-85). Only ever write a regular file.
if [ -L "$OUT_JSON" ] || { [ -e "$OUT_JSON" ] && [ ! -f "$OUT_JSON" ]; }; then
    rm -f "$OUT_JSON"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/coverage-director.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# body_sha256/gunzip oracles need OpenSSL/zlib, and http.c's h2 dispatch
# needs libnghttp2, same as build.sh.
LDFLAGS="${LDFLAGS:-}"
if command -v pkg-config >/dev/null 2>&1; then
    LDFLAGS="$LDFLAGS $(pkg-config --libs openssl 2>/dev/null || echo '-lssl -lcrypto')"
    LDFLAGS="$LDFLAGS $(pkg-config --libs zlib 2>/dev/null || echo '-lz')"
    LDFLAGS="$LDFLAGS $(pkg-config --libs libnghttp2 2>/dev/null || echo '-lnghttp2')"
else
    LDFLAGS="$LDFLAGS -lssl -lcrypto -lz -lnghttp2"
fi

COV_CFLAGS="-O0 -g --coverage -std=c11"

# merged[file][line] = space-separated, deduped-on-write set of test names.
# Built up as "file<TAB>line<TAB>test" rows in one accumulator file, then
# folded into JSON at the end -- keeps the per-test loop free of any
# in-memory associative-array bookkeeping (not all /bin/sh-adjacent bashes
# agree on assoc-array semantics; a flat row file is boring and portable).
rows="$WORK/rows.tsv"
: >"$rows"

n_tests=0

for src in *_test.c; do
    [ -e "$src" ] || continue
    test_name="${src%.c}"
    n_tests=$((n_tests + 1))

    tdir="$WORK/$test_name"
    mkdir -p "$tdir"

    # Compile the LIB + this one test, instrumented, into its own directory.
    # gcc's --coverage writes .gcno at compile time and .gcda at exit next to
    # the OBJECT path -- since -o points inside $tdir, both land there and
    # never collide with any other test's run.
    # shellcheck disable=SC2086
    "$CC" $COV_CFLAGS -o "$tdir/$test_name" "$src" $LIB $LDFLAGS -I .

    # Reset accumulated counters before running: a freshly compiled .gcno has
    # no .gcda yet, but be explicit and future-proof against a stray leftover
    # from an interrupted prior run in the same tdir.
    find "$tdir" -name '*.gcda' -delete

    # Run the test binary ALONE. Its own working directory is $tdir so the
    # .gcda files it writes land there and nowhere near another test's.
    ( cd "$tdir" && "./$test_name" >/dev/null 2>&1 ) || {
        echo "coverage-director: WARNING: $test_name exited nonzero; using whatever coverage it produced" >&2
    }

    # gcovr per this one test run, restricted to the LIB source files, JSON
    # output. -r . roots relative paths at ci/prober/; --filter narrows to the
    # LIB name list so a stray system header or the test's own .c never ends
    # up as a "covered file" row.
    json_out="$tdir/cov.json"
    filt_args=()
    for lib_src in $LIB; do
        filt_args+=(--filter "$(printf '%s' "$lib_src" | sed 's/[.[\*^$]/\\&/g')")
    done
    # shellcheck disable=SC2086
    "$GCOVR" --json "$json_out" -r . --object-directory "$tdir" \
        "${filt_args[@]}" >/dev/null 2>&1 || {
        echo "coverage-director: WARNING: gcovr produced no data for $test_name" >&2
        continue
    }

    [ -s "$json_out" ] || continue

    # Fold gcovr's {"files":[{"file":F,"lines":[{"line_number":N,"count":C}]}]}
    # into "ci/prober/F<TAB>N<TAB>test_name" rows for every line with count > 0.
    jq -r --arg test "$test_name" '
        .files[]
        | .file as $f
        | .lines[]
        | select(.count > 0)
        | "ci/prober/\($f)\t\(.line_number)\t\($test)"
    ' "$json_out" >>"$rows"

    # .gcno/.gcda for this test live only under $tdir, which the outer trap
    # removes on exit -- nothing to clean per-iteration.
done

if [ "$n_tests" -eq 0 ]; then
    echo "coverage-director: no *_test.c found -- refusing to write an empty coverage-map.json" >&2
    exit 1
fi

# --- fold rows.tsv into the final deterministic JSON -----------------------
#
# Deterministic by construction: LC_ALL=C sort of the rows, then jq builds
# nested objects with naturally sorted keys (jq -S) and sorts+dedups each
# test list. Same tests + same source therefore produce byte-identical JSON.
n_files=0
n_lines=0
if [ -s "$rows" ]; then
    n_files="$(cut -f1 "$rows" | LC_ALL=C sort -u | wc -l)"
    n_lines="$(cut -f1,2 "$rows" | LC_ALL=C sort -u | wc -l)"
fi

LC_ALL=C sort "$rows" | jq -R -S '
    split("\t") as $r | {file: $r[0], line: $r[1], test: $r[2]}
' 2>/dev/null | jq -s -S '
    reduce .[] as $r ({}; .[$r.file][$r.line] += [$r.test])
    | with_entries(.value |= with_entries(.value |= (unique | sort)))
' >"$OUT_JSON"

echo "coverage-director: $n_files file(s), $n_lines line(s), $n_tests test binary(ies) -> $OUT_JSON" >&2
