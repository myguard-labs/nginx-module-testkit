#!/usr/bin/env bash
#
# TAP self-test: prober_scrape_log() treats a sanitizer/UBSan report as a fatal,
# never-exemptable finding, distinct from an ordinary alert/crit/emerg line.
#
# The scenarios job now has a SAN=1 matrix leg that boots an AddressSanitizer/
# UBSan-instrumented server. A worker use-after-free or overflow aborts with a
# sanitizer banner, which nginx writes to its redirected fd 2 (the error_log
# after config load, the launcher's server.err before it). That banner is NOT
# an nginx severity line, so the alert/crit/emerg grep cannot see it, and
# PROBER_ALLOW_LOG -- which legitimately exempts an expected [crit] slab
# exhaustion -- must NEVER be able to exempt it. This guards both claims.
set -euo pipefail

cd "$(dirname "$0")"

export TMPDIR
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/scrape_test.XXXXXX")"
SCRATCH="$TMPDIR"
cleanup() {
    [ -n "${SCRATCH:-}" ] && rm -rf "$SCRATCH"
    return 0
}
trap cleanup EXIT

PLANNED=9
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

# A fresh prefix per case so one case's planted log cannot answer another's.
mkprefix() {
    PROBER_PREFIX="$(mktemp -d "$SCRATCH/prefix.XXXXXX")"
    mkdir -p "$PROBER_PREFIX/logs"
}

# 1 -- a clean error log is not a finding.
mkprefix
: > "$PROBER_PREFIX/logs/error.log"
if prober_scrape_log >/dev/null 2>&1; then ok 0 "clean error log passes"
else ok 1 "clean error log passes"; fi

# 2 -- an AddressSanitizer banner in the error log is fatal.
mkprefix
{ echo "2026/01/01 [notice] worker started"
  echo "==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x…"
} > "$PROBER_PREFIX/logs/error.log"
if prober_scrape_log >/dev/null 2>&1; then ok 1 "ASan report in error.log is fatal"
else ok 0 "ASan report in error.log is fatal"; fi

# 3 -- a UBSan "runtime error:" line in the error log is fatal.
mkprefix
echo "src/x.c:9:5: runtime error: signed integer overflow" \
    > "$PROBER_PREFIX/logs/error.log"
if prober_scrape_log >/dev/null 2>&1; then ok 1 "UBSan runtime error is fatal"
else ok 0 "UBSan runtime error is fatal"; fi

# 4 -- a sanitizer banner in the pre-redirect server.err (no error.log) is fatal.
mkprefix
echo "==777==ERROR: LeakSanitizer: detected memory leaks" \
    > "$PROBER_PREFIX/logs/server.err"
if prober_scrape_log >/dev/null 2>&1; then ok 1 "sanitizer report in server.err is fatal"
else ok 0 "sanitizer report in server.err is fatal"; fi

# 5 -- PROBER_ALLOW_LOG cannot exempt a sanitizer report. A pattern that would
#      exempt EVERYTHING still leaves the ASan finding fatal.
mkprefix
echo "==1==ERROR: AddressSanitizer: heap-buffer-overflow" \
    > "$PROBER_PREFIX/logs/error.log"
if PROBER_ALLOW_LOG='.*' prober_scrape_log >/dev/null 2>&1; then
    ok 1 "PROBER_ALLOW_LOG cannot exempt a sanitizer report"
else
    ok 0 "PROBER_ALLOW_LOG cannot exempt a sanitizer report"
fi

# 6 -- an ordinary [crit] IS exemptable by a matching PROBER_ALLOW_LOG (proves
#      the sanitizer path did not break the existing allow-list semantics).
mkprefix
echo "2026/01/01 [crit] ngx_slab_alloc() failed: no memory" \
    > "$PROBER_PREFIX/logs/error.log"
if PROBER_ALLOW_LOG='no memory' prober_scrape_log >/dev/null 2>&1; then
    ok 0 "an expected [crit] is still exemptable"
else
    ok 1 "an expected [crit] is still exemptable"
fi

# 7 -- an unexempted [crit] is still fatal (allow-list scope unchanged).
mkprefix
echo "2026/01/01 [crit] ngx_slab_alloc() failed: no memory" \
    > "$PROBER_PREFIX/logs/error.log"
if PROBER_ALLOW_LOG='some other pattern' prober_scrape_log >/dev/null 2>&1; then
    ok 1 "an unexempted [crit] is still fatal"
else
    ok 0 "an unexempted [crit] is still fatal"
fi

# 8 -- an ABSENT error log is a broken gate, not a clean one.
#      This used to `return 0`: with no file to read, the alert/crit/emerg gate
#      reported every run clean, which is indistinguishable from a run that
#      genuinely logged nothing. It is the shell twin of the C prober's
#      no_error_log fail-open, and of the 25 drivers whose `grep -q SIGSEGV
#      "$ELOG"` takes the "no worker died" branch when grep exits 2 on a missing
#      file. prober_boot now bails before any case runs if the log is absent, so
#      reaching this state means it vanished mid-run -- still a gate that saw
#      nothing, and still not a pass.
mkprefix
if prober_scrape_log >/dev/null 2>&1; then
    ok 1 "an absent error log is not reported clean"
else
    ok 0 "an absent error log is not reported clean"
fi

# 9 -- and the sanitizer scan does not mask case 8: with BOTH logs absent the
#      verdict must still be a failure, from the absent-log branch rather than
#      from a sanitizer hit that was never found.
mkprefix
rm -f "$PROBER_PREFIX/logs/server.err"
out="$(prober_scrape_log 2>&1 || true)"
case "$out" in
    *"is absent"*) ok 0 "the absent-log branch is what reports it" ;;
    *)             ok 1 "the absent-log branch is what reports it"
                   diag "got: $out" ;;
esac

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
