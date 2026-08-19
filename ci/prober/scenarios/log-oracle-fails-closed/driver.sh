#!/usr/bin/env bash
#
# Scenario: THE LOG ORACLE FAILS CLOSED ON AN UNREADABLE LOG.
#
# WHAT WAS WRONG. read_log_slice() returned NULL for two situations that mean
# opposite things -- "the file did not grow" and "the file could not be read" --
# and the no_error_log consumer was `if (slice != NULL && matched)`. So an
# unreadable log did not fail the assertion; it SKIPPED it. Every no_error_log
# in the run reported ok while reading nothing. Its sibling grep_error_log,
# eight lines below, was `if (slice == NULL || !matched)` and failed closed. The
# asymmetry was the defect: one direction of the same oracle silently answered
# from a file it never opened.
#
# The same fail-open sat in prober_scrape_log (`[ -f "$log" ] || return 0`) and
# in the 25 scenario drivers that grep $ELOG for SIGSEGV -- grep on a missing
# file exits 2, so the "no worker died" branch was taken. All three read a
# missing log as a clean run.
#
# WHY A SCENARIO AND NOT A UNIT TEST. read_log_slice is static in prober.c, so
# no C suite can reach it; and after the fix prober_boot bails when the log is
# absent, which makes the repaired branch UNREACHABLE on any healthy run. A
# gate CI never executes is not proven by CI however thorough the run looks
# (the lesson from #169). This scenario is the one place that reaches it: it
# boots a normal server with a normal log, then points the prober's -e at a
# path that does not exist, which is the only way left to ask the oracle a
# question it cannot answer.
#
# TWO-SIDED BY CONSTRUCTION. Each direction is run TWICE against the same rule
# file and the same server, changing only PROBER_ERROR_LOG:
#
#   readable log   -> the case must PASS   (proves the rule is satisfiable, so
#                                            a failure on the other run is not
#                                            just a broken rule)
#   unreadable log -> the case must FAIL   (the assertion could not run, so it
#                                            may not report a verdict)
#
# Without the readable half, "it failed" would be indistinguishable from a rule
# that fails everywhere. Assertion 2 is the one that reds on the old code: it
# exited 0 there, and exits nonzero here.
#
# NON-VACUITY (mutation-proven, mutate.sh row `prober-log-slice-fail-open`):
# restoring the old fail-open -- turning the `if (!readable)` block back into a
# skip -- makes assertion 2 report ok, and the mutation is CAUGHT by this
# scenario reporting `not ok 2`. Verified reddening BY THAT ASSERTION, not by a
# boot failure or a timeout.

set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MISSING="$PROBER_PREFIX/logs/no-such-error.log"
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"

# FAILED accumulates every failing assertion; the verdict is the EXIT STATUS, so
# a `not ok` that did not also raise it would be vacuous.
FAILED=0

# TAP plan:
#  1 no_error_log passes against a readable log      (the rule is satisfiable)
#  2 no_error_log FAILS against an unreadable log    (the fix; reds on old code)
#  3 grep_error_log passes against a readable log    (parity, satisfiable)
#  4 grep_error_log FAILS against an unreadable log  (parity, already closed)
echo "1..4"

# The prober is the only thing under test here, so run it directly rather than
# through run.sh: this needs a per-invocation PROBER_ERROR_LOG, which run.sh
# sets itself.
run_prober() {
    local elog="$1" rule="$2" out rc=0

    out="$(PROBER_ERROR_LOG="$elog" "$PROBER_CLIENT" -H "$HOST" -p "$PORT" \
        -t "$((5000 * ${PROBER_TIMEOUT_SCALE:-1}))" \
        "$SCENARIO_DIR/$rule" 2>&1)" || rc=$?

    printf '%s\n' "$out"

    # A nonzero exit is this scenario's evidence for half its assertions, so it
    # must mean "the prober ran and judged the case", never "the prober never
    # started". Without this the two unreachable-log cases pass for any reason
    # at all -- caught in development, where an unbound-variable typo in this
    # very function made cases 2 and 4 report ok while the binary was never
    # executed. A TAP plan line proves it got as far as emitting one.
    # HERESTRING, NOT `printf | grep -q`. `grep -q` exits on its first match
    # and closes the pipe while `printf` may still be writing; under this
    # file's `set -euo pipefail` that SIGPIPEs printf, `!` inverts the nonzero
    # status to true, and this reports "no TAP plan" for a prober that in fact
    # emitted one -- observed on run 30708134364, `not ok 2` on a long $out
    # where printf lost the race. Same class here: ci/prober/lib.sh (s143,
    # `find | head -1`) and scenarios/deploy-canary/driver.sh.
    if ! grep -q '^1\.\.' <<<"$out"; then
        echo "# the prober emitted no TAP plan, so its exit status judges nothing" >&2
        return 125
    fi

    return "$rc"
}

# Guard the premise both unreadable-log cases rest on. If this path ever
# existed, cases 2 and 4 would be asking a question with a readable answer and
# would pass for the wrong reason.
if [ -e "$MISSING" ]; then
    echo "Bail out! $MISSING exists, so the unreadable-log cases are vacuous"
    exit 1
fi

# A readable-log case: the prober must exit 0.
must_pass() {
    local n="$1" elog="$2" rule="$3" desc="$4" out rc=0

    out="$(run_prober "$elog" "$rule")" || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "ok $n - $desc"
    else
        echo "not ok $n - $desc"
        printf '%s\n' "$out" | sed 's/^/# /'
        FAILED=1
    fi
}

# An unreadable-log case: the prober must exit nonzero, and 125 does not count
# -- that is run_prober's "never emitted a plan" status, which would otherwise
# let a prober that failed to start satisfy the very assertion this scenario
# exists to make.
must_fail() {
    local n="$1" elog="$2" rule="$3" desc="$4" out rc=0

    out="$(run_prober "$elog" "$rule")" || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "not ok $n - $desc"
        echo "# the prober exited 0 with its error log at a nonexistent path, so"
        echo "# the assertion was skipped rather than evaluated -- the fail-open"
        echo "# this scenario guards has come back"
        printf '%s\n' "$out" | sed 's/^/# /'
        FAILED=1
    elif [ "$rc" -eq 125 ]; then
        echo "not ok $n - $desc"
        echo "# the prober did not run, so its nonzero exit proves nothing here"
        printf '%s\n' "$out" | sed 's/^/# /'
        FAILED=1
    else
        echo "ok $n - $desc"
    fi
}

must_pass 1 "$ELOG" no-error-log.rule \
    "no_error_log passes against a readable log"

# THE ASSERTION THIS SCENARIO EXISTS FOR. Before the fix this exited 0.
must_fail 2 "$MISSING" no-error-log.rule \
    "no_error_log fails when the log cannot be read"

must_pass 3 "$ELOG" grep-error-log.rule \
    "grep_error_log passes against a readable log"

must_fail 4 "$MISSING" grep-error-log.rule \
    "grep_error_log fails when the log cannot be read"

exit "$FAILED"
