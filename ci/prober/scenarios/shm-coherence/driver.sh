#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario: shm-coherence -- the one LIVE-WORKER leg of the cross-process
# shared-memory invariant lens (`fanout`, `quiesce`, `zone_invariant`).
#
# Everything this lens does is unit-tested in assert_test.c as pure functions
# over synthetic readings: no master, no fork(), no accept path, no mapped
# zone. This scenario is where the directives meet four real nginx workers.
#
# There is a driver here rather than a bare rules run for ONE reason: the
# scenario ships its own RUN negative control. The coverage oracle is the
# load-bearing assertion of the entire lens -- it is what stops a fanout
# passing having sampled one worker N times -- and an oracle nobody has watched
# fail is an oracle nobody should trust. A bare rules run can assert that the
# honest cases are green; only a driver can assert that a deliberately broken
# fixture comes back RED, on this box, in this run, against this server.
#
# Two legs, in this order:
#
#   1. The honest cases (shm-coherence.rule) must be GREEN. Read
#      shm-coherence.rule for what they assert, what they deliberately do not
#      assert (the three zone_invariant forms, and why asserting them against
#      the reference module would be vacuous), and why `fanout 24` is the width.
#
#   2. The negative control (negative-control.rule.fixture) must be RED, and
#      red for the RIGHT REASON: the exit status alone is not enough, because a
#      rule file that failed to parse, a server that stopped answering, or a
#      typo'd field name would all exit nonzero too and would "prove" the
#      oracle fires when it never ran. So the output is matched against the
#      coverage message itself. A nonzero exit with no coverage line in it
#      FAILS this leg.
#
# A quiet PASS on leg 2 is the failure mode this file exists to make
# impossible: if the fixture ever comes back green, the coverage comparison
# stopped comparing and every `fanout` in the tree silently became a test that
# cannot fail.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

PORT="$PROBER_RESOLVED_PORT"

# Same invocation run-scenario.sh builds for a rules scenario, including the
# PROBER_TIMEOUT_SCALE factor -- a driver that hardcoded 5000 would time out
# under valgrind while the rules path beside it did not, and the difference
# would be blamed on the scenario.
#
# The `:-1` default is load-bearing under `set -u`. run-scenario.sh does NOT
# export PROBER_TIMEOUT_SCALE to a driver (it validates it for its own rules
# path and for lib.sh's waiters), so a bare `$((5000 * PROBER_TIMEOUT_SCALE))`
# is an unbound-variable arithmetic error. Its cost is worse than a normal
# failure: the error aborts the SHELL from inside the function, so the
# `|| HONEST_RC=$?` at the call site never runs, the driver dies having printed
# only its plan line, and the scenario reports as a truncated TAP stream rather
# than as anything a reader can diagnose. Observed exactly that while writing
# this file.
TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"

run_rules() {
    "$PROBER_CLIENT" -H 127.0.0.1 -p "$PORT" \
        -t "$((5000 * TIMEOUT_SCALE))" "$1"
}

# Same slicing the rules path exports, so a case's no_error_log /
# grep_error_log directive works identically under this driver.
export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

echo "1..2"

# --- 1: the honest cases are green ----------------------------------------
#
# Run first. If the live fanout cannot spread across workers on this box at
# all, that is the finding, and reporting it before the negative control keeps
# a genuine coverage failure from being read as a broken control.

HONEST_OUT="$PROBER_PREFIX/honest.out"
HONEST_RC=0

# Not `set -e`-fatal: a red here must be REPORTED as a red, with its output,
# not abort the driver and lose the plan line and leg 2 entirely.
run_rules "$PROBER_SCENARIO/shm-coherence.rule" >"$HONEST_OUT" 2>&1 \
    || HONEST_RC=$?

if [ "$HONEST_RC" -eq 0 ]; then
    echo "ok 1 - the live four-worker cases are green"
    # The distinct-worker spread the cases achieved is the number a reader
    # wants when this scenario later flakes, so surface the prober's own TAP
    # rather than swallowing it on success.
    sed 's/^/# /' "$HONEST_OUT"
else
    echo "not ok 1 - the live four-worker cases are green"
    echo "# prober exited $HONEST_RC; its output follows"
    sed 's/^/# /' "$HONEST_OUT"
fi

# --- 2: the negative control is observed RED ------------------------------
#
# The fixture demands 8 distinct workers from a 4-worker server: unreachable by
# construction, so this leg is deterministic rather than probabilistic. See the
# fixture's header for why the probabilistic alternative was rejected.

NEG_OUT="$PROBER_PREFIX/negctl.out"
NEG_RC=0

run_rules "$PROBER_SCENARIO/negative-control.rule.fixture" >"$NEG_OUT" 2>&1 \
    || NEG_RC=$?

# The message the oracle prints on a coverage shortfall. Matched on the stable
# middle of the sentence -- not on the counts, which vary run to run, and not
# on trailing punctuation, which an edit to the wording would break without
# changing the behaviour under test.
NEG_PATTERN='fanout coverage: .* distinct worker.* need >='

if [ "$NEG_RC" -eq 0 ]; then
    # The whole reason this leg exists.
    echo "not ok 2 - the negative control is observed RED"
    echo "# THE COVERAGE ORACLE DID NOT FIRE. A fanout demanding 8 distinct"
    echo "# workers from a 4-worker server PASSED, which means the comparison"
    echo "# in eval_fanout_coverage stopped comparing. Every fanout in the"
    echo "# tree is now a test that cannot fail."
    sed 's/^/# /' "$NEG_OUT"
    FAILED=1

elif grep -qE "$NEG_PATTERN" "$NEG_OUT"; then
    echo "ok 2 - the negative control is observed RED, with the coverage message"
    # Quote the actual red. A control whose failure text nobody printed is a
    # claim, not evidence, and the next reader of this scenario should not have
    # to re-run it to see what firing looks like.
    grep -E "$NEG_PATTERN|^not ok" "$NEG_OUT" | sed 's/^/# /'

else
    # Nonzero, but not from the oracle: a parse error, a dead server, a renamed
    # field. Treated as a FAILED control, because it proves nothing about the
    # comparison this leg is here to exercise.
    echo "not ok 2 - the negative control is observed RED"
    echo "# the fixture exited $NEG_RC but printed no coverage message, so the"
    echo "# coverage oracle is not what failed it -- this control ran, and"
    echo "# proved nothing. Output follows."
    sed 's/^/# /' "$NEG_OUT"
    FAILED=1
fi

# The driver's exit status is the scenario's verdict.
if [ "$HONEST_RC" -ne 0 ] || [ "${FAILED:-0}" -ne 0 ]; then
    exit 1
fi

exit 0
