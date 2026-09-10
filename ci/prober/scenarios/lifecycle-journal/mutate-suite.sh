#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for lifecycle-journal's mutation rows. It is not
# a unit-test binary -- it is the scenario, run exactly the way a human runs
# it from ci/prober/. mutate.sh always executes suites relative to
# ci/prober/, which is why this script assumes that cwd.
#
# Everything real is in the shared helper, including why the port is
# allocated the way it is.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

# MUTATE_REQUIRE_MARKER (mutate-suite-lib.sh): every lifecycle-journal row is
# a NEGATIVE CONTROL, so "the suite exited nonzero" alone is not enough to
# credit it -- a lost port, a failed boot or a driver that never reached its
# assertions all exit nonzero too, and this scenario's own driver already
# does three boots per run, which is three more places to bail before ever
# reaching the row's assertion. driver.sh prints one LIFECYCLE-RED-* marker
# per red assertion (see its not-ok branches); a failing run that emits none
# is reported BROKEN, not caught.
#
# Pinned PER ROW, keyed on MUT_ROW (exported by mutate.sh) -- same discipline
# fd-starve's mutate-suite.sh uses and for the same reason: an anchor
# constrains what is MUTATED, not which assertion REDS, so a shared
# alternation would only prove that SOME assertion reddened and could paper
# over a row silently drifting onto the wrong one.
case "${MUT_ROW:-}" in
    *"QUIT terminal event"*)     EXPECT='LIFECYCLE-RED-QUIT' ;;
    *"TERM terminal event"*)     EXPECT='LIFECYCLE-RED-TERM' ;;
    *"SIGKILL non-vacuity"*)     EXPECT='LIFECYCLE-RED-SIGKILL-NONVACUITY' ;;
    *"dead phase-3 reader"*)     EXPECT='LIFECYCLE-RED-SIGKILL-NONVACUITY' ;;
    *"sequence"*)                EXPECT='LIFECYCLE-RED-SEQUENCE' ;;
    *"role/gen"*)                EXPECT='LIFECYCLE-RED-ROLEGEN' ;;
    "")
        EXPECT='LIFECYCLE-RED-(QUIT|TERM|SIGKILL-NONVACUITY|SEQUENCE|ROLEGEN|GENCOUNT)' ;;
    *)
        # A new row nobody taught this suite about. Failing closed keeps an
        # unrecognised row from being credited by whichever marker happens to
        # appear -- exactly the wrong-owner vacuity this gate exists to close.
        echo "Bail out! scenarios/lifecycle-journal/mutate-suite.sh does not" \
             "know which assertion row '$MUT_ROW' claims to red; add it to" \
             "the case above"
        exit 125
        ;;
esac
export MUTATE_REQUIRE_MARKER="$EXPECT"

run_mutate_suite scenarios/lifecycle-journal nginx 1.29.0
