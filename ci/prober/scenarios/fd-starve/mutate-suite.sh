#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for BOTH fd-starve control rows: CONTROL 1
# (worker_rlimit_nofile raised -- assertion 2, the EMFILE witness, must red) and
# CONTROL 2 (release_held withheld -- assertion 4, fd/connection NEUTRALITY,
# must red; NOT assertion 3, see driver.sh's header for the measurement that
# settled it). It is not a unit-test binary -- it is the scenario, run exactly
# the way a human runs it from ci/prober/. mutate.sh always executes suites
# relative to ci/prober/, which is why this script assumes that cwd.
#
# Everything real is in the shared helper, including why the port is allocated
# the way it is.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

# MUTATE_REQUIRE_MARKER (mutate-suite-lib.sh): both fd-starve rows are NEGATIVE
# CONTROLS, so "the suite exited nonzero" is not enough to credit them -- a lost
# port, a failed boot or a driver that never reached its assertions all exit
# nonzero too. driver.sh prints a marker on each red path; a failing run that
# emits none is reported BROKEN, not caught.
#
# The marker is pinned PER ROW, keyed on MUT_ROW (exported by mutate.sh). One
# alternation shared by both rows would only prove that SOME fd-starve
# assertion reddened, and this scenario has already been bitten by that gap:
# CONTROL 2 named assertion 3 until a marker-gated run showed it leaving 3
# green and reddening 4 instead. An anchor constrains what is MUTATED, not
# which assertion REDS -- so each row states the assertion it claims.
#
# A by-hand run (no MUT_ROW) accepts either marker: there is no row making a
# claim to hold it to.
case "${MUT_ROW:-}" in
    *"CONTROL 1"*)      EXPECT='FDSTARVE-RED-EMFILE-WITNESS' ;;
    *"release oracle"*) EXPECT='FDSTARVE-RED-NEUTRALITY' ;;
    "")                 EXPECT='FDSTARVE-RED-(EMFILE-WITNESS|NEUTRALITY)' ;;
    *)
        # A new row nobody taught this suite about. Failing closed keeps an
        # unrecognised row from being credited by whichever marker happens to
        # appear -- exactly the wrong-owner vacuity this gate exists to close.
        echo "Bail out! scenarios/fd-starve/mutate-suite.sh does not know which" \
             "assertion row '$MUT_ROW' claims to red; add it to the case above"
        exit 125
        ;;
esac
export MUTATE_REQUIRE_MARKER="$EXPECT"

run_mutate_suite scenarios/fd-starve nginx 1.29.0
