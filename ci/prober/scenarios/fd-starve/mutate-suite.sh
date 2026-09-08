#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for the fd-starve mutation claim below (recovery
# oracle: withholding release_held before the recovery probe). It is not a
# unit-test binary -- it is the scenario, run exactly the way a human runs it
# from ci/prober/ (see driver.sh's header, CONTROL 2, for the equivalent
# by-hand recipe this wires into CI). mutate.sh always executes suites
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
# nonzero too. The regex names the two red-path markers driver.sh prints (see its
# header): a failing run that emits neither is reported BROKEN, not caught. Both
# are accepted by the one pattern because each row is separately anchored on the
# assertion it mutates and mutate.sh already fails a row whose suite stays green.
export MUTATE_REQUIRE_MARKER='FDSTARVE-RED-(EMFILE-WITNESS|NEUTRALITY)'

run_mutate_suite scenarios/fd-starve nginx 1.29.0
