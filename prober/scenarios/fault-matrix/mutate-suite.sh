#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for fault-matrix's cycle_used oracle claim, which lives in
# driver.sh rather than in a compiled test binary.
# It is not a unit-test binary -- it is the scenario, run exactly the way a
# human runs it from prober/ (see driver.sh's header for the by-hand recipe).
# mutate.sh always executes suites relative to prober/, which is why this
# script assumes that cwd.
#
# Everything real is in the shared helper, including why the port is allocated
# the way it is.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/fault-matrix nginx 1.29.0
