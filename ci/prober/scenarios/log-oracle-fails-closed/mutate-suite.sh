#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for this scenario's log-oracle claims, which live
# in driver.sh and in prober.c rather than in a compiled test binary.
# It is not a unit-test binary -- it is the scenario, run exactly the way a
# human runs it from ci/prober/ (see driver.sh's header).
# mutate.sh always executes suites relative to ci/prober/, which is why this
# script assumes that cwd.
#
# Everything real is in the shared helper, including why the port is allocated
# the way it is.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/log-oracle-fails-closed nginx 1.29.0
