#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for this scenario's worker-inside-neutrality
# claims, which live entirely in driver.sh -- reachable only against a real
# h2-capable `listen ...; http2 on;` server, so the scenario IS the suite
# (same shape as h2-roundtrip/mutate-suite.sh, which this is copied from).
#
# mutate.sh always executes suites relative to ci/prober/, which is why this
# script assumes that cwd. Everything real is in the shared helper.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/h2-hostile-framing nginx 1.29.0
