#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for this scenario's h2 mechanism claims, which
# live in h2.c and in http.c's dispatch -- reachable only against a real h2-
# capable `listen ... ssl; http2 on;` server, so the scenario IS the suite
# (same shape as alpn-negotiation/mutate-suite.sh, which this is copied from
# rather than sourced from a sibling -- see that file's header for why).
#
# mutate.sh always executes suites relative to ci/prober/, which is why this
# script assumes that cwd. Everything real is in the shared helper, including
# why the port is allocated the way it is.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/h2-roundtrip nginx 1.29.0
