#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for the two stateful-property-fuzz mutation claims
# that live in driver.sh itself (PRNG determinism, plan persistence). Same shape
# and rationale as scenarios/property-fuzz/mutate-suite.sh: it is the scenario,
# run the way a human runs it from prober/, not a unit-test binary. mutate.sh
# always executes suites relative to prober/, which is why this assumes that cwd.
#
# NOTE the mutation claims wired here are the seed/plan ones ONLY -- both are
# proven by the driver's own tests 1/2/3, which run WITHOUT any lifecycle event
# needing to land (the plan is built and compared before the run). The lifecycle
# CHECKPOINT oracles (C1..C5) are proven by the documented manually-run driver
# mutations in driver.sh's header, not here, because catching them needs a real
# reload/kill to land inside mutate.sh's per-mutant budget on a booted server --
# the same reason property-fuzz's leak-oracle claim 1 is a manual control.
set -euo pipefail

cd "$(dirname "$0")/../.."

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"

PROBER_ROOT="$(pwd)/.." \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE="test_ref_probe;" \
PROBER_PORT="$PORT" \
./run-scenario.sh scenarios/stateful-property-fuzz nginx 1.29.0
