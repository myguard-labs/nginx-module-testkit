#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for the fault-matrix cycle_used-oracle
# non-vacuity claim (CONTROL B in driver.sh's header). Same shape and rationale
# as scenarios/stateful-property-fuzz/mutate-suite.sh: it is the scenario, run
# the way a human runs it from prober/, not a unit-test binary. mutate.sh always
# executes suites relative to prober/, which is why this assumes that cwd.
#
# The registered mutation corrupts BASE_USED. cycle_used is deterministic across
# every faulted get, so every healthy row then reads != baseline and reds,
# proving the exact cycle-pool oracle is live and raises the exit status. The fds
# CEILING oracle is proven by the documented-only CONTROL A (fds oscillates with
# the keepalive pool, so it is not a deterministic in-budget mutant).
set -euo pipefail

cd "$(dirname "$0")/../.."

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"

PROBER_ROOT="$(pwd)/.." \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE="test_ref_probe;" \
PROBER_PORT="$PORT" \
./run-scenario.sh scenarios/fault-matrix nginx 1.29.0
