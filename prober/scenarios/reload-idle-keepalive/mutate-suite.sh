#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for this scenario's drain-ordering claim, which
# lives in driver.sh itself rather than in a compiled test binary. It is the
# scenario, run exactly the way a human runs it from prober/ (see the local
# run recipe in driver.sh's header). mutate.sh always executes suites relative
# to prober/, which is why this script assumes that cwd.
#
# PORT is picked from the ephemeral range rather than left to the scenario's
# 18099 default: this box runs concurrent CI, and a hardcoded port collides.
set -euo pipefail

cd "$(dirname "$0")/../.."

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"

PROBER_ROOT="$(pwd)/.." \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE="test_ref_probe;" \
PROBER_PORT="$PORT" \
./run-scenario.sh scenarios/reload-idle-keepalive nginx 1.29.0
