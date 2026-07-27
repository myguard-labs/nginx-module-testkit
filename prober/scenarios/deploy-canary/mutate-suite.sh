#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for every deploy-canary (P2-H) non-vacuity claim.
# Same shape and rationale as fault-matrix's mutate-suite.sh: it is the
# scenario, run the way a human runs it from prober/, not a unit-test binary.
# mutate.sh always execs suites relative to prober/, which is why this assumes
# that cwd.
#
# Each of mutate.sh's five deploy-canary rows (O1 status, O2 headers, O3 body,
# O5 death, O7 growth) patches driver.sh: O1/O2/O3 set its CANARY_ARM_SED, so
# the driver seds the RENDERED conf between the control capture and the
# candidate reboot (a real behavioural difference on the candidate's second
# boot; the checked-in nginx.conf is never patched -- that would arm both legs
# identically) OR driver.sh's own oracle constant (O5/O7 -- corrupting the
# expectation/bound, same "cannot mutate nginx's own crash or pool-bookkeeping
# machinery in-budget" boundary fault-matrix's header documents), then runs
# THIS script once. O4/O6/O8 are documented-only manual neg-controls (see
# driver.sh's header) -- not wired here, same tier as rss-slope's and
# fault-matrix's own by-hand controls.
set -euo pipefail

cd "$(dirname "$0")/../.."

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"

PROBER_ROOT="$(pwd)/.." \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE="test_ref_probe;" \
PROBER_PORT="$PORT" \
./run-scenario.sh scenarios/deploy-canary nginx 1.29.0
