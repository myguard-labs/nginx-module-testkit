#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for this scenario's ALPN claims, which live in
# http.c (the offer, the refusal detection, the negotiated-protocol readback)
# and in prober.c (the refusal oracle's two directions) rather than in a
# compiled test binary. Those are reachable only against a real `listen ... ssl`
# server, so the scenario IS the suite -- run exactly the way a human runs it
# from ci/prober/.
#
# mutate.sh always executes suites relative to ci/prober/, which is why this
# script assumes that cwd. Everything real is in the shared helper, including
# why the port is allocated the way it is.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/alpn-negotiation nginx 1.29.0
