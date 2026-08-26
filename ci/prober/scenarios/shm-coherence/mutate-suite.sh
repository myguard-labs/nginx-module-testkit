#!/usr/bin/env bash
#
# The mutation suite for the shm-coherence scenario -- the live-worker leg of
# the cross-process shm invariant lens, and the home of the `fanout` coverage
# oracle's RUN negative control.
#
# It is the scenario run exactly the way a human runs it from ci/prober/.
#
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/shm-coherence nginx 1.29.0
