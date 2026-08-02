#!/usr/bin/env bash
#
# The mutation suite for zone.name escaping assertions.
# It is the scenario run exactly the way a human runs it from prober/.
#
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/zone-name-escaping nginx 1.29.0
