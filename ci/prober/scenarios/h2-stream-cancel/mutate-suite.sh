#!/usr/bin/env bash
# Live owner for the scenario-local cancellation and cleanup assertions.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=mutate-suite-lib.sh
. ./mutate-suite-lib.sh

run_mutate_suite scenarios/h2-stream-cancel nginx 1.29.0
