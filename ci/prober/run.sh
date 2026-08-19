#!/usr/bin/env bash
#
# Boot a server with the probe-enabled module, run the prober rules against it,
# tear it down. Emits TAP on stdout, so `prove` consumes it like any other test.
#
#   ci/prober/run.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what the consumer's build fetched
#
# Module-agnostic: everything specific to the consuming module arrives through
# the environment, so this script is shared verbatim rather than forked per
# repo.
#
#   PROBER_ROOT      consumer repo root            (default: two levels up)
#   PROBER_BUILD     built source tree             (default: $ROOT/.build/<flavor>-<version>)
#   PROBER_MODULE    module .so basename           (required)
#   PROBER_DIRECTIVE directive proving the harness build (required)
#   PROBER_CONF      nginx.conf template with @LOAD@/@PORT@ (default: ./conf/prober.conf)
#   PROBER_RULES     rule glob                     (default: ./rules/*.rule)
#   PROBER_PORT      listen port                   (default: 18099)
#
# This is the single-scenario form -- one conf, one rule glob, the original
# consumer contract, unchanged. Scenario trees (per-scenario conf/env/driver)
# run through run-scenario.sh and test-scenarios.sh; all three scripts share
# the same engine in lib.sh, so a fix to boot, teardown or the log scrape
# lands in every entry point at once instead of drifting apart.
#
# The build must have been made with the harness enabled, otherwise the probe
# directive does not exist and the config fails to load; the engine checks for
# that up front rather than letting it surface as a confusing connect error.
set -euo pipefail

cd "$(dirname "$0")"

# shellcheck source=lib.sh
. ./lib.sh

prober_resolve "${1:-nginx}" "${2:-1.31.3}"
prober_detect_load
prober_heap_env
prober_gates

# ONE ownership-aware trap, armed before the first resource exists. Earlier this
# script installed bare `rm -rf "$PROBER_PREFIX"` traps, which recursively delete
# a caller-supplied PROBER_PREFIX -- a documented env surface -- destroying data
# the harness does not own (AUD-01). prober_cleanup removes ONLY an mktemp prefix
# this run created, stops the server, saves/restores $?, and is idempotent, so
# the later inline prober_stop still composes. run-scenario.sh installs the same
# single trap for the same reason.
trap prober_cleanup EXIT

prober_render_conf "${PROBER_CONF:-./conf/prober.conf}"
prober_check_conf
prober_boot

STATUS=0
# The per-case no_error_log / grep_error_log directives need to know where the
# server is logging; the prober slices this file by offset around each case.
# Distinct from (and complementary to) the whole-run alert/crit/emerg scrape
# below, which stays authoritative for severities no rule thought to mention.
export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"
# Unquoted on purpose: PROBER_RULES is a glob (and may name several files), and
# quoting it would pass the literal pattern to the prober as one filename.
# -t is scaled by PROBER_TIMEOUT_SCALE (default 1) for parity with
# run-scenario.sh -- see lib.sh's PROBER_TIMEOUT_SCALE note.
# shellcheck disable=SC2086
./prober -H 127.0.0.1 -p "$PROBER_RESOLVED_PORT" \
    -t "$((5000 * PROBER_TIMEOUT_SCALE))" ${PROBER_RULES:-rules/*.rule} || STATUS=$?

prober_stop

prober_scrape_log || STATUS=1

# See run-scenario.sh's identical call: a no-op unless PROBER_VALGRIND was set.
prober_scrape_valgrind || STATUS=1

exit $STATUS
