#!/usr/bin/env bash
#
# Run ONE scenario: boot a fresh probe-enabled server under the scenario's
# environment, run its driver or its rules, tear down, scrape the log.
#
#   prober/run-scenario.sh <scenario-dir> [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what the consumer's build fetched
#
# A scenario is a directory. Every file in it is optional except the rules --
# and even those may be omitted when a driver.sh is present, because a pure
# orchestration scenario asserts through its driver:
#
#   nginx.conf   conf template with @LOAD@/@PORT@ (default: $PROBER_CONF)
#   *.rule       rule files for the prober         (default: $PROBER_RULES)
#   env          sourced before boot: LD_PRELOAD, ulimit, PROBER_ALLOW_LOG,
#                PROBER_ALLOW_MULTIWORKER, PROBER_DAEMON_MODE, PROBER_PORT
#                overrides -- anything the scenario needs armed before the
#                master process forks. PROBER_DAEMON_MODE=on is the opt-in a
#                USR2 binary-upgrade scenario sets: it inverts the daemon gate
#                (daemon on; + a $PROBER_PREFIX/nginx.pid pidfile required) and
#                switches boot/teardown from tracking the master by $! to
#                tracking it by that pidfile -- USR2 is ignored under daemon off
#   driver.sh    replaces the plain prober invocation (Layer 3): interleaves
#                prober runs with signals to the master, asserts pidfile
#                state, and emits the scenario's TAP itself
#   requires     executable gate; nonzero exit means the scenario is SKIPPED
#                (TAP skip-all), not failed -- missing tool, missing kernel
#                feature, missing locale are environment facts, not bugs
#   backend      fakesrv script; its presence is what starts a fake upstream,
#                on an ephemeral port, before the conf is rendered so
#                @BACKEND_PORT@ can be substituted with the port it bound
#
# Driver contract (exported before driver.sh runs):
#   PROBER_CLIENT      absolute path to the prober binary
#   PROBER_LIB         absolute path to lib.sh (source it for prober_stop etc.)
#   PROBER_SCENARIO    absolute path to the scenario directory
#   PROBER_PREFIX      server prefix; logs at $PROBER_PREFIX/logs/error.log,
#                      pidfile wherever the conf template put it
#   PROBER_SERVER_BIN  server binary (for USR2 binary-upgrade scenarios)
#   PROBER_SERVER_PID  master pid ($!): HUP/USR2/TERM target
#   PROBER_RESOLVED_PORT  the listen port
#   PROBER_BACKEND_PORT   port the fake upstream bound, empty if the scenario
#                         shipped no backend file
#   PROBER_BACKEND_JOURNAL  fakesrv's JSONL journal: what the upstream actually
#                         received and sent, empty if there is no backend.
#                         The only instrument that can see a connection the
#                         module reused rather than reopened
#
# The driver's stdout IS the scenario's TAP; its exit status is the scenario's
# verdict, combined with the error-log scrape exactly as a rules run is.
set -euo pipefail

cd "$(dirname "$0")"

SCENARIO="${1:?usage: run-scenario.sh <scenario-dir> [flavor] [version]}"
SCENARIO="$(cd "$SCENARIO" && pwd)"

# shellcheck source=lib.sh
. ./lib.sh

# The requires gate runs before anything expensive and before the env file, so
# a skip costs nothing and cannot be corrupted by a half-applied environment.
# Skip-all is the whole point: an unmet requirement on this box is not a red.
#
# The gate is passed the SCENARIO DIR, FLAVOR and VERSION as $1/$2/$3 -- the
# same flavor/version this script is about to hand prober_resolve. A gate whose
# requirement is per-build (a consumer .so that exists in one staged tree and
# not another) cannot answer correctly without them: prober_resolve has not run
# yet, so PROBER_RESOLVED_BUILD does not exist at gate time, and a gate that
# guesses by globbing .build/*/objs passes on a tree that is about to fail
# `nginx -t`. Gates with environment-only requirements (a CLI, a locale, a
# kernel feature) ignore the extra argv, so this is backward compatible.
if [ -x "$SCENARIO/requires" ]; then
    if ! REASON="$("$SCENARIO/requires" "$SCENARIO" "${2:-nginx}" "${3:-1.31.3}" 2>&1)"; then
        echo "1..0 # SKIP ${REASON:-$SCENARIO/requires gate not met}"
        exit 0
    fi
fi

prober_resolve "${2:-nginx}" "${3:-1.31.3}"
prober_detect_load
prober_heap_env
prober_gates

# The env file is sourced, not executed, so ulimit and export take effect in
# THIS shell -- the one about to fork the server. That is the mechanism by
# which a scenario arms LD_PRELOAD (mockeagain), lowers `ulimit -n`
# (fd-starve), or sets PROBER_ALLOW_LOG for a fault it provokes on purpose.
# It runs after prober_resolve so it may override the resolved port, and
# before conf render so template substitution sees the final values.
if [ -f "$SCENARIO/env" ]; then
    # shellcheck source=/dev/null
    . "$SCENARIO/env"
    PROBER_RESOLVED_PORT="${PROBER_PORT:-$PROBER_RESOLVED_PORT}"
    # The env file may have set PROBER_TIMEOUT_SCALE to an unvalidated value
    # (a leading-zero octal trap, out of range) AFTER prober_resolve already
    # normalized it -- re-normalize so every scaled arithmetic expansion below
    # sees a base-10 integer the C side agrees with. See lib.sh.
    prober_normalize_timeout_scale
fi

CONF="$SCENARIO/nginx.conf"
[ -f "$CONF" ] || CONF="${PROBER_CONF:-./conf/prober.conf}"

# ONE trap, installed before the first resource exists. The ladder this
# replaces (rm-only, then stop+rm) left a window: a failure between the render
# and the install after it leaked a tmpdir, because the trap that owned it was
# not armed yet. prober_cleanup is idempotent and guards every handle, so
# arming it against nothing is free.
trap prober_cleanup EXIT

# The backend boots BEFORE the conf is rendered, not after: it binds an
# ephemeral port and the conf needs that port substituted for @BACKEND_PORT@,
# so the value does not exist until the daemon is up. It needs the prefix in
# turn -- portfile, journal and errfile all live there -- so the prefix is
# created first, and prober_render_conf below reuses it.
#
# Only when the scenario asks for one: every scenario checked in today has no
# backend file, and starting one unconditionally would boot a fake upstream
# for all of them.
if [ -f "$SCENARIO/backend" ]; then
    prober_make_prefix
    prober_backend_start "$SCENARIO/backend"
fi

prober_render_conf "$CONF"
prober_check_conf
prober_boot

STATUS=0

if [ -x "$SCENARIO/driver.sh" ]; then
    export PROBER_CLIENT="$PWD/prober"
    export PROBER_LIB="$PWD/lib.sh"
    export PROBER_SCENARIO="$SCENARIO"
    export PROBER_PREFIX PROBER_SERVER_BIN PROBER_SERVER_PID PROBER_RESOLVED_PORT

    # Exported only when the scenario shipped a backend, and empty otherwise
    # rather than unset, so a driver may test them under `set -u` without
    # having to know whether its scenario has an upstream.
    export PROBER_BACKEND_PORT="${PROBER_BACKEND_PORT:-}"
    export PROBER_BACKEND_JOURNAL="${PROBER_BACKEND_JOURNAL:-}"

    "$SCENARIO/driver.sh" || STATUS=$?
else
    # A scenario without rules and without a driver can assert nothing; that
    # is a broken scenario, not an empty test plan, and reporting it as green
    # would be the vacuous-gate failure mode this repo keeps re-learning.
    # Deliberately a literal glob string, expanded unquoted at the prober call
    # below -- identical treatment to PROBER_RULES.
    RULES="$SCENARIO/*.rule"
    if ! compgen -G "$RULES" >/dev/null; then
        RULES="${PROBER_RULES:-rules/*.rule}"
        if ! compgen -G "$RULES" >/dev/null; then
            echo "Bail out! scenario $SCENARIO has no driver.sh, no *.rule," \
                 "and no PROBER_RULES fallback -- nothing to assert"
            exit 1
        fi
    fi

    # Same export as run.sh's: the per-case no_error_log / grep_error_log
    # directives slice this file by offset around each case.
    export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

    # Unquoted on purpose: RULES is a glob (and may name several files), and
    # quoting it would pass the literal pattern to the prober as one filename.
    # -t is scaled by PROBER_TIMEOUT_SCALE (default 1, ~40 under valgrind):
    # loosening the close_within/idle read timeout is the safe direction --
    # scaling it UP only widens what a healthy-but-slow (memcheck-instrumented)
    # server is allowed to take, it cannot hide a genuine hang.
    # shellcheck disable=SC2086
    ./prober -H 127.0.0.1 -p "$PROBER_RESOLVED_PORT" \
        -t "$((5000 * PROBER_TIMEOUT_SCALE))" $RULES || STATUS=$?
fi

# The backend is scraped while it is still RUNNING. Its liveness check asks
# whether the upstream survived the scenario -- "exited before teardown" -- so
# running it after prober_backend_stop would see the pid we just reaped and
# report every backend scenario as failed. The errfile is complete by now
# regardless: fakesrv writes it as it goes, and nothing more is asked of the
# upstream once the driver or the rules have finished.
prober_backend_scrape || STATUS=1

# Then teardown, backend before server, so the module under test sees its
# upstream disappear only after it has stopped being asked for anything --
# the other order provokes connection errors during shutdown that the log
# scrape below would report as a finding.
prober_backend_stop
prober_stop

# The error-log scrape runs after prober_stop, not before: the workers must
# have exited for the log to be complete and for nothing to still be
# appending to it.
prober_scrape_log || STATUS=1

# Same ordering requirement as the error-log scrape: a valgrinded worker only
# finishes writing its --log-file once it has actually exited, which
# prober_stop above waited for. A no-op when PROBER_VALGRIND was never set
# (the normal case) -- see prober_scrape_valgrind. Runs for BOTH the
# driver.sh path and the rules path above: the server-side valgrind logs are
# what matter regardless of which one drove the requests.
prober_scrape_valgrind || STATUS=1

# The prefix is freed by the EXIT trap, not here: both scrapes above read
# files inside it, so releasing it early would delete the evidence on exactly
# the runs that have some.
exit $STATUS
