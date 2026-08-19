#!/usr/bin/env bash
#
# Scenario: a reload is not "done" when a new worker answers, and it is not
# done when the old worker has gone either. This scenario gates on the one
# property those two oracles cannot supply -- that the worker now answering is
# running the configuration that was just loaded -- and proves the gate is
# worth having by requiring an observable config change to be live before the
# assertions are allowed to speak.
#
# THE RACE THIS CLOSES. prober_signal_wait returns when a DIFFERENT worker pid
# answers; prober_drain_wait returns when the master is back to its configured
# worker count. Both can hold while the server still serves the OLD config:
#
#   - A reload the master REJECTED. nginx tests the new configuration and, on a
#     parse or bind failure, logs the error and keeps the running cycle exactly
#     as it was. Nothing crashes, nothing exits non-zero, and the old worker
#     keeps answering -- a scenario asserting on the new config's behaviour is
#     asserting against the old one and calling it a pass.
#   - Reloads that overlap. A second SIGHUP arriving while the first is still
#     being absorbed leaves more than one new cycle in flight, and "a new pid
#     answered" cannot say which of them owns it.
#
# THE ORACLE, and why it is shaped this way. The probe reports
# config_generation, a counter the master bumps once per config LOAD and every
# worker of that cycle inherits through fork (see ngx_test_probe.h for why this
# is a process global and not angie's cycle->generation, which nginx does not
# have at all). prober_config_wait requires the new value to be read STREAK
# times CONSECUTIVELY, each on a fresh connection, so a single read that
# happened to land on the new worker while the old one is still accepting
# cannot settle it. The streak is the probabilistic half; prober_drain_wait,
# called alongside it, is the deterministic half. Neither is a substitute for
# the other and this scenario uses both.
#
# WHY THE MARKER EXISTS. A generation counter that only ever asserts about
# itself is the classic vacuous gate: it would stay green if the config it
# claims to track were never applied at all. So each reload REWRITES the
# rendered conf (a `marker=<n>` in the / response body) and the driver requires
# the served body to carry the new marker before it accepts the generation as
# meaningful. That makes "the new config is live" falsifiable from outside the
# probe entirely -- if config_generation advanced but the body still reads the
# old marker, the counter is lying and oracle 3 reds while oracle 2 stays green.
#
# NEGATIVE CONTROLS. Both were run locally against nginx 1.29.0 and the tree
# restored afterwards -- see lessons.md: this repo IS the harness, so a planted
# failure is a control proving the GATE fires, never a bug to fix.
#
#   A. The gate must fail on a REJECTED reload. Rewrite the conf to something
#      nginx refuses to parse (an unterminated block), then SIGHUP. The master
#      logs the error and keeps serving; prober_signal_wait may still see a new
#      pid from an unrelated respawn, but config_generation NEVER advances.
#      Result: oracle 2 reds with "the generation never advanced", which is the
#      whole point of the scenario. Verified: run with STREAK=20 and a broken
#      conf and the driver exits 1 rather than waiting forever.
#
#   B. The marker must be load bearing. Neutralise the sed rewrite (leave the
#      conf unchanged between reloads) while still sending the signal. The
#      generation still advances -- a reload of an IDENTICAL config is still a
#      config load -- so oracle 2 stays green, and oracle 3 reds because the
#      body never carries the marker the driver asked for. That is the vacuity
#      check working: it proves oracle 3 is not merely restating oracle 2.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"
CONF="$PROBER_PREFIX/conf/nginx.conf"

# The prober needs the error-log path to satisfy the final case's
# no_error_log directive (run-scenario.sh exports it only for the rules branch).
export PROBER_ERROR_LOG="$ELOG"

# How many reloads the series runs. Each one rewrites the config, so this is
# also the number of distinct marker values the server must serve in order.
RELOADS=5

# Consecutive agreeing reads required before a generation is called settled.
# 20 is the figure the plan specifies. It is not a timing constant -- the reads
# are back to back, not spaced -- so raising it costs connections, not seconds.
STREAK=20

# What worker_processes in this scenario's nginx.conf asks for; the drain oracle
# waits for exactly this many children. Kept beside the conf value it mirrors.
WORKERS=1

# FAILED accumulates every failing assertion. test-scenarios.sh keys the
# scenario verdict off this script's EXIT STATUS, so a `not ok` that did not
# also raise the exit status would be an assertion that can never fail.
FAILED=0

echo "1..6"

# --- helpers ---------------------------------------------------------------

# Fetch GET / and echo the response body. Used for the marker oracle only; the
# probe endpoint has its own bounded reader in lib.sh.
fetch_body() {
    (
        trap '' PIPE
        exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
        timeout 2 cat <&3
    ) 2>/dev/null
}

# Rewrite the marker in the RENDERED conf. Fails loudly when the substitution
# matches nothing: silently reloading an unchanged config would leave every
# assertion below technically green while testing nothing, which is precisely
# the vacuity this scenario is built to avoid.
set_marker() {
    local want="$1"
    sed -i -E "s/marker=[0-9]+/marker=$want/" "$CONF"
    grep -q "marker=$want" "$CONF"
}

# --- baseline -------------------------------------------------------------

GEN0="$(prober_probe_field "$(prober_probe_body "$HOST" "$PORT")" config_generation || true)"

if [ -z "$GEN0" ]; then
    # A module .so built before config_generation existed. Every oracle below
    # depends on it, so the scenario reports its own inapplicability as SKIPs
    # rather than emitting failures that describe the fixture, not the server.
    echo "ok 1 - config_generation # SKIP this module .so emits no \"config_generation\" field"
    echo "ok 2 - generation advances per reload # SKIP no \"config_generation\" field"
    echo "ok 3 - the new config is live # SKIP no \"config_generation\" field"
    echo "ok 4 - no worker died by signal # SKIP no \"config_generation\" field"
    echo "ok 5 - every reload drained # SKIP no \"config_generation\" field"
    echo "ok 6 - final worker serves cleanly # SKIP no \"config_generation\" field"
    exit 0
fi

echo "ok 1 - the probe reports config_generation (baseline $GEN0)"

# --- the reload series ----------------------------------------------------

ADVANCED=0
MARKER_OK=0
DRAINED=1
DRAIN_OBSERVABLE=1
PREV_GEN="$GEN0"
DETAIL=""

for ((r = 1; r <= RELOADS; r++)); do
    # Each reload gets its own marker value, so a stale body is distinguishable
    # from a merely old one: serving marker=3 when 4 was asked for names which
    # config the worker is on, not just that it is behind.
    MARK=$((r + 1))
    if ! set_marker "$MARK"; then
        echo "Bail out! the marker rewrite matched nothing in $CONF -- the conf's"
        echo "# \`return 200 \"marker=<n>\"\` line has changed shape; without the"
        echo "# rewrite this scenario would reload an identical config and prove nothing"
        exit 1
    fi

    kill -HUP "$MASTER" 2>/dev/null || true

    # THE GATE. Wait for a generation strictly greater than the previous one,
    # read STREAK times consecutively. A timeout here is a genuine failure: the
    # config load never happened (or was rejected), which is negative control A.
    RC=0
    GEN="$(prober_config_wait "$HOST" "$PORT" "$PREV_GEN" "$STREAK" 10000)" || RC=$?

    case "$RC" in
        0)  ADVANCED=$((ADVANCED + 1))
            PREV_GEN="$GEN"
            ;;
        2)  # Cannot happen after the baseline read succeeded, but a field that
            # vanished mid-run is a fixture fault, not a silent pass.
            DETAIL="$DETAIL
reload $r: config_generation disappeared from the probe body"
            continue
            ;;
        *)  DETAIL="$DETAIL
reload $r: generation never advanced past $PREV_GEN within 10 s (reload rejected?)"
            continue
            ;;
    esac

    # The old cycle's workers must also be gone before the marker is read: with
    # the old worker still accepting, a body fetched here could legitimately
    # come from the previous config and would red oracle 3 for a reason that is
    # not the one it exists to report.
    DRC=0
    prober_drain_wait "$MASTER" "$WORKERS" 10000 || DRC=$?
    case "$DRC" in
        0) ;;
        2) DRAIN_OBSERVABLE=0 ;;
        *) DETAIL="$DETAIL
reload $r: the previous cycle's workers had not drained after 10 s"
           DRAINED=0 ;;
    esac

    # THE VACUITY CHECK. The generation says a config was loaded; this says it
    # is the config we wrote.
    BODY="$(fetch_body || true)"
    # Herestring, not a pipe -- `grep -q` early-exit can break the writer.
    if grep -q "marker=$MARK" <<<"$BODY"; then
        MARKER_OK=$((MARKER_OK + 1))
    else
        DETAIL="$DETAIL
reload $r: generation advanced to $GEN but the body does not carry marker=$MARK"
    fi
done

# --- 2: the generation advanced on every reload ---------------------------
if [ "$ADVANCED" -eq "$RELOADS" ]; then
    echo "ok 2 - config_generation advanced and settled ($STREAK consecutive reads) on all $RELOADS reloads"
else
    echo "not ok 2 - config_generation settled on only $ADVANCED of $RELOADS reloads"
    FAILED=$((FAILED + 1))
fi

# --- 3: the newly loaded config was the one being served ------------------
if [ "$MARKER_OK" -eq "$RELOADS" ]; then
    echo "ok 3 - every settled reload served the config that had just been written"
else
    echo "not ok 3 - only $MARKER_OK of $RELOADS reloads served the newly written config"
    FAILED=$((FAILED + 1))
fi

if [ -n "$DETAIL" ]; then
    printf '%s\n' "$DETAIL" | sed '/^$/d; s/^/# /'
fi

# --- 4: no worker died by signal across the series ------------------------
# A crashed-and-respawned worker satisfies "a new pid answered" just as well as
# a reloaded one, so the signal-death path is asserted separately -- the same
# reasoning as reload-cycle and backend-reload-inflight.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 4 - a worker died by signal during the reload series"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 4 - no worker died by signal across the reload series"
fi

# --- 5: every old cycle's workers went away -------------------------------
if [ "$DRAIN_OBSERVABLE" -eq 0 ]; then
    echo "ok 5 - old-cycle worker drain # SKIP pgrep unavailable on this host"
elif [ "$DRAINED" -eq 1 ]; then
    echo "ok 5 - every reload drained back to $WORKERS worker"
else
    echo "not ok 5 - a previous cycle's worker was still running after a reload"
    FAILED=$((FAILED + 1))
fi

# --- 6: the final cycle is a working one ----------------------------------
# PIPESTATUS, not $?: a bare `./prober | sed` reports sed's status, which is
# always 0, silently discarding a red prober leg.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$STATUS" -eq 0 ]; then
    echo "ok 6 - the final reloaded worker serves cleanly"
else
    echo "not ok 6 - the final reloaded worker did not serve cleanly"
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
