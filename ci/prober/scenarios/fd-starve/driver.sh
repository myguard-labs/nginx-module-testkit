#!/usr/bin/env bash
#
# Scenario: fd-starve. Process-wide file-descriptor exhaustion (RLIMIT_NOFILE
# / EMFILE), witnessed and recovered from -- not connection-SLOT exhaustion,
# which `scenarios/open-conns` already covers and which is a different
# resource entirely (nginx docs, Connection Processing: worker_connections
# bounds per-worker connection OBJECTS, including upstream and keepalive
# slots; RLIMIT_NOFILE is the kernel's per-process descriptor table, Linux
# open(2)/accept(2): EMFILE is "the per-process limit... has been reached").
#
# WHY THIS SCENARIO USED TO PROVE NOTHING. The previous fd-starve.rule set
# only `events { worker_connections 10; }` and ran five identical sequential
# GETs, each asserting `status=200` and `delta fds == 0` -- a plain warmed-up
# worker satisfies both with worker_connections completely unconstrained (the
# default ~1024), so removing the low value could never change the evidence.
# There was no held descriptor, no RLIMIT_NOFILE manipulation, no accept
# fault and no EMFILE witness anywhere in the scenario. It measured the
# baseline, not pressure.
#
# WHY A DRIVER AND NOT `fault_accept=`. ngx_test_probe_arm() recognises
# fault_accept= as a query key (src/ngx_test_probe_arm.c), but arming it does
# nothing unless a consumer module registers a fault_set/fault_set_global
# hook for NGX_TEST_PROBE_FAULT_ACCEPT and calls it from inside nginx's own
# accept() call site -- and no such hook can be added from module code at
# all: ngx_event_accept() (src/event/ngx_event_accept.c) is nginx core, and
# this repository never patches nginx core for its own harness (README:
# "This is a probe tool for nginx. It is not an nginx module."). The
# reference module (t/module/ngx_http_test_ref_module.c) registers neither
# hook by design, and docs/attack-fault-injection.md and this file's own
# capability-inventory row (`lifecycle-fault-allocation`, README.md) already
# record that half of fault injection as unreachable in this repo's own CI
# without a consumer .so nginx core itself does not provide. A GENUINE
# process-wide EMFILE therefore has to come from the kernel refusing a real
# accept(), which means real held descriptors and a real low
# RLIMIT_NOFILE -- exactly what this driver drives directly, the same way
# `scenarios/open-conns` drives real connection-slot pressure with real
# parked sockets rather than a mocked counter.
#
# THE MECHANISM. nginx.conf pins worker_rlimit_nofile to 30 -- nginx's own
# setrlimit(RLIMIT_NOFILE, ...) call (ngx_worker_process_init) -- deliberately
# far BELOW worker_connections (1000), so the connection-slot ceiling never
# binds first (see nginx.conf's own comment for what that would silently
# degrade into). This driver opens raw, bare, unread TCP connections one at a
# time over /dev/tcp (the same held-fd shape `scenarios/open-conns` and every
# held-request driver in this tree already use, e.g.
# backend-idle-close-reload/driver.sh), until the worker's OWN accept() call
# returns EMFILE. nginx logs that exact condition at NGX_LOG_CRIT
# (ngx_event_accept.c's err == NGX_EMFILE || err == NGX_ENFILE branch):
#
#   [crit] <pid>#0: accept4() failed (24: Too many open files)
#
# (accept() on a build without NGX_HAVE_ACCEPT4 -- the driver's witness grep
# and env's log exemption both match either spelling.)
#
# which is the falsifiable witness this driver polls for -- not "the mutation
# is reachable", an OBSERVED line in the server's own error log. `env`
# exempts exactly that text from the [alert|crit|emerg] scrape (the expected-
# outcome contract every other purposely-faulted scenario in this tree
# follows -- backend-rst-midreply, worker-death, deploy-canary).
#
# On EMFILE, ngx_event_accept.c calls ngx_disable_accept_events() and either
# arms ngx_accept_disabled (accept-mutex builds) or a timer
# (accept_mutex_delay) to retry the listen socket later -- so recovery is
# nginx's OWN designed behaviour once descriptors free up, not something this
# driver has to force. Releasing the held connections and then requiring a
# plain request to succeed is therefore a genuine recovery assertion, not a
# tautology.
#
# NON-VACUITY -- the two required negative controls (see done criteria):
#   1. Raising or removing worker_rlimit_nofile (or deleting it, reverting to
#      the platform default) makes oracle 2 (the EMFILE witness) RED: the
#      held connections this driver opens no longer exceed any ceiling, so
#      the worker's accept() always succeeds and the log never carries the
#      witness line. Documented-only (not mutate.sh-wired): editing
#      nginx.conf from a suite script is the same "different shape than
#      patching the driver in place" reasoning fault-matrix's own header
#      gives for its analogous controls, and this scenario has no
#      compiled-in default to flip -- the conf IS the fixture.
#   2. Withholding the release (never closing the held fds before the final
#      probe) makes oracle 3 (recovery) RED: the worker stays pinned at
#      RLIMIT_NOFILE, the closing request cannot be accepted within the
#      driver's bounded wait, and the case reports "not ok" rather than
#      silently passing. Wired into mutate.sh (MUT_KIND=scenario): see
#      "fd-starve: recovery oracle vacuous" in mutate.sh, which neutralises
#      this exact `release_held` call and requires
#      scenarios/fd-starve/mutate-suite.sh to go red on it.
# Control 1 has no such wiring (see its own note below) and stays a by-hand
# recipe; its exact observed failing assertion is reported in the worker
# banner, per this repo's evidence rules -- not merely asserted to exist.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

# TAP plan: four assertions.
#   1 baseline request succeeds before any pressure is applied (anti-vacuity:
#     proves the server is healthy and the probe readable before the fixture
#     manipulates anything)
#   2 pressure witness -- an EXACT EMFILE accept() failure appears in the
#     server's own error log while descriptors are held
#   3 release -- with the held descriptors closed, a fresh request succeeds
#     (the recovery half of the done criterion: not merely "the process is
#     still alive" but "it serves a request again")
#   4 fd/connection neutrality -- after release plus one clean request, `fds`
#     and `connections.free` are back at (or better than) the pre-pressure
#     baseline this scenario's own first probe measured
echo "1..4"

# --- baseline -----------------------------------------------------------
BASE_BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "not ok 1 - baseline request before pressure"
    echo "# probe unreachable before any fd pressure was applied"
    FAILED=$((FAILED + 1))
}
if [ -n "${BASE_BODY:-}" ]; then
    BASE_FDS="$(prober_probe_field "$BASE_BODY" fds)" || BASE_FDS=""
    BASE_FREE="$(prober_probe_field "$BASE_BODY" free)" || BASE_FREE=""
    if [ -n "$BASE_FDS" ] && [ -n "$BASE_FREE" ]; then
        echo "ok 1 - baseline request before pressure (fds=$BASE_FDS free=$BASE_FREE)"
    else
        echo "not ok 1 - baseline probe missing fds or connections.free"
        FAILED=$((FAILED + 1))
    fi
fi

# --- hold real descriptors until the worker's own accept() hits EMFILE ---
#
# Bounded at 40 attempts against a 30-fd rlimit: the worker itself already
# holds ~3-4 descriptors of its own (listen socket, epoll/kqueue, error log --
# the same fixed handful scenarios/open-conns and conn-delta measure), so
# somewhere well before 30 successful accepts the kernel's per-process table
# for this worker is full and the NEXT accept() -- on the NEXT connection
# this loop opens -- returns EMFILE. 40 gives comfortable headroom above that
# without opening enough sockets to threaten the PROBER's own fd table
# (rules.h's MAX_BLOCKS/open_conns comment documents the same concern for the
# compiled prober; this is the shell equivalent).
declare -a HELD_FDS=()
MAX_HOLD=40
EMFILE_SEEN=0

release_held() {
    local fd
    for fd in "${HELD_FDS[@]}"; do
        exec {fd}<&- 2>/dev/null || true
    done
    HELD_FDS=()
}

# A bare TRAP guarantees release even on an unexpected early exit (a bug in
# this driver, a killed job) -- a fd-starve scenario that itself leaked the
# fds it opened would be exactly the kind of self-inflicted false positive
# this repo hunts.
trap release_held EXIT

for ((i = 0; i < MAX_HOLD; i++)); do
    # {fd} lets bash itself pick a free descriptor (>= 10, avoiding 0/1/2 and
    # any already-open one) rather than this loop guessing numbers by counting
    # -- a fixed `10 + i` scheme could silently collide with and clobber an
    # inherited descriptor the shell already holds. Held OPEN, never read from
    # and never written to -- the same bare-parked-connection shape
    # scenarios/open-conns uses, just opened one at a time from shell instead
    # of inside the compiled prober.
    if ! exec {fd}<>"/dev/tcp/$HOST/$PORT" 2>/dev/null; then
        # The CLIENT's own connect() failing here (rather than the server's
        # accept()) would mean this box's OWN fd table or backlog is the
        # constraint, not the worker's -- not the condition under test, and
        # not expected at 40 sockets on any CI runner. Treat it as a fixture
        # break rather than silently interpreting it as the witness.
        echo "# /dev/tcp connect failed while holding descriptor $i -- client-side fd pressure, not server-side"
        break
    fi
    HELD_FDS+=("$fd")

    # Poll the error log after each hold rather than opening all 40 first:
    # the witness must be observed to fire DURING the hold, not merely be
    # present afterwards for an unrelated reason. Fixed-step, no wall-clock
    # sleep loop beyond the tiny settle below -- accept() runs as soon as the
    # kernel completes the TCP handshake, so no long poll is needed.
    sleep 0.02
    if grep -qE 'accept4?\(\) failed \(24: Too many open files\)' "$ELOG" 2>/dev/null; then
        EMFILE_SEEN=1
        break
    fi
done

if [ "$EMFILE_SEEN" -eq 1 ]; then
    WITNESS="$(grep -E 'accept4?\(\) failed \(24: Too many open files\)' "$ELOG" | tail -1)"
    echo "ok 2 - accept() EMFILE witnessed under held fd pressure"
    echo "# $WITNESS"
else
    echo "not ok 2 - no accept() EMFILE line appeared in $ELOG after holding ${#HELD_FDS[@]} descriptors"
    echo "# CONTROL 1 (run by hand): raise or delete worker_rlimit_nofile in"
    echo "# nginx.conf and re-run -- this assertion must go RED exactly like this,"
    echo "# because the held connections no longer exceed any process ceiling."
    FAILED=$((FAILED + 1))
fi

# --- release: close every held descriptor --------------------------------
release_held
trap - EXIT

# --- recovery: a plain request must succeed again -------------------------
# Bounded retry, not a bare one-shot: ngx_disable_accept_events's own retry
# path (ngx_accept_disabled / accept_mutex_delay, see file header) may take
# one event-loop tick to re-arm the listen socket after descriptors free up,
# so a single immediate probe could race a healthy worker's own recovery
# window. 20 attempts * 100ms = 2s ceiling -- generous against a single
# in-worker tick, still finite (AUD-09 discipline: bounded, never an
# unbounded wait).
RECOVERED=0
RECOVER_BODY=""
for ((i = 0; i < 20; i++)); do
    if RECOVER_BODY="$(prober_probe_body "$HOST" "$PORT")"; then
        RECOVERED=1
        break
    fi
    sleep 0.1
done

if [ "$RECOVERED" -eq 1 ]; then
    echo "ok 3 - a fresh request succeeds after the held descriptors are released"
else
    echo "not ok 3 - no successful request within 2s of releasing the held descriptors"
    echo "# CONTROL 2 (wired in mutate.sh, MUT_KIND=scenario): neutralising the"
    echo "# 'release_held' call above (i.e. withholding the release) makes this"
    echo "# assertion RED exactly like this, because the worker stays pinned at"
    echo "# its rlimit and never accepts the recovery probe within the 2s bound."
    FAILED=$((FAILED + 1))
fi

# --- neutrality: fds and connections.free return to (at least) baseline ---
if [ "$RECOVERED" -eq 1 ] && [ -n "${BASE_FDS:-}" ] && [ -n "${BASE_FREE:-}" ]; then
    NOW_FDS="$(prober_probe_field "$RECOVER_BODY" fds)" || NOW_FDS=""
    NOW_FREE="$(prober_probe_field "$RECOVER_BODY" free)" || NOW_FREE=""

    if [ -n "$NOW_FDS" ] && [ -n "$NOW_FREE" ] \
       && [ "$NOW_FDS" -le "$BASE_FDS" ] && [ "$NOW_FREE" -ge "$BASE_FREE" ]; then
        echo "ok 4 - fds and connections.free are back at baseline after release (fds=$NOW_FDS free=$NOW_FREE)"
    else
        echo "not ok 4 - fds/connections.free did not return to baseline (fds=${NOW_FDS:-?} vs base $BASE_FDS, free=${NOW_FREE:-?} vs base $BASE_FREE)"
        echo "# a real leaked descriptor across the pressure window would fail exactly this way"
        FAILED=$((FAILED + 1))
    fi
else
    echo "not ok 4 - no recovered probe body to measure neutrality against"
    echo "# assertion 3 or the baseline already failed, so neutrality cannot be evaluated"
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -eq 0 ]; then
    exit 0
fi
exit 1
