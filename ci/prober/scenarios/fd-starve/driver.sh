#!/usr/bin/env bash
#
# Scenario: fd-starve. Process-wide file-descriptor exhaustion (RLIMIT_NOFILE
# / EMFILE), witnessed and recovered from -- not connection-SLOT exhaustion,
# which `scenarios/open-conns` already covers and which is a different
# resource entirely. See nginx.conf for the worker_connections vs
# RLIMIT_NOFILE distinction; it is stated there once, not repeated here.
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
# (accept4 vs accept: see env's own comment; the witness grep matches either.)
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
#   1. Raising or removing worker_rlimit_nofile makes assertion 2 (the EMFILE
#      witness) RED: the held connections this driver opens no longer exceed
#      any process ceiling, so the worker's accept() always succeeds and the
#      log never carries the witness line. WIRED (mutate.sh, MUT_KIND=scenario):
#      FDSTARVE_ARM_SED below, applied to the RENDERED conf strictly after
#      run-scenario.sh's own boot, exactly like deploy-canary's
#      CANARY_ARM_SED applied to its candidate leg -- this driver stops that
#      first boot, arms the sed, and reboots on the same rendered conf before
#      running any assertion. See "fd-starve: CONTROL 1" in mutate.sh.
#   2. Withholding the release (never closing the held fds before the final
#      probe) makes assertion 3 (recovery) RED: the worker stays pinned at
#      RLIMIT_NOFILE, the closing request cannot be accepted within the
#      driver's bounded wait, and the case reports "not ok" rather than
#      silently passing. WIRED (mutate.sh, MUT_KIND=scenario): see
#      "fd-starve: recovery oracle vacuous" in mutate.sh, which neutralises
#      this exact `release_held` call and requires
#      scenarios/fd-starve/mutate-suite.sh to go red on it.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

FAILED=0
REBOOTED=0

# HELD_FDS, release_held and on_exit are declared and armed BEFORE the
# CONTROL 1 reboot below, not after: prober_boot can start the second server
# and then fail its own listener wait (set -e kills this driver before
# REBOOTED would otherwise be set), or anything else in between can exit, and
# in either case a trap installed later never runs at all -- exactly the
# orphaned-second-server outcome the reboot exists not to cause. REBOOTED
# itself is still set immediately before prober_boot (not after it returns),
# so the trap treats "we started a second boot" as true the instant that boot
# is attempted, whether or not it succeeds.
declare -a HELD_FDS=()

release_held() {
    local fd
    for fd in "${HELD_FDS[@]}"; do
        exec {fd}<&- 2>/dev/null || true
    done
    HELD_FDS=()
}

# Combines both cleanup duties one EXIT trap must do, since a second `trap …
# EXIT` overwrites rather than adds to the first: release any fds still held
# (a fd-starve scenario that itself leaked the fds it opened would be exactly
# the kind of self-inflicted false positive this repo hunts), AND, when
# CONTROL 1 rebooted this driver's OWN second server (REBOOTED=1), stop it.
# That reboot's pid is local to THIS child process (run-scenario.sh runs
# driver.sh as a plain child, never sources it -- see
# deploy-canary/driver.sh's identical note on PROBER_SERVER_PID
# reassignment), so the PARENT's own cleanup still remembers the FIRST boot's
# (already-dead) pid and cannot reach this one; left alone, the second boot
# orphans and holds the port for the rest of the CI job, the exact failure
# deploy-canary/driver.sh's header documents diagnosing in reload-soak.
# shellcheck disable=SC2317  # called only via `trap on_exit EXIT` below
on_exit() {
    release_held
    if [ "$REBOOTED" -eq 1 ]; then
        prober_stop || true
    fi
}
trap on_exit EXIT

# --- CONTROL 1 anchor: reboot on the RENDERED conf, optionally armed -------
#
# run-scenario.sh already booted once against $PROBER_PREFIX/conf/nginx.conf
# before this driver ever runs. FDSTARVE_ARM_SED, empty by default, is the
# mutate.sh anchor for CONTROL 1 (raising/deleting worker_rlimit_nofile) --
# same shape as deploy-canary's CANARY_ARM_SED (see that driver's own
# comment): sed against the ON-DISK RENDERED conf, never the checked-in
# source, applied here and then rebooted on, so an unpatched tree's reboot is
# byte-identical to the first boot (the NULL case) and a mutate.sh row can
# arm a real, isolated fault without editing the checked-in fixture.
#
# PROBER_TIMEOUT_SCALE is a plain (unexported) shell variable in
# run-scenario.sh's own process -- it never reaches this driver, which runs
# as a separate child (run-scenario.sh's own comment on PROBER_SERVER_PID
# reassignment says the same about pid tracking). Normalized HERE,
# unconditionally, not only inside the CONTROL 1 branch below: SETTLE and
# RETRY_SLEEP further down are computed on EVERY run, armed or not, and their
# `${PROBER_TIMEOUT_SCALE:-1}` fallback would otherwise silently pin every
# ordinary (unarmed) CI run to scale 1 even under
# PROBER_TIMEOUT_SCALE=40 -- no `set -u` crash to catch it, since the `:-1`
# default swallows the unset variable without complaint.
prober_normalize_timeout_scale

# shellcheck disable=SC2016
FDSTARVE_ARM_SED="${FDSTARVE_ARM_SED:-}"
if [ -n "$FDSTARVE_ARM_SED" ]; then
    prober_stop
    # sed exits 0 on ZERO substitutions -- its status proves nothing about
    # whether the arm actually took. An FDSTARVE_ARM_SED that matches
    # nothing (a reformatted nginx.conf, a changed rlimit value) would reboot
    # on a byte-identical, NULL-case conf and mutate.sh would report
    # SURVIVED for a mutation that was never applied. Compare the bytes
    # instead of trusting the exit status. The backup lives OUTSIDE
    # $PROBER_PREFIX/conf/ (a plain mktemp file, not a sibling of nginx.conf)
    # so a future fixture that globs that directory (an `include conf/*.conf`)
    # can never parse this leftover copy.
    PREARM="$(mktemp)"
    cp "$PROBER_PREFIX/conf/nginx.conf" "$PREARM"
    sed -i "$FDSTARVE_ARM_SED" "$PROBER_PREFIX/conf/nginx.conf"
    if cmp -s "$PREARM" "$PROBER_PREFIX/conf/nginx.conf"; then
        echo "Bail out! FDSTARVE_ARM_SED ('$FDSTARVE_ARM_SED') changed nothing in the rendered conf -- the mutation was NOT applied and any verdict below would be meaningless"
        rm -f "$PREARM"
        # 125, not 1: mutate.sh reads any plain nonzero, non-124 exit as
        # `caught` (a red assertion), so a failed arm exiting 1 would report
        # this control row as green for a mutation that was never applied --
        # the exact vacuous-gate failure this driver exists to prevent, one
        # layer up. 125 is a distinct status mutate.sh maps to BROKEN. Every
        # other "the fixture itself could not be armed or exercised" bail in
        # this driver (below, and the two reboot-side checks that follow)
        # uses the same status for the same reason -- a fixture failure is
        # not a red assertion, and mixing the two exit codes lets a broken
        # fixture masquerade as proof.
        exit 125
    fi
    rm -f "$PREARM"
    if ! prober_check_conf; then
        echo "Bail out! the armed conf does not pass nginx -t -- the fixture could not be armed, so no verdict below is meaningful"
        exit 125
    fi
    # Armed BEFORE the boot: prober_boot can start the server and still fail
    # its own listener wait, and on_exit must stop it in that case too.
    REBOOTED=1
    if ! prober_boot; then
        echo "Bail out! the armed reboot did not come up -- fixture failure, not a red assertion"
        exit 125
    fi
fi

# TAP plan: four assertions.
#   1 baseline request succeeds before any pressure is applied (anti-vacuity:
#     proves the server is healthy and the probe readable before the fixture
#     manipulates anything)
#   2 pressure witness -- an EXACT EMFILE accept() failure, from THIS boot's
#     worker pid, appears in the server's own error log while descriptors
#     are held, and was ABSENT before the hold began
#   3 release -- with the held descriptors closed, a fresh request succeeds
#     (the recovery half of the done criterion: not merely "the process is
#     still alive" but "it serves a request again")
#   4 fd/connection neutrality -- fds/free are observed CLIMBING toward the
#     rlimit during the hold, then return to EXACTLY the pre-pressure
#     baseline after release plus one clean request
echo "1..4"

# --- baseline -----------------------------------------------------------
BASE_BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "not ok 1 - baseline request before pressure"
    echo "# probe unreachable before any fd pressure was applied"
    echo "Bail out! baseline probe unreadable -- refusing to apply fd pressure to a server already declared unhealthy"
    # 125: a fixture failure (the probe endpoint itself is unreadable), not a
    # red assertion -- see the CONTROL 1 arm's own exit-code comment above.
    exit 125
}
BASE_FDS="$(prober_probe_field "$BASE_BODY" fds)" || BASE_FDS=""
BASE_FREE="$(prober_probe_field "$BASE_BODY" free)" || BASE_FREE=""
if [ -n "$BASE_FDS" ] && [ -n "$BASE_FREE" ]; then
    echo "ok 1 - baseline request before pressure (fds=$BASE_FDS free=$BASE_FREE)"
else
    echo "not ok 1 - baseline probe missing fds or connections.free"
    echo "Bail out! baseline probe returned no fds/free field -- cannot evaluate later assertions against an unknown baseline"
    # 125: fixture failure, same reasoning as the unreadable-probe bail above.
    exit 125
fi

BASE_PID="$(prober_probe_field "$BASE_BODY" pid)" || BASE_PID=""
if [ -z "$BASE_PID" ]; then
    echo "Bail out! baseline probe returned no pid field -- assertion 2 could not attribute an EMFILE witness to THIS boot's worker"
    # 125: fixture failure, same reasoning as the fds/free bail above -- a
    # missing pid silently disables the pid gate rather than failing loudly,
    # which is exactly the "witness text alone" vacuity this driver added the
    # gate to close.
    exit 125
fi

# Before applying any pressure, the witness text must be ABSENT -- a real
# negative control (finding 4a): without it, a stale EMFILE line surviving
# from a prior boot in the same $ELOG would pass assertion 2 after this
# driver held even a single descriptor.
if grep -qE 'accept4?\(\) failed \(24: Too many open files\)' "$ELOG" 2>/dev/null; then
    echo "Bail out! EMFILE witness text already present in $ELOG before any pressure was applied -- stale log or reused prefix"
    # 125: fixture failure (a stale/reused log), same reasoning as above.
    exit 125
fi

# --- hold real descriptors until the worker's own accept() hits EMFILE ---
#
# Bounded well above a 30-fd rlimit: the worker itself already holds ~3-4
# descriptors of its own (listen socket, epoll/kqueue, error log -- the same
# fixed handful scenarios/open-conns and conn-delta measure), so somewhere
# before the rlimit is reached the kernel's per-process table for this worker
# is full and the NEXT accept() -- on the NEXT connection this loop opens --
# returns EMFILE. MAX_HOLD is bounded by `rlimit - worker's own fds`, not by
# "one accept at a time": nginx.conf sets `multi_accept on`, so a worker
# drains its whole listen backlog per event-loop wakeup rather than accepting
# one connection per wakeup, and the bound has to survive that. The slack
# above the rlimit (worker_rlimit_nofile 30, MAX_HOLD 40) is what actually
# guarantees EMFILE fires somewhere in the loop regardless of how many
# descriptors a single wakeup drains, without opening enough sockets to
# threaten the PROBER's own fd table (rules.h's MAX_BLOCKS/open_conns comment
# documents the same concern for the compiled prober; this is the shell
# equivalent).
MAX_HOLD=40
EMFILE_SEEN=0
SETTLE="$(awk -v s="${PROBER_TIMEOUT_SCALE:-1}" 'BEGIN { printf "%.3f", 0.02 * s }')"

PEAK_FDS="$BASE_FDS"
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
    # present afterwards for an unrelated reason. Fixed-step, scaled by
    # PROBER_TIMEOUT_SCALE like every other timing budget in this tree (a
    # valgrind-instrumented worker takes far longer than 0.02s per wakeup to
    # reach its own accept() call) -- accept() runs as soon as the kernel
    # completes the TCP handshake, so no long poll is needed even scaled up.
    sleep "$SETTLE"

    # Sample fds DURING the hold so the scenario actually observes the
    # worker's descriptor count climbing toward the rlimit, not merely an
    # at-rest reading before and after. A probe during active pressure is
    # best-effort (the worker may be too starved to answer once EMFILE is
    # imminent), so a failed probe here is not itself a finding.
    if MID_BODY="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null)"; then
        MID_FDS="$(prober_probe_field "$MID_BODY" fds 2>/dev/null)" || MID_FDS=""
        if [ -n "$MID_FDS" ] && [ "$MID_FDS" -gt "$PEAK_FDS" ] 2>/dev/null; then
            PEAK_FDS="$MID_FDS"
        fi
    fi

    if grep -qE 'accept4?\(\) failed \(24: Too many open files\)' "$ELOG" 2>/dev/null; then
        EMFILE_SEEN=1
        break
    fi
done

# The witness alone decides this assertion. PEAK_FDS comes from the
# best-effort in-pressure probe inside the hold loop above, which is LEAST
# likely to answer at the
# exact moment EMFILE fires (the worker is, by definition, refusing accept()
# right then) -- so a missing sample is reported, never treated as a reason
# to fail an assertion the log itself already proves.
if [ "$EMFILE_SEEN" -eq 1 ]; then
    WITNESS="$(grep -E 'accept4?\(\) failed \(24: Too many open files\)' "$ELOG" | tail -1)"
    # Extract the worker pid from the witness line and require it match THIS
    # boot's own worker, read fresh from the baseline probe -- otherwise a
    # stale line from a prior boot in the same (reused, or CONTROL-1-rebooted)
    # $ELOG would satisfy this assertion without this run ever having
    # produced EMFILE itself. nginx's own prefix is "<pid>#<tid>: ", but the
    # line STARTS with a timestamp ("2026/09/08 12:00:00 [crit] 1234#0: ..."),
    # so the pid cannot be anchored at ^ -- it is the run of digits
    # immediately before the "#<tid>:" pair.
    WITNESS_PID="$(printf '%s\n' "$WITNESS" \
        | sed -nE 's/.*[^0-9]([0-9]+)#[0-9]+:.*/\1/p')"
    if [ -z "$WITNESS_PID" ]; then
        # BASE_PID is already guaranteed non-empty (bailed out at 125 above
        # if not) -- an empty WITNESS_PID here means the extractor's own
        # regex stopped matching (e.g. an nginx log-prefix change), and
        # silently falling through to the witness-text-only check would
        # reopen exactly the vacuity this pid gate exists to close.
        echo "not ok 2 - could not extract a worker pid from the EMFILE witness line; the pid gate did not run"
        echo "# $WITNESS"
        FAILED=$((FAILED + 1))
    elif [ "$WITNESS_PID" != "$BASE_PID" ]; then
        echo "not ok 2 - EMFILE witness pid $WITNESS_PID does not match this boot's worker pid $BASE_PID"
        FAILED=$((FAILED + 1))
    elif [ "$PEAK_FDS" -gt "$BASE_FDS" ] 2>/dev/null; then
        echo "ok 2 - accept() EMFILE witnessed under held fd pressure (fds climbed $BASE_FDS -> $PEAK_FDS)"
        echo "# $WITNESS"
    else
        echo "ok 2 - accept() EMFILE witnessed under held fd pressure (in-pressure fds sample unavailable, base $BASE_FDS)"
        echo "# $WITNESS"
    fi
else
    if [ "$PEAK_FDS" -gt "$BASE_FDS" ] 2>/dev/null; then
        echo "not ok 2 - no accept() EMFILE line appeared in $ELOG after holding ${#HELD_FDS[@]} descriptors (fds climbed $BASE_FDS -> $PEAK_FDS)"
    else
        echo "not ok 2 - no accept() EMFILE line appeared in $ELOG after holding ${#HELD_FDS[@]} descriptors (in-pressure fds sample unavailable, base $BASE_FDS)"
    fi
    echo "# CONTROL 1 (mutate.sh, FDSTARVE_ARM_SED): raising or deleting"
    echo "# worker_rlimit_nofile in the rendered conf must make this assertion"
    echo "# RED exactly like this, because the held connections no longer exceed"
    echo "# any process ceiling."
    FAILED=$((FAILED + 1))
fi

# The EXIT trap (on_exit) stays armed past this point rather than being
# cleared: when CONTROL 1 rebooted this driver's own second server, that
# reboot still needs stopping on every remaining exit path below (a failed
# recovery probe included), and release_held is idempotent (HELD_FDS is
# already emptied by the call below, so on_exit's own call at exit iterates
# nothing).
# --- release: close every held descriptor --------------------------------
release_held

# --- recovery: a plain request must succeed again -------------------------
# Bounded retry, not a bare one-shot: ngx_disable_accept_events's own retry
# path (ngx_accept_disabled / accept_mutex_delay, see file header) may take
# one event-loop tick to re-arm the listen socket after descriptors free up,
# so a single immediate probe could race a healthy worker's own recovery
# window. Scaled by PROBER_TIMEOUT_SCALE like every other timing budget in
# this tree (a valgrind-instrumented worker's event loop tick is far slower
# than an unscaled 2s ceiling allows) -- 20 attempts * 100ms * scale, still
# finite (AUD-09 discipline: bounded, never an unbounded wait).
RECOVERED=0
RECOVER_BODY=""
RETRY_SLEEP="$(awk -v s="${PROBER_TIMEOUT_SCALE:-1}" 'BEGIN { printf "%.3f", 0.1 * s }')"
for ((i = 0; i < 20; i++)); do
    if RECOVER_BODY="$(prober_probe_body "$HOST" "$PORT")"; then
        RECOVERED=1
        break
    fi
    sleep "$RETRY_SLEEP"
done

if [ "$RECOVERED" -eq 1 ]; then
    echo "ok 3 - a fresh request succeeds after the held descriptors are released"
else
    echo "not ok 3 - no successful request within the recovery window after releasing the held descriptors"
    echo "# CONTROL 2 (wired in mutate.sh, MUT_KIND=scenario): neutralising the"
    echo "# 'release_held' call above (i.e. withholding the release) makes this"
    echo "# assertion RED exactly like this, because the worker stays pinned at"
    echo "# its rlimit and never accepts the recovery probe within the bound."
    FAILED=$((FAILED + 1))
fi

# --- neutrality: fds and connections.free return to EXACTLY baseline ------
if [ "$RECOVERED" -eq 1 ] && [ -n "${BASE_FDS:-}" ] && [ -n "${BASE_FREE:-}" ]; then
    # RECOVER_BODY is the FIRST probe that got through after the hold was
    # released -- by construction the earliest instant the worker could
    # answer again, with no guarantee the kernel and the worker have finished
    # reaping the 40 just-closed sockets in that same instant. Neutrality is
    # an AT-REST property, so re-sample with a small bounded settle rather
    # than judging exact equality against the least settled reading
    # available; a real leaked (or never-returned) descriptor still fails
    # this after the retry budget, a transient reaping lag does not.
    # Parse the body already in hand FIRST, then fetch a fresh one only if
    # this pass did not settle -- fetching before parsing (the earlier draft
    # of this loop) always threw away the last iteration's freshest sample
    # and judged the second-to-last one instead, narrowing the very flake
    # window this re-sample loop exists to widen.
    NOW_FDS=""
    NOW_FREE=""
    for ((i = 0; i < 20; i++)); do
        NOW_FDS="$(prober_probe_field "$RECOVER_BODY" fds)" || NOW_FDS=""
        NOW_FREE="$(prober_probe_field "$RECOVER_BODY" free)" || NOW_FREE=""
        if [ -n "$NOW_FDS" ] && [ -n "$NOW_FREE" ] \
           && [ "$NOW_FDS" -eq "$BASE_FDS" ] && [ "$NOW_FREE" -eq "$BASE_FREE" ]; then
            break
        fi
        [ "$i" -eq 19 ] && break
        sleep "$RETRY_SLEEP"
        if ! RECOVER_BODY="$(prober_probe_body "$HOST" "$PORT")"; then
            echo "# re-sample probe stopped answering; the values below are the last readable sample"
            break
        fi
    done

    if [ -n "$NOW_FDS" ] && [ -n "$NOW_FREE" ] \
       && [ "$NOW_FDS" -eq "$BASE_FDS" ] && [ "$NOW_FREE" -eq "$BASE_FREE" ]; then
        echo "ok 4 - fds and connections.free are back at exactly baseline after release (fds=$NOW_FDS free=$NOW_FREE)"
    else
        echo "not ok 4 - fds/connections.free did not return to exactly baseline (fds=${NOW_FDS:-?} vs base $BASE_FDS, free=${NOW_FREE:-?} vs base $BASE_FREE)"
        echo "# either a leaked descriptor, or one that never returned (e.g. an"
        echo "# error-log fd the worker itself dropped) would fail exactly this way"
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
