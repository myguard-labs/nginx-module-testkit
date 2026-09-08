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
#      probe) makes assertion 4 (fd/connection neutrality) RED: the descriptors
#      and connection slots this driver took are never given back, so `free`
#      cannot return to its pre-pressure baseline. WIRED (mutate.sh,
#      MUT_KIND=scenario): see "fd-starve: release oracle" in mutate.sh, which
#      neutralises this exact `release_held` call.
#
#      ASSERTION 4, NOT ASSERTION 3, and this was MEASURED rather than assumed.
#      The obvious claim -- that withholding the release reds RECOVERY, because
#      the worker stays pinned at its rlimit and cannot accept the closing
#      request -- is FALSE here, and the run that proved it is why this file no
#      longer makes it. With 20 held connections against worker_rlimit_nofile
#      30 there is still descriptor headroom for one more accept() once
#      ngx_disable_accept_events re-arms the listen socket, so the mutant run
#      reports `ok 3` and reds `not ok 4 - ... free=977 vs base 997`. Crediting
#      that run to a claim about assertion 3 would be the "wrong owner"
#      vacuity: a control is only evidence for the assertion that actually went
#      red, which is what the marker below pins down.
#
# HOW A CONTROL IS CREDITED -- the 125 convention, stated once for this whole
# file. mutate.sh reads any plain nonzero, non-124 exit as `caught` (a red
# assertion), so a driver that DIED before reaching its assertions would credit
# a control that never ran. Every "the fixture itself could not be armed or
# exercised" bail below therefore exits 125, a distinct status mutate.sh maps to
# BROKEN; only a genuine `not ok` reaches the final `exit 1`. Later bails carry
# no repeat of this rationale.
#
# Nonzero alone is still not enough for a CONTROL row, because a fixture can
# also break in ways this driver never sees (a lost port, a crash in
# run-scenario.sh's own boot). So each control's red path prints a marker line,
# and the control's mutate.sh row requires it via MUTATE_REQUIRE_MARKER
# (mutate-suite-lib.sh): a nonzero run WITHOUT the marker is reported BROKEN,
# not caught.
#
#   FDSTARVE-RED-EMFILE-WITNESS   assertion 2 went red (CONTROL 1)
#   FDSTARVE-RED-NEUTRALITY       assertion 4 went red (CONTROL 2)
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

FAILED=0
REBOOTED=0

# HELD_FDS, release_held and on_exit are declared and armed BEFORE the
# CONTROL 1 reboot below, not after: the reboot can start a second server and
# then fail, and a trap installed later would never run at all -- exactly the
# orphaned-second-server outcome the reboot exists not to cause. REBOOTED is
# likewise set immediately BEFORE that boot rather than after it returns, so the
# trap treats "we started a second boot" as true the instant it is attempted,
# whether or not it succeeds.
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
# driver.sh as a plain child, never sources it), so the PARENT's own cleanup
# still remembers the FIRST boot's (already-dead) pid and cannot reach this one;
# left alone, the second boot orphans and holds the port for the rest of the CI
# job.
# shellcheck disable=SC2317,SC2329 # invoked indirectly via `trap ... EXIT`, not a dead call
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
# PROBER_TIMEOUT_SCALE is unexported in run-scenario.sh, so it never reaches
# this driver's separate process. Normalized here UNCONDITIONALLY, not inside
# the arm branch: SETTLE and RETRY_SLEEP below are computed on every run, and
# their `${PROBER_TIMEOUT_SCALE:-1}` fallback would otherwise silently pin an
# ordinary CI run to scale 1 with no `set -u` crash to catch it.
prober_normalize_timeout_scale

# shellcheck disable=SC2016
FDSTARVE_ARM_SED="${FDSTARVE_ARM_SED:-}"
# Wait for a stopped server to be GONE, rather than trusting prober_stop's
# `wait`. In daemon-off mode prober_stop reaps with `wait "$PROBER_SERVER_PID"`,
# which only works for a CHILD of the calling shell -- and this driver's first
# server is a child of run-scenario.sh, its PARENT. `wait` on a non-child
# returns immediately without reaping, so prober_stop returns while the old
# master and its worker still hold the listen socket, and the reboot below then
# races them for the port: `bind() ... (98: Address already in use)`, a failed
# boot, and (before the marker gate) a control credited `caught` for a fixture
# that never armed. Poll for actual death instead, the same shape prober_stop's
# own daemon-on branch uses.
wait_port_free() {
    local _i _owners
    # Scaled like SETTLE and RETRY_SLEEP below: on a valgrind or sanitizer leg
    # the retired master holds the listen socket well past a fixed 5s, and an
    # unscaled budget would bail 125 and land CONTROL 1 as BROKEN -- the
    # control stops being evidence rather than going falsely red.
    for ((_i = 0; _i < 100 * PROBER_TIMEOUT_SCALE; _i++)); do
        _owners="$(prober_port_owner_pids 127.0.0.1 "$PORT")" || return 0
        [ -z "$_owners" ] && return 0
        sleep 0.05
    done
    return 1
}

if [ -n "$FDSTARVE_ARM_SED" ]; then
    prober_stop
    if ! wait_port_free; then
        echo "Bail out! the first boot still holds port $PORT after prober_stop -- rebooting onto it would race its own predecessor"
        exit 125
    fi
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
        exit 125
    fi
    rm -f "$PREARM"

    # PROBER_BAIL_RETURN=1 for exactly these two calls (see lib.sh's own
    # "BAILING" note): prober_check_conf and prober_boot bail with `exit 1` by
    # default, which would kill THIS driver outright and hand mutate.sh a plain
    # 1 -- credited `caught` -- for a fixture that never came up. The opt-in
    # makes them `return 1` instead so the guards below are reachable and can
    # exit 125. Scoped to the call and unset immediately after, so nothing later
    # in this driver silently inherits the soft-bail mode.
    if ! PROBER_BAIL_RETURN=1 prober_check_conf; then
        echo "Bail out! the armed conf fails prober_check_conf's directive gate (daemon/worker_processes/pid) -- the fixture could not be armed, so no verdict below is meaningful"
        exit 125
    fi
    # Armed BEFORE the boot: prober_boot can start the server and still fail
    # its own listener wait, and on_exit must stop it in that case too.
    REBOOTED=1
    if ! PROBER_BAIL_RETURN=1 prober_boot; then
        echo "Bail out! the armed reboot did not come up -- fixture failure, not a red assertion"
        exit 125
    fi
fi

# TAP plan: five assertions.
#   1 baseline request succeeds before any pressure is applied (anti-vacuity:
#     proves the server is healthy and the probe readable before the fixture
#     manipulates anything)
#   2 pressure witness -- an EXACT EMFILE accept() failure, from THIS boot's
#     worker pid, appears in the server's own error log while descriptors
#     are held, and was ABSENT before the hold began
#   3 release -- with the held descriptors closed, a fresh request succeeds
#     (the recovery half of the done criterion: not merely "the process is
#     still alive" but "it serves a request again")
#   4 fd/connection neutrality -- fds/free return to EXACTLY the pre-pressure
#     baseline after release plus one clean request
#   5 pressure was actually APPLIED -- the worker's own fd count was observed
#     STRICTLY ABOVE its pre-pressure baseline at some point during the hold.
#     Its own assertion rather than a cosmetic branch of assertion 2: the climb
#     is the direct evidence that this driver's held sockets reached the worker
#     at all, and a number that can only select between two passing message
#     strings cannot fail the run and therefore proves nothing.
echo "1..5"

# --- baseline -----------------------------------------------------------
BASE_BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "not ok 1 - baseline request before pressure"
    echo "# probe unreachable before any fd pressure was applied"
    echo "Bail out! baseline probe unreadable -- refusing to apply fd pressure to a server already declared unhealthy"
    exit 125
}
BASE_FDS="$(prober_probe_field "$BASE_BODY" fds)" || BASE_FDS=""
BASE_FREE="$(prober_probe_field "$BASE_BODY" free)" || BASE_FREE=""
if [ -n "$BASE_FDS" ] && [ -n "$BASE_FREE" ]; then
    echo "ok 1 - baseline request before pressure (fds=$BASE_FDS free=$BASE_FREE)"
else
    echo "not ok 1 - baseline probe missing fds or connections.free"
    echo "Bail out! baseline probe returned no fds/free field -- cannot evaluate later assertions against an unknown baseline"
    exit 125
fi

BASE_PID="$(prober_probe_field "$BASE_BODY" pid)" || BASE_PID=""
if [ -z "$BASE_PID" ]; then
    echo "Bail out! baseline probe returned no pid field -- assertion 2 could not attribute an EMFILE witness to THIS boot's worker"
    # A missing pid would silently disable the pid gate rather than fail
    # loudly, which is exactly the "witness text alone" vacuity it closes.
    exit 125
fi

# Before applying any pressure, the witness text must be ABSENT -- a real
# negative control (finding 4a): without it, a stale EMFILE line surviving
# from a prior boot in the same $ELOG would pass assertion 2 after this
# driver held even a single descriptor.
if grep -qE 'accept4?\(\) failed \(24: Too many open files\)' "$ELOG" 2>/dev/null; then
    echo "Bail out! EMFILE witness text already present in $ELOG before any pressure was applied -- stale log or reused prefix"
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
        # accept()) means this box's OWN fd table or backlog is the constraint,
        # not the worker's -- not the condition under test, and not expected at
        # 40 sockets on any CI runner. A `break` here would leave EMFILE_SEEN=0
        # and red assertion 2, presenting a fixture break as the very red
        # assertion the controls claim to cause; bail instead.
        echo "Bail out! /dev/tcp connect failed while holding descriptor $i -- client-side fd pressure, not server-side"
        exit 125
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

# The witness alone decides THIS assertion; whether the fd count was seen to
# climb is assertion 5's job, so a missing in-pressure sample cannot red an
# assertion the log itself already proves.
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
    else
        echo "ok 2 - accept() EMFILE witnessed under held fd pressure (peak fds $PEAK_FDS, base $BASE_FDS)"
        echo "# $WITNESS"
    fi
else
    echo "not ok 2 - no accept() EMFILE line appeared in $ELOG after holding ${#HELD_FDS[@]} descriptors (peak fds $PEAK_FDS, base $BASE_FDS)"
    # The machine-checkable marker CONTROL 1's mutate.sh row requires (see this
    # file's header): raising or deleting worker_rlimit_nofile must land HERE,
    # not merely make the suite exit nonzero.
    echo "# FDSTARVE-RED-EMFILE-WITNESS"
    FAILED=$((FAILED + 1))
fi

# on_exit stays armed past this point: a CONTROL 1 reboot still needs stopping
# on every remaining exit path, and release_held is idempotent.
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
    # Set when the re-sample fetch stops answering. Without it the loop breaks
    # carrying NOW_FDS/NOW_FREE from the PREVIOUS iteration and the comparison
    # below can print `ok 4` on that stale pair -- so a worker that answered
    # once and then died would pass a neutrality assertion measured on a body
    # fetched before it died.
    STALE=0
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
            STALE=1
            break
        fi
    done

    if [ "$STALE" -eq 0 ] && [ -n "$NOW_FDS" ] && [ -n "$NOW_FREE" ] \
       && [ "$NOW_FDS" -eq "$BASE_FDS" ] && [ "$NOW_FREE" -eq "$BASE_FREE" ]; then
        echo "ok 4 - fds and connections.free are back at exactly baseline after release (fds=$NOW_FDS free=$NOW_FREE)"
    else
        if [ "$STALE" -eq 1 ]; then
            echo "not ok 4 - the server stopped answering during the neutrality re-sample; the last readable values (fds=${NOW_FDS:-?} free=${NOW_FREE:-?}) predate that and cannot be asserted on"
        else
            echo "not ok 4 - fds/connections.free did not return to exactly baseline (fds=${NOW_FDS:-?} vs base $BASE_FDS, free=${NOW_FREE:-?} vs base $BASE_FREE)"
            echo "# either a leaked descriptor, or one that never returned (e.g. an"
            echo "# error-log fd the worker itself dropped) would fail exactly this way"
            # CONTROL 2's required marker: withholding release_held must land
            # HERE. Deliberately NOT on the STALE branch above -- that one means
            # the server stopped answering, i.e. the fixture broke, which is
            # exactly what the marker exists to distinguish from a red oracle.
            echo "# FDSTARVE-RED-NEUTRALITY"
        fi
        FAILED=$((FAILED + 1))
    fi
else
    echo "not ok 4 - no recovered probe body to measure neutrality against"
    echo "# assertion 3 or the baseline already failed, so neutrality cannot be evaluated"
    FAILED=$((FAILED + 1))
fi

# --- pressure actually reached the worker --------------------------------
# PEAK_FDS is the highest `fds` any in-pressure probe reported during the hold
# loop. Strictly above the pre-pressure baseline is the direct evidence that
# this driver's held sockets landed in the WORKER's descriptor table, rather
# than the run having witnessed an EMFILE line for some reason of its own.
#
# The probe during active pressure is best-effort -- the worker is, by
# definition, refusing accept() around the moment EMFILE fires -- but "the
# sample was unavailable" is reported as a FAILED assertion, not waved through:
# a hold loop that reached EMFILE necessarily answered at least one earlier
# in-pressure probe at a raised fd count, so no sample at all means the pressure
# was not observed to be applied.
if [ "$PEAK_FDS" -gt "$BASE_FDS" ] 2>/dev/null; then
    echo "ok 5 - worker fds observed climbing under the hold ($BASE_FDS -> $PEAK_FDS)"
else
    echo "not ok 5 - worker fds were never observed above the pre-pressure baseline (peak $PEAK_FDS, base $BASE_FDS) -- the hold did not demonstrably reach the worker"
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -eq 0 ]; then
    exit 0
fi
exit 1
