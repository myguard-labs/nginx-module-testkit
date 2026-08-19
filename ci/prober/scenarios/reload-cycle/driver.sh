#!/usr/bin/env bash
#
# Scenario: the server is reloaded (SIGHUP) N times in a row while otherwise
# idle. Each reload builds a NEW cycle -- a fresh cycle pool, a fresh worker,
# re-opened listening sockets -- and must release the OLD one. The classic
# module failure this catches is a per-cycle allocation or descriptor that is
# created in an init_module / init_process hook and never released when the
# cycle it belongs to goes away: nothing fails, nothing logs, and the process
# simply grows one cycle's worth on every reload for the life of the server.
#
# Why a driver and not a plain .rule file: a reload happens BETWEEN prober
# invocations, and the state that matters is a comparison of probe snapshots
# taken on either side of a signal that no single prober case can straddle.
# The prober's own per-case `delta` machinery measures within one case; this
# scenario needs the across-reload axis.
#
# THE ORACLES, and why each is the shape it is:
#
#   Worker cycle-pool counters (pool.cycle_used / cycle_blocks / cycle_large).
#   Each reload's worker builds its cycle pool by parsing the SAME config with
#   the same binary, so a healthy series produces the SAME counters every time.
#   The assertion is therefore EXACT EQUALITY between the first post-reload
#   snapshot and every later one -- not a band. A band here would be the weaker
#   claim, and the quantity genuinely is deterministic once the old cycle has
#   drained: measured identical across the series on nginx 1.29.0, nginx 1.31.3
#   and angie 1.12.0, over repeated runs. A module leaking into ngx_cycle->pool
#   per reload moves these monotonically.
#
#   Worker descriptor count (fds). A worker that inherits a descriptor from the
#   cycle before it -- the shape that eventually exhausts the process -- shows
#   up as a post-reload fd count that climbs with the reload index. Exact
#   equality again, and for the same reason.
#
#   MASTER descriptor count (/proc/<master>/fd). The worker-side counters can
#   only ever see the cycle the worker was forked into; a cycle leaked in the
#   MASTER (the process that actually keeps the old cycle alive until its
#   workers are gone) is invisible to them. A leaked listening socket or old
#   cycle fd in the master is deterministic and countable, which makes it the
#   sharp master-side oracle. Linux-only: skipped, VISIBLY, where /proc is not
#   readable, never silently dropped.
#
#   MASTER resident size (/proc/<master>/statm). The only signal available for
#   a master-side leak that is memory rather than descriptors. It is COARSE on
#   purpose: an allocator that does not return freed pages to the OS keeps RSS
#   flat over a leak of a few KiB, so this can only catch a gross one, and it
#   is given a generous band rather than a tight one to avoid a flaky gate
#   making a claim it cannot support. It is a backstop for the fd oracle above,
#   not a replacement for it. On a SANITIZED build it is skipped outright: ASan
#   quarantines freed memory and keeps its own shadow bookkeeping, so the
#   measurement describes the sanitizer, not the server (the same series grew
#   the master 21 pages unsanitized and 402 pages under ASan). Widening the band
#   to fit that would leave a gate that can no longer fail on any build.
#
# On pid oracles: every post-reload worker must still be a CHILD OF THE SAME
# MASTER (probe field "ppid" -- absent from a module .so built before that
# field existed, which becomes a visible skip, see snapshot() below). prober_signal_wait's own oracle is "a different
# pid answered", which a crashed-and-respawned worker satisfies just as well as
# a reloaded one; the ppid check plus the error-log scan below is what separates
# the two. A master that itself died and was restarted by something outside the
# harness would change ppid, and that must fail rather than read as a reload.
#
# NEGATIVE CONTROLS. Both were run locally against nginx 1.29.0 and the fixture
# restored afterwards -- see lessons.md: this repo IS the harness, so a planted
# "leak" is a control proving the GATE fires, never a real bug to fix. Each is
# planted in t/module's config handler (which runs once per config load, i.e.
# once per cycle) and the ref .so rebuilt (recipe in the s97 handoff block).
#
#   A. Per-cycle POOL accumulation -- a static counter incremented per config
#      load, allocating from the cycle pool in proportion to it:
#          static ngx_uint_t n = 0;  n++;  ngx_palloc(cf->pool, 64 * n);
#      Result: assertion 3 reds on cycle_used alone, climbing +64 per reload
#      (63855, 63919, 63983, ...), every other assertion green -- which is the
#      point, since the other oracles are blind to this class.
#      Sizing matters: the first attempt allocated 4096 * n and did NOT red,
#      because an allocation of a page or more goes to the pool's LARGE list
#      and never reaches cycle_used. That is exactly why this scenario asserts
#      cycle_blocks and cycle_large alongside it rather than cycle_used alone.
#
#   B. Per-cycle DESCRIPTOR leak -- ngx_open_file("/dev/null") per config load,
#      never closed. Result: assertion 3 reds on fds (12, 13, 14, ... one per
#      reload) AND assertion 6 reds on the master (9 -> 17 over 8 reloads),
#      confirming the worker-side and master-side oracles both fire and are
#      not measuring the same thing twice.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

# The prober needs the error-log path to satisfy the post-reload case's
# no_error_log directive. run-scenario.sh exports this only for the rules
# branch, so a driver that runs the prober must export it itself.
export PROBER_ERROR_LOG="$ELOG"

# How many reloads the series runs. Enough that a per-cycle leak is a clear
# monotone climb rather than one ambiguous step, and small enough that the
# scenario stays a fast PR-gate leg: each reload costs one prober_signal_wait,
# which returns as soon as a new worker answers rather than after a fixed sleep.
RELOADS=8

# What worker_processes in this scenario's nginx.conf asks for. The drain oracle
# below waits for exactly this many children of the master; keeping the two in
# one place is what stops a conf edit from turning the wait into a permanent
# timeout (or, worse, into a condition that is already true and never waits).
WORKERS=1

# FAILED accumulates every failing assertion. The driver's `not ok` lines are
# for a human; test-scenarios.sh keys the scenario verdict off this script's
# EXIT STATUS, so a `not ok` that did not also raise the exit status would be a
# vacuous assertion that can never fail the suite.
FAILED=0

echo "1..8"

# --- helpers ---------------------------------------------------------------

# Read one probe snapshot into the SNAP_* globals. Fails the whole driver if a
# field is missing: a snapshot with a silently absent counter would be compared
# as an empty string against a number, and the comparison below would be
# meaningless rather than red. prober_probe_field already refuses to report an
# absent field as 0 for the same reason.
snapshot() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    # The worker pid itself is deliberately NOT captured: "a different worker
    # is answering" is prober_signal_wait's own verdict, already asserted, and a
    # second copy here would be the same claim wearing a different name.
    # "ppid" is the one field allowed to be absent, and only because a module
    # .so built before it was added (ngx_test_probe.c) emits a body without it.
    # An absent ppid becomes a VISIBLE skip at assertion 4, never a silent pass:
    # the empty value cannot compare equal to a real one, and the assertion
    # branches on emptiness explicitly rather than letting "" = "" read as
    # agreement. Every other field stays mandatory -- a missing counter there
    # would make the comparison meaningless rather than red.
    SNAP_PPID="$(prober_probe_field "$body" ppid || true)"
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
}

# A handful of plain requests, so the worker's pool has done its per-request
# allocate-and-free cycle before a snapshot is taken. Without this the FIRST
# post-reload snapshot could be taken on a worker that has served nothing while
# later ones are taken on workers that have, and the difference between "never
# allocated" and "allocated and freed" would read as a leak.
warm() {
    local i
    for ((i = 0; i < 3; i++)); do
        (
            exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 0
            printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
            timeout 2 cat <&3 >/dev/null 2>&1 || true
        ) || true
    done
}

# Master-side counts, or empty when /proc is not readable (non-Linux, or a
# hardened /proc). Empty is handled by a VISIBLE skip at the assertion, never
# by treating the missing measurement as agreement.
master_fds() {
    [ -r "/proc/$MASTER/fd" ] || return 1
    # shellcheck disable=SC2012  # a count of entries; `ls | wc -l` is exact
    # here because /proc/<pid>/fd names are decimal integers and cannot contain
    # a newline.
    ls "/proc/$MASTER/fd" 2>/dev/null | wc -l
}

master_rss_pages() {
    [ -r "/proc/$MASTER/statm" ] || return 1
    awk '{print $2}' "/proc/$MASTER/statm" 2>/dev/null
}

# --- baseline (before any reload) -----------------------------------------

warm
if ! snapshot; then
    echo "Bail out! the probe endpoint did not answer before the first reload"
    exit 1
fi

# The master's own pid, as the worker sees it. Every later worker must report
# this same parent; a change means the master went away, which is not a reload.
BASE_PPID="$SNAP_PPID"

M_FDS_BASE="$(master_fds || true)"
M_RSS_BASE="$(master_rss_pages || true)"

# --- the reload series ----------------------------------------------------
# Snapshots are collected per reload and compared afterwards, so that one
# assertion covers the whole series rather than emitting N TAP lines whose
# count would change with RELOADS.

ABSORBED=0
PPID_STABLE=1
DRAINED=1
DRAIN_OBSERVABLE=1
FIRST_SET=0
FDS_REF=; USED_REF=; BLOCKS_REF=; LARGE_REF=
DRIFT=""

for ((r = 1; r <= RELOADS; r++)); do
    # A timeout here is a real failure: the reload never landed. Keep going
    # through the series anyway -- a later reload landing after an earlier one
    # did not is a diagnosis worth having in the same run.
    if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" 5000; then
        ABSORBED=$((ABSORBED + 1))
    else
        echo "# reload $r was not absorbed within 5 s (no new worker answered)"
        continue
    fi

    # A new worker answering does NOT mean the old cycle is gone: the previous
    # worker is still draining, and while it lives both the master and the new
    # worker hold extra channel descriptors that belong to the handover, not to
    # a cycle. Measuring there produced 10, 11 or 12 fds for the same healthy
    # series on this box (see prober_drain_wait). Wait for the single-worker
    # steady state before any snapshot, so every comparison below is taken at
    # the same, well-defined point of the cycle's life.
    #
    # WORKERS is what the CONFIG asks for (worker_processes 1); a drain timeout
    # is a real failure -- an old worker that never exits is a bug this scenario
    # should report, not a measurement to take anyway.
    DRC=0
    prober_drain_wait "$MASTER" "$WORKERS" 10000 || DRC=$?
    case "$DRC" in
        0) ;;
        2) DRAIN_OBSERVABLE=0 ;;
        *) echo "# reload $r: the previous cycle's workers had not drained after 10 s"
           DRAINED=0 ;;
    esac

    warm
    if ! snapshot; then
        echo "# reload $r: the probe endpoint did not answer afterwards"
        DRIFT="$DRIFT reload$r:no-snapshot"
        continue
    fi

    if [ -n "$BASE_PPID" ] && [ "$SNAP_PPID" != "$BASE_PPID" ]; then
        PPID_STABLE=0
    fi

    if [ "$FIRST_SET" -eq 0 ]; then
        # The FIRST post-reload snapshot is the reference, deliberately not the
        # pre-reload baseline: the very first cycle is built by a master that
        # has just started, and a one-off startup allocation that is not
        # repeated per reload would otherwise read as a leak in reverse. What
        # this scenario claims is that reload K costs the same as reload 1, for
        # every K -- which is exactly the property a per-cycle leak breaks.
        FDS_REF="$SNAP_FDS"; USED_REF="$SNAP_USED"
        BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
        FIRST_SET=1
        continue
    fi

    drift_if() {   # NAME GOT WANT -- one newline-delimited record per drift
        [ "$2" = "$3" ] && return 0
        DRIFT="$DRIFT
reload $r: $1 = $2, want $3"
    }
    drift_if fds          "$SNAP_FDS"    "$FDS_REF"
    drift_if cycle_used   "$SNAP_USED"   "$USED_REF"
    drift_if cycle_blocks "$SNAP_BLOCKS" "$BLOCKS_REF"
    drift_if cycle_large  "$SNAP_LARGE"  "$LARGE_REF"
done

# --- 1: every reload landed -----------------------------------------------
if [ "$ABSORBED" -eq "$RELOADS" ]; then
    echo "ok 1 - all $RELOADS reloads were absorbed"
else
    echo "not ok 1 - only $ABSORBED of $RELOADS reloads were absorbed"
    FAILED=$((FAILED + 1))
fi

# --- 2: the series actually produced comparable snapshots ------------------
# Guards the assertions below against being vacuously green on a run where the
# probe never answered: with FIRST_SET still 0 there is nothing to compare, and
# an empty DRIFT would otherwise certify "no drift".
if [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 2 - post-reload snapshots were collected for comparison"
else
    echo "not ok 2 - no post-reload snapshot could be taken; the comparisons below prove nothing"
    FAILED=$((FAILED + 1))
fi

# --- 3: worker cycle pool and descriptors flat across the series ----------
if [ -z "$DRIFT" ] && [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 3 - worker fds and cycle-pool counters identical across all reloads"
    echo "# fds=$FDS_REF cycle_used=$USED_REF cycle_blocks=$BLOCKS_REF cycle_large=$LARGE_REF"
else
    echo "not ok 3 - worker state drifted across reloads (per-cycle leak?)"
    # Quoted, newline-delimited: an unquoted $DRIFT would word-split each
    # record on its own spaces and print one token per line.
    printf '%s\n' "$DRIFT" | sed '/^$/d; s/^/# /'
    FAILED=$((FAILED + 1))
fi

# --- 4: every worker stayed a child of the same master --------------------
if [ -z "$BASE_PPID" ]; then
    echo "ok 4 - master parentage # SKIP this module .so emits no \"ppid\" field"
elif [ "$PPID_STABLE" -eq 1 ]; then
    echo "ok 4 - every post-reload worker was a child of the original master"
else
    echo "not ok 4 - a post-reload worker reported a different master (ppid changed from $BASE_PPID)"
    FAILED=$((FAILED + 1))
fi

# --- 5: no worker died by signal across the series ------------------------
# prober_signal_wait cannot tell a reload from a crash (a respawned worker has
# the same master as a reloaded one), so the signal-death path is asserted
# separately, exactly as backend-reload-inflight does.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the reload series"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the reload series"
fi

# --- 6: the master leaked no descriptor -----------------------------------
M_FDS_END="$(master_fds || true)"
if [ -z "$M_FDS_BASE" ] || [ -z "$M_FDS_END" ]; then
    echo "ok 6 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$M_FDS_END" -eq "$M_FDS_BASE" ]; then
    echo "ok 6 - the master held $M_FDS_END descriptors before and after $RELOADS reloads"
else
    echo "not ok 6 - the master's descriptor count moved $M_FDS_BASE -> $M_FDS_END across $RELOADS reloads"
    FAILED=$((FAILED + 1))
fi

# --- 7: the master did not grow grossly -----------------------------------
# Coarse by construction (see header). The band is per-reload so that changing
# RELOADS cannot silently loosen or tighten the claim: 16 pages (64 KiB on a
# 4 KiB page) per reload is far above the measured noise of a healthy series
# (0 pages) and far below a leaked cycle pool's footprint.
M_RSS_END="$(master_rss_pages || true)"
if [ "${PROBER_SANITIZED:-0}" -eq 1 ]; then
    echo "ok 7 - master resident size # SKIP sanitized build: the runtime's quarantine and shadow state dominate RSS"
elif [ -z "$M_RSS_BASE" ] || [ -z "$M_RSS_END" ]; then
    echo "ok 7 - master resident size # SKIP /proc/$MASTER/statm not readable on this host"
else
    RSS_BAND=$(( 16 * RELOADS ))
    RSS_GROWTH=$(( M_RSS_END - M_RSS_BASE ))
    if [ "$RSS_GROWTH" -le "$RSS_BAND" ]; then
        echo "ok 7 - master resident size grew $RSS_GROWTH pages over $RELOADS reloads (band $RSS_BAND)"
    else
        echo "not ok 7 - master resident size grew $RSS_GROWTH pages over $RELOADS reloads (band $RSS_BAND)"
        FAILED=$((FAILED + 1))
    fi
fi

# --- 8: every old cycle's workers went away ------------------------------
# Not a mere precondition of the measurements above: a worker that never exits
# after its cycle was replaced IS the leak, in process form -- the server ends
# up with one live worker per reload it has ever served.
if [ "$DRAIN_OBSERVABLE" -eq 0 ]; then
    echo "ok 8 - old-cycle worker drain # SKIP pgrep unavailable on this host"
elif [ "$DRAINED" -eq 1 ]; then
    echo "ok 8 - every reload drained back to $WORKERS worker"
else
    echo "not ok 8 - a previous cycle's worker was still running after a reload"
    FAILED=$((FAILED + 1))
fi

# --- post-reload coherence (prober, folded in as diagnostics) -------------
# PIPESTATUS, not $?: a bare `./prober | sed` reports sed's status, which is
# always 0, silently discarding a red prober leg.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
