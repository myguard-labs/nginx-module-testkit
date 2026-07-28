#!/usr/bin/env bash
#
# Scenario: the module holds an upstream (memcached) connection in its keepalive
# pool; the backend hangs that parked connection up while it is idle. The next
# request must NOTICE the peer closed and RECONNECT -- open a fresh upstream
# connection -- rather than write down the dead descriptor. A reload is then
# folded in on top: after the pool has already had to reconnect once, a SIGHUP
# lands and a post-reload request must still serve correctly.
#
# This closes the L14 gap: cache-turbo's memcached keepalive pool has
# config-time rejection tests only, and nothing anywhere proves the runtime
# reconnect-after-idle-close path. The falsifiable instrument is the backend
# JOURNAL: only it can distinguish a connection the module REUSED (one accept)
# from one it REOPENED (a second accept). No module log settles it as directly.
#
# Why a driver and not a plain .rule file: the reconnect only happens if a real
# time gap separates the two requests -- long enough for the backend's idle
# timer to fire and close the parked connection -- and that ordering is proven
# by polling the journal for the idle-close fault, not by a sleep. The prober
# runs cases back to back with no such gap and no signal delivery, so it cannot
# drive this on its own.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
JOURNAL="$PROBER_BACKEND_JOURNAL"

# The prober leg's no_error_log directive needs this; run-scenario.sh exports it
# only for a rules run, so a driver that runs the prober exports it itself.
export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing driver assertion. A consumer folds this
# driver's TAP into one block and keys the scenario verdict off the EXIT STATUS
# (test-scenarios.sh), not the inner plan -- so a `not ok` that did not also
# raise the exit status would be vacuous. Every branch that prints `not ok`
# bumps FAILED; the final exit is nonzero if FAILED>0 or the prober leg went red.
FAILED=0

# A GET /mc?key=k over /dev/tcp (bash's client, as lib.sh uses it -- nc variants
# differ). Captures the full response so the driver can assert the body.
# $1 = output file.
do_request() {
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /mc?key=k HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        # cat's exit is ignored: a Connection: close reply commonly ends in an
        # RST once everything is sent, and cat exits non-zero having already
        # delivered a complete body (see prober_probe_pid).
        cat <&3 2>/dev/null || true
    ) >"$1" 2>/dev/null
}

served_value() {   # $1 = captured response file
    grep -q '^HTTP/1.1 200' "$1" && grep -q 'idle-close-reload-value' "$1"
}

# Count {"ev":"accept",...} records in the journal so far. Each new upstream
# connection the module opens is exactly one accept; reuse of a parked
# connection adds none. This is the reconnect oracle.
accepts_so_far() {
    [ -n "$JOURNAL" ] || { echo 0; return; }
    grep -c '"ev":"accept"' "$JOURNAL" 2>/dev/null || true
}

# TAP plan:
#  1 first request served correctly and parked a pool connection
#  2 the backend closed the parked connection while it was idle (fault applied)
#  3 the post-idle request reconnected (a second upstream accept) -- the L14 proof
#  4 the post-idle request was served correctly over the fresh connection
#  5 the reload was absorbed
#  6 the post-reload request was served correctly
#  7 no worker died by signal across the reload
#  + the prober's own post-reload verdict, folded in as diagnostics
echo "1..7"

# --- request A: establish and park a keepalive connection ------------------
OUT_A="$PROBER_PREFIX/a.out"
do_request "$OUT_A"
if served_value "$OUT_A"; then
    echo "ok 1 - first request served correctly and parked a pool connection"
else
    echo "not ok 1 - first request did not serve the seeded value"
    sed 's/^/# /' "$OUT_A" | head -20
    FAILED=$((FAILED + 1))
fi
ACCEPTS_AFTER_A=$(accepts_so_far)

# --- wait for the backend to close the parked connection while idle --------
# Falsifiable ordering: poll the journal for the idle-close fault record rather
# than sleeping past a guessed timeout. fakesrv writes {"ev":"fault","on":"idle",
# "action":"close_after","applied":true} the moment it hangs the parked
# connection up. Fixed-step counted iterations, never a wall-clock diff (same
# discipline as prober_wait_listen): a loaded runner performs the same count.
IDLE_SEEN=0
for ((i = 0; i < 100; i++)); do            # 100 * 50 ms = 5 s ceiling (fault is 200 ms)
    if [ -n "$JOURNAL" ] \
       && grep -q '"ev":"fault"[^}]*"on":"idle"[^}]*"applied":true' "$JOURNAL" 2>/dev/null; then
        IDLE_SEEN=1
        break
    fi
    sleep 0.05
done
if [ "$IDLE_SEEN" -eq 1 ]; then
    echo "ok 2 - the backend closed the parked connection while it was idle"
else
    echo "not ok 2 - the backend never closed the idle parked connection within 5 s"
    echo "# no idle close_after fault recorded; the reconnect precondition is unmet"
    FAILED=$((FAILED + 1))
fi

# --- request B: must reconnect, not reuse the dead descriptor --------------
OUT_B="$PROBER_PREFIX/b.out"
do_request "$OUT_B"
ACCEPTS_AFTER_B=$(accepts_so_far)

# The reconnect oracle: request B forced at least one NEW upstream accept beyond
# what request A did. Reuse of the (now dead) parked connection would add zero
# accepts and the request would fail on the closed descriptor instead.
if [ "$ACCEPTS_AFTER_B" -gt "$ACCEPTS_AFTER_A" ]; then
    echo "ok 3 - the post-idle request reconnected (a fresh upstream accept)"
else
    echo "not ok 3 - no new upstream connection after the idle close (dead fd reused?)"
    echo "# accepts: $ACCEPTS_AFTER_A after A, $ACCEPTS_AFTER_B after B (expected an increase)"
    FAILED=$((FAILED + 1))
fi

if served_value "$OUT_B"; then
    echo "ok 4 - the post-idle request was served correctly over the fresh connection"
else
    echo "not ok 4 - the post-idle request failed (reconnect did not recover the request)"
    sed 's/^/# /' "$OUT_B" | head -20
    FAILED=$((FAILED + 1))
fi

# --- reload on top of the already-reconnected pool -------------------------
# prober_signal_wait sends SIGHUP and blocks until a different worker pid answers
# the probe -- the reload is fully absorbed -- or times out (a real failure).
if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" 5000; then
    echo "ok 5 - the reload was absorbed"
else
    echo "not ok 5 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- request C: the reloaded worker serves correctly -----------------------
OUT_C="$PROBER_PREFIX/c.out"
do_request "$OUT_C"
if served_value "$OUT_C"; then
    echo "ok 6 - the post-reload request was served correctly"
else
    echo "not ok 6 - the post-reload request did not serve the seeded value"
    sed 's/^/# /' "$OUT_C" | head -20
    FAILED=$((FAILED + 1))
fi

# --- no worker died by signal ----------------------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash, so the
# worker-exit path is asserted separately: a clean reload never logs a signal
# death for a worker.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 7 - a worker died by signal during the scenario"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 7 - no worker died by signal"
fi

# --- let the reloaded worker settle before the strict-oracle prober leg -----
# prober_signal_wait returns as soon as A different worker answers, but the
# master may still be finishing the reload -- and on angie the first post-reload
# worker was observed to be replaced again a moment later. The post-reload case
# below uses a STRICT pid oracle (its two probe snapshots must see the SAME
# worker), so running it into that churn misreads the second respawn as "the
# worker died during this case". Wait for the worker pid to be STABLE -- the same
# value on two consecutive probes -- before the strict leg. Fixed-step counted
# iterations, never a wall-clock diff (prober_wait_listen discipline). This is a
# settle, not a relaxed oracle: the case still demands one unchanging worker, it
# just does not begin until the reload has stopped moving.
#
# The pid alone is NOT a sufficient settle, and waiting on it only is what made
# this scenario the most frequent flake in the suite (3 of 4 scenario legs on one
# 2026-07-28 CI wave, both flavors). The red was never a pid change -- driver
# oracles 1-7 all passed and the prober leg reported
#   delta fds: 13 -> 12 is -1, want == 0 (unchanged over 8 re-reads)
# A NEGATIVE delta means a descriptor closed INSIDE the probe window: after the
# reload the old worker's parked upstream connection is reaped asynchronously, so
# a stable pid coexists with an fd table that is still draining. post-reload.rule
# asserts `delta fds == 0`, so the settle must cover the quantity that oracle
# reads. Require pid AND fd count identical on two consecutive probes.
#
# Both are read from ONE snapshot per iteration, not two: probing twice per turn
# would let the pid come from a different snapshot than the fd count and settle
# on a pair that never coexisted.
prev_pid=""
prev_fds=""
settled=0
for ((i = 0; i < 100; i++)); do            # 100 * 50 ms = 5 s ceiling
    body=$(prober_probe_body "$HOST" "$PORT" || true)
    cur_pid=""
    cur_fds=""
    if [ -n "$body" ]; then
        cur_pid=$(prober_probe_field "$body" pid || true)
        cur_fds=$(prober_probe_field "$body" fds || true)
    fi
    if [ -n "$cur_pid" ] && [ -n "$cur_fds" ] \
       && [ "$cur_pid" = "$prev_pid" ] && [ "$cur_fds" = "$prev_fds" ]; then
        settled=1
        break
    fi
    prev_pid="$cur_pid"
    prev_fds="$cur_fds"
    sleep 0.05
done

# Exhausting the loop without settling used to fall through SILENTLY into the
# strict oracle, which then failed for a reason the log never named. Say so.
# Not a hard exit: the strict leg below is still the real oracle and may well
# pass -- but if it fails, this line is the difference between "known settle
# timeout" and half an hour of diagnosis.
if [ "$settled" -ne 1 ]; then
    echo "# settle: worker pid+fds still moving after 100 probes" \
         "(pid=$cur_pid fds=$cur_fds); running the strict leg anyway"
fi

# --- post-reload coherence (prober, folded in as diagnostics) --------------
# A plain strict case AFTER the reload: the reloaded worker serves a correct 200
# on the plain location, leaks no descriptor, and logs nothing on the error
# path. STRICT pid oracle is correct here -- a single post-reload worker answers
# both probe snapshots, so "same worker pid" is the stronger true assertion, and
# no case in this file straddles the signal within its own before/after window.
# The settle loop above guarantees the reload has stopped churning first.
STATUS=0
# PIPESTATUS, not $?: a bare `./prober | sed` reports sed's exit (always 0),
# silently discarding a red prober leg.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
