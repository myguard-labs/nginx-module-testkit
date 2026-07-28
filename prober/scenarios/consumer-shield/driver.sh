#!/usr/bin/env bash
#
# Scenario: CONSUMER PER-REQUEST ALLOCATION NEUTRALITY, shield equivalent of
# consumer-cache-turbo's H3 (see that scenario's header for the full oracle-4
# rationale -- reused verbatim here). A real consumer module --
# nginx-http-shield-module's ngx_http_shield_module.so, NOT the harness's own
# ref probe -- runs its PRECONTENT detection path on every request through
# `shield detect;`, and the driver proves the per-request work is
# allocation-neutral: cycle-pool counters (cycle_used, cycle_blocks,
# cycle_large), worker fd count, and MASTER fd count are all identical across
# two post-drain QUIESCENT snapshots taken around one extra full request.
#
# WHY /  (detect mode) AND NOT /guarded (block mode): `shield block` on a
# detected request short-circuits with a 403 before proxy_pass runs, which is
# a DIFFERENT code path (less work, not representative of steady-state
# traffic). `shield detect` always runs the full detection logic and then
# still proxies, so every request here exercises the module's real
# per-request analysis path end-to-end, upstream failure (502, nothing
# listens on 127.0.0.1:1) notwithstanding -- the response code is irrelevant
# to this oracle; only the ALLOCATION behaviour is under test.
#
# ORACLE-4-STYLE DESIGN, reused from consumer-cache-turbo (H3) / reload-
# compressing (G6f): two post-drain QUIESCENT snapshots around one extra
# request; never a cold pre-request baseline (carries a startup one-off) nor a
# mid-work snapshot (flakes on live per-request buffers).
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

master_fds() {
    [ -r "/proc/$MASTER/fd" ] || return 1
    # shellcheck disable=SC2012  # /proc fd names are decimal ints, ls|wc is exact
    ls "/proc/$MASTER/fd" 2>/dev/null | wc -l
}

snapshot() {             # read one probe snapshot into SNAP_* globals
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
}

# one_request PATH OUTFILE: drive ONE full-speed GET PATH to completion under
# a bounded deadline, capturing the raw response. Same bounded-subshell-kill
# shape as consumer-cache-turbo's one_request: a hung fetch must not hang the
# whole scenario, and a truncated capture must not be silently trusted as a
# completed request.
one_request() {
    local path="$1" out="$2" pid dl
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$path" >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    pid=$!
    dl=$(( SECONDS + 10 ))
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$SECONDS" -ge "$dl" ]; then
            pkill -P "$pid" 2>/dev/null || true
            kill "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.05
    done
    wait "$pid" 2>/dev/null || true
    # Any HTTP status line at all proves the connection did not hang and
    # shield's PRECONTENT handler ran to completion (502 from the dead
    # upstream is the EXPECTED, correct response in detect mode -- see header).
    grep -qE '^HTTP/1\.1 [0-9]{3}' "$out"
}

# TAP plan (6 oracles, one fewer than cache-turbo -- no cache HIT header to
# assert since shield has no cache semantics):
#  1 warm-up request completes with a valid HTTP status (readiness)
#  2 cycle_used equal across the two post-drain quiescent snapshots
#  3 cycle_blocks + cycle_large equal across the same two snapshots
#  4 worker fds equal across the same two snapshots
#  5 master fd count flat across the same window
#  6 no signal-death in the error log + a strict final request still answers
echo "1..6"

# --- 1: warm-up request --------------------------------------------------
WARMUP="$PROBER_PREFIX/warmup.out"
WARMUP_OK=0
if one_request / "$WARMUP"; then
    WARMUP_OK=1
fi
if [ "$WARMUP_OK" -eq 1 ]; then
    echo "ok 1 - the warm-up request through shield detect completed (server is ready)"
else
    echo "not ok 1 - the warm-up request did not complete with a valid HTTP status"
    head -5 "$WARMUP" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- oracle-2..5 measurement: two QUIESCENT snapshots around one more request
BASE_OK=1
if ! snapshot; then
    BASE_OK=0
    echo "# the probe endpoint did not answer for the first post-drain snapshot"
fi
if [ "$BASE_OK" -eq 1 ]; then
    BASE_USED="$SNAP_USED"; BASE_BLOCKS="$SNAP_BLOCKS"; BASE_LARGE="$SNAP_LARGE"; BASE_FDS="$SNAP_FDS"
fi
BASE_MFDS="$(master_fds || true)"

STIM="$PROBER_PREFIX/stimulus.out"
STIM_OK=0
if [ "$BASE_OK" -eq 1 ] && [ "$WARMUP_OK" -eq 1 ] && one_request / "$STIM"; then
    STIM_OK=1
fi

FINAL_OK=0
if [ "$STIM_OK" -eq 1 ] && snapshot; then
    FINAL_OK=1
    FINAL_USED="$SNAP_USED"; FINAL_BLOCKS="$SNAP_BLOCKS"; FINAL_LARGE="$SNAP_LARGE"; FINAL_FDS="$SNAP_FDS"
fi
FINAL_MFDS="$(master_fds || true)"

if [ "$STIM_OK" -ne 1 ]; then
    echo "# the extra measured request did not complete cleanly -- oracles 2-5 will SKIP rather than compare against a vacuous reading"
fi

# --- 2: cycle_used flat ---------------------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 2 - cycle_used allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_USED" = "$FINAL_USED" ]; then
    echo "ok 2 - cycle_used was flat across the extra shield-detect request ($BASE_USED)"
else
    echo "not ok 2 - cycle_used grew across the extra shield-detect request (before=$BASE_USED after=$FINAL_USED)"
    FAILED=$((FAILED + 1))
fi

# --- 3: cycle_blocks + cycle_large flat -----------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 3 - cycle_blocks/cycle_large allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_BLOCKS" = "$FINAL_BLOCKS" ] && [ "$BASE_LARGE" = "$FINAL_LARGE" ]; then
    echo "ok 3 - cycle_blocks ($BASE_BLOCKS) and cycle_large ($BASE_LARGE) were flat across the extra shield-detect request"
else
    echo "not ok 3 - cycle_blocks/cycle_large grew across the extra shield-detect request (before blocks=$BASE_BLOCKS large=$BASE_LARGE, after blocks=$FINAL_BLOCKS large=$FINAL_LARGE)"
    FAILED=$((FAILED + 1))
fi

# --- 4: worker fds flat ----------------------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 4 - worker fds allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_FDS" = "$FINAL_FDS" ]; then
    echo "ok 4 - worker fd count was flat across the extra shield-detect request ($BASE_FDS)"
else
    echo "not ok 4 - worker fd count grew across the extra shield-detect request (before=$BASE_FDS after=$FINAL_FDS)"
    FAILED=$((FAILED + 1))
fi

# --- 5: master fd count flat ------------------------------------------------
if [ -z "$BASE_MFDS" ] || [ -z "$FINAL_MFDS" ]; then
    echo "ok 5 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 5 - master descriptor count allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_MFDS" = "$FINAL_MFDS" ]; then
    echo "ok 5 - master fd count was flat across the extra shield-detect request ($BASE_MFDS)"
else
    echo "not ok 5 - master fd count grew across the extra shield-detect request (before=$BASE_MFDS after=$FINAL_MFDS)"
    FAILED=$((FAILED + 1))
fi

# --- 6: no signal-death + a final request still answers ---------------------
SIGDEATH=0
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    SIGDEATH=1
fi

FINAL_REQ="$PROBER_PREFIX/final.out"
FINAL_CLEAN=0
if one_request / "$FINAL_REQ"; then
    FINAL_CLEAN=1
fi

if [ "$SIGDEATH" -eq 0 ] && [ "$FINAL_CLEAN" -eq 1 ]; then
    echo "ok 6 - no worker died by signal, and a final request still answered"
else
    echo "not ok 6 - server health check failed (signal-death=$SIGDEATH, final-clean=$FINAL_CLEAN)"
    if [ "$SIGDEATH" -eq 1 ]; then
        grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    fi
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
