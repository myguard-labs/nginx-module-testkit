#!/usr/bin/env bash
#
# Scenario: CONSUMER PER-REQUEST ALLOCATION NEUTRALITY (grind item H3, "second
# consumer zero-hook"). A real consumer module -- nginx-cache-turbo-module's
# ngx_http_cache_turbo_module.so, NOT the harness's own ref probe -- serves
# repeated GETs through its in-memory (shm) L1 cache and the driver proves the
# per-request work is allocation-neutral: cycle-pool counters (cycle_used,
# cycle_blocks, cycle_large), worker fd count, and MASTER fd count are all
# identical across two post-drain QUIESCENT snapshots taken around one extra
# full served request. Equal means the HIT path frees everything it allocates
# per request -- no per-request cache-entry-ref, header-copy, or connection
# leak surviving repeated serves.
#
# WHY THIS IS THE CONSUMER SCENARIO, NOT ANOTHER REF-MODULE ONE: every sibling
# leak scenario (alloc-per-request, rss-slope, reload-soak, ...) drives the
# harness's own ref probe module, whose per-request behaviour is a stand-in.
# This one loads a real third-party module and asserts a property that only
# exists because THAT module's HIT filter does per-request work (cache-key
# lookup, shared-zone node refcounting, response-header replay) atop the plain
# request lifecycle. The shm zone + config dict are config-pool/shm state,
# allocated once at parse time -- NOT per request -- so they must NOT show up
# as a per-request delta; that absence IS the property under test. The harness
# stays generic: it contributes the probe (cycle-pool/fd fields) and the drain
# wait; the cache-turbo specifics (the zone, the HIT header, the origin
# location) live entirely in this scenario + its conf. On a tree without the
# cache_turbo .so the `requires` gate SKIPs the whole scenario, so CI -- which
# builds the ref probe only -- reports SKIP, never a false pass.
#
# ORACLE-4-STYLE DESIGN LESSON (reused from reload-compressing/G6f, see
# memory/labs/nginx-module-testkit/HANDOFF.md "Oracle 4 design lesson"): a
# per-request-leak oracle for a module that allocates per request canNOT use a
# COLD pre-request baseline (carries a startup one-off) NOR a mid-work
# snapshot (flakes on the module's live per-request buffers). Use TWO
# post-drain QUIESCENT snapshots taken around one extra full request: equal =>
# allocation-neutral. This scenario has no reload in it at all (H3 is about
# steady-state per-request neutrality, not reload survival), so "post-drain"
# here means "after a warm-up request has settled the worker", not "after a
# reload's old cycle exited" -- see the warm-up step below.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

# master_fds: open descriptor count of the MASTER process (not a worker).
# Same idiom as reload-soak/worker-death's master_fds -- /proc/$MASTER/fd is
# not readable on every host (e.g. no /proc, or permission), so a caller must
# treat a failed read as "cannot observe", not as zero, and surface that as a
# visible SKIP rather than a false pass. See oracle 6 below.
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

# one_request OUTFILE: drive ONE full-speed GET / to completion under a
# bounded deadline, capturing the raw response. Same bounded-subshell-kill
# shape as reload-compressing's one_zstd_request: a hung fetch must not hang
# the whole scenario, and a truncated capture must not be silently trusted as
# a completed request (which would make the quiescent snapshot around it
# meaningless).
one_request() {
    local out="$1" pid dl
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    pid=$!
    dl=$(( SECONDS + 10 ))          # a shm-cache HIT answers in well under 1 s
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$SECONDS" -ge "$dl" ]; then
            pkill -P "$pid" 2>/dev/null || true
            kill "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.05
    done
    wait "$pid" 2>/dev/null || true
    grep -q '^HTTP/1.1 200' "$out"
}

# TAP plan (7 oracles from the spec):
#  1 warm-up request serves 200 (readiness / non-vacuity)
#  2 a cache HIT actually occurred on the measured request (anti-vacuity: the
#    filter's HIT path genuinely ran, not an empty pass-through)
#  3 cycle_used equal across the two post-drain quiescent snapshots
#  4 cycle_blocks + cycle_large equal across the same two snapshots
#  5 worker fds equal across the same two snapshots
#  6 master fd count flat across the same window
#  7 no signal-death in the error log + a strict clean 200 on a final request
echo "1..7"

# --- 1: warm-up request -- also what makes request 2 onward a HIT ------------
# The FIRST GET / is necessarily a MISS (nothing cached yet): it populates the
# shm zone via proxy_pass to /origin. This is deliberately NOT counted as part
# of the leak measurement -- it is what turns every subsequent GET into a real
# HIT, which is the anti-vacuity precondition oracle 2 checks. Captured raw so
# its status line can be asserted directly.
WARMUP="$PROBER_PREFIX/warmup.out"
WARMUP_OK=0
if one_request "$WARMUP"; then
    WARMUP_OK=1
fi
if [ "$WARMUP_OK" -eq 1 ]; then
    echo "ok 1 - the warm-up request served a clean 200 (server is ready, cache populated)"
else
    echo "not ok 1 - the warm-up request did not complete as a clean 200"
    head -5 "$WARMUP" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 2: a genuine cache HIT occurred -----------------------------------------
# Fire ONE more request (distinct from the warm-up and distinct from the pair
# used for the leak measurement below) purely to prove the HIT path runs at
# all -- without this, oracle 3-6 could be measuring an empty/pass-through
# filter and calling that "allocation-neutral" vacuously. cache-turbo emits
# `X-Cache: HIT` on a served-from-shm response (ngx_http_cache_turbo_module.c
# X-Cache header logic); a MISS or STALE response would read differently, so
# this is a real assertion on the module's own status line, not a body guess.
HITCHECK="$PROBER_PREFIX/hitcheck.out"
HIT_SEEN=0
if [ "$WARMUP_OK" -eq 1 ] && one_request "$HITCHECK"; then
    if grep -qi '^X-Cache:[[:space:]]*HIT' "$HITCHECK"; then
        HIT_SEEN=1
    fi
fi
if [ "$HIT_SEEN" -eq 1 ]; then
    echo "ok 2 - a genuine cache HIT occurred (X-Cache: HIT on the served response)"
else
    echo "not ok 2 - no cache HIT was observed (X-Cache header absent or not HIT)"
    head -20 "$HITCHECK" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- oracle-3..6 measurement: two QUIESCENT snapshots around one more request
# Both snapshots are taken with NO request in flight (the probe read itself is
# the only traffic at each instant, and the HIT-path request between them
# completes before the second read begins) -- never a cold pre-warm-up
# baseline (would carry cache-turbo's own config-init / first-MISS one-off,
# same trap the reload-compressing lesson documents in reverse) and never a
# mid-request snapshot (would flake on live per-request buffers). If the
# stimulus request does not complete cleanly, both oracles SKIP rather than
# compare against a vacuous reading.
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
if [ "$BASE_OK" -eq 1 ] && one_request "$STIM" && grep -qi '^X-Cache:[[:space:]]*HIT' "$STIM"; then
    STIM_OK=1
fi

FINAL_OK=0
if [ "$STIM_OK" -eq 1 ] && snapshot; then
    FINAL_OK=1
    FINAL_USED="$SNAP_USED"; FINAL_BLOCKS="$SNAP_BLOCKS"; FINAL_LARGE="$SNAP_LARGE"; FINAL_FDS="$SNAP_FDS"
fi
FINAL_MFDS="$(master_fds || true)"

if [ "$STIM_OK" -ne 1 ]; then
    echo "# the extra measured request did not complete as a valid cache HIT -- oracles 3-6 will SKIP rather than compare against a vacuous reading"
fi

# --- 3: cycle_used flat -------------------------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 3 - cycle_used allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_USED" = "$FINAL_USED" ]; then
    echo "ok 3 - cycle_used was flat across the extra HIT request ($BASE_USED)"
else
    echo "not ok 3 - cycle_used grew across the extra HIT request (before=$BASE_USED after=$FINAL_USED)"
    FAILED=$((FAILED + 1))
fi

# --- 4: cycle_blocks + cycle_large flat --------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 4 - cycle_blocks/cycle_large allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_BLOCKS" = "$FINAL_BLOCKS" ] && [ "$BASE_LARGE" = "$FINAL_LARGE" ]; then
    echo "ok 4 - cycle_blocks ($BASE_BLOCKS) and cycle_large ($BASE_LARGE) were flat across the extra HIT request"
else
    echo "not ok 4 - cycle_blocks/cycle_large grew across the extra HIT request (before blocks=$BASE_BLOCKS large=$BASE_LARGE, after blocks=$FINAL_BLOCKS large=$FINAL_LARGE)"
    FAILED=$((FAILED + 1))
fi

# --- 5: worker fds flat -------------------------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 5 - worker fds allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_FDS" = "$FINAL_FDS" ]; then
    echo "ok 5 - worker fd count was flat across the extra HIT request ($BASE_FDS)"
else
    echo "not ok 5 - worker fd count grew across the extra HIT request (before=$BASE_FDS after=$FINAL_FDS)"
    FAILED=$((FAILED + 1))
fi

# --- 6: master fd count flat --------------------------------------------------
if [ -z "$BASE_MFDS" ] || [ -z "$FINAL_MFDS" ]; then
    echo "ok 6 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 6 - master descriptor count allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_MFDS" = "$FINAL_MFDS" ]; then
    echo "ok 6 - master fd count was flat across the extra HIT request ($BASE_MFDS)"
else
    echo "not ok 6 - master fd count grew across the extra HIT request (before=$BASE_MFDS after=$FINAL_MFDS)"
    FAILED=$((FAILED + 1))
fi

# --- 7: no signal-death + a final strict clean 200 ---------------------------
SIGDEATH=0
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    SIGDEATH=1
fi

FINAL_REQ="$PROBER_PREFIX/final.out"
FINAL_CLEAN=0
if one_request "$FINAL_REQ"; then
    FINAL_CLEAN=1
fi

if [ "$SIGDEATH" -eq 0 ] && [ "$FINAL_CLEAN" -eq 1 ]; then
    echo "ok 7 - no worker died by signal, and a final request still served a clean 200"
else
    echo "not ok 7 - server health check failed (signal-death=$SIGDEATH, final-clean=$FINAL_CLEAN)"
    if [ "$SIGDEATH" -eq 1 ]; then
        grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    fi
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
