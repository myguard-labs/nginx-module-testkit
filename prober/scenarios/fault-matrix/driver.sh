#!/usr/bin/env bash
#
# Scenario: fault-matrix (P2-G6, named fault matrix from uncovered error
# branches). For EACH named upstream fault the fake can express -- reset, short
# read, length undercount, length overcount, byte-drip, idle close -- the worker
# takes a different ngx_http_upstream error branch, and after that branch has
# run to completion the request pool and the upstream connection must be back to
# exactly the state a clean request would leave. The harness-owned oracle is
# resource neutrality read from the probe: fds and pool.cycle_used return to the
# settled post-warmup baseline, and no worker died.
#
# THE MATRIX (branch -> fault -> fast target -> resource oracle -> mutation) is
# in matrix.tsv beside this driver; each row's "get ordinal" column is the get
# this driver issues to trigger that row, and the backend script arms the fault
# on that same ordinal (on=get:<nth>). So the table, the backend and this driver
# are three views of one list -- a row is added by editing all three, and the
# plan-count assertion below catches a driver that drifts from the table.
#
# WHY THE PROBE AND NOT nginx.pm. Every fault here can be thrown at a plain
# Test::Nginx suite too, and the STATUS/body it produces is not the point -- a
# module that leaks an upstream fd or a cycle-pool block on the reset branch
# still returns a plausible 200/502. The unique oracle is the in-worker fd count
# and cycle-pool footprint AFTER the branch, which only the probe supplies. This
# is exactly the "allocator/cleanup/lifetime C -> probe delta/baseline" row of
# the plan's diff table.
#
# WHY A FIXED, ORDINAL-KEYED INJECTION (no timers, no random). Each fault fires
# on a numbered get, so the sequence is byte-identical on a fast box and a slow
# ASan box -- the property-fuzz reproducibility discipline applied to fault
# selection. A wall-clock or racey injector would make a leak that only shows on
# row 5 unreachable on the leg that is slow to get there.
#
# NON-VACUITY -- why the oracles are proven load-bearing. The branch under test
# is nginx's own upstream cleanup (ngx_http_upstream_finalize_request + the
# memcached module), which this repo cannot mutate in-budget the way it mutates
# its own C, and the ref module serves /__probe not /mc so a planted leak in it
# would not sit on the upstream path. So each oracle is proven by a DOCUMENTED
# baseline-corruption control -- the sanctioned fallback (same as
# stateful-property-fuzz's C1..C5 and property-fuzz's leak claim 1), one of which
# is also wired into mutate.sh so CI re-proves it every run:
#   CONTROL B (wired, mutate.sh "fault-matrix: cycle_used oracle vacuous"):
#     corrupt BASE_USED (subtract 1). cycle_used is deterministic (measured
#     identical to the byte across 20 faulted gets), so every healthy row then
#     reads != baseline and reds -- proving the EXACT cycle-pool oracle fires and
#     its verdict raises the exit status, not just prints. A real per-request
#     cycle-pool leak makes the live reading climb past baseline the same way.
#   CONTROL A (documented, run by hand): tighten BASE_FDS by 1. A parked-
#     keepalive reading (11) then exceeds the ceiling (10) and reds -- proving the
#     fds CEILING oracle fires. Not wired into mutate.sh because fds oscillates
#     10<->11 with the keepalive pool state (see the baseline block), so at the
#     boundary a row that happens to read 10 would pass 10<=10; the ceiling is a
#     monotonic-growth backstop (a real fd leak of N climbs to BASE_FDS+N and
#     crosses on every row), and cycle_used is the deterministic primary oracle.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MATRIX="$PROBER_SCENARIO/matrix.tsv"

# FAILED accumulates every failing driver assertion; the scenario verdict keys
# off the EXIT STATUS (test-scenarios.sh), so a `not ok` that did not also raise
# the status would be vacuous. Every not-ok branch bumps FAILED.
FAILED=0

# GET /mc?key=k over /dev/tcp (bash's client, as lib.sh uses it -- nc variants
# differ). The response is discarded: this scenario asserts on the worker's
# resource state after the request, never on the faulted reply's shape (that is
# backend-lying-length / backend-rst-midreply's job). cat's exit is ignored -- a
# reset or a Connection: close reply commonly ends in an RST after a complete
# transfer (see prober_probe_pid).
# GETNO is the GLOBAL get counter (fakesrv numbers get occurrences from 1 across
# the whole connection lifetime, and on=get:<nth> keys off that ordinal). The
# warmup gets consume 1..WARMUP, so the matrix faults sit at WARMUP+1.. -- the
# driver asserts each row's declared ordinal against GETNO so a table/backend
# drift cannot pass on an unfaulted get.
GETNO=0
do_get() {
    GETNO=$((GETNO + 1))
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /mc?key=k HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        trap '' PIPE
        cat <&3 2>/dev/null || true
    ) >/dev/null 2>&1 || true
}

# Read one probe field, failing closed on the -1 sentinel (an unreadable /proc
# renders fds as -1, and -1 minus -1 is 0 -- a clean-looking delta over a broken
# probe). prober_probe_field is numeric-only, which is what fds and cycle_used
# are, so no boolean-parse trap here.
snap_field() {   # $1 = probe body, $2 = field name -> value on stdout, or "" + rc1
    local v
    v="$(prober_probe_field "$1" "$2")" || return 1
    case "$v" in
        -1) return 1 ;;                 # fail-loud sentinel
        ''|*[!0-9-]*) return 1 ;;       # non-numeric -> unusable
    esac
    printf '%s\n' "$v"
}

# --- warm up and take the settled baseline ---------------------------------
# get 1 carries NO fault (backend row above): it establishes the keepalive pool
# and a steady per-worker fd/cycle-pool footprint. A few extra warmup gets settle
# any first-request one-offs (the pool's first connection, a lazily-mapped page)
# so the baseline is what a HEALTHY steady request leaves, not a cold-start
# transient -- the same reasoning prober_slope_check's warmup discard uses.
#
# TWO DIFFERENT OBSERVABLES, TWO DIFFERENT BASELINE RULES:
#
#  * cycle_used is a DETERMINISTIC memory footprint -- the long-lived cycle pool
#    does not shrink and a healthy steady request adds nothing to it, so it holds
#    a single exact value across the whole sweep (measured: identical to the byte
#    across 20 repeated faulted gets). A per-request cycle-pool leak makes it
#    climb. Oracle: cycle_used == baseline, EXACT.
#
#  * fds is NOT exact-comparable. The keepalive upstream pool parks a connection
#    between requests, so the worker's fd count legitimately oscillates by one
#    (parked vs just-closed) depending on the pool state at the instant the probe
#    reads -- measured 10<->11 with NO leak, settling at a ceiling of 11, never
#    growing. This is the same "fds is a per-worker count that legitimately
#    shifts" fact flavor-differential and stateful-property-fuzz record. So the
#    fds oracle is a CEILING, not an equality: baseline is the MAX fds observed
#    once the pool is warm, and a row fails only if it EXCEEDS that ceiling -- a
#    leaked descriptor climbs past it, a parked keepalive fd never does.
WARMUP=8
BASE_FDS=0
BASE_USED=""
BASE_PID=""
for ((i = 0; i < WARMUP; i++)); do
    do_get
    wbody="$(prober_probe_body "$HOST" "$PORT")" || {
        echo "Bail out! probe unreadable while warming the fault-matrix baseline"
        exit 1
    }
    wf="$(snap_field "$wbody" fds)" || {
        echo "Bail out! fds unreadable/sentinel in a warmup probe -- cannot judge fd neutrality"
        exit 1
    }
    [ "$wf" -gt "$BASE_FDS" ] && BASE_FDS="$wf"   # ceiling = max settled fd count
    BASE_USED="$(snap_field "$wbody" cycle_used)" || {
        echo "Bail out! cycle_used unreadable in a warmup probe"
        exit 1
    }
    BASE_PID="$(snap_field "$wbody" pid)" || {
        echo "Bail out! pid unreadable in a warmup probe"
        exit 1
    }
done

# --- the matrix rows -------------------------------------------------------
# Read the rows from matrix.tsv (skip comments/blank/header). Columns:
#   1 name   2 fault-summary   3 get-ordinal
# For each row, issue the numbered get (the backend applies the row's fault to
# that ordinal) and assert resource neutrality against the baseline.
rows=0
while IFS=$'\t' read -r name fault ordinal _rest; do
    case "$name" in ''|'#'*|name) continue ;; esac
    rows=$((rows + 1))
done < "$MATRIX"

# The plan line is the row count plus one final "no worker died" aggregate.
echo "1..$((rows + 1))"

n=0
worker_died=0
while IFS=$'\t' read -r name fault ordinal _rest; do
    case "$name" in ''|'#'*|name) continue ;; esac
    n=$((n + 1))

    # Issue this row's faulted get. The backend arms the fault on this exact
    # global ordinal; asserting the row's declared ordinal against the get this
    # driver is about to issue is the drift guard between table, backend and
    # driver -- without it a WARMUP change or a re-numbered fault would silently
    # fault a warmup get and leave the matrix gets clean (a vacuous green).
    do_get
    if [ "$ordinal" != "$GETNO" ]; then
        echo "not ok $n - $name: matrix ordinal $ordinal != issued get $GETNO (table/backend/driver drift)"
        echo "#  the fault for this row is armed on=get:$ordinal but this driver issued get $GETNO;"
        echo "#  a warmup-count or backend-ordinal change desynced the three views of the matrix"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Read the post-fault probe and compare fds + cycle_used to the baseline.
    body="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    fds="$(snap_field "$body" fds 2>/dev/null || true)"
    used="$(snap_field "$body" cycle_used 2>/dev/null || true)"
    pid="$(snap_field "$body" pid 2>/dev/null || true)"

    problems=""
    if [ -z "$fds" ] || [ -z "$used" ] || [ -z "$pid" ]; then
        problems="probe unreadable after fault ($fault)"
    else
        # fds: CEILING oracle -- a leak climbs past the settled max, a parked
        # keepalive fd never does (see the baseline block for why not equality).
        [ "$fds" -le "$BASE_FDS" ] || problems="$problems fds=$fds/ceiling-$BASE_FDS(leaked upstream descriptor?)"
        # cycle_used: EXACT -- deterministic, a leak is any increase.
        [ "$used" = "$BASE_USED" ] || problems="$problems cycle_used=$used/want-$BASE_USED(cycle-pool residue?)"
        # A pid change here means the worker crashed on this branch and was
        # respawned -- a hard failure, not merely a resource drift.
        [ "$pid" = "$BASE_PID" ]   || { problems="$problems pid=$pid/want-$BASE_PID(worker crashed on this branch?)"; worker_died=1; }
    fi

    if [ -z "$problems" ]; then
        echo "ok $n - $name ($fault): fds and cycle_used returned to baseline after the fault branch"
    else
        echo "not ok $n - $name ($fault): resource not neutral after the fault branch"
        echo "#  $problems"
        FAILED=$((FAILED + 1))
    fi
done < "$MATRIX"

# --- aggregate: no worker died by signal across the whole sweep ------------
# A resource drift and a crash present differently: the per-row pid check above
# catches a crash-and-respawn WITHIN a row, but a worker that died at the very
# end (after its last probe) or logged a signal death without changing the pid
# the next probe reads needs the error-log backstop. A clean sweep logs no
# signal death for any worker.
if [ "$worker_died" -eq 0 ] \
   && ! grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "ok $((n + 1)) - no worker died by signal across the fault sweep"
else
    echo "not ok $((n + 1)) - a worker died during the fault sweep"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
