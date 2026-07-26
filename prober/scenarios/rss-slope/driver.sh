#!/usr/bin/env bash
#
# Scenario: POST-WARMUP RESOURCE SLOPE -- the third resource-scoreboard oracle
# from plan.md P2-E, alongside the per-operation `delta` and suite-origin
# `probe_baseline` oracles the .rule DSL already carries. It asserts that, once
# the server has warmed up, a resource grows by no more than a fixed amount PER
# OPERATION across a run of identical operations.
#
# WHY A SLOPE, NOT ANOTHER delta. A single request's `delta pool.cycle_used == 0`
# (soak-delta, alloc-per-request) catches a leak that shows on EVERY request. It
# is blind to two shapes a slope catches:
#
#   * A leak amortised below the per-case granularity -- a few bytes carved from
#     a shared block that a single before/after subtraction rounds to zero, but
#     that a hundred operations accumulate into an unmistakable climb.
#   * A resource the pool walk cannot see at all: RSS. smaps.private_dirty counts
#     the pages THIS worker alone has dirtied across every mapping -- a module's
#     own malloc arena, an mmap'd temp file, a thread stack -- none of which
#     touch ngx_cycle->pool, so `delta pool.cycle_used` stays flat while memory
#     climbs. The slope over smaps.private_dirty is the external-observer signal
#     for exactly that.
#
# WHY THIS SCENARIO USES A DRIVER, not a .rule file. The slope is a property of a
# SEQUENCE of probe snapshots taken between repeated operations, with a warmup
# prefix discarded; no single prober case straddles that sequence. The slope
# logic lives in prober_slope_check (lib.sh) so the warmup/sentinel/per-op
# discipline is written once and shared, exactly as the reload waits are.
#
# THE TWO SLOPE ORACLES:
#
#   1. pool.cycle_used slope == 0/op. Nothing in normal request handling may
#      allocate on the cycle pool; it lives as long as the worker. A per-request
#      cycle-pool leak drifts this monotonically, and the slope divides the total
#      drift by the operation count so a per-op leak of even a few bytes is a
#      nonzero (>=1) slope while a healthy server sits dead flat at 0/op. This is
#      the DETERMINISTIC oracle -- the cycle pool does not move on its own.
#
#   2. smaps.private_dirty slope, bounded not zero. RSS is noisier than the pool:
#      the kernel dirties and reclaims pages on its own schedule, glibc's arena
#      grows in chunks and does not shrink, and the first requests fault in code
#      and buffers that never come back. So this oracle is a BOUND on per-op
#      growth (PROBER_SLOPE_MAX_DIRTY kB/op, default 4 -- one page every few
#      ops), not an equality: a steady multi-page-per-op climb reds it, while the
#      ordinary settling of a healthy worker stays under it. The warmup prefix
#      (discarded) absorbs the boot one-off so it is not billed as a slope.
#
# NON-VACUITY (planted control, restore the ref .so after -- this is a HARNESS
# gate proof, never a real nginx finding; see lessons.md "this repo IS the
# tool"):
#   Flip the reference module's response-buffer allocation from r->pool to
#   ngx_cycle->pool (ngx_http_test_ref_module.c, the ~3 KiB JSON buffer). Each
#   /__probe-adjacent request then leaks a sub-pagesize block into the cycle
#   pool's block chain, so pool.cycle_used climbs ~3 KiB per operation:
#   oracle 1's slope goes from 0/op to thousands/op and reds `not ok 1`, and the
#   RSS climb reds oracle 2 as the leaked pages are dirtied. Restore the .so and
#   both return to a flat slope. Verified this reddens BY THE SLOPE ASSERTION,
#   not by a boot/probe failure.
#
# PER-OP COUNT is fixed (PROBER_SLOPE_OPS, default 60) with a fixed warmup
# (PROBER_SLOPE_WARMUP, default 10). A counted iteration, never a wall-clock
# budget: a slope measured per wall-second runs a different program on a loaded
# runner than an idle one and its flake reproduces nowhere (the discipline the
# rest of lib.sh follows). Because it is per-operation and bounded, the whole
# sweep is a few hundred fast local requests -- but the cadence for a real soak
# is weekly, per plan.md ("PR runs the mapped smallest case; slope/soak is
# weekly"): a consumer maps this scenario into the weekly lane, not the PR path.

set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

WARMUP="${PROBER_SLOPE_WARMUP:-10}"
OPS="${PROBER_SLOPE_OPS:-60}"
MAX_DIRTY="${PROBER_SLOPE_MAX_DIRTY:-4}"

# FAILED accumulates every failing assertion; the verdict is the EXIT STATUS, so
# a `not ok` that did not also raise it would be vacuous.
FAILED=0

# TAP plan:
#  1 the cycle-pool slope is flat (== 0/op) after warmup
#  2 the RSS (private_dirty) slope stays under the per-op bound
#    (SKIPped, not failed, on a sanitizer build -- see oracle 2 below)
echo "1..2"

# --- oracle 1: cycle-pool slope is exactly flat -----------------------------
# The stimulus is a plain GET /; each is one operation. A healthy server frees
# every request allocation back to the request pool, so the cycle pool is dead
# flat and the slope is 0/op. max_per_op is 0: this field does not move on its
# own, so any positive slope is a leak.
if out="$(prober_slope_check "$HOST" "$PORT" cycle_used / \
            "$WARMUP" "$OPS" 0)"; then
    echo "ok 1 - cycle-pool slope is flat across $OPS operations"
    printf '%s\n' "$out"
else
    echo "not ok 1 - cycle-pool slope is flat across $OPS operations"
    printf '%s\n' "$out"
    FAILED=1
fi

# --- oracle 2: RSS slope stays under the per-op bound ------------------------
# private_dirty is the pages this worker alone dirtied. Bounded, not zero: a
# healthy worker settles a little as glibc's arena grows in chunks, so the
# assertion is <= MAX_DIRTY kB/op. A steady multi-page-per-op climb -- a real
# leak dirtying fresh pages every operation -- exceeds it. If smaps_rollup is
# unreadable the field is the -1 sentinel and prober_slope_check fails CLOSED
# (naming it), never subtracting to a passing zero -- but the `requires` gate
# has already established the file is present, so a failure here is a real read
# problem, not an unsupported kernel.
#
# SKIPPED ON A SANITIZER BUILD. An ASan/UBSan runtime dirties fresh pages of its
# OWN as the worker services requests -- shadow memory, the allocator's redzones
# and quarantine, lazy servicing -- so private_dirty climbs steadily (measured
# ~91 kB/op on the san leg vs 0/op on a bare build) for reasons that are the
# sanitizer's memory surface, not a module leak. Widening MAX_DIRTY to absorb it
# would dull the bound on every uninstrumented leg for a san-only artifact, the
# same trap syscall-allowlist documents for its syscall set. So this ONE oracle
# SKIPs under a sanitizer binary; oracle 1 (cycle_used) is unaffected -- ASan
# does not allocate on the nginx cycle pool -- and still runs, so the san leg
# keeps a live slope assertion. Detected with the same `__asan_`/`__ubsan_`
# binary scan lib.sh and syscall-allowlist use.
if grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
    echo "ok 2 - RSS private_dirty slope # SKIP sanitizer build dirties its own pages (not a module leak)"
elif out="$(prober_slope_check "$HOST" "$PORT" private_dirty / \
            "$WARMUP" "$OPS" "$MAX_DIRTY")"; then
    echo "ok 2 - RSS private_dirty slope stays under ${MAX_DIRTY} kB/op"
    printf '%s\n' "$out"
else
    echo "not ok 2 - RSS private_dirty slope stays under ${MAX_DIRTY} kB/op"
    printf '%s\n' "$out"
    FAILED=1
fi

exit "$FAILED"
