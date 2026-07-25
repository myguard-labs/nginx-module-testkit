#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario: nginx and angie must agree on the FLAVOR-INVARIANT shape of the
# probe document. Every other scenario runs under whichever flavor the CI
# matrix leg gives it and asserts things true of that one server; this is the
# only one whose entire point is a claim ACROSS flavors -- that a field the
# harness calls "generic" (see ngx_test_probe.h's own words: "Everything here
# is generic to nginx and angie") really is, not merely on the flavor whoever
# wrote the assertion happened to test against.
#
# SHAPE CHOSEN: golden, not two-tree. test-scenarios.sh discovers scenarios by
# a glob (`./scenarios/*/`, see test-scenarios.sh:24) and the CI `scenarios:`
# job already runs that glob once per flavor leg (nginx 1.28.0, nginx 1.29.0,
# angie 1.12.0 -- ci.yml's `scenarios:` matrix). So THIS scenario needs no new
# CI job and no new flavor axis: it runs under whatever leg it lands on,
# normalizes that leg's probe JSON, and diffs the result against a CHECKED-IN
# golden both flavors must match. A leg whose invariant fields disagree with
# the golden reds; ci.yml is untouched.
#
# THE MASKING LIST IS THE WHOLE DESIGN. A field belongs in NORMALIZE (masked to
# a fixed token before the diff) when it is legitimately allowed to differ
# across flavor or across an unrelated environment axis, i.e. a difference
# there is not a bug. Get this list wrong in either direction and the scenario
# lies: too little masking makes the golden flaky (a real, harmless difference
# reds every run); too much masking makes it vacuous (nothing left to disagree
# on, so a real divergence never reds -- see the mutation proof below).
#
#   MASKED (flavor/env-specific, not a bug if it differs):
#     flavor            -- IS the axis under test; asserted structurally
#                           (see ok 1) rather than compared verbatim.
#     flavor_version    -- differs by construction (1.28.0 vs 1.29.0 vs
#                           1.12.0); also drifts release to release.
#     pid, ppid         -- OS-assigned, different on every boot regardless
#                           of flavor.
#     config_generation -- the header itself: "no assertion should depend on
#                           the origin" -- it is a per-binary counter, not a
#                           cross-flavor invariant.
#     pool.cycle_used   -- MEASURED to differ: nginx 1.29.0 startup reports
#     pool.cycle_blocks    67287/5 blocks, angie 1.12.0 reports 84536/6 on an
#                           otherwise-identical conf (empirically confirmed
#                           locally, 3 runs each, both stable but disagreeing
#                           -- angie's own module set allocates more from the
#                           cycle pool at startup). A genuine per-flavor
#                           startup-allocation difference, not a leak.
#     pool.cycle_large  -- not asserted on its own elsewhere in this repo as a
#                           cross-flavor invariant; grouped with the other
#                           pool.* members for the same startup-allocation
#                           reasoning.
#
#   INVARIANT (asserted, exact value both flavors must produce):
#     page_size             -- ngx_pagesize; same host, same libc, same
#                               getconf(_SC_PAGESIZE) on both binaries.
#     connections.total     -- worker_connections from THIS conf, echoed back
#                               structurally; both flavors render the same
#                               template so this must be identical or the
#                               config layer itself diverged.
#     connections.free      -- MEASURED identical (13 both, 3 runs each) on a
#                               freshly booted single-worker server with no
#                               request yet made; both flavors reserve the same
#                               number of connections for their own listening/
#                               event-loop/log fds on this conf.
#     fds                   -- MEASURED identical (10 both, 3 runs each) on
#                               the same freshly booted conf.
#     zone.present           -- no zone is configured in this scenario's conf,
#                               so both flavors must report false.
#
# The response itself (status 200, body "OK") is asserted too -- not because
# it is part of the probe JSON, but because a differential over a document
# both sides render identically without a real request behind it would not be
# testing anything a static compile-time check could not already tell you.
#
# ANTI-VACUITY: see lessons.md / issues.md for the mutation performed to prove
# this golden is not vacuous -- flip an invariant field's rendered value in
# ngx_test_probe.c, rebuild the reference .so, rerun: the golden must RED. Then
# restore and confirm GREEN. The opposite check (masking a genuinely
# flavor-specific field, e.g. pool.cycle_used, must NOT red across the flavors
# runnable locally) is proved by the empirical 3x3 measurement above: had that
# field been left unmasked, this scenario would already be red on a clean tree.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
GOLDEN="$PROBER_SCENARIO/golden.json"

FAILED=0

echo "1..4"

# --- 1: the flavor detection fired (structural, not a golden compare) ------
BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "Bail out! no probe response at all -- server did not boot cleanly"
    exit 1
}

FLAVOR="$(printf '%s' "$BODY" | grep -o '"flavor"[[:space:]]*:[[:space:]]*"[^"]*"' \
          | grep -o '"[^"]*"$' | tr -d '"')"

case "$FLAVOR" in
    nginx|angie)
        echo "ok 1 - flavor detected as '$FLAVOR'" ;;
    *)
        echo "not ok 1 - flavor field is '$FLAVOR', neither nginx nor angie"
        FAILED=$((FAILED + 1)) ;;
esac

# --- normalize: mask every flavor/env-specific field to a fixed token ------
#
# The full masking rationale (which fields are masked, which are invariant,
# and the measurements backing each classification) lives once, in
# prober_probe_normalize (lib.sh) -- a sibling of prober_probe_body/
# prober_probe_field, so a future second differential scenario (a consumer
# module's own probe fields) reuses the same masking discipline instead of
# re-deriving it.
#
# prober_probe_body hands back the RAW HTTP response, headers included -- a
# `Date:`-shaped header in there would never match twice, golden or not. The
# JSON document is the one line beginning with `{`; everything before it is
# transport, not payload, and is dropped before normalizing.
JSON_LINE="$(printf '%s' "$BODY" | grep '^{')"
NORMALIZED="$(prober_probe_normalize "$JSON_LINE")"

# --- 2: the normalized document matches the checked-in golden -------------
#
# The golden was captured from a clean nginx 1.29.0 run of this exact conf and
# is meant to be reproduced, field for field, by every flavor this scenario
# runs under. A missing golden is a fixture bug (scenario shipped without one),
# not a pass -- so it fails loudly rather than silently seeding itself, which
# would make the FIRST bad run become the reference for every run after it.
if [ ! -f "$GOLDEN" ]; then
    echo "Bail out! $GOLDEN is missing -- this scenario ships a golden, it does" \
         "not generate one at runtime (that would let a bad first run become"  \
         "the reference forever)"
    exit 1
fi

if diff -u "$GOLDEN" <(printf '%s\n' "$NORMALIZED") >/tmp/flavor-differential.diff 2>&1; then
    echo "ok 2 - normalized probe document matches the golden"
else
    echo "not ok 2 - normalized probe document diverges from the golden"
    sed 's/^/# /' /tmp/flavor-differential.diff
    FAILED=$((FAILED + 1))
fi

# --- 3: no zone was configured, and both flavors must agree on that --------
if printf '%s' "$BODY" | grep -q '"zone":{"present":false}'; then
    echo "ok 3 - zone.present is false (no zone configured in this conf)"
else
    echo "not ok 3 - zone.present is not false with no zone configured"
    FAILED=$((FAILED + 1))
fi

# --- 4: the plain response the conf serves is itself flavor-invariant ------
RESP="$(
    trap '' PIPE
    exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
    printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
    timeout 2 cat <&3
    exit 0
)"

if printf '%s' "$RESP" | grep -q '^HTTP/1.1 200' \
   && printf '%s' "$RESP" | grep -q '^OK$'; then
    echo "ok 4 - the plain response is 200/OK on both flavors"
else
    echo "not ok 4 - the plain response was not 200/OK"
    printf '%s\n' "$RESP" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
