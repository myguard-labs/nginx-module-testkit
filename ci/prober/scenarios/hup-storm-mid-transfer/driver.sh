#!/usr/bin/env bash
#
# Scenario: a HUP STORM -- 10 SIGHUPs delivered back to back -- underneath ONE
# single client request whose upstream reply is still dripping out of the fake
# backend. This is reload-soak's deferred "Major": instead of a stream of
# serial close-conn requests hammering an otherwise-fungible server, ONE
# request is held open on the wire and must survive ALL TEN reloads as the
# SAME logical exchange -- byte-complete body, status 200, never re-issued to
# the upstream, no worker killed by signal, and the worker cycle-pool counters
# flat across the whole series (the same per-cycle-leak claim reload-soak
# makes, just under a held-request storm instead of a load loop).
#
# Composed from three templates (see their own headers for the full rationale
# behind each shape -- summarized here, not re-derived):
#   * backend-reload-inflight/driver.sh -- the drip-held-request + INFLIGHT_PID
#     + backend "send" journal ordering oracle + bounded-deadline join (kills
#     the client subtree via pkill -P then kill, never an unbounded wait) +
#     exactly-once-upstream oracle. This driver reuses that structure verbatim
#     for the held-request lifecycle; only the reload step becomes a LOOP.
#   * reload-soak/driver.sh -- the N-reload loop shape (prober_signal_wait HUP
#     in a for loop + prober_drain_wait each iteration + cycle-pool drift
#     oracle + master-fd oracle + no-signal-death check), here with RELOADS=10
#     instead of 100 (a storm needs to prove the held request survives EVERY
#     one of several closely-spaced reloads, not to stress a leak over a long
#     series -- ten is enough to make "no request dies, no state drifts" an
#     unambiguous multi-signal claim without the wall-clock cost of a hundred).
#   * usr2-mid-transfer/driver.sh -- the anti-vacuity gate shape (see below).
#
# THE ANTI-VACUITY GATE (the whole point of this scenario, read this before
# touching oracle 3): "the request survived a HUP storm" is only a true claim
# if the request was PROVABLY STILL OPEN throughout the storm, not merely "a
# background client happened to be running at some point and later a complete
# body existed". A version of this driver that let the held request finish
# BEFORE the storm even started would still pass every other oracle (body
# intact, status 200, exactly-once upstream hit) while proving NOTHING about
# reload behavior under a mid-transfer request -- exactly the vacuous shape
# usr2-mid-transfer's ok 3 guards against for USR2. The discriminator here is
# the same: snapshot whether INFLIGHT_PID is still alive (kill -0) at the
# moment of the LAST HUP in the storm. The drip is sized (see ./backend) to
# comfortably outlast all ten HUP+drain round trips, so on any non-pathological
# host INFLIGHT_PID is alive at every check; if it is not, the ordering broke
# (or the driver was mutated into the vacuous shape) and the gate reds instead
# of silently certifying a storm that never actually overlapped the request.
#
# Why a driver and not a plain .rule file: same reason as every sibling here --
# the prober runs each case synchronously to completion, so it cannot hold one
# request open on the wire while ten signals land on the master between
# invocations. This driver keeps the held request open in a background shell,
# delivers the storm underneath it, and only then joins.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

# The prober needs the error-log path to satisfy the spanning case's
# no_error_log directive. run-scenario.sh exports this only for the rules
# branch, so a driver that runs the prober must export it itself.
export PROBER_ERROR_LOG="$ELOG"

RELOADS=10
WORKERS=1               # matches worker_processes in nginx.conf (drain target)

# FAILED accumulates every failing assertion this driver makes directly. The
# TAP consumer keys the scenario's verdict off the EXIT STATUS
# (test-scenarios.sh), not off parsing the inner plan, so a `not ok` that did
# not also raise FAILED (and therefore the exit status) would be a vacuous
# assertion that could never fail the suite. Every `not ok` branch below bumps
# it, and the final exit is nonzero if FAILED > 0 OR the prober leg went red.
FAILED=0

snapshot() {            # read one probe snapshot into SNAP_* globals
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
}

# TAP plan: eight prober-independent assertions the driver makes itself --
#  1 the held reply was provably dripping from the upstream before the storm
#    (ordering oracle, same shape as backend-reload-inflight's ok 1)
#  2 all 10 HUPs in the storm were absorbed
#  3 the held request was PROVABLY still in flight across the whole storm --
#    the anti-vacuity gate (see header)
#  4 worker cycle-pool counters flat across the 10-reload series (drain-gated
#    snapshots, reload-soak's leak oracle shape)
#  5 the held response completed intact (full seeded value, status 200)
#  6 the backend served the held get EXACTLY ONCE across all 10 reloads
#  7 no worker died by signal during the storm
#  8 the old worker set drained after the held request completed (no stuck
#    old worker masked by the new one serving the coherence leg)
#  9 post-storm coherence (prober leg, folded in as diagnostics)
echo "1..9"

# --- baseline: cycle-pool snapshot before the first HUP ---------------------
# Taken before the held request is even fired, same as reload-soak's baseline:
# the FIRST post-reload snapshot (not this one) becomes the reference value,
# so a one-off startup allocation not repeated per reload does not read as a
# leak in reverse (see reload-soak's header for why).
BASE_OK=1
if ! snapshot; then
    BASE_OK=0
    echo "# baseline probe did not answer before the storm; cycle-pool oracle (4) will SKIP"
fi

# --- fire the held request ---------------------------------------------------
# A raw HTTP/1.1 GET over /dev/tcp, captured to a file in a background
# subshell -- identical shape to backend-reload-inflight and usr2-mid-transfer.
# The request will still be receiving its dripped upstream reply when the
# first HUP fires, and (by construction of the drip pacing in ./backend) for
# every one of the nine that follow it too.
INFLIGHT="$PROBER_PREFIX/inflight.out"
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET /mc?key=slow HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
    # Ignore cat's exit status: a Connection: close response commonly ends in
    # an RST once the server has sent everything, and cat then exits non-zero
    # having already delivered a complete body (documented in
    # backend-reload-inflight and prober_probe_pid).
    cat <&3 2>/dev/null || true
) >"$INFLIGHT" 2>/dev/null &
INFLIGHT_PID=$!

# The storm must not start until the held reply has PROVABLY begun dripping --
# otherwise, on a loaded runner, the request could arrive at nginx AFTER the
# first HUP and still return a correct 200/body, certifying "a request spanned
# the storm" while none did (AUD-10, see backend-reload-inflight). The
# falsifiable ordering oracle is the backend JOURNAL: fakesrv writes a
# {"ev":"send",...} record the moment it puts the FIRST byte of the reply on
# the wire -- a strictly stronger event than {"ev":"cmd",...,"cmd":"get",...},
# which proves only that the get was RECEIVED, not that the multi-second drip
# has actually started.
#
# Fixed-step counted iterations, never a wall-clock diff (same discipline as
# prober_wait_listen): a loaded runner performs the same number of attempts.
SEND_SEEN=0
for ((i = 0; i < 100; i++)); do            # 100 * 50 ms = 5 s ceiling
    if [ -n "$PROBER_BACKEND_JOURNAL" ] \
       && grep -q '"ev":"send"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null; then
        SEND_SEEN=1
        break
    fi
    sleep 0.05
done
if [ "$SEND_SEEN" -eq 1 ]; then
    echo "ok 1 - the held reply was dripping from the upstream before the HUP storm"
else
    echo "not ok 1 - the upstream never started dripping its reply before the storm"
    echo "# backend journal recorded no send within 5 s; ordering precondition unmet"
    FAILED=$((FAILED + 1))
fi

# --- the storm: 10 HUPs underneath the held request --------------------------
# Each iteration: prober_signal_wait sends SIGHUP to the master and blocks
# until a DIFFERENT worker pid answers the probe (the reload absorbed).
#
# Deliberately NO prober_drain_wait inside this loop, unlike reload-soak: this
# scenario's whole point is that ONE worker keeps a connection open across
# EVERY reload in the series, so the old worker from cycle N-1 cannot exit
# (and drain) until the held response finishes -- which by construction does
# not happen until after the storm. Calling prober_drain_wait(want=1) inside
# the loop would therefore wait out its own timeout on every iteration (old +
# new worker both alive = 2 children, never 1), burning ~10 s x 10 for no
# signal -- confirmed by a local run before this comment was written. Instead,
# each new worker's cycle-pool counters are snapshotted right after
# prober_signal_wait confirms it is answering: this still proves the claim
# reload-soak's oracle 3 makes (repeated config loads produce identical
# cycle-pool state) -- it is simply proven from the ANSWERING side (each new
# worker's cycle pool) rather than the DRAINED side, because "drained" cannot
# be true here mid-storm. The one moment draining genuinely does happen -- once
# the held request finally completes -- is checked separately below, after the
# join, before the post-storm prober leg runs.
#
# The cycle-pool reference is set from the SECOND post-HUP snapshot (HUP 2),
# not the first. The first new worker forked mid-storm carries a one-off: on
# the self-hosted nginx 1.28.0 leg HUP 1 read cycle_used 3572 B ABOVE the flat
# HUPs 2..10 (which were byte-identical), the same first-fork warm-up the ASan
# note below independently observed ("first post-HUP snapshot 3569 bytes above
# the rest"). Pinning USED_REF to HUP 1 made all nine steady-state forks look
# like drift and reddened the oracle. HUP 1 is treated as warm-up; ref latches
# on HUP 2 and HUPs 3..10 are compared to it -- eight comparisons, so a genuine
# per-reload leak still drifts monotonically and is caught. Every subsequent
# snapshot is compared to it with drift_if. This oracle is OPTIONAL per the task
# spec if it overcomplicated the held-request logic -- it did not: it composes
# cleanly as long as it never touches or joins INFLIGHT_PID, so it is included.
ABSORBED=0
USED_REF=; BLOCKS_REF=; LARGE_REF=
FIRST_SET=0
DRIFT=""
# INFLIGHT_ALIVE_ALL_HUPS starts optimistic (1) and is only ever cleared to 0.
# This mirrors usr2-mid-transfer's INFLIGHT_ALIVE_AT_USR2 pattern but checked
# at EVERY HUP in the loop, not just once -- the storm's claim is "in flight
# across the WHOLE series", so a single miss anywhere in the ten must sink it.
INFLIGHT_ALIVE_ALL_HUPS=1

for ((r = 1; r <= RELOADS; r++)); do
    if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" 5000; then
        ABSORBED=$((ABSORBED + 1))
    else
        echo "# HUP $r of $RELOADS was not absorbed within 5 s (no new worker answered)"
        DRIFT="$DRIFT
HUP $r: no-new-worker"
    fi

    # The anti-vacuity check for THIS HUP: was the held client still alive
    # (i.e. still blocked reading its drip, not yet joined) at the moment this
    # reload landed? Checked immediately after prober_signal_wait returns --
    # the earliest point at which "this HUP has landed" is provably true --
    # rather than at the top of the next iteration, which would let an
    # already-finished request slip through undetected for up to one more
    # signal_wait's worth of time.
    if ! kill -0 "$INFLIGHT_PID" 2>/dev/null; then
        INFLIGHT_ALIVE_ALL_HUPS=0
        echo "# held request was NOT alive immediately after HUP $r (drip finished too early, or ordering broke)"
    fi

    if [ "$BASE_OK" -eq 1 ]; then
        if [ "$r" -eq 1 ]; then
            # HUP 1 is warm-up: the first mid-storm fork carries a one-off that
            # is not a leak (see header). Take no snapshot as the reference.
            :
        elif ! snapshot; then
            echo "# HUP $r: the probe endpoint did not answer for a cycle-pool snapshot"
            DRIFT="$DRIFT
HUP $r: no-snapshot"
        elif [ "$FIRST_SET" -eq 0 ]; then
            USED_REF="$SNAP_USED"; BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
            FIRST_SET=1
        else
            drift_if() {   # NAME GOT WANT
                [ "$2" = "$3" ] && return 0
                DRIFT="$DRIFT
HUP $r: $1 = $2, want $3"
            }
            drift_if cycle_used   "$SNAP_USED"   "$USED_REF"
            drift_if cycle_blocks "$SNAP_BLOCKS" "$BLOCKS_REF"
            drift_if cycle_large  "$SNAP_LARGE"  "$LARGE_REF"
        fi
    fi
done

# --- 2: all 10 HUPs landed ---------------------------------------------------
if [ "$ABSORBED" -eq "$RELOADS" ]; then
    echo "ok 2 - all $RELOADS HUPs in the storm were absorbed"
else
    echo "not ok 2 - only $ABSORBED of $RELOADS HUPs were absorbed"
    FAILED=$((FAILED + 1))
fi

# --- 3: THE ANTI-VACUITY GATE -------------------------------------------------
# The held request must have been provably still in flight at EVERY HUP in the
# storm, not merely "at some point during the run". Gated additionally on
# GET_CMDS==1 checked later would be redundant here (that is oracle 6's job);
# this oracle is purely about liveness overlap, the discriminator that makes
# oracle 5 ("body arrived intact") mean "survived the storm" rather than
# "finished at some unspecified time and a storm also happened somewhere".
if [ "$INFLIGHT_ALIVE_ALL_HUPS" -eq 1 ]; then
    echo "ok 3 - the held request was provably still in flight across all $RELOADS HUPs"
else
    echo "not ok 3 - the held request was not alive at every HUP; the storm did not genuinely overlap it"
    FAILED=$((FAILED + 1))
fi

# --- 4: worker cycle-pool counters flat across the storm --------------------
#
# EXACT-equal cycle_used/blocks/large across every new worker in the storm is a
# PLAIN-build invariant only. Under ASan each new worker is forked while the old
# cycle is still held alive by the inflight request (this scenario cannot drain
# mid-storm), and the sanitizer's quarantine + shadow accounting make each
# fork's cycle-pool figure vary run to run -- the CI san leg read the first
# post-HUP snapshot 3569 bytes above the rest, a per-fork ASan artifact, not a
# leak. So skip this oracle on sanitized builds, same as reload-cycle skips its
# master-RSS band for the same reason; the non-san legs still assert it for real.
if [ "${PROBER_SANITIZED:-0}" -eq 1 ]; then
    echo "ok 4 - worker cycle-pool counters # SKIP sanitized build: per-fork quarantine/shadow state perturbs the cycle pool"
elif [ "$BASE_OK" -eq 0 ]; then
    echo "ok 4 - worker cycle-pool counters # SKIP baseline probe did not answer"
elif [ -z "$DRIFT" ] && [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 4 - worker cycle-pool counters identical across all $RELOADS HUPs"
    echo "# cycle_used=$USED_REF cycle_blocks=$BLOCKS_REF cycle_large=$LARGE_REF"
else
    echo "not ok 4 - worker state drifted across the storm (per-cycle leak, or a HUP/snapshot failed)"
    printf '%s\n' "$DRIFT" | sed '/^$/d; s/^/# /'
    FAILED=$((FAILED + 1))
fi

# DRC captures whether the post-join drain actually completed; asserted as
# oracle 8 below (a stuck old worker must red the scenario -- see there).
DRC=0
# --- join the held request ---------------------------------------------------
# It must have completed by now -- the storm is over. A bare `wait` on a hung
# request would never reach the body check below (AUD-09, see
# backend-reload-inflight): if some HUP dropped the request and the upstream
# never closes, the background client blocks forever and so does this driver,
# consuming the whole CI job instead of reporting a bounded failure. Poll for
# the background shell to exit within a deadline; if it overruns, KILL the
# whole subtree (pkill -P first, then kill) and fall through -- the
# truncated/empty $INFLIGHT then fails the assertion below, the correct
# verdict for a request that never completed.
# A longer ceiling than backend-reload-inflight's 10 s: the drip here is sized
# to outlast the WHOLE storm (~26 s at 172 B @ 2 B/300 ms, see ./backend), so
# on a fast box the join may still need to wait out most of that after the
# last HUP lands. 40 s is comfortably above the drip's own ceiling while still
# being a bounded, killed deadline rather than an unbounded wait.
join_deadline=$(( SECONDS + 40 ))
while kill -0 "$INFLIGHT_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        # Kill the whole subtree, not just the subshell. The background job is
        # `( ... cat <&3 ) &`, and `cat` is a CHILD of that subshell blocked on
        # the socket read; killing only $INFLIGHT_PID would orphan the cat,
        # which keeps the fd open and can go on writing to $INFLIGHT. Reap the
        # children first (job control is off in a script, so there is no
        # process group to signal), then the subshell.
        pkill -P "$INFLIGHT_PID" 2>/dev/null || true
        kill "$INFLIGHT_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$INFLIGHT_PID" 2>/dev/null || true

# Now that the held request has finished, the LAST cycle's old worker is free
# to actually exit -- this is the one point in the whole driver where
# prober_drain_wait(want=$WORKERS) can genuinely succeed rather than time out
# against a connection that is deliberately still open (see the storm-loop
# comment above). This IS a numbered oracle (8): a `|| true` here would let the
# scenario pass while an old worker stayed stuck after the held request ended,
# because the post-storm strict probe (oracle 9) can be served entirely by the
# NEW worker and never observe the leftover old one -- exactly the masking
# CodeRabbit flagged. A real drain timeout (return 1) reds the scenario; a host
# that simply cannot observe the child set (no pgrep, return 2) is a VISIBLE
# skip, never a failure -- the same return-2 discipline reload-soak uses.
prober_drain_wait "$MASTER" "$WORKERS" 10000 || DRC=$?

# --- 5: held response completed intact ---------------------------------------
# The response must be a complete, correct 200 carrying the full seeded value.
# A storm that dropped the held request anywhere along its ten HUPs would
# leave a truncated body, a 502, or an empty file -- each of which fails this
# single check. head BEFORE sed in the diagnostic pipeline: under `pipefail` a
# `sed ... | head -20` would return 141 when sed is SIGPIPEd by head closing
# the pipe early on a long INFLIGHT file, which `set -e` turns into an abort
# on exactly the failure path this diagnostic exists for (the 3 CodeRabbit
# findings on G6d were this exact class -- see repo discipline notes).
if grep -q '^HTTP/1.1 200' "$INFLIGHT" \
   && grep -q 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffffgggg' "$INFLIGHT"; then
    echo "ok 5 - the held response completed intact across the entire 10-HUP storm"
else
    echo "not ok 5 - the held response was dropped or truncated somewhere in the storm"
    head -20 "$INFLIGHT" | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 6: the held request hit the upstream exactly once -----------------------
# Counted BEFORE the post-storm prober leg runs (that leg issues its own get,
# which would inflate the tally). If any HUP in the storm had dropped the held
# request and nginx re-issued it upstream -- or retried it after a later
# worker came up -- the backend journal would carry a SECOND {"ev":"cmd",...,
# "cmd":"get",...}. Exactly one proves the single client request crossed all
# ten reloads as one upstream exchange, never re-issued. A zero here is
# impossible once ok 1 passed (it required a send, which requires a received
# get); the guard is against >1.
GET_CMDS=0
if [ -n "$PROBER_BACKEND_JOURNAL" ]; then
    GET_CMDS=$(grep -c '"ev":"cmd"[^}]*"cmd":"get"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null || true)
fi
if [ "$GET_CMDS" -eq 1 ]; then
    echo "ok 6 - the backend served the held get exactly once across all $RELOADS HUPs"
else
    echo "not ok 6 - the backend saw the held get $GET_CMDS times (expected 1: re-issued during the storm?)"
    FAILED=$((FAILED + 1))
fi

# --- 7: no worker died by signal during the storm -----------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit path
# is asserted separately here: a clean reload logs the old worker leaving via
# "gracefully shutting down" / "exiting", never a signal-death line, across
# every one of the ten cycles.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 7 - a worker died by signal during the storm"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 7 - no worker died by signal across the whole storm"
fi

# --- 8: the old worker set drained after the held request completed ----------
# A real drain timeout (return 1) means an old-cycle worker is still stuck after
# the held request ended -- a leaked/hung worker, which the strict coherence leg
# (oracle 9) cannot see because the NEW worker answers it. return 2 = no pgrep on
# this host: a visible SKIP, never a failure (same exemption reload-soak makes).
if [ "$DRC" -eq 0 ]; then
    echo "ok 8 - the old worker set drained to $WORKERS after the held request completed"
elif [ "$DRC" -eq 2 ]; then
    echo "ok 8 - old-worker drain # SKIP pgrep unavailable; cannot observe the child set on this host"
else
    echo "not ok 8 - an old worker never drained after the held request ended (stuck/leaked worker)"
    FAILED=$((FAILED + 1))
fi

# --- 9: post-storm coherence (prober, folded in as diagnostics) --------------
# Runs a plain strict case AFTER the tenth reload has been absorbed and
# drained: the final worker serves a correct 200, leaks no descriptor, and
# logs nothing on the error path in the window around the request. The pid
# oracle here is STRICT on purpose -- by the time this runs a single
# post-storm worker is answering, so both of the case's probe snapshots see
# that same worker and "same worker pid" is the correct, stronger assertion
# (same rationale as backend-reload-inflight's post-reload.rule).
STATUS=0
# PIPESTATUS, not $?: a bare `./prober | sed` would have $? report sed's exit,
# which is always 0, silently discarding a red prober leg -- the exact
# vacuous shape this driver guards against elsewhere.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

# The scenario is red if ANY driver assertion failed OR the prober leg did.
if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
