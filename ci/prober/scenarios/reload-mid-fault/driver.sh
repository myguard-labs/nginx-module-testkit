#!/usr/bin/env bash
#
# Scenario: reload-mid-fault (A-2, "fault injection during a lifecycle
# event" from README's Ideas and opportunities list). A client request is
# in flight against the fake memcached upstream, that upstream drips its
# reply slowly enough to trip nginx's OWN memcached_read_timeout mid-transfer
# -- a real upstream FAULT, not a slow-but-clean transfer -- and a SIGHUP
# reload is delivered while that read-timeout error path is running. This
# attacks the intersection the sibling reload-* scenarios do not: every one
# of them (backend-reload-inflight, hup-storm-mid-transfer,
# reload-compressing) proves a CLEAN in-flight request survives a reload.
# None puts the reload on top of a request that is ALREADY failing upstream,
# which is exactly where an unbalanced allocation or a leaked upstream
# descriptor becomes visible: ngx_http_upstream_finalize_request's
# error/cleanup branch and the reload's own worker-drain teardown are now
# running concurrently on the same worker, instead of at two separate idle
# moments the way fault-matrix (fault, no reload) and reload-cycle/reload-soak
# (reload, no fault) each test in isolation.
#
# WHY THE PROBE AND NOT nginx.pm / t/*.t (repo rule -- justify vs the Perl
# suite before adding a probe scenario, see README + AGENTS.md). Every fault
# and every reload here could be thrown at a plain Test::Nginx suite too, and
# the STATUS/body it produces is not the point: a worker that leaks the
# upstream fd or a cycle-pool block specifically on the "reload landed while
# the read-timeout cleanup was running" branch still returns a plausible
# 502/504 to the client and a plausible "worker process ... exiting" to the
# log -- nothing in a .t file's assertion surface (response status, body,
# headers, log grep) can tell that apart from a worker that cleaned up
# correctly. The unique oracle is the in-worker fd count and cycle-pool
# footprint read from the probe AFTER both the fault's cleanup and the
# reload's drain have completed, which only this harness supplies (the same
# "allocator/cleanup/lifetime -> probe delta/baseline" argument
# fault-matrix's own driver makes for its half of this combination).
#
# WHY A FAKESRV UPSTREAM FAULT AND NOT fault_slab=/fault_palloc=/
# fault_tempfile=/fault_accept= (established repo constraint, do not
# re-litigate): those arm via ngx_test_probe_arm(), which needs the ref
# module to register a fault_set hook, and it deliberately does not (see
# fault-matrix's own header for the same reasoning). This scenario needs no
# module hook at all -- the fault lives entirely in the fake memcached
# upstream fakesrv already runs on stock ref-probe CI legs, so it exercises
# nginx's OWN ngx_http_upstream cleanup under reload, the same consumer
# fault-matrix targets, just with a reload now landing inside that window
# instead of at an idle moment.
#
# THE UPSTREAM FAULT: drip, not rst/truncate/lie_bytes. ./backend drips the
# reply 4 bytes every 400 ms; ./nginx.conf pins memcached_read_timeout to
# 150 ms. Because memcached_read_timeout applies BETWEEN successive reads,
# not to the whole response (ngx_http_memcached_module docs -- same citation
# fault-matrix's nginx.conf uses), a 400 ms inter-chunk gap deterministically
# exceeds the 150 ms budget and nginx's own upstream read times out --
# ngx_http_upstream_finalize_request's read-timeout error branch, a genuine
# upstream failure, not a slow-but-successful transfer. rst/truncate/
# lie_bytes were considered and rejected: fakesrv's fault vocabulary applies
# exactly one action per get and none of rst, truncate, close_after or
# lie_bytes can be dripped (each sends its (possibly-doctored) reply in one
# shot -- see fakesrv.c apply_fault()), so none of them can hold a request
# open long enough to genuinely straddle a SIGHUP the way this scenario
# needs; only drip paces bytes over time, and pacing it past the read
# timeout is what turns "in flight" into "in flight AND failing" without
# needing a second fault primitive.
#
# WHY A FIXED, ORDINAL-KEYED INJECTION (no timers, no random, for fault
# SELECTION). ./backend arms the fault at `on=get:2`, not get:1: get ordinal 1
# is a single, fixed, clean warmup GET this driver issues BEFORE the held
# request (see the warmup block below -- reused from post-reload.rule's own
# "clean"-keyed case, settling the worker into its steady post-first-request
# state before the resource-neutrality baseline is taken). The held, faulted
# request is therefore always and only get ordinal 2, so which fault fires
# never depends on timing or a random draw, only on the fixed get sequence
# this driver issues (the fault-matrix discipline: WARMUP + row index, here a
# single row). The read-timeout itself is necessarily time-based (that is the thing
# under test -- a real network fault race), but the injection POINT is not:
# 400 ms vs a 150 ms budget is a fixed 2.7x margin, generous enough that no
# non-pathological host blurs the cross, and it is the same fixed pair on
# every run regardless of machine speed.
#
# Structure adapted from backend-reload-inflight/driver.sh (held drip request
# + ordering oracle via the backend "send" journal event + bounded,
# subtree-killing join + post-reload coherence leg) and hup-storm-mid-transfer
# (in-flight liveness gate at signal time). Read those headers for the shapes
# reused verbatim; only the fault-outcome oracles (2, 4) are new here and
# documented at their own sites below.
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
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
}

# TAP plan: six prober-independent assertions the driver makes itself, plus
# the post-reload coherence leg folded in as diagnostics --
#  1 the faulted reply was provably dripping from the upstream, and the held
#    client was still open, before the reload landed (ordering + anti-vacuity
#    gate, the same shape as every held-request sibling)
#  2 the held request genuinely FAILED (did not complete as a plain 200) --
#    proves the read-timeout branch actually ran, not merely that a slow
#    request happened to also survive a reload
#  3 the reload was absorbed while that failing request was in flight
#  4 the new (post-reload) worker's fds and cycle pool are allocation-neutral
#    across an extra clean request, taken after the fault's own cleanup and
#    the reload's drain have both completed -- the harness-owned resource-
#    neutrality oracle, fault-matrix's technique (deterministic cycle_used,
#    ceiling fds) applied on top of a reload instead of at an idle moment
#  5 no worker died by signal across the whole window
#  6 the upstream saw the held get exactly once (the timeout was not retried
#    as a fresh upstream connection attempt)
#  7 post-reload coherence (prober leg, folded in as diagnostics): the
#    reloaded worker serves a CLEAN request afterwards
echo "1..7"

# --- warmup: one clean, unfaulted GET against the SAME /mc upstream path ---
# Gated by backend-smoke's own discipline (an adversarially-timed reply proves
# nothing unless the same path is first proven correct when told to behave
# normally). This ALSO fixes the get ordinal the fault fires on: ./backend
# arms its drip at `on=get:2`, so this warmup GET (get ordinal 1) must run
# BEFORE the held request or the fault would fire on the wrong get -- see
# ./backend's own ordinal-accounting comment. Reuses post-reload.rule verbatim
# (same "clean"-keyed GET the post-reload leg runs later) rather than a second
# near-duplicate rule file. Its outcome is not itself asserted here: a failure
# would already be surfaced downstream (a faulted GET ordinal would make
# oracle 2 read a clean 200 where a fault was expected, or oracle 6's exactly-
# once count would come up short), so this call only needs to have RUN.
if ! ./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" \
     >/dev/null 2>&1
then
    echo "# warmup GET did not complete cleanly; proceeding -- a resulting ordinal drift would surface downstream"
fi

# --- fire the held, faulted request -----------------------------------------
# A raw HTTP/1.1 GET over /dev/tcp, captured to a file in a background
# subshell -- identical shape to every held-request sibling. The request will
# still be blocked mid-transfer, waiting out nginx's own read timeout, when
# the HUP fires.
INFLIGHT="$PROBER_PREFIX/inflight.out"
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET /mc?key=slow HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
    # Ignore cat's exit status: however this connection ends (a clean FIN, an
    # RST, or nginx's own error response followed by a close), cat may exit
    # non-zero having already delivered everything there was to deliver.
    cat <&3 2>/dev/null || true
) >"$INFLIGHT" 2>/dev/null &
INFLIGHT_PID=$!

# --- 1: ordering + anti-vacuity gate -----------------------------------------
# The HUP must not be sent until the request has PROVABLY reached the
# upstream and started dripping -- otherwise, on a loaded runner, the request
# could arrive at nginx AFTER the reload and this scenario would prove
# nothing about a reload landing during a fault. The falsifiable ordering
# oracle is the backend JOURNAL: fakesrv writes {"ev":"send",...} the moment
# it puts the FIRST byte of the reply on the wire -- strictly stronger than
# {"ev":"cmd",...}, which proves only that the get was RECEIVED (AUD-10,
# documented in every held-request sibling). Fixed-step counted iterations,
# never a wall-clock diff, so a loaded runner performs the same number of
# attempts (prober_wait_listen's discipline).
SEND_SEEN=0
for ((i = 0; i < 100; i++)); do            # 100 * 50 ms = 5 s ceiling
    if [ -n "$PROBER_BACKEND_JOURNAL" ] \
       && grep -q '"ev":"send"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null; then
        SEND_SEEN=1
        break
    fi
    sleep 0.05
done
INFLIGHT_ALIVE=0
if kill -0 "$INFLIGHT_PID" 2>/dev/null; then
    INFLIGHT_ALIVE=1
fi
if [ "$SEND_SEEN" -eq 1 ] && [ "$INFLIGHT_ALIVE" -eq 1 ]; then
    echo "ok 1 - the faulted reply was dripping AND the held request was still open at reload time"
elif [ "$SEND_SEEN" -ne 1 ]; then
    echo "not ok 1 - the upstream never started dripping its reply before the reload"
    echo "# backend journal recorded no send within 5 s; ordering precondition unmet"
    FAILED=$((FAILED + 1))
else
    echo "not ok 1 - the held request had already completed before the reload was sent"
    echo "# the background client exited before the HUP: nothing straddled the signal"
    FAILED=$((FAILED + 1))
fi

# --- reload underneath the ALREADY-FAILING request ---------------------------
# prober_signal_wait sends SIGHUP to the master and blocks until a DIFFERENT
# worker pid answers the probe -- i.e. the reload has been fully absorbed --
# or times out. 150 ms read timeout + 400 ms drip means the upstream read
# times out well before this call returns; the reload therefore lands with
# the fault's own cleanup already in progress or freshly finished on the old
# worker, not before it started.
if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" 5000; then
    echo "ok 3 - the reload was absorbed while the faulted request was failing upstream"
else
    echo "not ok 3 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- join the held request (bounded, subtree-killing deadline) -------------
# A bare `wait` on a hung request would consume the whole CI job if something
# wedged (AUD-09, every held-request sibling); poll for the background shell
# to exit within a deadline, and on overrun KILL the whole subtree (pkill -P
# then kill, never an unbounded wait) so a genuinely stuck connection reds
# oracle 2 rather than hanging the run. 150 ms timeout means nginx itself
# closes this out in well under a second; 10 s is generous headroom.
join_deadline=$(( SECONDS + 10 ))
while kill -0 "$INFLIGHT_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        pkill -P "$INFLIGHT_PID" 2>/dev/null || true
        kill "$INFLIGHT_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$INFLIGHT_PID" 2>/dev/null || true

# --- 2: the held request genuinely FAILED, proving the fault fired ---------
# THE oracle that distinguishes this scenario from every clean-in-flight
# sibling. If the read-timeout branch never actually ran -- e.g. the drip
# pacing regressed to something faster than the read timeout, or the fault
# was silently dropped -- the held request would complete as an ordinary
# 200 with the full seeded value, exactly like backend-reload-inflight's
# oracle 3 asserts as SUCCESS. Here the opposite is required: the response
# must NOT be a complete 200 carrying the full "slow" value. nginx's memcached
# module reports an upstream read timeout as a 504 (Gateway Time-out) in the
# common case; the assertion is deliberately phrased as "NOT the clean 200"
# rather than "IS exactly 504", because the precise status a given nginx/angie
# build renders for this internal error is not the load-bearing claim -- the
# load-bearing claim is that the fault fired and the request did not silently
# succeed. A version of this driver that let the fault regress to a no-op
# would still pass every OTHER oracle (reload absorbed, resource-neutral,
# no worker died) while proving nothing about a fault firing during reload --
# this is the anti-vacuity check for THAT failure mode, the same role
# fault-matrix's fault-fired journal poll plays for its own matrix.
FULL_VALUE='0123456789abcdefghijklmnopqrstuvwxyzABCD'
FAULT_FIRED=0
if ! { grep -q '^HTTP/1.1 200' "$INFLIGHT" && grep -q "$FULL_VALUE" "$INFLIGHT"; }; then
    FAULT_FIRED=1
fi
if [ "$FAULT_FIRED" -eq 1 ]; then
    echo "ok 2 - the held request did not complete as a clean 200 (the read-timeout fault fired)"
else
    echo "not ok 2 - the held request completed as an ordinary clean 200; the fault never fired"
    sed 's/^/# /' "$INFLIGHT" | head -20
    FAILED=$((FAILED + 1))
fi

# --- 4: resource neutrality after fault-cleanup + reload-drain overlap -----
# NOTE: this oracle deliberately does NOT compare against the pre-fault
# baseline taken on the OLD worker. Measured directly against this scenario:
# the NEW (post-reload) worker's first post-drain cycle_used reading is
# reproducibly ~3.5 KB LOWER than the old worker's post-warmup baseline
# (80968 vs 77393 B, byte-identical across repeat runs) -- the same
# "first post-HUP fork carries a one-off" artifact hup-storm-mid-transfer's
# own header documents (there: 3569-3572 B above the steady state; here,
# below it -- same magnitude, opposite sign, because the comparison point
# differs). A cross-worker compare would either have to band around that
# artifact (weakening the oracle for no gain, reload-compressing's own
# rejected shape) or misread a real per-fork constant as a leak. So instead
# this follows reload-compressing's oracle 4 exactly: prove allocation
# NEUTRALITY on the NEW worker's own steady state, via two QUIESCENT
# post-drain snapshots taken around one extra full clean request, rather than
# a baseline captured on a different worker entirely. Equal readings mean the
# read-timeout's cleanup path, having already run once on this new worker
# (the fault-matrix technique: cycle_used is deterministic across faulted
# requests), left it allocation-neutral for a SUBSEQUENT request too -- a
# leaked cycle-pool block or upstream descriptor from the fault+reload overlap
# would instead make the second reading strictly exceed the first.
prober_drain_wait "$MASTER" 1 10000 >/dev/null 2>&1 || true
if ! snapshot; then
    echo "not ok 4 - the probe endpoint did not answer for the first post-reload resource snapshot"
    FAILED=$((FAILED + 1))
else
    FIRST_FDS="$SNAP_FDS"; FIRST_USED="$SNAP_USED"
    FIRST_BLOCKS="$SNAP_BLOCKS"; FIRST_LARGE="$SNAP_LARGE"
    # The stimulus MUST run, and its failure MUST be fatal to oracle 4. Two
    # snapshots taken without a request between them are trivially identical,
    # so a warn-and-continue here would report "allocation-neutral" having
    # measured nothing -- the vacuous-green shape this suite deletes scenarios
    # for. (It also hid a bug: `./prober` resolved against the scenario dir,
    # not the prober dir, so the stimulus silently failed on every run.)
    STIM_OK=1
    if ! ./prober -H "$HOST" -p "$PORT" \
         "$PROBER_SCENARIO/post-reload.rule" >/dev/null 2>&1
    then
        STIM_OK=0
    fi
    if [ "$STIM_OK" -eq 0 ]; then
        echo "not ok 4 - the oracle-4 stimulus request did not complete, so the two snapshots bracket no request and prove nothing"
        FAILED=$((FAILED + 1))
    elif ! snapshot; then
        echo "not ok 4 - the probe endpoint did not answer for the second post-reload resource snapshot"
        FAILED=$((FAILED + 1))
    elif [ "$SNAP_FDS" -le "$FIRST_FDS" ] \
      && [ "$SNAP_USED" = "$FIRST_USED" ] \
      && [ "$SNAP_BLOCKS" = "$FIRST_BLOCKS" ] \
      && [ "$SNAP_LARGE" = "$FIRST_LARGE" ]; then
        # fds is a CEILING, not exact-equal, for the same reason fault-matrix's
        # own fds oracle is a ceiling: a parked keepalive connection legitimately
        # oscillates the count by one without being a leak (a leaked descriptor
        # climbs PAST the first reading, a parked keepalive fd never does).
        # cycle_used/blocks/large stay exact: deterministic across a settled
        # worker serving one more clean request.
        echo "ok 4 - the new worker's request path was allocation-neutral after the fault+reload overlap"
        echo "# first reading  fds=$FIRST_FDS used=$FIRST_USED blocks=$FIRST_BLOCKS large=$FIRST_LARGE"
        echo "# second reading fds=$SNAP_FDS used=$SNAP_USED blocks=$SNAP_BLOCKS large=$SNAP_LARGE"
    else
        echo "not ok 4 - the new worker's resource state grew after an extra request (leak on the fault+reload overlap path)"
        echo "# first reading  fds=$FIRST_FDS used=$FIRST_USED blocks=$FIRST_BLOCKS large=$FIRST_LARGE"
        echo "# second reading fds=$SNAP_FDS used=$SNAP_USED blocks=$SNAP_BLOCKS large=$SNAP_LARGE"
        FAILED=$((FAILED + 1))
    fi
fi

# --- 5: no worker died by signal ---------------------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit path
# is asserted separately: a clean reload logs the old worker leaving via
# "gracefully shutting down" / "exiting", never a signal-death line, even
# though this run's error log DOES legitimately carry the read-timeout's own
# [error] line (that is the fault firing correctly, not a crash).
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the fault+reload overlap"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the fault+reload overlap"
fi

# --- 6: the held request hit the upstream exactly once -----------------------
# Counted BEFORE the post-reload prober leg runs (that leg issues its own get
# under a different key, "clean", captured by a LATER prober invocation, so it
# cannot inflate this tally). More than one "get" for the "slow" key would
# mean nginx retried the timed-out upstream connection as a fresh attempt
# rather than finalizing the request with an error -- a different bug class
# than the resource-neutrality oracle catches, so it gets its own check. The
# fakesrv journal's "cmd" event carries the key inside "args":["slow"], not a
# "key" field (see fakesrv.c's cmd-journal block), so the match is against
# the args array, not a nonexistent key field.
GET_CMDS=0
if [ -n "$PROBER_BACKEND_JOURNAL" ]; then
    GET_CMDS=$(grep -c '"ev":"cmd","conn":[0-9]*,"n":[0-9]*,"cmd":"get","args":\["slow"\]' "$PROBER_BACKEND_JOURNAL" 2>/dev/null || true)
fi
if [ "$GET_CMDS" -eq 1 ]; then
    echo "ok 6 - the backend saw the held get exactly once (timeout finalized, not retried)"
else
    echo "not ok 6 - the backend saw the held get $GET_CMDS times (expected 1: retried after the timeout?)"
    FAILED=$((FAILED + 1))
fi

# --- 7: post-reload coherence (prober, folded in as diagnostics) ------------
# A plain strict case AFTER the reload has been absorbed and the fault's
# cleanup has finished: the reloaded worker serves a CLEAN (unfaulted, "clean"
# key) request correctly, leaks no descriptor, and logs nothing NEW on the
# error path in this case's own window (no_error_log is scoped to a log mark
# taken at the start of THIS case, so the read-timeout's own earlier [error]
# line does not retroactively fail it -- see prober.c error_log_mark()). The
# pid oracle is STRICT: a single post-reload worker is answering by now, so
# both of the case's probe snapshots see the same worker.
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
