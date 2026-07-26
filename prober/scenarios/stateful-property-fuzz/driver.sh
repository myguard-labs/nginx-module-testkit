#!/usr/bin/env bash
#
# Scenario: stateful-property-fuzz (P2-G5) -- the STATEFUL descendant of
# scenarios/property-fuzz. property-fuzz draws a fixed batch of independent
# REQUEST SHAPES and throws each at a fresh connection; this scenario draws a
# fixed SEQUENCE OF STATEFUL STEPS -- connection reuse (keepalive/pipeline),
# partial writes and half-close, upstream faults, AND server-lifecycle events
# (SIGHUP reload, USR2-less* worker death) -- and after each lifecycle event
# asserts that the worker's LINEAGE, the error log, the cycle-pool/fd footprint
# and the config-generation all stayed coherent. It is the model P2-G6/G7/H
# trust for "a sequence of adversarial events left the worker settled".
#
#   * USR2 binary-upgrade is deliberately NOT in the step alphabet here: it
#     requires the PROBER_DAEMON_MODE=on boot contract (see
#     backend-usr2-keepalive), which is incompatible with the mandatory
#     `daemon off;` this scenario boots under (index.md "daemon off" durable
#     fact). USR2 across-exec state is owned by usr2-mid-transfer /
#     backend-usr2-keepalive / usr2-state-machine; this scenario owns the
#     reload + worker-death half of the lifecycle alphabet, which is what the
#     default boot contract can drive soundly. G7 (trigger-gated worker fuzz)
#     is where a master_process-off discovery target would extend the alphabet;
#     this one stays inside what the ordinary harness boot can replay.
#
# WHY A DRIVER AND NOT A .RULE FILE. The lifecycle steps (HUP, kill) happen
# BETWEEN prober invocations, and the state that matters -- did the master ride
# the event out, did the cycle pool settle, is the answering worker running the
# config we last loaded -- is a comparison of probe snapshots taken on either
# side of a signal that no single prober case can straddle. Same rationale as
# reload-cycle / reload-soak / worker-death.
#
# THE STEP ALPHABET (gen_stream draws one per step, in a fixed field order so
# the stream a seed produces never depends on earlier steps' outcomes):
#
#   REQUEST steps (the majority) run as a generated .rule BATCH -- a contiguous
#   run of request steps between two lifecycle events is rendered into ONE rule
#   file and run by the stock prober, so the request half reuses property-fuzz's
#   proven generator wholesale. A request step is one of:
#     direct-single   one corpus fragment on its own close-connection
#     direct-pipeline TWO corpus fragments down ONE keepalive connection
#                     (the `block` DSL, keepalive-bleed's proven shape), so the
#                     request-reuse / no-response-bleed path is exercised
#     backend         GET /mc?key=kN -> fakesrv memcached fault (upstream
#                     teardown path, property-fuzz's backend leg)
#     abort           a direct-single that `abort`s mid-request (client RST)
#     halfclose       a direct-single that `shutdown 1`s after sending in full
#   Every request step, whatever its kind, carries the stock leak oracle
#   (`delta fds == 0`, `delta pool.cycle_used == 0`) and the DEFAULT worker-alive
#   oracle -- identical to property-fuzz. Pipeline blocks that must survive to a
#   Connection: close ending carry it on the closing block.
#
#   LIFECYCLE steps (drawn rarely -- see LIFECYCLE_EVERY) end the current batch,
#   run it, then fire the event and run the CHECKPOINT oracles below:
#     reload   SIGHUP; a marker in the rendered conf is NOT changed (the ref
#              conf has no reloadable marker location -- the ref module owns no
#              zone, lessons.md), so the coherence claim here is "generation
#              advanced AND the same master's worker answers the SAME cycle-pool
#              footprint", not "the new config's behaviour changed". A config
#              CHANGE across reload is reload-config-version's job; this scenario
#              asserts the reload was ABSORBED without lineage/resource drift.
#     kill     SIGKILL the serving worker; the master must respawn it (contained
#              death), exactly worker-death's oracle set, folded in as a step.
#
# THE CHECKPOINT ORACLES (run after every lifecycle step, and once at the end):
#   C1 lineage: the answering worker is still a child of the ORIGINAL master
#      (ppid == BASE_PPID). A master that died would move ppid or stop answering.
#   C2 no forbidden death: no worker exited on a FAULT signal (SEGV/ABRT/BUS)
#      and no signal-9 death BEYOND the kills this run intentionally sent. The
#      expected signal-9 count is tracked in EXPECT_SIG9 and compared exactly --
#      a kill we did not send, or a cascade, reds.
#   C3 fd/pool settlement: after the cycle has drained to one worker, the
#      cycle-pool footprint (cycle_used/blocks/large) equals the batch's settled
#      baseline. A leak into the long-lived cycle pool across a reload/respawn
#      moves it. (fds is a per-worker count that legitimately shifts across a
#      respawn's transient handover channels -- lessons.md reload-cycle -- so it
#      is NOT pinned absolute here; the request-level `delta fds == 0` in every
#      batch is the fd oracle.)
#   C4 generation coherence: after a reload, config_generation is STRICTLY
#      GREATER than before it AND settled (prober_config_wait streak) -- the
#      reload was actually absorbed, not rejected-and-old-cycle-kept (the
#      config-vacuity class, lessons.md). After a kill (no reparse) generation
#      must be UNCHANGED -- a respawn that bumped it would mean the master
#      reloaded when we only killed a worker.
#   C5 zone coherence: the probe body still PARSES and reports zone.present
#      (false for the ref module, by design) -- a probe that stopped answering
#      or returned malformed JSON after the event is a settlement failure the
#      batch oracles (which need a parseable probe) would surface as a Bail; C5
#      makes it an explicit, named checkpoint assertion instead.
#
# DETERMINISM + REPLAY. Same contract as property-fuzz: a fixed step count (not
# a wall clock), an xorshift64 PRNG in gawk seeded from ./seed, and the full
# generated STEP PLAN persisted to $PROBER_PREFIX so a red run reproduces from
# the printed plan file. The lifecycle steps make byte-identical prober-TAP
# replay impossible (a kill's respawn pid is not reproducible, and the shared
# fakesrv get:N counter is not reset -- property-fuzz/backend's "WHY 40" note),
# so the replay claim here is PLAN-LEVEL: regenerating from the same seed yields
# the byte-identical step plan (tests 1/2), and the plan is what a human reruns.
#
# --- non-vacuity: the claims and how each is proven ------------------------
#
# 1. PRNG DETERMINISM + SEED-SENSITIVITY (tests 1/2 below, real TAP): same seed
#    -> byte-identical plan; seed+1 -> different plan. Mutation-tested live via
#    mutate.sh "stateful-property-fuzz: PRNG ignores its seed".
# 2. REPLAY PLAN PERSISTED (test 3 asserts the plan file exists and matches what
#    was executed). Mutation-tested live via mutate.sh
#    "stateful-property-fuzz: step plan not persisted to the replay path".
# 3. THE CHECKPOINT ORACLES ARE LIVE. Proven as documented, manually-run driver
#    mutations (the sanctioned fallback where a claim cannot be wired into
#    mutate.sh's per-mutant budget), each red for a NAMED reason:
#      * C1 lineage: force BASE_PPID to a bogus value -> C1 reds.
#      * C2 kill accounting: replace `kill -9` with `kill -0` (kills nothing) ->
#        the kill checkpoint's "a worker exited on signal 9" sub-check reds
#        (EXPECT_SIG9 says 1, the log shows 0), exactly worker-death's oracle 2.
#      * C3 pool settlement: corrupt the batch baseline USED_REF -> C3 reds.
#      * C4 generation: on a reload step, assert generation UNCHANGED instead of
#        greater -> C4 reds (proving it is not vacuously satisfied by a rejected
#        reload). On a kill step, bump the expected generation -> C4 reds.
#    The per-request leak oracle inside each batch is property-fuzz's claim 1,
#    proven there by the documented probe-drift .so mutation; this scenario adds
#    no new per-request oracle, only the lifecycle checkpoints, so it does not
#    re-prove the .so-level leak control.
#
# On failure this driver names the saved step-plan file in its diagnostics; a
# human reproduces the request BATCHES with `./prober <the per-batch .rule>` and
# the lifecycle sequence by reading the plan.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
MASTER="$PROBER_SERVER_PID"
WORKERS=1                       # matches worker_processes in nginx.conf
ELOG="$PROBER_PREFIX/logs/error.log"
SEED_FILE="$PROBER_SCENARIO/seed"
CORPUS_DIR="$PROBER_SCENARIO/corpus"

PLAN="$PROBER_PREFIX/stateful-property-fuzz.plan"
PLAN_SAME="$PROBER_PREFIX/stateful-property-fuzz.sameseed.plan"
PLAN_PLUS="$PROBER_PREFIX/stateful-property-fuzz.seedplus1.plan"

# signal-9 exits from a contained kill are EXPECTED and asserted-positive by the
# kill checkpoint (C2). The run-level log-scrape exemption for that ONE line
# lives in ./env (sourced pre-boot by run-scenario.sh in the PARENT process);
# it cannot be set here, because this driver runs in a subprocess and its
# exports never reach the parent's scrape (worker-death's env-file lesson).
export PROBER_ERROR_LOG="$ELOG"

# The fixed step count and the lifecycle cadence. NUM_STEPS is a constant, never
# a wall clock (property-fuzz's header explains why at length). LIFECYCLE_EVERY
# governs how often the rarely-drawn lifecycle branch is TAKEN -- a lifecycle
# step is expensive (a full reload/respawn + drain + checkpoint), so the stream
# spends most steps on cheap request batches and punctuates them.
NUM_STEPS=32

FAILED=0

if [ ! -f "$SEED_FILE" ]; then
    echo "Bail out! seed file missing: $SEED_FILE"
    exit 1
fi
SEED="$(tr -d '[:space:]' < "$SEED_FILE")"

mapfile -t FRAGS < <(cd "$CORPUS_DIR" && printf '%s\n' *.frag | sort)
NFRAG=${#FRAGS[@]}
if [ "$NFRAG" -eq 0 ] || [ "${FRAGS[0]}" = "*.frag" ]; then
    echo "Bail out! no corpus fragments in $CORPUS_DIR"
    exit 1
fi

# --- the PRNG --------------------------------------------------------------
#
# xorshift64 (Marsaglia 13/7/17), seeded from $1, printing $2 lines of
# "kind frag1 frag2 fate" -- FOUR draws per step in a fixed order, so the stream
# a seed produces never depends on a step's outcome. Field meanings:
#   kind  (mod 10)  0    -> lifecycle event (reload or kill, chosen by fate)
#                   1..9 -> a request step (see below), so ~1 in 10 steps is a
#                           lifecycle event -- rare, as LIFECYCLE_EVERY intends
#   frag1 (mod NFRAG) primary corpus fragment for a request step
#   frag2 (mod NFRAG) second fragment (pipeline steps only)
#   fate  (mod 6)   for a request step: 0 backend, 1 abort, 2 halfclose,
#                                       3 pipeline, else direct-single
#                   for a lifecycle step (kind 0): even -> reload, odd -> kill
gen_stream() {
    gawk -v seed="$1" -v count="$2" -v nfrag="$3" '
        function xorshift64(x) {
            x = xor(x, lshift(x, 13))
            x = xor(x, rshift(x, 7))
            x = xor(x, lshift(x, 17))
            return x
        }
        BEGIN {
            x = seed + 0
            if (x == 0) { x = 88172645463325252 }
            for (i = 0; i < count; i++) {
                x = xorshift64(x); kind  = x % 10
                x = xorshift64(x); frag1 = x % nfrag
                x = xorshift64(x); frag2 = x % nfrag
                x = xorshift64(x); fate  = x % 6
                printf "%d %d %d %d\n", kind, frag1, frag2, fate
            }
        }
    '
}

# build_plan SEED > plan-file
#
# Renders gen_stream's raw draws into a human-legible, replay-authoritative STEP
# PLAN: one line per step, `<n> <verb> <args...>`. This is the file tests 1/2
# compare whole-file for determinism and that a human reads to reproduce a red
# run. It is derived ONLY from the seed + corpus (no runtime state), so it is
# byte-reproducible -- the lifecycle steps' non-reproducible RUNTIME effects
# (respawn pids) never enter it.
build_plan() {
    local seed="$1"
    local n=0 backend_n=0 kind frag1 frag2 fate

    cat <<'HDR'
# GENERATED step plan for stateful-property-fuzz -- do not hand-edit. Edit
# corpus/*.frag, ./backend or ./seed and let the driver regenerate. Each line
# is one step the driver executed, in order; see driver.sh's header for what a
# red run against this plan proves and how to reproduce it.
HDR
    while IFS=' ' read -r kind frag1 frag2 fate; do
        n=$((n + 1))
        if [ "$kind" -eq 0 ]; then
            if [ $((fate % 2)) -eq 0 ]; then
                printf '%d reload\n' "$n"
            else
                printf '%d kill\n' "$n"
            fi
            continue
        fi
        case "$fate" in
            0)
                backend_n=$((backend_n + 1))
                printf '%d request backend k%d\n' "$n" "$backend_n" ;;
            1) printf '%d request abort %s\n'     "$n" "${FRAGS[$frag1]}" ;;
            2) printf '%d request halfclose %s\n' "$n" "${FRAGS[$frag1]}" ;;
            3) printf '%d request pipeline %s %s\n' "$n" "${FRAGS[$frag1]}" "${FRAGS[$frag2]}" ;;
            *) printf '%d request single %s\n'    "$n" "${FRAGS[$frag1]}" ;;
        esac
    done < <(gen_stream "$seed" "$NUM_STEPS" "$NFRAG")
}

# emit_request_step PLANLINE -> appends stock .rule text to $RULE_TMP
#
# Translates ONE `request` plan line into a stock rule stanza, reusing exactly
# property-fuzz's escaping/oracle contract. All request kinds carry the leak
# oracle; the pipeline kind uses the `block` DSL (keepalive-bleed's shape).
emit_request_step() {
    local _n _v kind arg1 body
    # plan line: "<n> request <kind> <arg1> [<arg2>]". arg2 (pipeline's second
    # fragment) is recorded in the plan for stream stability but not consumed
    # here -- the pipeline step's second block is a fixed `/` GET (see below) --
    # so it is intentionally not read into a variable.
    read -r _n _v kind arg1 _ <<<"$1"

    case "$kind" in
        backend)
            {
                printf 'name    step %s: backend fault via /mc?key=%s\n' "$_n" "$arg1"
                printf 'send    GET /mc?key=%s HTTP/1.1\\r\\n\n' "$arg1"
                printf 'send    Host: prober\\r\\nConnection: close\\r\\n\\r\\n\n'
                printf 'delta   fds == 0\n'
                printf 'delta   pool.cycle_used == 0\n'
                echo
            } >>"$RULE_TMP"
            ;;
        single|abort|halfclose)
            body="$(cat "$CORPUS_DIR/$arg1")"
            {
                printf 'name    step %s: %s corpus/%s\n' "$_n" "$kind" "$arg1"
                printf 'send    %s\n' "$body"
                case "$kind" in
                    abort)     printf 'abort    10\n' ;;
                    halfclose) printf 'shutdown 1\n' ;;
                esac
                printf 'delta   fds == 0\n'
                printf 'delta   pool.cycle_used == 0\n'
                echo
            } >>"$RULE_TMP"
            ;;
        pipeline)
            {
                printf 'name    step %s: two requests reuse one keepalive connection\n' "$_n"
                # The pipeline step exercises CONNECTION REUSE + no-response-bleed
                # (keepalive-bleed's shape), NOT request-shape variety -- the
                # single/abort/halfclose kinds already draw the whole corpus for
                # shape coverage. So both blocks issue a deterministic, cleanly
                # FRAMED request to `/` (Content-Length'd `return 200 "OK\n"`),
                # which is what makes the `block` reader able to find the end of
                # response 1 and reuse the fd for response 2. Feeding a raw
                # corpus fragment as block 1 would break reuse the moment the
                # fragment carries its own `Connection: close` (most do) -- the
                # framed reader would then see the socket close after block 1 and
                # read -1 for block 2. arg1/arg2 are still DRAWN by the PRNG (for
                # stream-order stability across kinds) but do not vary this step.
                printf 'block   first\n'
                printf 'send    GET / HTTP/1.1\\r\\n\n'
                printf 'send    Host: prober\\r\\n\\r\\n\n'
                printf 'expect  status=200\n'
                printf 'expect  body~OK\n'
                printf 'block   second-and-close\n'
                printf 'send    GET / HTTP/1.1\\r\\n\n'
                printf 'send    Host: prober\\r\\nConnection: close\\r\\n\\r\\n\n'
                printf 'expect  status=200\n'
                printf 'expect  body~OK\n'
                printf 'delta   fds == 0\n'
                echo
            } >>"$RULE_TMP"
            ;;
        *)
            echo "Bail out! unknown request kind in plan line: $1"
            exit 1
            ;;
    esac
}

# --- probe snapshot helper (cycle-pool + lineage + generation) -------------
snapshot() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_PID="$(prober_probe_field "$body" pid)"             || return 1
    SNAP_PPID="$(prober_probe_field "$body" ppid || true)"
    SNAP_USED="$(prober_probe_field "$body" cycle_used)"     || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)"   || return 1
    SNAP_GEN="$(prober_probe_field "$body" config_generation || true)"
    SNAP_ZONE="$(prober_probe_field "$body" present || true)"   # zone.present
    return 0
}

echo "1..5"

# --- test 1/2: PRNG determinism + seed-sensitivity -------------------------
build_plan "$SEED"          > "$PLAN"
build_plan "$SEED"          > "$PLAN_SAME"
SEED_PLUS_1=$((SEED + 1))
build_plan "$SEED_PLUS_1"   > "$PLAN_PLUS"

if cmp -s "$PLAN" "$PLAN_SAME"; then
    echo "ok 1 - regenerating the step plan with the same seed ($SEED) is byte-identical"
else
    echo "not ok 1 - same seed produced a DIFFERENT step plan (PRNG is not deterministic)"
    FAILED=1
fi

if cmp -s "$PLAN" "$PLAN_PLUS"; then
    echo "not ok 2 - seed+1 ($SEED_PLUS_1) produced the SAME step plan (PRNG is stuck)"
    FAILED=1
else
    echo "ok 2 - seed+1 ($SEED_PLUS_1) produced a different step plan"
fi

# --- test 3: the step plan is persisted where the driver's diagnostics point -
if [ -s "$PLAN" ]; then
    echo "ok 3 - the executed step plan is saved to $PLAN for replay"
else
    echo "not ok 3 - the step plan was not persisted to the replay path"
    FAILED=1
fi

# --- establish the baseline the checkpoints compare against ----------------
#
# Warm the worker first: the FIRST request a fresh worker serves grows the cycle
# pool by a one-off (config-pool-adjacent lazy allocation), so a baseline taken
# COLD would be below the warm steady state every checkpoint measures against
# and the first kill's exact-equality C3 would red on a legitimate warm-up.
# Same cold-baseline trap reload-soak / reload-compressing document. A handful
# of plain requests settles it.
warm() {
    local i
    for ((i = 0; i < 5; i++)); do
        (
            exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 0
            printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
            timeout 2 cat <&3 >/dev/null 2>&1 || true
        ) || true
    done
}
warm
if ! snapshot; then
    echo "Bail out! the probe endpoint did not answer before the run"
    exit 1
fi
BASE_PPID="$SNAP_PPID"
USED_REF="$SNAP_USED"; BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
USED_HWM="$SNAP_USED"          # running high-water mark for the C3 reload-leak backstop
GEN_REF="${SNAP_GEN:-}"
EXPECT_SIG9=0                   # how many contained kills we have deliberately sent
CKPT_FAIL=0                     # checkpoint (C1..C5) failures, folded into FAILED
CKPT_N=0                        # for diagnostic numbering only

# run_batch: flush the accumulated $RULE_TMP through the prober; any failing
# generated case reds. Empty batch (two lifecycle steps in a row) is a no-op.
BATCH_IDX=0
run_batch() {
    [ -s "$RULE_TMP" ] || return 0
    BATCH_IDX=$((BATCH_IDX + 1))
    local saved="$PROBER_PREFIX/batch-$BATCH_IDX.rule"
    cp "$RULE_TMP" "$saved"
    local status=0 log="$PROBER_PREFIX/logs/batch-$BATCH_IDX.tap"
    "$PROBER_CLIENT" -H "$HOST" -p "$PORT" "$saved" >"$log" 2>&1 || status=$?
    sed 's/^/    /' "$log"
    if [ "$status" -ne 0 ]; then
        echo "# FAIL: batch $BATCH_IDX had a failing generated case (replay: ./prober $saved)"
        CKPT_FAIL=$((CKPT_FAIL + 1))
    fi
    : >"$RULE_TMP"
}

# checkpoint EVENT -- run C1..C5 after a lifecycle EVENT (reload|kill). Adds
# diagnostic # lines and bumps CKPT_FAIL; the numbered ok 4/ok 5 below summarise.
checkpoint() {
    local event="$1"
    CKPT_N=$((CKPT_N + 1))
    local tag="checkpoint $CKPT_N ($event)"

    # settle to a single steady-state worker before measuring (worker-death's
    # rationale). rc 2 = no pgrep -> requires already SKIPs the scenario, so this
    # cannot legitimately be hit; treat it as a failure if it ever is.
    local drc=0
    prober_drain_wait "$MASTER" "$WORKERS" 10000 || drc=$?
    if [ "$drc" -ne 0 ]; then
        echo "# $tag C-settle: cycle did not drain to $WORKERS worker (drain rc=$drc)"
        CKPT_FAIL=$((CKPT_FAIL + 1))
        return 0
    fi

    if ! snapshot; then
        echo "# $tag C5: the probe did not answer / did not parse after the event"
        CKPT_FAIL=$((CKPT_FAIL + 1))
        return 0
    fi

    # C1 lineage
    if [ -z "$BASE_PPID" ]; then
        echo "# $tag C1: ppid not emitted by this probe build -- SKIP lineage"
    elif [ "$SNAP_PPID" = "$BASE_PPID" ]; then
        echo "# $tag C1: lineage intact (ppid=$SNAP_PPID)"
    else
        echo "# $tag C1: ppid drifted $BASE_PPID -> $SNAP_PPID (master died?)"
        CKPT_FAIL=$((CKPT_FAIL + 1))
    fi

    # C2 no forbidden death
    if grep -qE 'exited on signal (11|6|7)|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
        echo "# $tag C2: a worker died by a FAULT signal"
        grep -nE 'exited on signal (11|6|7)|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/#   /'
        CKPT_FAIL=$((CKPT_FAIL + 1))
    else
        local n_sig9
        n_sig9="$(grep -cE 'worker process [0-9]+ exited on signal 9' "$ELOG" 2>/dev/null || true)"
        [ -n "$n_sig9" ] || n_sig9=0
        if [ "$n_sig9" -ne "$EXPECT_SIG9" ]; then
            echo "# $tag C2: signal-9 deaths=$n_sig9, expected $EXPECT_SIG9 (unsent kill or cascade)"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        else
            echo "# $tag C2: no forbidden death (signal-9=$n_sig9 == expected)"
        fi
    fi

    # C3 cycle-pool settlement. The invariant is GENERATION-SCOPED, learned
    # from the run: a KILL re-forks the SAME already-loaded cycle, so the
    # replacement's cycle_used/blocks/large must equal the pre-event baseline
    # EXACTLY (worker-death's oracle 4). A RELOAD builds a NEW cycle from a
    # re-parsed config, so its footprint legitimately differs from the old
    # cycle's -- pinning it to the old baseline would be the cold-baseline trap
    # this repo keeps re-learning (a reload's fresh cycle is not the old one).
    # So: on a reload, RE-BASELINE to the settled new-cycle footprint (and
    # separately guard against a LEAK by requiring the new cycle_used not to
    # EXCEED the running high-water mark by more than one slab block's worth --
    # a genuine per-reload cycle-pool leak grows monotonically and would breach
    # it, while ordinary config re-parse variance stays under it). On a kill,
    # require exact equality with the current baseline.
    if [ "$event" = "reload" ]; then
        # leak backstop: a monotonic climb across reloads is the failure this
        # scenario adds over reload-cycle's single reload. HWM starts at the
        # cold baseline; tolerance is one 4 kB pool block (nginx grows the
        # cycle pool in ngx_pagesize-ish chunks, so sub-block jitter is noise).
        local tol=4096
        if [ "$SNAP_USED" -gt $((USED_HWM + tol)) ]; then
            echo "# $tag C3: cycle_used climbed to $SNAP_USED, past HWM $USED_HWM + ${tol}B (reload leak?)"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        else
            echo "# $tag C3: new cycle footprint used=$SNAP_USED (<= HWM $USED_HWM + ${tol}B); re-baselining"
        fi
        [ "$SNAP_USED" -gt "$USED_HWM" ] && USED_HWM="$SNAP_USED"
        USED_REF="$SNAP_USED"; BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
    else   # kill or end-of-run: same cycle, footprint must be identical
        local drift=""
        [ "$SNAP_USED"   = "$USED_REF"   ] || drift="$drift cycle_used=$SNAP_USED/want-$USED_REF"
        [ "$SNAP_BLOCKS" = "$BLOCKS_REF" ] || drift="$drift cycle_blocks=$SNAP_BLOCKS/want-$BLOCKS_REF"
        [ "$SNAP_LARGE"  = "$LARGE_REF"  ] || drift="$drift cycle_large=$SNAP_LARGE/want-$LARGE_REF"
        if [ -z "$drift" ]; then
            echo "# $tag C3: cycle-pool footprint held (used=$USED_REF blocks=$BLOCKS_REF large=$LARGE_REF)"
        else
            echo "# $tag C3: cycle-pool drift within one generation:$drift"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        fi
    fi

    # C4 generation coherence
    if [ -z "$GEN_REF" ] || [ -z "${SNAP_GEN:-}" ]; then
        echo "# $tag C4: config_generation not emitted -- SKIP generation coherence"
    elif [ "$event" = "reload" ]; then
        if [ "$SNAP_GEN" -gt "$GEN_REF" ]; then
            echo "# $tag C4: generation advanced $GEN_REF -> $SNAP_GEN (reload absorbed)"
            GEN_REF="$SNAP_GEN"
        else
            echo "# $tag C4: generation did NOT advance ($GEN_REF -> $SNAP_GEN); reload rejected/not absorbed"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        fi
    else   # kill: no reparse, generation must hold
        if [ "$SNAP_GEN" -eq "$GEN_REF" ]; then
            echo "# $tag C4: generation held at $SNAP_GEN across the kill (no spurious reload)"
        else
            echo "# $tag C4: generation moved $GEN_REF -> $SNAP_GEN on a KILL (unexpected reload)"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        fi
    fi

    # C5 zone coherence: probe parsed (we are here) and zone.present is the
    # ref module's expected false. A missing field is the ref build's normal
    # state; a probe that returned a DIFFERENT shape would have failed snapshot.
    if [ -z "$SNAP_ZONE" ] || [ "$SNAP_ZONE" = "false" ]; then
        echo "# $tag C5: probe coherent, zone.present=${SNAP_ZONE:-absent} (ref module, expected)"
    else
        echo "# $tag C5: zone.present=$SNAP_ZONE unexpected for the ref module"
        CKPT_FAIL=$((CKPT_FAIL + 1))
    fi

    return 0
}

# --- the run: walk the plan, batch requests, checkpoint on lifecycle -------
RULE_TMP="$PROBER_PREFIX/stateful.batch.rule"
: >"$RULE_TMP"

while read -r line; do
    case "$line" in
        \#*|"") continue ;;      # plan header / blanks
    esac
    # word-splitting on the plan line is intentional: it is our own generated
    # "<n> <verb> <args...>" with single-space fields, never external data.
    # shellcheck disable=SC2086
    set -- $line
    step_n="$1"; step_verb="$2"

    if [ "$step_verb" = "request" ]; then
        emit_request_step "$line"
        continue
    fi

    # a lifecycle step: flush the pending request batch first, then the event
    run_batch

    if [ "$step_verb" = "reload" ]; then
        if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" 8000; then
            # generation streak confirms the reload was absorbed (C4 reads it)
            prober_config_wait "$HOST" "$PORT" "${GEN_REF:-0}" 3 8000 >/dev/null 2>&1 || true
            checkpoint reload
        else
            echo "# step $step_n reload: no new worker answered within 8 s after SIGHUP"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        fi
    elif [ "$step_verb" = "kill" ]; then
        if ! snapshot; then
            echo "# step $step_n kill: probe did not answer before the kill"
            CKPT_FAIL=$((CKPT_FAIL + 1))
            continue
        fi
        victim="$SNAP_PID"
        if kill -0 "$victim" 2>/dev/null; then
            kill -9 "$victim" 2>/dev/null || true
            EXPECT_SIG9=$((EXPECT_SIG9 + 1))
            # wait for a different pid to answer (respawn), bounded
            replaced=0
            for _i in $(seq 1 100); do
                sleep 0.05
                now="$(prober_probe_pid "$HOST" "$PORT" 2>/dev/null || true)"
                [ -n "$now" ] && [ "$now" != "$victim" ] && { replaced=1; break; }
            done
            if [ "$replaced" -eq 1 ]; then
                checkpoint kill
            else
                echo "# step $step_n kill: no replacement worker answered within 5 s"
                CKPT_FAIL=$((CKPT_FAIL + 1))
            fi
        else
            echo "# step $step_n kill: victim $victim not alive to kill"
            CKPT_FAIL=$((CKPT_FAIL + 1))
        fi
    else
        echo "Bail out! unknown lifecycle verb in plan: $line"
        exit 1
    fi
done < <(grep -vE '^#|^$' "$PLAN")

# flush any trailing request batch, then a final end-of-run checkpoint
run_batch
checkpoint end-of-run

# --- test 4: every request batch held its leak/alive oracle ----------------
if [ "$CKPT_FAIL" -eq 0 ]; then
    echo "ok 4 - all request batches held the leak/alive oracle across every lifecycle event"
else
    echo "not ok 4 - a batch or lifecycle checkpoint failed (see # diagnostics above)"
    FAILED=1
fi

# --- test 5: summary of the lifecycle checkpoints --------------------------
# CKPT_FAIL already folded into test 4; test 5 states the coverage that ran, so
# a plan that drew ZERO lifecycle events (and thus proved nothing about the
# stateful half) is a visible non-vacuity failure rather than a silent green.
if [ "$CKPT_N" -lt 1 ]; then
    echo "not ok 5 - the generated plan contained NO lifecycle checkpoint (stateful half unexercised)"
    FAILED=1
elif [ "$CKPT_FAIL" -eq 0 ]; then
    echo "ok 5 - $CKPT_N lifecycle checkpoint(s) all coherent (lineage/log/pool/generation/zone)"
else
    echo "not ok 5 - $CKPT_FAIL of the $CKPT_N lifecycle checkpoint(s) failed"
    FAILED=1
fi

exit "$FAILED"
