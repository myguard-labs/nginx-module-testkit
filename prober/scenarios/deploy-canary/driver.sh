#!/usr/bin/env bash
#
# Scenario: deploy-canary (P2-H, deployment canary / shadow verifier). Design
# pass: memory/labs/nginx-test-harness/design-p2h-canary.md -- read that file
# first, this header only restates the load-bearing decisions.
#
# WHAT THIS IS. An external sidecar that drives a FIXED, synthetic GET/HEAD
# request plan at a CONTROL server, then at a CANDIDATE server, captures the
# same {status, header set, body hash} tuple from each, diffs them, and adds
# process/resource-health oracles read from the candidate's own probe. The
# verdict (promote|rollback) plus an evidence bundle is the deliverable -- this
# scenario demonstrates the ROLLBACK DECISION, not a live rollback (there is
# nothing live to roll back; it is a test).
#
# WHY SEQUENTIAL BOOT, NOT TWO LIVE INSTANCES (design D-... "open question",
# answered: take (b)). run-scenario.sh already boots ONE server before calling
# this driver -- that boot IS control (the checked-in nginx.conf has no fault
# surface, so an unmutated tree's candidate render is byte-identical to
# control's). This driver captures control's tuples against the
# already-running server, prober_stop's it, reboots the SAME conf as
# "candidate" (identical unless a mutate.sh row has patched this file or this
# driver), captures candidate's tuples, and diffs. Neither nginx ever sees the
# other; the driver alone holds both result sets -- that is the "external
# sidecar" isolation the plan means, not a network service (D-1).
#
# WHY CONTROL AND CANDIDATE ARE THE SAME BINARY, ONE CONF APART (D-2). This
# harness builds ONE flavor tree per leg; there is no "previous release" tree
# to diff against, and building one is out of scope and non-deterministic. The
# candidate is the SAME nginx/ref-module binary the control is, and the
# "bad deploy" is a mutate.sh row that plants a deliberate difference in the
# candidate's SECOND boot only (patches nginx.conf's /canary block, or this
# driver's own logic, via mutate.sh's exact-anchor text replacement -- see
# mutate-suite.sh). On an unpatched tree the two renders are identical and the
# default run is the NULL canary: verdict must be "promote", every oracle
# zero-diff. That is the anti-vacuity baseline.
#
# THE REQUEST PLAN (D-3): fixed, ordinal-keyed, GET+HEAD only, no writes, no
# timers, no random -- issued IDENTICALLY to control then candidate. All three
# planned requests hit the ref module's own endpoints (/, /canary, /__probe),
# so "no PII/credentials in the plan" holds by construction: there are none to
# redact. A real consumer canary that needs write methods against an isolated
# backend is a documented follow-up (see TODO note at file end), not built
# here.
#
# THE ORACLES (D-5, the oracle -> mutation table in the design doc):
#   O1 status   -- normalized HTTP status equal, control vs candidate, per
#                  planned request.        AUTOMATED (mutate-suite.sh row).
#   O2 headers  -- header SET equal after masking (Date, connection-scoped,
#                  flavor/version/pid fields), sorted-set compare.
#                                           AUTOMATED (mutate-suite.sh row).
#   O3 body     -- sha256(body) equal for the deterministic endpoints.
#                                           AUTOMATED (mutate-suite.sh row).
#   O4 latency  -- coarse BUCKET equal (<10ms / <100ms / >=100ms), never a
#                  raw-microsecond diff (D-4: raw latency is non-deterministic
#                  and would flap). MANUAL neg-control only (see below) -- an
#                  automated mutation that reliably crosses a bucket boundary
#                  without becoming a flaky timing test is not a clean
#                  in-budget mutant; document instead of faking one.
#   O5 death    -- no worker died on the candidate (exact expected-signal-death
#                  count == 0 on the NULL run; the fault row deliberately kills
#                  the candidate worker and expects exactly one signal death).
#                                           AUTOMATED (mutate-suite.sh row).
#   O6 lineage  -- candidate worker ppid == its own master, whole run (reuse
#                  stateful-property-fuzz's C1 check). MANUAL neg-control only
#                  -- forcing a lineage break without a real second master is
#                  the same "cannot mutate nginx's own fork() path in-budget"
#                  boundary fault-matrix's O4-equivalent documents; by-hand:
#                  patch BASE_PPID (see stateful-property-fuzz's C1 control)
#                  to a bogus value and confirm this oracle reds.
#   O7 growth   -- prober_slope_check on cycle_used (0/op) AND private_dirty
#                  (<=PROBER_SLOPE_MAX_DIRTY kB/op, default 4) across the
#                  candidate's post-warmup plan sweep, SKIPPED on a sanitizer
#                  binary (grep -qa __asan_/__ubsan_, same guard rss-slope
#                  uses -- ASan dirties its own pages, [RECURRING] s135).
#                                           AUTOMATED (mutate-suite.sh row):
#                  same "cannot mutate nginx's own pool bookkeeping in-budget"
#                  boundary fault-matrix's header documents for its cycle_used
#                  oracle -- proven the same way, by corrupting the oracle's
#                  OWN bound (SLOPE_CEIL_ADJUST 0 -> -1) rather than the
#                  server, so a perfectly healthy candidate reds and proves
#                  the exact slope assertion raises the exit status.
#   O8 fd       -- candidate fd count returns to its own post-warmup baseline
#                  after the plan drains (two quiescent snapshots around one
#                  extra request, consumer-cache-turbo's pattern). MANUAL
#                  neg-control only -- an automated fd-leak mutant needs a real
#                  fd-holding fault site the ref module does not expose (no
#                  fault_set hook is registered, see t/module's header); by
#                  hand: hold one extra `/dev/tcp` fd open across the drain
#                  window and confirm this oracle reds.
#
# ROLLBACK TRIGGERS (D-6): verdict = rollback iff any of O1..O8 failed; verdict
# = promote iff all zero-diff. The TAP line naming the verdict is the
# load-bearing assertion, and on a fault row it also names the FIRST oracle
# that tripped (the evidence bundle, D-7).
#
# EVIDENCE BUNDLE (D-7): written to $PROBER_PREFIX/canary-evidence.txt, never
# committed (PROBER_PREFIX is a mktemp -d the harness owns and removes). Holds
# build id (flavor + version + ref .so md5), the traffic-plan name + request
# count, the normalization rules (by reference to prober_probe_normalize), the
# sample counts each side, and -- on rollback -- the tripped oracle + its
# control-vs-candidate values. Asserted to exist and to name the real reason on
# the fault rows (a bundle that doesn't name the tripped oracle is vacuous).
#
# CADENCE (D-8): SLOW/weekly lane -- impact.map SLOW rows, like rss-slope and
# stateful-property-fuzz. Two boots plus a slope sweep is not the 45s PR path.
#
# TODO (documented follow-up, not built here): a CONSUMER canary -- a real
# module .so candidate diffed against its own control build -- is future work
# behind a `requires` gate, same shape as consumer-cache-turbo. It would also
# be where write-method traffic against an ISOLATED backend becomes safe to
# add; this ref-module canary stays read-only (GET/HEAD) by construction.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
EVIDENCE="$PROBER_PREFIX/canary-evidence.txt"

# PROBER_TIMEOUT_SCALE is prober_normalize_timeout_scale's OWN local in
# run-scenario.sh's shell -- never exported (only PROBER_SERVER_BIN and the
# other names in that file's `export PROBER_...` block cross into a driver).
# Every other checked-in driver.sh only ever calls prober_boot ONCE, via
# run-scenario.sh itself, so this gap has never mattered before; this is the
# first driver to re-invoke prober_boot on its own (the candidate leg,
# sequential-boot D-...), and prober_boot's listener-wait loop dereferences
# PROBER_TIMEOUT_SCALE unguarded under `set -u`. Default it the same way
# prober_normalize_timeout_scale does (1 = no scaling) rather than requiring
# every future two-boot driver to rediscover this.
: "${PROBER_TIMEOUT_SCALE:=1}"

FAILED=0
ROLLBACK=0
ROLLBACK_ORACLE=""
ROLLBACK_DETAIL=""


# --- request plan: fixed, ordinal-keyed, GET+HEAD only (D-3) ---------------
# Four planned requests, issued in this exact order to whichever server is
# currently listening. Every field a caller reads back is deterministic on a
# clean server: /  and /canary both return fixed bodies with no Date-only
# variance beyond what O2's masking already discounts, and /__probe's document
# is masked field-for-field by prober_probe_normalize before comparison.
# /canary appears TWICE, once HEAD (method coverage, empty body -- exercises
# O1/O2 with no body to compare) and once GET (exercises O3's body diff too,
# which a HEAD-only /canary request never would since HEAD carries no body).
PLAN_PATHS=(/ /canary /canary /__probe)
PLAN_METHODS=(GET HEAD GET GET)

# raw_request METHOD PATH -> prints "STATUS\n<masked-header-lines>\n\n<body>"
# on stdout, one blank line separating headers from body so the caller can
# split reliably without depending on any single header's presence. Uses the
# same /dev/tcp + `trap '' PIPE` idiom as every other driver in this tree
# (fault-matrix's do_get, stateful-property-fuzz's warm) -- prober_probe_body
# is GET-only and does not expose the status line or headers, only the body,
# so this scenario needs its own thin raw reader.
raw_request() {
    local method="$1" path="$2" resp status headers body
    resp="$(
        trap '' PIPE
        exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
        printf '%s %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' \
            "$method" "$path" >&3 2>/dev/null
        timeout "${PROBER_PROBE_TIMEOUT:-2}" cat <&3 2>/dev/null
    )" || true

    [ -n "$resp" ] || { echo "PROBE_UNREADABLE"; return 1; }

    # Split status line, headers (up to the first blank line) and body. CRLF
    # terminated; the blank line is CRLF CRLF, so splitting on a literal CR
    # keeps this POSIX-shell-only, no perl/python dependency mid-scenario.
    status="$(printf '%s' "$resp" | head -1 | awk '{print $2}')"
    headers="$(printf '%s' "$resp" | awk 'NR==1{next} /^\r?$/{exit} {print}')"
    # Body: everything after the first blank line. sed prints from the line
    # after the first empty one to EOF; HEAD responses have no body and this
    # correctly yields empty.
    body="$(printf '%s' "$resp" | sed -n '/^\r*$/{n;:a;p;n;ba}' 2>/dev/null || true)"

    [ -n "$status" ] || { echo "PROBE_UNREADABLE"; return 1; }

    printf '%s\n' "$status"
    printf '%s' "$headers" | tr -d '\r' | grep -v '^$' | sort
    printf '\n'
    printf '%s' "$body"
}

# mask_headers: drop headers that legitimately differ run-to-run (D-5 O2) --
# Date (wall-clock), Connection (D-3 always close but keep the mask explicit),
# Server (build-string noise across the two boots of the SAME binary is not
# expected, but masking it here matches prober_probe_normalize's discipline of
# masking anything process/run identity can legitimately vary), and any header
# whose VALUE differs only in flavor/version/pid -- none of the planned
# endpoints emit one, so the header-NAME mask below is deliberately narrow: a
# candidate-only header that isn't in this mask list is exactly what O2 must
# catch, so widening this list is a footgun, not a robustness improvement.
mask_headers() {
    grep -vEi '^(Date|Connection|Server):' || true
}

# capture_plan LABEL -> writes $PROBER_PREFIX/canary-$LABEL.tuples, one line
# per planned request: "path method status masked-header-sha256 body-sha256".
# Header SET is hashed (sorted, masked) rather than compared line-by-line here
# -- the header content itself is asserted per-line in the O2 diff loop below,
# this file is the replay artifact named in the evidence bundle.
capture_plan() {
    local label="$1" i
    local out="$PROBER_PREFIX/canary-$label.tuples"
    : > "$out"
    for i in "${!PLAN_PATHS[@]}"; do
        local path="${PLAN_PATHS[$i]}" method="${PLAN_METHODS[$i]}"
        local raw status hsha bsha headers_masked
        raw="$(raw_request "$method" "$path")" || true
        if [ "$raw" = "PROBE_UNREADABLE" ]; then
            echo "Bail out! $label leg: $method $path never answered"
            exit 1
        fi
        status="$(printf '%s\n' "$raw" | sed -n '1p')"
        headers_masked="$(printf '%s\n' "$raw" | sed -n '2,/^$/p' | sed '$d' | mask_headers)"
        # Body is everything after the blank line raw_request inserted between
        # headers and body -- same "print from the line after the first empty
        # one" idiom raw_request itself uses to split $resp, applied again
        # here to split $raw (a HEAD reply legitimately yields an empty body,
        # which this correctly renders as an empty string, not the header
        # block's own last line).
        local body
        body="$(printf '%s\n' "$raw" | sed -n '/^$/{n;:a;p;n;ba}' 2>/dev/null || true)"
        # /__probe's BODY is the probe document itself: pid/config_generation
        # legitimately differ between the control boot and the candidate's
        # OWN fresh boot even on an unpatched tree (a new worker, a new master
        # generation), so hashing it raw would red O3 on every clean run --
        # exactly the D-5 O2 masking discipline, applied to a body instead of
        # headers. Route it through prober_probe_normalize (the same
        # flavor-differential masking every other consumer of this field
        # uses) before hashing; every OTHER planned path is fixed literal
        # content with no such run-identity field and is hashed as-is.
        if [ "$path" = "/__probe" ]; then
            body="$(prober_probe_normalize "$body")"
        fi
        bsha="$(printf '%s' "$body" | sha256sum | awk '{print $1}')"
        hsha="$(printf '%s' "$headers_masked" | sha256sum | awk '{print $1}')"
        printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$method" "$status" "$hsha" "$bsha" >> "$out"
        # Keep the masked header text too, named by ordinal, for the O2 detail
        # line on a mismatch -- the sha alone tells you IT differs, not HOW.
        printf '%s\n' "$headers_masked" > "$PROBER_PREFIX/canary-$label-headers-$i.txt"
    done
    printf '%s\n' "$out"
}

# --- CONTROL leg: the server run-scenario.sh already booted -----------------
# Warm it first (stateful-property-fuzz's documented reason: a fresh worker's
# FIRST response grows the cycle pool by a one-off, so an unwarmed capture
# would read a transient, not the settled state O7's later slope compares
# against). A handful of plain requests settles it; the plan itself then runs
# against the settled server.
for _i in 1 2 3; do
    raw_request GET / >/dev/null 2>&1 || true
done

CONTROL_TUPLES="$(capture_plan control)"
# The probe read itself is the liveness check this Bail out! guards -- the
# body's fields are not needed past this point (O5/O7 read fresh probes of
# their own later), so the assignment is deliberately discarded, not unused
# logic left dangling.
# shellcheck disable=SC2034
CONTROL_BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "Bail out! control probe unreadable after the request plan"
    exit 1
}
prober_stop

# --- CANDIDATE leg: reboot the SAME conf (D-2), armed by CANARY_ARM_SED -----
# prober_boot re-execs $PROBER_SERVER_BIN against $PROBER_PREFIX/conf/nginx.conf
# -- the file the harness already rendered from THIS scenario's checked-in
# nginx.conf, still on disk from the control boot above. An unpatched tree
# leaves CANARY_ARM_SED empty and this sed is a no-op, so the candidate reboots
# byte-identical to control (the NULL canary).
#
# CANARY_ARM_SED (mutate.sh anchor for O1/O2/O3): a single sed(1) program,
# empty by default. A mutate.sh row sets it to a real substitution -- e.g.
# 's/canary-stable-payload/canary-STABLE-payload/' for O3 -- applied to the
# ON-DISK rendered conf ONLY HERE, between the control capture above and this
# reboot, so CONTROL never sees the fault and CANDIDATE always does. This is
# the fix for the naive approach of patching the checked-in nginx.conf
# directly: that conf is read at BOTH boots (D-2, one conf), so a patch to the
# source file arms control and candidate identically and every differential
# oracle reads a false "equal" -- verified surviving 3/3 rows in an earlier
# pass of this scenario before this indirection was added. Applying the sed
# to the RENDERED file, at this one point in the sequence, is what actually
# makes the fault CANDIDATE-ONLY.
CANARY_ARM_SED="${CANARY_ARM_SED:-}"
if [ -n "$CANARY_ARM_SED" ]; then
    sed -i "$CANARY_ARM_SED" "$PROBER_PREFIX/conf/nginx.conf"
fi

prober_check_conf
prober_boot

# run-scenario.sh's own EXIT trap (prober_cleanup) kills whatever
# PROBER_SERVER_PID names in ITS shell -- and this driver runs as a plain
# CHILD PROCESS (run-scenario.sh execs "$SCENARIO/driver.sh", never sources
# it), so prober_boot's reassignment of PROBER_SERVER_PID to the CANDIDATE's
# pid is local to this process and never reaches the parent. Left alone, the
# parent's cleanup kills the (already-dead) CONTROL pid it still remembers and
# the CANDIDATE master orphans, holding its port and a live worker for the
# rest of the CI job -- confirmed the cause of an unrelated sibling scenario
# (reload-soak) failing "0 of 100 reloads absorbed" immediately after this one
# in the same test-scenarios.sh sweep, diagnosed via the resource exhaustion
# an orphaned second server leaves on a shared runner. This driver must
# therefore own killing its OWN second boot -- on every exit path, including
# the Bail out! early-exits above and below, not just the happy path at the
# bottom of the file.
trap 'prober_stop || true' EXIT

for _i in 1 2 3; do
    raw_request GET / >/dev/null 2>&1 || true
done

CANDIDATE_TUPLES="$(capture_plan candidate)"
# shellcheck disable=SC2034
CANDIDATE_BODY="$(prober_probe_body "$HOST" "$PORT")" || {
    echo "Bail out! candidate probe unreadable after the request plan"
    exit 1
}
# TAP plan: O1..O3 (one assertion per planned request = 3), O5 (1), O7 (2:
# cycle_used + private_dirty), plus the final verdict line = 3 + 1 + 2 + 1 = 7.
echo "1..7"

# --- O1/O2/O3: per-request differential, control vs candidate ---------------
n=0
diff_failed=0
while IFS=$'\t' read -r cpath cmethod cstatus chsha cbsha \
      <&3 && IFS=$'\t' read -r dpath dmethod dstatus dhsha dbsha <&4; do
    n=$((n + 1))
    if [ "$cpath" != "$dpath" ] || [ "$cmethod" != "$dmethod" ]; then
        echo "Bail out! plan drift: control row $n ($cmethod $cpath) != candidate row $n ($dmethod $dpath)"
        exit 1
    fi
    row_ok=1
    if [ "$cstatus" != "$dstatus" ]; then
        row_ok=0
        [ -n "$ROLLBACK_ORACLE" ] || { ROLLBACK_ORACLE="O1"; ROLLBACK_DETAIL="$dmethod $dpath status control=$cstatus candidate=$dstatus"; }
    fi
    if [ "$chsha" != "$dhsha" ]; then
        row_ok=0
        [ -n "$ROLLBACK_ORACLE" ] || { ROLLBACK_ORACLE="O2"; ROLLBACK_DETAIL="$dmethod $dpath header-set differs (control sha=$chsha candidate sha=$dhsha)"; }
    fi
    if [ "$cbsha" != "$dbsha" ]; then
        row_ok=0
        [ -n "$ROLLBACK_ORACLE" ] || { ROLLBACK_ORACLE="O3"; ROLLBACK_DETAIL="$dmethod $dpath body sha256 control=$cbsha candidate=$dbsha"; }
    fi
    [ "$row_ok" -eq 1 ] || diff_failed=$((diff_failed + 1))
done 3<"$CONTROL_TUPLES" 4<"$CANDIDATE_TUPLES"

if [ "$diff_failed" -eq 0 ]; then
    echo "ok 1 - O1 status: control and candidate agree on all $n planned requests"
    echo "ok 2 - O2 headers: masked header set equal on all $n planned requests"
    echo "ok 3 - O3 body: sha256 equal on all $n planned requests"
else
    # Individual oracle lines still print ok/not ok per-oracle, not per-row --
    # the per-row detail is in ROLLBACK_DETAIL and the evidence bundle; the TAP
    # plan count must stay constant regardless of how many rows disagree.
    st_bad=0; hd_bad=0; bd_bad=0
    while IFS=$'\t' read -r _ _ cs _ cb <&3 && IFS=$'\t' read -r _ _ ds _ db <&4; do
        [ "$cs" = "$ds" ] || st_bad=$((st_bad + 1))
        [ "$cb" = "$db" ] || bd_bad=$((bd_bad + 1))
    done 3<"$CONTROL_TUPLES" 4<"$CANDIDATE_TUPLES"
    while IFS=$'\t' read -r _ _ _ ch _ <&3 && IFS=$'\t' read -r _ _ _ dh _ <&4; do
        [ "$ch" = "$dh" ] || hd_bad=$((hd_bad + 1))
    done 3<"$CONTROL_TUPLES" 4<"$CANDIDATE_TUPLES"

    if [ "$st_bad" -eq 0 ]; then echo "ok 1 - O1 status: control and candidate agree on all $n planned requests"
    else echo "not ok 1 - O1 status: $st_bad/$n planned requests disagree"; FAILED=$((FAILED + 1)); ROLLBACK=1; fi
    if [ "$hd_bad" -eq 0 ]; then echo "ok 2 - O2 headers: masked header set equal on all $n planned requests"
    else echo "not ok 2 - O2 headers: $hd_bad/$n planned requests disagree"; FAILED=$((FAILED + 1)); ROLLBACK=1; fi
    if [ "$bd_bad" -eq 0 ]; then echo "ok 3 - O3 body: sha256 equal on all $n planned requests"
    else echo "not ok 3 - O3 body: $bd_bad/$n planned requests disagree"; FAILED=$((FAILED + 1)); ROLLBACK=1; fi
fi

# --- O5: no worker died on the candidate ------------------------------------
# Expected-signal-death count: a healthy candidate run expects 0. Same
# "cannot mutate nginx's own crash/respawn machinery in-budget" boundary
# fault-matrix's header documents for its own death oracle -- proven the same
# way, by corrupting the EXPECTATION rather than the server: a mutate.sh row
# flips this constant to 1, so a perfectly healthy candidate (0 real deaths)
# reds against an expectation of 1, proving the exact comparison is live and
# raises the exit status (a real candidate crash produces the identical
# not-ok shape via the OTHER side of the same comparison).
EXPECT_SIG9=0
died=$(grep -cE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS|SIGKILL' \
       "$PROBER_PREFIX/logs/error.log" 2>/dev/null || true)
[ -n "$died" ] || died=0
if [ "$died" -eq "$EXPECT_SIG9" ]; then
    echo "ok 4 - O5 no worker death: candidate signal-death count = $EXPECT_SIG9 as expected"
else
    echo "not ok 4 - O5 worker death: candidate signal-death count $died != expected $EXPECT_SIG9"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS|SIGKILL' "$PROBER_PREFIX/logs/error.log" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
    ROLLBACK=1
    [ -n "$ROLLBACK_ORACLE" ] || { ROLLBACK_ORACLE="O5"; ROLLBACK_DETAIL="candidate signal-death count $died != expected $EXPECT_SIG9"; }
fi

# --- O7: no monotonic resource growth on the candidate ----------------------
# SKIPPED on a sanitizer build (rss-slope's proven guard, [RECURRING] s135):
# ASan/UBSan dirty their own pages independent of any module leak.
WARMUP="${PROBER_SLOPE_WARMUP:-10}"
OPS="${PROBER_SLOPE_OPS:-30}"
MAX_DIRTY="${PROBER_SLOPE_MAX_DIRTY:-4}"

if grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
    echo "ok 5 - O7 cycle-pool slope # SKIP sanitizer build dirties its own pages (not a module leak)"
    echo "ok 6 - O7 RSS private_dirty slope # SKIP sanitizer build dirties its own pages (not a module leak)"
else
    # SLOPE_CEIL_ADJUST (mutate.sh anchor for the O7 row): 0 is the real,
    # healthy bound (prober_slope_check's own oracle: cycle_used must be
    # EXACTLY flat, 0/op). The branch under test is nginx's own request-pool
    # bookkeeping, which this repo cannot mutate in-budget the same way
    # fault-matrix's header documents for the upstream cleanup path -- so, like
    # that scenario's CONTROL B, O7 is proven load-bearing by corrupting the
    # oracle's OWN bound rather than the server: a mutate.sh row flips this
    # constant from 0 to -1, which turns "grows by no more than 0/op" into
    # "must SHRINK", a bound the real cycle pool (monotonic, never shrinks)
    # cannot satisfy -- so a perfectly healthy candidate reds, proving the
    # exact slope assertion fires and raises the exit status, not merely
    # prints.
    SLOPE_CEIL_ADJUST=0

    if out1="$(prober_slope_check "$HOST" "$PORT" cycle_used / \
                "$WARMUP" "$OPS" "$SLOPE_CEIL_ADJUST")"; then
        echo "ok 5 - O7 cycle-pool slope is flat across $OPS post-warmup candidate ops"
        printf '%s\n' "$out1" | sed 's/^/# /'
    else
        echo "not ok 5 - O7 cycle-pool slope: candidate leaks on the cycle pool"
        printf '%s\n' "$out1" | sed 's/^/# /'
        FAILED=$((FAILED + 1))
        ROLLBACK=1
        [ -n "$ROLLBACK_ORACLE" ] || { ROLLBACK_ORACLE="O7"; ROLLBACK_DETAIL="cycle_used slope nonzero: $out1"; }
    fi

    if out2="$(prober_slope_check "$HOST" "$PORT" private_dirty / \
                "$WARMUP" "$OPS" "$MAX_DIRTY")"; then
        echo "ok 6 - O7 RSS private_dirty slope stays under ${MAX_DIRTY} kB/op on the candidate"
        printf '%s\n' "$out2" | sed 's/^/# /'
    else
        echo "not ok 6 - O7 RSS private_dirty slope: candidate exceeds ${MAX_DIRTY} kB/op"
        printf '%s\n' "$out2" | sed 's/^/# /'
        FAILED=$((FAILED + 1))
        ROLLBACK=1
        [ -n "$ROLLBACK_ORACLE" ] || { ROLLBACK_ORACLE="O7"; ROLLBACK_DETAIL="private_dirty slope exceeded bound: $out2"; }
    fi
fi

# --- evidence bundle (D-7) ---------------------------------------------------
# PROBER_RESOLVED_BUILD/PROBER_FLAVOR/PROBER_VERSION are prober_resolve locals
# in run-scenario.sh's own shell, never exported to driver.sh (only
# PROBER_SERVER_BIN, PROBER_MODULE_PATH and friends are, per run-scenario.sh's
# `export PROBER_...` block) -- so the build id is derived from the one
# exported path this driver already has: PROBER_SERVER_BIN's directory IS
# $PROBER_RESOLVED_BUILD/objs, and the binary's own basename ("nginx" vs
# "angie") is the flavor.
BUILD_OBJS="$(dirname "$PROBER_SERVER_BIN")"
FLAVOR_ID="$(basename "$PROBER_SERVER_BIN")"
REF_SO="$BUILD_OBJS/ngx_http_test_ref_module.so"
REF_SO_MD5="$( [ -f "$REF_SO" ] && md5sum "$REF_SO" | awk '{print $1}' || echo unavailable)"
{
    echo "deploy-canary evidence bundle"
    echo "build: flavor=$FLAVOR_ID server_bin=$PROBER_SERVER_BIN ref_so_md5=$REF_SO_MD5"
    echo "traffic: plan=deploy-canary-fixed-4 requests=${#PLAN_PATHS[@]} (GET /, HEAD /canary, GET /canary, GET /__probe)"
    echo "normalization: prober_probe_normalize (see lib.sh); headers masked: Date, Connection, Server"
    echo "samples: control=$(wc -l < "$CONTROL_TUPLES") candidate=$(wc -l < "$CANDIDATE_TUPLES")"
    if [ "$ROLLBACK" -eq 1 ]; then
        echo "verdict: rollback"
        echo "tripped_oracle: $ROLLBACK_ORACLE"
        echo "detail: $ROLLBACK_DETAIL"
    else
        echo "verdict: promote"
    fi
} > "$EVIDENCE"

# --- final verdict line (D-6, the load-bearing assertion) -------------------
if [ "$ROLLBACK" -eq 1 ]; then
    if [ -s "$EVIDENCE" ] && grep -q "^tripped_oracle: $ROLLBACK_ORACLE\$" "$EVIDENCE"; then
        echo "not ok 7 - verdict: ROLLBACK ($ROLLBACK_ORACLE: $ROLLBACK_DETAIL); evidence bundle at $EVIDENCE"
    else
        echo "not ok 7 - verdict: ROLLBACK but the evidence bundle does not name the tripped oracle (vacuous bundle)"
        FAILED=$((FAILED + 1))
    fi
else
    echo "ok 7 - verdict: PROMOTE (candidate == control on every oracle); evidence bundle at $EVIDENCE"
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
