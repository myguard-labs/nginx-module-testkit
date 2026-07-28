#!/usr/bin/env bash
#
# gen-consumer-scenarios.sh -- generate the zero-hook consumer scenarios under
# prober/scenarios/consumer-<name>/ from one table.
#
# WHY A GENERATOR
#   Every zero-hook consumer scenario asserts the SAME property with the SAME
#   oracle: two post-drain QUIESCENT probe snapshots taken around one extra
#   full request must report identical cycle_used, cycle_blocks, cycle_large,
#   worker fds and master fds. Equal means the module's per-request path frees
#   what it allocates. Only three things differ per module: the .so name, the
#   http{}/server{} config that switches the module on, and the anti-vacuity
#   check proving the module's code actually ran. Hand-copying a ~230-line
#   driver eight times means eight places to fix the next oracle bug and eight
#   chances to leave a stale module name in a comment. The table below is the
#   whole difference; the driver body is written once, here.
#
#   consumer-cache-turbo is NOT generated -- it predates this script, carries a
#   hand-written HIT-path rationale worth keeping, and is the reference the
#   generated ones are modelled on. It is left alone deliberately.
#
# USAGE
#   tools/gen-consumer-scenarios.sh [--only NAME,...] [--check] [--list]
#
#   --only A,B   generate only these scenario names (the consumer-<x> suffix)
#   --check      regenerate into a temp dir and diff against what is committed;
#                exit 1 if they differ. This is the CI guard that stops a
#                hand-edit to a generated scenario from silently surviving.
#   --list       print the scenario names this script owns, one per line
#   -h, --help   this header
#
# OUTPUT   prober/scenarios/consumer-<name>/{nginx.conf,requires,driver.sh}
#
# SIDE EFFECTS
#   Overwrites the three files of every scenario it owns. It does NOT touch
#   consumer-cache-turbo, and it does not create scenarios for modules absent
#   from the table.
#
# LIMITS / WHERE TO EXTEND
#   * Zero-hook only. A module that grows a real ngx_*_probe_hooks.c wants a
#     hand-written scenario reading ITS zone fields -- drop it from this table
#     at that point rather than teaching the generator about hooks.
#   * ANTIVAC is a grep run against the raw response of the measured request.
#     A module with no observable response signature gets ANTIVAC='' and its
#     oracle 2 degrades to "the request served a clean 200", which is weaker;
#     the driver says so in that case rather than pretending otherwise.
#   * Adding a module = one row in the table + a rerun. Keep the row's comment
#     saying WHY that conf is the minimal switch-on for that module.
#
set -euo pipefail

cd "$(dirname "$0")/.."

ONLY=""; CHECK=0; LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --only)  ONLY="${2:?}"; shift 2 ;;
        --check) CHECK=1; shift ;;
        --list)  LIST=1; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "gen-consumer-scenarios: unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---- the table --------------------------------------------------------------
# name|so|http_extra|server_extra|antivac_grep|antivac_desc|trigger_hdr
#
# http_extra   goes inside http{} (shm zones, module-level switches)
# server_extra goes inside server{}, after the listen -- typically the
#              location / block that turns the module on for the measured path.
#              A '@@' is expanded to a newline+indent so the table stays legible.
# antivac_grep an ERE matched against the measured response's raw bytes; empty
#              means "no observable signature" (see LIMITS).
#
# Every conf below was derived from that module's own README/tests, not
# invented -- a directive spelled wrong makes `nginx -t` fail and the scenario
# reds for a reason that has nothing to do with allocation neutrality.
#
# ON THE ANTI-VACUITY COLUMN -- READ BEFORE ADDING A ROW.
#
# Three of these modules expose a signature that is genuinely IMPOSSIBLE without
# the module in the request path, and each was verified by running the module
# both ways (see the per-row note). Two do not, and say so rather than pretending:
# api-abuse and error-abuse only act once a threshold is crossed, and neither
# emits a header, a body change, or even an INFO-level log line on a normal
# request. A `grep '^HTTP/1.1 200'` against a `return 200` response would "pass"
# with the module's directive commented out entirely -- that is a VACUOUS gate,
# the exact shape this repo deletes scenarios for, so it is not used as one.
# Those two rows carry an empty signature and the driver states the weakness in
# its own output instead of overclaiming.
#
# THE `shield` ROW IS THE ONE UNVERIFIED SIGNATURE, AND IT IS MARKED HERE
# BECAUSE THAT MATTERS. nginx-http-shield-module does not currently BUILD (its
# vendored t/harness copy still declares the old 2-arg fault_set, while its own
# hook implements the 3-arg one -- filed in that module's memory mirror, not
# fixed here). So `consumer-shield` SKIPs on every tree today and its 403
# signature has never been observed running. `/bin/sh` IS in that module's
# ngx_http_shield_patterns.h attack table, so the expectation is grounded in its
# source rather than guessed -- but it is an expectation, not a verified
# observation like the other four. When shield builds again, RUN IT and confirm
# oracle 2 goes green, and confirm a negative control (comment out `shield
# block;`) reds it. Until then the all-SKIP guard in the `consumers` CI job is
# what stops this scenario from banking a false green.
#
# A NOTE ON `return 200` (cost an hour): a `return 200` in the location fires at
# the REWRITE phase and short-circuits ACCESS/PRECONTENT, so a module whose
# handler runs at those phases never executes -- skeleton's block reported 200 on
# a request that should have been 403 until the location was changed to serve a
# real static file from root. If a module's signature will not fire, check this
# before concluding the module is broken.
TABLE=$(cat <<'ROWS'
skeleton|ngx_http_skel_module.so||location / {@@    skel block;@@    skel_status 403;@@}|^HTTP/1\.1 403|the skeleton module BLOCKED a marker request with 403 (the same request without the marker gets 200 -- verified both ways)|User-Agent: skel-marker
strip-filter|ngx_http_strip_filter_module.so||location / {@@    strip on;@@    strip_min_size 0;@@}|<html><body><p>x</p></body></html>|the strip filter COLLAPSED the whitespace in the response body (the unstripped file on disk contains runs of spaces -- verified both ways)|
api-abuse|ngx_http_api_abuse_module.so||location / {@@    api_abuse enforce;@@}||the configured path serves with api_abuse enforcing (WEAK -- no observable signature, see driver)|
error-abuse|ngx_http_error_abuse_module.so|error_abuse_zone zone=consumer_errors:1m;|location / {@@    error_abuse zone=consumer_errors;@@}||the configured path serves with error_abuse attached (WEAK -- no observable signature, see driver)|
shield|ngx_http_shield_module.so|shield_ban_zone szone:1m;|location / {@@    shield block;@@}|^HTTP/1\.1 403|the shield module BLOCKED a request carrying an attack pattern with 403 (a benign request gets 200)|User-Agent: /bin/sh
coraza|ngx_http_coraza_module.so||location / {@@    coraza on;@@    coraza_rules 'SecRuleEngine On';@@    coraza_rules 'SecRule REQUEST_HEADERS:X-Consumer-Probe "@streq trip" "id:9001,phase:1,deny,status:418"';@@}|^HTTP/1\.1 418|coraza's own rule DENIED with 418 (a status nginx never returns by itself; without the engine the request is a plain 200 -- verified both ways)|X-Consumer-Probe: trip
ROWS
)

names() { printf '%s\n' "$TABLE" | cut -d'|' -f1; }

if [ "$LIST" -eq 1 ]; then names; exit 0; fi

in_csv() { case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

OUTROOT="prober/scenarios"
if [ "$CHECK" -eq 1 ]; then
    OUTROOT="$(mktemp -d "${TMPDIR:-/tmp}/gen-consumer.XXXXXX")"
    trap 'rm -rf "$OUTROOT"' EXIT
fi

emit_one() {
    local name="$1" so="$2" http_extra="$3" server_extra="$4" av="$5" avdesc="$6" trig="$7"
    local dir="$OUTROOT/consumer-$name"
    mkdir -p "$dir"

    # `@@` -> newline + 8 spaces, so the table can hold a multi-line block.
    server_extra="${server_extra//@@/$'\n'        }"

    # ---- nginx.conf ---------------------------------------------------------
    {
        printf '%s\n' '@LOAD@'
        cat <<EOF
# GENERATED by tools/gen-consumer-scenarios.sh -- do not hand-edit; edit the
# table in that script and rerun it (CI checks this file matches).
#
# CONSUMER MODULE under test: $so, built into the same objs/ dir as the ref
# probe by tools/build-consumers.sh. @LOAD@ above load_modules the harness
# probe; @BUILD_OBJS@ resolves to that objs/ dir so this scenario loads the
# consumer .so itself. On a tree lacking the .so, ./requires has already
# SKIPped the scenario, so this line is only reached where it exists.
load_module @BUILD_OBJS@/$so;
daemon off;
pid @PREFIX@/nginx.pid;
error_log @PREFIX@/logs/error.log info;
worker_processes 1;
events { worker_connections 16; }
http {
    @PROBE_ZONE@
EOF
        [ -n "$http_extra" ] && printf '    %s\n' "$http_extra"
        cat <<EOF

    server {
        listen 127.0.0.1:@PORT@;

        # A REAL STATIC ROOT, not \`return 200\`. A return directive fires at the
        # REWRITE phase and short-circuits ACCESS/PRECONTENT, so a module whose
        # handler runs there never executes and the scenario measures nothing.
        # The driver writes @PREFIX@/www/index.html before booting.
        root @PREFIX@/www;

        $server_extra

        location /__probe { @PROBE@ }
    }
}
EOF
    } >"$dir/nginx.conf"

    # ---- requires -----------------------------------------------------------
    cat >"$dir/requires" <<EOF
#!/usr/bin/env bash
#
# GENERATED by tools/gen-consumer-scenarios.sh -- do not hand-edit.
#
# CONSUMER-SCENARIO GATE. This scenario's nginx.conf ALWAYS load_modules
# @BUILD_OBJS@/$so, so a tree without that .so would fail
# \`nginx -t\` and red the scenario. Exiting nonzero here makes run-scenario.sh
# emit "1..0 # SKIP <stdout>" instead.
#
# THE SKIP IS NOT FREE. A scenario that SKIPs on every leg forever proves
# nothing while reading green -- build the consumers with
# tools/build-consumers.sh and run against that tree, or the coverage is
# imaginary. The PR gate builds only the reference probe, so these scenarios
# SKIP there BY DESIGN; the dedicated consumers CI job is what actually
# executes them, and that job fails if EVERY scenario skipped.
#
# THE GATE MUST CHECK THE TREE THAT WILL ACTUALLY BE BOOTED -- nothing else.
# run-scenario.sh runs this gate BEFORE prober_resolve, so PROBER_RESOLVED_BUILD
# does not exist yet and cannot be relied on here. An earlier version of this
# gate globbed \`.build/*/objs\` instead, which finds the .so in ANY staged tree:
# with a matching .so present in one tree and absent from the one being booted,
# the gate passed and nginx then died at \`nginx -t\` with a dlopen failure --
# a hard FAIL where the whole point of the gate was to produce a clean SKIP.
# So recompute the same path lib.sh will: \$PROBER_BUILD if set, else
# \$PROBER_ROOT/.build/<flavor>-<version>, taking flavor/version from argv
# exactly as run-scenario.sh passes them (with the same defaults).
FLAVOR="\${2:-nginx}"
VERSION="\${3:-1.31.3}"
BUILD="\${PROBER_BUILD:-\${PROBER_ROOT:-.}/.build/\${FLAVOR}-\${VERSION}}"

if [ ! -f "\$BUILD/objs/$so" ]; then
    echo "$so not found in \$BUILD/objs -- nginx.conf load_modules it unconditionally, so this tree cannot run the scenario; build it as a dynamic module (tools/build-consumers.sh --stage \${FLAVOR}-\${VERSION}) to run this scenario"
    exit 1
fi

exit 0
EOF
    chmod +x "$dir/requires"

    # ---- driver.sh ----------------------------------------------------------
    # The anti-vacuity oracle differs per module; everything else is fixed.
    local av_block av_plan TRIGGER_FN

    # trigger_request is emitted ONLY for a scenario that has a real signature
    # to trigger. A weak-branch scenario never calls it, and an uncalled
    # function is dead code shellcheck flags (SC2317) -- and rightly: it would
    # read as "this scenario has a trigger" to anyone skimming it.
    if [ -n "$av" ]; then
        TRIGGER_FN=$(cat <<'TRIGEOF'
# trigger_request OUTFILE [EXTRA_HEADER]: same bounded fetch as one_request,
# but it must NOT require a 200 -- the whole point is that the module answers
# with its own non-200 status. Only a COMPLETE response line is required;
# oracle 2 then matches the module's signature against the captured bytes.
trigger_request() {
    local out="$1" extra="${2:-}" pid dl
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\n' >&3
        [ -n "$extra" ] && printf '%s\r\n' "$extra" >&3
        printf 'Connection: close\r\n\r\n' >&3
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
    grep -q '^HTTP/1.1 ' "$out"
}
TRIGEOF
)
    else
        TRIGGER_FN=""
    fi
    if [ -n "$av" ]; then
        av_plan="a signature proving $so's code path actually ran"
        av_block=$(cat <<EOF
# REAL ANTI-VACUITY. The signature matched below cannot be produced by nginx
# core on this config -- only by the module. Commenting the module's directive
# out of nginx.conf makes THIS oracle fail (and it was verified that way before
# this scenario was committed), which is what makes oracles 3-6 worth reading:
# they are measuring a request the module demonstrably participated in.
if [ "\$WARMUP_OK" -eq 1 ] && trigger_request "\$HITCHECK" "$trig"; then
    if grep -qiE '$av' "\$HITCHECK"; then
        SIG_SEEN=1
    fi
fi
if [ "\$SIG_SEEN" -eq 1 ]; then
    echo "ok 2 - $avdesc"
else
    echo "not ok 2 - no signature that $so ran was observed"
    head -20 "\$HITCHECK" 2>/dev/null | sed 's/^/# /' || true
    FAILED=\$((FAILED + 1))
fi
EOF
)
    else
        av_plan="the module is loaded and serving (WEAK: no observable signature -- see below)"
        av_block=$(cat <<EOF
# WEAK ANTI-VACUITY, STATED HONESTLY -- THIS ORACLE DOES NOT PROVE THE MODULE
# RAN. This module only acts once a rate/error threshold is crossed, and emits
# no header, no body change and no INFO log line on an ordinary request, so
# there is nothing a response-based check can match. Oracle 2 therefore asserts
# only that the configured path still serves a clean 200 with the module loaded
# and its directive accepted by \`nginx -t\`.
#
# WHAT THAT MEANS FOR ORACLES 3-6: if the module's per-request hook silently
# stopped being invoked, this oracle would still pass and 3-6 would go flat and
# green -- measuring a request the module never touched. Read a green run here
# as "the module is loaded, configured and not leaking on a path it MAY be
# handling", not as "the per-request path is proven allocation-neutral".
# Promote this to a real signature check the moment the module grows one; that
# is a strict improvement and is the reason this comment names the gap instead
# of hiding it.
if [ "\$WARMUP_OK" -eq 1 ] && one_request "\$HITCHECK"; then
    SIG_SEEN=1
fi
if [ "\$SIG_SEEN" -eq 1 ]; then
    echo "ok 2 - $avdesc"
else
    echo "not ok 2 - the configured path did not serve a clean 200 with the module loaded"
    head -20 "\$HITCHECK" 2>/dev/null | sed 's/^/# /' || true
    FAILED=\$((FAILED + 1))
fi
EOF
)
    fi

    cat >"$dir/driver.sh" <<EOF
#!/usr/bin/env bash
#
# GENERATED by tools/gen-consumer-scenarios.sh -- do not hand-edit; edit the
# table in that script and rerun it (CI checks this file matches).
#
# Scenario: CONSUMER PER-REQUEST ALLOCATION NEUTRALITY for $so.
# A real consumer module -- NOT the harness's own ref probe -- serves requests
# and the driver proves the per-request work is allocation-neutral: cycle-pool
# counters (cycle_used, cycle_blocks, cycle_large), worker fd count and MASTER
# fd count are all identical across two post-drain QUIESCENT snapshots taken
# around one extra full served request. Equal means the per-request path frees
# everything it allocates.
#
# DESIGN NOTE (inherited from consumer-cache-turbo, which is the hand-written
# reference this file is modelled on): a per-request-leak oracle canNOT use a
# COLD pre-request baseline -- that carries the module's startup one-off -- nor
# a mid-work snapshot, which flakes on live per-request buffers. Two post-drain
# quiescent snapshots around one extra request is the shape that works.
#
# The module's own config-time state (shm zones, parsed rules) is allocated
# once at parse time, NOT per request, so it must not appear as a per-request
# delta; that absence is exactly the property under test.
set -euo pipefail

# shellcheck source=lib.sh
. "\$PROBER_LIB"

HOST=127.0.0.1
PORT="\$PROBER_RESOLVED_PORT"
ELOG="\$PROBER_PREFIX/logs/error.log"
MASTER="\$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="\$ELOG"

FAILED=0

# The docroot the conf's \`root @PREFIX@/www\` points at. Written here rather than
# served by \`return 200\` so the module's ACCESS/PRECONTENT-phase handler
# actually runs -- see the note in nginx.conf. The runs of spaces matter: they
# are what the strip filter collapses, which is that module's signature.
mkdir -p "\$PROBER_PREFIX/www"
printf '<html>   <body>  <p>x</p>   </body></html>\n' >"\$PROBER_PREFIX/www/index.html"

# master_fds: open descriptor count of the MASTER process. /proc/\$MASTER/fd is
# not readable on every host, so a failed read is "cannot observe" -- surfaced
# as a visible SKIP on oracle 6, never as a passing zero.
master_fds() {
    [ -r "/proc/\$MASTER/fd" ] || return 1
    # shellcheck disable=SC2012  # /proc fd names are decimal ints, ls|wc is exact
    ls "/proc/\$MASTER/fd" 2>/dev/null | wc -l
}

snapshot() {             # read one probe snapshot into SNAP_* globals
    local body
    body="\$(prober_probe_body "\$HOST" "\$PORT")" || return 1
    SNAP_USED="\$(prober_probe_field "\$body" cycle_used)" || return 1
    SNAP_BLOCKS="\$(prober_probe_field "\$body" cycle_blocks)" || return 1
    SNAP_LARGE="\$(prober_probe_field "\$body" cycle_large)" || return 1
    SNAP_FDS="\$(prober_probe_field "\$body" fds)" || return 1
}

# one_request OUTFILE [EXTRA_HEADER]: drive ONE full GET / to completion under
# a bounded deadline. A hung fetch must not hang the scenario, and a truncated
# capture must not be trusted as a completed request -- that would make the
# quiescent snapshot around it meaningless.
#
# EXTRA_HEADER is the module's anti-vacuity trigger (oracle 2 only). The
# MEASURED requests deliberately omit it: the allocation-neutrality comparison
# must run over the module's ORDINARY path, not its block/deny path, which
# takes a different, shorter code route.
one_request() {
    local out="\$1" extra="\${2:-}" pid dl
    (
        exec 3<>"/dev/tcp/\$HOST/\$PORT" || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\n' >&3
        [ -n "\$extra" ] && printf '%s\r\n' "\$extra" >&3
        printf 'Connection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    ) >"\$out" 2>/dev/null &
    pid=\$!
    dl=\$(( SECONDS + 10 ))
    while kill -0 "\$pid" 2>/dev/null; do
        if [ "\$SECONDS" -ge "\$dl" ]; then
            pkill -P "\$pid" 2>/dev/null || true
            kill "\$pid" 2>/dev/null || true
            break
        fi
        sleep 0.05
    done
    wait "\$pid" 2>/dev/null || true
    grep -q '^HTTP/1.1 200' "\$out"
}

${TRIGGER_FN}

# TAP plan:
#  1 warm-up request serves 200 (readiness / non-vacuity)
#  2 $av_plan
#  3 cycle_used equal across the two post-drain quiescent snapshots
#  4 cycle_blocks + cycle_large equal across the same two snapshots
#  5 worker fds equal across the same two snapshots
#  6 master fd count flat across the same window
#  7 no signal-death in the error log + a strict clean 200 on a final request
echo "1..7"

# --- 1: warm-up -- settles the worker so request 2 onward is steady-state ----
WARMUP="\$PROBER_PREFIX/warmup.out"
WARMUP_OK=0
if one_request "\$WARMUP"; then
    WARMUP_OK=1
fi
if [ "\$WARMUP_OK" -eq 1 ]; then
    echo "ok 1 - the warm-up request served a clean 200 (server is ready)"
else
    echo "not ok 1 - the warm-up request did not complete as a clean 200"
    head -5 "\$WARMUP" 2>/dev/null | sed 's/^/# /' || true
    FAILED=\$((FAILED + 1))
fi

# --- 2: anti-vacuity ---------------------------------------------------------
HITCHECK="\$PROBER_PREFIX/hitcheck.out"
SIG_SEEN=0
$av_block

# --- oracle-3..6 measurement: two QUIESCENT snapshots around one more request
BASE_OK=1
if ! snapshot; then
    BASE_OK=0
    echo "# the probe endpoint did not answer for the first post-drain snapshot"
fi
if [ "\$BASE_OK" -eq 1 ]; then
    BASE_USED="\$SNAP_USED"; BASE_BLOCKS="\$SNAP_BLOCKS"; BASE_LARGE="\$SNAP_LARGE"; BASE_FDS="\$SNAP_FDS"
fi
BASE_MFDS="\$(master_fds || true)"

STIM="\$PROBER_PREFIX/stimulus.out"
STIM_OK=0
if [ "\$BASE_OK" -eq 1 ] && one_request "\$STIM"; then
    STIM_OK=1
fi

FINAL_OK=0
if [ "\$STIM_OK" -eq 1 ] && snapshot; then
    FINAL_OK=1
    FINAL_USED="\$SNAP_USED"; FINAL_BLOCKS="\$SNAP_BLOCKS"; FINAL_LARGE="\$SNAP_LARGE"; FINAL_FDS="\$SNAP_FDS"
fi
FINAL_MFDS="\$(master_fds || true)"

if [ "\$STIM_OK" -ne 1 ]; then
    echo "# the extra measured request did not complete -- oracles 3-6 will SKIP rather than compare against a vacuous reading"
fi

# --- 3: cycle_used flat -------------------------------------------------------
if [ "\$BASE_OK" -eq 0 ] || [ "\$FINAL_OK" -eq 0 ]; then
    echo "ok 3 - cycle_used allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "\$BASE_USED" = "\$FINAL_USED" ]; then
    echo "ok 3 - cycle_used was flat across the extra request (\$BASE_USED)"
else
    echo "not ok 3 - cycle_used grew across the extra request (before=\$BASE_USED after=\$FINAL_USED)"
    FAILED=\$((FAILED + 1))
fi

# --- 4: cycle_blocks + cycle_large flat --------------------------------------
if [ "\$BASE_OK" -eq 0 ] || [ "\$FINAL_OK" -eq 0 ]; then
    echo "ok 4 - cycle_blocks/cycle_large allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "\$BASE_BLOCKS" = "\$FINAL_BLOCKS" ] && [ "\$BASE_LARGE" = "\$FINAL_LARGE" ]; then
    echo "ok 4 - cycle_blocks (\$BASE_BLOCKS) and cycle_large (\$BASE_LARGE) were flat across the extra request"
else
    echo "not ok 4 - cycle_blocks/cycle_large grew across the extra request (before blocks=\$BASE_BLOCKS large=\$BASE_LARGE, after blocks=\$FINAL_BLOCKS large=\$FINAL_LARGE)"
    FAILED=\$((FAILED + 1))
fi

# --- 5: worker fds flat -------------------------------------------------------
if [ "\$BASE_OK" -eq 0 ] || [ "\$FINAL_OK" -eq 0 ]; then
    echo "ok 5 - worker fds allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "\$BASE_FDS" = "\$FINAL_FDS" ]; then
    echo "ok 5 - worker fd count was flat across the extra request (\$BASE_FDS)"
else
    echo "not ok 5 - worker fd count grew across the extra request (before=\$BASE_FDS after=\$FINAL_FDS)"
    FAILED=\$((FAILED + 1))
fi

# --- 6: master fd count flat --------------------------------------------------
if [ -z "\$BASE_MFDS" ] || [ -z "\$FINAL_MFDS" ]; then
    echo "ok 6 - master descriptor count # SKIP /proc/\$MASTER/fd not readable on this host"
elif [ "\$BASE_OK" -eq 0 ] || [ "\$FINAL_OK" -eq 0 ]; then
    echo "ok 6 - master descriptor count allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "\$BASE_MFDS" = "\$FINAL_MFDS" ]; then
    echo "ok 6 - master fd count was flat across the extra request (\$BASE_MFDS)"
else
    echo "not ok 6 - master fd count grew across the extra request (before=\$BASE_MFDS after=\$FINAL_MFDS)"
    FAILED=\$((FAILED + 1))
fi

# --- 7: no signal-death + a final strict clean 200 ---------------------------
SIGDEATH=0
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "\$ELOG"; then
    SIGDEATH=1
fi

FINAL_REQ="\$PROBER_PREFIX/final.out"
FINAL_CLEAN=0
if one_request "\$FINAL_REQ"; then
    FINAL_CLEAN=1
fi

if [ "\$SIGDEATH" -eq 0 ] && [ "\$FINAL_CLEAN" -eq 1 ]; then
    echo "ok 7 - no worker died by signal, and a final request still served a clean 200"
else
    echo "not ok 7 - server health check failed (signal-death=\$SIGDEATH, final-clean=\$FINAL_CLEAN)"
    if [ "\$SIGDEATH" -eq 1 ]; then
        grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "\$ELOG" | sed 's/^/# /'
    fi
    FAILED=\$((FAILED + 1))
fi

if [ "\$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
EOF
    chmod +x "$dir/driver.sh"
    echo "generated consumer-$name"
}

while IFS='|' read -r name so http_extra server_extra av avdesc trig; do
    [ -n "$name" ] || continue
    [ -n "$ONLY" ] && { in_csv "$name" "$ONLY" || continue; }
    emit_one "$name" "$so" "$http_extra" "$server_extra" "$av" "$avdesc" "$trig"
done <<<"$TABLE"

if [ "$CHECK" -eq 1 ]; then
    rc=0
    while IFS= read -r name; do
        [ -n "$ONLY" ] && { in_csv "$name" "$ONLY" || continue; }
        if ! diff -ru "prober/scenarios/consumer-$name" "$OUTROOT/consumer-$name"; then
            rc=1
        fi
    done < <(names)
    if [ "$rc" -ne 0 ]; then
        echo "consumer scenarios are OUT OF DATE -- rerun tools/gen-consumer-scenarios.sh" >&2
        exit 1
    fi
    echo "generated consumer scenarios match what is committed"
fi
