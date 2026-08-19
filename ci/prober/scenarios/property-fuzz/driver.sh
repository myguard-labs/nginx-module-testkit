#!/usr/bin/env bash
#
# Scenario: property-fuzz -- no matter what REQUEST SHAPE or TRANSPORT/UPSTREAM
# FAULT is thrown at the worker, it leaks no fds, leaks no request-pool memory,
# and stays alive. Every other scenario in this tree hand-writes a fixed list
# of adversarial shapes; this one draws them from a small checked-in corpus
# through a deterministic PRNG so the shape SPACE explored can grow (add a
# .frag file) without anyone hand-writing a new case, while staying perfectly
# reproducible between a fast run and a slow (ASan) one.
#
# THE PROPERTY, PRECISELY. For each of a FIXED number of generated cases:
#   delta fds == 0             -- the request's descriptors were all released
#   delta pool.cycle_used == 0 -- nothing was left in the long-lived cycle pool
#   worker stayed alive        -- the DEFAULT oracle every rule-file case gets
#                                  (see README's `pid_may_change` section): if
#                                  the worker the master answers with changes
#                                  pid mid-case, that case fails, full stop. We
#                                  do not set `pid_may_change` anywhere in the
#                                  generated rule, so a crash-and-respawn on ANY
#                                  generated case is a hard failure, not a
#                                  quietly-passed retry.
# All three ride on the stock `.rule` DSL and the stock prober -- no new C code
# anywhere in this scenario, exactly as F1 requires.
#
# WHY A FIXED ITERATION COUNT, NOT A TIME BUDGET. A wall-clock budget makes the
# fast (plain) leg and the slow (ASan-instrumented) leg run DIFFERENT programs:
# the fast leg gets through more iterations than the ASan leg in the same
# wall-clock window, so a failure that only reproduces past iteration K on the
# fast leg may never be reached under ASan, and a bisection across legs chases
# a program that never existed on the other side. NUM_CASES below is a
# constant (40): whatever ran on the box that found a bug is exactly what runs
# on the box replaying it, ASan-instrumented or not, fast or slow.
#
# WHY xorshift64 IN awk, NOT $RANDOM. $RANDOM's generator is
# implementation-defined per bash build (see the bash manual: "there is no
# guarantee ... will produce a sequence of numbers that cannot be reasonably
# predicted" -- it does not even promise the SAME sequence for the same seed
# across bash versions). A harness whose reproducibility depends on which
# bash happens to be installed on the CI runner that day is exactly the
# "fails only in CI, never locally" trap this repo keeps re-learning. gawk's
# xor/lshift/rshift are a fixed, specified bitwise contract; given the same
# seed they produce the same stream on any box with gawk installed, which is
# why `requires` SKIPs rather than degrading to a different generator when
# gawk is absent.
#
# WHAT "xorshift64 in awk" ACTUALLY GUARANTEES HERE. gawk's bitwise functions
# convert through a C integer type at the boundary, and 64 bits of state
# fed through three shift/xor rounds is exactly the classic George Marsaglia
# xorshift64 core -- see gen_stream() below. This scenario's determinism claim
# does NOT depend on that stream being statistically excellent (this is a
# corpus PICKER, not a cryptographic generator); it depends only on it being
# REPRODUCIBLE and SEED-SENSITIVE, both of which are proven as real TAP
# assertions below (tests 1 and 2), not asserted in a comment and left
# unchecked.
#
# THE CORPUS (corpus/*.frag). Each file is ONE fully-formed, already-escaped
# request (the same \r \n \t \\ \" \0 \xNN escaping a rule file's `send` uses),
# so a regression is pinned by adding one file -- a one-file, reviewable PR,
# with no driver.sh change required. Ten fragments ship: a plain GET, mixed
# header casing, an oversize header value (forces the large_client_header_buffers
# promotion path in nginx.conf), a request with no Host header, an unusual
# method, a chunked POST body, a query string carrying NUL/percent-escapes and
# a directory-traversal-shaped path, a bare HTTP/1.0 request, a duplicated
# Host header, and a header value carrying embedded NUL/control bytes. None of
# them is malformed enough to make the SERVER hang waiting for more bytes --
# that would stall the generator's own read, which is a driver bug, not a
# finding this property exists to catch (slowloris-shaped stalls are already
# covered by rules/stock/slowloris.rule and are out of scope here).
#
# THE BACKEND LEG (backend, nginx.conf's /mc). Fd/pool leaks on the WORKER'S
# error path are disproportionately likely to live in
# ngx_http_upstream_finalize_request -- code that runs only when the upstream
# misbehaves, which is exactly the code a request-shape-only fuzzer never
# reaches. A quarter of the generated cases (route == 0, see gen_stream)
# therefore skip the corpus entirely and hit /mc?key=kN instead, a location
# that proxy_passes to fakesrv over memcached. ./backend is a STATIC,
# checked-in fault script -- it cannot be generated per-run, because
# run-scenario.sh boots the backend from that file BEFORE driver.sh (this
# script) ever runs, substituting @BACKEND_PORT@ into the conf ahead of
# render. Its 40 fault stanzas (truncate/rst/accept_close/lie_bytes, cycling)
# are keyed by memcached `get` OCCURRENCE, which is why the driver counts its
# own backend-routed cases in order (backend_n below) rather than using the
# overall iteration index -- get:1 must land on the FIRST backend case, not
# generated case number 1. The stanza count is 40 (not 20) because this fakesrv
# is one process whose get:N counter spans BOTH prober runs (test 3 + the test-4
# replay), so the replay's backend cases continue at get:K+1.. and must still
# land on a real fault rather than an inert past-the-end slot -- see ./backend's
# header ("WHY 40, NOT 20") for the full reasoning and the verdict-level (not
# identical-stream) fidelity this gives the replay.
#
# THE OTHER TRANSPORT FAULT (fate, see gen_stream). A third of the
# non-backend cases additionally `abort` the connection partway through the
# request, and another third `shutdown 1` (half-close) after sending it in
# full -- the same two client-side failure shapes conn-delta's hand-written
# error-path battery exercises, now drawn at random over the whole corpus
# instead of over one fixed request.
#
# THE ORACLE IS THE STOCK ONE, ON PURPOSE. Every generated case carries
# `delta fds == 0` and `delta pool.cycle_used == 0`, identical to conn-delta
# and soak-delta -- see those scenarios' own extensive comments on why
# `connections.free`/`pool.cycle_used` and not their `total`/ceiling cousins.
# This scenario adds no new oracle; it only widens what gets thrown at the
# existing one.
#
# --- non-vacuity: three claims, three proofs -------------------------------
#
# 1. LEAK ORACLE IS LIVE (a real leak would be CAUGHT, not rubber-stamped).
#    Cannot be wired into mutate.sh cleanly: the leak this property hunts is
#    reported by ngx_test_probe_json() in src/ngx_test_probe.c, which compiles
#    INTO the nginx/angie module binary -- catching a mutation there needs a
#    full module rebuild (`configure --add-dynamic-module=... && make modules`),
#    which is far outside mutate.sh's per-mutant budget (it only reruns
#    ./build.sh, the PROBER's own build, never the module's). Proven instead
#    as a documented, MANUALLY-RUN negative control, the sanctioned fallback:
#
#      Mutation:  src/ngx_test_probe.c, ngx_test_probe_json(), changed
#                     fds = ngx_test_probe_fd_count();
#                 to
#                     { static ngx_int_t drift = 0; drift++;
#                       fds = ngx_test_probe_fd_count() + drift; }
#                 -- a fake fd count that grows by one on every single probe
#                 call (arming request, before-snapshot, after-snapshot), so
#                 `delta fds == 0` sees a nonzero drift on every case: a stand-
#                 in for "the module leaks one descriptor per request".
#      Rebuild:   nginx 1.29.0 objs/, `make modules`, .so copied over
#                 .build/nginx-1.29.0/objs/ngx_http_test_ref_module.so
#                 (clean .so and .c backed up first).
#      Result:    RED -- every generated case's `delta fds == 0` failed
#                 (consistent nonzero drift per case). Clean .c and .so restored
#                 immediately after and reconfirmed green before moving on.
#
# 2. PRNG IS NOT STUCK (same seed -> byte-identical rule; seed+1 -> different
#    rule). Proven as real TAP tests 1 and 2 below: this driver regenerates
#    the rule TWICE more, once with $SEED again and once with $SEED + 1, and
#    `cmp`s both against the saved generated rule. Mutation-tested live: see
#    mutate.sh's "property-fuzz: PRNG ignores its seed" entry, which changes
#    gen_stream()'s seed-adoption line so every seed collapses to the same
#    constant -- test 2 (seed+1 differs) goes red, caught.
#
# 3. REPLAY WORKS (the saved generated rule, re-run, reproduces the same
#    verdict -- so a CI failure is `./prober <the printed path>`, nothing
#    more). Proven as real TAP test 4 below: the driver re-invokes the prober
#    a second time against the EXACT SAME saved file from test 3 and diffs the
#    two TAP transcripts byte for byte. Mutation-tested live: see mutate.sh's
#    "property-fuzz: generated rule not persisted to the replay path" entry,
#    which redirects the save to a decoy file so what gets replayed is not
#    what test 3 actually ran against -- caught.
#
# On failure this driver's diagnostics always name the saved rule file, so a
# human reproduces a red run with exactly:
#   ./prober -H 127.0.0.1 -p <port> <the printed .generated.rule path>
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
SEED_FILE="$PROBER_SCENARIO/seed"
CORPUS_DIR="$PROBER_SCENARIO/corpus"

# The fixed iteration count. See the header: never a time budget.
NUM_CASES=40

GENRULE="$PROBER_PREFIX/property-fuzz.generated.rule"
SEEDPLUS_RULE="$PROBER_PREFIX/property-fuzz.seedplus1.rule"
SAMESEED_RULE="$PROBER_PREFIX/property-fuzz.sameseed.rule"
CHECK_LOG="$PROBER_PREFIX/logs/property-fuzz-check.log"
RUN1_LOG="$PROBER_PREFIX/logs/property-fuzz-run1.tap"
RUN2_LOG="$PROBER_PREFIX/logs/property-fuzz-run2.tap"

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

# --- the PRNG ----------------------------------------------------------
#
# xorshift64 (Marsaglia's classic 13/7/17 triple), seeded from $1, printing
# $2 lines of "frag route fate" -- three draws per generated case, drawn in
# that fixed order regardless of which branch a case ends up taking, so the
# stream a given seed produces never depends on earlier draws' outcomes.
#   frag  (mod NFRAG)  -- which corpus/*.frag this case sends, when direct
#   route (mod 4)      -- ==0 routes through the backend instead of the corpus
#   fate  (mod 3)      -- for a direct case only: 0 complete, 1 abort mid-way,
#                         2 half-close (shutdown) after sending in full
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
                x = xorshift64(x); frag = x % nfrag
                x = xorshift64(x); route = x % 4
                x = xorshift64(x); fate = x % 3
                printf "%d %d %d\n", frag, route, fate
            }
        }
    '
}

# build_rule SEED > rule-file
#
# Renders the fixed-count case sequence gen_stream draws for SEED into a
# complete .rule file on stdout.
build_rule() {
    local seed="$1"
    local i=0 backend_n=0
    local frag route fate name body key

    # Deliberately does NOT embed $seed's value in this comment: tests 1/2
    # below `cmp` two of these files whole-file to prove determinism, and a
    # seed-dependent header would make same-seed/different-seed comparisons
    # trivially right for the wrong reason -- differing on the header's own
    # text even if a mutated generator ignored the seed for every actual
    # case. The seed value itself is reported separately, in the TAP lines
    # around the cmp, not inside the compared file.
    cat <<'HDR'
# GENERATED by driver.sh -- do not hand-edit. Edit corpus/*.frag, ./backend,
# or ./seed and let the driver regenerate instead. See property-fuzz/
# driver.sh's header for what this file proves.
HDR
    echo

    while IFS=' ' read -r frag route fate; do
        i=$((i + 1))
        if [ "$route" -eq 0 ]; then
            backend_n=$((backend_n + 1))
            key="k${backend_n}"
            printf 'name    iteration %d: backend fault via /mc?key=%s\n' "$i" "$key"
            printf 'send    GET /mc?key=%s HTTP/1.1\\r\\n\n' "$key"
            printf 'send    Host: prober\\r\\nConnection: close\\r\\n\\r\\n\n'
        else
            name="${FRAGS[$frag]}"
            body="$(cat "$CORPUS_DIR/$name")"
            printf 'name    iteration %d: corpus/%s\n' "$i" "$name"
            printf 'send    %s\n' "$body"
            case "$fate" in
                1) printf 'abort    10\n' ;;
                2) printf 'shutdown 1\n' ;;
            esac
        fi
        printf 'delta   fds == 0\n'
        printf 'delta   pool.cycle_used == 0\n'
        echo
    done < <(gen_stream "$seed" "$NUM_CASES" "$NFRAG")
}

echo "1..4"

# --- test 1/2: the PRNG is deterministic and seed-sensitive -----------------
#
# Generated BEFORE the main rule is written, from the same gen_stream/build_rule
# this scenario's own run uses -- a divergent implementation living only in the
# test would prove the test, not the generator.
build_rule "$SEED" > "$GENRULE"
build_rule "$SEED" > "$SAMESEED_RULE"
SEED_PLUS_1=$((SEED + 1))
build_rule "$SEED_PLUS_1" > "$SEEDPLUS_RULE"

if cmp -s "$GENRULE" "$SAMESEED_RULE"; then
    echo "ok 1 - regenerating with the same seed ($SEED) is byte-identical"
else
    echo "not ok 1 - same seed produced a DIFFERENT rule (PRNG is not deterministic)"
    FAILED=1
fi

if cmp -s "$GENRULE" "$SEEDPLUS_RULE"; then
    echo "not ok 2 - seed+1 ($SEED_PLUS_1) produced the SAME rule (PRNG is stuck)"
    FAILED=1
else
    echo "ok 2 - seed+1 ($SEED_PLUS_1) produced a different rule"
fi

# --- load-time sanity before spending a server run on the file --------------
#
# A malformed generated rule is a driver bug, not a finding; catching it here
# (the same --check gate the README's mini-howto recommends) costs nothing
# next to a server boot, and failing loud here beats a confusing case-3 Bail.
if ! "$PROBER_CLIENT" --check "$GENRULE" >"$CHECK_LOG" 2>&1; then
    echo "Bail out! generated rule $GENRULE fails to parse:"
    sed 's/^/# /' "$CHECK_LOG"
    exit 1
fi

# --- test 3: the property itself, over the fixed 40-case batch -------------
#
# The prober's own TAP is embedded verbatim (indented), same idiom
# test-scenarios.sh uses for a whole scenario -- so a failing generated case
# names itself in the log with no translation needed.
RUN1_STATUS=0
"$PROBER_CLIENT" -H "$HOST" -p "$PORT" "$GENRULE" >"$RUN1_LOG" 2>&1 || RUN1_STATUS=$?
sed 's/^/    /' "$RUN1_LOG"

if [ "$RUN1_STATUS" -eq 0 ]; then
    echo "ok 3 - all $NUM_CASES generated cases held (fds/pool oracle, worker stayed alive)"
else
    echo "not ok 3 - a generated case failed the leak/alive oracle"
    echo "# generated rule: $GENRULE"
    FAILED=1
fi

# --- test 4: replay -- the saved file reproduces the same verdict ----------
#
# Re-running the EXACT SAME saved file (not a freshly generated one) is the
# whole point of persisting it to $PROBER_PREFIX in the first place: a
# consumer who sees this scenario go red in CI reproduces with nothing more
# than `./prober <that path>`. Diffed transcript, not just exit status, so a
# replay that passes for a DIFFERENT reason (a different case now fails) is
# still caught.
#
# ONE WRINKLE, DOCUMENTED, NOT A BUG: the shared fakesrv's get:N counter is not
# reset between run 1 and this replay (it is one process; the driver cannot
# restart it without re-rendering @BACKEND_PORT@), so the backend-routed cases
# here traverse a phase-shifted fault stanza (get:K+1..2K) rather than the same
# get:1..K stream run 1 saw. ./backend ships 40 stanzas precisely so both runs
# stay on a real fault; the guarantee this test makes is therefore verdict-level
# (leak/alive oracle reproduces, and a case flipping pass->fail is still caught),
# not that the underlying fault stanza is byte-identical across the two runs.
RUN2_STATUS=0
"$PROBER_CLIENT" -H "$HOST" -p "$PORT" "$GENRULE" >"$RUN2_LOG" 2>&1 || RUN2_STATUS=$?

if [ "$RUN1_STATUS" -eq "$RUN2_STATUS" ] && cmp -s "$RUN1_LOG" "$RUN2_LOG"; then
    echo "ok 4 - replaying the saved generated rule reproduces the same verdict"
else
    echo "not ok 4 - replaying $GENRULE did not reproduce test 3's verdict"
    echo "# generated rule: $GENRULE"
    diff -u "$RUN1_LOG" "$RUN2_LOG" | sed 's/^/# /' || true
    FAILED=1
fi

exit "$FAILED"
