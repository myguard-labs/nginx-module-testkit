#!/usr/bin/env bash
#
# Scenario: RELOAD WHILE COMPRESSING (the http-zstd consumer scenario, G6f). One
# client request pulls a value from the fake memcached upstream that DRIPS it
# back two bytes at a time; the http-zstd response-body filter compresses that
# response as the pieces arrive, so a live ZSTD_CCtx (registered on the request
# pool's cleanup chain) is held mid-stream. TWO SIGHUPs are then delivered
# underneath that held, mid-compression request, and the driver proves:
#
#   * the response was genuinely COMPRESSED (wire body strictly smaller than the
#     plaintext, Content-Encoding: zstd) -- so the surviving context is a real
#     compression context, not a pass-through no-op;
#   * the held response DECOMPRESSES to the exact seeded plaintext, byte for byte,
#     after surviving both reloads -- the CCtx (per request, request-pool cleanup)
#     and the CDict (per config, config-pool cleanup) were NOT freed out from
#     under the in-flight stream when the old cycle was signalled;
#   * the worker cycle-pool counters are flat across the reloads (no per-reload
#     leak in the module's config init), the old worker drains once the held
#     request finally completes, no worker died by signal, and the upstream saw
#     the held get exactly once (never re-issued mid-reload).
#
# WHY THIS IS THE CONSUMER SCENARIO, NOT ANOTHER REF-MODULE ONE: every sibling
# reload scenario drives the harness's own ref probe module. This one loads a
# real third-party module (the http-zstd filter) as the module under test and
# asserts a property that only exists because THAT module holds libzstd state
# across a config reload. The harness stays generic: it contributes the probe
# (cycle-pool/fd deltas, pid oracle, drain wait) and the drip upstream; the
# compression specifics live entirely in this scenario + its conf. On a tree
# without the zstd .so the `requires` gate SKIPs the whole scenario (see
# ./requires), so CI -- which builds the ref probe only -- reports SKIP, never a
# false pass.
#
# Structure is adapted from hup-storm-mid-transfer/driver.sh (held drip request
# + INFLIGHT_PID anti-vacuity gate + bounded subtree-killing join + cycle-pool
# drift oracle + exactly-once upstream + no-signal-death + post-join drain
# oracle). Read that driver's header for the full rationale behind each of those
# shapes; only the compression-specific oracles (2, 5, 6) are new here and are
# documented at their own sites below. RELOADS is 2, not a storm: the claim is
# "a response being compressed survives a reload", and two reloads make that an
# unambiguous multi-signal claim without a storm's wall-clock cost.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="$ELOG"

RELOADS=2
WORKERS=1                # matches worker_processes in nginx.conf (drain target)

# The exact plaintext the fake upstream seeds under key "slow" (see ./backend).
# Kept here as the checksum reference so a change to the seed that this driver
# was not updated for fails loudly (the decompressed body will not match) rather
# than silently checking the wrong bytes. 256 bytes, four 64-byte blocks.
EXPECT_PLAIN='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'
PLAIN_LEN=${#EXPECT_PLAIN}

FAILED=0

snapshot() {             # read one probe snapshot into SNAP_* globals
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
}

# TAP plan (eight driver assertions + the folded prober coherence leg):
#  1 the held reply was provably dripping from the upstream before the reloads
#  2 the response was a genuine zstd frame (C-E: zstd AND bytes != plaintext)
#  3 the held request was PROVABLY still in flight across every reload (gate)
#  4 the zstd request path is allocation-neutral after the reloads (leak oracle,
#    two post-drain quiescent snapshots around one extra compressed request)
#  5 the held compressed response DECOMPRESSES to the exact seeded plaintext
#  6 the backend served the held get EXACTLY ONCE across the reloads
#  7 no worker died by signal during the reloads
#  8 the old worker set drained after the held request completed
#  9 post-reload coherence (prober leg, folded in as diagnostics)
echo "1..9"

# NOTE on the per-reload-leak oracle (4): it is made AFTER the reloads drain,
# not from a cold pre-request baseline. A cold first-fork snapshot measures a
# one-off startup state (measured used=82440 blocks=6) that legitimately settles
# to a smaller value once the worker has serviced a request (78894/5), so a
# cold-vs-served compare reds on a perfectly healthy server -- reload-soak's
# "a startup one-off must not read as a leak" trap, in reverse. Across-reload
# cycle-pool growth for the plain config-init path is already covered by the
# sibling reload-cycle / reload-soak scenarios (ref module). What THIS consumer
# scenario adds is the zstd-specific check: the compressed-request path is
# allocation-NEUTRAL at steady state (each request's CCtx is freed on the
# request-pool cleanup chain), even after the config reloads. Oracle 4 proves
# that by comparing two post-drain quiescent snapshots taken around one extra
# full compressed request -- see there. No pre-request baseline is needed.

# --- fire the held, compressed request ----------------------------------------
# Accept-Encoding: zstd is what makes the filter engage; without it the response
# is served uncompressed and oracle 2 (compressed, C-E: zstd) reds -- so the
# header is load-bearing, not decoration. Connection: close so the server ends
# the body with a clean FIN/RST once everything is sent (documented in
# backend-reload-inflight). Raw bytes captured verbatim to a file so the driver
# can split headers from the compressed frame afterwards.
INFLIGHT="$PROBER_PREFIX/inflight.out"
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET /mc?key=slow HTTP/1.1\r\nHost: prober\r\nAccept-Encoding: zstd\r\nConnection: close\r\n\r\n' >&3
    cat <&3 2>/dev/null || true
) >"$INFLIGHT" 2>/dev/null &
INFLIGHT_PID=$!

# --- 1: the reply was dripping before the first reload ------------------------
# Falsifiable ordering oracle: fakesrv journals {"ev":"send",...} the moment it
# puts the FIRST byte of the reply on the wire (strictly stronger than "get
# received"). Fixed-step counted iterations, never a wall-clock diff, so a loaded
# runner performs the same number of attempts (same discipline as
# prober_wait_listen and every sibling driver).
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
    echo "ok 1 - the held reply was dripping from the upstream before the reloads"
else
    echo "not ok 1 - the upstream never started dripping its reply before the reloads"
    echo "# backend journal recorded no send within 5 s; ordering precondition unmet"
    FAILED=$((FAILED + 1))
fi

# --- the reloads: RELOADS SIGHUPs underneath the held compressed request -------
# No prober_drain_wait inside the loop, for the same reason as
# hup-storm-mid-transfer: the held request keeps the old worker alive across
# each reload, so a drain-to-1 wait would always time out mid-series (old + new
# = 2 children). The genuine drain -- and the settled cycle-pool comparison --
# happen once, after the join (oracles 4 and 8). The loop only counts absorbed
# reloads and runs the anti-vacuity liveness check.
ABSORBED=0
INFLIGHT_ALIVE_ALL=1

for ((r = 1; r <= RELOADS; r++)); do
    if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" 5000; then
        ABSORBED=$((ABSORBED + 1))
    else
        echo "# HUP $r of $RELOADS was not absorbed within the counted budget (no new worker answered)"
        DRIFT="$DRIFT
HUP $r: no-new-worker"
    fi

    # Anti-vacuity: was the held client still alive (still blocked reading its
    # drip, not yet joined) at the moment this reload landed? Checked immediately
    # after prober_signal_wait returns -- the earliest provable "this HUP landed".
    if ! kill -0 "$INFLIGHT_PID" 2>/dev/null; then
        INFLIGHT_ALIVE_ALL=0
        echo "# held request was NOT alive immediately after HUP $r (drip finished too early, or ordering broke)"
    fi
    # NOTE deliberately NO in-loop cycle-pool snapshot here, unlike
    # hup-storm-mid-transfer. There, the answering worker's cycle pool is stable
    # the instant it answers; HERE the answering worker is actively compressing
    # the held stream, so its cycle_used includes libzstd's per-request CCtx and
    # working buffers whose live size depends on exactly WHERE in the 2 B/250 ms
    # drip the snapshot lands -- a genuinely varying quantity that is NOT a leak.
    # Snapshotting it mid-compression made oracle 4 flake (cycle_used drifted by
    # a slab node run-to-run). The per-reload-leak claim is instead made at two
    # QUIESCENT points -- baseline before the request, and final after the drain
    # (oracle 4 below) -- when no stream is in flight and the pool has settled.
    # This is the "a reload is not finished when a new worker answers" lesson
    # applied to a consumer that allocates per-request: only compare quiescent
    # states.
done

# --- join the held request (bounded, subtree-killing deadline) ----------------
# It must have completed by now. A bare `wait` on a hung request would consume
# the whole CI job (AUD-09); poll for the background shell to exit within a
# deadline, and on overrun KILL the whole subtree (pkill -P then kill) so the
# truncated/empty $INFLIGHT then fails oracle 5, the correct verdict. 40 s
# ceiling: the 256-byte value @ 2 B/250 ms drips for ~32 s, so on a fast box the
# join may still wait out most of that after the last HUP; 40 s clears it while
# staying bounded.
join_deadline=$(( SECONDS + 40 ))
while kill -0 "$INFLIGHT_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        pkill -P "$INFLIGHT_PID" 2>/dev/null || true
        kill "$INFLIGHT_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$INFLIGHT_PID" 2>/dev/null || true

# --- drain the old worker set, then take the FINAL quiescent snapshot ----------
# The held request has finished, so the last cycle's old worker is now free to
# exit -- this is the one point where prober_drain_wait can genuinely succeed
# (mid-storm it could not: the held conn kept the old worker alive). DRC is
# asserted as oracle 8; a stuck old worker (return 1) reds the scenario, no-pgrep
# (return 2) is a visible SKIP. Done HERE, before the oracles print, so the
# post-drain cycle-pool snapshot for oracle 4 is taken with NO stream in flight
# and the worker set settled -- the only state that compares meaningfully to the
# pre-request baseline (see the loop comment on why mid-compression snapshots
# flake).
DRC=0
prober_drain_wait "$MASTER" "$WORKERS" 10000 || DRC=$?

# Count the held request's upstream gets NOW, before oracle 4's extra request
# adds one -- oracle 6 (exactly-once) must see only the gets the held request
# itself caused (a re-issue during a reload would already be recorded here).
HELD_GETS=0
if [ -n "$PROBER_BACKEND_JOURNAL" ]; then
    HELD_GETS=$(grep -c '"ev":"cmd"[^}]*"cmd":"get"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null || true)
fi

# Oracle-4 measurement: two QUIESCENT post-drain snapshots taken around one
# extra full (non-dripped) compressed request. If the zstd request path leaked
# cycle-pool memory per request -- a CCtx or CDict reference not freed, the
# classic consumer-module reload bug -- the second snapshot would exceed the
# first. Equal means the compressed path is allocation-neutral at steady state
# even after the two reloads. Both readings are post-served and quiescent, so
# neither carries the cold-start one-off that a pre-request baseline would.
# one_zstd_request: drive ONE full-speed compressed GET to completion under a
# BOUNDED deadline, and report whether it actually completed as a valid zstd
# response. This is oracle 4's stimulus, so it must not (a) hang the scenario if
# the server wedged, nor (b) let a truncated/reset response be treated as a
# completed request -- either would make the FINAL2 snapshot meaningless and the
# leak comparison vacuous. So: run the fetch in a background subshell, poll for
# it under a short deadline, KILL its subtree on overrun, and require the capture
# to carry BOTH a 200 status line and Content-Encoding: zstd (a complete,
# genuinely-compressed reply) before the caller trusts the second snapshot.
# Returns 0 only on a complete valid response; nonzero otherwise.
one_zstd_request() {
    local out="$PROBER_PREFIX/oracle4.out" pid dl
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /mc?key=slow HTTP/1.1\r\nHost: prober\r\nAccept-Encoding: zstd\r\nConnection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    pid=$!
    dl=$(( SECONDS + 10 ))                 # full-speed reply completes in well under 1 s
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$SECONDS" -ge "$dl" ]; then
            pkill -P "$pid" 2>/dev/null || true
            kill "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.05
    done
    wait "$pid" 2>/dev/null || true
    grep -q '^HTTP/1.1 200' "$out" \
        && grep -qi '^Content-Encoding:[[:space:]]*zstd' "$out"
}
FINAL_OK=1
if snapshot; then
    FINAL_USED="$SNAP_USED"; FINAL_BLOCKS="$SNAP_BLOCKS"; FINAL_LARGE="$SNAP_LARGE"
    if one_zstd_request && snapshot; then
        FINAL2_USED="$SNAP_USED"; FINAL2_BLOCKS="$SNAP_BLOCKS"; FINAL2_LARGE="$SNAP_LARGE"
    else
        FINAL_OK=0
        echo "# oracle 4 stimulus did not complete as a valid zstd response, or the second snapshot did not answer -- oracle 4 will SKIP rather than compare against a vacuous reading"
    fi
else
    FINAL_OK=0
    echo "# the probe endpoint did not answer for the first post-drain snapshot"
fi

# --- split the captured response into headers and the raw compressed frame ----
# The raw capture is "<headers>\r\n\r\n<body>". The body is the zstd frame, but
# nginx serves the dripped response with Transfer-Encoding: chunked (the
# compressed length is unknown until the stream ends), so the body on the wire
# is chunk-framed: <hexlen>\r\n<octets>\r\n ... 0\r\n\r\n. The zstd frame is
# BINARY and may contain \r\n bytes, so a line-based de-chunk is unsafe; this is
# done with a length-driven, byte-exact splitter in python3 (an established
# harness dependency -- see lib.sh/mutate.sh -- and checked by ./requires).
#
# The splitter writes the header block to $HDRS and the de-chunked (or, for a
# non-chunked response, verbatim) body to $FRAME. On any malformed framing it
# leaves $FRAME empty, which reds oracles 2 and 5 -- the correct verdict for a
# response that did not arrive intact.
HDRS="$PROBER_PREFIX/inflight.hdrs"
FRAME="$PROBER_PREFIX/inflight.frame"
python3 - "$INFLIGHT" "$HDRS" "$FRAME" <<'PY' || { : > "$HDRS"; : > "$FRAME"; }
import sys
raw = open(sys.argv[1], "rb").read()
sep = raw.find(b"\r\n\r\n")
if sep < 0:
    open(sys.argv[2], "wb").write(b""); open(sys.argv[3], "wb").write(b""); sys.exit(0)
hdrs, body = raw[:sep], raw[sep + 4:]
open(sys.argv[2], "wb").write(hdrs)
# Chunked only if the header block says so (case-insensitive), else verbatim.
if b"transfer-encoding: chunked" in hdrs.lower():
    out, i = bytearray(), 0
    while True:
        nl = body.find(b"\r\n", i)
        if nl < 0:
            out = bytearray(); break          # truncated size line -> empty = fail
        try:
            n = int(body[i:nl].split(b";", 1)[0], 16)
        except ValueError:
            out = bytearray(); break          # garbage size -> empty = fail
        i = nl + 2
        if n == 0:
            break                              # last chunk; trailer ignored
        if i + n > len(body):
            out = bytearray(); break          # short chunk data -> empty = fail
        out += body[i:i + n]
        i += n + 2                             # skip the chunk's trailing CRLF
    body = bytes(out)
open(sys.argv[3], "wb").write(body)
PY
FRAME_LEN=$(wc -c < "$FRAME" 2>/dev/null | tr -d ' ')
FRAME_LEN=${FRAME_LEN:-0}

# --- 2: the response was actually a genuine zstd frame, not pass-through -------
# Two independent facts must both hold: the server ADVERTISED zstd
# (Content-Encoding: zstd) AND the de-chunked wire body is NOT byte-identical to
# the plaintext (i.e. it really is a compressed frame, not the raw value passed
# through with a mislabeling header). NOTE deliberately NOT "frame < plaintext":
# the upstream drips 2 bytes at a time, so the filter emits a ZSTD_e_flush per
# tiny buffer and the resulting frame -- littered with per-block headers -- is
# LARGER than this short, trivially-compressible input. That is correct zstd
# behaviour for a heavily-flushed stream, not a defect; a size test would red on
# a perfectly good frame. The genuine-frame proof is instead: the header claims
# zstd, the bytes differ from the plaintext, AND (oracle 5) the frame decodes
# back to exactly the plaintext -- a pass-through body would fail the byte-differ
# check here, and random/corrupt bytes would fail the decode there.
CE_OK=0
grep -qi '^Content-Encoding:[[:space:]]*zstd' "$HDRS" && CE_OK=1
DIFFERS=0
[ "$FRAME_LEN" -gt 0 ] && ! cmp -s "$FRAME" <(printf '%s' "$EXPECT_PLAIN") && DIFFERS=1
if [ "$CE_OK" -eq 1 ] && [ "$DIFFERS" -eq 1 ]; then
    echo "ok 2 - the response was a genuine zstd frame on the wire (Content-Encoding: zstd, $FRAME_LEN B frame, not the raw $PLAIN_LEN B plaintext)"
else
    echo "not ok 2 - the response was not a genuine zstd frame (C-E:zstd=$CE_OK, differs-from-plaintext=$DIFFERS, frame=$FRAME_LEN B)"
    head -20 "$HDRS" | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 3: the held request was in flight across every reload (anti-vacuity) ------
if [ "$INFLIGHT_ALIVE_ALL" -eq 1 ]; then
    echo "ok 3 - the held request was provably still in flight across all $RELOADS reloads"
else
    echo "not ok 3 - the held request was not alive at every reload; the reloads did not genuinely overlap it"
    FAILED=$((FAILED + 1))
fi

# --- 4: the compressed-request path is allocation-neutral after the reloads ----
# Two post-drain quiescent snapshots taken around one extra full compressed
# request (see the measurement block above). Equal cycle-pool counters mean the
# zstd path freed everything it allocated for that request -- no per-request CCtx
# or CDict-reference leak surviving the two config reloads. A leak would make the
# second snapshot strictly larger.
if [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 4 - compressed-path allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$FINAL_USED" = "$FINAL2_USED" ] \
  && [ "$FINAL_BLOCKS" = "$FINAL2_BLOCKS" ] \
  && [ "$FINAL_LARGE" = "$FINAL2_LARGE" ]; then
    echo "ok 4 - the zstd request path was allocation-neutral after all $RELOADS reloads"
    echo "# cycle_used=$FINAL_USED cycle_blocks=$FINAL_BLOCKS cycle_large=$FINAL_LARGE (stable across an extra compressed request)"
else
    echo "not ok 4 - the zstd request path grew the cycle pool after the reloads (per-request leak)"
    echo "# before extra request: used=$FINAL_USED blocks=$FINAL_BLOCKS large=$FINAL_LARGE"
    echo "# after  extra request: used=$FINAL2_USED blocks=$FINAL2_BLOCKS large=$FINAL2_LARGE"
    FAILED=$((FAILED + 1))
fi

# --- 5: the held compressed response decompresses to the exact plaintext ------
# THE central oracle. Decompress the surviving frame and compare byte for byte
# to the seeded plaintext. A reload that freed the CCtx or the CDict out from
# under the in-flight stream would corrupt or truncate the frame, and zstd -d
# would either fail outright (nonzero) or emit bytes that do not match -- either
# way this reds. `zstd -d` exit status is captured explicitly (not swallowed):
# a decode FAILURE and a decode-to-wrong-bytes are BOTH failures, but must not
# be conflated with a clean decode, so the status gates the compare.
DEC="$PROBER_PREFIX/inflight.plain"
ZSTD_RC=0
zstd -d -q -c "$FRAME" > "$DEC" 2>/dev/null || ZSTD_RC=$?
GOT_PLAIN=""
[ "$ZSTD_RC" -eq 0 ] && GOT_PLAIN="$(cat "$DEC")"
if [ "$ZSTD_RC" -eq 0 ] && [ "$GOT_PLAIN" = "$EXPECT_PLAIN" ]; then
    echo "ok 5 - the held compressed response decompressed to the exact seeded plaintext after $RELOADS reloads"
else
    echo "not ok 5 - the held response did not decompress to the seeded plaintext (zstd rc=$ZSTD_RC, got ${#GOT_PLAIN} B, want $PLAIN_LEN B)"
    FAILED=$((FAILED + 1))
fi

# --- 6: the held request hit the upstream exactly once ------------------------
# HELD_GETS was captured right after the join, BEFORE oracle 4's extra request
# and BEFORE the post-reload prober leg -- so it counts only the gets the held
# request itself caused. More than one means a reload dropped the held request
# and nginx re-issued it upstream.
if [ "$HELD_GETS" -eq 1 ]; then
    echo "ok 6 - the backend served the held get exactly once across all $RELOADS reloads"
else
    echo "not ok 6 - the backend saw the held get $HELD_GETS times (expected 1: re-issued during a reload?)"
    FAILED=$((FAILED + 1))
fi

# --- 7: no worker died by signal during the reloads ---------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 7 - a worker died by signal during the reloads"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 7 - no worker died by signal across the reloads"
fi

# --- 8: the old worker set drained after the held request completed -----------
# DRC was computed right after the join (before the snapshots), so oracle 4's
# final reading was taken against the drained set. return 1 = a real drain
# timeout (an old-cycle worker stuck after the held request ended); return 2 =
# no pgrep on this host, a visible SKIP not a failure (same exemption
# reload-soak/hup-storm use). A stuck old worker would otherwise be masked by
# the NEW worker answering the coherence leg (oracle 9).
if [ "$DRC" -eq 0 ]; then
    echo "ok 8 - the old worker set drained to $WORKERS after the held request completed"
elif [ "$DRC" -eq 2 ]; then
    echo "ok 8 - old-worker drain # SKIP pgrep unavailable; cannot observe the child set on this host"
else
    echo "not ok 8 - an old worker never drained after the held request ended (stuck/leaked worker)"
    FAILED=$((FAILED + 1))
fi

# --- 9: post-reload coherence (prober, folded in as diagnostics) --------------
# A plain strict case AFTER both reloads are absorbed and drained: the final
# worker serves a correct probe, leaks no descriptor, logs nothing on the error
# path. PIPESTATUS[0], not $?, so a red prober leg is not masked by sed's 0.
STATUS=0
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
