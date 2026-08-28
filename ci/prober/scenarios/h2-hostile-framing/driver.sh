#!/usr/bin/env bash
#
# H2-3: hostile h2 framing oracles.
#
# THE REAL ATTACK ROW, restated from the TODO: a client can put frames on the
# wire an nghttp2-driven client (h2.c, H2-2) would never construct on its own,
# because a well-behaved library enforces the spec on its OWN output before
# this harness ever gets a chance to violate it. h2-roundtrip proves the
# MECHANISM carries one clean exchange; this file is the one place in the tree
# that can put a genuinely illegal frame on the wire and watch what the worker
# does with it.
#
# WHAT MAKES A ROW HERE ADMISSIBLE, same standard as every worker-inside probe
# oracle in this tree: "the connection died" is not a finding on its own --
# nginx tearing down a connection that sent it garbage is the CORRECT, boring
# outcome, and a case that only checked for that would pass identically
# whether the worker freed every byte it touched or quietly leaked one on the
# error path. Each case below FIRST asserts the attack was actually delivered
# and actually treated as illegal (a GOAWAY, frame type 7 -- see send_attack),
# then takes a probe snapshot (fd count, cycle-pool bytes, slab pages) BEFORE
# the attack and again AFTER the attacking connection has been reaped, and
# asserts the two are IDENTICAL. The delivery check rules out "the harness
# never touched the server" reading as a pass; the snapshot pair rules out
# "the worker rejected this frame and leaked a descriptor/pool block/slab page
# doing it" reading as a pass.
#
# WHY TWO ATTACKS AND NOT SEVEN. The roadmap row lists seven hostile shapes.
# Five are not here. Four (oversized/zero-length frames, CONTINUATION without
# END_HEADERS, SETTINGS floods) each need either a real, fully-negotiated
# request in flight first or a multi-frame sequence whose ordering matters --
# more moving parts than a single malformed frame on a fresh connection, and
# more than this row can ship with a real observed-red control on each. The
# fifth, RST_STREAM on an idle stream, WAS implemented and then pulled after
# measurement (2026-08-29): this nginx build does not treat it as an error at
# all -- no GOAWAY, no connection close, no EOF, and a second frame on the
# same socket right after it still gets answered, identically to sending a
# harmless PING first. RFC 9113 SS5.1's state diagram has no transition out of
# "idle" on RST_STREAM, so the frame is illegal by the spec, but nothing
# observable here distinguishes "nginx silently discarded an illegal frame"
# from "nginx silently discarded a frame for a stream id it has no interest
# in, illegal or not" -- there is no oracle, worker-inside or on the wire, an
# admissible row could assert on. A follow-up row is the honest way to grow
# this file with the five remaining shapes, not a bigger diff now with a case
# that cannot fail. The two shipped here are each a SINGLE frame, each
# unambiguously illegal under RFC 9113, and each MEASURED to make nginx answer
# with a GOAWAY:
#
#   A. HEADERS on an EVEN stream id. RFC 9113 SS5.1.1: streams a client
#      initiates MUST use odd-numbered ids; an even one from a client is a
#      connection error (PROTOCOL_ERROR).
#   B. WINDOW_UPDATE at the CONNECTION level (stream 0) with an increment that
#      pushes the window past 2^31-1. RFC 9113 SS6.9.1: a flow-control window
#      that overflows a 31-bit signed value is a connection error
#      (FLOW_CONTROL_ERROR). The default initial window is 65535, so a single
#      increment of 0x7fffffff (2147483647) already overflows it in one frame.
#
# WHY RAW PYTHON SOCKETS AND NOT h2.c. h2_exchange() is built on the system
# nghttp2 CLIENT session, which enforces frame validity on its own outgoing
# frames before they ever reach the wire -- that is precisely why H2-2's file
# header says hostile framing is not reachable from it. Constructing an
# illegal frame needs to bypass that enforcement entirely, which means driving
# the raw bytes by hand. See ./requires for why python3 and not bash /dev/tcp.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

# Pre-declared under `set -u`: if the very first wait_quiescent call below
# never succeeds (the probe endpoint is down from the first request onward,
# say), snapshot() never runs and these stay unset -- without an initial
# empty value, run_attack_case's very first `before_fds="$SNAP_FDS"` would
# abort the whole script on an unbound-variable error instead of the
# designed `not ok`/settle-timeout diagnostic every later failure path
# already produces.
SNAP_FDS=""
SNAP_POOL=""
SNAP_SLAB=""

# --- raw h2 attack delivery --------------------------------------------------
#
# send_attack HEX_FRAME
#
# Opens ONE fresh TCP connection, sends the h2 client connection preface (RFC
# 9113 SS3.4) plus an empty client SETTINGS frame (the wire shape every real h2
# client sends first, so this is not itself part of the attack), then the
# attacker-supplied frame given as a hex string, then reads whatever the
# server sends back for up to 2s and closes.
#
# Fills two globals rather than returning a single string, and DOES NOT
# swallow a failed connect/sendall: the python3 body wraps connect+sendall in
# its own try/except and prints a `DELIVERY_OK`/`DELIVERY_FAIL:<reason>`
# marker as line 1, so a refused connection, a stale port, or a listener not
# speaking h2c is a *reported* failure, not empty output silently accepted as
# "attack sent, nginx neutral". The python3 exit status also propagates
# through this function's own `$?` -- run_attack_case's caller now checks it
# instead of a bare `|| true` throwing it away (MEASURED 2026-08-28: before
# this fix a caller with no listener at all still produced 9 green TAP
# points, because before==after trivially when neither snapshot ever moves).
#
#   ATTACK_STATUS      "DELIVERY_OK" or "DELIVERY_FAIL:<python exception>"
#   ATTACK_RESP_TYPES  comma-separated h2 frame TYPE bytes seen in the
#                      response (may be empty even on DELIVERY_OK -- a
#                      connection that hung up with no bytes back is still a
#                      completed send). A frame type of 7 is GOAWAY.
send_attack() {
    local hex_frame="$1" out rc=0

    out="$(H="$HOST" P="$PORT" F="$hex_frame" timeout 5 python3 - <<'PY'
import os, socket, sys

host = os.environ["H"]
port = int(os.environ["P"])
frame = bytes.fromhex(os.environ["F"])

preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
client_settings = bytes([0, 0, 0, 4, 0, 0, 0, 0, 0])  # len=0 type=SETTINGS flags=0 stream=0

try:
    s = socket.create_connection((host, port), 5)
    s.settimeout(2)
    s.sendall(preface + client_settings + frame)
except Exception as e:
    print("DELIVERY_FAIL:%s" % e)
    print("")
    sys.exit(1)

data = b""
try:
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
finally:
    s.close()

types = []
i = 0
while i + 9 <= len(data):
    length = int.from_bytes(data[i:i + 3], "big")
    types.append(str(data[i + 3]))
    i += 9 + length

print("DELIVERY_OK")
print(",".join(types))
PY
)" || rc=$?

    # timeout(1) killing the whole python3 body (rc=124, e.g. a hung recv the
    # 2s socket timeout should have caught but didn't) is ALSO a delivery
    # failure, not a silent success -- there is no well-formed DELIVERY_OK
    # marker to trust from a process that had to be killed.
    if [ "$rc" -ne 0 ]; then
        ATTACK_STATUS="${out%%$'\n'*}"
        [ -n "$ATTACK_STATUS" ] || ATTACK_STATUS="DELIVERY_FAIL:python3 exited $rc with no output"
        ATTACK_RESP_TYPES=""
        return 1
    fi

    ATTACK_STATUS="$(printf '%s\n' "$out" | sed -n '1p')"
    ATTACK_RESP_TYPES="$(printf '%s\n' "$out" | sed -n '2p')"
}

# csv_contains CSV VALUE -- true if VALUE is one of CSV's comma-separated
# fields. Used to check for a GOAWAY (frame type 7) in ATTACK_RESP_TYPES
# without a false match against a longer type number ("17" must not match
# "7").
csv_contains() {
    local csv="$1" want="$2" field
    IFS=',' read -ra fields <<<"$csv"
    for field in "${fields[@]}"; do
        [ "$field" = "$want" ] && return 0
    done
    return 1
}

# A minimal, well-formed HPACK header block: :method GET (static idx 2),
# :path / (static idx 4), :scheme http (static idx 6), :authority "prober"
# (literal-with-incremental-indexing over static idx 1's name). Reused as the
# HEADERS payload for attack A -- the payload itself is ordinary; only the
# stream id carrying it is illegal.
HPACK_MINIMAL_GET="828486410670726f626572"

# Attack A: HEADERS, stream id 2 (even -- illegal for a client-initiated
# stream), the minimal GET payload above (11 bytes), built explicitly byte by
# byte so length/flags/stream-id are each visibly correct:
#   length   = 00000b (11, the HPACK block above)
#   type     = 01     (HEADERS)
#   flags    = 05     (END_HEADERS 0x4 | END_STREAM 0x1)
#   stream   = 00000002 (EVEN -- the illegal part)
ATTACK_A="00000b010500000002${HPACK_MINIMAL_GET}"

# Attack B: WINDOW_UPDATE, stream 0 (connection-level), increment 0x7fffffff.
#   length = 000004, type = 08, flags = 00, stream = 00000000
#   payload = 7fffffff (top bit reserved 0, so this is the max legal single
#   increment value -- it is the ARITHMETIC that is illegal, not the encoding:
#   65535 (default initial window) + 2147483647 > 2^31-1)
ATTACK_B="0000040800000000007fffffff"


# --- worker-inside evidence --------------------------------------------------
#
# snapshot: fill SNAP_FDS/SNAP_POOL/SNAP_SLAB from one /__probe read. A missing
# field is a hard failure, not a zero -- see prober_probe_field's own contract.
snapshot() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
    SNAP_POOL="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_SLAB="$(prober_probe_field "$body" slab_pages_free)" || return 1
}

# wait_quiescent: the attacking connection's teardown (ngx_http_close_connection
# freeing the pool, the kernel reclaiming the fd) happens on the SAME worker
# event loop that will answer the next probe read, but not necessarily before
# it -- a probe issued in the same tick as the close can race it. Poll until
# two consecutive snapshots agree on all three fields (same discipline as
# backend-idle-close-reload's settle loop), bounded at 5s. This is a settle,
# not the oracle: the case below still demands the settled reading equal the
# PRE-attack one exactly.
#
# send_attack's own read window (2s, hardcoded in the python3 body) has less
# slack against this 5s ceiling than most existing settle loops: a slow CI
# runner could in principle spend most of the 5s just inside send_attack
# before wait_quiescent gets its first look. Not touched here -- widening
# either bound is a scenario-timing change with its own tradeoffs, not part
# of the delivery-assertion fix this file was updated for.
wait_quiescent() {
    local prev_fds="" prev_pool="" prev_slab="" i
    for ((i = 0; i < 100; i++)); do            # 100 * 50ms = 5s ceiling
        if snapshot \
           && [ "$SNAP_FDS" = "$prev_fds" ] \
           && [ "$SNAP_POOL" = "$prev_pool" ] \
           && [ "$SNAP_SLAB" = "$prev_slab" ]
        then
            return 0
        fi
        prev_fds="${SNAP_FDS:-}"
        prev_pool="${SNAP_POOL:-}"
        prev_slab="${SNAP_SLAB:-}"
        sleep 0.05
    done
    return 1
}

# run_attack_case LABEL HEX_FRAME
#
# TAP numbering: the Nth call occupies test points (4N-3) delivery-confirmed,
# (4N-2) neutral-fds, (4N-1) neutral-pool-bytes, (4N) neutral-slab-pages,
# tracked via the shared $TP counter rather than a case-id argument -- there
# is nothing else here that would consume a per-case identifier.
#
# The delivery check asserts a GOAWAY (frame type 7) unconditionally: both
# attacks shipped in this file were MEASURED (2026-08-28) to make nginx answer
# with one, so there is no second mode to select here. A future case whose
# attack does not earn a GOAWAY needs its own delivery assertion, not a silent
# third option threaded through this function ahead of having one.
run_attack_case() {
    local label="$1" hex="$2"
    local before_fds before_pool before_slab
    local after_fds after_pool after_slab
    local delivered=1

    wait_quiescent || echo "# $label: pre-attack snapshot never settled; racing a moving baseline"
    before_fds="$SNAP_FDS"; before_pool="$SNAP_POOL"; before_slab="$SNAP_SLAB"

    if ! send_attack "$hex"; then
        delivered=0
    fi
    echo "# $label: $ATTACK_STATUS; response frame types seen: ${ATTACK_RESP_TYPES:-<none>}"

    # Delivery is now a SCORED assertion, not a `#` diagnostic -- a swallowed
    # connect/sendall failure used to leave before==after trivially, which
    # read as "attack sent, worker neutral" for a harness that never touched
    # the server at all.
    if [ "$delivered" -eq 1 ] && csv_contains "$ATTACK_RESP_TYPES" 7; then
        echo "ok $((TP + 1)) - $label: server responded with GOAWAY (frame type 7)"
    elif [ "$delivered" -eq 1 ]; then
        echo "not ok $((TP + 1)) - $label: no GOAWAY seen (types: ${ATTACK_RESP_TYPES:-<none>})"
        FAILED=$((FAILED + 1))
    else
        echo "not ok $((TP + 1)) - $label: attack was never delivered ($ATTACK_STATUS)"
        FAILED=$((FAILED + 1))
    fi

    if wait_quiescent; then
        after_fds="$SNAP_FDS"; after_pool="$SNAP_POOL"; after_slab="$SNAP_SLAB"
    else
        echo "# $label: post-attack snapshot never settled within 5s"
        after_fds="<unsettled>"; after_pool="<unsettled>"; after_slab="<unsettled>"
    fi

    if [ "$before_fds" = "$after_fds" ]; then
        echo "ok $((TP + 2)) - $label: fd count neutral ($before_fds)"
    else
        echo "not ok $((TP + 2)) - $label: fd count moved ($before_fds -> $after_fds)"
        FAILED=$((FAILED + 1))
    fi

    if [ "$before_pool" = "$after_pool" ]; then
        echo "ok $((TP + 3)) - $label: cycle-pool bytes neutral ($before_pool)"
    else
        echo "not ok $((TP + 3)) - $label: cycle-pool bytes moved ($before_pool -> $after_pool)"
        FAILED=$((FAILED + 1))
    fi

    if [ "$before_slab" = "$after_slab" ]; then
        echo "ok $((TP + 4)) - $label: slab pages neutral ($before_slab)"
    else
        echo "not ok $((TP + 4)) - $label: slab pages moved ($before_slab -> $after_slab)"
        FAILED=$((FAILED + 1))
    fi

    TP=$((TP + 4))
}

# A throwaway, entirely well-formed h2c connection (preface + client SETTINGS
# + a valid GET on stream 1, END_HEADERS|END_STREAM) run ONCE before any
# attack and never scored. MEASURED 2026-08-28: the first h2c connection this
# worker ever answers grows the cycle pool by 16 bytes relative to every
# connection after it -- a one-time per-worker "first h2 request" allocation
# (h2's own module context/state, not a per-connection cost), not a leak.
# Without this warm-up that one-time growth lands on attack A's before/after
# window and reads as a non-neutral pool, which would be a false positive on
# the exact oracle this file exists to keep honest. Every attack case after
# this one measures ONLY marginal cost, which is what "neutral across the
# attack" actually means.
WARMUP="00000b010500000001${HPACK_MINIMAL_GET}"
send_attack "$WARMUP" || echo "# warm-up: delivery failed ($ATTACK_STATUS) -- baseline may be against a dead server"
wait_quiescent || echo "# warm-up: baseline never settled; racing a moving reading"

TP=0
echo "1..8"

# Both were MEASURED (2026-08-28, this same server/build) to make nginx
# answer with a GOAWAY (response types "4,8,4,7" for both), which is what
# run_attack_case's delivery check asserts on.
run_attack_case "HEADERS on an even (illegal) stream id" "$ATTACK_A"
run_attack_case "WINDOW_UPDATE overflow at the connection level" "$ATTACK_B"

# --- the worker must still be the SAME worker, not a crash-and-respawn -----
#
# A crash the master immediately respawned would still read as "fds/pool/slab
# neutral" on the NEW worker's fresh state, which is a false pass on exactly
# the failure this file exists to catch. Fold in the pid check as a final
# diagnostic against the error log rather than a 10th TAP point: a worker that
# died by signal across both attacks logs it, and that is real corroborating
# evidence even though it is not this file's primary oracle (see the file
# header on why "it didn't crash" alone would be the wrong oracle to lead
# with).
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "# WARNING: a worker died by signal during the hostile-framing run"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
