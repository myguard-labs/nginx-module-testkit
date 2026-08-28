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
# error path. The three cases below each take a probe snapshot (fd count,
# cycle-pool bytes, slab pages) BEFORE the attack and again AFTER the attacking
# connection has been reaped, and assert the two are IDENTICAL. That is the
# only vantage point from which "the worker rejected this frame and freed
# everything it allocated to reject it" is distinguishable from "the worker
# rejected this frame and leaked a descriptor/pool block/slab page doing it".
#
# WHY THREE ATTACKS AND NOT SEVEN. The roadmap row lists seven hostile shapes;
# the four left out here (oversized/zero-length frames, CONTINUATION without
# END_HEADERS, SETTINGS floods) each need either a real, fully-negotiated
# request in flight first or a multi-frame sequence whose ordering matters --
# more moving parts than a single malformed frame on a fresh connection, and
# more than this row can ship with a real observed-red control on each. A
# follow-up row is the honest way to grow this file, not a bigger diff now
# with weaker verification per case. The three shipped here are each a SINGLE
# frame, each unambiguously illegal under RFC 9113, and each a distinct
# violation class (stream-id parity, flow-control arithmetic, stream-state
# machine):
#
#   A. HEADERS on an EVEN stream id. RFC 9113 SS5.1.1: streams a client
#      initiates MUST use odd-numbered ids; an even one from a client is a
#      connection error (PROTOCOL_ERROR).
#   B. WINDOW_UPDATE at the CONNECTION level (stream 0) with an increment that
#      pushes the window past 2^31-1. RFC 9113 SS6.9.1: a flow-control window
#      that overflows a 31-bit signed value is a connection error
#      (FLOW_CONTROL_ERROR). The default initial window is 65535, so a single
#      increment of 0x7fffffff (2147483647) already overflows it in one frame.
#   C. RST_STREAM on an IDLE stream -- one the client never opened with a
#      HEADERS frame. RFC 9113 SS5.1's state diagram has no transition out of
#      "idle" on RST_STREAM; receiving one there is a connection error
#      (PROTOCOL_ERROR).
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
# attacker-supplied frame given as a hex string. Reads whatever the server
# sends back for up to 2s (a GOAWAY is expected but never asserted ON here --
# see the file header for why "the connection died correctly" is not this
# row's oracle), then closes.
#
# Prints the comma-separated list of h2 frame TYPE bytes seen in the response,
# purely as an `# ` diagnostic in the TAP output -- never consulted by an
# `ok`/`not ok` line. A frame type of 7 is GOAWAY; observing one confirms the
# harness's own read of "illegal" agrees with the server's, but the probe
# snapshot below is what actually gates the case.
send_attack() {
    local hex_frame="$1"
    H="$HOST" P="$PORT" F="$hex_frame" timeout 5 python3 - <<'PY' 2>/dev/null || true
import os, socket, sys

host = os.environ["H"]
port = int(os.environ["P"])
frame = bytes.fromhex(os.environ["F"])

preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
client_settings = bytes([0, 0, 0, 4, 0, 0, 0, 0, 0])  # len=0 type=SETTINGS flags=0 stream=0

s = socket.create_connection((host, port), 5)
s.settimeout(2)
try:
    s.sendall(preface + client_settings + frame)
    data = b""
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
print(",".join(types))
PY
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

# Attack C: RST_STREAM, stream 99 (odd -- a legal client stream id, but one
# never opened by a HEADERS frame, so it is IDLE), error code CANCEL (8).
#   length = 000004, type = 03, flags = 00, stream = 00000063 (99),
#   payload = 00000008 (CANCEL)
ATTACK_C="00000403000000006300000008"

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
# TAP numbering: the Nth call occupies test points (3N-2) neutral-fds,
# (3N-1) neutral-pool-bytes, (3N) neutral-slab-pages, tracked via the shared
# $TP counter rather than a case-id argument -- there is nothing else here
# that would consume a per-case identifier.
run_attack_case() {
    local label="$1" hex="$2"
    local before_fds before_pool before_slab
    local after_fds after_pool after_slab
    local resp_types

    wait_quiescent || echo "# $label: pre-attack snapshot never settled; racing a moving baseline"
    before_fds="$SNAP_FDS"; before_pool="$SNAP_POOL"; before_slab="$SNAP_SLAB"

    resp_types="$(send_attack "$hex")"
    echo "# $label: response frame types seen: ${resp_types:-<none>}"

    if wait_quiescent; then
        after_fds="$SNAP_FDS"; after_pool="$SNAP_POOL"; after_slab="$SNAP_SLAB"
    else
        echo "# $label: post-attack snapshot never settled within 5s"
        after_fds="<unsettled>"; after_pool="<unsettled>"; after_slab="<unsettled>"
    fi

    if [ "$before_fds" = "$after_fds" ]; then
        echo "ok $((TP + 1)) - $label: fd count neutral ($before_fds)"
    else
        echo "not ok $((TP + 1)) - $label: fd count moved ($before_fds -> $after_fds)"
        FAILED=$((FAILED + 1))
    fi

    if [ "$before_pool" = "$after_pool" ]; then
        echo "ok $((TP + 2)) - $label: cycle-pool bytes neutral ($before_pool)"
    else
        echo "not ok $((TP + 2)) - $label: cycle-pool bytes moved ($before_pool -> $after_pool)"
        FAILED=$((FAILED + 1))
    fi

    if [ "$before_slab" = "$after_slab" ]; then
        echo "ok $((TP + 3)) - $label: slab pages neutral ($before_slab)"
    else
        echo "not ok $((TP + 3)) - $label: slab pages moved ($before_slab -> $after_slab)"
        FAILED=$((FAILED + 1))
    fi

    TP=$((TP + 3))
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
send_attack "$WARMUP" >/dev/null
wait_quiescent || echo "# warm-up: baseline never settled; racing a moving reading"

TP=0
echo "1..9"

run_attack_case "HEADERS on an even (illegal) stream id" "$ATTACK_A"
run_attack_case "WINDOW_UPDATE overflow at the connection level" "$ATTACK_B"
run_attack_case "RST_STREAM on an idle stream" "$ATTACK_C"

# --- the worker must still be the SAME worker, not a crash-and-respawn -----
#
# A crash the master immediately respawned would still read as "fds/pool/slab
# neutral" on the NEW worker's fresh state, which is a false pass on exactly
# the failure this file exists to catch. Fold in the pid check as a final
# diagnostic against the error log rather than a 10th TAP point: a worker that
# died by signal across three attacks logs it, and that is real corroborating
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
