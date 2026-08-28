#!/usr/bin/env bash
#
# H2-5: ordinary HTTP/2 multiplexing with one active stream cancelled.
#
# One negotiated h2c connection carries streams 1 and 3.  The client enlarges
# only the connection window, leaving each stream's default 65535-byte window
# intact.  Against a 256 KiB response, DATA on both streams therefore proves
# both were active and neither could already be complete.  Only then does the
# client send standard RST_STREAM(CANCEL) on stream 1.  Stream 3 receives new
# credit after the reset and must continue to END_STREAM on the same socket.
#
# Wire success is deliberately not the main claim.  After the connection is
# closed and the worker settles, fd count, cycle-pool bytes, and slab free-page
# count must exactly equal the stable pre-cancellation baseline.  This is the
# cleanup evidence an ordinary request/response suite cannot observe.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
FAILED=0

SNAP_FDS=""
SNAP_POOL=""
SNAP_SLAB=""

snapshot() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
    SNAP_POOL="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_SLAB="$(prober_probe_field "$body" slab_pages_free)" || return 1
}

# Two consecutive successful equal reads make one stable observation.  A
# failed read invalidates its predecessor so stale data cannot satisfy settle.
wait_quiescent() {
    local prev_fds="" prev_pool="" prev_slab="" i
    for ((i = 0; i < 100; i++)); do
        if snapshot; then
            if [ -n "$prev_fds" ] \
               && [ "$SNAP_FDS" = "$prev_fds" ] \
               && [ "$SNAP_POOL" = "$prev_pool" ] \
               && [ "$SNAP_SLAB" = "$prev_slab" ]; then
                return 0
            fi
            prev_fds="$SNAP_FDS"
            prev_pool="$SNAP_POOL"
            prev_slab="$SNAP_SLAB"
        else
            prev_fds=""
            prev_pool=""
            prev_slab=""
        fi
        sleep 0.05
    done
    return 1
}

# run_h2_client MODE
#
# MODE=warmup performs one small stream and absorbs nginx's measured one-time
# first-h2-connection cycle allocation.  MODE=cancel performs the scored two-
# stream exchange and prints the observations consumed below.  This remains a
# scenario-local driver; the prober's public one-exchange API is unchanged.
run_h2_client() {
    local mode="$1"
    H="$HOST" P="$PORT" MODE="$mode" timeout 12 python3 - <<'PY'
import os
import socket
import time

host = os.environ["H"]
port = int(os.environ["P"])
mode = os.environ["MODE"]


def frame(frame_type, flags, stream_id, payload=b""):
    return (len(payload).to_bytes(3, "big")
            + bytes((frame_type, flags))
            + stream_id.to_bytes(4, "big")
            + payload)


def headers_frame(stream_id, path):
    # HPACK: indexed :method GET (2), indexed :scheme http (6), literal
    # :path (static-name index 4), and literal-with-indexing :authority.
    block = (b"\x82\x86\x04" + bytes((len(path),)) + path
             + b"\x41\x06prober")
    return frame(1, 0x5, stream_id, block)  # END_HEADERS | END_STREAM


def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("EOF while receiving an HTTP/2 frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock):
    header = recv_exact(sock, 9)
    length = int.from_bytes(header[:3], "big")
    return (header[3], header[4],
            int.from_bytes(header[5:9], "big") & 0x7fffffff,
            recv_exact(sock, length))


server_settings = False
client_settings_ack = False
before = {1: 0, 3: 0}
ended_before = {1: False, 3: False}
rst_code = -1
after_stream3 = 0
stream3_ended = False

try:
    sock = socket.create_connection((host, port), 5)
    sock.settimeout(5)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    client_settings = frame(4, 0, 0)

    if mode == "warmup":
        sock.sendall(preface + client_settings + headers_frame(1, b"/"))
        deadline = time.monotonic() + 5
        warmup_done = False
        while time.monotonic() < deadline and not warmup_done:
            frame_type, flags, stream_id, payload = recv_frame(sock)
            if frame_type == 4 and flags == 0:
                server_settings = True
                sock.sendall(frame(4, 1, 0))
            elif frame_type == 4 and flags & 1:
                client_settings_ack = True
            if stream_id == 1 and flags & 1 and frame_type in (0, 1):
                warmup_done = True
        if not warmup_done:
            raise RuntimeError("warm-up stream did not reach END_STREAM")
    else:
        # Extra connection credit lets both default-sized stream windows make
        # progress; no stream credit is added until after cancellation.
        conn_credit = frame(8, 0, 0, (1048576).to_bytes(4, "big"))
        sock.sendall(preface + client_settings + conn_credit
                     + headers_frame(1, b"/payload.bin")
                     + headers_frame(3, b"/payload.bin"))

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (before[1] and before[3]):
            frame_type, flags, stream_id, payload = recv_frame(sock)
            if frame_type == 4 and flags == 0:
                server_settings = True
                sock.sendall(frame(4, 1, 0))
            elif frame_type == 4 and flags & 1:
                client_settings_ack = True
            elif frame_type == 7:
                raise RuntimeError("server sent GOAWAY before cancellation")
            if stream_id in before:
                if frame_type == 0:
                    before[stream_id] += len(payload)
                if flags & 1 and frame_type in (0, 1):
                    ended_before[stream_id] = True

        if not before[1] or not before[3]:
            raise RuntimeError("both streams did not transfer DATA before reset")
        if ended_before[1] or ended_before[3]:
            raise RuntimeError("a stream ended before the cancellation point")

        rst_payload = (8).to_bytes(4, "big")  # RFC 9113 CANCEL
        rst = frame(3, 0, 1, rst_payload)
        sock.sendall(rst)
        rst_code = int.from_bytes(rst_payload, "big")

        # Credit only the surviving stream after the reset.  DATA observed
        # after this point and its END_STREAM prove the connection and stream
        # 3 stayed live while stream 1 was cancelled.
        more_credit = (1048576).to_bytes(4, "big")
        sock.sendall(frame(8, 0, 0, more_credit)
                     + frame(8, 0, 3, more_credit))

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not stream3_ended:
            frame_type, flags, stream_id, payload = recv_frame(sock)
            if frame_type == 4 and flags == 0:
                server_settings = True
                sock.sendall(frame(4, 1, 0))
            elif frame_type == 4 and flags & 1:
                client_settings_ack = True
            elif frame_type == 7:
                raise RuntimeError("server sent GOAWAY after standard cancellation")
            if stream_id == 3:
                if frame_type == 0:
                    after_stream3 += len(payload)
                if flags & 1 and frame_type in (0, 1):
                    stream3_ended = True
        if not stream3_ended:
            raise RuntimeError("surviving stream did not reach END_STREAM")
finally:
    try:
        sock.close()
    except NameError:
        pass

negotiated = int(server_settings and client_settings_ack)
print("NEGOTIATED=%d" % negotiated)
print("STREAM1_DATA_BEFORE_RST=%d" % before[1])
print("STREAM3_DATA_BEFORE_RST=%d" % before[3])
print("STREAM1_ENDED_BEFORE_RST=%d" % int(ended_before[1]))
print("STREAM3_ENDED_BEFORE_RST=%d" % int(ended_before[3]))
print("RST_SENT=%d" % rst_code)
print("STREAM3_DATA_AFTER_RST=%d" % after_stream3)
print("STREAM3_ENDED_AFTER_RST=%d" % int(stream3_ended))
PY
}

field() {
    local key="$1"
    sed -n "s/^${key}=//p" <<<"$CLIENT_OUT" | tail -n 1
}

positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

# Create the response body before either h2 connection asks for it.
dd if=/dev/zero of="$PROBER_PREFIX/payload.bin" bs=262144 count=1 status=none

warmup_rc=0
run_h2_client warmup >/dev/null 2>"$PROBER_PREFIX/h2-warmup.err" || warmup_rc=$?
if [ "$warmup_rc" -ne 0 ]; then
    echo "Bail out! h2 warm-up failed (rc=$warmup_rc): $(head -c 300 "$PROBER_PREFIX/h2-warmup.err")"
    exit 1
fi

baseline_ok=1
if wait_quiescent; then
    before_fds="$SNAP_FDS"
    before_pool="$SNAP_POOL"
    before_slab="$SNAP_SLAB"
else
    baseline_ok=0
    before_fds="<unsettled>"
    before_pool="<unsettled>"
    before_slab="<unsettled>"
fi

CLIENT_OUT=""
client_rc=0
CLIENT_OUT="$(run_h2_client cancel 2>"$PROBER_PREFIX/h2-client.err")" || client_rc=$?

negotiated="$(field NEGOTIATED)"
stream1_before="$(field STREAM1_DATA_BEFORE_RST)"
stream3_before="$(field STREAM3_DATA_BEFORE_RST)"
stream1_ended="$(field STREAM1_ENDED_BEFORE_RST)"
stream3_ended_before="$(field STREAM3_ENDED_BEFORE_RST)"
rst_sent="$(field RST_SENT)"
stream3_after="$(field STREAM3_DATA_AFTER_RST)"
stream3_ended_after="$(field STREAM3_ENDED_AFTER_RST)"

after_ok=1
if wait_quiescent; then
    after_fds="$SNAP_FDS"; after_pool="$SNAP_POOL"; after_slab="$SNAP_SLAB"
else
    after_ok=0
    after_fds="<unsettled>"; after_pool="<unsettled>"; after_slab="<unsettled>"
fi

echo "1..7"

if [ "$client_rc" -eq 0 ] && [ "$negotiated" = 1 ]; then
    echo "ok 1 - one HTTP/2 connection negotiated SETTINGS in both directions"
else
    echo "not ok 1 - HTTP/2 SETTINGS negotiation was not observed (client rc=$client_rc, negotiated=${negotiated:-<missing>})"
    FAILED=$((FAILED + 1))
fi

if positive_integer "$stream1_before" && positive_integer "$stream3_before" \
   && [ "$stream1_ended" = 0 ] && [ "$stream3_ended_before" = 0 ]; then
    echo "ok 2 - streams 1 and 3 were concurrently active before cancellation ($stream1_before/$stream3_before DATA bytes)"
else
    echo "not ok 2 - two active streams were not observed before cancellation (bytes=${stream1_before:-<missing>}/${stream3_before:-<missing>}, ended=${stream1_ended:-<missing>}/${stream3_ended_before:-<missing>})"
    FAILED=$((FAILED + 1))
fi

if [ "$rst_sent" = 8 ] && positive_integer "$stream1_before" \
   && [ "$stream1_ended" = 0 ]; then
    echo "ok 3 - active stream 1 was cancelled with RST_STREAM CANCEL (code 8)"
else
    echo "not ok 3 - active stream cancellation stimulus was not delivered (RST=${rst_sent:-<missing>})"
    FAILED=$((FAILED + 1))
fi

if positive_integer "$stream3_after" && [ "$stream3_ended_after" = 1 ]; then
    echo "ok 4 - stream 3 continued after the reset and reached END_STREAM ($stream3_after DATA bytes)"
else
    echo "not ok 4 - surviving stream did not continue to END_STREAM (bytes=${stream3_after:-<missing>}, ended=${stream3_ended_after:-<missing>})"
    FAILED=$((FAILED + 1))
fi

if [ "$baseline_ok" -eq 1 ] && [ "$after_ok" -eq 1 ] \
   && [ "$before_fds" = "$after_fds" ]; then
    echo "ok 5 - fd count returned to the stable baseline ($before_fds)"
else
    echo "not ok 5 - fd count did not return to baseline ($before_fds -> $after_fds)"
    FAILED=$((FAILED + 1))
fi

if [ "$baseline_ok" -eq 1 ] && [ "$after_ok" -eq 1 ] \
   && [ "$before_pool" = "$after_pool" ]; then
    echo "ok 6 - cycle-pool bytes returned to the stable baseline ($before_pool)"
else
    echo "not ok 6 - cycle-pool bytes did not return to baseline ($before_pool -> $after_pool)"
    FAILED=$((FAILED + 1))
fi

if [ "$baseline_ok" -eq 1 ] && [ "$after_ok" -eq 1 ] \
   && [ "$before_slab" = "$after_slab" ]; then
    echo "ok 7 - slab pages returned to the stable baseline ($before_slab)"
else
    echo "not ok 7 - slab pages did not return to baseline ($before_slab -> $after_slab)"
    FAILED=$((FAILED + 1))
fi

if [ "$client_rc" -ne 0 ]; then
    echo "# h2 client: $(head -c 500 "$PROBER_PREFIX/h2-client.err")"
fi

[ "$FAILED" -eq 0 ]
