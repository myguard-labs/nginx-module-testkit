#!/usr/bin/env python3
"""Drive one scenario-local ordered H2-3c framing sequence."""

import hashlib
import os
import socket
import sys
import time


def frame(frame_type, flags, stream_id, payload=b""):
    """Return one HTTP/2 frame with its exact nine-byte wire header."""
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def build_attack(kind, minimal_get):
    """Build one bounded attack sequence after SETTINGS and stream setup."""
    ping = frame(6, 0, 0, b"multi-h2")
    if kind == "oversized-zero":
        # DATA may be empty; PING payloads must be exactly eight bytes.
        return (
            frame(0, 0, 1)
            + frame(6, 0, 0, b"boundary")
            + frame(6, 0, 0, b"oversized")
            + ping
        )
    if kind == "continuation":
        # PING interrupts a header block whose CONTINUATION never ends it.
        return frame(1, 0, 3, b"\x82") + frame(9, 0, 3, b"\x84") + ping
    if kind == "settings-flood":
        return b"".join(frame(4, 0, 0) for _ in range(128)) + ping
    if kind == "rst-storm":
        opens = b"".join(
            frame(1, 4, stream_id, minimal_get)
            for stream_id in range(3, 67, 2)
        )
        resets = b"".join(
            frame(3, 0, stream_id, (8).to_bytes(4, "big"))
            for stream_id in range(1, 67, 2)
        )
        return opens + resets + ping
    raise RuntimeError("unknown multiframe kind: " + kind)


def drain_frames(buf, consume):
    """Consume complete frames, retaining a truncated tail for the next read."""
    while len(buf) >= 9:
        length = int.from_bytes(buf[0:3], "big")
        end = 9 + length
        if len(buf) < end:
            return
        frame_type = buf[3]
        flags = buf[4]
        stream_id = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
        payload = bytes(buf[9:end])
        del buf[:end]
        consume(frame_type, flags, stream_id, payload)


def record_frame(state, sock, frame_type, flags, stream_id, payload):
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Record only response fields consumed by the scenario's TAP oracles."""
    if frame_type == 4 and stream_id == 0:
        if flags & 1:
            state["client_settings_ack"] = True
            state["settings_acks"] += 1
        else:
            state["server_settings"] = True
            sock.sendall(frame(4, 1, 0))
    if frame_type == 7 and stream_id == 0 and len(payload) >= 8:
        state["goaway_errors"].append(str(int.from_bytes(payload[4:8], "big")))
    if (
        frame_type == 6
        and stream_id == 0
        and flags & 1
        and payload == b"multi-h2"
    ):
        state["ping_ack"] = True


def pump(sock, buf, state, deadline, stop):
    """Read until a state predicate, EOF, or a monotonic deadline."""

    def consume(*args):
        record_frame(state, sock, *args)

    drain_frames(buf, consume)
    while time.monotonic() < deadline:
        if stop():
            return
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, socket.timeout):  # noqa: UP041
            continue
        except OSError:
            drain_frames(buf, consume)
            state["eof"] = True
            return
        if not chunk:
            drain_frames(buf, consume)
            state["eof"] = True
            return
        buf.extend(chunk)
        drain_frames(buf, consume)


def run_self_test():
    """Exercise the helper's boundary, malformed, and error branches offline."""
    minimal_get = bytes.fromhex("828486410670726f626572")
    oversized = build_attack("oversized-zero", minimal_get)
    zero_end = 9
    boundary_end = zero_end + 9 + 8
    one_over_end = boundary_end + 9 + 9
    if int.from_bytes(oversized[0:3], "big") != 0:
        raise RuntimeError("zero-length DATA boundary missing")
    if int.from_bytes(oversized[zero_end:zero_end + 3], "big") != 8:
        raise RuntimeError("exact PING payload boundary missing")
    if int.from_bytes(oversized[boundary_end:boundary_end + 3], "big") != 9:
        raise RuntimeError("one-over PING payload boundary missing")
    if oversized[one_over_end:] != frame(6, 0, 0, b"multi-h2"):
        raise RuntimeError("ordered PING witness missing after DATA boundaries")
    print("SELFTEST_BOUNDARIES_OK")

    expected_lengths = {
        "oversized-zero": 61,
        "continuation": 37,
        "settings-flood": 1169,
        "rst-storm": 1086,
    }
    for kind, expected in expected_lengths.items():
        if len(build_attack(kind, minimal_get)) != expected:
            raise RuntimeError(kind + " attack length changed")
    continuation = build_attack("continuation", minimal_get)
    if continuation[3:5] != b"\x01\x00" or continuation[13:15] != b"\x09\x00":
        raise RuntimeError("CONTINUATION sequence ended before the PING witness")
    print("SELFTEST_SHAPES_OK")

    seen = []
    truncated = bytearray(bytes.fromhex("00000807000000000000000000"))
    drain_frames(truncated, lambda *args: seen.append(args))
    if seen or len(truncated) != 13:
        raise RuntimeError("truncated response escaped the complete-frame guard")
    print("SELFTEST_MALFORMED_OK")

    try:
        build_attack("unknown", minimal_get)
    except RuntimeError as exc:
        if str(exc) != "unknown multiframe kind: unknown":
            raise
    else:
        raise RuntimeError("unknown attack kind did not fail closed")
    print("SELFTEST_ERROR_OK")


def main():
    """Run either the offline self-test or one live ordered frame sequence."""
    if os.environ.get("H2_MULTIFRAME_SELF_TEST") == "1":
        run_self_test()
        return 0

    host = os.environ["H"]
    port = int(os.environ["P"])
    kind = os.environ["K"]
    minimal_get = bytes.fromhex(os.environ["G"])
    sock = None
    buf = bytearray()
    state = {
        "server_settings": False,
        "client_settings_ack": False,
        "goaway_errors": [],
        "ping_ack": False,
        "settings_acks": 0,
        "eof": False,
    }
    status = "DELIVERY_OK"
    marker = ""
    request_inflight = False

    try:
        sock = socket.create_connection((host, port), 5)
        sock.settimeout(0.2)
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        sock.sendall(preface + frame(4, 0, 0))
        pump(
            sock,
            buf,
            state,
            time.monotonic() + 3,
            lambda: state["server_settings"] and state["client_settings_ack"],
        )
        if not state["server_settings"] or not state["client_settings_ack"]:
            raise RuntimeError("SETTINGS negotiation did not complete")
        # END_HEADERS without END_STREAM opens stream 1 only after SETTINGS.
        sock.sendall(frame(1, 4, 1, minimal_get))
        request_inflight = True

        attack = build_attack(kind, minimal_get)
        sock.sendall(attack)
        marker = f"{kind}:{len(attack)}:{hashlib.sha256(attack).hexdigest()}"
        pump(sock, buf, state, time.monotonic() + 3, lambda: False)
    except (KeyError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
        # The caller scores every failure as TAP red.
        status = f"DELIVERY_FAIL:{str(exc).replace(chr(10), ' ')}"
    finally:
        if sock is not None:
            sock.close()

    print(status)
    print(int(state["server_settings"] and state["client_settings_ack"]))
    print(int(request_inflight))
    print(marker)
    print(",".join(state["goaway_errors"]))
    print(int(state["ping_ack"]))
    print(state["settings_acks"])
    print(int(state["eof"]))
    return 0 if status == "DELIVERY_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
