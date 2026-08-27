#!/usr/bin/env bash
#
# TAP self-test for the ALPN directives (`alpn`, `alpn_raw`, `expect_alpn`,
# `expect_alpn_refused`).
#
# WHY THIS EXISTS ALONGSIDE THE SCENARIO. scenarios/alpn-negotiation drives the
# same code against a real nginx and is the evidence that the WORKER gives up
# nothing across a failed negotiation. What it structurally cannot do is prove
# the refusal oracle can FAIL: every offer it makes is one the nginx fixture
# refuses, so a `expect_alpn_refused` that reported "refused" unconditionally
# would satisfy every case there. An oracle only agreed with is not an oracle.
#
# So this file stands up a TLS server that ACCEPTS ANY ALPN PROTOCOL IT IS
# OFFERED -- the negative control the row demands -- and requires the refusal
# assertion to go RED against it. That server cannot be nginx: nginx refuses an
# unsatisfiable offer, which is precisely the behaviour under test, so the
# control has to come from somewhere that can be told to say yes to anything.
# Python's ssl module can, via an ALPN callback that echoes the client's first
# offer back.
#
# The pairing is the point, and the two halves live where each is provable:
#   - against a server that REFUSES, `expect_alpn_refused` must PASS. Only
#     nginx sends RFC 7301's fatal alert, so that half is asserted in
#     scenarios/alpn-negotiation, not here.
#   - against a server that ACCEPTS, the same assertion must FAIL, naming the
#     acceptance. Only a server that can be told to say yes to anything shows
#     that, which is this file.
# A harness that always passed would fail the second; one that always failed
# would fail the first. Neither can be reached by getting the code right.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=10
tests_run=0
failures=0

echo "1..$PLANNED"

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
    fi
}

WORK="$(mktemp -d)"
SRV_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

./build.sh >/dev/null

# python3 and openssl(1) are both already gated dependencies elsewhere in this
# tree (see tls_test.sh and scenarios/tls-listener/requires), so this adds no
# new requirement -- but a missing one must bail rather than silently skip the
# only place the refusal oracle is falsified.
for tool in python3 openssl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "Bail out! $tool not found -- needed for the ALPN control server"
        exit 1
    }
done

# ---- parser-level claims, no server needed ----------------------------------
#
# --check parses and validates without connecting, so these cost no handshake.
# They are the load-time rules that keep a case from asserting something it
# could never reach; each is a die() whose absence would let a vacuous case run.

cat >"$WORK/refused-no-probe.rule" <<'EOF'
name                  no worker-side evidence
send                  GET / HTTP/1.1\r\n
send                  Host: prober\r\nConnection: close\r\n\r\n
alpn                  h2
expect_alpn_refused
EOF

out="$(./prober --check "$WORK/refused-no-probe.rule" 2>&1)" && status=0 || status=$?
case "$out" in
    *"no probe/delta/probe_baseline"*)
        ok "$((status == 0 ? 1 : 0))" \
           "expect_alpn_refused without probe evidence is refused at load time" ;;
    *)
        ok 1 "expect_alpn_refused without probe evidence is refused at load time (got: $out)" ;;
esac

cat >"$WORK/expect-no-offer.rule" <<'EOF'
name          asserts a protocol it never offered
send          GET / HTTP/1.1\r\n
send          Host: prober\r\nConnection: close\r\n\r\n
expect_alpn   h2
EOF

out="$(./prober --check "$WORK/expect-no-offer.rule" 2>&1)" && status=0 || status=$?
case "$out" in
    *"offers no \`alpn\` list"*)
        ok "$((status == 0 ? 1 : 0))" \
           "expect_alpn without an offer is refused at load time" ;;
    *)
        ok 1 "expect_alpn without an offer is refused at load time (got: $out)" ;;
esac

cat >"$WORK/both.rule" <<'EOF'
name                  both forms at once
send                  GET / HTTP/1.1\r\n
send                  Host: prober\r\nConnection: close\r\n\r\n
alpn                  h2
alpn_raw              \x02h2
expect_alpn_refused
delta                 fds == 0
EOF

out="$(./prober --check "$WORK/both.rule" 2>&1)" && status=0 || status=$?
case "$out" in
    *"mutually exclusive"*)
        ok "$((status == 0 ? 1 : 0))" "alpn and alpn_raw are mutually exclusive" ;;
    *)
        ok 1 "alpn and alpn_raw are mutually exclusive (got: $out)" ;;
esac

cat >"$WORK/empty-name.rule" <<'EOF'
name                  an empty protocol name
send                  GET / HTTP/1.1\r\n
send                  Host: prober\r\nConnection: close\r\n\r\n
alpn                  h2,,http/1.1
expect_alpn_refused
delta                 fds == 0
EOF

out="$(./prober --check "$WORK/empty-name.rule" 2>&1)" && status=0 || status=$?
case "$out" in
    *"empty protocol name"*)
        ok "$((status == 0 ? 1 : 0))" \
           "an empty ALPN protocol name is refused rather than encoded as a zero-length entry" ;;
    *)
        ok 1 "an empty ALPN protocol name is refused (got: $out)" ;;
esac

# ---- the two control servers ------------------------------------------------

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 1 -subj '/CN=prober' >"$WORK/openssl.log" 2>&1 || {
    echo "Bail out! openssl failed to mint the fixture certificate; see $WORK/openssl.log"
    exit 1
}
chmod 600 "$WORK/k.pem"

# Two servers in one script, selected by argv, so the certificate, the probe
# reply and the HTTP framing cannot drift between them -- the ONLY difference
# between the control and the comparison must be the ALPN policy, or the
# pairing at the end proves nothing about ALPN.
cat >"$WORK/server.py" <<'PYEOF'
import socket, ssl, sys, threading

# `permissive` accepts whatever it is offered; `strict` accepts only http/1.1
# and refuses everything else, which is what nginx does.
POLICY = sys.argv[1]
CERT, KEY = sys.argv[2], sys.argv[3]

def http(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
            b"Connection: close\r\n\r\n%s" % (len(body), body))

# The prober fetches /__probe for its ORIGIN snapshot before any case runs and
# parses the body as probe JSON, so a server answering every path with the same
# fixed body fails that fetch with "malformed number" and reds every case for a
# reason unrelated to ALPN. The numbers are arbitrary; nothing here asserts a
# delta.
PROBE = http(b'{"fds":7,"pid":1,"conns":1}')
REPLY = http(b"OK\n")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)

if POLICY == "permissive":
    # THE NEGATIVE CONTROL: a server that ACCEPTS the very protocol the rule
    # file asserts will be refused.
    #
    # Done by ADVERTISING the hostile protocol rather than by installing an
    # accept-anything ALPN callback, and that is forced rather than preferred:
    # ssl.SSLContext exposes no ALPN select callback at all (checked on this
    # box, CPython 3.13 / OpenSSL 3.5.6 -- neither set_alpn_select_callback nor
    # the private _set_alpn_select_callback exists). An earlier version of this
    # file called the private name inside a try/except AttributeError, which
    # swallowed the failure and left the "permissive" server byte-identical to
    # the strict one -- a negative control that controlled nothing, and could
    # not have failed. Naming the protocol is checkable by reading this file.
    #
    # HOSTILE must stay in step with the offer in $WORK/refuse.rule; the
    # assertion below is what notices if it drifts, since a server that does
    # not actually accept the offer makes the refusal assertion pass and the
    # control reports the wrong verdict loudly rather than silently.
    ctx.set_alpn_protocols(["nosuchprotocol/9.9", "http/1.1"])
else:
    ctx.set_alpn_protocols(["http/1.1"])

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(8)

# The port goes out BEFORE the first accept, so the caller never polls for
# readiness: by the time it can read the number, listen() has been called and a
# connect cannot be refused.
sys.stdout.write("%d\n" % srv.getsockname()[1])
sys.stdout.flush()

def serve(raw):
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        # A refused ALPN lands here, which is the point for the strict server:
        # the handshake dies and the client sees the alert.
        try:
            raw.close()
        except OSError:
            pass
        return
    try:
        req = c.recv(65536)
        c.sendall(PROBE if b"/__probe" in req else REPLY)
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PYEOF

start_server() {
    exec 4< <(python3 "$WORK/server.py" "$1" "$WORK/c.pem" "$WORK/k.pem")
    SRV_PID=$!
    read -r PORT <&4

    if [ -z "${PORT:-}" ]; then
        echo "Bail out! the $1 ALPN server published no port"
        exit 1
    fi
}

stop_server() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    SRV_PID=""
    exec 4<&- 2>/dev/null || true
}

# The rule file used against BOTH servers, byte for byte. Using one file is
# what makes the pair a controlled comparison: if the two runs used different
# rules, a difference in verdict would say nothing about the servers.
cat >"$WORK/refuse.rule" <<'EOF'
name                  the peer must refuse this offer
send                  GET / HTTP/1.1\r\n
send                  Host: prober\r\nConnection: close\r\n\r\n
alpn                  nosuchprotocol/9.9
expect_alpn_refused
delta                 fds == 0
EOF

# ---- the TOLERANT server: negotiation works, and a no-overlap offer is NOT
# ---- a refusal -------------------------------------------------------------
#
# Python's ssl module takes OpenSSL's TOLERANT ALPN default: an offer with no
# overlap selects NO protocol and the handshake SUCCEEDS -- measured here on
# OpenSSL 3.5.6, 2026-08-27. Only a server whose callback opts into RFC 7301's
# fatal alert (nginx does) refuses. That is a fact about the control server,
# not a gap in it, and it is what makes the pairing below meaningful: the
# "refuses" half of the oracle is proved against real nginx in
# scenarios/alpn-negotiation, which is the only thing here that can send alert
# 120, while the "must not pass when the peer accepts" half is proved here,
# which is the only thing that can be told to accept anything.
#
# So a no-overlap offer against this server is a case where the handshake
# SUCCEEDS with no protocol negotiated -- which `expect_alpn_refused` must
# still treat as a failure, since no refusal occurred.

start_server strict

cat >"$WORK/accept.rule" <<'EOF'
name          a supported protocol negotiates
send          GET / HTTP/1.1\r\n
send          Host: prober\r\nConnection: close\r\n\r\n
alpn          http/1.1
expect_alpn   http/1.1
expect        status=200
EOF

./prober -H 127.0.0.1 -p "$PORT" -t 5000 --tls "$WORK/accept.rule" \
    >"$WORK/accept.out" 2>&1 && status=0 || status=$?
ok "$status" "expect_alpn reports the protocol the server selected"

# The readback is the SERVER's choice, not the client's offer: this offers h2
# first and demands http/1.1, which the strict server selects. A readback that
# echoed the offer reports h2 and reds here.
cat >"$WORK/fallback.rule" <<'EOF'
name          the server picks from the list rather than taking the first entry
send          GET / HTTP/1.1\r\n
send          Host: prober\r\nConnection: close\r\n\r\n
alpn          h2,http/1.1
expect_alpn   http/1.1
expect        status=200
EOF

./prober -H 127.0.0.1 -p "$PORT" -t 5000 --tls "$WORK/fallback.rule" \
    >"$WORK/fallback.out" 2>&1 && status=0 || status=$?
ok "$status" "expect_alpn reads the server's selection, not the client's offer"

stop_server

# ---- the PERMISSIVE server: THE NEGATIVE CONTROL ----------------------------
#
# THIS IS THE CASE THE ROW ASKS FOR. Same rule file, same offer, a server that
# accepts anything -- and the refusal assertion must go RED. A green here means
# `expect_alpn_refused` is satisfied by a server that refuses nothing, at which
# point every refusal case in scenarios/alpn-negotiation is vacuous.

start_server permissive

./prober -H 127.0.0.1 -p "$PORT" -t 5000 --tls "$WORK/refuse.rule" \
    >"$WORK/permissive.out" 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" \
   "expect_alpn_refused FAILS against a server that accepts any ALPN (the negative control)"

# ...and it fails BY THE REFUSAL ASSERTION, naming THE PROTOCOL THE SERVER
# ACCEPTED. Requiring the protocol NAME rather than merely the phrase
# "handshake SUCCEEDED" is what makes this case discriminate, and it is the
# difference between a control and a decoration:
#
# OpenSSL's DEFAULT ALPN behaviour is tolerant -- a server offered a list it
# shares nothing with completes the handshake having selected NO protocol.
# That is also a handshake that "SUCCEEDED", so a check for the phrase alone
# passes against the strict server too, and the two servers become
# interchangeable. Measured 2026-08-27: against `strict` the diagnostic reads
# `negotiated "(no protocol)"`, against `permissive` it reads
# `negotiated "nosuchprotocol/9.9"` -- and only the second is a server that
# ACCEPTED the offer, which is the state this control exists to produce.
#
# So the assertion demands the protocol name. Swap `start_server permissive`
# for `start_server strict` above and this line goes red, which is the
# property a negative control has to have and the earlier version of this file
# did not.
if grep -q 'handshake SUCCEEDED (negotiated "nosuchprotocol/9.9")' \
        "$WORK/permissive.out"; then
    ok 0 "the control fails naming the ACCEPTED protocol, not merely a successful handshake"
else
    ok 1 "the control fails naming the ACCEPTED protocol (got: $(head -c 400 "$WORK/permissive.out"))"
fi

stop_server

# ---- a handshake that fails for a NON-ALPN reason is not a refusal ----------
#
# THE ROW THAT KEEPS `expect_alpn_refused` A STATEMENT ABOUT ALPN. The
# directive is satisfied only by RFC 7301's `no_application_protocol` alert; if
# it accepted ANY handshake failure it would be satisfied by a wrong port, a
# missing certificate or a fixture that never booted, and a case asserting it
# would go green on a server that was never even asked about protocols.
#
# The instrument has to fail the CASE's handshake while leaving the PROBE
# fetches working -- the prober reads /__probe over the same transport before
# any case runs, so a fixture that refused every handshake would die at the
# origin snapshot and the case would never be reached at all. Measured
# 2026-08-27: pointing this at a plain non-TLS responder does exactly that, the
# widened branch is never executed, and the mutation survives.
#
# So the server below completes the handshake normally for the probe and ABORTS
# it -- a bare TCP close mid-handshake, no alert of any kind -- for the
# connection carrying the case's hostile ALPN offer. The offered list travels
# in the ClientHello in cleartext, so that decision can be made by PEEKING at
# the first flight without completing a handshake. The result is a handshake
# failure that is emphatically not an ALPN refusal, so the case must go RED as
# an ordinary request failure rather than be satisfied by it.
cat >"$WORK/picky.py" <<'PYEOF'
import socket, ssl, sys, threading

CERT, KEY = sys.argv[1], sys.argv[2]

def http(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
            b"Connection: close\r\n\r\n%s" % (len(body), body))

PROBE = http(b'{"fds":7,"pid":1,"conns":1}')
REPLY = http(b"OK\n")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
ctx.set_alpn_protocols(["http/1.1"])

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(8)
sys.stdout.write("%d\n" % srv.getsockname()[1])
sys.stdout.flush()

HOSTILE = b"nosuchprotocol/9.9"

def serve(raw):
    try:
        head = raw.recv(4096, socket.MSG_PEEK)
    except OSError:
        raw.close()
        return

    if HOSTILE in head:
        try:
            raw.close()
        except OSError:
            pass
        return

    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        try:
            raw.close()
        except OSError:
            pass
        return

    try:
        req = c.recv(65536)
        c.sendall(PROBE if b"/__probe" in req else REPLY)
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PYEOF

exec 4< <(python3 "$WORK/picky.py" "$WORK/c.pem" "$WORK/k.pem")
SRV_PID=$!
read -r PORT <&4

if [ -z "${PORT:-}" ]; then
    echo "Bail out! the selective TLS responder published no port"
    exit 1
fi

./prober -H 127.0.0.1 -p "$PORT" -t 2000 --tls "$WORK/refuse.rule" \
    >"$WORK/nonalpn.out" 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" \
   "a handshake failing for a NON-ALPN reason does not satisfy expect_alpn_refused"

# ...and it is not MISLABELLED a refusal. This is the assertion the reason-code
# check exists for: a widened check reports the abort above as "peer refused
# every offered ALPN protocol", a claim about a negotiation the peer never made.
if grep -qi 'refused every offered ALPN' "$WORK/nonalpn.out"; then
    ok 1 "the non-ALPN failure is not mislabelled a refusal (it was: $(head -c 300 "$WORK/nonalpn.out"))"
else
    ok 0 "the non-ALPN failure is not mislabelled a refusal"
fi

stop_server

# ---- plan reconciliation ----------------------------------------------------

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
