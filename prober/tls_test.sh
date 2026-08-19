#!/usr/bin/env bash
#
# TAP self-test for `prober --tls`.
#
# http_test.c covers the TLS transport itself (handshake, reader, side-table
# teardown) against throwaway servers, and prober/scenarios/tls-listener covers
# the whole path against a real nginx `listen ... ssl`. Neither reaches the CLI
# WIRING in between, which is what this file exists for: that --tls is accepted,
# that it actually reaches opt_tls.enable, and that a client carrying it behaves
# differently on the wire from one that does not.
#
# THE LOAD-BEARING CASE IS THE HANDSHAKE PROBE. A test that only asserted
# "--tls is accepted and exits 0" would still pass with `opt_tls.enable = 0`
# patched in -- the flag would parse, do nothing, and every assertion would be
# green. So the flag is proved by pointing the prober at a PLAINTEXT listener:
# with TLS armed the client tries to hand it a ClientHello and the exchange
# fails, while the same rule file against the same listener without --tls
# succeeds. The pair is what makes the claim falsifiable in both directions.
#
# No nginx is needed: a plain TCP responder is enough, because the property
# under test is what the CLIENT does, not what any server understands.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=6
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

# ---- the flag parses --------------------------------------------------------

# No `from` directive: this case needs no delta, only that the exchange
# completes. The probe snapshot is taken regardless (it is the run's ORIGIN
# snapshot, not a per-case one), which is why the responder below has to answer
# /__probe with well-formed probe JSON -- a responder that returned the same
# fixed body for every path fails the snapshot with "malformed number" and reds
# this case for a reason that has nothing to do with the transport.
cat >"$WORK/good.rule" <<'EOF'
name    a well-formed case
send    GET / HTTP/1.1\r\n
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
EOF

# --check exits before connecting, so this asks only whether the argv walker
# accepts --tls at all. It is the cheap half of the claim; the wire behaviour
# below is the half that cannot be faked.
./prober --check --tls "$WORK/good.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$status" "--tls is accepted alongside --check"

# Argument-less, like --check: if it were handled below the "flag needs a
# value" guard it would consume the rule file as its argument and the run would
# report a missing rule file instead.
out="$(./prober --tls 2>&1)" && status=0 || status=$?
ok "$((status == 2 ? 0 : 1))" "--tls with no rule file exits 2 via usage()"

case "$out" in
    *"--tls"*) ok 0 "usage() documents --tls" ;;
    *) ok 1 "usage() documents --tls (got: $out)" ;;
esac

# ---- a plaintext listener, with and without --tls ---------------------------
#
# The responder answers any bytes with a fixed HTTP/1.1 200 and closes. Against
# a plaintext client that is a passing case; against a TLS client the first
# thing on the wire is a ClientHello, the responder replies with a status line
# that is not a ServerHello, and the handshake fails.

# The responder binds port 0 and PUBLISHES what the kernel gave it, rather
# than picking a port and hoping. Three things were tried before this:
#
#   - probing 18400-18460 by CONNECTING to each: consumes the port it selects
#     and races the listener about to bind it.
#   - `nc -l`: this box has the traditional v1.10 variant, whose listen syntax
#     differs from the OpenBSD one every example assumes.
#   - fakesrv, the repo's own fake upstream: it speaks memcached, not HTTP, so
#     it cannot answer the rule file's GET.
#
# The thing that made all three worth fixing rather than working around: a
# responder that never binds makes the --tls case pass on "Connection
# refused" -- a green that proves nothing about TLS. That vacuous pass actually
# happened here, and the handshake-naming case at the end is what caught it.
#
# python3 is already a gated dependency elsewhere in this tree (see
# scenarios/reload-compressing/requires), so this adds no new requirement.
if ! command -v python3 >/dev/null 2>&1; then
    echo "Bail out! python3 not found -- needed for the plaintext responder"
    exit 1
fi

cat >"$WORK/responder.py" <<'PYEOF'
import socket, sys, threading

# Two replies, because the prober fetches /__probe for its ORIGIN snapshot
# before running any case and parses the body as probe JSON. A responder that
# answered every path with the same fixed body fails that fetch with "malformed
# number", and the plaintext control case then reds for a reason unrelated to
# the transport under test.
#
# The probe numbers are arbitrary: nothing here asserts a delta, so they need
# only parse. The property under test is what the CLIENT puts on the wire
# first, so the responder still does not need to understand HTTP beyond telling
# the two paths apart.
def http(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
            b"Connection: close\r\n\r\n%s" % (len(body), body))

PROBE = http(b'{"fds":7,"pid":1,"conns":1}')
REPLY = http(b"OK\n")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(8)

# The port goes out on stdout BEFORE the first accept, so the caller never has
# to poll for readiness: by the time it can read the number, listen() has
# already been called and a connect cannot be refused.
sys.stdout.write("%d\n" % srv.getsockname()[1])
sys.stdout.flush()

def serve(c):
    try:
        req = c.recv(65536)
        c.sendall(PROBE if b"/__probe" in req else REPLY)
    except OSError:
        pass
    finally:
        c.close()

while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PYEOF

# The port is read from the pipe, which doubles as the readiness barrier.
exec 4< <(python3 "$WORK/responder.py")
SRV_PID=$!
read -r PORT <&4

if [ -z "${PORT:-}" ]; then
    echo "Bail out! the plaintext responder published no port"
    exit 1
fi

# WITHOUT --tls: the plaintext exchange completes. This is the control. If it
# fails, the responder is broken and the --tls case below proves nothing --
# which is exactly why it is asserted rather than assumed.
./prober -H 127.0.0.1 -p "$PORT" -t 2000 "$WORK/good.rule" >/dev/null 2>&1 \
    && status=0 || status=$?
ok "$status" "the plaintext responder satisfies the rule without --tls"

# WITH --tls: the same rule, the same listener, and the exchange must NOT
# succeed. This is the case that dies if opt_tls.enable is patched to 0.
./prober -H 127.0.0.1 -p "$PORT" -t 2000 --tls "$WORK/good.rule" \
    >"$WORK/tls.out" 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" \
   "--tls against a PLAINTEXT listener fails (the flag reaches the transport)"

# ...and it fails as a HANDSHAKE, not as some unrelated error. Without this the
# case above would also pass if --tls broke the client in any other way -- a
# crash, a bad port, a connection that was never established -- none of which
# would prove the TLS transport was engaged.
#
# "Connection refused" is excluded EXPLICITLY rather than left to the tls/ssl
# match, because a refused connection is the one failure mode that looks like
# success to every other assertion in this file.
if grep -qi 'connection refused' "$WORK/tls.out"; then
    ok 1 "the --tls failure names the handshake (connection was refused, so the responder never bound)"
elif grep -qi 'tls\|ssl\|handshake' "$WORK/tls.out"; then
    ok 0 "the --tls failure names the handshake"
else
    ok 1 "the --tls failure names the handshake (got: $(cat "$WORK/tls.out"))"
fi

# ---- plan reconciliation ----------------------------------------------------

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
