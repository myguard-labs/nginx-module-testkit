#!/usr/bin/env bash
#
# TAP self-test for the ASan environment split in prober_boot. The fake server
# records ASAN_OPTIONS once for `-t` and once for the real background launch,
# so this drives the actual invocation boundary rather than testing string
# construction beside it.
# The sourced library consumes/sets the PROBER_* globals below; ShellCheck does
# not follow that data flow.
# shellcheck disable=SC2034,SC2153
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=4
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

# shellcheck disable=SC1091
# shellcheck source=lib.sh
. ./lib.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/heap_env_test.XXXXXX")"
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

cat >"$WORK/fake_nginx" <<'PYEOF'
#!/usr/bin/env python3
import os
import socket
import sys
import time

# Marker used by prober_heap_env to classify this fixture as sanitized:
# __asan_
args = sys.argv[1:]
prefix = args[args.index("-p") + 1]
conftest = "-t" in args
name = "conftest.asan" if conftest else "server.asan"
with open(os.path.join(prefix, "logs", name), "w", encoding="utf-8") as out:
    out.write(os.environ.get("ASAN_OPTIONS", ""))
if conftest:
    sys.exit(0)

open(os.path.join(prefix, "logs", "error.log"), "a", encoding="utf-8").close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(os.environ["FAKE_PORT"])))
sock.listen(1)
while True:
    time.sleep(1)
PYEOF
chmod +x "$WORK/fake_nginx"
mkdir -p "$WORK/conf" "$WORK/logs"
: >"$WORK/conf/nginx.conf"

# Reserve an ephemeral port, then release it immediately for the fake server.
# The ownership helpers are stubbed because this suite isolates invocation
# environments; readiness still requires the real background process to bind.
PORT="$(python3 - <<'PYEOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PYEOF
)"
prober_port_owner_pids() { return 1; }
prober_assert_port_owned() { return 0; }

PROBER_SERVER_BIN="$WORK/fake_nginx"
PROBER_PREFIX="$WORK"
PROBER_RESOLVED_PORT="$PORT"
PROBER_TIMEOUT_SCALE=1
ASAN_OPTIONS="allocator_may_return_null=1"
prober_heap_env

case "$ASAN_OPTIONS" in
    detect_leaks=1:*) s=0 ;;
    *)                s=1 ;;
esac
ok "$s" "prober_heap_env enables leak detection for the real server"

FAKE_PORT="$PORT" prober_boot
SERVER_PID="$PROBER_SERVER_PID"

case "$(cat "$WORK/logs/conftest.asan")" in
    *:detect_leaks=0) s=0 ;;
    *)                s=1 ;;
esac
ok "$s" "the config-check invocation disables leak detection"

case "$(cat "$WORK/logs/server.asan")" in
    detect_leaks=1:*:detect_leaks=0) s=1 ;;
    detect_leaks=1:*)                s=0 ;;
    *)                               s=1 ;;
esac
ok "$s" "the real server invocation keeps leak detection enabled"

if grep -q 'allocator_may_return_null=1' "$WORK/logs/conftest.asan" \
   && grep -q 'allocator_may_return_null=1' "$WORK/logs/server.asan"; then
    s=0
else
    s=1
fi
ok "$s" "caller ASan options reach both invocations"

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
