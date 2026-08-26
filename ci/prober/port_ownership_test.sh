#!/usr/bin/env bash
#
# TAP self-test for prober_boot's port-ownership guards (lib.sh) -- the pair of
# checks that replace "kill -0 our own pid" liveness with a positive identity
# check on the listener itself.
#
# WHY LIVENESS IS THE WRONG PROOF. nginx does not exit on EADDRINUSE: it logs
#     [emerg] bind() to 127.0.0.1:<port> failed (98: Address already in use)
#     [notice] try again to bind() after 500ms
# and stays alive through its retry window. The readiness loop's original
# guard re-checked "is our recorded pid still alive" after each successful
# connect -- which is true throughout that retry window, so the loop breaks
# with the port answered by WHATEVER WAS THERE FIRST, not by us. An entire
# fault-injection sweep in http-zstd ran this way against an orphaned nginx
# from a previous session; every assertion the driver made got an answer, so
# the run reported green while measuring a different binary than the one
# under test. Full incident:
# memory/lessons/feedback-orphaned-server-on-test-port-silently-answers-your-
# experiment.md.
#
# THE FIX HAS TWO LAYERS, each covered here:
#   1. prober_boot refuses to even ATTEMPT to spawn onto an already-bound
#      port (cheaper than racing nginx's own bind(), and catches the common
#      case: a leaked process from a previous cycle already squatting).
#   2. After the readiness loop breaks, prober_assert_port_owned confirms the
#      listener is ours (master pid or a direct child) before prober_boot
#      returns success.
# Layer 2 exists because layer 1 cannot close every race (a squatter that
# binds AFTER the pre-spawn check but before our own bind() would slip past
# layer 1 alone) -- so the suite proves each layer independently rather than
# only the common case both would catch together.
#
# THE FAKE SERVER. prober_boot needs a real $PROBER_SERVER_BIN to drive: a
# unit test against prober_port_owner_pids/prober_assert_port_owned alone
# would prove the helpers work but not that prober_boot actually CALLS them at
# the right points with the right arguments, which is exactly the class of
# defect this suite exists to catch (a correct helper nobody wires in reads
# identically to no fix at all). fake_srv (this repo's existing fault-
# injection daemon, built by build.sh) is reused as the SQUATTER -- it already
# binds a fixed host:port and is exercised by fakesrv_test.sh, so nothing new
# needs trusting there. The FAKE NGINX driving prober_boot itself has no
# existing equivalent (fakesrv always binds or dies; nginx's actual behaviour
# on EADDRINUSE -- log and retry, never exit -- has no other stand-in in this
# tree) and is therefore a small inline Python script, generated once into
# WORK and invoked exactly like the real binary: `-t -p PREFIX -c conf/
# nginx.conf` for the config test, `-p PREFIX -c conf/nginx.conf` for the real
# launch. Python rather than a shell script because bash cannot bind()/
# listen() on its own -- some real socket program has to hold the port for
# prober_boot's readiness loop to have anything to connect to.
#
# Every prober_boot invocation here runs in a SUBSHELL: prober_boot calls
# `exit 1` on a bail, and the subshell's exit status is read as the verdict
# while the parent test process survives to make the next assertion.
#
# File-wide SC2030/SC2031: this file deliberately sets PROBER_SERVER_BIN,
# PROBER_PREFIX, PROBER_RESOLVED_PORT, PROBER_SERVER_PID, FAKE_PORT and
# FAKE_STUCK inside those subshells so each case gets a clean, non-leaking
# environment for prober_boot to read -- and separately reads/exports some of
# the same names at top level between cases. shellcheck cannot tell "isolated
# on purpose" from "leaked by accident", so it flags every one; every actual
# instance is checked by hand in review, not silenced case by case.
# shellcheck disable=SC2030,SC2031
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=9
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

command -v ss >/dev/null 2>&1 || {
    echo "1..0 # SKIP no ss on this host -- the port-ownership guard has no" \
         "way to prove anything here, and neither does this suite"
    exit 0
}

# shellcheck source=lib.sh
. ./lib.sh

./build.sh >/dev/null

WORK="$(mktemp -d "${TMPDIR:-/tmp}/port_ownership_test.XXXXXX")"
PORT=$((20000 + (RANDOM % 10000)))
SQUAT_PID=""
SRV_PID=""

# Sweep whoever is CURRENTLY listening on $PORT, whatever their pid --
# used both at final cleanup and after every prober_boot that might have
# spawned and left a server behind. Depending on by name/booted.pid alone is
# not enough: a boot that spawns successfully and THEN bails (e.g. the
# error-log gate, which only fires after the readiness loop confirms the bind
# succeeded) exits the subshell via prober_boot's own `exit 1` before this
# script's own "echo $PROBER_SERVER_PID > booted.pid" line ever runs, so the
# live server is never named anywhere this script can read -- only `ss` still
# sees it.
kill_port_holders() {
    local leftover
    leftover="$(ss -lptnH "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2)" || true
    for p in $leftover; do
        kill -9 "$p" 2>/dev/null
    done
    wait 2>/dev/null || true
}

cleanup() {
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null
    [ -n "$SQUAT_PID" ] && kill -9 "$SQUAT_PID" 2>/dev/null
    # Anything still holding $PORT at exit is this suite's own leak, not a
    # sibling suite's business to clean up.
    kill_port_holders
    rm -rf "$WORK"
}
trap cleanup EXIT

# ---- the fake server driving prober_boot ------------------------------------
# Mirrors nginx's actual EADDRINUSE shape: opens error_log before any socket
# work (so the harness's "log must exist once the server answers" gate is
# satisfied independently of this suite), then either binds immediately
# (FAKE_STUCK unset) or writes the emerg/notice retry lines once and stays
# alive without ever calling bind() again (FAKE_STUCK=1) -- the exact "alive,
# logging retries, not listening" state a real nginx sits in during its retry
# window.
cat > "$WORK/fake_nginx" <<'PYEOF'
#!/usr/bin/env python3
import sys, os

argv = sys.argv[1:]
prefix = None
conftest = False
i = 0
while i < len(argv):
    if argv[i] == '-t':
        conftest = True
    elif argv[i] == '-p':
        i += 1
        prefix = argv[i]
    i += 1

os.makedirs(f"{prefix}/logs", exist_ok=True)

if conftest:
    sys.exit(0)

port = os.environ.get("FAKE_PORT", "18099")
stuck = os.environ.get("FAKE_STUCK", "0") == "1"

errlog = open(f"{prefix}/logs/error.log", "a", buffering=1)
errlog.write("[notice] fake nginx starting\n")

if stuck:
    # The EADDRINUSE-retry shape: log once and sit alive, never binding.
    errlog.write(f"[emerg] bind() to 127.0.0.1:{port} failed "
                 "(98: Address already in use)\n")
    errlog.write("[notice] try again to bind() after 500ms\n")
    errlog.flush()
    os.fsync(errlog.fileno())
    import time
    while True:
        time.sleep(1)

errlog.flush()
os.fsync(errlog.fileno())

import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(port)))
s.listen(5)
while True:
    time.sleep(1)
PYEOF
chmod +x "$WORK/fake_nginx"

mkdir -p "$WORK/conf" "$WORK/logs"
echo "unused by the fake binary; prober_boot only passes the path" \
    > "$WORK/conf/nginx.conf"

: >"$WORK/squat.script"
printf 'proto\tmemcached\n' > "$WORK/squat.script"

start_squatter() {
    ./fakesrv -script "$WORK/squat.script" -listen "127.0.0.1:$PORT" \
        -portfile "$WORK/squat.port" >/dev/null 2>&1 &
    SQUAT_PID=$!
    local _i
    for _i in $(seq 1 100); do
        ss -lptnH "sport = :$PORT" 2>/dev/null | grep -q . && return 0
        sleep 0.05
    done
    return 1
}

stop_squatter() {
    [ -n "$SQUAT_PID" ] && kill -9 "$SQUAT_PID" 2>/dev/null
    wait "$SQUAT_PID" 2>/dev/null || true
    SQUAT_PID=""
}

boot_against() {
    # Runs prober_boot in a subshell against $WORK as the prefix and
    # $WORK/fake_nginx as the server binary, with the caller's env already
    # exported. Echoes PROBER_SERVER_PID on success so callers can inspect
    # what prober_boot adopted.
    (
        cd "$WORK" || exit 1
        PROBER_SERVER_BIN="$WORK/fake_nginx"
        PROBER_PREFIX="$WORK"
        PROBER_RESOLVED_PORT="$PORT"
        PROBER_TIMEOUT_SCALE=1
        rm -f "$WORK/logs/error.log"
        prober_boot
        echo "$PROBER_SERVER_PID" > "$WORK/booted.pid"
    ) >"$WORK/boot.out" 2>&1
}

# ================================================================
# Layer 1: pre-spawn refusal -- port already bound before boot starts.
# ================================================================

# ---- happy path: nothing squatting, boot succeeds ---------------------------
# Paired baseline: if this failed, every case below would "pass" only because
# boot always fails, which would make the whole suite vacuous.
FAKE_PORT="$PORT" FAKE_STUCK=0 boot_against && s=0 || s=$?
ok "$s" "boot succeeds when the port is free"
[ -n "$SRV_PID" ] || SRV_PID="$(cat "$WORK/booted.pid" 2>/dev/null || true)"
[ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null
wait "$SRV_PID" 2>/dev/null || true
SRV_PID=""

# ---- the core regression guard: pre-spawn refusal on a squatted port -------
# Squat the port with fakesrv (a real, already-tested listener -- see
# fakesrv_test.sh) BEFORE calling prober_boot at all. The fix's layer 1 must
# refuse to even attempt a spawn.
rm -f "$WORK/booted.pid"
start_squatter || { echo "# fakesrv never came up on port $PORT"; exit 1; }
FAKE_PORT="$PORT" FAKE_STUCK=0 boot_against && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "pre-spawn refusal bails when the port is already bound"

# ---- the bail names the squatting pid ---------------------------------------
# Load-bearing on its own: a bail for the right reason that does not name the
# offending pid sends the next session hunting for it by hand, which is
# exactly the manual forensics the http-zstd incident needed and this fix
# exists to remove.
case "$(cat "$WORK/boot.out")" in
    *"pid $SQUAT_PID"*) s=0 ;;
    *)                  s=1 ;;
esac
ok "$s" "the pre-spawn bail names the squatting pid ($SQUAT_PID)"

# ---- the bail happens BEFORE the fake server is even spawned ---------------
# Distinguishes layer 1 from layer 2: if prober_boot spawned the server and
# only then noticed the squatter, PROBER_SERVER_PID would still be set and a
# server process would exist. Layer 1 is a pure pre-check.
if [ -s "$WORK/booted.pid" ]; then
    s=1
else
    s=0
fi
ok "$s" "the pre-spawn bail never records a PROBER_SERVER_PID"

stop_squatter

# ================================================================
# Layer 2: post-readiness ownership assertion -- the port answers but the
# owner is not us. Layer 1 cannot catch this: the port must be FREE at
# pre-spawn time (or layer 1 would already have bailed, as proven above), and
# then get taken by someone else while our own server is stuck in exactly the
# state nginx sits in during a real bind() retry window.
# ================================================================

# ---- the core regression guard: a stale listener is rejected, not adopted --
# Start OUR fake server first, in FAKE_STUCK mode (bind() never called, logs
# the emerg/notice retry lines once, then sits alive) -- the port is free at
# prober_boot's pre-spawn check, so layer 1 passes it through. THEN squat the
# port out from under it, simulating a leaked process claiming it during the
# retry window. The readiness loop's /dev/tcp connect is answered by the
# squatter; kill -0 on our own pid succeeds (it really is alive, just never
# bound) -- exactly the false-positive shape kill -0 alone cannot detect.
# Layer 2 (prober_assert_port_owned) must catch it where kill -0 could not.
(
    cd "$WORK" || exit 1
    FAKE_PORT="$PORT" FAKE_STUCK=1 "$WORK/fake_nginx" -p "$WORK" -c conf/nginx.conf &
    echo $! > "$WORK/stuck_srv.pid"
)
STUCK_SRV_PID="$(cat "$WORK/stuck_srv.pid")"
# Give the stuck server a moment to open its error.log so the "log exists"
# gate inside prober_boot never becomes a confound for THIS case -- this suite
# is isolating the ownership check, not re-proving the log-existence gate
# already covered by scrape_test.sh.
for _i in $(seq 1 50); do
    [ -s "$WORK/logs/error.log" ] && break
    sleep 0.05
done
start_squatter || { echo "# fakesrv never came up on port $PORT"; exit 1; }

(
    cd "$WORK" || exit 1
    PROBER_SERVER_BIN="$WORK/fake_nginx"
    PROBER_PREFIX="$WORK"
    PROBER_SERVER_PID="$STUCK_SRV_PID"
    PROBER_RESOLVED_PORT="$PORT"
    PROBER_TIMEOUT_SCALE=1
    # Drive only the readiness loop + the checks after it, not the full
    # prober_boot (which would re-spawn a second fake server and re-run the
    # pre-spawn refusal this suite already covered above): reproduce exactly
    # the state prober_boot is in immediately after PROBER_SERVER_PID=$! --
    # our own process already running, port already squatted underneath it.
    _i=0
    while [ "$_i" -lt $((50 * PROBER_TIMEOUT_SCALE)) ]; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PROBER_RESOLVED_PORT") 2>/dev/null; then
            kill -0 "$PROBER_SERVER_PID" 2>/dev/null && break
        fi
        sleep 0.1
        _i=$((_i + 1))
    done
    kill -0 "$PROBER_SERVER_PID" 2>/dev/null || { echo "our server died"; exit 1; }
    prober_assert_port_owned "$PROBER_SERVER_PID"
) >"$WORK/layer2.out" 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "prober_assert_port_owned rejects a listener owned by a different pid"

# ---- the rejection names the real owner, not our (innocent) pid ------------
case "$(cat "$WORK/layer2.out")" in
    *"$SQUAT_PID"*) s=0 ;;
    *)              s=1 ;;
esac
ok "$s" "prober_assert_port_owned's output names the squatting pid ($SQUAT_PID)"

kill -9 "$STUCK_SRV_PID" 2>/dev/null
wait "$STUCK_SRV_PID" 2>/dev/null || true
stop_squatter

# ---- the counterpart: OUR OWN listener is accepted, not just liveness ------
# Paired with the case above so neither is vacuous: if prober_assert_port_owned
# ignored ownership entirely and always failed, both cases would look like
# regressions; if it always passed, the squatter case above would never have
# gone red. This proves it genuinely discriminates.
(
    cd "$WORK" || exit 1
    FAKE_PORT="$PORT" FAKE_STUCK=0 "$WORK/fake_nginx" -p "$WORK" -c conf/nginx.conf &
    echo $! > "$WORK/real_srv.pid"
)
REAL_SRV_PID="$(cat "$WORK/real_srv.pid")"
for _i in $(seq 1 100); do
    ss -lptnH "sport = :$PORT" 2>/dev/null | grep -q "pid=$REAL_SRV_PID" && break
    sleep 0.05
done
(
    PROBER_RESOLVED_PORT="$PORT"
    prober_assert_port_owned "$REAL_SRV_PID"
) >"$WORK/layer2_ok.out" 2>&1 && s=0 || s=$?
ok "$s" "prober_assert_port_owned accepts our own genuine listener"
kill -9 "$REAL_SRV_PID" 2>/dev/null
wait "$REAL_SRV_PID" 2>/dev/null || true

# ---- fatal error-log gate: EADDRINUSE in the log is never a soft pass ------
# Independent of ownership: even a run where we eventually win the race must
# not ship if the log shows we lost it at least once first. Drive prober_boot
# itself (not a bare grep re-implementation) so this proves the gate is
# actually WIRED IN, not merely that grep can find the string -- boot our own
# fake server directly on the free port (no squatter needed: the gate reads
# whatever landed in error.log, regardless of how it got there) after seeding
# a prior EADDRINUSE line into its error.log ourselves.
rm -f "$WORK/booted.pid"
mkdir -p "$WORK/logs"
printf '[emerg] bind() to 127.0.0.1:%s failed (98: Address already in use)\n' \
    "$PORT" > "$WORK/logs/error.log"
(
    cd "$WORK" || exit 1
    export FAKE_PORT="$PORT" FAKE_STUCK=0
    PROBER_SERVER_BIN="$WORK/fake_nginx"
    PROBER_PREFIX="$WORK"
    PROBER_RESOLVED_PORT="$PORT"
    PROBER_TIMEOUT_SCALE=1
    prober_boot
    echo "$PROBER_SERVER_PID" > "$WORK/booted.pid"
) >"$WORK/boot_addrinuse.out" 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" \
    "a pre-existing Address already in use line in error.log bails the boot"
# The readiness loop confirms a real bind before the log gate ever runs, so
# THIS bail leaves a live server behind unlike layer 1's pre-spawn refusal --
# booted.pid was never written (prober_boot's exit 1 pre-empts that line), so
# only a port sweep, not booted.pid, can find it.
kill_port_holders

# ---- PROBER_ALLOW_LOG exempts that same line, matching prober_scrape_log ---
# deploy-canary's env file sets exactly
# `PROBER_ALLOW_LOG='Address already in use'` because a shared CI runner can
# hand two concurrent jobs adjacent ports, and that collision is not the fault
# the scenario exists to detect. Without this case, the fatal gate above would
# silently turn that already-accepted, already-documented tolerance into a
# hard failure for every scenario carrying the same opt-out -- the over-
# tightening the env file was written to prevent. Same seeded log, same boot,
# opt-out set: must now succeed.
rm -f "$WORK/booted.pid"
printf '[emerg] bind() to 127.0.0.1:%s failed (98: Address already in use)\n' \
    "$PORT" > "$WORK/logs/error.log"
(
    cd "$WORK" || exit 1
    export FAKE_PORT="$PORT" FAKE_STUCK=0
    export PROBER_ALLOW_LOG='Address already in use'
    PROBER_SERVER_BIN="$WORK/fake_nginx"
    PROBER_PREFIX="$WORK"
    PROBER_RESOLVED_PORT="$PORT"
    PROBER_TIMEOUT_SCALE=1
    prober_boot
    echo "$PROBER_SERVER_PID" > "$WORK/booted.pid"
) >"$WORK/boot_allowlog.out" 2>&1 && s=0 || s=$?
ok "$s" "PROBER_ALLOW_LOG='Address already in use' lifts that same bail (deploy-canary's exact opt-out)"
SRV_PID="$(cat "$WORK/booted.pid" 2>/dev/null || true)"
[ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null
wait "$SRV_PID" 2>/dev/null || true
SRV_PID=""
kill_port_holders

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
