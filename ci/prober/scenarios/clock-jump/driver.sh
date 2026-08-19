#!/usr/bin/env bash
#
# Scenario: the WALL CLOCK steps backwards under a running worker, and nothing
# that measures elapsed time notices. This is the NTP-correction shape -- a
# machine that boots with a wrong clock, syncs, and jumps; a leap-second slew; a
# VM resumed from a snapshot. A module that computes an interval from
# CLOCK_REALTIME (a ban that expires, a rate-limit window, a cache TTL) has that
# interval silently extended by the size of the step: an hour's step parks a
# one-second timer an hour in the future, and nothing logs, errors or crashes.
#
# WHAT THIS SCENARIO WAS BEFORE 2026-07-29, recorded because it is the exact
# defect this repo exists to hunt. It shipped an nginx.conf and a four-case
# clock-jump.rule and NOTHING ELSE -- no env, no LD_PRELOAD, no driver. The four
# cases sent byte-identical requests and asserted `status=200` + `delta fds ==
# 0`; their names ("request after clock jump", "request after negative clock
# jump") described an event that never occurred, because nothing in the tree
# could step a clock -- libfaketime appeared nowhere in it. It passed reliably
# for having tested nothing, which is precisely why `zone-exhaustion` was
# deleted on 2026-07-28. It is rebuilt here rather than deleted because the
# attack it NAMED is real and worth running.
#
# WHY A DRIVER, NOT A .rule. The step has to land BETWEEN a connection being
# parked and its timer expiring, on a server that is already up. No prober case
# straddles that, and the rule DSL has no verb for "rewrite the server's clock".
#
# THE INSTRUMENT, and the trap inside it. libfaketime is LD_PRELOADed with a
# TIMESTAMP FILE (see `env`), so the driver steps the clock by writing to a file
# rather than by rebooting the server in the past. The trap: by default
# libfaketime fakes CLOCK_MONOTONIC as well, and a backward-stepping MONOTONIC
# clock is not a thing nginx is required to survive -- the kernel guarantees it
# cannot happen. Measured, both ways:
#
#   default          : -3600 step moves CLOCK_MONOTONIC *and* CLOCK_REALTIME
#                      (unpreloaded mono ~90183; faked mono ~1785276494)
#                      -> the parked keepalive connection NEVER closes (>12s)
#   DONT_FAKE_MONO=1 : mono passes through untouched (~90191), realtime steps
#                      -> the connection closes in 1.70s, exactly as unstepped
#
# The first reading is libfaketime breaking a kernel invariant, not nginx
# mishandling a clock; asserting on it would be a gate that measures the test
# tool. So the scenario runs with FAKETIME_DONT_FAKE_MONOTONIC=1 and asserts the
# SECOND reading. That also makes the first one this scenario's negative
# control -- see NON-VACUITY below.
#
# THE ORACLES.
#
#   O1 the step actually landed. Read from the server's own `Date` header, not
#   assumed from having written the file. A step that did not reach the worker
#   (the pre-2026-07-29 failure mode: env vars stripped at fork -- see
#   nginx.conf) leaves every other oracle passing against an unstepped clock,
#   which is the vacuous shape this scenario is a rebuild of. Asserted FIRST so
#   a failure names the cause rather than the symptom.
#
#   O2 timers survive the step. A keepalive connection parked BEFORE the step
#   must still close on its ~2s timeout AFTER it. This is the assertion the
#   scenario exists for: it holds iff the expiry is computed from a monotonic
#   source. A REALTIME-derived timer is pushed a full hour out and the read
#   blocks until the driver's own timeout.
#
#   O3 the worker is unharmed. It still answers, keeps its pid (no crash and
#   respawn), and the request is allocation-neutral across the stepped clock --
#   the harness's standard resource oracle, here asserting the step did not
#   leave a connection or descriptor stranded.
#
# NON-VACUITY. O1 and O2 have a real, RUN negative control, and unusually it is
# a one-variable flip rather than a code mutation: deleting
# FAKETIME_DONT_FAKE_MONOTONIC from `env` reds O2 (the parked connection stops
# closing; measured: no close within 12s, against 1.70s with it set) while O1
# stays green -- proving O2 reads the timer and not merely the clock. The
# forward-step direction was measured as the third leg of the same experiment
# (+3600: closes in 1.70s, i.e. indistinguishable from unstepped), which is why
# only the backward step is asserted: it is the direction with a failure mode.
# O1's own control is the historical bug itself -- removing the `env` directives
# from nginx.conf reds O1 with the worker's Date advancing instead of stepping.
#
# WHAT THIS DOES NOT CLAIM. The probe document exposes no time field, so this
# scenario cannot see a MODULE's internal timer directly; it asserts on nginx's
# own keepalive expiry as the observable proxy. A module that keeps its own
# CLOCK_REALTIME deadline is caught only if the consumer exposes it via
# zone_render and adds a case. That is a module-side capability, and it is the
# honest limit of a generic clock oracle.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
FT="$PROBER_PREFIX/faketime.rc"

export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

# FAILED accumulates every failing assertion; the scenario verdict is the EXIT
# STATUS, so a `not ok` that did not also raise it would be vacuous.
FAILED=0

STEP_SECONDS=3600      # one hour back: unmistakable in a Date header
KEEPALIVE_WAIT=8       # >> the conf's 2s keepalive_timeout, << a hung read

# --- preconditions -------------------------------------------------------
#
# `requires` already gated on the library existing. What it cannot check is
# whether the preload actually REACHED the worker, which is a property of this
# server's build and config rather than of the box -- so it is asserted as O1
# below rather than skipped on here.
#
# python3 drives the parked connection: it needs to hold a socket open across
# the step and time the close, which curl cannot express.
if ! command -v python3 >/dev/null 2>&1; then
    echo "1..0 # SKIP python3 not installed (needed to park a keepalive connection)"
    exit 0
fi

echo "1..4"

# --- helpers -------------------------------------------------------------

# Server's own view of the wall clock, as epoch seconds, read from the Date
# header of a real response. Deliberately the SERVER's clock and not the
# driver's: the whole question is what the worker believes.
server_epoch() {
    local body
    body="$(H="$HOST" P="$PORT" timeout 5 python3 -c '
import socket, os, sys
s = socket.create_connection((os.environ["H"], int(os.environ["P"])), 5)
s.settimeout(5)
s.sendall(b"GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n")
d = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    d += c
sys.stdout.buffer.write(d)
' 2>/dev/null)" || return 1
    local datehdr
    datehdr="$(printf '%s' "$body" | tr -d '\r' | sed -n 's/^[Dd]ate: //p' | head -1)"
    [ -n "$datehdr" ] || return 1
    date -u -d "$datehdr" +%s 2>/dev/null
}

# Write the offset ATOMICALLY (write a temp beside it, then rename). The server
# re-reads this file on every clock call (FAKETIME_NO_CACHE=1), so a plain
# truncate-and-write leaves a window in which the library reads an empty or
# half-written file and reports
#   libfaketime: In parse_ft_string(), failed to parse FAKETIME timestamp.
# on stderr. rename(2) is atomic within a directory, so every read sees either
# the old offset or the new one and never a partial line.
step_clock() {
    printf '%s\n' "$1" > "$FT.tmp"
    mv -f "$FT.tmp" "$FT"
}

# --- O1: the step reaches the worker -------------------------------------

step_clock '+0'
sleep 0.3

BEFORE="$(server_epoch || true)"
if [ -z "$BEFORE" ]; then
    echo "not ok 1 - the server reports a readable Date before the step"
    echo "# could not read a Date header from the server"
    FAILED=1
else
    step_clock "-$STEP_SECONDS"
    sleep 0.5
    AFTER="$(server_epoch || true)"

    if [ -z "$AFTER" ]; then
        echo "not ok 1 - the wall clock steps backwards under the running worker"
        echo "# could not read a Date header after the step"
        FAILED=1
    else
        DELTA=$(( BEFORE - AFTER ))
        # Allow a couple of seconds of real time to have passed during the two
        # requests; the step is an hour, so the bound is nowhere near tight.
        if [ "$DELTA" -ge $(( STEP_SECONDS - 60 )) ]; then
            echo "ok 1 - the wall clock steps backwards under the running worker (-${DELTA}s)"
        else
            echo "not ok 1 - the wall clock steps backwards under the running worker"
            echo "# expected the server's clock to move back ~${STEP_SECONDS}s, saw ${DELTA}s"
            echo "# a delta near zero means the preload did not reach the worker:"
            echo "# check the 'env' directives in nginx.conf (nginx rebuilds the"
            echo "# worker environ from those alone, so FAKETIME_* is stripped without them)"
            FAILED=1
        fi
    fi
fi

# --- O2: a timer parked before the step still fires after it -------------
#
# Park a keepalive connection, step the clock backwards while it is parked, and
# require the server to close it on its ~2s keepalive_timeout. Under a monotonic
# expiry the step is invisible and the close lands on schedule; under a realtime
# expiry the deadline moves an hour out and the read blocks until KEEPALIVE_WAIT.
step_clock '+0'
sleep 0.5

KA_OUT="$PROBER_PREFIX/logs/clock-jump.keepalive"
# LD_PRELOAD= clears the inherited libfaketime interposer for THIS process only
# (the server keeps it -- preloaded at fork, unaffected by an env change here).
# This probe is the OBSERVER: it measures elapsed time with time.monotonic()
# around a time.sleep(), and CPython's time.sleep() is clock_nanosleep(...,
# TIMER_ABSTIME, deadline) -- an absolute-deadline call, not the plain
# clock_gettime()/recv() the other three assertions make. libfaketime does not
# honour FAKETIME_DONT_FAKE_MONOTONIC (see 'env') consistently on that
# interception path, so a preloaded probe computes its sleep deadline against
# one clock scale and the kernel rejects it against another -- EINVAL, no
# socket ever touched. A self-faking observer can't measure real elapsed time
# regardless of the crash, so leaving the preload on here would be wrong even
# if libfaketime patched the EINVAL away.
H="$HOST" P="$PORT" FT="$FT" STEP="$STEP_SECONDS" WAIT="$KEEPALIVE_WAIT" LD_PRELOAD='' \
timeout $(( KEEPALIVE_WAIT + 6 )) python3 - >"$KA_OUT" 2>&1 <<'PY' || true
import os, socket, time

host, port = os.environ["H"], int(os.environ["P"])
ft, step, wait = os.environ["FT"], os.environ["STEP"], float(os.environ["WAIT"])

s = socket.create_connection((host, port), 5)
s.settimeout(wait)
# A request WITHOUT Connection: close, so the server parks the connection on its
# keepalive timer rather than closing it as part of the exchange.
s.sendall(b"GET / HTTP/1.1\r\nHost: prober\r\n\r\n")
time.sleep(0.3)
s.recv(65536)

# The step lands while the connection is parked and its timer is already armed.
# Atomic for the same reason step_clock() is: the server re-reads this file on
# every clock call, so a partial read makes libfaketime print a parse error and
# fall back to the real clock.
with open(ft + ".tmp", "w") as fh:
    fh.write("-%s\n" % step)
os.replace(ft + ".tmp", ft)

t0 = time.monotonic()
try:
    data = s.recv(65536)
    print("CLOSED %.2f %s" % (time.monotonic() - t0, "eof" if data == b"" else "data"))
except socket.timeout:
    print("HUNG %.2f" % (time.monotonic() - t0))
except OSError as exc:
    # A reset is still the server ending the connection on schedule.
    print("CLOSED %.2f reset:%s" % (time.monotonic() - t0, exc.errno))
PY

KA_RESULT="$(head -1 "$KA_OUT" 2>/dev/null || true)"
case "$KA_RESULT" in
    CLOSED\ *)
        echo "ok 2 - a keepalive timer parked before the step still fires after it (${KA_RESULT#CLOSED })"
        ;;
    HUNG\ *)
        echo "not ok 2 - a keepalive timer parked before the step still fires after it"
        echo "# the parked connection did not close within ${KEEPALIVE_WAIT}s of a -${STEP_SECONDS}s step"
        echo "# an expiry computed from CLOCK_REALTIME is pushed forward by the step; a"
        echo "# monotonic one is unaffected. If FAKETIME_DONT_FAKE_MONOTONIC is unset in"
        echo "# 'env', this is the library faking CLOCK_MONOTONIC too -- the scenario's"
        echo "# own negative control, not a server bug."
        FAILED=1
        ;;
    *)
        echo "not ok 2 - a keepalive timer parked before the step still fires after it"
        echo "# the keepalive probe produced no verdict; output follows"
        sed 's/^/# /' "$KA_OUT" 2>/dev/null || true
        FAILED=1
        ;;
esac

# --- O3: the worker rode it out ------------------------------------------

step_clock '+0'
sleep 0.5

BODY_BEFORE="$(prober_probe_body "$HOST" "$PORT" || true)"
PID_BEFORE="$(prober_probe_pid "$HOST" "$PORT" || true)"

step_clock "-$STEP_SECONDS"
sleep 0.5

BODY_AFTER="$(prober_probe_body "$HOST" "$PORT" || true)"
PID_AFTER="$(prober_probe_pid "$HOST" "$PORT" || true)"

if [ -n "$PID_BEFORE" ] && [ "$PID_BEFORE" = "$PID_AFTER" ]; then
    echo "ok 3 - the worker survives the step without dying and respawning (pid $PID_AFTER)"
else
    echo "not ok 3 - the worker survives the step without dying and respawning"
    echo "# pid before=${PID_BEFORE:-<none>} after=${PID_AFTER:-<none>}"
    FAILED=1
fi

# Allocation neutrality across the step, on the harness's primary oracle. The
# cycle pool is deterministic once the worker has settled, so this is an exact
# comparison -- the same claim conn-delta makes per request, asserted here
# across a clock step instead.
USED_BEFORE="$(prober_probe_field "$BODY_BEFORE" cycle_used || true)"
USED_AFTER="$(prober_probe_field "$BODY_AFTER" cycle_used || true)"

if [ -z "$USED_BEFORE" ] || [ -z "$USED_AFTER" ]; then
    echo "not ok 4 - the stepped clock leaves the cycle pool unchanged"
    echo "# cycle_used absent from the probe document (before=${USED_BEFORE:-<absent>} after=${USED_AFTER:-<absent>})"
    FAILED=1
elif [ "$USED_BEFORE" = "$USED_AFTER" ]; then
    echo "ok 4 - the stepped clock leaves the cycle pool unchanged ($USED_AFTER bytes)"
else
    echo "not ok 4 - the stepped clock leaves the cycle pool unchanged"
    echo "# cycle_used before=$USED_BEFORE after=$USED_AFTER"
    FAILED=1
fi

# Leave the clock where the harness found it, so teardown's own log scrape and
# any timestamp it writes are not in the past.
step_clock '+0'

exit "$FAILED"
