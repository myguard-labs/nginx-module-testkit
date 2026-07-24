#!/usr/bin/env bash
#
# Scenario: a client opens an HTTP/1.1 KEEPALIVE connection, sends ONE
# request, reads the full response, and then holds the connection IDLE -- no
# further request in flight, just an open, quiescent client<->nginx socket.
# A reload (SIGHUP) is then delivered. The old worker enters graceful
# shutdown and MUST close that idle client keepalive connection: it cannot be
# carried into the new worker's accept cycle. The client observes the
# server-side FIN (its read returns EOF).
#
# This is DISTINCT from backend-idle-close-reload: that scenario is about an
# UPSTREAM (memcached) keepalive pool connection nginx holds to a backend.
# This one is the CLIENT-facing keepalive connection nginx holds open to a
# browser/curl-like peer. Different direction, different pool, different code
# path (event_pipe/upstream keepalive vs. the core HTTP keepalive state
# machine and lingering-close-on-shutdown handling).
#
# Why a driver and not a plain .rule file: the prober runs each case
# synchronously to completion (connect, send, read, disconnect) and so cannot
# hold a connection open and IDLE while a signal is delivered to the master
# out from under it. This driver keeps the idle connection open in a
# background subshell, delivers the SIGHUP underneath it, waits for the
# reload to land, and only then checks whether the idle connection was
# closed.
#
# THE CLOSE ORACLE AND ITS HONEST STRENGTH: after the one response is fully
# read, the subshell blocks on a further read from the socket (nothing else
# is ever sent on it). A live TCP peer that never writes and never closes
# leaves that read blocked indefinitely -- so if the subshell ever exits, it
# is because the read returned EOF, which happens if and only if the peer
# (nginx) closed its end. This is a strong, direct proof: "subshell exited"
# is equivalent to "server closed the connection", not a proxy for it. The
# negative control (assertion 1) additionally proves the converse direction
# that matters for calibration: absent a reload, with a 3600s keepalive
# timeout, the connection does NOT close on its own within the same settle
# window used later -- so a close seen after the reload is attributable to
# the reload, not to some other timer or accident of this harness.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

# The prober leg's no_error_log directive needs this; run-scenario.sh exports
# it only for a rules run, so a driver that runs the prober exports it itself.
export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing driver assertion. test-scenarios.sh keys
# the scenario verdict off the EXIT STATUS, not the inner TAP text -- so a
# `not ok` that did not also raise FAILED (and thus the exit status) would be
# a vacuous assertion that never fails the suite. Every branch that prints
# `not ok` also bumps FAILED, and the final exit is nonzero if FAILED>0 or
# the prober leg went red.
FAILED=0

# TAP plan: (1) NEGATIVE CONTROL -- an idle keepalive conn opened WITHOUT any
# reload must stay open through the settle window (proves the close oracle in
# assertion 4 discriminates: a close seen there is reload-caused, not
# spontaneous), (2) the real idle conn is established and idle before the
# signal is sent, (3) the reload was absorbed, (4) the close oracle -- the
# draining old worker closed the idle client keepalive conn, (5) no worker
# died by signal, (6) the post-reload prober leg folded in as diagnostics.
echo "1..6"

# --- idle-keepalive-connection helper ---------------------------------------
# Opens a raw HTTP/1.1 keepalive connection over /dev/tcp, sends exactly ONE
# request, reads the one Content-Length-delimited response, drops a READY
# marker the instant the full response is in hand (so the caller can wait for
# "established and idle" without sleeping blind), and then blocks reading
# further from the socket. Because nothing else is ever written on this
# connection, that trailing read can only return by EOF -- i.e. the peer
# closed -- at which point the subshell exits. So: subshell alive == conn
# still open; subshell exited == conn closed by the server. This mirrors the
# kill -0 liveness pattern reload-mid-upload/driver.sh uses for its upload
# subshell, just for a close instead of a hang.
#
# The response has a known, fixed body ("OK\n", see nginx.conf's `return 200
# "OK\n";`), so the response is read to completion with a small counted
# read-loop over headers + the exact body length rather than blocking on a
# read that would never return end-of-response on a keepalive socket (there
# is no EOF at the end of a keepalive response -- only at the end of the
# WHOLE connection, which is exactly the event this driver is trying to
# distinguish from "response finished").
#
# $1 = ready-marker file path (created once the response is fully read)
# $2 = pidvar (out-param name to receive the background PID)
#
# WHY THE OUT-PARAM AND NOT `pid=$(open_keepalive_conn ...)`: command
# substitution runs the function body in a SUBSHELL, so the `( ... ) &`
# backgrounded job inside it becomes a child of THAT subshell, not of this
# driver. Bash `wait`/`kill -0` only address direct children (or at least a
# job bash's own job table knows about); a pid obtained via command
# substitution can end up referring to a process this shell never forked as a
# direct child, so `kill -0`/`wait` on it becomes unreliable ("not a child of
# this shell"). Backgrounding directly in the driver's own shell and handing
# the pid back through a caller-named variable (`printf -v "$pidvar" '%s'
# "$!"`) keeps the job a true, addressable child. This exact trap is
# documented at length in reload-mid-upload/driver.sh lines ~99-142; the
# reasoning is identical here, just applied to a read instead of a write.
open_keepalive_conn() {
    local marker=$1 pidvar=$2 closedmarker=$3
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: keep-alive\r\n\r\n' >&3

        # Read the response headers line by line until the blank
        # (CRLF-only) line that separates headers from body.
        content_length=0
        while IFS= read -r -u3 line; do
            line=${line%$'\r'}
            if [ -z "$line" ]; then
                break
            fi
            case "$line" in
                [Cc]ontent-[Ll]ength:*)
                    content_length=${line#*:}
                    content_length=${content_length## }
                    ;;
            esac
        done

        # Read exactly content_length body bytes -- no more, no less -- so
        # the socket is left positioned exactly at "response fully
        # consumed, connection now idle" with nothing of the next
        # (nonexistent) response accidentally buffered or blocked on.
        if [ "$content_length" -gt 0 ]; then
            body=$(dd bs=1 count="$content_length" <&3 2>/dev/null)
            : "$body"   # body content itself is not asserted here
        fi

        # The one response is now fully in hand and the connection is
        # idle: drop the ready marker so the caller can stop polling.
        : >"$marker"

        # Block reading further. Nothing else is ever sent on this
        # connection, so this read can only return when the peer closes its
        # end, at which point this subshell exits.
        #
        # PRESERVE the reader's exit status rather than swallowing it with
        # `|| true`: a graceful nginx keepalive close on worker shutdown is a
        # FIN, so `cat` sees a clean end-of-file and exits 0. A socket-read
        # FAILURE (e.g. an RST, or the fd going bad for another reason) makes
        # `cat` exit nonzero. We must not let those two look alike, or
        # assertion 4 would print `ok` for a reader that failed rather than
        # for the intended close/EOF path. So drop the `|| true` (this is the
        # exit-status-swallowing pitfall the up/download drivers accept only
        # because their oracle is liveness, not close-classification) and, on
        # a clean EOF only, drop a CLOSED marker the caller can gate `ok 4`
        # on. If `cat` exits nonzero, no marker is written and the subshell's
        # own nonzero status is preserved.
        if cat <&3 >/dev/null 2>/dev/null; then
            : >"$closedmarker"
        fi
    ) &
    printf -v "$pidvar" '%s' "$!"
}

# Fixed-step counted settle: same iteration count used for both the negative
# control (assertion 1) and the real close-wait (assertion 4), so the two are
# directly comparable and neither depends on wall-clock timing (same
# discipline as prober_signal_wait / prober_wait_listen).
SETTLE_ITERS=100     # 100 * 50 ms = 5 s

# --- assertion 1: NEGATIVE CONTROL -- an idle conn must NOT close itself ----
# Runs FIRST, fully reaped before the real conn is opened (mirrors
# reload-mid-upload: its fast neg-control upload runs and is reaped before
# the real slow upload starts -- never concurrently). Opens an idle
# keepalive conn, sends NO signal, and polls the same settle window used
# later for the real close-wait. With keepalive_timeout 3600s, nothing in
# this harness should close it. If it closes anyway, the close oracle in
# assertion 4 would not discriminate a reload-caused close from ambient
# noise, and this scenario would prove nothing.
CONTROL_MARKER="$PROBER_PREFIX/control.ready"
CONTROL_CLOSED="$PROBER_PREFIX/control.closed"
open_keepalive_conn "$CONTROL_MARKER" CONTROL_PID "$CONTROL_CLOSED"

# Wait for the control conn to become IDLE (its one response fully read, ready
# marker dropped) BEFORE starting the liveness window. Without this gate the
# window could elapse while the child is still connecting or reading the first
# response -- then "stayed alive" would say nothing about an *idle* keepalive
# socket, and the discrimination claim (an idle conn does not close on its own)
# would be unproven. Fixed-step counted iterations, never a sleep. The child
# must still be alive when the marker appears; if it died before ever reaching
# the marker, readiness failed.
control_ready=0
for ((i = 0; i < SETTLE_ITERS; i++)); do
    if [ -e "$CONTROL_MARKER" ]; then
        control_ready=1
        break
    fi
    if ! kill -0 "$CONTROL_PID" 2>/dev/null; then
        break
    fi
    sleep 0.05
done

control_alive=0
if [ "$control_ready" -eq 1 ] && kill -0 "$CONTROL_PID" 2>/dev/null; then
    # Now, and only now, time the idle socket across the full settle window.
    for ((i = 0; i < SETTLE_ITERS; i++)); do
        if kill -0 "$CONTROL_PID" 2>/dev/null; then
            control_alive=1
        else
            control_alive=0
            break
        fi
        sleep 0.05
    done
fi

# Reap the control connection's subtree so it cannot linger into the real
# run -- job control is off in a script (no process group to signal), so the
# child (`cat`, or `dd` if still mid-read) is killed explicitly before the
# subshell itself.
pkill -P "$CONTROL_PID" 2>/dev/null || true
kill "$CONTROL_PID" 2>/dev/null || true
wait "$CONTROL_PID" 2>/dev/null || true

if [ "$control_ready" -eq 0 ]; then
    echo "not ok 1 - the control idle keepalive conn was never established/idle in time"
    FAILED=$((FAILED + 1))
elif [ "$control_alive" -eq 1 ]; then
    echo "ok 1 - an idle keepalive conn stayed open on its own (close oracle discriminates)"
else
    echo "not ok 1 - the idle keepalive conn closed itself with no reload (close oracle cannot discriminate)"
    FAILED=$((FAILED + 1))
fi

# --- open the REAL idle keepalive connection --------------------------------
REAL_MARKER="$PROBER_PREFIX/real.ready"
REAL_CLOSED="$PROBER_PREFIX/real.closed"
open_keepalive_conn "$REAL_MARKER" REAL_PID "$REAL_CLOSED"

# --- assertion 2: established and idle BEFORE signalling -------------------
# Poll for the ready marker with fixed-step counted iterations, never a
# sleep -- same discipline as prober_signal_wait / prober_wait_listen. This
# is a hard gate, not a soft assertion: if the marker never appears (or the
# subshell already exited) within the window, the run must not proceed to
# certify a span that was never actually established.
marker_seen=0
for ((i = 0; i < SETTLE_ITERS; i++)); do
    if [ -e "$REAL_MARKER" ]; then
        marker_seen=1
        break
    fi
    if ! kill -0 "$REAL_PID" 2>/dev/null; then
        # subshell already gone without ever reaching the marker -- a hard
        # failure, not a race to keep polling through.
        break
    fi
    sleep 0.05
done

READY_OK=0
if [ "$marker_seen" -eq 1 ] && kill -0 "$REAL_PID" 2>/dev/null; then
    READY_OK=1
    echo "ok 2 - the real idle keepalive conn is established and idle before the reload"
else
    echo "not ok 2 - the real idle keepalive conn was never established/idle in time"
    FAILED=$((FAILED + 1))
fi

# READINESS IS A HARD GATE. If assertion 2 failed, the idle conn was never
# established -- so sending the reload and then watching the (already-dead or
# never-idle) subshell "exit" would let assertion 4 print `ok` for a close
# that has nothing to do with the reload. Reap the child and mark the
# dependent assertions 3+4 as failures rather than running them against an
# unestablished conn. FAILED is already bumped for the not-ok-2 above.
if [ "$READY_OK" -eq 0 ]; then
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    echo "not ok 3 - skipped: the idle conn was never established (see not ok 2)"
    echo "not ok 4 - skipped: the idle conn was never established (see not ok 2)"
    FAILED=$((FAILED + 2))
else
# --- assertion 3: the reload is absorbed ------------------------------------
# prober_signal_wait probes via /__probe on its OWN fresh connections --
# independent of our idle conn -- and blocks until a different worker pid
# answers, or times out (a real failure).
if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" 5000; then
    echo "ok 3 - the reload was absorbed"
else
    echo "not ok 3 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

# --- assertion 4: THE CLOSE ORACLE ------------------------------------------
# After the reload has landed, the draining old worker must close the idle
# client keepalive connection it was still holding -- it cannot carry that
# connection into the new worker's accept cycle. Poll (bounded, counted,
# generous 100 * 50 ms = 5 s ceiling) for the real subshell to exit. It
# should close near-immediately once graceful shutdown starts, well inside
# the ceiling; the ceiling only exists to bound a genuine failure.
#
# The subshell writes REAL_CLOSED only on a CLEAN EOF (`cat` exit 0 -- a FIN
# from a graceful worker shutdown). Gating `ok 4` on that marker, not merely
# on the subshell being gone, means a subshell that exited because its read
# FAILED (a nonzero `cat`, e.g. an RST or a bad fd) does NOT certify the
# close/EOF path this oracle exists to prove.
closed=0
for ((i = 0; i < SETTLE_ITERS; i++)); do
    if ! kill -0 "$REAL_PID" 2>/dev/null; then
        closed=1
        break
    fi
    sleep 0.05
done
wait "$REAL_PID" 2>/dev/null || true

if [ "$closed" -eq 1 ] && [ -e "$REAL_CLOSED" ]; then
    echo "ok 4 - the draining old worker closed the idle client keepalive conn (clean EOF)"
elif [ "$closed" -eq 1 ]; then
    echo "not ok 4 - the idle conn's reader exited without a clean EOF (read error, not a graceful close)"
    FAILED=$((FAILED + 1))
else
    echo "not ok 4 - the idle client keepalive conn was still open $((SETTLE_ITERS * 50))ms after the reload"
    # Kill the subtree so nothing lingers past this driver's exit.
    pkill -P "$REAL_PID" 2>/dev/null || true
    kill "$REAL_PID" 2>/dev/null || true
    wait "$REAL_PID" 2>/dev/null || true
    FAILED=$((FAILED + 1))
fi
fi   # end READY_OK gate (assertions 3+4)

# --- assertion 5: no worker died by signal ----------------------------------
# prober_signal_wait's relaxed oracle cannot tell a reload from a crash (a
# SIGKILLed worker's replacement has the same master), so the worker-exit
# path is asserted separately: a clean reload logs the old worker leaving via
# "gracefully shutting down" / "exiting", never a signal-death line.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the reload"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the reload"
fi

# --- assertion 6: post-reload coherence (prober, folded in as diagnostics) --
# A plain strict case AFTER the reload: the new worker serves a correct 200,
# leaks no descriptor, and logs nothing on the error path around the
# request. The pid oracle in post-reload.rule is STRICT on purpose -- see
# that file's header. The reload-survival claim this scenario exists to make
# is ok 4 above (the idle client keepalive conn was closed by the draining
# worker), not this leg.
STATUS=0
# PIPESTATUS, not $?: a bare `./prober | sed` would report sed's exit status
# (always 0), silently discarding a red prober leg -- the exact vacuous shape
# this driver guards against elsewhere.
./prober -H "$HOST" -p "$PORT" "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
