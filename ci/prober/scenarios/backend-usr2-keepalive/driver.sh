#!/usr/bin/env bash
#
# Scenario: a USR2 binary upgrade. The running master holds a worker whose
# keepalive pool has a parked upstream (memcached) connection. USR2 forks a NEW
# master that execs the (same) binary and spawns a NEW worker; that worker
# inherited NONE of the old worker's keepalive pool, so the first request it
# answers MUST open a fresh upstream connection. The old master is then retired
# (WINCH to drain its workers, QUIT to stop it) and the new master must keep
# serving correctly on its own.
#
# This closes the last P1-D gap the harness could not reach: the binary-upgrade
# path for a module holding upstream keepalive state. cache-turbo's memcached
# pool is proven at config time and, since #76, across an idle-close + reload --
# but a USR2 exec discards the pool wholesale, a different transition, and
# nothing proved the new master's worker reconnects rather than reusing a
# descriptor it never inherited.
#
# The falsifiable instrument is the backend JOURNAL accept count -- the same
# oracle #76 uses. A request answered by the new-exec worker must add at least
# one accept; reuse of a (non-existent, un-inherited) parked connection would
# add zero. No module log settles reuse-vs-reopen as directly.
#
# Why a driver and not a .rule file: USR2 is a signal to the master and the
# proof spans two master generations (old + new), with the pidfile changing
# hands underneath. The prober runs cases back to back with no signal delivery
# and no notion of a master pid, so it cannot drive this.
#
# BOOT CONTRACT: this scenario runs under PROBER_DAEMON_MODE=on (see env). The
# master is daemonized and tracked by $PROBER_PREFIX/nginx.pid, not $!. On USR2,
# the old master RENAMES its pidfile to nginx.pid.oldbin and the new master
# writes a fresh nginx.pid -- this driver reads both to target each generation.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
JOURNAL="$PROBER_BACKEND_JOURNAL"
PIDFILE="$PROBER_PREFIX/nginx.pid"
OLDBIN="$PROBER_PREFIX/nginx.pid.oldbin"

export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing driver assertion; the scenario verdict is the
# EXIT STATUS, so a `not ok` that did not also raise it would be vacuous. Every
# branch that prints `not ok` bumps FAILED.
FAILED=0

do_request() {   # $1 = output file
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /mc?key=k HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    ) >"$1" 2>/dev/null
}

served_value() { grep -q '^HTTP/1.1 200' "$1" && grep -q 'usr2-keepalive-value' "$1"; }

accepts_so_far() {
    [ -n "$JOURNAL" ] || { echo 0; return; }
    grep -c '"ev":"accept"' "$JOURNAL" 2>/dev/null || true
}

read_pidfile() {   # $1 = pidfile path; echoes a live pid or nothing
    [ -s "$1" ] || return 0
    local p
    # Brace-group the input redirect so its OWN open failure is suppressed too:
    # `[ -s ]` and this read are not atomic, and the master may unlink/rewrite the
    # pidfile in the two-master USR2 overlap between them. `tr ... < "$1" 2>/dev/null`
    # only silences tr's stderr, not the shell's redirect-open error, which then
    # leaks a "No such file or directory" line. Absence is a normal outcome here.
    p="$( { tr -d '[:space:]' <"$1"; } 2>/dev/null )"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
    return 0
}

# TAP plan:
#  1 first request served correctly and parked a pool connection
#  2 USR2 forked a new master (a fresh nginx.pid, distinct from the old master)
#  3 the new-exec worker answers with a different pid than the pre-upgrade worker
#  4 the request on the new worker reconnected (a fresh upstream accept) -- the proof
#  5 the request on the new worker was served correctly over that connection
#  6 the old master was retired and the new master kept serving correctly
#  7 no worker died by signal across the upgrade
echo "1..7"

# --- request A: establish and park a keepalive connection on the OLD worker --
OUT_A="$PROBER_PREFIX/a.out"
do_request "$OUT_A"
if served_value "$OUT_A"; then
    echo "ok 1 - first request served correctly and parked a pool connection"
else
    echo "not ok 1 - first request did not serve the seeded value"
    sed 's/^/# /' "$OUT_A" | head -20
    FAILED=$((FAILED + 1))
fi
ACCEPTS_AFTER_A=$(accepts_so_far)

OLD_MASTER="$PROBER_SERVER_PID"
OLD_WORKER=$(prober_probe_pid "$HOST" "$PORT" || true)

# --- USR2: start the new binary -------------------------------------------
# The old master renames nginx.pid -> nginx.pid.oldbin and the new master writes
# a fresh nginx.pid. Poll for a nginx.pid holding a pid DIFFERENT from the old
# master -- that difference is the upgrade landing, and it is what tells daemon
# on; apart from the daemon off; case where USR2 is silently ignored (the pid
# would never change). Fixed-step counted iterations, never a wall-clock diff
# (prober_wait_listen discipline).
kill -USR2 "$OLD_MASTER" 2>/dev/null || true

NEW_MASTER=""
for ((i = 0; i < 100; i++)); do            # 100 * 50 ms = 5 s ceiling
    p=$(read_pidfile "$PIDFILE")
    if [ -n "$p" ] && [ "$p" != "$OLD_MASTER" ]; then
        NEW_MASTER="$p"
        break
    fi
    sleep 0.05
done

if [ -n "$NEW_MASTER" ]; then
    echo "ok 2 - USR2 forked a new master (pid $NEW_MASTER, was $OLD_MASTER)"
    # Adopt the new master as THE master: teardown (prober_stop, via the EXIT
    # trap) must target the generation that owns the listen socket and the
    # pidfile. The old master is retired explicitly below.
    PROBER_SERVER_PID="$NEW_MASTER"
    export PROBER_SERVER_PID
else
    echo "not ok 2 - USR2 did not fork a new master (binary upgrade ignored?)"
    echo "# nginx.pid still holds the old master $OLD_MASTER after 5 s;"
    echo "# under daemon off; USR2 is dropped -- check PROBER_DAEMON_MODE=on took effect"
    grep -n 'changing binary signal is ignored' "$ELOG" | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- wait for the new-exec worker to take over answering probes ------------
# The new master spawns its own worker; poll until a worker whose pid differs
# from the pre-upgrade worker answers the probe. Until then a request could
# still be routed to the old worker (both masters share the listen socket during
# the overlap), which would reuse the old pool and mask the reconnect.
NEW_WORKER=""
for ((i = 0; i < 100; i++)); do            # 5 s ceiling
    w=$(prober_probe_pid "$HOST" "$PORT" || true)
    if [ -n "$w" ] && [ -n "$OLD_WORKER" ] && [ "$w" != "$OLD_WORKER" ]; then
        NEW_WORKER="$w"
        break
    fi
    sleep 0.05
done

if [ -n "$NEW_WORKER" ]; then
    echo "ok 3 - the new-exec worker answers (pid $NEW_WORKER, was $OLD_WORKER)"
else
    echo "not ok 3 - no new worker took over after USR2 (old worker $OLD_WORKER still answering)"
    FAILED=$((FAILED + 1))
fi

# --- retire the OLD worker before request B --------------------------------
# ok 3 only proves the new worker CAN answer, not that the old one stopped:
# both generations share the listen socket during the overlap, so a bare
# request B can still be accepted by the OLD worker and served from its parked
# keepalive pool, moving no accept count. That is a scheduling race -- rare on a
# fast build, reliable under ASan, which slows the new worker enough that the old
# one keeps winning accept(). WINCH the old master so its worker drains, then
# poll until the old worker pid no longer answers, so request B can ONLY land on
# the new worker. (The old MASTER is still QUIT below for the serve-alone case.)
OLDBIN_PID=$(read_pidfile "$OLDBIN")
[ -n "$OLDBIN_PID" ] || OLDBIN_PID="$OLD_MASTER"
kill -WINCH "$OLDBIN_PID" 2>/dev/null || true
for ((i = 0; i < 100; i++)); do            # 5 s ceiling
    w=$(prober_probe_pid "$HOST" "$PORT" || true)
    [ -n "$w" ] && [ "$w" != "$OLD_WORKER" ] && break
    sleep 0.05
done

# --- request B: answered by the new worker, must reconnect upstream --------
OUT_B="$PROBER_PREFIX/b.out"
do_request "$OUT_B"
ACCEPTS_AFTER_B=$(accepts_so_far)

# The reconnect oracle: the new-exec worker inherited no keepalive pool, so
# serving request B forced at least one NEW upstream accept beyond request A's.
# A count that did not move would mean the request was answered without opening
# an upstream connection -- only possible if the old worker (with the parked
# pool) served it, which the old-worker retirement above has now ruled out.
if [ "$ACCEPTS_AFTER_B" -gt "$ACCEPTS_AFTER_A" ]; then
    echo "ok 4 - the new worker reconnected upstream (a fresh accept)"
else
    echo "not ok 4 - no new upstream connection from the new worker (inherited a pool it should not have?)"
    echo "# accepts: $ACCEPTS_AFTER_A after A, $ACCEPTS_AFTER_B after B (expected an increase)"
    FAILED=$((FAILED + 1))
fi

if served_value "$OUT_B"; then
    echo "ok 5 - the request on the new worker was served correctly"
else
    echo "not ok 5 - the request on the new worker failed"
    sed 's/^/# /' "$OUT_B" | head -20
    FAILED=$((FAILED + 1))
fi

# --- retire the old master, the new master must serve alone ----------------
# The old worker was already WINCH-drained above; QUIT now stops the old master
# itself (WINCH repeated harmlessly in case the drain above was skipped). The pid
# comes from nginx.pid.oldbin (where the old master moved it on USR2), not from
# the shell's memory of OLD_MASTER, so the driver retires whatever generation the
# engine actually parked there. Then a request must still be served -- by the new
# master alone.
OLDBIN_PID=$(read_pidfile "$OLDBIN")
[ -n "$OLDBIN_PID" ] || OLDBIN_PID="$OLD_MASTER"
kill -WINCH "$OLDBIN_PID" 2>/dev/null || true
kill -QUIT  "$OLDBIN_PID" 2>/dev/null || true

# Wait for the old master to actually exit before asserting the new one serves
# alone: otherwise a pass could be the departing old generation still answering.
for ((i = 0; i < 100; i++)); do            # 5 s ceiling
    kill -0 "$OLDBIN_PID" 2>/dev/null || break
    sleep 0.05
done

OUT_C="$PROBER_PREFIX/c.out"
do_request "$OUT_C"
if served_value "$OUT_C" && ! kill -0 "$OLDBIN_PID" 2>/dev/null; then
    echo "ok 6 - the old master was retired and the new master kept serving"
else
    echo "not ok 6 - the new master did not serve alone after the old master was retired"
    if kill -0 "$OLDBIN_PID" 2>/dev/null; then
        echo "# old master $OLDBIN_PID is still alive after WINCH+QUIT"
    fi
    sed 's/^/# /' "$OUT_C" | head -20
    FAILED=$((FAILED + 1))
fi

# --- no worker died by signal ----------------------------------------------
# A binary upgrade retires the old workers via WINCH (a graceful shutdown that
# logs "gracefully shutting down", not a signal death). A SIGSEGV/ABRT/BUS, or a
# worker "exited on signal", is a real crash on the upgrade path.
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 7 - a worker died by signal during the upgrade"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 7 - no worker died by signal"
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
