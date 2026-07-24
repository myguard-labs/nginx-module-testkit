#!/usr/bin/env bash
#
# Scenario: the USR2 binary-upgrade MASTER-GENERATION state machine, observed
# through the pidfile hand-off, the .oldbin lifecycle, and the survival of the
# inherited listen socket across the old master's retirement.
#
# This is the sibling of backend-usr2-keepalive, split by subject. That scenario
# proves the NEW-exec worker reconnects an upstream keepalive pool it did not
# inherit; its oracle is the backend accept count. This one proves the ENGINE
# side of the same upgrade -- the observable transitions of the two master
# generations -- and needs no upstream at all. Kept separate so a failure names
# which half broke: a missing accept is a module fact, a stuck .oldbin or a
# re-bound listen socket is an engine/harness fact.
#
# THE ORACLES, and why each is the shape it is:
#
#   Pidfile hand-off. Before USR2, nginx.pid holds the live master and no
#   nginx.pid.oldbin exists. On USR2 the old master RENAMES its pidfile to
#   nginx.pid.oldbin and the new master writes a fresh nginx.pid holding a
#   DIFFERENT pid. Both files then name a DISTINCT, LIVE process. This is the
#   direct test that the upgrade landed -- under daemon off; USR2 is silently
#   dropped and the pid would never change (see nginx.conf and env).
#
#   Listen-socket survival (the headline). The new master execs from a fd table
#   inherited from the old master, so the listening socket is the SAME kernel
#   socket object -- not re-created with a fresh bind(). Read as the inode behind
#   the master's listening fd in /proc/<master>/fd: it is IDENTICAL across the
#   old master, the new master, and the new master AFTER the old master is QUIT.
#   A re-bind would change the inode (and would race a bind() against the still-
#   held socket -- the failure this guards). The port must also keep answering
#   across every transition: the socket surviving is only meaningful if service
#   never has a refused window. Linux-only (needs /proc): skipped VISIBLY, never
#   silently dropped, where /proc/<pid>/fd is not readable.
#
#   .oldbin teardown. After the old master is retired (WINCH to drain its
#   workers, then QUIT to stop it), the old master exits and nginx.pid.oldbin
#   DISAPPEARS, while nginx.pid still holds the new master. A .oldbin that
#   lingered would mean the old generation never cleaned up -- a stuck upgrade.
#
#   No worker died by signal. A binary upgrade retires the old workers via WINCH
#   (a graceful shutdown, logged "gracefully shutting down", not a signal death).
#   A SIGSEGV/ABRT/BUS or "exited on signal" on the upgrade path is a real crash.
#
# Why a driver and not a .rule file: USR2 is a signal to the master and the
# proof spans two master generations with the pidfile changing hands underneath;
# the prober has no notion of a master pid or of signal delivery, so it cannot
# drive this. Same rationale as backend-usr2-keepalive.
#
# BOOT CONTRACT: runs under PROBER_DAEMON_MODE=on (see env). The master is
# daemonized and tracked by $PROBER_PREFIX/nginx.pid, not $!. On USR2 the old
# master renames nginx.pid -> nginx.pid.oldbin and the new master writes a fresh
# nginx.pid; this driver reads both to target each generation.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
PIDFILE="$PROBER_PREFIX/nginx.pid"
OLDBIN="$PROBER_PREFIX/nginx.pid.oldbin"

export PROBER_ERROR_LOG="$ELOG"

# FAILED accumulates every failing assertion; the scenario verdict is the EXIT
# STATUS, so a `not ok` that did not also raise it would be vacuous. Every branch
# that prints `not ok` bumps FAILED.
FAILED=0

serves_ok() {   # a fresh connection is accepted and answers 200
    local out
    out="$(
        exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    )" || return 1
    printf '%s' "$out" | grep -q '^HTTP/1.1 200'
}

read_pidfile() {   # $1 = pidfile path; echoes a live pid or nothing
    [ -s "$1" ] || return 0
    local p
    p="$(tr -d '[:space:]' < "$1" 2>/dev/null)"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
}

# The inode behind the master's FIRST listening socket fd. nginx names its
# listening sockets `socket:[INODE]` under /proc/<pid>/fd; the inherited socket
# keeps its inode across the USR2 exec, a re-bind would not. Returns nothing when
# /proc is unreadable (caller treats that as a visible SKIP) or when no listening
# socket fd is found.
listen_inode() {   # $1 = master pid
    local d="/proc/$1/fd" fd tgt first=""
    [ -r "$d" ] || return 0
    for fd in "$d"/*; do
        tgt="$(readlink "$fd" 2>/dev/null)" || continue
        case "$tgt" in
            socket:\[*\])
                # Match it to a LISTENING socket by cross-checking the inode
                # against a listen state in /proc/net/tcp; if that is unreadable,
                # fall back to the first socket fd (the master holds only the
                # listener plus signal/channel pipes, no data sockets while idle).
                local ino="${tgt#socket:[}"; ino="${ino%]}"
                if [ -r /proc/net/tcp ] && \
                   awk -v i="$ino" 'NR>1 && $10==i && $4=="0A"{f=1} END{exit !f}' \
                       /proc/net/tcp 2>/dev/null; then
                    echo "$ino"; return 0
                fi
                # remember the first socket as a fallback
                [ -n "$first" ] || first="$ino"
                ;;
        esac
    done
    [ -n "$first" ] && echo "$first"
    return 0
}

# TAP plan:
#  1 the server serves before the upgrade, with a clean pidfile and no .oldbin
#  2 USR2 forked a new master (fresh nginx.pid, distinct pid)
#  3 .oldbin appeared holding the OLD master, distinct from and alongside the new
#  4 the listen socket survived the exec (same inode on old and new master)
#  5 both master generations serve the SAME listen socket (port answers)
#  6 the old master retired and .oldbin disappeared, nginx.pid still the new master
#  7 the listen socket survived the old master's death (same inode, still serving)
#  8 no worker died by signal across the upgrade
echo "1..8"

# --- baseline -------------------------------------------------------------
OLD_MASTER="$PROBER_SERVER_PID"
INODE_PROBED=0            # set to 1 once we have a real listen inode to compare
OLD_INODE="$(listen_inode "$OLD_MASTER")"
[ -n "$OLD_INODE" ] && INODE_PROBED=1

if serves_ok && [ -n "$(read_pidfile "$PIDFILE")" ] && [ ! -e "$OLDBIN" ]; then
    echo "ok 1 - baseline: serving, pidfile live, no .oldbin"
else
    echo "not ok 1 - baseline not clean before the upgrade"
    [ -e "$OLDBIN" ] && echo "# nginx.pid.oldbin already exists before USR2"
    FAILED=$((FAILED + 1))
fi

# --- USR2: fork the new binary --------------------------------------------
# Fixed-step counted polling, never a wall-clock diff (prober_wait_listen
# discipline): 100 * 50 ms = 5 s ceiling.
kill -USR2 "$OLD_MASTER" 2>/dev/null || true

NEW_MASTER=""
for ((i = 0; i < 100; i++)); do
    p="$(read_pidfile "$PIDFILE")"
    if [ -n "$p" ] && [ "$p" != "$OLD_MASTER" ]; then
        NEW_MASTER="$p"
        break
    fi
    sleep 0.05
done

if [ -n "$NEW_MASTER" ]; then
    echo "ok 2 - USR2 forked a new master (pid $NEW_MASTER, was $OLD_MASTER)"
    # Adopt the new master as THE master so teardown (prober_stop via the EXIT
    # trap) targets the generation that owns the listen socket and pidfile.
    PROBER_SERVER_PID="$NEW_MASTER"
    export PROBER_SERVER_PID
else
    echo "not ok 2 - USR2 did not fork a new master (binary upgrade ignored?)"
    echo "# nginx.pid still holds the old master $OLD_MASTER after 5 s;"
    echo "# under daemon off; USR2 is dropped -- check PROBER_DAEMON_MODE=on took effect"
    grep -n 'changing binary signal is ignored' "$ELOG" | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- .oldbin appeared, naming the OLD master alongside the new -------------
# Poll: the rename can lag the fresh nginx.pid write by a scheduler tick.
OLDBIN_PID=""
for ((i = 0; i < 100; i++)); do
    OLDBIN_PID="$(read_pidfile "$OLDBIN")"
    [ -n "$OLDBIN_PID" ] && break
    sleep 0.05
done

if [ -n "$OLDBIN_PID" ] && [ "$OLDBIN_PID" = "$OLD_MASTER" ] && \
   [ -n "$NEW_MASTER" ] && [ "$OLDBIN_PID" != "$NEW_MASTER" ]; then
    echo "ok 3 - .oldbin holds the old master $OLD_MASTER, distinct from new $NEW_MASTER"
else
    echo "not ok 3 - .oldbin did not name the old master alongside a distinct new master"
    echo "# .oldbin=${OLDBIN_PID:-<none>} old=$OLD_MASTER new=${NEW_MASTER:-<none>}"
    FAILED=$((FAILED + 1))
fi

# --- listen socket survived the exec (same inode on the new master) --------
NEW_INODE=""
[ -n "$NEW_MASTER" ] && NEW_INODE="$(listen_inode "$NEW_MASTER")"
if [ "$INODE_PROBED" -eq 0 ] || [ -z "$NEW_INODE" ]; then
    echo "ok 4 - listen socket inode # SKIP /proc listen-fd not readable on this host"
elif [ "$NEW_INODE" = "$OLD_INODE" ]; then
    echo "ok 4 - listen socket survived the exec (inode $NEW_INODE, inherited not re-bound)"
else
    echo "not ok 4 - listen socket inode changed across USR2 (old $OLD_INODE, new $NEW_INODE = a re-bind)"
    FAILED=$((FAILED + 1))
fi

# --- both generations serve the same listen socket ------------------------
if serves_ok; then
    echo "ok 5 - the port keeps answering across the upgrade overlap"
else
    echo "not ok 5 - service refused during the two-master overlap"
    FAILED=$((FAILED + 1))
fi

# --- retire the old master, .oldbin must disappear ------------------------
# WINCH drains the old master's workers, QUIT stops the old master itself. The
# pid comes from nginx.pid.oldbin (where the old master parked it on USR2), not
# from the shell's memory, so the driver retires whatever generation the engine
# actually placed there.
RETIRE_PID="$(read_pidfile "$OLDBIN")"
[ -n "$RETIRE_PID" ] || RETIRE_PID="$OLD_MASTER"
kill -WINCH "$RETIRE_PID" 2>/dev/null || true
kill -QUIT  "$RETIRE_PID" 2>/dev/null || true

# Wait for the old master to exit AND .oldbin to be removed (nginx unlinks it on
# clean shutdown). 5 s ceiling, counted.
OLDBIN_GONE=0
for ((i = 0; i < 100; i++)); do
    if ! kill -0 "$RETIRE_PID" 2>/dev/null && [ ! -e "$OLDBIN" ]; then
        OLDBIN_GONE=1
        break
    fi
    sleep 0.05
done

if [ "$OLDBIN_GONE" -eq 1 ] && [ -n "$(read_pidfile "$PIDFILE")" ] && \
   [ "$(read_pidfile "$PIDFILE")" = "$NEW_MASTER" ]; then
    echo "ok 6 - old master retired, .oldbin gone, nginx.pid still the new master"
else
    echo "not ok 6 - the old generation did not clean up after QUIT"
    kill -0 "$RETIRE_PID" 2>/dev/null && echo "# old master $RETIRE_PID still alive after WINCH+QUIT"
    [ -e "$OLDBIN" ] && echo "# nginx.pid.oldbin still present"
    FAILED=$((FAILED + 1))
fi

# --- the listen socket survived the old master's death --------------------
# The inherited socket object is now held only by the new master; the old master
# (its other holder) is gone. The inode behind the new master's listening fd
# must be UNCHANGED -- the socket was inherited, not owned by the retired
# generation -- and the port must still answer.
POST_INODE=""
[ -n "$NEW_MASTER" ] && POST_INODE="$(listen_inode "$NEW_MASTER")"
if [ "$INODE_PROBED" -eq 0 ] || [ -z "$POST_INODE" ]; then
    if serves_ok; then
        echo "ok 7 - listen socket serves after old-master death # SKIP inode not readable"
    else
        echo "not ok 7 - service refused after the old master was retired"
        FAILED=$((FAILED + 1))
    fi
elif [ "$POST_INODE" = "$OLD_INODE" ] && serves_ok; then
    echo "ok 7 - listen socket survived the old master's death (inode $POST_INODE, still serving)"
else
    echo "not ok 7 - listen socket lost when the old master was retired"
    [ "$POST_INODE" != "$OLD_INODE" ] && echo "# inode changed: was $OLD_INODE, now $POST_INODE"
    serves_ok || echo "# port no longer answers"
    FAILED=$((FAILED + 1))
fi

# --- no worker died by signal ---------------------------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 8 - a worker died by signal during the upgrade"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 8 - no worker died by signal"
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
