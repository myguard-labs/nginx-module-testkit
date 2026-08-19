#!/usr/bin/env bash
#
# Scenario: a client request is IN FLIGHT -- its upstream reply still DRIPPING
# out of the fake backend -- when a USR2 binary upgrade is delivered to the
# master. USR2 execs a whole new master (not a SIGHUP reload of the same
# process): the two master generations overlap on the wire while the old
# master's worker keeps serving the dripping response, and only after that
# response completes intact is the old generation retired (WINCH+QUIT). This
# driver proves the full body arrives, status 200, the backend was hit exactly
# once (not re-issued to the new generation), the listen socket survives the
# exec, and no worker died by signal.
#
# DISTINCT from backend-usr2-keepalive: that scenario proves the NEW-exec
# worker RECONNECTS an upstream keepalive POOL it did not inherit -- its oracle
# is the backend ACCEPT count, and the request in that scenario is always
# issued fresh, after the exec. This scenario proves a LIVE STREAMING RESPONSE
# that was ALREADY in flight BEFORE the exec survives it intact -- a different
# subject entirely: keepalive-pool continuity vs. in-flight-transfer survival.
#
# DISTINCT from backend-reload-inflight: that scenario holds a streaming
# response across a HUP *reload* -- the SAME master respawning ONE worker, no
# second master, no pidfile hand-off. This scenario holds it across a USR2
# *binary upgrade* -- a whole NEW master forked via execve, a genuine two-
# master overlap, a .oldbin hand-off, and the OLD master's worker (not a fresh
# one) is what must finish draining the drip before the old generation is
# retired. The reload driver's ordering/exactly-once/intact-body oracles are
# reused here verbatim because the underlying hazard (dropping or re-issuing
# an in-flight request across a master-side signal) is the same shape; what
# changes is the signal and the master-generation bookkeeping around it, which
# is usr2-state-machine's territory, folded in here as oracles 3, 6, 7 and 8.
#
# Why a driver and not a plain .rule file: the prober runs each case
# synchronously to completion, so it cannot hold one request open on the wire
# while a USR2 is delivered to the master and a new master generation takes
# over the pidfile underneath it. This driver keeps the drip request open in a
# background shell, delivers the USR2 only after the reply is PROVABLY
# in flight (the backend journal "send" oracle, not a wall-clock guess), polls
# for a distinct new master pid, joins the in-flight request with a bounded
# deadline, and only THEN retires the old master.
#
# BOOT CONTRACT: runs under PROBER_DAEMON_MODE=on (see env) -- a USR2 cannot be
# delivered to a daemon-off master (ngx_signal_handler drops NGX_CHANGEBIN when
# getppid()==ngx_parent, always true under prober_boot's `&` launcher). The
# master is tracked by $PROBER_PREFIX/nginx.pid, not $!; on USR2 the old master
# renames it to nginx.pid.oldbin and the new master writes a fresh nginx.pid.
#
# ORDERING IS CRITICAL and enforced by this driver, not left to chance: fire
# the in-flight request -> wait for the backend "send" event (ok 2) -> deliver
# USR2 (ok 3) -> join the in-flight response to completion (ok 4) -> ONLY THEN
# retire the old master with WINCH+QUIT (ok 8). Retiring the old master before
# the in-flight response completes would test worker_shutdown_timeout behavior
# instead of USR2 survival, which is a different (and already covered, see
# reload-worker-shutdown-timeout) scenario.
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
# STATUS, so a `not ok` that did not also raise it would be vacuous. Every
# branch that prints `not ok` bumps FAILED.
FAILED=0

serves_ok() {   # a fresh connection is accepted and answers 200
    local out
    out="$(
        exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    )" || return 1
    # Herestring, not a pipe -- same early-match SIGPIPE as
    # usr2-state-machine. See that file for the CI evidence.
    grep -q '^HTTP/1.1 200' <<<"$out"
}

read_pidfile() {   # $1 = pidfile path; echoes a live pid or nothing
    [ -s "$1" ] || return 0
    local p
    # Brace-group the input redirect so its OWN open failure is suppressed: `[ -s ]`
    # and this read are not atomic, and `tr ... < "$1" 2>/dev/null` only silences
    # tr's stderr, not the shell's redirect-open error (which leaks a stray "No such
    # file or directory" when the master unlinks the pidfile between the two).
    p="$( { tr -d '[:space:]' <"$1"; } 2>/dev/null )"
    # MUST return 0 even with no live pid: absence is a normal outcome (missing
    # .oldbin, an already-retired master, or a pidfile caught mid-rewrite during
    # the two-master overlap). Callers detect it via empty stdout; a non-zero
    # status would abort the driver under `set -e` at the bare assignments in
    # the new-master poll (L221) and the .oldbin/retire legs (L317, L350).
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
    return 0
}

# The inode behind the master's listening socket fd for OUR 127.0.0.1:$PORT.
# Copied verbatim from usr2-state-machine: pinned to a LISTEN-state entry in
# /proc/net/tcp bound to our exact address:port, never an arbitrary socket fd
# (the master also holds channel/signal socketpairs, inherited the same way,
# which would pass the oracle without proving listen-socket survival). Returns
# nothing when /proc is unreadable or no matching listener fd is found; the
# caller treats an empty result as a visible SKIP.
LISTEN_HEX=""
if [ -n "${PORT:-}" ]; then
    LISTEN_HEX="$(printf '0100007F:%04X' "$PORT")"
fi

listen_inode() {   # $1 = master pid
    local d="/proc/$1/fd" fd tgt ino
    [ -r "$d" ] || return 0
    [ -r /proc/net/tcp ] && [ -n "$LISTEN_HEX" ] || return 0
    for fd in "$d"/*; do
        tgt="$(readlink "$fd" 2>/dev/null)" || continue
        case "$tgt" in
            socket:\[*\])
                ino="${tgt#socket:[}"; ino="${ino%]}"
                if awk -v i="$ino" -v a="$LISTEN_HEX" \
                       'NR>1 && $10==i && $4=="0A" && $2==a{f=1} END{exit !f}' \
                       /proc/net/tcp 2>/dev/null; then
                    echo "$ino"; return 0
                fi
                ;;
        esac
    done
    return 0
}

# TAP plan:
#  1 baseline: serving, pidfile live, no .oldbin
#  2 the in-flight reply was dripping from the upstream BEFORE the USR2
#    (backend journal "send" ordering oracle)
#  3 USR2 forked a new master (fresh nginx.pid, distinct live pid; adopted) AND
#    the in-flight request was still open at USR2-delivery time -- the second
#    half is the anti-vacuity gate that makes ok 4 mean "survived the exec",
#    not merely "a complete body exists somewhere"
#  4 the in-flight streaming response completed INTACT across the USR2 (the
#    headline: bounded join, 200, full 40-char body)
#  5 the backend served the in-flight request EXACTLY ONCE (not re-issued
#    across the upgrade)
#  6 .oldbin held the old master, distinct from the new
#  7 the listen socket survived the exec (same inode old vs new master)
#  8 old master retired (WINCH+QUIT), .oldbin gone, nginx.pid still the new
#    master, port still answers, listen inode unchanged
#  9 no worker died by signal
echo "1..9"

# --- baseline ---------------------------------------------------------------
OLD_MASTER="$PROBER_SERVER_PID"
INODE_PROBED=0
OLD_INODE="$(listen_inode "$OLD_MASTER")"
[ -n "$OLD_INODE" ] && INODE_PROBED=1

if serves_ok && [ -n "$(read_pidfile "$PIDFILE")" ] && [ ! -e "$OLDBIN" ]; then
    echo "ok 1 - baseline: serving, pidfile live, no .oldbin"
else
    echo "not ok 1 - baseline not clean before the upgrade"
    [ -e "$OLDBIN" ] && echo "# nginx.pid.oldbin already exists before USR2"
    FAILED=$((FAILED + 1))
fi

# --- fire the in-flight request ---------------------------------------------
# Raw HTTP/1.1 GET over /dev/tcp, captured to a file in a background subshell,
# same shape as backend-reload-inflight. The request will still be receiving
# its dripped upstream reply when the USR2 fires.
INFLIGHT="$PROBER_PREFIX/inflight.out"
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET /mc?key=slow HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
    # Ignore cat's exit status: a Connection: close response commonly ends in
    # an RST once the server has sent everything, and cat then exits non-zero
    # having already delivered a complete body.
    cat <&3 2>/dev/null || true
) >"$INFLIGHT" 2>/dev/null &
INFLIGHT_PID=$!

# The USR2 must not be sent until the request has PROVABLY reached the
# upstream and the drip has begun -- otherwise, on a loaded runner, the
# request could arrive AFTER the exec and still return 200/full-body,
# certifying "a request spanned the USR2" while none did. A bare sleep is a
# wall-clock guess that races the request on exactly the hosts where the
# ordering is fragile (AUD-10, see backend-reload-inflight). The falsifiable
# ordering oracle is the backend JOURNAL: fakesrv writes a {"ev":"send",...}
# record the moment it puts the FIRST byte of the reply on the wire -- a
# strictly stronger event than {"ev":"cmd",...,"cmd":"get",...}, which proves
# only that the get was RECEIVED, not that a multi-second drip has begun.
#
# Fixed-step counted iterations, never a wall-clock diff: 100 * 50 ms = 5 s.
SEND_SEEN=0
for ((i = 0; i < 100; i++)); do
    if [ -n "$PROBER_BACKEND_JOURNAL" ] \
       && grep -q '"ev":"send"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null; then
        SEND_SEEN=1
        break
    fi
    sleep 0.05
done
if [ "$SEND_SEEN" -eq 1 ]; then
    echo "ok 2 - the in-flight reply was dripping from the upstream before the USR2"
else
    echo "not ok 2 - the upstream never started dripping its reply before the USR2"
    echo "# backend journal recorded no send within 5 s; ordering precondition unmet"
    FAILED=$((FAILED + 1))
fi

# --- USR2: fork the new binary, AFTER the drip is provably underway ---------
# Fixed-step counted polling, never a wall-clock diff (same discipline as
# usr2-state-machine): 100 * 50 ms = 5 s ceiling.
kill -USR2 "$OLD_MASTER" 2>/dev/null || true

# Snapshot, the instant the USR2 is delivered, whether the in-flight request
# is STILL open. This is the discriminator that makes ok 4 non-vacuous. ok 4
# alone ("the body arrived intact") is satisfied by ANY complete response --
# including one that finished BEFORE the USR2 ever landed, in which case no
# transfer actually spanned the upgrade and the scenario proved nothing. The
# "send" journal record (ok 2) is append-only and cannot be un-seen, so it too
# stays green for a request that has since completed. The honest proof that a
# transfer was genuinely mid-flight ACROSS the exec is that the client was
# still receiving when the new master forked: assert INFLIGHT_PID is alive at
# USR2-delivery time (checked in ok 3 below). The drip (~3 s over a 40-byte
# value at 4 B/300 ms) is many times longer than a USR2 fork (~ms), so on any
# non-pathological host the request is provably still open here; if it is
# already gone, the ordering broke and the "intact" claim would be vacuous.
INFLIGHT_ALIVE_AT_USR2=0
kill -0 "$INFLIGHT_PID" 2>/dev/null && INFLIGHT_ALIVE_AT_USR2=1

NEW_MASTER=""
for ((i = 0; i < 100; i++)); do
    p="$(read_pidfile "$PIDFILE")"
    if [ -n "$p" ] && [ "$p" != "$OLD_MASTER" ]; then
        NEW_MASTER="$p"
        break
    fi
    sleep 0.05
done

# ok 3 gates on BOTH: a distinct new master forked AND the in-flight request
# was still open when the USR2 was delivered. The second half is the
# anti-vacuity gate (see the INFLIGHT_ALIVE_AT_USR2 comment above): without it,
# a run where the reply finished before the USR2 -- so no transfer spanned the
# exec at all -- would still sail through ok 4's "body intact" and ok 2's
# append-only "send" record, certifying a mid-flight survival that never
# happened. A full-join-before-USR2 mutation (or any host where the drip
# finished too fast) reds here instead of passing silently.
if [ -n "$NEW_MASTER" ] && [ "$INFLIGHT_ALIVE_AT_USR2" -eq 1 ]; then
    echo "ok 3 - USR2 forked a new master (pid $NEW_MASTER, was $OLD_MASTER) while the reply was in flight"
    # Adopt the new master as THE master so teardown (prober_stop via the EXIT
    # trap) targets the generation that owns the listen socket and pidfile.
    PROBER_SERVER_PID="$NEW_MASTER"
    export PROBER_SERVER_PID
elif [ -z "$NEW_MASTER" ]; then
    echo "not ok 3 - USR2 did not fork a new master (binary upgrade ignored?)"
    echo "# nginx.pid still holds the old master $OLD_MASTER after 5 s;"
    echo "# under daemon off; USR2 is dropped -- check PROBER_DAEMON_MODE=on took effect"
    grep -n 'changing binary signal is ignored' "$ELOG" | sed 's/^/# /' || true
    # No adoption here: this branch proved NEW_MASTER is empty, so no new master
    # exists. The old master still owns nginx.pid, so PROBER_SERVER_PID is
    # already the correct teardown target.
    FAILED=$((FAILED + 1))
else
    echo "not ok 3 - the in-flight reply had already completed when the USR2 was delivered (no transfer spanned the exec; ok 4 would be vacuous)"
    echo "# INFLIGHT_PID was not alive at USR2-delivery time -- the drip finished too fast or ordering broke"
    PROBER_SERVER_PID="$NEW_MASTER"
    export PROBER_SERVER_PID
    FAILED=$((FAILED + 1))
fi

# --- join the in-flight request ---------------------------------------------
# It must have completed. A bare `wait` on a hung request would never reach
# the body check below (AUD-09, see backend-reload-inflight): if the USR2
# overlap dropped the request and the upstream never closes, the background
# client blocks forever and so does this driver. Poll for the background shell
# to exit within a deadline; if it overruns, KILL the subtree (cat is a CHILD
# of the backgrounded subshell, killing only INFLIGHT_PID would orphan it) and
# fall through -- the truncated/empty $INFLIGHT then fails the assertion
# below, the correct verdict for a request that never completed.
join_deadline=$(( SECONDS + 10 ))
while kill -0 "$INFLIGHT_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        pkill -P "$INFLIGHT_PID" 2>/dev/null || true
        kill "$INFLIGHT_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$INFLIGHT_PID" 2>/dev/null || true

# The response must be a complete, correct 200 carrying the full seeded value.
# A USR2 that dropped the in-flight request would leave a truncated body, a
# 502/connection-reset, or an empty file -- each of which fails this check.
# THE HEADLINE oracle: the old master's worker kept serving the drip across
# the exec and the two-master overlap.
if grep -q '^HTTP/1.1 200' "$INFLIGHT" \
   && grep -q '0123456789abcdefghijklmnopqrstuvwxyzABCD' "$INFLIGHT"; then
    echo "ok 4 - the in-flight streaming response completed intact across the USR2"
else
    echo "not ok 4 - the in-flight response was dropped or truncated by the USR2"
    # head FIRST, then sed: under `pipefail` a `sed ... | head -20` pipeline
    # returns 141 when sed is SIGPIPEd (INFLIGHT >20 lines), which `set -e`
    # turns into an abort before the FAILED bump below -- on the very failure
    # path this diagnostic exists for.
    head -20 "$INFLIGHT" | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- the in-flight request hit the upstream exactly once --------------------
# Counted now, before any further legs. If the USR2 overlap had dropped the
# in-flight request and it were re-issued to the new generation, the backend
# journal would carry a SECOND {"ev":"cmd",...,"cmd":"get",...}. Exactly one
# proves the single client request crossed the upgrade as one upstream
# exchange, not two. A zero is impossible once ok 2 passed (it required a
# send, which requires a received get); the guard is against >1.
GET_CMDS=0
if [ -n "$PROBER_BACKEND_JOURNAL" ]; then
    GET_CMDS=$(grep -c '"ev":"cmd"[^}]*"cmd":"get"' "$PROBER_BACKEND_JOURNAL" 2>/dev/null || true)
fi
if [ "$GET_CMDS" -eq 1 ]; then
    echo "ok 5 - the backend served the in-flight request exactly once across the USR2"
else
    echo "not ok 5 - the backend saw the in-flight get $GET_CMDS times (expected 1: re-issued across the upgrade?)"
    FAILED=$((FAILED + 1))
fi

# --- .oldbin appeared, naming the OLD master alongside the new --------------
# Poll: the rename can lag the fresh nginx.pid write by a scheduler tick. By
# this point ok 4 has already joined the in-flight response, so this is purely
# bookkeeping confirmation, not part of the ordering-critical path.
OLDBIN_PID=""
for ((i = 0; i < 100; i++)); do
    OLDBIN_PID="$(read_pidfile "$OLDBIN")"
    [ -n "$OLDBIN_PID" ] && break
    sleep 0.05
done

if [ -n "$OLDBIN_PID" ] && [ "$OLDBIN_PID" = "$OLD_MASTER" ] && \
   [ -n "$NEW_MASTER" ] && [ "$OLDBIN_PID" != "$NEW_MASTER" ]; then
    echo "ok 6 - .oldbin holds the old master $OLD_MASTER, distinct from new $NEW_MASTER"
else
    echo "not ok 6 - .oldbin did not name the old master alongside a distinct new master"
    echo "# .oldbin=${OLDBIN_PID:-<none>} old=$OLD_MASTER new=${NEW_MASTER:-<none>}"
    FAILED=$((FAILED + 1))
fi

# --- listen socket survived the exec (same inode on the new master) ---------
NEW_INODE=""
[ -n "$NEW_MASTER" ] && NEW_INODE="$(listen_inode "$NEW_MASTER")"
if [ "$INODE_PROBED" -eq 0 ] || [ -z "$NEW_INODE" ]; then
    echo "ok 7 - listen socket inode # SKIP /proc listen-fd not readable on this host"
elif [ "$NEW_INODE" = "$OLD_INODE" ]; then
    echo "ok 7 - listen socket survived the exec (inode $NEW_INODE, inherited not re-bound)"
else
    echo "not ok 7 - listen socket inode changed across USR2 (old $OLD_INODE, new $NEW_INODE = a re-bind)"
    FAILED=$((FAILED + 1))
fi

# --- retire the old master, ONLY NOW that the in-flight response is done ----
# WINCH drains the old master's remaining workers, QUIT stops the old master
# itself. The pid comes from nginx.pid.oldbin (where the old master parked it
# on USR2), not from the shell's memory, so the driver retires whatever
# generation the engine actually placed there. This happens strictly AFTER ok
# 4 joined the in-flight request -- retiring earlier would test
# worker_shutdown_timeout behavior, not USR2 survival (see header).
RETIRE_PID="$(read_pidfile "$OLDBIN")"
[ -n "$RETIRE_PID" ] || RETIRE_PID="$OLD_MASTER"
kill -WINCH "$RETIRE_PID" 2>/dev/null || true
kill -QUIT  "$RETIRE_PID" 2>/dev/null || true

# Wait for the old master to exit AND .oldbin to be removed (nginx unlinks it
# on clean shutdown). 5 s ceiling, counted.
OLDBIN_GONE=0
for ((i = 0; i < 100; i++)); do
    if ! kill -0 "$RETIRE_PID" 2>/dev/null && [ ! -e "$OLDBIN" ]; then
        OLDBIN_GONE=1
        break
    fi
    sleep 0.05
done

POST_INODE=""
[ -n "$NEW_MASTER" ] && POST_INODE="$(listen_inode "$NEW_MASTER")"
INODE_OK=1
if [ "$INODE_PROBED" -eq 1 ] && [ -n "$POST_INODE" ] && [ "$POST_INODE" != "$OLD_INODE" ]; then
    INODE_OK=0
fi

if [ "$OLDBIN_GONE" -eq 1 ] && [ -n "$(read_pidfile "$PIDFILE")" ] && \
   [ "$(read_pidfile "$PIDFILE")" = "$NEW_MASTER" ] && serves_ok && [ "$INODE_OK" -eq 1 ]; then
    echo "ok 8 - old master retired, .oldbin gone, nginx.pid still the new master, port still answers, listen inode unchanged"
else
    echo "not ok 8 - the old generation did not clean up after WINCH+QUIT, or service was disrupted"
    kill -0 "$RETIRE_PID" 2>/dev/null && echo "# old master $RETIRE_PID still alive after WINCH+QUIT"
    [ -e "$OLDBIN" ] && echo "# nginx.pid.oldbin still present"
    serves_ok || echo "# port no longer answers"
    [ "$INODE_OK" -eq 0 ] && echo "# listen inode changed: was $OLD_INODE, now $POST_INODE"
    FAILED=$((FAILED + 1))
fi

# --- no worker died by signal ------------------------------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 9 - a worker died by signal during the upgrade"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 9 - no worker died by signal"
fi

# No separate prober leg: the nine driver oracles above already cover baseline
# health (1), ordering (2), the master-generation hand-off (3, 6, 7, 8), the
# in-flight-survival headline (4, 5), and crash-freedom (9) -- everything a
# post-usr2.rule strict case would additionally prove (a fresh request on the
# new-only generation gets a clean 200 with no leaked fds) is already implied
# by ok 8's serves_ok check plus usr2-state-machine's own post-retire leg
# covering that shape independently. Adding a redundant prober leg here would
# duplicate usr2-state-machine's ok 7 without adding a new falsifiable claim.

[ "$FAILED" -eq 0 ] || exit 1
exit 0
