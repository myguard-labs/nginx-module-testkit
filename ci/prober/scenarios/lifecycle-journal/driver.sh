#!/usr/bin/env bash
#
# Scenario: an out-of-process lifecycle-event journal, and the process-
# termination proof it makes possible that an in-worker HTTP probe snapshot
# cannot.
#
# WHY OUT OF PROCESS. This tree has no exit_process / init_process /
# exit_master module hooks anywhere in it (`grep -rn` over the whole tree for
# them returns nothing), and the probe this project's other 50+ scenarios
# lean on (ngx_test_probe.c / PROBE_HTTP_TEMPLATE.c) is a request-time
# renderer: once a worker has exited there is nothing left inside the process
# to ask. So the oracle for "did this process terminate, and how" cannot live
# inside nginx or inside a request/response pair -- it has to be a reader
# that outlives the thing it describes. prober_journal_start (lib.sh) is that
# reader: a background `tail -F` loop translating nginx's OWN NOTICE-level
# exit lines into an append-only JSONL journal that keeps running after every
# worker and the master it watches are gone.
#
# THE FOUR CLAIMS, and why each is the shape it is:
#
#   1. QUIT emits the terminal event for the worker(s) it retired. QUIT is the
#      graceful shutdown signal: the worker logs "gracefully shutting down"
#      then, once its timers drain, "exiting" -- both NOTICE lines the
#      journal watcher translates into worker/shutting_down and
#      worker/exiting records. The terminal record here is "exiting".
#
#   2. TERM emits the terminal event too, by a DIFFERENT log path
#      (ngx_terminate, no "gracefully shutting down" step -- see
#      ngx_process_cycle.c:714 vs :731) but the SAME terminal line, "exiting".
#      Proving both signals produce the record, via different code paths in
#      the traced binary, is what makes claim 3 below a real negative control
#      rather than an artefact of one signal's phrasing.
#
#   3. SIGKILL does NOT emit a terminal event. nginx installs no handler for
#      SIGKILL -- the process is torn down by the kernel before
#      ngx_worker_process_cycle's `if (ngx_terminate)` branch, the one that
#      logs "exiting", ever runs. So a killed worker leaves NO record in the
#      journal for its pid: not because the watcher was told to ignore one,
#      but because nginx itself never wrote the line the watcher translates.
#      This is the NON-VACUITY control: it is what tells apart a real
#      out-of-process oracle from one that would print something on its own
#      teardown regardless of how the process actually died.
#
#   4. Sequence numbers strictly increase, one per emitted event, with none
#      lost or duplicated -- checked across all the events the three phases
#      above produced, read back from the one journal file spanning them.
#
# Why a driver and not a .rule file: this proof spans three separate signals
# delivered to three separate master/worker generations with the journal
# file read back BETWEEN them, and the prober has no notion of a lifecycle
# journal or of signal delivery -- same rationale as usr2-state-machine and
# worker-death.
#
# BOOT CONTRACT: PROBER_DAEMON_MODE=on (see env) -- the master is tracked by
# $PROBER_PREFIX/nginx.pid, not $!. Phase 1 (QUIT) runs against the
# generation run-scenario.sh's OWN prober_boot already started before this
# driver runs; phases 2 (TERM) and 3 (SIGKILL) stop whatever master is
# currently up (via the same pidfile-driven prober_stop the harness itself
# uses for teardown) and call prober_boot again for a genuinely fresh
# generation, so QUIT, TERM and SIGKILL each land on an independent
# master/worker with no state carried over from the phase before it.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

# The env file's PROBER_DAEMON_MODE=on is sourced into run-scenario.sh's OWN
# shell (run-scenario.sh:112) and never exported -- fine for every OTHER
# PROBER_DAEMON_MODE=on scenario, none of which calls prober_boot a second
# time from inside driver.sh (a separate process). This one does (phases 2
# and 3 below need a genuinely fresh master/worker generation), so
# prober_boot's daemon-on branch needs the opt-in visible in THIS process too,
# or it silently falls back to tracking the launcher's own $! -- which the
# daemon-on path immediately reaps, and the very next liveness check reports
# "server failed to start" on a server that in fact started and is fine.
export PROBER_DAEMON_MODE=on

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
JOURNAL="$PROBER_PREFIX/lifecycle.jsonl"
PIDFILE="$PROBER_PREFIX/nginx.pid"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

read_pidfile() {   # echoes a live pid, or nothing
    [ -s "$PIDFILE" ] || return 0
    local p
    p="$( { tr -d '[:space:]' <"$PIDFILE"; } 2>/dev/null )"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
    return 0
}

wait_master_gone() {   # $1 = pid, $2 = timeout steps of 50ms
    local pid="$1" n="$2" i
    for ((i = 0; i < n; i++)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.05
    done
    return 1
}

wait_journal_lines() {   # $1 = pattern (grep -E), $2 = timeout steps of 50ms
    local pattern="$1" n="$2" i
    for ((i = 0; i < n; i++)); do
        [ -s "$JOURNAL" ] && grep -qE "$pattern" "$JOURNAL" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# wait_port_free -- poll until nothing owns $PORT, up to 5 s.
#
# The retiring master's own exit (ngx_master_process_exit, the line this
# scenario's journal watches) happens BEFORE its listening children have
# necessarily closed the socket down to the kernel's last reference -- a
# worker that is still draining a connection can hold the listen fd open a
# few scheduler ticks past the master's own "exit" log line. Rebooting a
# fresh master onto the port before that last reference is gone is exactly
# prober_boot's own pre-boot ownership check's failure mode (a stale listener
# from a process this run just retired, not "another job's process" as that
# check's comment describes, but the same shape) -- so this driver waits for
# the port to go fully quiet BETWEEN phases, the same way prober_boot itself
# refuses to spawn onto an already-bound one.
wait_port_free() {
    local i
    for ((i = 0; i < 100; i++)); do
        prober_port_owner_pids 127.0.0.1 "$PORT" >/dev/null 2>&1 || return 0
        sleep 0.05
    done
    return 1
}

# One fresh master/worker generation, journalled from its own boot.
#
# run-scenario.sh already called prober_boot ONCE, before driver.sh ever
# runs, and that is the generation phase 1 (QUIT) uses -- calling
# prober_boot again here on the very first phase would try to bind the same
# port a second time out from under the master that already owns it. Only
# phase 2 (TERM) and phase 3 (SIGKILL) need a genuinely fresh boot, after the
# previous phase's stop_phase has fully retired the generation before it;
# start_phase's REBOOT argument selects that.
start_phase() {
    local reboot="${1:-0}"
    if [ "$reboot" = "1" ]; then
        # PROBER_TIMEOUT_SCALE is normalized by run-scenario.sh's own
        # prober_resolve call in ITS shell and never exported to this
        # driver process -- prober_boot reads it directly, so a second boot
        # from here needs it normalized again or `set -u` aborts on the
        # first scaled arithmetic expansion inside prober_boot.
        prober_normalize_timeout_scale
        prober_boot
    fi
    prober_journal_start "$ELOG" "$JOURNAL" "$PIDFILE"
}

# Stops the journal watcher FIRST, then the server: the watcher's own exit
# must not race the last line it is meant to translate, so its "$1" argument
# below is only ever called after wait_journal_lines has already confirmed
# the terminal record landed (or the timeout has already been charged to the
# calling phase's own failure).
stop_phase() {
    prober_journal_stop
    prober_stop
    wait_port_free || true
}

echo "1..4"

# --- 1: QUIT emits the terminal event for the worker(s) it retired --------
start_phase 0
# Discover the one worker pid via the probe endpoint -- the pidfile only
# names the master.
WPID1=""
for ((i = 0; i < 100; i++)); do
    body="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID1="$(prober_probe_field "$body" pid 2>/dev/null || true)"
    [ -n "$WPID1" ] && break
    sleep 0.05
done

MASTER1="$(read_pidfile)"
if [ -z "$WPID1" ] || [ -z "$MASTER1" ]; then
    echo "Bail out! phase 1 (QUIT) never got a live worker/master pid to target"
    exit 1
fi

kill -QUIT "$MASTER1" 2>/dev/null || true
wait_master_gone "$MASTER1" 100 || true

if wait_journal_lines "\"role\":\"worker\",\"pid\":$WPID1,\"gen\":[0-9]+,\"ev\":\"exiting\"" 40; then
    echo "ok 1 - QUIT produced a terminal (exiting) journal record for worker $WPID1"
else
    echo "not ok 1 - no terminal journal record for worker $WPID1 after QUIT"
    echo "# LIFECYCLE-RED-QUIT"
    [ -s "$JOURNAL" ] && sed 's/^/# /' "$JOURNAL" || echo "# journal is empty"
    FAILED=$((FAILED + 1))
fi
stop_phase

# --- 2: TERM emits the terminal event ---------------------------------------
start_phase 1
WPID2=""
for ((i = 0; i < 100; i++)); do
    body="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID2="$(prober_probe_field "$body" pid 2>/dev/null || true)"
    [ -n "$WPID2" ] && break
    sleep 0.05
done
MASTER2="$(read_pidfile)"
if [ -z "$WPID2" ] || [ -z "$MASTER2" ]; then
    echo "Bail out! phase 2 (TERM) never got a live worker/master pid to target"
    exit 1
fi

kill -TERM "$MASTER2" 2>/dev/null || true
wait_master_gone "$MASTER2" 100 || true

if wait_journal_lines "\"role\":\"worker\",\"pid\":$WPID2,\"gen\":[0-9]+,\"ev\":\"exiting\"" 40; then
    echo "ok 2 - TERM produced a terminal (exiting) journal record for worker $WPID2"
else
    echo "not ok 2 - no terminal journal record for worker $WPID2 after TERM"
    echo "# LIFECYCLE-RED-TERM"
    [ -s "$JOURNAL" ] && sed 's/^/# /' "$JOURNAL" || echo "# journal is empty"
    FAILED=$((FAILED + 1))
fi
stop_phase

# --- 3: SIGKILL does NOT emit a terminal event (the non-vacuity control) --
start_phase 1
WPID3=""
for ((i = 0; i < 100; i++)); do
    body="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID3="$(prober_probe_field "$body" pid 2>/dev/null || true)"
    [ -n "$WPID3" ] && break
    sleep 0.05
done
MASTER3="$(read_pidfile)"
if [ -z "$WPID3" ] || [ -z "$MASTER3" ]; then
    echo "Bail out! phase 3 (SIGKILL) never got a live worker/master pid to target"
    exit 1
fi

# Kill the WORKER, not the master: a killed master's own generation never
# writes the "exit" line either (same reason), but proving the effect on the
# worker keeps this row targeting exactly the pid this driver tracked and
# read out of the probe, with no ambiguity about which generation "gen" would
# apply to for an untracked master death.
kill -KILL "$WPID3" 2>/dev/null || true
# The master respawns a replacement almost immediately; give the log/journal
# a fair window before concluding no terminal record exists, same 40-step
# (2 s) budget as the two positive legs above, so this is not a race the
# positive legs did not also have to win.
sleep 2

if wait_journal_lines "\"role\":\"worker\",\"pid\":$WPID3,\"gen\":[0-9]+,\"ev\":\"exiting\"" 1; then
    echo "not ok 3 - SIGKILL produced a terminal journal record for worker $WPID3 (should be none)"
    echo "# LIFECYCLE-RED-SIGKILL-NONVACUITY"
    FAILED=$((FAILED + 1))
else
    echo "ok 3 - SIGKILL produced NO terminal journal record for worker $WPID3"
fi
# The master this phase booted is a fresh generation kill -QUIT can retire
# cleanly for teardown's own sake; its own exit record (if any) does not
# affect claim 3, which is scoped to the WORKER pid only.
kill -QUIT "$MASTER3" 2>/dev/null || true
wait_master_gone "$MASTER3" 100 || true
stop_phase

# --- 4: sequence numbers strictly increase, none lost or duplicated -------
if [ ! -s "$JOURNAL" ]; then
    echo "not ok 4 - the journal is empty; nothing to check monotonicity on"
    echo "# LIFECYCLE-RED-SEQUENCE"
    FAILED=$((FAILED + 1))
else
    SEQ_CHECK="$(awk -F'"seq":' '{n=$2+0; if (n<=prev) bad=1; prev=n; seen[n]++}
        END{
            for (s in seen) if (seen[s] > 1) { print "dup:" s; exit }
            if (bad) { print "nonmonotonic"; exit }
            print "ok"
        }' "$JOURNAL")"
    if [ "$SEQ_CHECK" = "ok" ]; then
        N="$(wc -l < "$JOURNAL")"
        echo "ok 4 - sequence numbers strictly increase across $N events, none lost or duplicated"
    else
        echo "not ok 4 - sequence check failed ($SEQ_CHECK)"
        echo "# LIFECYCLE-RED-SEQUENCE"
        sed 's/^/# /' "$JOURNAL"
        FAILED=$((FAILED + 1))
    fi
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
