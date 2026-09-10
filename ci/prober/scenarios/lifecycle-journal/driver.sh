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
# THE FIVE CLAIMS, and why each is the shape it is:
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
#      This is the NON-VACUITY control.
#
#      IT IS ALSO THE CLAIM MOST EASILY FAKED, because its pass condition is
#      an ABSENCE, and an absence is produced just as readily by a reader that
#      never attached, died, or was never started as by the truth being
#      asserted. Two things stop that, and only together: prober_journal_start
#      does not return until its attach handshake proves the watcher is
#      reading the log, and this phase requires a LIVENESS WITNESS at its end
#      -- the phase-3 master's own correctly attributed exit record, on the
#      same watcher, in the same phase -- before it will conclude anything
#      from the killed worker's silence. Without the witness this printed
#      `ok 3` with the phase-3 watcher SIGKILLed, and assertion 4 passed too,
#      because phases 1 and 2 had already made the journal non-empty. The
#      "dead phase-3 reader" mutation row exists to keep it that way.
#
#   4. Sequence numbers strictly increase, one per emitted event, with none
#      lost or duplicated -- checked across all the events the three phases
#      above produced, read back from the one journal file spanning them. A
#      record with no seq field at all is reported as MALFORMED, not as
#      non-monotonic: scoring it 0 would report a fabricated sequence defect
#      of the server for what is a defect of the record shape.
#
#   5. The records carry the schema this journal documents: every line matches
#      the declared shape, no pid this driver read out of the probe as a
#      WORKER is recorded with role master, and gen advances exactly once per
#      master exit. Nothing else here reads role or gen, which is precisely
#      how the journal first shipped producing a schema it did not document --
#      both roles log an identical bare "exit", and a classifier keying on the
#      absence of a pid in the text labelled every worker exit "master" while
#      claims 1-4 stayed green. Claim 5 is the one that reds.
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

# Every `Bail out!` below leaves this phase's journal watcher running, and
# with it a `tail -F` on a log the harness is about to remove. run-scenario.sh
# installs prober_cleanup in ITS shell, not in this driver process, so nothing
# else reaps it. One trap, installed before the first watcher exists.
trap 'prober_journal_stop || true' EXIT

FAILED=0

read_pidfile() {   # echoes a live pid, or nothing
    [ -s "$PIDFILE" ] || return 0
    local p
    p="$( { tr -d '[:space:]' <"$PIDFILE"; } 2>/dev/null )"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
    # explicit: the && chain's falsity must not become the function's status
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
    prober_journal_start "$ELOG" "$JOURNAL"
}

# Stops the SERVER first, then the watcher -- the opposite of the original
# order, which stopped the watcher first and lost every master's own "exit"
# line to the gap.
#
# Stopping the watcher first is only safe if nothing more will be logged, and
# that is false here: prober_stop is what retires the generation, so the
# master's ngx_master_process_exit "exit" line -- the very line assertion 5's
# gen accounting counts, and the line assertion 3's liveness witness needs --
# is written AFTER the point the watcher used to be killed. With -n0 the next
# phase's watcher cannot recover it either. So the server is retired first,
# the master's terminal record is waited for, and only then is the watcher
# stopped.
#
# The wait is bounded and advisory: a phase whose own assertion already failed
# must not additionally hang here, and the assertion that cares about the
# record (5) reports its absence itself.
stop_phase() {
    local m="${1:-}"
    prober_stop
    if [ -n "$m" ]; then
        wait_journal_lines "\"role\":\"master\",\"pid\":$m,\"gen\":[0-9]+,\"ev\":\"exit\"" 60 || true
    fi
    prober_journal_stop
    wait_port_free || true
}

# The driver's own phase structure: phase 1 (QUIT) reuses run-scenario.sh's
# initial prober_boot, and phases 2 (TERM) and 3 (SIGKILL) each call
# start_phase with REBOOT=1 -- one boot-and-retire per phase, three phases,
# three generations. This is the out-of-band count assertion 5(c) verifies
# NMASTER against; it comes from the driver's structure, not from anything
# the journal or its classifier produced.
EXPECTED_GENS=3

echo "1..5"

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
stop_phase "$MASTER1"

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
stop_phase "$MASTER2"

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
# a fair window before concluding no terminal record exists. The wall-clock
# ceiling matches the two positive legs' 40-step (2 s) budget, but the
# semantics are stronger, not merely equal: the positive legs POLL and return
# as soon as their record appears, so they typically wait far less than 2 s,
# while this leg always burns the FULL 2 s. Absence is concluded only after
# strictly more time than any positive leg needed to confirm presence.
sleep 2

KILLED_RECORD=0
if wait_journal_lines "\"role\":\"worker\",\"pid\":$WPID3,\"gen\":[0-9]+,\"ev\":\"exiting\"" 1; then
    KILLED_RECORD=1
fi

# THE LIVENESS WITNESS, and why claim 3 is worthless without one.
#
# Claim 3's pass condition is an ABSENCE, and an absence is satisfied just as
# well by a watcher that never attached, died, or was never started at all as
# by the truth being asserted -- nginx genuinely never writing a line for a
# SIGKILLed process. prober_journal_start's handshake proves the watcher was
# attached when the phase BEGAN; this proves it was still alive and still
# translating lines at the END of the phase, after the kill, on the SAME
# watcher and in the SAME phase whose absence is being read.
#
# The witness is the phase-3 master's own clean retirement, which this driver
# has to perform for teardown anyway: QUIT it and require its correctly
# attributed terminal record (role master, its own pid) to appear. Only then
# does "no record for $WPID3" mean anything. The replacement worker the master
# respawned after the kill also retires here, which is why the QUIT happens
# before the verdict rather than after it.
kill -QUIT "$MASTER3" 2>/dev/null || true
wait_master_gone "$MASTER3" 100 || true

if wait_journal_lines "\"role\":\"master\",\"pid\":$MASTER3,\"gen\":[0-9]+,\"ev\":\"exit\"" 60; then
    WITNESS=1
else
    WITNESS=0
fi

if [ "$WITNESS" != "1" ]; then
    echo "not ok 3 - phase-3 journal watcher never produced the master $MASTER3 exit record that witnesses it was live; the absence of a record for worker $WPID3 proves nothing"
    echo "# LIFECYCLE-RED-SIGKILL-NONVACUITY"
    [ -s "$JOURNAL" ] && sed 's/^/# /' "$JOURNAL" || echo "# journal is empty"
    FAILED=$((FAILED + 1))
elif [ "$KILLED_RECORD" = "1" ]; then
    echo "not ok 3 - SIGKILL produced a terminal journal record for worker $WPID3 (should be none)"
    echo "# LIFECYCLE-RED-SIGKILL-NONVACUITY"
    FAILED=$((FAILED + 1))
else
    echo "ok 3 - SIGKILL produced NO terminal journal record for worker $WPID3, on a watcher witnessed live by master $MASTER3's own exit record"
fi
stop_phase "$MASTER3"

# --- 4: sequence numbers strictly increase, none lost or duplicated -------
if [ ! -s "$JOURNAL" ]; then
    echo "not ok 4 - the journal is empty; nothing to check monotonicity on"
    echo "# LIFECYCLE-RED-SEQUENCE"
    FAILED=$((FAILED + 1))
else
    # A line with no "seq": field at all is MALFORMED, not non-monotonic:
    # awk's $2+0 scores it 0, which then reads as "the sequence went
    # backwards" and reports a fabricated defect of the server for what is a
    # defect of the record shape. The two are separated so the diagnostic
    # names the real fault.
    SEQ_CHECK="$(awk '{
            if ($0 !~ /"seq":[0-9]+/) { print "malformed:line" NR; exit }
            split($0, a, /"seq":/); n = a[2] + 0
            if (n <= prev) bad = 1
            prev = n; seen[n]++
        }
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

# --- 5: role and gen are what the schema says they are --------------------
#
# WHY THIS EXISTS. Nothing above reads role or gen, which is exactly how the
# journal shipped producing a schema it did not document: ngx_process_cycle.c
# logs the SAME bare "exit" NOTICE for both roles (:662 master, :994 worker),
# so a classifier keying on "the text has no pid" -- rather than on WHOSE pid
# the line carries -- labels every worker's own exit "master" and, because gen
# advances after each master exit, advances gen about twice per real
# generation. Every assertion above stayed green through all of it. This row
# is the one that reds.
#
# Three things are checked, all derivable from what this driver already knows:
#
#   a. Every record matches the documented shape exactly. A watcher record of
#      ev "unparsed" is a shape violation on purpose: it is what lib.sh writes
#      when a line matched a lifecycle keyword but failed the anchored
#      "<pid>#<tid>: <word>" extraction, so a silent parser drift across the
#      pinned matrix reds here instead of quietly degrading the oracle to
#      "emits nothing" -- which claim 3 would score as a pass.
#
#   b. No master record carries a pid this driver knows to be a WORKER's. The
#      three worker pids were read out of the probe endpoint, so a
#      misclassification is directly observable rather than argued about.
#
#   c. gen advanced exactly once per master record and never went backwards.
#      This is checked two ways: first against EXPECTED_GENS, the number of
#      generations THIS DRIVER actually booted and retired (an out-of-band
#      count the classifier cannot influence), and second as a cheap
#      self-consistency guard that the emitter's own gen/master-exit identity
#      still holds. The self-consistency guard is NOT the generation oracle --
#      it is a structural identity of the emitter (see the comment below,
#      where it is checked) and holds for every journal the emitter can
#      produce, correct or not, so it alone would not catch a classifier
#      double-counting worker exits as master exits.
BAD5=""
BAD5_MARKER=""

# The alternation admits exactly two record families: a lifecycle event for a
# worker or master, and the watcher's own attach acknowledgement. It does NOT
# admit ev "unparsed" -- see (a) above, that record exists to red here.
RECORD_RE='^\{"role":"(worker|master)","pid":[0-9]+,"gen":[0-9]+,"ev":"(exit|exiting|shutting_down)","seq":[0-9]+\}$|^\{"role":"watcher","pid":0,"gen":[0-9]+,"ev":"ready","seq":[0-9]+\}$'
while IFS= read -r rec; do
    if ! printf '%s\n' "$rec" | grep -qE "$RECORD_RE"; then
        BAD5="record does not match the documented shape: $rec"
        break
    fi
done < "$JOURNAL"

if [ -z "$BAD5" ]; then
    for wp in "$WPID1" "$WPID2" "$WPID3"; do
        [ -n "$wp" ] || continue
        if grep -qE "\"role\":\"master\",\"pid\":$wp," "$JOURNAL"; then
            BAD5="worker pid $wp (read from the probe endpoint) is recorded with role master"
            break
        fi
    done
fi

if [ -z "$BAD5" ]; then
    NMASTER="$(grep -cE '"role":"master",.*"ev":"exit"' "$JOURNAL" || true)"
    # awk's `exit` inside a main rule transfers control to END rather than
    # skipping it, so every early-exit error path would ALSO print "final:<n>"
    # from END -- a second, unwanted line that gives BAD5 an embedded newline.
    # `err` suppresses that: END prints only when no main rule already did.
    GEN_CHECK="$(awk '{
            split($0, r, /"role":"/); split(r[2], r2, /"/); role = r2[1]
            split($0, g, /"gen":/); n = g[2] + 0
            if (NR > 1 && n < prev) { print "gen went backwards at line " NR; err=1; exit }
            if (NR > 1 && n > prev + 1) { print "gen jumped by " (n - prev) " at line " NR; err=1; exit }
            # gen may advance by exactly one, and only immediately AFTER a
            # master exit record -- the increment fires once that record is
            # emitted, so it is the FOLLOWING record that first shows the new
            # value, whatever role that record happens to carry.
            if (NR > 1 && n == prev + 1 && prevrole != "master") {
                print "gen advanced after a " prevrole " record at line " NR; err=1; exit
            }
            prev = n; prevrole = role; last = n
        }
        END{ if (!err) print "final:" last }' "$JOURNAL")"
    case "$GEN_CHECK" in
        final:*)
            FINAL_GEN="${GEN_CHECK#final:}"
            # THE GENERATION ORACLE: NMASTER (how many master-exit records the
            # journal holds) against EXPECTED_GENS (how many generations this
            # driver actually booted and retired -- out-of-band, independent
            # of anything the classifier produced). A classifier crediting
            # worker exits to the master inflates NMASTER past EXPECTED_GENS;
            # this is the comparison that catches it.
            if [ "$NMASTER" != "$EXPECTED_GENS" ]; then
                BAD5="recorded $NMASTER master exit records, but this driver booted and retired $EXPECTED_GENS generations"
                BAD5_MARKER="LIFECYCLE-RED-GENCOUNT"
            # Cheap emitter self-consistency guard ONLY, not the generation
            # oracle above: gen starts at 0 and increments AFTER each master
            # exit record is emitted, so the Kth master-exit record always
            # carries gen == K-1 and the final recorded gen is one less than
            # NMASTER, for EVERY journal the emitter can produce -- correct or
            # miscounted, since the restart path reseeds gen by recomputing
            # NMASTER the same way. It cannot distinguish a correct classifier
            # from a miscounting one; it only catches the emitter's internal
            # bookkeeping going out of step with its own master-exit count.
            elif [ "$FINAL_GEN" != "$((NMASTER - 1))" ]; then
                BAD5="internal: gen/master-exit identity violated (final gen $FINAL_GEN, $NMASTER master exits)"
            fi
            ;;
        *) BAD5="$GEN_CHECK" ;;
    esac
fi

if [ -z "$BAD5" ]; then
    echo "ok 5 - every record matches the documented schema; no worker pid is recorded as master; gen advanced once per master exit ($NMASTER)"
else
    echo "not ok 5 - role/gen schema violation ($BAD5)"
    echo "# ${BAD5_MARKER:-LIFECYCLE-RED-ROLEGEN}"
    sed 's/^/# /' "$JOURNAL"
    FAILED=$((FAILED + 1))
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
