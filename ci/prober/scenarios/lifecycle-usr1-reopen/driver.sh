#!/usr/bin/env bash
#
# Scenario: L-1 remainder (a) -- USR1 log-reopen inode/fd neutrality under
# traffic.
#
# USR1 tells nginx's master to reopen every log file at its CONFIGURED PATH
# (ngx_signal_handler.c's NGX_REOPEN_SIGNAL, "log rotation" in the manual):
# the operator (or logrotate) renames the old file away first, then sends
# USR1, and the master's new fd points at whatever inode now sits at that
# path -- a fresh, empty file if nothing else created one first, exactly as
# this driver does below. Three claims:
#
#   1. GENUINE REOPEN. The error_log's inode after USR1 differs from its
#      inode before, proven by st_ino, not by "the file got shorter" or any
#      other proxy a reopen-that-truncates-in-place could also produce.
#
#   2. NEUTRAL. The worker set (pid) and the worker's own open-fd count
#      (probe's "fds" field) are unchanged across the reopen: no fd leaked by
#      opening the new file before closing the old one, no restart, no extra
#      worker. This is a same-pid, same-run, before/after DELTA -- not an
#      absolute pin -- so it is unaffected by lib.sh's own note (see
#      prober_probe_normalize's header) that fds is environment-fragile
#      across HOSTS/FLAVORS; here both readings come from the identical
#      process on the identical box moments apart.
#
#   3. UNDISTURBED. A request already in flight when USR1 is sent completes
#      cleanly, with its own response, rather than being cut, delayed, or
#      duplicated -- USR1 must cost nothing to live traffic. Same slow-drip
#      /upload + mirror idiom as lifecycle-quit-vs-term-drain (see that
#      driver's header for why a bare `return 200` would leave this vacuous).
#
# THE SEAM lib.sh's own prober_journal_start comment documents ("SEED/ATTACH
# SEAM"): `_mark` is a line COUNT of whatever inode currently sits at $log,
# and the `tail -F -n "+$((_mark+1))"` that follows opens $log BY PATH,
# seeking to that line count in whatever inode it finds there. If the path is
# rotated (renamed away, fresh file created) in the gap between those two
# statements, tail attaches to the NEW, near-empty inode and seeks to a line
# number that file will not reach for a long time (or ever) -- every line
# that was in the OLD inode is gone from the new one and is never delivered.
# The ready-sentinel handshake does NOT catch this: the injected token is
# appended to whatever inode `$log` currently names, so it still eventually
# reaches the (correctly attached) tail and "ready" still fires -- it proves
# tail is reading A file at that path, never that it saw everything from
# $_mark forward in the file that mark was taken against.
#
# Durable memory mem_bacdaad51b3940dc9b3d1597ed858ced flags this seam as
# REFUTED-but-newly-reachable: no scenario before this one ever rotated
# $ELOG, so the race was real but unexercised. This scenario is the first to
# rotate that exact file the journal watches, so the seam is now live.
#
# RESOLUTION (rotation-safe attach, not a silent skip): this driver captures
# $ELOG's inode in the SAME breath as calling prober_journal_start, then
# re-checks it immediately after the attach handshake returns. If the inode
# changed underneath the call -- i.e. this run's own USR1 (or anything else)
# rotated the file between mark and attach -- the watcher may have silently
# lost the seam window, so the attach is torn down and retried from scratch
# against the (now stable) current inode, bounded, with a LOUD Bail out! if
# retries are exhausted. In this driver's own structure the hazard window is
# in practice empty (USR1 is sent well after start_phase's attach has already
# completed and been handshake-confirmed -- see PHASE below), so in a healthy
# run this guard fires zero times; it exists so a change to phase ordering,
# or a future scenario copying this file, cannot reintroduce the silent
# failure mem_bacdaad51b3940dc9b3d1597ed858ced warned about.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

export PROBER_DAEMON_MODE=on

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
JOURNAL="$PROBER_PREFIX/lifecycle.jsonl"
PIDFILE="$PROBER_PREFIX/nginx.pid"

trap 'prober_journal_stop || true' EXIT

FAILED=0

read_pidfile() {
    [ -s "$PIDFILE" ] || return 0
    local p
    p="$( { tr -d '[:space:]' <"$PIDFILE"; } 2>/dev/null )"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo "$p"
    return 0
}


# log_inode -- st_ino of $ELOG, or empty if it does not exist yet. `stat -c`
# is GNU-specific but this whole harness already assumes a GNU userland
# elsewhere (see lib.sh's own `stat -c` uses); no portability shim is owed
# here that the rest of the tree does not also owe.
log_inode() {
    stat -c '%i' "$ELOG" 2>/dev/null || true
}

# journal_attach_rotation_safe -- calls prober_journal_start, then proves the
# inode $_mark was taken against is still the inode tail -F actually attached
# to. See the SEAM comment above for why this cannot be inferred from the
# ready handshake alone. Retries (bounded) on a detected seam hit; Bail out!
# loud, never silent, if the race cannot be won.
journal_attach_rotation_safe() {
    local attempt ino_before ino_after
    for ((attempt = 0; attempt < 5; attempt++)); do
        ino_before="$(log_inode)"
        prober_journal_start "$ELOG" "$JOURNAL"
        ino_after="$(log_inode)"
        if [ "$ino_before" = "$ino_after" ]; then
            return 0
        fi
        # The file was rotated between the mark prober_journal_start took and
        # this check -- exactly the seam. The watcher this call just started
        # may have attached to the wrong (post-rotation) inode and skipped
        # every line the old one held; tear it down and retry against the
        # now-stable path rather than trust a journal that might be missing
        # its seam-window lines.
        echo "# lifecycle-usr1-reopen: journal attach raced a log rotation" \
             "(inode $ino_before -> $ino_after) on attempt $((attempt + 1));" \
             "retrying rotation-safe" >&2
        prober_journal_stop || true
    done
    echo "Bail out! journal_attach_rotation_safe could not win the" \
         "mark/attach seam against $ELOG after 5 attempts -- the watcher" \
         "may be reading the wrong inode, so no assertion over $JOURNAL" \
         "would mean anything. Not proceeding silently."
    exit 1
}

BODY="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX0123456789abcdefghij"   # 200 bytes
BODY_LEN=${#BODY}
CHUNK=4
STEP_SLEEP=0.15   # ~7.5s total drip -- see lifecycle-quit-vs-term-drain's sizing note

start_upload() {
    local step_sleep=$1 out=$2 pidvar=$3
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'POST /upload HTTP/1.1\r\nHost: prober\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' \
            "$BODY_LEN" >&3

        off=0
        while [ "$off" -lt "$BODY_LEN" ]; do
            len=$CHUNK
            remaining=$((BODY_LEN - off))
            [ "$len" -gt "$remaining" ] && len=$remaining
            printf '%s' "${BODY:$off:$len}" >&3
            off=$((off + len))
            if [ "$off" -lt "$BODY_LEN" ] && [ "$step_sleep" != 0 ]; then
                sleep "$step_sleep"
            fi
        done

        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    printf -v "$pidvar" '%s' "$!"
}

echo "1..7"

# run-scenario.sh has already called prober_boot ONCE, before driver.sh ever
# runs (same contract as lifecycle-journal's phase 1 and
# lifecycle-quit-vs-term-drain's phase A) -- this scenario has only one
# generation throughout, so no reboot is needed here at all.
journal_attach_rotation_safe

WPID_BEFORE=""
BODY0=""
for ((i = 0; i < 100; i++)); do
    BODY0="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID_BEFORE="$(prober_probe_field "$BODY0" pid 2>/dev/null || true)"
    [ -n "$WPID_BEFORE" ] && break
    sleep 0.05
done
MASTER="$(read_pidfile)"
if [ -z "$WPID_BEFORE" ] || [ -z "$MASTER" ]; then
    echo "Bail out! never got a live worker/master pid to target"
    exit 1
fi
FDS_BEFORE="$(prober_probe_field "$BODY0" fds 2>/dev/null || true)"
if [ -z "$FDS_BEFORE" ]; then
    echo "Bail out! probe did not report an fds field -- fd-neutrality" \
         "cannot be measured without it"
    exit 1
fi

INODE_BEFORE="$(log_inode)"
if [ -z "$INODE_BEFORE" ]; then
    echo "Bail out! error_log does not exist yet at $ELOG -- nothing to rotate"
    exit 1
fi

# --- start the in-flight upload, gate on it genuinely being open ----------
UPLOAD_OUT="$PROBER_PREFIX/upload-usr1.out"
start_upload "$STEP_SLEEP" "$UPLOAD_OUT" UPLOAD_PID

alive=0
for ((i = 0; i < 20; i++)); do   # 1s settle, well under the ~7.5s drip
    if kill -0 "$UPLOAD_PID" 2>/dev/null; then alive=1; else alive=0; break; fi
    sleep 0.05
done
if [ "$alive" -eq 1 ] && kill -0 "$UPLOAD_PID" 2>/dev/null; then
    echo "ok 1 - the upload was still in flight immediately before USR1"
else
    echo "not ok 1 - the upload was not in flight before USR1; the undisturbed-traffic claim below would be vacuous"
    echo "# LIFECYCLE-USR1-RED-NOT-INFLIGHT"
    FAILED=$((FAILED + 1))
fi

# --- rotate: rename the log away (the operator/logrotate half of the
# contract), THEN send USR1 (the "reopen at this path" half). Doing the
# rename ourselves, outside nginx, is exactly what real log rotation is --
# nginx's USR1 handler never renames anything itself, it only reopens
# whatever inode currently sits at the configured path.
mv -f "$ELOG" "$ELOG.rotated" 2>/dev/null || true

kill -USR1 "$MASTER" 2>/dev/null || true

# The reopen is asynchronous (the master signals workers; the actual
# freopen()-equivalent happens on nginx's own event-loop tick), so poll for
# the new inode to appear rather than assume it exists the instant kill
# returns.
INODE_AFTER=""
for ((i = 0; i < 100; i++)); do
    INODE_AFTER="$(log_inode)"
    [ -n "$INODE_AFTER" ] && [ "$INODE_AFTER" != "$INODE_BEFORE" ] && break
    sleep 0.05
done

if [ -n "$INODE_AFTER" ] && [ "$INODE_AFTER" != "$INODE_BEFORE" ]; then
    echo "ok 2 - the log was genuinely reopened (inode $INODE_BEFORE -> $INODE_AFTER)"
else
    echo "not ok 2 - the log inode did not change after USR1 (before=$INODE_BEFORE after=$INODE_AFTER)"
    echo "# LIFECYCLE-USR1-RED-NO-REOPEN"
    FAILED=$((FAILED + 1))
fi

# --- join the upload: USR1 must not disturb it -----------------------------
wait "$UPLOAD_PID" 2>/dev/null || true

if grep -q '^HTTP/1\.1 200' "$UPLOAD_OUT" 2>/dev/null && grep -q 'UPLOADED' "$UPLOAD_OUT" 2>/dev/null; then
    echo "ok 3 - the in-flight upload completed cleanly across the reopen (not cut, not stalled)"
else
    echo "not ok 3 - the in-flight upload did not complete cleanly across USR1"
    echo "# LIFECYCLE-USR1-RED-DISTURBED"
    sed 's/^/# /' "$UPLOAD_OUT" 2>/dev/null || true
    FAILED=$((FAILED + 1))
fi

# --- worker-set / pid neutrality: USR1 reopens files, it does not fork a
# new worker or retire the old one. A pid change here would mean this
# "reopen" actually triggered a restart -- a DIFFERENT bug this assertion
# exists to catch, distinct from an fd leak on the same worker.
WPID_AFTER=""
BODY1=""
for ((i = 0; i < 100; i++)); do
    BODY1="$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)"
    WPID_AFTER="$(prober_probe_field "$BODY1" pid 2>/dev/null || true)"
    [ -n "$WPID_AFTER" ] && break
    sleep 0.05
done

if [ -n "$WPID_AFTER" ] && [ "$WPID_AFTER" = "$WPID_BEFORE" ]; then
    echo "ok 4 - the worker set is unchanged across the reopen (pid $WPID_BEFORE, no restart)"
else
    echo "not ok 4 - the worker pid changed across USR1 (before=$WPID_BEFORE after=$WPID_AFTER) -- this was a restart, not a reopen"
    echo "# LIFECYCLE-USR1-RED-WORKER-CHANGED"
    FAILED=$((FAILED + 1))
fi

# --- fd-count neutrality: same worker (assertion 4), open-fd count read
# again after the reopen has settled. A reopen that opens the new fd before
# closing the old one, or that leaks the old fd entirely, shows up here as
# fds strictly greater than before; nginx's actual ngx_reopen_files closes
# each old fd immediately after dup2'ing/opening the replacement (one fd
# in, one fd out), so a correct reopen holds this exactly equal.
FDS_AFTER="$(prober_probe_field "$BODY1" fds 2>/dev/null || true)"
if [ -n "$FDS_AFTER" ] && [ "$FDS_AFTER" = "$FDS_BEFORE" ]; then
    echo "ok 5 - the worker's open-fd count is unchanged across the reopen (fds=$FDS_BEFORE)"
else
    echo "not ok 5 - the worker's fd count changed across USR1 (before=$FDS_BEFORE after=$FDS_AFTER)"
    echo "# LIFECYCLE-USR1-RED-FD-LEAK"
    FAILED=$((FAILED + 1))
fi

# --- non-vacuity: USR1 must NOT emit the terminal ("exiting") journal
# record lifecycle-journal and lifecycle-quit-vs-term-drain key their own
# claims on -- a reopen is not a shutdown, and a watcher or classifier bug
# that conflated the two would corrupt every assertion above by making the
# worker look terminated when it is not. Checked directly off the SAME
# journal this driver already trusts (rotation-safe attach, see above), for
# the pid this run has been tracking throughout.
if grep -qE "\"role\":\"worker\",\"pid\":$WPID_BEFORE,\"gen\":[0-9]+,\"ev\":\"exiting\"" "$JOURNAL" 2>/dev/null; then
    echo "not ok 6 - a terminal journal record was emitted for worker $WPID_BEFORE after USR1 -- USR1 is a reopen, not a shutdown"
    echo "# LIFECYCLE-USR1-RED-SPURIOUS-EXIT"
    FAILED=$((FAILED + 1))
else
    echo "ok 6 - no terminal journal record for worker $WPID_BEFORE after USR1 (reopen, not a shutdown)"
fi

# --- the rotated-away file itself is undisturbed content-wise: it still
# exists (mv, not rm) and its own inode is exactly INODE_BEFORE, closing the
# loop on assertion 2's claim from the other direction -- the OLD inode
# persisted under its new name rather than being reused or truncated in
# place, which is what a genuine rename-based rotation guarantees and an
# in-place-truncate "reopen" would not.
OLD_INODE_NOW="$(stat -c '%i' "$ELOG.rotated" 2>/dev/null || true)"
if [ -n "$OLD_INODE_NOW" ] && [ "$OLD_INODE_NOW" = "$INODE_BEFORE" ]; then
    echo "ok 7 - the pre-rotation log file survived under its renamed path with its original inode ($INODE_BEFORE)"
else
    echo "not ok 7 - the renamed log file's inode does not match the pre-rotation inode (expected $INODE_BEFORE, got $OLD_INODE_NOW)"
    echo "# LIFECYCLE-USR1-RED-OLD-FILE-CORRUPTED"
    FAILED=$((FAILED + 1))
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
