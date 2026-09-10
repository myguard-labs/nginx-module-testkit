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
    local step_sleep=$1 out=$2 pidvar=$3 progress=${4:-} rcfile=${5:-}
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
            # Record how far the request has actually got, so the caller can
            # gate on WRITTEN BYTES rather than on this subshell merely
            # existing. `kill -0` is true from the instant the subshell is
            # forked, before /dev/tcp has connected and before a single header
            # byte has left the process; gating on it alone would let a
            # delayed connect pass while the upload had not started, making
            # the undisturbed-traffic claim vacuous. A non-zero offset here
            # proves the connection was established, the request line and
            # headers were accepted by nginx, and body bytes are flowing.
            #
            # It does NOT prove nginx has parsed those bytes -- that is not
            # observable client-side under proxy_request_buffering on, which
            # buffers the whole body before any upstream signal exists. The
            # gate claims exactly what it can see: the request is on the wire
            # and incomplete.
            # Published atomically: a plain truncating redirect would leave the
            # file momentarily empty, and the foreground gate reads it once
            # without retrying, so it would read that window as "no bytes
            # written" and fail a perfectly healthy upload. A rename within
            # the same directory swaps the value in one step, so a reader sees
            # either the old offset or the new one, never nothing.
            if [ -n "$progress" ]; then
                if printf '%s\n' "$off" >"$progress.tmp" 2>/dev/null; then
                    mv -f "$progress.tmp" "$progress" 2>/dev/null || true
                fi
            fi
            if [ "$off" -lt "$BODY_LEN" ] && [ "$step_sleep" != 0 ]; then
                sleep "$step_sleep"
            fi
        done

        # Bounded, because the failure this driver exists to detect is the
        # server NOT completing the request. An unbounded read would hang
        # rather than fail: run-scenario.sh invokes the driver directly and
        # test-scenarios.sh waits on scenario workers without a timeout, so
        # nothing upstream would cut it off and the "not ok" below would
        # never be reached. A timeout turns that hang into the failure it is.
        # The reader's exit status is RECORDED, not discarded. The assertion
        # below claims the upload completed "not cut, not stalled", and a
        # timeout (124) is exactly the stall it names: the server can emit the
        # 200 and UPLOADED bytes and then hang without finishing the response
        # or closing, and a grep over the captured bytes cannot tell that from
        # a clean completion. Only the read's own outcome can.
        reader_rc=0
        timeout 30 cat <&3 2>/dev/null || reader_rc=$?
        if [ -n "$rcfile" ]; then
            if printf '%s\n' "$reader_rc" >"$rcfile.tmp" 2>/dev/null; then
                mv -f "$rcfile.tmp" "$rcfile" 2>/dev/null || true
            fi
        fi
    ) >"$out" 2>/dev/null &
    printf -v "$pidvar" '%s' "$!"
}

echo "1..8"

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
UPLOAD_PROGRESS="$PROBER_PREFIX/upload-usr1.progress"
rm -f "$UPLOAD_PROGRESS"
# Accept baseline for the server-side half of the gate below. Deliberately a
# separate sample from FDS_BEFORE, which is the fd-NEUTRALITY baseline for
# assertion 5 and must keep its own sampling point.
ACC_FDS="$(prober_probe_field "$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)" fds 2>/dev/null || true)"
case "$ACC_FDS" in ''|*[!0-9]*) ACC_FDS=-1 ;; esac
UPLOAD_RC="$PROBER_PREFIX/upload-usr1.readerrc"
rm -f "$UPLOAD_RC"
start_upload "$STEP_SLEEP" "$UPLOAD_OUT" UPLOAD_PID "$UPLOAD_PROGRESS" "$UPLOAD_RC"

# Wait for the upload to be DEMONSTRABLY on the wire and still incomplete:
# some body bytes written, but fewer than all of them. Both halves matter --
# zero bytes means it has not started, and BODY_LEN bytes means it has already
# finished, and in either case USR1 would not land mid-request.
UPLOAD_OFF=""
for ((i = 0; i < 40; i++)); do   # 2s, well under the ~7.5s drip
    kill -0 "$UPLOAD_PID" 2>/dev/null || break
    UPLOAD_OFF="$( { tr -d '[:space:]' <"$UPLOAD_PROGRESS"; } 2>/dev/null )" || UPLOAD_OFF=""
    case "$UPLOAD_OFF" in
        ''|*[!0-9]*) ;;
        *) [ "$UPLOAD_OFF" -gt 0 ] && break ;;
    esac
    UPLOAD_OFF=""
    sleep 0.05
done

case "$UPLOAD_OFF" in ''|*[!0-9]*) UPLOAD_OFF=0 ;; esac

# SERVER-SIDE acceptance, the same evidence the QUIT/TERM driver requires. A
# successful client write proves only that the kernel buffered the bytes; if
# the worker has not yet accepted the queued connection when USR1 arrives it
# can reopen its logs first and handle the upload afterwards, and the
# undisturbed-traffic claim would never have crossed the reopen at all. An
# accepted connection is an extra descriptor the worker holds, so a count
# above the baseline is evidence from the server that it is handling this
# request. The baseline came through the same probe request, so the probe's
# own transient descriptor cancels out.
ACC_FDS_NOW=""
for ((i = 0; i < 40; i++)); do   # 2s, well under the ~7.5s drip
    kill -0 "$UPLOAD_PID" 2>/dev/null || break
    ACC_FDS_NOW="$(prober_probe_field "$(prober_probe_body "$HOST" "$PORT" 2>/dev/null || true)" fds 2>/dev/null || true)"
    case "$ACC_FDS_NOW" in
        ''|*[!0-9]*) ;;
        *) [ "$ACC_FDS_NOW" -gt "$ACC_FDS" ] && break ;;
    esac
    ACC_FDS_NOW=""
    sleep 0.05
done
case "$ACC_FDS_NOW" in ''|*[!0-9]*) ACC_FDS_NOW=-1 ;; esac

# Re-sample the offset: the probe loop above ran for up to two seconds while
# the upload kept writing, so the earlier value may describe an upload that
# has since finished its body. The gate must be about the moment USR1 is sent.
UPLOAD_OFF="$( { tr -d '[:space:]' <"$UPLOAD_PROGRESS"; } 2>/dev/null )" || UPLOAD_OFF=""
case "$UPLOAD_OFF" in ''|*[!0-9]*) UPLOAD_OFF=0 ;; esac

if [ "$UPLOAD_OFF" -gt 0 ] && [ "$UPLOAD_OFF" -lt "$BODY_LEN" ] \
   && [ "$ACC_FDS" -ge 0 ] && [ "$ACC_FDS_NOW" -gt "$ACC_FDS" ] \
   && kill -0 "$UPLOAD_PID" 2>/dev/null; then
    echo "ok 1 - the upload was still in flight immediately before USR1 ($UPLOAD_OFF of $BODY_LEN body bytes written; worker fds $ACC_FDS -> $ACC_FDS_NOW, so the worker has accepted it)"
else
    echo "not ok 1 - the upload was not in flight before USR1 ($UPLOAD_OFF of $BODY_LEN body bytes written; worker fds $ACC_FDS -> $ACC_FDS_NOW); the undisturbed-traffic claim below would be vacuous"
    echo "# LIFECYCLE-USR1-RED-NOT-INFLIGHT"
    FAILED=$((FAILED + 1))
fi

# --- rotate: rename the log away (the operator/logrotate half of the
# contract), THEN send USR1 (the "reopen at this path" half). Doing the
# rename ourselves, outside nginx, is exactly what real log rotation is --
# nginx's USR1 handler never renames anything itself, it only reopens
# whatever inode currently sits at the configured path.
# Snapshot the pre-rotation bytes so assertion 7 can check CONTENT survival,
# not merely inode identity. Taken immediately before the rename, so it is
# exactly what the rotated file must still begin with.
PRE_ROTATE_SNAPSHOT="$PROBER_PREFIX/elog-pre-rotate.snapshot"
cp -- "$ELOG" "$PRE_ROTATE_SNAPSHOT" 2>/dev/null || true
PRE_ROTATE_BYTES="$(stat -c '%s' "$PRE_ROTATE_SNAPSHOT" 2>/dev/null || echo 0)"

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

UPLOAD_READER_RC="$( { tr -d '[:space:]' <"$UPLOAD_RC"; } 2>/dev/null )" || UPLOAD_READER_RC=""
# Same framing check as the QUIT leg: the grep matches a body one byte short
# of its declared Content-Length, so "completed cleanly" needs the length
# measured, not a substring found.
UPLOAD_FRAMING="$(prober_http_body_complete "$UPLOAD_OUT")" && UPLOAD_FRAMING=""
if grep -q '^HTTP/1\.1 200' "$UPLOAD_OUT" 2>/dev/null && grep -q 'UPLOADED' "$UPLOAD_OUT" 2>/dev/null \
   && [ "$UPLOAD_READER_RC" = 0 ] && [ -z "$UPLOAD_FRAMING" ]; then
    echo "ok 3 - the in-flight upload completed cleanly across the reopen (not cut, not stalled; the whole declared body arrived and the response read ended at EOF, reader rc=0)"
else
    echo "not ok 3 - the in-flight upload did not complete cleanly across USR1 (reader rc=${UPLOAD_READER_RC:-unrecorded}; rc 124 means the response bytes arrived but the read then stalled to the 30s bound${UPLOAD_FRAMING:+; $UPLOAD_FRAMING})"
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

# --- non-vacuity: USR1 must NOT emit the terminal ("exiting") record that
# lifecycle-journal and lifecycle-quit-vs-term-drain key their own claims on
# -- a reopen is not a shutdown, and a watcher or classifier bug that
# conflated the two would corrupt every assertion above by making the worker
# look terminated when it is not.
#
# Read the ERROR LOG rather than $JOURNAL, for the pid this run has tracked
# throughout. This is a NEGATIVE assertion, and the journal is transcribed
# from the log by an asynchronous `tail -F` watcher subshell (lib.sh,
# prober_journal_start) whose own comment notes it is routinely still behind.
# Absence from the journal therefore conflates "no such record was written"
# (the claim) with "the watcher has not transcribed it yet" (an artefact) --
# and for a negative assertion the artefact direction makes it falsely GREEN,
# which is exactly the failure mode this assertion exists to rule out. Worse,
# the window straddles a rotation, so the watcher may be reattaching to the
# new inode precisely when a spurious record would land.
#
# nginx writes the log itself, synchronously and in order, so by the time the
# assertions above have observed the post-USR1 state any record nginx emitted
# is already in the file. Both surfaces name one event -- lib.sh keys on the
# anchored shape "<pid>#<slot>: exiting" -- so this asks the same question
# against the surface that can actually answer it. Both the rotated file and
# the reopened one are read: a spurious exit logged before the rename would
# otherwise be rotated out of view and silently pass.
if grep -qE "$WPID_BEFORE#[0-9]+: exiting$" "$ELOG" "$ELOG.rotated" 2>/dev/null; then
    echo "not ok 6 - a terminal log record was emitted for worker $WPID_BEFORE after USR1 -- USR1 is a reopen, not a shutdown"
    echo "# LIFECYCLE-USR1-RED-SPURIOUS-EXIT"
    FAILED=$((FAILED + 1))
else
    echo "ok 6 - no terminal log record for worker $WPID_BEFORE after USR1 (reopen, not a shutdown)"
fi

# --- the rotated-away file itself is undisturbed content-wise: it still
# exists (mv, not rm) and its own inode is exactly INODE_BEFORE, closing the
# loop on assertion 2's claim from the other direction -- the OLD inode
# persisted under its new name rather than being reused or truncated in
# place, which is what a genuine rename-based rotation guarantees and an
# in-place-truncate "reopen" would not.
#
# The inode alone does not state that claim: a "reopen" that truncated the
# file in place after the rename keeps the same inode while destroying every
# byte, and would pass an inode-only check. So the surviving CONTENT is
# checked too -- the rotated file must still BEGIN with the exact bytes the
# file held immediately before the rename. A prefix rather than an equality,
# because the worker may legitimately append a few more lines to its old
# descriptor in the window between the rename and its handling of USR1;
# appended bytes are consistent with the guarantee, altered or lost ones are
# not.
OLD_INODE_NOW="$(stat -c '%i' "$ELOG.rotated" 2>/dev/null || true)"
ROTATED_PREFIX_OK=0
if [ "$PRE_ROTATE_BYTES" -gt 0 ] 2>/dev/null &&
    [ "$(stat -c '%s' "$ELOG.rotated" 2>/dev/null || echo 0)" -ge "$PRE_ROTATE_BYTES" ] &&
    head -c "$PRE_ROTATE_BYTES" "$ELOG.rotated" 2>/dev/null |
        cmp -s - "$PRE_ROTATE_SNAPSHOT" 2>/dev/null; then
    ROTATED_PREFIX_OK=1
fi

if [ -n "$OLD_INODE_NOW" ] && [ "$OLD_INODE_NOW" = "$INODE_BEFORE" ] && [ "$ROTATED_PREFIX_OK" -eq 1 ]; then
    echo "ok 7 - the pre-rotation log file survived under its renamed path with its original inode ($INODE_BEFORE) and its $PRE_ROTATE_BYTES pre-rotation bytes intact"
elif [ "$OLD_INODE_NOW" != "$INODE_BEFORE" ]; then
    echo "not ok 7 - the renamed log file's inode does not match the pre-rotation inode (expected $INODE_BEFORE, got $OLD_INODE_NOW)"
    echo "# LIFECYCLE-USR1-RED-OLD-FILE-CORRUPTED"
    FAILED=$((FAILED + 1))
else
    echo "not ok 7 - the renamed log file kept inode $INODE_BEFORE but no longer begins with its $PRE_ROTATE_BYTES pre-rotation bytes -- it was truncated or rewritten in place"
    echo "# LIFECYCLE-USR1-RED-OLD-FILE-CORRUPTED"
    FAILED=$((FAILED + 1))
fi

# --- the WORKER, not just the master, is writing to the new inode.
# Assertions 2 and 7 prove the FILE was rotated and reopened, but both stat
# the path (or the renamed old path) -- neither observes which object the
# worker's own descriptor points at. That gap is not hypothetical: nginx
# reopens files in the master (ngx_reopen_files) and FORWARDS USR1 to each
# worker via ngx_signal_worker_processes. If that forwarding, or the worker's
# handling of it, regressed, the master would still create the new file --
# so inode-before != inode-after still holds -- while the worker kept its old
# descriptor and went on appending to the ROTATED inode. The pid (4), fd
# COUNT (5) and no-exit (6) assertions would all still pass, because none of
# them looks at what an fd points to. Every log line would silently land in
# the rotated-away file, which is precisely the bug a reopen test exists to
# catch.
#
# Read straight out of /proc/$WPID_BEFORE/fd: the worker runs as this same
# uid (no privilege separation in the testkit's prefix), so its descriptors
# are resolvable. Matched by INODE, not by path string -- a readlink target
# still reads "$ELOG" for a stale fd only until the rename, after which it
# shows "$ELOG.rotated"; comparing st_ino against INODE_AFTER states the
# claim directly and cannot be satisfied by a coincidental path spelling.
WORKER_LOG_INOS=""
for fd in /proc/"$WPID_BEFORE"/fd/*; do
    [ -e "$fd" ] || continue
    ino="$(stat -L -c '%i' "$fd" 2>/dev/null || true)"
    [ -n "$ino" ] || continue
    WORKER_LOG_INOS="$WORKER_LOG_INOS $ino"
done

# INODE_AFTER is empty when the reopened log never appeared at $ELOG (see
# assertion 2, which already reds this without exiting). WORKER_LOG_INOS
# always carries a leading space, so an empty INODE_AFTER turns the case
# pattern below into *"  "* (two spaces), which the padded subject
# " $WORKER_LOG_INOS " always contains -- printing a green assertion 8
# unconditionally, even on a failed reopen. Guard the empty case explicitly.
if [ -z "$INODE_AFTER" ]; then
    echo "not ok 8 - no post-reopen inode was ever observed (see assertion 2), so the worker's descriptor has nothing to match against"
    echo "# LIFECYCLE-USR1-RED-WORKER-STALE-FD"
    FAILED=$((FAILED + 1))
else
    case " $WORKER_LOG_INOS " in
        *" $INODE_AFTER "*)
            echo "ok 8 - the worker itself holds a descriptor on the reopened log (inode $INODE_AFTER), not the rotated-away one"
            ;;
        *)
            echo "not ok 8 - no descriptor of worker $WPID_BEFORE points at the reopened log (inode $INODE_AFTER); it is still writing to the rotated file"
            echo "# LIFECYCLE-USR1-RED-WORKER-STALE-FD"
            FAILED=$((FAILED + 1))
            ;;
    esac
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
