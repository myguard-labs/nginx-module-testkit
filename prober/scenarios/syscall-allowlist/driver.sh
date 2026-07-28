#!/usr/bin/env bash
#
# Scenario: the request path's syscall SURFACE. Every other scenario asserts on
# what the server RETURNS -- status, body, fd deltas, log lines. This one asserts
# on HOW it got there: the set of syscalls the worker issues while answering a
# burst of ordinary requests. A module that quietly starts calling getrandom,
# opening a file, spawning a socket, or exec-ing a helper changes that set, and
# a consumer should have to acknowledge the new capability (by editing
# baseline.syscalls) rather than have it slip in unremarked.
#
# INSTRUMENT. strace -f -c ATTACHES to the already-running worker (ptrace, no
# rebuild, no LD_PRELOAD), counts syscalls across a fixed burst of probe
# requests, then detaches. The `-c` summary's last column is the syscall name;
# the union of those names is the observed set. The gate: every observed name
# must appear in baseline.syscalls, or the run is red. It is one-directional --
# a baseline name NOT observed is fine (allowlist, not fingerprint) -- so it does
# not flake on a kernel that satisfies an epoll from cache or coalesces a write.
#
# WHY ATTACH, NOT BOOT-WRAP. Wrapping the boot in strace would fold nginx's
# startup syscalls (open the conf, the logs, the shared libs, map them) into the
# set -- a large, version-variable surface that has nothing to do with the
# request path under test. Attaching to the worker AFTER boot and firing
# requests isolates exactly the per-request surface, which is both the stable
# thing to baseline and the thing a module actually influences.
#
# WHY A DRIVER, NOT A .rule. The prober speaks HTTP; it has no notion of
# attaching a tracer to the server it is probing or diffing a syscall set. This
# is server-side introspection the rule DSL cannot express.
#
# CROSS-VERSION STABILITY. The observed set on a bare request path is small and
# stable across nginx mainline, stable, and angie: accept4/close for the
# connection, epoll_ctl/epoll_wait for readiness, recvfrom for the request,
# write/writev for the response, setsockopt for per-connection options. The near
# neighbours a different kernel/libc can substitute (accept, epoll_pwait, recv,
# read, send/sendto) are pre-listed in baseline.syscalls so a benign
# substitution is not mistaken for a new capability.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ALLOWLIST="$PROBER_SCENARIO/baseline.syscalls"
STRACE_OUT="$PROBER_PREFIX/logs/syscall.strace"

export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

# FAILED accumulates every failing assertion; the scenario verdict is the EXIT
# STATUS, so a `not ok` that did not also raise it would be vacuous.
FAILED=0

# --- preconditions -------------------------------------------------------
#
# A precondition that is not met SKIPs the whole scenario the harness-native way:
# a lone `1..0 # SKIP <reason>` plan line, which test-scenarios.sh renders as
# `ok N - <scenario> # SKIP <reason>` (same idiom as run-scenario.sh's requires
# gate). The real `1..2` plan is emitted only once every precondition holds, so a
# skipped leg reports as SKIPPED, not as two vacuous passes.
#
# A sanitizer-instrumented server pollutes the request-path syscall set with the
# runtime's own calls -- ASan maps its shadow and services allocations lazily,
# so the worker issues an `mmap` (and can issue more, version-dependently) while
# answering a probe that the bare build never makes. That is the sanitizer's
# surface, not the module's; gating it here would either flake or force us to
# widen baseline.syscalls with runtime noise that dulls the gate on every OTHER
# leg. The syscall surface is only a meaningful contract on an uninstrumented
# binary, so on a sanitizer build this scenario SKIPs -- the same
# environment-fact contract as strace being absent or ptrace being restricted.
# Detected with the same `__asan_`/`__ubsan_` binary scan lib.sh uses to decide
# whether MALLOC_CHECK_ is safe to set.
if grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
    echo "1..0 # SKIP sanitizer build: runtime pollutes the request-path syscall set"
    exit 0
fi

# strace attach needs ptrace permission. On a box with yama ptrace_scope>=2 a
# non-root attach to a same-uid child is still allowed; scope==3 forbids ptrace
# outright. Rather than fail there -- an environment fact, not a server bug --
# the scenario SKIPs, the same contract the requires-gate uses. (This is a
# belt-and-braces check: run-scenario also honours a requires gate, but the
# attach can only be truly proven by attempting it.)
if ! command -v strace >/dev/null 2>&1; then
    echo "1..0 # SKIP strace not installed"
    exit 0
fi

# Being installed is not the same as being able to ATTACH. A hardened container
# (a restrictive seccomp profile, no CAP_SYS_PTRACE, yama ptrace_scope>=2) lets
# strace run but denies the PTRACE_SEIZE the -p attach needs -- observed on
# GitHub's scenario runners: "ptrace(PTRACE_SEIZE, ...): Operation not
# permitted". That is an environment fact, not a server bug, so the scenario
# SKIPs there rather than reporting a false failure -- the same contract as
# strace being absent. Preflight it against a throwaway short-lived child so the
# decision does not depend on racing the real worker: sleep briefly, attach, and
# check strace's own stderr for the permission error. `command -v strace`
# already passed, so a failure here is specifically the ptrace-attach capability.
_pf_err="$PROBER_PREFIX/logs/strace-preflight.err"
sleep 2 &
_pf_pid=$!
strace -e trace=none -p "$_pf_pid" -o /dev/null 2>"$_pf_err" &
_pf_strace=$!
# Give strace a moment to either attach or fail, then tear both down.
sleep 0.5
kill -INT "$_pf_strace" 2>/dev/null || true
wait "$_pf_strace" 2>/dev/null || true
kill "$_pf_pid" 2>/dev/null || true
wait "$_pf_pid" 2>/dev/null || true
if grep -qiE 'operation not permitted|ptrace|could not attach|permission denied' "$_pf_err"; then
    _pf_reason="$(tr -d '\r' <"$_pf_err" | grep -iE 'not permitted|ptrace|attach|denied' | head -1)"
    echo "1..0 # SKIP strace cannot attach (ptrace restricted): ${_pf_reason:-permission denied}"
    exit 0
fi

# Every precondition holds: from here the scenario runs its two real assertions.
echo "1..2"

# The worker, not the master: the master accepts no connections and answers no
# probe, so its syscall set is a boot-and-signal surface, not the request path.
# prober_probe_pid returns the pid that actually answered a probe -- the worker.
WORKER="$(prober_probe_pid "$HOST" "$PORT" || true)"
if [ -z "${WORKER:-}" ] || ! kill -0 "$WORKER" 2>/dev/null; then
    echo "Bail out! could not resolve a live worker pid to trace"
    exit 1
fi

# --- capture -------------------------------------------------------------
#
# Attach with -f so a worker that (unexpectedly) forks is followed; -c to emit
# the summary table only. strace runs in the background attached to the worker;
# we fire the burst, then SIGINT strace so it detaches cleanly and flushes its
# summary. `strace: Process N attached` on stderr is the handshake -- wait for
# the trace to actually be in place before generating load, or the first
# requests race the attach and their syscalls are missed.
: >"$STRACE_OUT"
strace -f -e trace=all -c -p "$WORKER" -o "$STRACE_OUT" 2>"$STRACE_OUT.err" &
STRACE_PID=$!

# Wait for the attach handshake rather than sleeping a fixed interval.
ATTACHED=0
for _i in $(seq 1 50); do
    if grep -q 'attached' "$STRACE_OUT.err" 2>/dev/null; then
        ATTACHED=1
        break
    fi
    if ! kill -0 "$STRACE_PID" 2>/dev/null; then
        echo "Bail out! strace exited before attaching:"
        sed 's/^/# /' "$STRACE_OUT.err"
        exit 1
    fi
    sleep 0.1
done

# Do NOT fire the burst until the attach is CONFIRMED. If the handshake window
# expired while strace is still alive but not yet attached, a late attach would
# observe only the tail of the request path (or none of it), and the gate would
# read that truncated -- necessarily subset -- syscall set as green. An unproven
# attach is a timing/environment fault, so tear strace down and bail rather than
# trace nothing.
if [ "$ATTACHED" -ne 1 ]; then
    kill -INT "$STRACE_PID" 2>/dev/null || true
    wait "$STRACE_PID" 2>/dev/null || true
    echo "Bail out! strace did not confirm attach within the handshake window:"
    sed 's/^/# /' "$STRACE_OUT.err"
    exit 1
fi

# A fixed burst -- enough requests that the full per-request surface is exercised
# (accept, read, write, close on each), few enough to stay fast. Count is not
# asserted on; only the set of names is. Each request goes to /__probe, the
# location wired to the MODULE handler: a burst to a `return 200` location would
# exercise only nginx core and never touch the syscalls a module makes.
#
# Over /dev/tcp (bash's own client), not curl -- the same client lib.sh uses, so
# the scenario carries no dependency the rest of the harness does not already
# have. Read to EOF (Connection: close) so each exchange completes -- accept
# through close -- before the next, keeping the per-request surface intact.
for _r in $(seq 1 20); do
    if exec 3<>"/dev/tcp/$HOST/$PORT"; then
        # trap '' PIPE + a `timeout`-bounded read, the load-bearing pattern
        # lib.sh uses on this same transport: a `Connection: close` server can
        # reply and close BEFORE it finishes reading the request, so the write
        # can take SIGPIPE (fatal under set -e) and the read can block forever if
        # the peer stalls. Guard both so a burst iteration cannot kill the driver
        # or hang it.
        (trap '' PIPE
         printf 'GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null) || true
        timeout "${PROBER_PROBE_TIMEOUT:-2}" cat <&3 >/dev/null 2>&1 || true
        exec 3>&- 3<&- || true
    fi
done

# Detach: SIGINT makes strace print its summary and exit 0. Give the summary a
# moment to flush before reading the file.
kill -INT "$STRACE_PID" 2>/dev/null || true
wait "$STRACE_PID" 2>/dev/null || true

# --- extract the observed set --------------------------------------------
#
# The -c summary is a table whose last column is the syscall name, after two
# header rows and a `------` separator, ending at a `total` row. Take the last
# whitespace-delimited field of the data rows, dropping the header/separator/
# total lines. Anything with a non-identifier name (the ruler) is filtered by
# the [a-z] guard.
OBSERVED="$(awk '
    /^[[:space:]]*-+/ { next }
    /% time/          { next }
    /total/           { next }
    NF >= 2 && $NF ~ /^[a-z][a-z0-9_]*$/ { print $NF }
' "$STRACE_OUT" | sort -u)"

if [ -z "$OBSERVED" ]; then
    echo "not ok 1 - strace captured no syscalls (attach raced the burst?)"
    echo "# strace summary:"
    sed 's/^/# /' "$STRACE_OUT"
    echo "# strace stderr:"
    sed 's/^/# /' "$STRACE_OUT.err"
    FAILED=1
    # Still emit test 2's line so the plan count holds.
    echo "not ok 2 - no observed set to check against the allowlist"
    exit "$FAILED"
fi

# Non-vacuity: a capture of ONLY the worker's idle loop -- epoll_wait and friends,
# all allowlisted -- would sail through the allowlist gate having observed nothing
# of the request path, which is the entire surface this scenario exists to check.
# That happens whenever the burst does not actually reach the traced worker: it
# exited, a replacement worker (strace is pinned to one pid) served the load, or
# every /dev/tcp connect failed silently (all ignored above). Require positive
# proof the request path itself was traced -- an accept, a read, and a write must
# each appear in the observed set, via any of the near-neighbours the header
# documents. Missing any group, the trace is not of a served request; that is a
# red, not a vacuous green.
# Herestring, not a pipe: -q exits on first match and can break the writer.
_witnessed() { grep -qxE "$1" <<<"$OBSERVED"; }
MISSING=""
_witnessed 'accept4|accept'                     || MISSING="$MISSING accept"
_witnessed 'recvfrom|recvmsg|recv|read'         || MISSING="$MISSING read"
_witnessed 'write|writev|send|sendto|sendmsg'   || MISSING="$MISSING write"
if [ -n "$MISSING" ]; then
    echo "not ok 1 - request path not traced on the worker (missing:$MISSING)"
    echo "# the burst did not reach the traced worker; observed set:"
    printf '%s\n' "$OBSERVED" | sed 's/^/#   /'
    FAILED=1
    echo "not ok 2 - no request-path trace to check against the allowlist"
    exit "$FAILED"
fi
echo "ok 1 - traced the request path on the worker (accept+read+write present)"

# --- the allowlist gate --------------------------------------------------
#
# Load the allowlist (one name per line, # and blanks stripped) into a set, then
# report every OBSERVED name absent from it. A single unknown syscall fails the
# scenario and is named in the TAP diagnostics so a consumer knows exactly which
# capability to acknowledge.
ALLOWED="$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$ALLOWLIST" | grep -E '^[a-z][a-z0-9_]*$' | sort -u || true)"
if [ -z "$ALLOWED" ]; then
    echo "not ok 2 - allowlist $ALLOWLIST is empty or unreadable"
    exit 1
fi

UNKNOWN=""
while IFS= read -r sc; do
    [ -n "$sc" ] || continue
    if ! grep -qxF "$sc" <<<"$ALLOWED"; then
        UNKNOWN="${UNKNOWN:+$UNKNOWN }$sc"
    fi
done <<<"$OBSERVED"

if [ -n "$UNKNOWN" ]; then
    echo "not ok 2 - request path made syscalls not in the allowlist: $UNKNOWN"
    echo "# observed set:"
    # shellcheck disable=SC2001
    echo "$OBSERVED" | sed 's/^/#   /'
    echo "# if this is an intended new capability, add it to baseline.syscalls"
    FAILED=1
else
    echo "ok 2 - every request-path syscall is in the allowlist"
fi

exit "$FAILED"
