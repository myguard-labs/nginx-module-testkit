#!/usr/bin/env bash
#
# TAP self-test for the backend-plumbing half of lib.sh.
#
# render_conf_test.sh covers the renderer; this file covers the functions a
# scenario uses to stand a fake upstream up, tear it down, and judge whether it
# misbehaved. They are shell, they touch real sockets and a real daemon, and
# nothing else in this repo executes them -- the same gap that let @PREFIX@ go
# unsubstituted for the whole life of the scenario tree.
#
# fakesrv itself is proven by backend_test.c and fakesrv_test.sh. What is under
# test here is the lifecycle around it: that a missing script is fatal, that a
# port is read only once it is real, and that a dead backend is reported rather
# than absorbed.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=41
tests_run=0
failures=0

echo "1..$PLANNED"

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
    fi
}

diag() { printf '# %s\n' "$1"; }

# shellcheck source=lib.sh
. ./lib.sh

if [ ! -x ./fakesrv ]; then
    echo "Bail out! no fakesrv binary -- run ci/prober/build.sh first"
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lib_backend_test.XXXXXX")"

# ONE trap covering all three resources. A second `cleanup() { ... }` later in
# the file would silently REDEFINE this one rather than add to it, and whatever
# the first definition owned would leak on every run.
#
# Every command is guarded and the function ends in an explicit `return 0`. An
# EXIT trap's own status becomes the script's when it is the last thing to run,
# so a cleanup whose final command fails turns a fully passing suite red -- and
# it fails routinely here, because these tests kill the backend on purpose and
# `kill` on an already-reaped pid returns non-zero. This suite hit exactly that
# and reported exit 1 with every assertion green.
cleanup() {
    if [ -n "${PROBER_BACKEND_PID:-}" ]; then
        kill "$PROBER_BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "${LISTENER_PID:-}" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [ -n "${STUB_PID:-}" ]; then
        kill "$STUB_PID" 2>/dev/null || true
        wait "$STUB_PID" 2>/dev/null || true
    fi
    if [ -n "${VICTIM_PID:-}" ]; then
        kill "$VICTIM_PID" 2>/dev/null || true
        wait "$VICTIM_PID" 2>/dev/null || true
    fi
    if [ -n "${HANGSRV_PID:-}" ]; then
        kill "$HANGSRV_PID" 2>/dev/null || true
        wait "$HANGSRV_PID" 2>/dev/null || true
    fi
    if [ -n "${WORK:-}" ]; then
        rm -rf "$WORK" || true
    fi
    return 0
}
trap cleanup EXIT

# prober_backend_start writes into $PROBER_PREFIX, which the renderer normally
# creates. These tests do not render a conf, so stand one in directly.
PROBER_PREFIX="$WORK/prefix"
mkdir -p "$PROBER_PREFIX"

cat > "$WORK/ok.backend" <<'EOF'
proto   memcached
seed    hello  world
EOF

# A port nothing is listening on. Bound and released so the number is one the
# kernel just handed out, rather than a guess that some unrelated service on
# this host happens to be using -- which would turn the timeout assertions
# green for the wrong reason.
free_port() {
    local p
    p="$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
    printf '%s' "$p"
}

# ---------------------------------------------------------------- wait_listen

DEAD_PORT="$(free_port)"

if prober_wait_listen 127.0.0.1 "$DEAD_PORT" 200; then
    ok 1 "a closed port times out"
else
    ok 0 "a closed port times out"
fi

# The timeout must actually bound the call. A loop that retries forever, or one
# whose step is much larger than advertised, still satisfies the assertion
# above by eventually returning 1 -- so the useful claim is that it returns
# WITHIN a sane multiple of what was asked. Measured with SECONDS, whose
# granularity is fine for a 4x-of-500ms ceiling and which needs no date(1).
start=$SECONDS
prober_wait_listen 127.0.0.1 "$DEAD_PORT" 500 || true
elapsed=$(( SECONDS - start ))

if [ "$elapsed" -le 2 ]; then
    ok 0 "the timeout bounds the call instead of hanging"
else
    diag "prober_wait_listen 500ms took ${elapsed}s"
    ok 1 "the timeout bounds the call instead of hanging"
fi

# A listening port must be seen. Backgrounded so the listener exists while the
# wait runs; `nc` is deliberately avoided here for the reason in the header, so
# the listener is python3's socket module, already required by free_port.
LISTEN_PORT="$(free_port)"
python3 -c "import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $LISTEN_PORT))
s.listen(8)
time.sleep(5)" &
LISTENER_PID=$!


if prober_wait_listen 127.0.0.1 "$LISTEN_PORT" 3000; then
    ok 0 "a listening port is detected"
else
    ok 1 "a listening port is detected"
fi

# A listener that is already up must be reported without spending the timeout.
# This is what makes the function usable in a boot path: a wait that always
# costs its full budget turns every scenario start into a fixed stall.
start=$SECONDS
prober_wait_listen 127.0.0.1 "$LISTEN_PORT" 3000
elapsed=$(( SECONDS - start ))

if [ "$elapsed" -le 1 ]; then
    ok 0 "an already-listening port returns promptly"
else
    diag "detecting a live listener took ${elapsed}s"
    ok 1 "an already-listening port returns promptly"
fi

# A timeout shorter than one sleep step must still attempt a connect. Rounding
# the iteration count down would make this report "not listening" for a port
# that is -- the failure would only appear in a caller that passed a small
# budget, which is exactly where a readiness check is tuned.
if prober_wait_listen 127.0.0.1 "$LISTEN_PORT" 1; then
    ok 0 "a sub-step timeout still attempts one connect"
else
    ok 1 "a sub-step timeout still attempts one connect"
fi

# ------------------------------------------------------------ backend lifecycle
#
# prober_backend_start depends on prober_wait_listen, asserted above. Checked
# again as a function rather than assumed, so a refactor that renames it fails
# here by name instead of surfacing as an obscure failure three checks later.
if declare -F prober_wait_listen >/dev/null; then
    ok 0 "prober_wait_listen is available to the backend lifecycle"
else
    ok 1 "prober_wait_listen is available to the backend lifecycle"
fi

# --------------------------------------------------------------------- start

prober_backend_start "$WORK/ok.backend"

case "${PROBER_BACKEND_PORT:-}" in
    ''|*[!0-9]*)
        diag "port was \"${PROBER_BACKEND_PORT:-}\""
        ok 1 "_start publishes a numeric port" ;;
    0)  diag "port was 0 -- the portfile was read before it was written"
        ok 1 "_start publishes a numeric port" ;;
    *)  ok 0 "_start publishes a numeric port" ;;
esac

# The port must be one a client can actually reach. A published number that
# nothing is listening on is the failure the readiness wait exists to prevent,
# and it would otherwise surface as a connect error inside the module under
# test -- pointing at the module rather than at the harness.
if (exec 3<>"/dev/tcp/127.0.0.1/$PROBER_BACKEND_PORT") 2>/dev/null; then
    ok 0 "the published port is actually accepting"
else
    ok 1 "the published port is actually accepting"
fi

if [ -n "${PROBER_BACKEND_PID:-}" ] && kill -0 "$PROBER_BACKEND_PID" 2>/dev/null; then
    ok 0 "_start leaves a live pid behind"
else
    ok 1 "_start leaves a live pid behind"
fi

# The journal is the instrument several planned scenarios assert against (the
# keepalive-reuse proof reads its accept count), so its path must be published
# and the file must exist once a command has been served.
printf 'get hello\r\n' > /dev/tcp/127.0.0.1/"$PROBER_BACKEND_PORT" 2>/dev/null || true

if [ -n "${PROBER_BACKEND_JOURNAL:-}" ] && [ -f "$PROBER_BACKEND_JOURNAL" ]; then
    ok 0 "_start publishes a journal path and the daemon writes it"
else
    diag "journal: ${PROBER_BACKEND_JOURNAL:-<unset>}"
    ok 1 "_start publishes a journal path and the daemon writes it"
fi

# The port must be read only from a NON-EMPTY portfile. Asserted as a property
# of the source, not by racing the window: fakesrv writes the file
# tmp+fsync+rename, so the interval in which a reader could see it empty is
# microseconds wide and its width is a property of the HOST -- a test that must
# catch it passes on one runner and fails on another. s69 hit exactly this on
# the daemon's own `portfile written non-atomically` mutant, where a shell loop
# watching for an existing-but-empty file never won the race on CI, and the
# resolution was the same: assert the mechanism.
#
# `-e` instead of `-s` is the defect this pins. It accepts the file the instant
# rename() makes it visible, and a reader that then parses "" as a port
# connects to port 0 -- the 1-in-20 flake fakesrv.c:37 exists to prevent.
# shellcheck disable=SC2016  # a literal grep pattern, not a shell expansion
if grep -q 'if \[ -s "\$portfile" \]' lib.sh; then
    ok 0 "_start waits for a non-empty portfile, not merely an existing one"
else
    diag "the portfile wait does not test for non-empty (-s)"
    ok 1 "_start waits for a non-empty portfile, not merely an existing one"
fi

# --------------------------------------------------------------------- scrape
#
# A healthy backend, still running, must produce no finding. Asserted before
# the failure cases so a scrape that reports a finding unconditionally cannot
# masquerade as working detection below.
if prober_backend_scrape >/dev/null 2>&1; then
    ok 0 "_scrape is silent on a healthy backend"
else
    diag "scrape reported: $(prober_backend_scrape 2>&1 || true)"
    ok 1 "_scrape is silent on a healthy backend"
fi

# ----------------------------------------------------------------------- stop

prober_backend_stop

if kill -0 "$PROBER_BACKEND_PID" 2>/dev/null; then
    ok 1 "_stop actually reaps the daemon"
else
    ok 0 "_stop actually reaps the daemon"
fi

# A second _stop must be a no-op. run-scenario.sh's teardown can reach it twice
# -- once on the normal path and once from a trap -- and a cleanup that fails
# on its second call turns a passing scenario red during teardown.
if prober_backend_stop; then
    ok 0 "_stop is idempotent"
else
    ok 1 "_stop is idempotent"
fi

# ------------------------------------------------- scrape: the died-backend case
#
# The pid is now dead, so the scrape must report it. This is the finding that
# matters most: a scenario whose upstream vanished mid-run sees only connection
# errors from the module under test, which reads as a module bug.
if prober_backend_scrape >/dev/null 2>&1; then
    ok 1 "_scrape reports a backend that died"
else
    ok 0 "_scrape reports a backend that died"
fi

if PROBER_BACKEND_ALLOW_EXIT=1 prober_backend_scrape >/dev/null 2>&1; then
    ok 0 "PROBER_BACKEND_ALLOW_EXIT exempts a deliberate kill"
else
    ok 1 "PROBER_BACKEND_ALLOW_EXIT exempts a deliberate kill"
fi

# The opt-out is scoped to the exit, not a blanket off switch: an exempted
# backend that ALSO wrote an error must still be a finding. Without this the
# variable would silence the parse-error path too, and a scenario that kills
# its backend on purpose would stop reporting a malformed script.
printf 'fakesrv: something went wrong\n' > "$PROBER_PREFIX/backend.err"

if PROBER_BACKEND_ALLOW_EXIT=1 prober_backend_scrape >/dev/null 2>&1; then
    ok 1 "ALLOW_EXIT still reports an errfile finding"
else
    ok 0 "ALLOW_EXIT still reports an errfile finding"
fi

rm -f "$PROBER_PREFIX/backend.err"

# ------------------------------------------------ start: the missing-script case
#
# THE mutation gate for P1-B. A nonexistent script must bail, never boot
# backendless: a scenario that silently runs with no upstream passes every
# assertion that does not need one, under a name claiming otherwise. Run in a
# subshell so the bail's `exit 1` cannot take this script down.
if ( prober_backend_start "$WORK/nonesuch.backend" ) >/dev/null 2>&1; then
    ok 1 "_start bails on a nonexistent script instead of booting backendless"
else
    ok 0 "_start bails on a nonexistent script instead of booting backendless"
fi

# The bail must name the MISSING SCRIPT, and that is not pedantry about wording
# -- it is what makes the assertion above non-vacuous. With the existence check
# deleted, _start still exits non-zero a few lines later: fakesrv cannot read
# the script, dies, and the "exited before publishing a port" bail fires. A
# check that only asks "did it fail" therefore passes with the guard REMOVED,
# proving nothing about the case it is named for. Verified by mutation: this is
# the assertion that goes red, the one above stays green.
MISSING_MSG="$( ( prober_backend_start "$WORK/nonesuch.backend" ) 2>&1 || true )"

case "$MISSING_MSG" in
    *"Bail out!"*"no backend script at"*)
        ok 0 "the bail names the missing script, not a downstream symptom" ;;
    *)  diag "bail message was: $MISSING_MSG"
        ok 1 "the bail names the missing script, not a downstream symptom" ;;
esac

# --- prober_cleanup (P1-B4) ------------------------------------------------
#
# The status-preservation cases come first because they are the reason this
# function is written the way it is: an EXIT trap's own status becomes the
# script's, so a cleanup that clobbers $? turns a failing scenario green with
# every assertion in the TAP stream still reading ok. Asserting merely that
# cleanup "runs" would not catch that -- the VALUE is the claim.
#
# Each case runs in a SUBSHELL that seeds $? and exits with what cleanup
# returned. A bare `( exit N )` in this file would trip `set -e` and kill the
# script mid-plan -- and a truncated TAP stream reads as "the rest passed",
# which is the trap lessons.md already records twice.
# The seeded status is the LAST thing before the call, with nothing in
# between to reset it.
# `set -e` stays ON inside here, deliberately. run-scenario.sh runs under
# `set -euo pipefail`, so that is the shell prober_cleanup must survive: an
# unguarded command in it aborts the trap partway and never reaches the
# `return "$rc"`. A helper that relaxed to `set +e` would absorb exactly that
# failure and report the mutant as caught while the assertion never ran --
# the vacuous-gate mode this file already documents twice.
#
# The seeded status has to reach prober_cleanup INTACT, and `set -e` would
# abort on the seed itself. An EXIT trap is the one construct that gives both:
# it is how the real caller invokes cleanup anyway, and `exit N` sets $? to N
# without `set -e` intervening. So this mirrors production exactly.
cleanup_rc() (
    set -eo pipefail
    PROBER_BACKEND_PID="${2:-}"
    PROBER_SERVER_PID="${3:-}"
    PROBER_PREFIX="${4:-}"
    trap 'prober_cleanup; exit $?' EXIT
    exit "$1"
)

CLEAN_RC=0; cleanup_rc 7 || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 7 ]; then
    ok 0 "cleanup preserves a non-zero \$? through to its own return"
else
    diag "cleanup returned $CLEAN_RC, seeded 7"
    ok 1 "cleanup preserves a non-zero \$? through to its own return"
fi

CLEAN_RC=0; cleanup_rc 0 || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 0 ]; then
    ok 0 "cleanup preserves a zero \$? rather than inventing a failure"
else
    diag "cleanup returned $CLEAN_RC, seeded 0"
    ok 1 "cleanup preserves a zero \$? rather than inventing a failure"
fi

# A stale pid is the exact input that made B3's unguarded kill flip the
# suite's exit status.
CLEAN_RC=0; cleanup_rc 3 999999 999999 "" || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 3 ]; then
    ok 0 "an already-dead pid does not change the status cleanup returns"
else
    diag "cleanup returned $CLEAN_RC, seeded 3"
    ok 1 "an already-dead pid does not change the status cleanup returns"
fi

CLEAN_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober-cleanup.XXXXXX")"
PROBER_PREFIX="$CLEAN_PREFIX"
# Marked owned, as prober_make_prefix would: cleanup removes only what the
# harness created, so a hand-built prefix must claim ownership to stand in for
# a real one. The inherited (unowned) case is asserted separately below.
PROBER_PREFIX_OWNED=1
PROBER_BACKEND_PID=""
PROBER_SERVER_PID=""
prober_cleanup
if [ ! -d "$CLEAN_PREFIX" ]; then
    ok 0 "cleanup removes the prefix directory"
else
    ok 1 "cleanup removes the prefix directory"
fi

if [ -z "${PROBER_PREFIX:-}" ]; then
    ok 0 "cleanup clears the prefix handle so a second call cannot re-tear it"
else
    ok 1 "cleanup clears the prefix handle so a second call cannot re-tear it"
fi

# Idempotence is what lets the caller arm the trap before any resource exists
# and still run cleanup on the happy path.
CLEAN_RC=0; prober_cleanup || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 0 ]; then
    ok 0 "a second cleanup on cleared handles is a no-op, not an error"
else
    ok 1 "a second cleanup on cleared handles is a no-op, not an error"
fi

# --- prober_make_prefix (P1-B4) --------------------------------------------

PROBER_PREFIX=""
prober_make_prefix
MK_FIRST="$PROBER_PREFIX"
prober_make_prefix
if [ "$PROBER_PREFIX" = "$MK_FIRST" ] && [ -d "$MK_FIRST" ]; then
    ok 0 "make_prefix reuses an existing prefix instead of stranding it"
else
    ok 1 "make_prefix reuses an existing prefix instead of stranding it"
fi

# render_conf must accept the prefix the backend already populated, or the
# portfile and journal written into it would be orphaned by a second mktemp.
# The template is written here rather than reused from the tree: this repo
# ships no conf/ -- the template is consumer-supplied -- and prober_render_conf
# bails with `exit 1` on a missing one, which a sourced function's `|| true`
# cannot catch.
MK_TEMPLATE="$WORK/reuse.conf"
cat >"$MK_TEMPLATE" <<'CONF'
# listen @PORT@ in @PREFIX@, upstream @BACKEND_PORT@
CONF

PROBER_LOAD="" PROBER_RESOLVED_PORT=18099 PROBER_PROBE="" \
    prober_render_conf "$MK_TEMPLATE" >/dev/null 2>&1
if [ "$PROBER_PREFIX" = "$MK_FIRST" ]; then
    ok 0 "render_conf renders into the prefix make_prefix already created"
else
    diag "prefix moved: $MK_FIRST -> $PROBER_PREFIX"
    ok 1 "render_conf renders into the prefix make_prefix already created"
fi

rm -rf "$MK_FIRST"
PROBER_PREFIX=""

# --- prefix ownership (CodeRabbit #58, Major) -------------------------------
#
# PROBER_PREFIX can arrive from outside the harness: run-scenario.sh exports it
# to driver.sh, and a scenario's `env` file is sourced into the same shell. A
# cleanup that rm -rf's an inherited value destroys a directory the harness
# never created. Only a prefix we mktemp'd ourselves may be removed.

INHERITED="$(mktemp -d "${TMPDIR:-/tmp}/prober-inherited.XXXXXX")"
touch "$INHERITED/caller-data"

PROBER_PREFIX="$INHERITED"
PROBER_PREFIX_OWNED=""
PROBER_BACKEND_PID=""
PROBER_SERVER_PID=""
prober_cleanup

if [ -d "$INHERITED" ] && [ -f "$INHERITED/caller-data" ]; then
    ok 0 "cleanup does not delete a prefix the harness did not create"
else
    ok 1 "cleanup does not delete a prefix the harness did not create"
fi
rm -rf "$INHERITED"

# make_prefix must not claim ownership of a value it merely found.
PROBER_PREFIX="$INHERITED"
PROBER_PREFIX_OWNED=""
prober_make_prefix
if [ -z "${PROBER_PREFIX_OWNED:-}" ]; then
    ok 0 "make_prefix does not claim ownership of an inherited prefix"
else
    ok 1 "make_prefix does not claim ownership of an inherited prefix"
fi

PROBER_PREFIX=""
PROBER_PREFIX_OWNED=""
prober_make_prefix
OWNED_PREFIX="$PROBER_PREFIX"
if [ -n "${PROBER_PREFIX_OWNED:-}" ]; then
    ok 0 "make_prefix claims ownership of a prefix it created"
else
    ok 1 "make_prefix claims ownership of a prefix it created"
fi
prober_cleanup
rm -rf "$OWNED_PREFIX"

# --- scrape ordering (CodeRabbit #58, Major) --------------------------------
#
# prober_backend_scrape's liveness check asks whether the upstream survived the
# scenario -- its own message says "exited before teardown". Running it AFTER
# prober_backend_stop therefore sees the pid the stop just reaped and reports
# every backend scenario as failed. This asserts the ordering hazard directly,
# because no scenario in the tree ships a `backend` file yet and the
# integration path has no other coverage.

PROBER_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober-order.XXXXXX")"
PROBER_PREFIX_OWNED=1
prober_backend_start "$WORK/ok.backend"

SCRAPE_LIVE=0
prober_backend_scrape >/dev/null 2>&1 || SCRAPE_LIVE=$?
if [ "$SCRAPE_LIVE" -eq 0 ]; then
    ok 0 "scrape is silent while the backend is still running (pre-teardown)"
else
    diag "scrape returned $SCRAPE_LIVE against a live backend"
    ok 1 "scrape is silent while the backend is still running (pre-teardown)"
fi

prober_backend_stop
SCRAPE_DEAD=0
prober_backend_scrape >/dev/null 2>&1 || SCRAPE_DEAD=$?
if [ "$SCRAPE_DEAD" -ne 0 ]; then
    ok 0 "scrape after stop reports the reaped pid -- why run-scenario.sh scrapes first"
else
    ok 1 "scrape after stop reports the reaped pid -- why run-scenario.sh scrapes first"
fi

prober_cleanup

# run-scenario.sh must call the scrape before the stop. Asserting the source
# because the ordering is the whole claim and a wrong order fails only on a
# scenario type that does not exist in this repo yet.
SCRAPE_LINE="$(grep -n 'prober_backend_scrape' run-scenario.sh | head -1 | cut -d: -f1)"
STOP_LINE="$(grep -n '^prober_backend_stop' run-scenario.sh | head -1 | cut -d: -f1)"
if [ -n "$SCRAPE_LINE" ] && [ -n "$STOP_LINE" ] && [ "$SCRAPE_LINE" -lt "$STOP_LINE" ]; then
    ok 0 "run-scenario.sh scrapes the backend before stopping it"
else
    diag "scrape at line ${SCRAPE_LINE:-none}, stop at line ${STOP_LINE:-none}"
    ok 1 "run-scenario.sh scrapes the backend before stopping it"
fi

# ---- prober_probe_pid / prober_signal_wait ---------------------------------
#
# The signal helpers are exercised against a throwaway bash listener serving a
# canned probe body rather than against a real nginx. What is under test is the
# helpers' own logic -- does the pid get parsed out, does a wait that never
# sees a new worker time out instead of hanging, is a failed `before` read
# fatal rather than silently degrading. None of that needs a server, and
# requiring one would mean this file could not run without a build.
#
# The reload behaviour itself -- that a HUP really does swap the worker -- is
# not asserted here and cannot be: it belongs to the scenario that uses it.

# Serve a canned HTTP response to every connection, using fakesrv itself.
#
# Not nc(1): fakesrv_test.sh:13 records why this repo never depends on it --
# it is absent on some boxes and the openbsd/traditional/ncat variants take
# incompatible listen flags, so a suite built on it fails for reasons that have
# nothing to do with what it asserts. (Confirmed while writing this: the box it
# was first run on carries the traditional variant, whose `-l -p PORT` spelling
# differs from the one most examples use, and the stub silently never bound.)
#
# python3 instead, the same listener this file already uses for
# prober_wait_listen above -- no new dependency.
#
# Serves EVERY connection, not one: prober_signal_wait probes at least twice
# (once for the before-pid, then once per poll step), and a one-shot listener
# would make the second read fail for a reason the test is not about.
probe_stub_start() {
    local body="$1"

    STUB_PORT="$(free_port)"
    # The stub's accept loop must outlive the whole probe interaction: on a slow
    # emulated/loaded runner (qemu-s390x) prober_wait_listen polling, the
    # ghost-connect serve, and the real prober_probe_pid connect can together
    # exceed a fixed 10 s wall budget -- the accept() for the REAL probe then
    # times out and breaks the loop, so the probe reads an empty body and the
    # pid parse yields '' (the residual test-34 flake after the sendall guard).
    # Scale the budget off PROBER_PROBE_TIMEOUT (5x, floor 30 s) so it tracks the
    # same slow-host tunable the read bound already uses.
    local stub_deadline=$(( ${PROBER_PROBE_TIMEOUT:-2} * 5 ))
    [ "$stub_deadline" -lt 30 ] && stub_deadline=30
    python3 -c "import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $STUB_PORT))
s.listen(8)
deadline = time.time() + $stub_deadline
body = '''$body'''
reply = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s'
         % (len(body), body)).encode()
while time.time() < deadline:
    try:
        s.settimeout(max(0.1, deadline - time.time()))
        c, _ = s.accept()
    except OSError:
        break
    # The serve is fully guarded: prober_wait_listen probes this port by
    # completing a TCP handshake and closing IMMEDIATELY, so the FIRST accept()
    # here can hand back an already-closed peer. An unguarded sendall() to that
    # dead socket raises BrokenPipeError/OSError, which -- being outside the
    # accept try -- killed the whole stub. The real prober_probe_pid connection
    # that followed then found nothing serving and read an empty body FAST (not
    # a 124 timeout), so the pid parse yielded '' (the qemu-s390x test-34 flake).
    # Skip a dead peer and keep looping so the next (real) connection is served.
    # shutdown(SHUT_WR) before close() flushes the body and half-closes so the
    # peer drains it and sees a clean EOF rather than a race-truncated read.
    try:
        c.sendall(reply)
        try:
            c.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        c.close()" &
    STUB_PID=$!

    prober_wait_listen 127.0.0.1 "$STUB_PORT" 3000 || return 1
    return 0
}

probe_stub_stop() {
    if [ -n "${STUB_PID:-}" ]; then
        kill "$STUB_PID" 2>/dev/null || true
        wait "$STUB_PID" 2>/dev/null || true
        STUB_PID=
    fi
}

if true; then
    # Claim 1: the pid is parsed out of a real probe body. The format is the one
    # ngx_test_probe.c:203 actually emits (`"pid":%P` -- no space), not a guess.
    #
    # The expected value is drawn at RUN TIME rather than written as a literal.
    # A fixed constant here is answerable by a helper that returns that same
    # constant: the first version of this test used 424242 on both sides, and a
    # mutant hardcoding `printf 424242` passed it. The claim is that the body's
    # pid is READ, so the body must carry a number the helper cannot know.
    WANT_PID=$(( 100000 + RANDOM % 800000 ))
    if probe_stub_start "{\"fds\":7,\"pid\":$WANT_PID,\"conns\":1}"; then
        GOT="$(prober_probe_pid 127.0.0.1 "$STUB_PORT" || true)"
        probe_stub_stop
        if [ "$GOT" = "$WANT_PID" ]; then
            ok 0 "prober_probe_pid parses the pid out of a probe body"
        else
            diag "got '$GOT', want $WANT_PID"
            ok 1 "prober_probe_pid parses the pid out of a probe body"
        fi
    else
        diag "could not bind a stub listener"
        ok 1 "prober_probe_pid parses the pid out of a probe body"
    fi

    # Claim 2: a body with no pid field is a failure, not an empty string that a
    # caller would go on to compare against. prober_signal_wait's `before` read
    # depends on this being fatal.
    if probe_stub_start '{"fds":7,"conns":1}'; then
        if prober_probe_pid 127.0.0.1 "$STUB_PORT" >/dev/null 2>&1; then
            ok 1 "prober_probe_pid fails on a body with no pid"
        else
            ok 0 "prober_probe_pid fails on a body with no pid"
        fi
        probe_stub_stop
    else
        diag "could not bind a stub listener"
        ok 1 "prober_probe_pid fails on a body with no pid"
    fi

    # Claim 3: with nothing listening there is no `before` pid, so the wait must
    # fail WITHOUT signalling anything. Signalling first and then discovering it
    # cannot observe the result would leave a real master reloaded and the
    # caller told the reload did not happen.
    #
    # The signal target is a sacrificial sleep, NOT $$. An earlier version aimed
    # at the test's own pid and was safe only because the before-read fails
    # before the kill is reached -- which is the very thing under test. Mutating
    # that guard away made the suite HUP itself and hang, so the test's safety
    # depended on the absence of the bug it exists to catch. A separate victim
    # makes the failure observable instead of self-inflicted.
    #
    # The return value alone CANNOT carry this claim, and asserting on it was
    # the first version's mistake. Both the correct code (refuses to signal,
    # returns 1) and a broken one (signals anyway, polls a dead port, exhausts
    # the budget, returns 1) return exactly 1. A mutant removing the guard left
    # this test green -- it was checking that the call failed, never that the
    # signal was withheld.
    #
    # So observe the VICTIM instead. SIGTERM kills a sleep; if the helper
    # signalled despite having no before-pid, the victim is gone afterwards.
    # That is the claim, and nothing else in the call is sensitive to it.
    sleep 30 &
    VICTIM_PID=$!
    DEAD_PROBE_PORT="$(free_port)"

    prober_signal_wait TERM "$VICTIM_PID" 127.0.0.1 "$DEAD_PROBE_PORT" 200 2>/dev/null || true

    if kill -0 "$VICTIM_PID" 2>/dev/null; then
        ok 0 "prober_signal_wait does not signal when the before-pid is unreadable"
    else
        diag "the victim was signalled despite an unreadable before-pid"
        ok 1 "prober_signal_wait does not signal when the before-pid is unreadable"
    fi

    kill "$VICTIM_PID" 2>/dev/null || true
    wait "$VICTIM_PID" 2>/dev/null || true

    # Claim 4: a wait whose pid never changes times out and RETURNS -- it does
    # not hang.
    #
    # Run under timeout(1), NOT by measuring elapsed time after the fact. An
    # elapsed-time check can only be evaluated once the call has returned, so
    # against a genuinely unbounded wait it is never reached at all: the suite
    # hangs, the TAP stream stops mid-plan, and the run reports zero tests. A
    # mutant that removed the iteration bound produced exactly that -- rc=124,
    # ran=0/37, no failing assertion -- which is a DEAD GATE, not a kill. Under
    # timeout(1) the same mutant fails THIS assertion and the plan still
    # completes.
    #
    # 10s against a 200 ms budget: generous enough that a loaded runner is not
    # flaky, tight enough that an unbounded loop cannot pass.
    #
    # Same sacrificial victim as claim 3, and for the same reason: this wait
    # DOES reach the kill, so aiming it at $$ would signal the test script on
    # every run.
    if probe_stub_start '{"pid":424242}'; then
        sleep 30 &
        VICTIM_PID=$!

        # `|| WAIT_RC=$?` on the SAME command: a correct helper returns 1 here
        # (the wait is meant to time out), and under `set -e` an unguarded call
        # aborts the whole suite. That failure is silent in TAP -- the stream
        # simply stops, 36 tests pass, none fail, and only the planned-count
        # check at the end catches it.
        WAIT_RC=0
        # SC2016 is wrong here: the single quotes are the point. $1/$2/$3 are
        # the inner shell's positional parameters, supplied after the `_`, so
        # expanding them in THIS shell would substitute the outer values into
        # the program text instead of passing them as arguments.
        # shellcheck disable=SC2016
        timeout 10 bash -c '
            cd "$1" || exit 111
            . ./lib.sh
            prober_signal_wait CONT "$2" 127.0.0.1 "$3" 200
        ' _ "$PWD" "$VICTIM_PID" "$STUB_PORT" >/dev/null 2>&1 || WAIT_RC=$?

        kill "$VICTIM_PID" 2>/dev/null || true
        wait "$VICTIM_PID" 2>/dev/null || true
        probe_stub_stop

        # 124 is timeout(1) killing a hung call. Any other status means the
        # helper returned on its own, which is the claim.
        if [ "$WAIT_RC" -ne 124 ]; then
            ok 0 "prober_signal_wait returns on timeout rather than hanging"
        else
            diag "the wait did not return within 10s for a 200ms budget"
            ok 1 "prober_signal_wait returns on timeout rather than hanging"
        fi
    else
        diag "could not bind a stub listener"
        ok 1 "prober_signal_wait returns on timeout rather than hanging"
    fi
fi

# ---------------------------------------------------------------------------
# AUD-01: prober_cleanup must delete ONLY a prefix the harness created itself.
# run.sh once installed bare `rm -rf "$PROBER_PREFIX"` traps, so a caller who
# exported PROBER_PREFIX=/their/data had it recursively deleted on exit. The
# ownership-aware cleanup removes a prefix only when PROBER_PREFIX_OWNED is set,
# which prober_make_prefix sets exclusively for an mktemp prefix.

# A caller-supplied (unowned) prefix, with a sentinel file, must survive cleanup.
# SC2030/SC2031: the assignments are meant to be subshell-local -- the whole
# point is to exercise prober_cleanup against a scoped environment and leave the
# outer test state untouched.
# shellcheck disable=SC2030,SC2031
if (
    SENTINEL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aud01.XXXXXX")"
    touch "$SENTINEL_DIR/keepme"

    PROBER_PREFIX="$SENTINEL_DIR"
    PROBER_PREFIX_OWNED=""          # not owned: arrived from outside
    PROBER_SERVER_PID=""
    PROBER_BACKEND_PID=""

    prober_cleanup || true

    survived=0
    [ -f "$SENTINEL_DIR/keepme" ] || survived=1
    rm -rf "$SENTINEL_DIR" 2>/dev/null || true
    exit "$survived"
); then
    ok 0 "prober_cleanup leaves a caller-supplied prefix intact (AUD-01)"
else
    ok 1 "prober_cleanup leaves a caller-supplied prefix intact (AUD-01)"
fi

# A prefix the harness minted itself must be removed.
# shellcheck disable=SC2030,SC2031
if (
    unset PROBER_PREFIX PROBER_PREFIX_OWNED
    PROBER_SERVER_PID=""
    PROBER_BACKEND_PID=""

    prober_make_prefix                        # sets PROBER_PREFIX + _OWNED=1
    owned_path="$PROBER_PREFIX"
    [ -d "$owned_path" ] || exit 1

    prober_cleanup || true

    removed=0
    [ -d "$owned_path" ] && { removed=1; rm -rf "$owned_path"; }
    exit "$removed"
); then
    ok 0 "prober_cleanup removes an owned mktemp prefix (AUD-01)"
else
    ok 1 "prober_cleanup removes an owned mktemp prefix (AUD-01)"
fi

# ---- AUD-09: prober_probe_pid is bounded, not an infinite read --------------
#
# A probe endpoint that accepts the connection and then HOLDS it open -- never
# closing, never sending a full body -- used to hang prober_probe_pid's
# `cat <&3` forever. Because prober_signal_wait only advances its counted budget
# between calls, one such probe would freeze the whole reload wait and eat the
# CI job. The read is now `timeout`-bounded, so the call must RETURN (with a
# failure, since no pid can be extracted) in a few seconds, not hang.
#
# The fixture is a python3 server that accepts one connection and sleeps well
# past the 2 s probe bound. python3 is already required by the harness; if it is
# somehow absent, skip rather than bail so the suite still runs elsewhere.
if command -v python3 >/dev/null 2>&1; then
    fifo="$WORK/hangport.fifo"
    mkfifo "$fifo"
    # Linger must outlast the bound assertion below (probe timeout + slack) so a
    # genuine hang is still distinguishable from a bounded return. Scale it off
    # PROBER_PROBE_TIMEOUT: 5x the probe bound, floor 30 s. At the 2 s default
    # that is 30 s (the original literal); at 20 s (qemu-s390x) it is 100 s.
    hang_linger=$(( ${PROBER_PROBE_TIMEOUT:-2} * 5 ))
    [ "$hang_linger" -lt 30 ] && hang_linger=30
    python3 - "$fifo" "$hang_linger" <<'PY' &
import socket, sys, time
fifo = sys.argv[1]
linger = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(1)
with open(fifo, "w") as f:
    f.write(str(s.getsockname()[1]) + "\n")
    f.flush()
c, _ = s.accept()
time.sleep(linger)
PY
    HANGSRV_PID=$!   # tracked by the EXIT cleanup, so an early failure below
                     # cannot leak the python3 process for its linger sleep.

    # Bound the fifo read: if python3 dies before opening the fifo for write,
    # `head` on the reader side would block forever. `timeout` turns that into a
    # failed capture, and an empty hangport then fails the connect below rather
    # than hanging the suite.
    hangport="$(timeout 5 head -1 "$fifo" 2>/dev/null || true)"

    t0=$SECONDS
    if [ -n "$hangport" ] && prober_probe_pid 127.0.0.1 "$hangport" >/dev/null 2>&1; then
        probe_ok=0   # returned SUCCESS -- wrong, it should have failed
    else
        probe_ok=1   # returned FAILURE -- correct for a probe that never answered
    fi
    elapsed=$(( SECONDS - t0 ))

    kill "$HANGSRV_PID" 2>/dev/null || true
    wait "$HANGSRV_PID" 2>/dev/null || true
    HANGSRV_PID=""
    rm -f "$fifo"

    # The probe must FAIL (no pid extractable), not succeed. ok wants 0=pass, so
    # invert: pass this assertion exactly when the probe returned failure.
    if [ "$probe_ok" -eq 1 ]; then st=0; else st=1; fi
    ok "$st" "prober_probe_pid fails on a hung probe rather than succeeding (AUD-09)"

    # Bounded: the read must return within the probe timeout plus process/
    # scheduling slack, and well short of the 5*timeout the server holds the
    # connection open (line ~830). A genuine hang would blow past the server's
    # linger and never return. The bound tracks PROBER_PROBE_TIMEOUT rather than
    # a literal so raising the timeout for a slow emulated host (qemu-s390x)
    # does not turn this into a false failure: at the 2 s default the bound is
    # 12 s (matches the old literal-10 intent), at 20 s it is 30 s -- still far
    # below the 100 s linger, so a real hang is still distinguishable.
    probe_timeout=${PROBER_PROBE_TIMEOUT:-2}
    bound=$(( probe_timeout + 10 ))
    if [ "$elapsed" -lt "$bound" ]; then st=0; else st=1; fi
    ok "$st" "prober_probe_pid returns in bounded time on a hung probe (AUD-09)"
else
    diag "python3 absent -- skipping AUD-09 bounded-probe tests as passes"
    ok 0 "prober_probe_pid AUD-09 bound (skipped: no python3)"
    ok 0 "prober_probe_pid AUD-09 timing (skipped: no python3)"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
