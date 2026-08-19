#!/usr/bin/env bash
#
# TAP self-test for prober_check_conf (lib.sh) -- the pre-boot gate that reads
# the RENDERED nginx.conf and bails when it cannot be driven by the pid oracle.
#
# Nothing else in this repo executes this function directly: it is exercised only
# as a side effect of booting a scenario, so a regression in it (a healthy conf
# wrongly bailed, or a gate silently lifted) would show up as a confusing boot
# failure far from the cause. Two properties are load-bearing and covered here:
#   - worker_processes != 1 bails BY DEFAULT (the strict pid oracle reads a
#     multi-worker server's per-request pid rotation as a crash), and
#   - PROBER_ALLOW_MULTIWORKER=1 lifts exactly that bail -- the opt-in the
#     multi-worker scenario carries in its env, for cases that use pid_may_change.
#   - daemon off; is required regardless of the worker opt-in.
#
# prober_check_conf calls `exit 1` on a bail, so every invocation here runs in a
# SUBSHELL: the exit status of the subshell is the gate's verdict, and the parent
# test process survives to make the next assertion.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=9
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

# shellcheck source=lib.sh
. ./lib.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/check_conf_test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# prober_check_conf reads "$PROBER_PREFIX/conf/nginx.conf"; stage a prefix with a
# conf directory and write each fixture into it in turn.
PROBER_PREFIX="$WORK/prefix"
mkdir -p "$PROBER_PREFIX/conf"
CONF="$PROBER_PREFIX/conf/nginx.conf"

# A single-worker, daemon-off conf: the shape every existing scenario ships and
# the gate must accept unconditionally.
write_conf() { printf '%s\n' "$@" >"$CONF"; }

# ---- the happy path: one worker, daemon off ---------------------------------
write_conf 'daemon off;' 'worker_processes 1;'
( PROBER_PREFIX="$PROBER_PREFIX" prober_check_conf ) >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "one worker + daemon off passes the gate"

# ---- multi-worker bails by default ------------------------------------------
# The core regression guard: without the opt-in, worker_processes 4 must bail, or
# the multi-worker scenario would have booted into a wall of false pid failures
# all along (which is exactly the state its requires-skip was papering over).
write_conf 'daemon off;' 'worker_processes 4;'
( PROBER_PREFIX="$PROBER_PREFIX" prober_check_conf ) >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "worker_processes 4 bails by default"

# ---- the opt-in lifts exactly that bail -------------------------------------
# Same conf, PROBER_ALLOW_MULTIWORKER=1 set: the gate must now pass. Paired with
# the case above so neither is vacuous -- if the opt-in did nothing the two would
# disagree, and if the gate ignored the worker count both would pass.
( PROBER_PREFIX="$PROBER_PREFIX" PROBER_ALLOW_MULTIWORKER=1 prober_check_conf ) \
    >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "PROBER_ALLOW_MULTIWORKER=1 lets worker_processes 4 past the gate"

# ---- daemon off is still required, opt-in or not ----------------------------
# The worker opt-in must not become a blanket "skip the gate": a conf missing
# daemon off; still bails even with PROBER_ALLOW_MULTIWORKER=1, because the two
# checks guard different failure modes.
write_conf 'worker_processes 4;'
( PROBER_PREFIX="$PROBER_PREFIX" PROBER_ALLOW_MULTIWORKER=1 prober_check_conf ) \
    >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "a conf lacking daemon off; still bails even with the multiworker opt-in"

# ---- the opt-in does not weaken the single-worker default -------------------
# Setting PROBER_ALLOW_MULTIWORKER=1 on a one-worker conf is a harmless no-op,
# not an error: the gate's worker check only fires above 1.
write_conf 'daemon off;' 'worker_processes 1;'
( PROBER_PREFIX="$PROBER_PREFIX" PROBER_ALLOW_MULTIWORKER=1 prober_check_conf ) \
    >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "the multiworker opt-in is a no-op on a single-worker conf"

# ---- daemon-on opt-in: accepts daemon on; + a matching pidfile --------------
# PROBER_DAEMON_MODE=on inverts the daemon gate for the USR2 scenario. The happy
# path is a conf that says daemon on; AND writes its pidfile to the prefix the
# gate reads ($PROBER_PREFIX/nginx.pid) -- the path prober_boot adopts the
# master from.
write_conf 'daemon on;' 'worker_processes 1;' "pid $PROBER_PREFIX/nginx.pid;"
( PROBER_PREFIX="$PROBER_PREFIX" PROBER_DAEMON_MODE=on prober_check_conf ) \
    >/dev/null 2>&1 && s=0 || s=$?
ok "$s" "PROBER_DAEMON_MODE=on accepts daemon on; with a prefix pidfile"

# ---- daemon-on opt-in still requires daemon on; -----------------------------
# Paired with the case above: opting in does not skip the daemon check, it
# INVERTS it. A conf that opts in but stays daemon off; would ignore the USR2
# upgrade (the whole reason the opt-in exists), so it must bail -- not pass, and
# not fall through to the daemon-off branch.
write_conf 'daemon off;' 'worker_processes 1;' "pid $PROBER_PREFIX/nginx.pid;"
( PROBER_PREFIX="$PROBER_PREFIX" PROBER_DAEMON_MODE=on prober_check_conf ) \
    >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "PROBER_DAEMON_MODE=on bails when the conf is still daemon off;"

# ---- daemon-on opt-in requires the pidfile at the read path -----------------
# Teardown reads the master pid from $PROBER_PREFIX/nginx.pid because a
# daemonized master is not $!. A conf that says daemon on; but puts its pidfile
# elsewhere (or nowhere) leaves teardown with no master to kill, so it must bail.
write_conf 'daemon on;' 'worker_processes 1;' 'pid /somewhere/else.pid;'
( PROBER_PREFIX="$PROBER_PREFIX" PROBER_DAEMON_MODE=on prober_check_conf ) \
    >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "PROBER_DAEMON_MODE=on bails when the pidfile is not at the read path"

# ---- the daemon-on opt-in does not leak into a default (daemon-off) run -----
# A daemon on; conf without the opt-in must STILL bail on the default daemon-off
# gate: the inversion is scoped to PROBER_DAEMON_MODE=on and nothing else turns
# it on. This is the counterpart to the multiworker no-op case above.
write_conf 'daemon on;' 'worker_processes 1;' "pid $PROBER_PREFIX/nginx.pid;"
( PROBER_PREFIX="$PROBER_PREFIX" prober_check_conf ) >/dev/null 2>&1 && s=0 || s=$?
ok "$((s != 0 ? 0 : 1))" "daemon on; still bails without the PROBER_DAEMON_MODE opt-in"

# ---- plan reconciliation ----------------------------------------------------
if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
