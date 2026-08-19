#!/usr/bin/env bash
#
# TAP self-test for `prober --check`.
#
# The rule parser itself is covered by rules_test.c. What that cannot reach is
# the CLI wiring: that --check actually routes into load_rules(), that it exits
# on the parse verdict rather than the run's, and -- the load-bearing property
# -- that it never opens a connection. A --check that quietly fell through to
# the request loop would hang or fail against a host with no server on it, and
# a --check that skipped the parser would report every rule file as valid.
#
# No server is booted, which is the point: every case here must pass with
# nothing listening on the prober's default port.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=18
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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

./build.sh >/dev/null

# ---- a valid rule file ------------------------------------------------------

cat >"$WORK/good.rule" <<'EOF'
name    a well-formed case
from    127.0.0.1
send    GET / HTTP/1.1\r\n
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
EOF

# Nothing is listening on the default port. A --check that reached the request
# loop would fail or block here, so a clean exit is itself the evidence that it
# did not connect.
out="$(./prober --check "$WORK/good.rule" 2>&1)" && status=0 || status=$?
ok "$status" "--check exits 0 on a valid rule file with no server running"

case "$out" in
    *"1 cases parsed"*) ok 0 "--check reports the parsed case count" ;;
    *) ok 1 "--check reports the parsed case count (got: $out)" ;;
esac

case "$out" in
    *"1.."*) ok 1 "--check emits no TAP plan (got: $out)" ;;
    *) ok 0 "--check emits no TAP plan" ;;
esac

# ---- malformed input --------------------------------------------------------

cat >"$WORK/unknown.rule" <<'EOF'
name    a case with a bogus directive
frobnicate 1
EOF

./prober --check "$WORK/unknown.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "--check exits nonzero on an unknown directive"

# A cross-directive guard, not a syntax error: every line parses, but the case
# asserts on a response that a reset connection will never produce. This is the
# class of defect --check exists to catch before a run burns a server boot.
cat >"$WORK/semantic.rule" <<'EOF'
name    abort with a response assertion
from    127.0.0.1
send    GET / HTTP/1.1\r\n
abort   5
expect_not body~oops
EOF

out="$(./prober --check "$WORK/semantic.rule" 2>&1)" && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "--check rejects abort carrying a response expectation"

case "$out" in
    *"no response to assert on"*)
        ok 0 "--check explains why the abort case was rejected" ;;
    *)
        ok 1 "--check explains why the abort case was rejected (got: $out)" ;;
esac

./prober --check "$WORK/does-not-exist.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "--check exits nonzero on an unopenable rule file"

# ---- close deadline vs the read timeout -------------------------------------
#
# The parser caps expect_close_within at a compile-time constant, but the read
# timeout is a RUNTIME value (-t), so the two can only be compared here. A
# deadline at or past the timeout is unfalsifiable: the read gives up first and
# the case reports a timeout whatever the server did. Checked through the CLI
# because that is the only place both numbers exist.

cat > "$WORK/deadline.rule" <<'RULE'
name t
send GET / HTTP/1.1\r\nConnection: close\r\n\r\n
expect_close_within 8000
RULE

out="$(./prober --check "$WORK/deadline.rule" 2>&1)" && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" \
   "--check rejects a close deadline past the default read timeout"

case "$out" in
    *"could never fail"*)
        ok 0 "--check explains why the close deadline was rejected" ;;
    *)
        ok 1 "--check explains why the close deadline was rejected (got: $out)" ;;
esac

# ...and the SAME file is accepted once -t is raised above it. Without this the
# test above would still pass if the guard rejected every deadline outright,
# which would make the directive unusable rather than merely bounded.
./prober --check -t 9000 "$WORK/deadline.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 0 : 1))" \
   "the same deadline is accepted when -t is raised above it"

# The same runtime comparison for the idle wait, which answers to -t for a
# different reason: the wait polls, so it is not truncated by the read timeout
# and stays falsifiable -- but a case that parks longer than the per-request
# budget stalls the run somewhere the operator has no reason to look.

cat > "$WORK/idle.rule" <<'RULE'
name t
send GET / HTTP/1.1\r\nConnection: close\r\n\r\n
expect_idle 8000
RULE

out="$(./prober --check "$WORK/idle.rule" 2>&1)" && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" \
   "--check rejects an idle wait past the default read timeout"

case "$out" in
    *"outlast the per-request budget"*)
        ok 0 "--check explains why the idle wait was rejected" ;;
    *)
        ok 1 "--check explains why the idle wait was rejected (got: $out)" ;;
esac

./prober --check -t 9000 "$WORK/idle.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 0 : 1))" \
   "the same idle wait is accepted when -t is raised above it"

# An idle wait carrying a response expectation is rejected at load time: the
# wait never reads, so `expect` would assert against an empty buffer and
# `expect_not` would pass having looked at nothing.

cat > "$WORK/idle-expect.rule" <<'RULE'
name t
send GET / HTTP/1.1\r\nConnection: close\r\n\r\n
expect_idle 200
expect status=200
RULE

out="$(./prober --check "$WORK/idle-expect.rule" 2>&1)" && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" \
   "--check rejects an idle wait carrying a response expectation"

# ---- AUD-08: an empty plan is a false green in a normal run -----------------
#
# load_rules() can legitimately yield zero cases (a blank or comment-only file,
# a glob that matched files carrying no case). A normal run then printed `1..0`
# and exited 0 -- a passing suite that asserted nothing. --check must still
# report the zero informationally; a normal run must die.

cat >"$WORK/empty.rule" <<'EOF'
# a rule file with nothing but a comment
EOF

# Normal run (no --check, nothing listening): must die BEFORE any 1..0 plan or
# connection attempt, so the exit status is the empty-plan verdict, not a
# connection failure.
out="$(./prober "$WORK/empty.rule" 2>&1)" && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "a comment-only rule file fails a normal run (AUD-08)"

case "$out" in
    *"empty plan"*) ok 0 "the empty-plan failure names the cause (AUD-08)" ;;
    *) ok 1 "the empty-plan failure names the cause (got: $out)" ;;
esac

case "$out" in
    *"1..0"*) ok 1 "a failed empty run emits no 1..0 plan (got: $out)" ;;
    *) ok 0 "a failed empty run emits no 1..0 plan (AUD-08)" ;;
esac

# --check on the SAME file is the informational zero, still exit 0: the guard is
# scoped to execution, not to inspection.
out="$(./prober --check "$WORK/empty.rule" 2>&1)" && status=0 || status=$?
ok "$status" "--check still accepts a zero-case file (AUD-08)"

# ---- plan reconciliation ----------------------------------------------------

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
