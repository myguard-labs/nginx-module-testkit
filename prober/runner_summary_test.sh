#!/usr/bin/env bash
#
# TAP self-test: test.sh names the suites that failed.
#
# The runner aggregates every *_test.c and *_test.sh and gates the whole
# self-test stage on their exit codes. When something reds, the summary line is
# what a reader actually sees at the end of a long log -- and it used to report
# a COUNT and nothing else.
#
# That is a diagnosability hole rather than a correctness one, but it has a
# specific and expensive shape. A TAP suite here can exit NONZERO with every
# assertion green: the plan check at the bottom of each suite fails a run whose
# assertion count does not match its plan ("ran 39 tests but the plan says 38").
# The reflex on a red is to grep the output for `not ok`, that finds nothing,
# and the reader goes hunting for an assertion that does not exist. Naming the
# suite in the summary is what turns that back into a two-second answer.
#
# Why this file exists at all: with no test, deleting both `failed_names`
# appends leaves the entire tree green -- measured, not assumed. An addition
# nothing can falsify is dead weight the next reader is entitled to delete.
#
# The runner is exercised as a SUBPROCESS against a fixture directory, not by
# sourcing it: `test.sh` opens with `cd "$(dirname "$0")"` and `./build.sh`,
# and its suite discovery is a glob over that directory. Sourcing it would run
# the real suites and prove nothing about discovery. A copy in a temp dir with
# a stub build.sh and two planted suites exercises the real glob, the real
# aggregation, and the real summary.
set -euo pipefail

cd "$(dirname "$0")"

RUNNER=test.sh

PLANNED=4
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

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cp "$RUNNER" "$tmpdir/test.sh"

# The runner invokes ./build.sh before discovering anything, and would fail on
# its absence long before reaching the code under test.
printf '#!/bin/sh\nexit 0\n' > "$tmpdir/build.sh"
chmod +x "$tmpdir/build.sh"

# A suite that fails the way the summary change is about: a plan-count
# mismatch. Every assertion is `ok`, and the exit status is still 1, so a
# reader grepping `not ok` finds nothing.
cat > "$tmpdir/planmismatch_test.sh" <<'FIXTURE'
#!/usr/bin/env bash
echo "1..1"
echo "ok 1 - this assertion passes"
echo "# ran 2 tests but the plan says 1"
exit 1
FIXTURE
chmod +x "$tmpdir/planmismatch_test.sh"

# A suite that passes, so the summary has something to NOT name. Without it a
# mutant that prints every discovered suite would pass this file.
cat > "$tmpdir/clean_test.sh" <<'FIXTURE'
#!/usr/bin/env bash
echo "1..1"
echo "ok 1 - this suite is fine"
exit 0
FIXTURE
chmod +x "$tmpdir/clean_test.sh"

# ../t/*_test.c is globbed by the runner; give it a real directory so the
# `[ -e "$src" ] || continue` guard sees an unmatched glob rather than an
# error under `set -u`.
mkdir -p "$tmpdir/../t" 2>/dev/null || true

set +e
out=$("$tmpdir/test.sh" 2>&1)
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
    ok 0 "the runner exits nonzero when a suite fails"
else
    ok 1 "the runner reported success despite a failing suite (rc=$rc)"
fi

# The point of the change. The summary must carry the failing suite's NAME,
# not merely a count.
summary=$(printf '%s\n' "$out" | grep 'self-test suites failed' || true)

if printf '%s' "$summary" | grep -q 'planmismatch_test\.sh'; then
    ok 0 "the summary names the failing suite"
else
    ok 1 "the summary omits the failing suite's name (summary: $summary)"
fi

# ...and must not name the suite that passed, which is what separates
# "reports the failures" from "prints the discovery list".
if printf '%s' "$summary" | grep -q 'clean_test\.sh'; then
    ok 1 "the summary names a suite that passed (summary: $summary)"
else
    ok 0 "the summary names only the suites that failed"
fi

# The premise the whole change rests on: this failure really does have no
# `not ok` line. If a future fixture edit makes the planted suite emit one,
# the other assertions would still pass while no longer testing the case the
# summary exists for.
if printf '%s\n' "$out" | grep -q '^not ok'; then
    ok 1 "the fixture emitted a 'not ok' line, so it no longer models the case"
else
    ok 0 "the failing suite emits no 'not ok' line, as the summary warns"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

exit $((failures > 0))
