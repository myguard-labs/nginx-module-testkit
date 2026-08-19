#!/usr/bin/env bash
#
# TAP self-test for prober_probe_field (lib.sh), the extractor every driver
# reads probe counters through.
#
# Why it needs its own test rather than being covered by the scenarios that use
# it: a field extractor fails SILENTLY. If it returned an empty string for a
# field the probe never emitted, every driver doing arithmetic on the result
# would read it as 0 -- and 0 is a perfectly plausible delta, so a probe body
# that lost a counter (an older module .so, a build without it) would certify
# "nothing grew" instead of failing. A scenario running against a healthy server
# can never distinguish those two, because both come out green. Only a test
# holding a body with a KNOWN-absent field can.
#
# The prefix case is the other half: `"pid"` must not be satisfied by `"ppid"`,
# which is a real field emitted immediately next to it in the same body. An
# unanchored matcher would make a worker's parent pid answer to a request for
# the worker's own -- and the two are equal in no configuration, so the error
# would surface as an unexplained mismatch in an unrelated assertion.
set -euo pipefail

cd "$(dirname "$0")"

# Sourced by literal path so shellcheck can follow it; PROBER_LIB is exported
# for parity with how run-scenario.sh hands lib.sh to a driver, since the
# functions under test read it in that role.
PROBER_LIB="$PWD/lib.sh"
export PROBER_LIB
# shellcheck source=lib.sh
. ./lib.sh

PLANNED=9
tests_run=0
failures=0

echo "1..$PLANNED"

n=0
FAILED=0

# ok NAME EXPECTED ACTUAL -- one comparison, one TAP line.
check() {
    n=$((n + 1))
    tests_run=$((tests_run + 1))
    if [ "$2" = "$3" ]; then
        echo "ok $n - $1"
    else
        echo "not ok $n - $1"
        echo "# expected [$2], got [$3]"
        FAILED=$((FAILED + 1))
        failures=$((failures + 1))
    fi
}

# A body in exactly the shape ngx_test_probe.c emits (:211), including the
# nested pool object and a zone object after it, so leaf-name addressing is
# tested against real neighbours rather than a flattened toy.
BODY='HTTP/1.1 200 OK
Content-Type: application/json

{"flavor":"nginx","flavor_version":"1.29.0","pid":3719177,"ppid":3719176,"page_size":4096,"connections":{"total":16,"free":13},"fds":10,"pool":{"cycle_used":67287,"cycle_blocks":5,"cycle_large":5},"zone":{"present":false}}'

check "a flat field is read"                "10"      "$(prober_probe_field "$BODY" fds || echo RC1)"
check "a nested leaf field is read"         "67287"   "$(prober_probe_field "$BODY" cycle_used || echo RC1)"
check "a deeper nested leaf is read"        "13"      "$(prober_probe_field "$BODY" free || echo RC1)"

# The prefix pair, asserted in BOTH directions: neither name may pick up the
# other's value, and testing only one direction would miss a matcher anchored
# at the wrong end.
check "\"pid\" is not satisfied by \"ppid\"" "3719177" "$(prober_probe_field "$BODY" pid || echo RC1)"
check "\"ppid\" reads its own value"         "3719176" "$(prober_probe_field "$BODY" ppid || echo RC1)"

# The load-bearing case: absent must be an ERROR, never an empty string that a
# caller's arithmetic turns into 0.
check "an absent field returns nonzero"      "RC1"     "$(prober_probe_field "$BODY" cycle_huge || echo RC1)"
check "an absent field prints nothing"       ""        "$(prober_probe_field "$BODY" cycle_huge 2>/dev/null || true)"

# The prefix pair again, against a body where the LONGER name comes FIRST.
# This is the case that actually pins the anchor: `grep -o` reports the
# earliest match, so with the emitter's own ordering ("pid" before "ppid") a
# matcher missing its leading quote still answers correctly by accident, and
# tests 4-5 pass on the broken extractor (verified by mutating lib.sh). Field
# order is the emitter's business and not something this extractor may depend
# on, so the ordering it is NOT written against is the one worth asserting.
REORDERED='{"ppid":3719176,"pid":3719177,"fds":10}'
check "\"pid\" is not satisfied by a preceding \"ppid\"" "3719177" \
      "$(prober_probe_field "$REORDERED" pid || echo RC1)"

# A body that never arrived (the shape prober_probe_body returns 1 on) must not
# yield a field either -- the same silent-zero hazard, reached by a different
# path.
check "an empty body returns nonzero"        "RC1"     "$(prober_probe_field "" fds || echo RC1)"

# plan reconciliation

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi

exit 0
