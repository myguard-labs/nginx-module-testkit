#!/usr/bin/env bash
#
# TAP self-test for prober_strace_counts and prober_strace_family_sum (lib.sh):
# the summary parser and family budgeter behind the syscall-allowlist
# scenario's assertion 3.
#
# WHY THIS EXISTS RATHER THAN LEANING ON THE SCENARIO. The scenario only ever
# sees the table a healthy run produces: clean rows, every budgeted name
# present, one row per name. The two shapes that broke this parser are exactly
# the ones it therefore cannot exercise --
#
#   1. An ERRORS row. strace's -c table emits the `errors` column only on rows
#      that HAD errors, so a clean row is NF=5 and a failing row is NF=6. The
#      first version of this code took calls as $(NF-1), which reads errors on
#      exactly those rows: a 200-call/7-error openat was compared as 7 against
#      a ceiling of 60 and PASSED while 3.3x breached. A budgeted syscall that
#      starts erroring is precisely what the hostile conditions this harness
#      creates produce, so the gate would have gone quiet when it mattered. CI
#      never emits an errors row, so reverting $4 to $(NF-1) would stay green
#      forever without this file.
#   2. A MISSING family. The first version returned 0 for an absent row, so a
#      typo'd family, a truncated capture, or a changed strace format would all
#      report the most comfortable possible answer to a question that could not
#      be evaluated -- and every ceiling would pass.
#
# Both are asserted here against committed fixtures, and mutate.sh carries a row
# restoring $(NF-1) that must red this suite.
#
# The family assertions are the other half: a name-wise budget closes nothing,
# because open/accept are separately allowlisted near-neighbours of
# openat/accept4. A test that only checked single names would pass on the
# broken design.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=33
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

# Both assertion helpers run their check inside an `if` CONDITION rather than as
# a bare command followed by `ok $?`. Under `set -e` a failing bare test ABORTS
# the script, so the first red would truncate the TAP stream and leave every
# later assertion unevaluated -- which is exactly the information a mutation run
# needs (did the mutation red ONE assertion, or does the suite collapse?).
# Errexit is suspended inside an if-condition, so a red is reported and the run
# continues to the end of the plan.

# assert_eq DESC EXPECTED ACTUAL -- the common shape, spelled out so a mismatch
# names both values instead of only failing. Command substitutions feeding it
# append `|| echo FAILED` where the function under test can return non-zero, so
# a status failure surfaces as a visible mismatch rather than an empty string
# that could coincide with an expected empty result.
assert_eq() {
    if [ "$2" = "$3" ]; then
        ok 0 "$1"
    else
        ok 1 "$1 (expected '$2', got '$3')"
    fi
}

# refute DESC CMD... -- the negative form. It is a separate helper rather than
# an `assert ! cmd` argument because `!` is shell syntax, not a command that
# could be the first word of "$@".
refute() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then ok 1 "$desc"; else ok 0 "$desc"; fi
}

# shellcheck source=lib.sh
. ./lib.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/syscall_budget_test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# --- fixtures ------------------------------------------------------------
#
# Real strace -c output shapes, written by hand so the column arrangement is
# the assertion rather than something a live capture happens to produce today.
# Note the MIXED table: `openat` carries an errors column (NF=6) while
# `accept4` does not (NF=5). That mix is the whole point -- a parser that reads
# consistently from the left handles both, one that counts backwards past an
# optional column reads one of them wrong.

cat >"$WORK/clean.txt" <<'EOF'
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 41.02    0.000512           8        60           openat
 20.11    0.000251          12        20           accept4
 18.44    0.000230          11        20           writev
 12.03    0.000150           1        80           close
  8.40    0.000105           5        20           recvfrom
------ ----------- ----------- --------- --------- ----------------
100.00    0.001248                    200           total
EOF

# The dangerous shape: openat made 200 calls, 7 of which failed. $(NF-1) reads
# 7 here; $4 reads 200.
cat >"$WORK/errors.txt" <<'EOF'
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 61.02    0.001512           7       200         7 openat
 20.11    0.000251          12        20           accept4
 18.87    0.000230          11        20           writev
------ ----------- ----------- --------- --------- ----------------
100.00    0.001993                    240         7 total
EOF

# No openat row at all, and no `open` either -- the whole family is absent.
cat >"$WORK/missing.txt" <<'EOF'
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 55.11    0.000251          12        20           accept4
 44.89    0.000230          11        20           writev
------ ----------- ----------- --------- --------- ----------------
100.00    0.000481                     40           total
EOF

# The alias case the family exists for: the module reaches the kernel through
# `open`, not `openat`, so a name-wise openat budget sees 60 (unmoved) while the
# family sees 80.
cat >"$WORK/alias.txt" <<'EOF'
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 40.02    0.000512           8        60           openat
 21.00    0.000260           13        20           open
 20.11    0.000251          12        20           accept4
 18.87    0.000230          11        20           writev
------ ----------- ----------- --------- --------- ----------------
100.00    0.001253                    120           total
EOF

# The same name twice -- an -f capture that did not fold two threads, or two
# summaries concatenated. Summing both is the only read that is not low.
cat >"$WORK/duplicate.txt" <<'EOF'
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 40.02    0.000512           8        45           openat
 21.00    0.000260          13        35           openat
 20.11    0.000251          12        20           accept4
 18.87    0.000230          11        20           writev
------ ----------- ----------- --------- --------- ----------------
100.00    0.001253                    120           total
EOF

# --- prober_strace_counts ------------------------------------------------

counts="$(prober_strace_counts "$WORK/clean.txt")"

assert_eq "clean row: openat calls read as 60" \
    "60" "$(awk '$1 == "openat" { print $2 }' <<<"$counts")"

# The header, ruler and total rows must not leak into the pairs. `total` in
# particular carries a call count in a shifted column and would be summed into
# any family whose member name matched.
refute "header, ruler and total rows are dropped" \
    grep -qE '^(total|-+|%)' <<<"$counts"

assert_eq "clean fixture yields exactly its five data rows" \
    "5" "$(wc -l <<<"$counts" | tr -d ' ')"

# THE REGRESSION. $(NF-1) on this row is 7; $4 is 200. A parser reading the
# wrong column reports the error count as if it were the call count -- low, and
# therefore under every ceiling.
errcounts="$(prober_strace_counts "$WORK/errors.txt")"
assert_eq "errors row: calls read as 200, not the 7 errors" \
    "200" "$(awk '$1 == "openat" { print $2 }' <<<"$errcounts")"

# The clean rows in the SAME table must still read correctly -- the mix is what
# makes a backwards-counting parser wrong on only some rows, which is how it
# survived review.
assert_eq "errors table: a clean row alongside it still reads 20" \
    "20" "$(awk '$1 == "accept4" { print $2 }' <<<"$errcounts")"

assert_eq "an empty capture yields no pairs (not a fabricated row)" \
    "" "$(prober_strace_counts /dev/null)"

# --- prober_strace_family_sum --------------------------------------------

assert_eq "family sum with one member present is that member's count" \
    "60" "$(prober_strace_family_sum "$counts" "openat+open" || echo FAILED)"

assert_eq "a single-name family still works" \
    "60" "$(prober_strace_family_sum "$counts" "openat" || echo FAILED)"

aliascounts="$(prober_strace_counts "$WORK/alias.txt")"
assert_eq "alias: openat 60 + open 20 sums to 80 (a name-wise budget would see 60)" \
    "80" "$(prober_strace_family_sum "$aliascounts" "openat+open" || echo FAILED)"

# The paired negative: the same table read name-wise reports the unmoved 60,
# which is the vacuous verdict the family form exists to replace. Asserting it
# here is what keeps the previous assertion from being a tautology.
assert_eq "...while openat alone reads 60, the count that let the hole through" \
    "60" "$(prober_strace_family_sum "$aliascounts" "openat" || echo FAILED)"

dupcounts="$(prober_strace_counts "$WORK/duplicate.txt")"
assert_eq "a duplicated name is summed (45+35), not read first-match-wins" \
    "80" "$(prober_strace_family_sum "$dupcounts" "openat" || echo FAILED)"

# MISSING IS AN ERROR. Both the status and the empty stdout matter: a caller
# doing `got="$(... )" || red` needs the status, and one that ignores it must
# not receive a usable 0.
misscounts="$(prober_strace_counts "$WORK/missing.txt")"
out="$(prober_strace_family_sum "$misscounts" "openat+open" 2>/dev/null || echo "__RC$?")"
assert_eq "a family absent from the table returns non-zero and prints nothing" \
    "__RC1" "$out"

# ...but an absent member of a family that WAS observed is fine at zero. This is
# the boundary the rule is drawn on, and without it "missing is an error" would
# red every healthy run (no server calls the legacy `open`).
assert_eq "an absent member of an observed family contributes zero, not an error" \
    "20" "$(prober_strace_family_sum "$misscounts" "accept4+accept" || echo FAILED)"

refute "an empty family string is an error" \
    prober_strace_family_sum "$counts" ""

refute "a malformed family (trailing separator) is an error" \
    prober_strace_family_sum "$counts" "openat+"

refute "a non-syscall-shaped member name is an error" \
    prober_strace_family_sum "$counts" "Openat"

# THE PARTIAL-MALFORM REGRESSION. Each case pairs a VALID member with one that
# is not syscall-SHAPED, which is what the first version of the validator could
# not see: `case "$name" in [a-z]*)` tested only the first character, so "open!"
# and "open*" passed it, and family-wide `seen` then let the valid openat row
# satisfy the whole family -- rc=0 with the sum 60, openat's count alone,
# silently re-creating the name-wise budget the family form replaced. The status
# is the assertion: a caller doing `|| red` must red.
#
# "Openat" above catches only the first-character rule, which is exactly why it
# passed while these did not; the two together pin both ends of the name.
#
# SCOPE, stated so this is not read as more than it is: shape validation cannot
# catch a typo that is itself syscall-shaped. "openat+opemat" is indistinguishable
# from a family whose second member simply did not appear in this capture, and
# absent-member-contributes-zero is a rule this suite pins deliberately two
# assertions up. What the validator closes is the class where a member could
# never match ANY row because it is not a syscall name at all; a well-formed
# misspelling is caught by the scenario going red on a budget it cannot meet, not
# here.
for _bad in "openat+open!" "openat+open*" "openat+ open" "openat+open-at" "openat+OPEN"; do
    refute "a partially-malformed family is an error, not the valid member's count ($_bad)" \
        prober_strace_family_sum "$counts" "$_bad"
done

# The paired positive, so the rule above cannot be over-tightened into rejecting
# every family: the legitimate names it must still accept, including the
# underscore and digit forms real syscalls use.
assert_eq "a valid multi-member family is still accepted" \
    "80" "$(prober_strace_family_sum "$aliascounts" "openat+open" || echo FAILED)"
assert_eq "digits and underscores are valid inside a member name" \
    "20" "$(prober_strace_family_sum $'accept4 20\nepoll_wait 9' "accept4+epoll_pwait" || echo FAILED)"

# A glob metacharacter must never reach pathname expansion. Run from a directory
# holding a file that "open*" would match: an unquoted `set -- $family` expands
# it to that filename, so the member the validator sees is not the member the
# caller wrote. The refute above proves the status; this proves the mechanism,
# and would pass vacuously without the fixture file.
#
# NOT in a subshell: ok() increments tests_run, and a subshell's copy of that
# variable dies with it -- the assertion reports but the count does not carry,
# so the plan reconciliation at the bottom reds with an off-by-one that has
# nothing to do with the code under test. Save and restore the cwd instead.
: >"$WORK/open_glob_bait"
_prevpwd="$PWD"
cd "$WORK"
refute "a glob member is not pathname-expanded against the cwd" \
    prober_strace_family_sum "$counts" "openat+open*"
cd "$_prevpwd"

# --- prober_served_by ----------------------------------------------------
#
# The budget's DENOMINATOR predicate, and the second route to the same
# vacuous-gate shape the family sum closed. strace attaches to one pid; a
# replacement worker is forked by the MASTER, so it is not followed even under
# -f. The first version counted any line matching `^HTTP/1\.[01] [0-9]{3}`, which
# binds a counted response to no pid at all: a worker retiring mid-burst let its
# successor serve the rest off-tracee, all 20 counted, the mutant's extra opens
# landed where nothing was counting, and all three assertions passed.
#
# These run against fixtures for the same reason as everything above -- a healthy
# local run never retires a worker mid-burst, so the scenario cannot produce the
# case that breaks this.

TRACED=1111

assert_eq "a 200 from the TRACED worker is served" \
    "yes" "$(prober_served_by $'HTTP/1.1 200 OK\r\n\r\n{"pid":1111,"ppid":1}' "$TRACED" && echo yes || echo no)"

# THE BLOCKER. Same status line, different worker: this is the response that
# inflated the denominator while contributing none of the counted syscalls.
assert_eq "a 200 from a REPLACEMENT worker is NOT served" \
    "no" "$(prober_served_by $'HTTP/1.1 200 OK\r\n\r\n{"pid":2222,"ppid":1}' "$TRACED" && echo yes || echo no)"

# Absent must not read as a value. prober_probe_field returns non-zero on a
# missing field precisely so a caller cannot silently treat absent as 0/match.
assert_eq "a body with no pid field is NOT served" \
    "no" "$(prober_served_by $'HTTP/1.1 200 OK\r\n\r\n{"ppid":1}' "$TRACED" && echo yes || echo no)"

# The overbroad-matcher cases. Each matched the original [0-9]{3} pattern and
# counted as a served response; none is one. The 103 is the sharpest: it is an
# INTERIM line that precedes the real response, so it could double-count a single
# request.
for _st in '103 Early Hints' '500 Internal Server Error' '204 No Content'; do
    assert_eq "a '${_st%% *}' response is NOT served" \
        "no" "$(prober_served_by $'HTTP/1.1 '"$_st"$'\r\n\r\n{"pid":1111}' "$TRACED" && echo yes || echo no)"
done

# `2000` is not a status code; a bare three-digit match accepted its first three
# characters. The trailing-context guard is what rejects it.
assert_eq "a malformed '2000' status is NOT served" \
    "no" "$(prober_served_by $'HTTP/1.1 2000 Bogus\r\n\r\n{"pid":1111}' "$TRACED" && echo yes || echo no)"

# The paired negative for the anchor. NOTE the body line is UNPREFIXED: a
# `X: `-prefixed one fails the regex on any line-matching implementation, buggy
# or fixed, so it proves nothing. This shape reds against the whole-document
# grep and passes only once the match is pinned to the status line.
assert_eq "an unprefixed status-like line in the BODY does not make an unserved response served" \
    "no" "$(prober_served_by $'HTTP/1.1 500 Internal\r\n\r\nHTTP/1.1 200 OK\n{"pid":1111}' "$TRACED" && echo yes || echo no)"

# The other half of the same anchor: a REAL status line must still be found
# when it is not the only line in the document.
assert_eq "a 200 with a multi-line body is still served" \
    "yes" "$(prober_served_by $'HTTP/1.1 200 OK\r\nX: y\r\n\r\nnoise\n{"pid":1111}' "$TRACED" && echo yes || echo no)"

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "not ok $((tests_run + 1)) - plan said $PLANNED, ran $tests_run"
    failures=$((failures + 1))
fi

exit $((failures > 0))
