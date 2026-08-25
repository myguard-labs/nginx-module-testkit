#!/usr/bin/env bash
#
# TAP self-test for tools/gen-consumer-scenarios.sh's COLUMN ESCAPING -- that a
# table column reaches the generated driver as TEXT TO PRINT, never as shell to
# evaluate.
#
# THE DEFECT THIS PINS. Every heredoc in the generator uses an UNQUOTED
# delimiter (it has to; the templates interpolate $so, $av_block and friends),
# and the columns landed inside double-quoted shell strings in the emitted
# driver with no escaping pass. Command substitution, $var and backticks were
# all live AT SCENARIO RUN TIME. Observed with the zstd row, whose description
# named a directive in backticks -- the markdown reflex, and the table is the
# one place this script INVITES prose (its header asks for a WHY sentence per
# row):
#
#     zstd: can't stat off : No such file or directory -- ignored
#     ok 2 - ... (the same request against  has no such header ...)
#
# Note the empty gap where the backticked text was, and note the scenario still
# banked `ok 2`. Worse than a mangled message: oracle 2 matches the row's ERE
# against the response, so a substitution whose OUTPUT happened to match that
# ERE would bank a FALSE GREEN attributed to the module.
#
# WHY --check IS NOT THE GUARD, AND MUST NOT BE OFFERED AS ONE. The committed
# driver matched the generator PERFECTLY while being wrong: both sides are
# derived from the same unescaped column, so the diff is empty by construction.
# --check answers "is the file in sync", never "is the file correct". This
# round-trip test is the guard: it drives the real generator over a hostile row
# and then asserts on what the EMITTED file does.
#
# THE ASSERTIONS RUN THE EMITTED LINE. Grepping the driver for the literal text
# would be a weaker proxy -- it cannot distinguish a backslash that neutralises
# a backtick from one that does not, and it would pass on an escape that is
# syntactically present but semantically inert. Each property below extracts
# oracle 2's echo line from the generated driver and EXECUTES it, then compares
# what it printed against the column that went in. That is the round trip.
set -euo pipefail

cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"

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
        [ -n "${3:-}" ] && printf '%s\n' "$3" | sed 's/^/# /'
    fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gen_escape_test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---- the hostile row --------------------------------------------------------
# One row carrying, in its DESCRIPTION column, every character that is live
# inside a double-quoted shell string:
#
#   `id -u`      command substitution, backtick form -- the observed defect
#   $(id -u)     command substitution, modern form
#   $HOME        parameter expansion
#   "            a double quote, which would end the driver's own string
#   \            a backslash, which would escape the next character
#
# The substitutions are chosen to produce OUTPUT THAT IS OBVIOUSLY NOT THE
# INPUT: `id -u` prints a number, $HOME an absolute path. An evaluated driver
# therefore prints something measurably different from the column, which is what
# makes the comparison below an oracle rather than a formality. A substitution
# that happened to print its own source text could not be distinguished from a
# correctly escaped one.
# SC2016: the single quotes are the entire point -- this string must reach the
# generator with its backticks and `$` UNEXPANDED, because what is under test is
# whether the GENERATED DRIVER expands them. Expanding here would substitute
# them in this test's own shell and the fixture would carry the results instead
# of the hazardous characters.
# shellcheck disable=SC2016
HOSTILE='backtick `id -u` dollar $(id -u) var $HOME quote " backslash \ end'

# The generator reads its table from a heredoc in its own source. Drive the
# hostile row through the REAL script by copying it and substituting one row --
# testing a reimplementation of the emitter would prove nothing about the
# shipped one.
GEN="$WORK/gen.sh"
cp "$REPO/tools/gen-consumer-scenarios.sh" "$GEN"
chmod +x "$GEN"

# Replace the zstd row's description column (field 6) with the hostile string,
# keeping every other column and every other row exactly as shipped -- so the
# generated scenario differs from the committed one in one field only.
#
# python3 does BOTH the split and the write. Neither awk nor sed can be trusted
# with this fixture: awk reinterprets `\ ` in a -v assignment (observed -- it
# warned and SILENTLY DROPPED the backslash, which made property 4 fail against
# a fixture that no longer contained the character it was asserting about), and
# sed reinterprets `\` and `&` in a replacement. A fixture the test tool mangles
# tests the wrong input, and would have read as a generator bug.
python3 - "$GEN" "$HOSTILE" <<'PY'
import sys
path, hostile = sys.argv[1], sys.argv[2]
lines = open(path).read().split('\n')
for i, l in enumerate(lines):
    if l.startswith('zstd|'):
        cols = l.split('|')
        assert len(cols) == 7, cols
        cols[5] = hostile
        lines[i] = '|'.join(cols)
        break
else:
    sys.exit("zstd row not found")
open(path, 'w').write('\n'.join(lines))
PY

# A staged repo root so the generator writes its scenarios into the temp dir,
# not into the checkout. It resolves output as $(dirname $0)/../ci/prober/...
ROOT="$WORK/root"
mkdir -p "$ROOT/tools" "$ROOT/ci/prober/scenarios"
mv "$GEN" "$ROOT/tools/gen-consumer-scenarios.sh"
chmod +x "$ROOT/tools/gen-consumer-scenarios.sh"

( cd "$ROOT" && tools/gen-consumer-scenarios.sh --only zstd ) >"$WORK/gen.log" 2>&1 || {
    echo "Bail out! the generator failed on the hostile row"
    sed 's/^/# /' "$WORK/gen.log"
    exit 1
}

DRIVER="$ROOT/ci/prober/scenarios/consumer-zstd/driver.sh"
if [ ! -f "$DRIVER" ]; then
    echo "Bail out! no driver.sh generated"
    exit 1
fi

# ---- property 1: the generated driver is syntactically valid ----------------
# An escape that breaks the driver's own quoting is not a fix. This must come
# first: every assertion below executes a line out of this file, and a driver
# that does not parse would fail them for the wrong reason.
if bash -n "$DRIVER" 2>"$WORK/syn.err"; then s=0; else s=1; fi
ok "$s" "the driver generated from a hostile row is syntactically valid bash" "$(cat "$WORK/syn.err")"

# ---- extract oracle 2's success line and RUN it -----------------------------
# The line is `    echo "ok 2 - <avdesc>"`. Take the first such line, execute it
# in a clean shell, and capture what it printed. Executing is the point: it is
# the same thing the scenario does, so a passing round trip is a statement about
# behaviour, not about the presence of a backslash.
LINE="$(grep -n 'echo "ok 2 - ' "$DRIVER" | head -1 | cut -d: -f1)"
if [ -z "$LINE" ]; then
    echo "Bail out! oracle 2's echo line is not in the generated driver"
    exit 1
fi
sed -n "${LINE}p" "$DRIVER" >"$WORK/line.sh"

# HOME is pinned to a value that appears nowhere in the input, so an unescaped
# $HOME expands to something unmistakable rather than to whatever the runner's
# home happens to be.
PRINTED="$(env HOME=/SENTINEL-HOME bash "$WORK/line.sh" 2>"$WORK/line.err" || true)"

# ---- property 2: nothing was executed ---------------------------------------
# The paired NEGATIVE half of the round trip, and the one that catches the
# observed defect directly. `id -u` and $(id -u) print the numeric uid; if
# either ran, that number is in the output. Asserting the absence of the uid is
# stronger than asserting the presence of the literal text: an escape that
# emitted the backticks AND still ran something would pass a presence check.
UID_NOW="$(id -u)"
case "$PRINTED" in
    *"$UID_NOW"*) s=1 ;;
    *)            s=0 ;;
esac
ok "$s" "no command substitution ran (the uid $UID_NOW is absent from the printed line)" "printed=$PRINTED"

# ---- property 3: no parameter expansion ran ---------------------------------
case "$PRINTED" in
    *SENTINEL-HOME*) s=1 ;;
    *)               s=0 ;;
esac
ok "$s" "no parameter expansion ran (\$HOME did not become /SENTINEL-HOME)" "printed=$PRINTED"

# ---- property 4: the column is printed VERBATIM -----------------------------
# The positive half. Properties 2 and 3 alone would be satisfied by a generator
# that dropped the description entirely -- which is close to what the defect
# actually did (it left an empty gap). Requiring the exact input string back
# rules that out.
case "$PRINTED" in
    *"$HOSTILE"*) s=0 ;;
    *)            s=1 ;;
esac
ok "$s" "the description column is printed VERBATIM, backtick/\$/quote/backslash included" \
   "expected substring: $HOSTILE
printed            : $PRINTED"

# ---- property 5: no diagnostic on stderr ------------------------------------
# The observed defect announced itself on stderr ("zstd: can't stat off") while
# the scenario still reported ok 2. A silent stderr is part of the contract:
# noise there is a substitution that ran and failed.
if [ -s "$WORK/line.err" ]; then s=1; else s=0; fi
ok "$s" "running oracle 2's line produces no stderr diagnostic" "$(cat "$WORK/line.err")"

# ---- property 6: the ERE column survives its single quotes intact -----------
# The anti-vacuity ERE lands inside SINGLE quotes in the driver, where a
# backslash is literal -- so it needs the OPPOSITE treatment from the
# description, and getting that wrong is silent. `^HTTP/1\.1` doubled to
# `^HTTP/1\\.1` still parses as an ERE and still runs; it just stops matching,
# and oracle 2 fails for a reason that reads like a module bug. Assert the
# shipped zstd ERE reaches the driver byte-for-byte.
WANT_ERE="$(awk 'BEGIN{FS="|"} /^zstd\|/ { print $5; exit }' "$REPO/tools/gen-consumer-scenarios.sh")"
if [ -z "$WANT_ERE" ]; then
    echo "Bail out! could not read the zstd ERE column"
    exit 1
fi
GOT_ERE="$(grep -o "grep -qiE '[^']*'" "$DRIVER" | head -1 | sed "s/^grep -qiE '//; s/'$//" || true)"
if [ "$GOT_ERE" = "$WANT_ERE" ]; then s=0; else s=1; fi
ok "$s" "the anti-vacuity ERE reaches the driver byte-for-byte (no backslash doubling)" \
   "want: $WANT_ERE
got : $GOT_ERE"

# ============================================================================
# THE EVALUATION-ONLY ROW -- properties 7-9
# ============================================================================
# WHY A SECOND ROW. The hostile row above also carries a `"` and a `\`, which
# pre-fix broke the driver's own quoting so badly that oracle 2's line did not
# parse and printed NOTHING. Properties 2 and 3 therefore passed against the
# BROKEN generator -- vacuously, on an empty string. Verified by running them
# that way; the negative control showed `printed :` empty.
#
# This row carries ONLY substitution characters -- no quote, no backslash -- so
# the pre-fix driver parses fine and RUNS the substitution. That is the observed
# defect in its pure form (the zstd row's backticked `zstd off;` did exactly
# this: parsed, ran, printed a diagnostic, still banked ok 2), and it is the
# shape properties 2 and 3 exist to catch. Without this row those two assertions
# have no proven red.
# SC2016: deliberate, same reason as $HOSTILE above.
# shellcheck disable=SC2016
EVALROW='backtick `id -u` and dollar $(id -u) and var $HOME'

GEN2="$WORK/gen2.sh"
cp "$REPO/tools/gen-consumer-scenarios.sh" "$GEN2"
python3 - "$GEN2" "$EVALROW" <<'PY2'
import sys
path, hostile = sys.argv[1], sys.argv[2]
lines = open(path).read().split('\n')
for i, l in enumerate(lines):
    if l.startswith('zstd|'):
        cols = l.split('|')
        assert len(cols) == 7, cols
        cols[5] = hostile
        lines[i] = '|'.join(cols)
        break
else:
    sys.exit("zstd row not found")
open(path, 'w').write('\n'.join(lines))
PY2

ROOT2="$WORK/root2"
mkdir -p "$ROOT2/tools" "$ROOT2/ci/prober/scenarios"
mv "$GEN2" "$ROOT2/tools/gen-consumer-scenarios.sh"
chmod +x "$ROOT2/tools/gen-consumer-scenarios.sh"
( cd "$ROOT2" && tools/gen-consumer-scenarios.sh --only zstd ) >"$WORK/gen2.log" 2>&1 || {
    echo "Bail out! the generator failed on the evaluation-only row"
    sed 's/^/# /' "$WORK/gen2.log"
    exit 1
}
DRIVER2="$ROOT2/ci/prober/scenarios/consumer-zstd/driver.sh"
LINE2="$(grep -n 'echo "ok 2 - ' "$DRIVER2" | head -1 | cut -d: -f1)"
if [ -z "$LINE2" ]; then
    echo "Bail out! oracle 2's echo line is not in the evaluation-only driver"
    exit 1
fi
sed -n "${LINE2}p" "$DRIVER2" >"$WORK/line2.sh"
PRINTED2="$(env HOME=/SENTINEL-HOME bash "$WORK/line2.sh" 2>"$WORK/line2.err" || true)"

# Property 7: the line PARSES and PRINTS something. This is what makes 8 and 9
# non-vacuous -- it establishes that the pre-fix driver really did run, so their
# reds below are about evaluation, not about a broken file.
if [ -n "$PRINTED2" ]; then s=0; else s=1; fi
ok "$s" "the evaluation-only row yields a driver line that parses and prints"    "printed=$PRINTED2
stderr=$(cat "$WORK/line2.err")"

# Property 8: no substitution ran. Pre-fix this printed the uid twice.
case "$PRINTED2" in
    *"$UID_NOW"*) s=1 ;;
    *)            s=0 ;;
esac
ok "$s" "the evaluation-only row ran no command substitution (uid $UID_NOW absent)" "printed=$PRINTED2"

# Property 9: verbatim round trip on the evaluation-only row.
case "$PRINTED2" in
    *"$EVALROW"*) s=0 ;;
    *)            s=1 ;;
esac
ok "$s" "the evaluation-only row is printed VERBATIM" \
   "expected substring: $EVALROW
printed            : $PRINTED2"

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# PLAN MISMATCH: ran $tests_run, planned $PLANNED"
    exit 1
fi

exit $((failures > 0 ? 1 : 0))
