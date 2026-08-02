#!/usr/bin/env bash
#
# TAP self-test: the README documents the directives the parser accepts.
#
# The rule DSL has exactly one implementation -- the strcmp ladder in
# ../prober/rules.c -- and exactly one reference -- ../README.md. Nothing
# connects them, so the two drift in both directions and neither drift is
# loud:
#
#   * a directive added to the parser and never written down is invisible to
#     everyone who did not add it, which is the whole readership;
#   * a directive documented but removed (or renamed) from the parser sends a
#     reader to write a rule file that dies at load time with "unknown
#     directive", against a README that says otherwise.
#
# Both were live when this file was written: `fault` and `repeat` had been
# accepted by the parser for several releases with no mention in the README.
#
# Grep rather than parse: the directive names are literal text on both sides
# (a strcmp argument in C, a backticked span in markdown), and a rename is
# precisely the drift being guarded against -- so matching them as text
# catches the failure this suite exists for.
set -euo pipefail

cd "$(dirname "$0")"

RULES=rules.c
README=../README.md

# 30 parser directives + 1 reverse sweep + 10 exclusion pairs + 5 self-checks
# (ladder extraction, backlog cut, fenced backlog heading, locale letter range,
# parser not empty).
# The per-directive count is not hardcoded anywhere else on purpose (see
# parser_directives), so a directive added without touching this number fails
# the plan check at the bottom -- which is the intended nag, not a nuisance.
PLANNED=47
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

# The directive set, read out of the parser rather than listed here. A literal
# list in this file would be a third place to drift, and the one place nobody
# would think to update.
#
# Written as a function with two callers -- the sweeps below and the
# self-check at the end -- so the self-check exercises THIS extraction rather
# than a copy of its pattern. A duplicated regex keeps passing when the real
# one is mutated, which is the tautology mutate.sh exists to expose.
parser_directives() {
    grep -oE 'strcmp\(directive, "[[:alnum:]_]+"\)' "$1" \
        | grep -oE '"[[:alnum:]_]+"' | tr -d '"' | sort -u
}

# The "Ideas and opportunities" section is the backlog: it PROPOSES directives
# that do not exist yet, in the same backticked code voice the reference uses.
# Matching it is how `concurrent` reported as documented while carrying no
# syntax entry and no semantics -- the backlog entry that proposed it ("A
# `concurrent N` directive that issues N requests in flight") satisfied the
# gate on its own. Any directive discussed before it is built inherits the same
# pre-satisfied gate, so the backlog is cut out before any matching happens.
#
# Cut by section rather than by tightening the pattern: the argument-syntax
# form would also work for `concurrent` specifically, but directives here are
# documented in several legitimate voices (`repeat <count> <text>`, a bare
# `dechunk`, a fenced `send ...`) and demanding one of them fails against a
# README that documents them, just differently.
#
# Fence state is tracked because a heading inside a fenced block is example
# text, not a section boundary. Without it, a fenced line reading
# "## Ideas and opportunities" turns the cut ON and nothing ever turns it off
# -- the rest of the README vanishes from the gate and every directive below
# that point reports as undocumented. No such fence exists today, but this
# README does carry fenced markdown, and a gate whose failure mode is
# "silently stop checking" is the shape this whole change exists to remove.
#
# Both CommonMark fence delimiters count. The README uses only backticks today
# (76 of them, balanced; zero tildes), but ~~~ is equally valid and a tilde
# fence would be invisible to a backtick-only tracker -- which puts us straight
# back in the latching case above, for a delimiter nobody thinks about.
readme_reference() {
    awk '
        /^(```|~~~)/ { fence = !fence }
        !fence && /^## / { in_backlog = ($0 ~ /^## Ideas and opportunities/) }
        !in_backlog
    ' "$1"
}

# A directive is "documented" when the README names it in code voice: inside
# backticks, as the whole span or followed by its argument syntax. Prose
# mentions do not count -- "a per-IP fault never fires" is about faults, not
# about the `fault` directive, and treating it as documentation is how `fault`
# stayed undocumented while reading as covered.
#
# The examples in the README are fenced blocks where directives appear bare at
# the start of a line, so those count too: that is the form `name`, `send` and
# `from` are taught in, and demanding a backticked mention of every one of them
# would fail against a README that does document them, just differently.
documented() {
    local directive=$1 reference=$2

    grep -qE "\`$directive([ \`<]|\$)" <<<"$reference" \
        || grep -qE "^${directive}[[:space:]]+[^[:space:]]" <<<"$reference"
}

REFERENCE=$(readme_reference "$README")

for directive in $(parser_directives "$RULES"); do
    if documented "$directive" "$REFERENCE"; then
        ok 0 "\`$directive\` is accepted by the parser and documented"
    else
        ok 1 "\`$directive\` is accepted by the parser but $README never documents it"
    fi
done

# The reverse sweep: a directive the README teaches that the parser would
# reject. Without this the README decays into a superset -- every check above
# stays green while the documentation accumulates directives that die at load
# time.
#
# Candidates come from FENCED BLOCKS ONLY. Ordinary prose in this README
# routinely opens a line with a lowercase word followed by more text ("no
# version banner sniffing.", "special HTTP request with..."), which is
# character-for-character the shape of a directive line. Scanning the whole
# file made every one of those a candidate; they were rejected only because no
# prose word happens to collide with a plausible-but-unknown directive name.
# That is luck, not a check -- one future sentence starting "header ..." turns
# this into a bogus "the README teaches directives the parser rejects".
#
# Only UNTAGGED and ```text fences, which is where this README puts rule files.
# The ```sh and ```c fences are the other half of the same problem: they yield
# `git`, `prober`, `static` and `size_t`, none of which are directives and all
# of which have a directive's line shape.
# A closing fence is always a bare ```, so "is this untagged" cannot tell an
# opener from a closer -- the state has to be tracked explicitly.
#
# A fence qualifies as a rule file by CONTENT, not by tag: it must carry a
# `name` line, which every case begins with. Tag alone is not enough, because
# the untagged fences also hold shell commands and an ASCII architecture
# diagram whose first column ("prober (standalone binary) ...") has exactly a
# directive's shape. Buffering to decide per fence costs nothing at this size.
fenced_lines() {
    awk '
        /^```/ {
            if (open) {
                if (isrule) { printf "%s", buf }
                open = 0; buf = ""; isrule = 0
            } else {
                open = 1
            }
            next
        }
        open {
            buf = buf $0 "\n"
            if ($0 ~ /^name[[:space:]]+[^[:space:]]/) { isrule = 1 }
        }
    ' "$1"
}

undocumented_removals() {
    local rules=$1 readme=$2 out="" word
    local known fenced
    known=$(parser_directives "$rules")
    fenced=$(fenced_lines "$readme")

    while IFS= read -r word; do
        [ -n "$word" ] || continue
        grep -qx "$word" <<<"$known" && continue
        out="$out $word"
    done < <(printf '%s\n' "$fenced" \
        | grep -oE '^[[:lower:]_]+[[:space:]]+[^[:space:]]' \
        | grep -oE '^[[:lower:]_]+' | sort -u)

    printf '%s' "$out"
}

stale=$(undocumented_removals "$RULES" "$README")

if [ -z "$stale" ]; then
    ok 0 "the README teaches no directive the parser would reject"
else
    ok 1 "the README teaches directives the parser rejects:$stale"
fi

# The mutually-exclusive pairs the parser enforces at load time. These are the
# rules a reader is most likely to hit and least likely to guess: the parser
# dies, and the README is where the reason lives. Checking the prose exists at
# all is weak, but it is the difference between a documented constraint and one
# discovered by a failing suite.
#
# Each entry is <directive>:<directive it excludes>.
EXCLUSIONS="
abort:shutdown
abort:recv_slow
abort:hold
abort:expect_close_within
abort:expect_idle
hold:recv_slow
hold:expect_close_within
hold:expect_idle
recv_slow:expect_idle
expect_close_within:expect_idle
"

# True when one sentence of the README names both directives AND says they are
# exclusive. Either directive's own section is a fair place to document the
# pair, so no order is preferred -- the match is symmetric in a and b.
related_within() {
    local a=$1 b=$2 readme=$3

    # Scoped to the EXCLUSIVITY SENTENCE, not to a window around the
    # directive's section. A window wide enough to hold the prose is also wide
    # enough to reach the next directive's own definition, so deleting the
    # exclusion outright left the check green -- proven by mutating
    # `hold`/`recv_slow` out of the README and watching this pass. A check that
    # survives the deletion of the thing it checks is the vacuous gate this
    # repo keeps re-learning.
    #
    # The whole file is joined into one stream first, because a sentence here
    # routinely spans two or three lines and splitting per line would cut the
    # exclusion prose in half. Sentence boundaries are then a period followed
    # by whitespace -- after joining, the line break IS that whitespace.
    # The backtick is passed IN as a variable rather than written inside the
    # awk program: a literal backtick in the program text ends up in shell
    # command-substitution position on some quoting paths, and the resulting
    # syntax error kills the script mid-run -- which reads as "the remaining
    # checks passed", the exact false green this file exists to prevent.
    local q='`'

    tr '\n' ' ' < "$readme" | awk -v a="$a" -v b="$b" -v q="$q" '
        {
            n = split($0, parts, /\.[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                s = parts[i]

                # Track whose section we are in: a sentence that opens by
                # introducing a directive with its argument syntax
                # (`abort <offset>` ..., `expect_idle <ms>` ...) starts that
                # directive s section, and the implicit-subject prose below
                # belongs to whichever one is current.
                if (match(s, "^[[:space:]]*" q "[[:lower:]_]+[ ]+[<0-9]")) {
                    hdr = substr(s, RSTART, RLENGTH)
                    gsub(/[^[:lower:]_]/, "", hdr)
                    sect = hdr
                }

                if (s !~ /exclusive|may not carry|rejects that/) { continue }

                # A name counts as present when the sentence backticks it OR
                # when it owns the section: the implicit-subject voice
                # ("Mutually exclusive with `abort` and `hold`") never repeats
                # its own subject, so requiring both names as literal text
                # rejected every pair documented that way.
                has_a = (s ~ (q a q)) || (sect == a)
                has_b = (s ~ (q b q)) || (sect == b)
                if (!has_a || !has_b) { continue }

                # The sentence must be ABOUT one of the pair, not merely name
                # both. A directive with a long exclusion list names several
                # others in one breath -- the expect_idle list names `hold` and
                # `recv_slow` together -- and counting that as documentation of
                # the hold/recv_slow pair let BOTH sentences that actually
                # document it be deleted with this check still green.
                #
                # Two accepted voices, because the README uses both:
                #   "`hold` is mutually exclusive with `recv_slow`"  -- the
                #     subject leads the sentence in code voice;
                #   "Mutually exclusive with `abort` and `hold`"     -- the
                #     subject is the section, left implicit, so the sentence
                #     opens with the exclusivity phrase itself.
                # In the second voice the section owner is passed in as `sect`
                # and must be one of the pair, which is what stops expect_idle
                # section prose from vouching for an unrelated pair.
                if (s ~ ("^[[:space:]]*" q a q) || s ~ ("^[[:space:]]*" q b q)) {
                    found = 1
                } else if (s ~ /^[[:space:]]*(Mutually exclusive|For the same reason)/ &&
                           (sect == a || sect == b)) {
                    found = 1
                }
            }
        }
        END { exit !found }
    '
}

for pair in $EXCLUSIONS; do
    a=${pair%%:*}
    b=${pair##*:}

    # The parser's own exclusion, so a pair that stops being enforced is caught
    # here rather than silently documented forever.
    if ! grep -qE "$a|$b" "$RULES"; then
        ok 1 "\`$a\`/\`$b\`: neither appears in $RULES"
        continue
    fi

    if related_within "$a" "$b" "$README"; then
        ok 0 "the README relates \`$a\` and \`$b\`"
    else
        ok 1 "the README never relates \`$a\` and \`$b\` (they are exclusive)"
    fi
done

# A bracket range spelled with a letter range is a range over COLLATION order,
# not over ASCII. Under LC_ALL=tr_TR.UTF-8 it stops covering the letters this
# file needs, so a sweep anchored on one reports every directive as missing.
# The locale-hostility CI job caught exactly that in the sibling schema test.
#
# Only grep/sed lines are examined, and this check's own line is excluded: a
# guard whose pattern matches itself can never pass.
bad_ranges=$(grep -nE '(grep|sed)[^|]*\[[^]]*[a-y]-[a-z]' "$0" \
    | grep -cv 'bad_ranges=' || true)

if [ "$bad_ranges" -eq 0 ]; then
    ok 0 "no locale-dependent letter range in this file"
else
    ok 1 "locale-dependent letter range in this file (use [[:lower:]])"
fi

# The extraction, exercised through parser_directives itself on a synthetic
# source. Nothing else in this file would notice the pattern being narrowed --
# a mutation that drops the ladder match makes every loop above run zero times,
# and a loop that runs zero times reports zero failures.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

printf '%s\n' \
    'if (strcmp(directive, "alpha") == 0) {' \
    '} else if (strcmp(directive, "beta_two") == 0) {' \
    '} else if (strcmp(other, "not_a_directive") == 0) {' \
    > "$tmpdir/rules.c"

found=$(parser_directives "$tmpdir/rules.c" | tr '\n' ' ')

if [ "$found" = "alpha beta_two " ]; then
    ok 0 "the extraction reads the strcmp ladder and nothing else"
else
    ok 1 "the extraction misread the ladder (got: $found)"
fi

# The backlog cut, exercised through readme_reference + documented on a
# synthetic README. All three directions are asserted from one fixture, because
# no one of them is meaningful alone:
#
#   * `shipped` (before the backlog) catches a cut that removes everything --
#     which would otherwise satisfy the `proposed` half while silently
#     reporting all 29 real directives undocumented;
#   * `proposed` (inside the backlog) catches a cut that removes nothing, which
#     restores the exact hole this check exists to close;
#   * `after_backlog` (after the NEXT heading) catches a cut that latches on and
#     never reopens. That mutant is invisible to the other two and to the real
#     sweep, because every directive the README documents today sits ABOVE the
#     backlog -- so a permanently-latched cut passes the live gate while
#     silencing everything a future section might add.
# shellcheck disable=SC2016  # the backticks are markdown code voice, not command substitution
printf '%s\n' \
    '## Rule reference' \
    '- **`shipped <n>`** -- a directive that really exists.' \
    '' \
    '## Ideas and opportunities -- ways to break a module we do not yet try' \
    '  A `proposed N` directive that issues N requests in flight.' \
    '' \
    '## Who maintains this' \
    '- **`after_backlog <n>`** -- documented after the backlog section ends.' \
    > "$tmpdir/README.md"

synthetic=$(readme_reference "$tmpdir/README.md")

if documented "shipped" "$synthetic" \
   && ! documented "proposed" "$synthetic" \
   && documented "after_backlog" "$synthetic"; then
    ok 0 "a backlog-only mention is not documentation, a reference entry is"
else
    ok 1 "the backlog cut is wrong (shipped=$(documented shipped "$synthetic" && echo y || echo n), proposed=$(documented proposed "$synthetic" && echo y || echo n), after_backlog=$(documented after_backlog "$synthetic" && echo y || echo n))"
fi

# The same cut, against a backlog heading that appears as EXAMPLE TEXT inside a
# fenced block. Without fence tracking the cut latches on at the fenced line and
# never releases, so the directive documented below -- in an ordinary section --
# reports undocumented, and so would every real directive after it.
#
# Both delimiters are exercised in one fixture. Asserting only the backtick case
# would leave the ~~~ branch of the fence pattern untested, which is how a
# half-covered guard passes while one of its arms does nothing.
# shellcheck disable=SC2016  # markdown code voice, not command substitution
printf '%s\n' \
    '## Rule reference' \
    'Sections in this file look like:' \
    '```' \
    '## Ideas and opportunities' \
    '```' \
    '- **`after_fence <n>`** -- documented after the backtick example.' \
    '~~~' \
    '## Ideas and opportunities' \
    '~~~' \
    '- **`after_tilde <n>`** -- documented after the tilde example.' \
    > "$tmpdir/README-fence.md"

fenced=$(readme_reference "$tmpdir/README-fence.md")

if documented "after_fence" "$fenced" && documented "after_tilde" "$fenced"; then
    ok 0 "a backlog heading inside a fence does not cut the rest of the README"
else
    ok 1 "a fenced backlog heading latched the cut (backtick=$(documented after_fence "$fenced" && echo y || echo n), tilde=$(documented after_tilde "$fenced" && echo y || echo n))"
fi

# ...and the plan is not satisfied by an empty parser. If parser_directives
# ever returns nothing, every per-directive check vanishes and the count check
# below is the only thing standing between that and a green run.
count=$(parser_directives "$RULES" | grep -c .)

if [ "$count" -ge 20 ]; then
    ok 0 "the parser exposes $count directives"
else
    ok 1 "the parser exposes only $count directives (expected >= 20)"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

exit $((failures > 0))
