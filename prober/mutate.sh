#!/usr/bin/env bash
#
# Mutation smoke test: break the code on purpose, and require the suite to
# notice.
#
# WHY THIS EXISTS. This repo's self-tests decide whether a module's run is
# green, so a test that cannot fail is worse than a missing one -- the run still
# reports success. A passing suite proves the tests RAN; only a failing one
# proves they ASSERT. Every directive added here has been mutation-checked by
# hand, and that ritual has caught a real defect on each of the last three
# passes -- including one (a dropped SO_LINGER) where the feature's entire
# effect was untested behind assertions that looked thorough.
#
# Doing it by hand is where the danger is. Three separate failure modes have
# each produced a result that READ like "the mutation was caught" when nothing
# of the sort happened:
#
#   1. The mutation did not compile. The build fails, the STALE binary from the
#      last build runs, the suite goes red -- indistinguishable from a caught
#      mutation unless the build's exit status is checked. The -Werror wall
#      makes this common: zeroing a parameter's only use trips
#      -Werror=unused-parameter, so `x * 0` is the safe form, not `0`.
#   2. The edit did not apply. A sed expression that silently matches nothing
#      leaves the code pristine; the suite passes; that reads as SURVIVED and
#      sends you hunting a coverage gap that does not exist.
#   3. The wrong suite was run. A transport mutation checked against the parser
#      tests survives trivially, because those tests never touch the transport.
#
# So this script verifies, for every mutation: that the patch changed the file,
# that the build succeeded, and that the named suite -- not merely some suite --
# went red. Anything else is reported as a BROKEN mutation, never as a result.
#
# Usage:  ./mutate.sh            run every mutation
#         ./mutate.sh SO_LINGER  run those whose name matches a substring
#
# Each mutant's suite is bounded by MUT_SUITE_TIMEOUT seconds (default 120); a
# timeout counts as a caught mutation. Exit status is 0 only when every mutation
# was caught.
set -uo pipefail

cd "$(dirname "$0")" || exit 1

FILTER="${1:-}"

# Per-mutant wall-clock ceiling. A mutation that removes a loop bound or a wait
# ceiling can make its suite spin forever; without this the mutation job runs to
# GitHub's 360 min cap. Overridable for a slow runner.
MUT_SUITE_TIMEOUT="${MUT_SUITE_TIMEOUT:-120}"

work=$(mktemp -d)

pass=0
fail=0
broken=0

#
# One mutation: name, file, python replacement (old -> new), suite that must
# catch it.
#
# The edit is a literal string replacement rather than a regex: a sed pattern
# that fails to match is silent, and failure mode 2 above is exactly that. A
# literal old-string either appears or does not, and this checks which.
#
# A 6th argument opts a mutant into a sanitizer build. Without it every build
# this script makes is plain, so a mutation whose only effect is a leak or a
# use-after-free is a behavioural no-op -- rules_test still exits 0 and the
# mutant reads as SURVIVED, sending an auditor after a coverage gap that does
# not exist. `mutate NAME file old new suite san` rebuilds the just-mutated tree
# with SAN=1 (ASan + LSan) before running the suite, so a leak/UAF mutant goes
# red on the sanitizer's own report exactly as the CI asan leg would catch it.
# The clean rebuild in the restore path is plain again, so the next mutant is
# not silently sanitized. (TODO Pack 3; proven s65 on the probe_baseline free.)
mutate () {
    local name="$1" file="$2" old="$3" new="$4" suite="$5" san="${6:-}"

    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then
        return
    fi

    local buildenv=""
    if [ -n "$san" ]; then
        buildenv="SAN=1"
        # LSan reports at exit but does not, by itself, make the process exit
        # non-zero on a leak -- so a leaked mutant would still exit 0 and read
        # as SURVIVED. exitcode=1 is what turns the leak report into the red
        # verdict this opt-in exists to produce.
        buildenv="$buildenv ASAN_OPTIONS=detect_leaks=1:exitcode=1"
    fi

    cp "$file" "$work/orig"

    # Names the file from the moment it is about to be patched until it has
    # been put back, so the EXIT trap can restore it if this run is killed
    # in between. See summarise().
    MUT_ACTIVE="$file"

    if ! MUT_FILE="$file" MUT_OLD="$old" MUT_NEW="$new" python3 - <<'PY'
import os, sys
path, old, new = os.environ['MUT_FILE'], os.environ['MUT_OLD'], os.environ['MUT_NEW']
s = open(path).read()
if s.count(old) != 1:
    sys.exit(f"anchor appears {s.count(old)} times, need exactly 1")
open(path, 'w').write(s.replace(old, new))
PY
    then
        echo "BROKEN  $name -- anchor did not match uniquely (mutation not applied)"
        cp "$work/orig" "$file"
        MUT_ACTIVE=""
        broken=$((broken + 1))
        return
    fi

    # Failure mode 1: without this check a failed build silently re-runs the
    # previous binary, and its red result reads as a caught mutation.
    # SC2086: $buildenv is a set of VAR=value words that env must receive as
    # separate arguments; quoting would pass them as one bogus program name.
    # shellcheck disable=SC2086
    if ! env $buildenv ./build.sh >"$work/build.log" 2>&1; then
        echo "BROKEN  $name -- did not compile (see below); use x*0 rather than 0"
        sed -n '1,3p' "$work/build.log" | sed 's/^/          /'
        cp "$work/orig" "$file"
        MUT_ACTIVE=""
        broken=$((broken + 1))
        return
    fi

    # Failure mode 3: the NAMED suite must go red. A mutation that only breaks
    # some other suite is not evidence that this one asserts anything.
    #
    # The suite is bounded by a per-mutant timeout. Without it a mutation that
    # removes a loop bound or a wait ceiling makes the suite spin, and the whole
    # mutation job runs to GitHub's 360 min cap before the runner kills it. A
    # timeout is itself a caught mutation -- the suite did not report ok -- but is
    # labelled distinctly so a genuine spin is not mistaken for a red assertion.
    # $buildenv carries ASAN_OPTIONS for a san mutant: the instrumented binary
    # reads it at RUN time, so it must be on the suite invocation and not only
    # the build. It is empty for a plain mutant, so env is a no-op there.
    local rc=0
    # shellcheck disable=SC2086  # $buildenv is VAR=value words for env; see above.
    env $buildenv timeout "$MUT_SUITE_TIMEOUT" ./"$suite" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SURVIVED $name -- $suite still passes; the behaviour is untested"
        fail=$((fail + 1))
    elif [ "$rc" -eq 124 ]; then
        echo "caught   $name ($suite timed out after ${MUT_SUITE_TIMEOUT}s)"
        pass=$((pass + 1))
    else
        echo "caught   $name ($suite)"
        pass=$((pass + 1))
    fi

    cp "$work/orig" "$file"
    MUT_ACTIVE=""
}


#
# The summary and the exit decision live in a trap rather than at the end of the
# file, so a mutation appended below this point still counts. Written flat, an
# added mutation lands AFTER the tally and is silently excluded from it -- the
# script would report "survived 0" while printing a SURVIVED line, and exit 0.
# That was not hypothetical: it happened while self-testing this script.
#
summarise () {
    local rc=0

    #
    # Put the file back FIRST, before anything that could exit.
    #
    # Every restore in mutate() is a plain cp on a normal code path, so a run
    # killed mid-mutation -- a Ctrl-C, a harness timeout, an OOM -- leaves the
    # MUTATED SOURCE on disk. That is materially worse than the stale-binary
    # trap this script already documents: rebuilding does not clear it, and
    # `git status` reports only "modified", which is indistinguishable from the
    # feature work in progress around it. It happened for real: a foreground
    # timeout killed a full run and left `opt_check = 0` in prober.c, silently
    # disabling --check, and the four build configs that ran afterwards all
    # reported green against mutated source.
    #
    # MUT_ACTIVE is set immediately before the patch is applied and cleared
    # immediately after the restore, so it names a file only while one is
    # genuinely mutated.
    #
    if [ -n "${MUT_ACTIVE:-}" ] && [ -f "$work/orig" ]; then
        cp "$work/orig" "$MUT_ACTIVE"
        echo "restored $MUT_ACTIVE (run interrupted mid-mutation)"
    fi

    echo
    echo "caught $pass, survived $fail, broken $broken"

    # A broken mutation is a failure of THIS SCRIPT, not a verdict about the
    # code, and must never be reported as either a pass or a coverage gap.
    if [ "$fail" -gt 0 ] || [ "$broken" -gt 0 ]; then
        rc=1
    fi

    rm -rf "$work"
    exit "$rc"
}

trap summarise EXIT INT TERM


# ---- transport: send-side pacing -------------------------------------------

# The two pacers now sleep with the same statement, so each anchor carries the
# preceding line that is unique to its own loop -- an ambiguous anchor is
# reported BROKEN rather than silently mutating the wrong function.
mutate "send_slow: inter-chunk sleep zeroed" http.c \
    'off += n;

        if (off < len) {
            long  slept = sleep_ms(ms);' 'off += n;

        if (off < len) {
            long  slept = sleep_ms(ms * 0);' http_test

mutate "send_slow: leading stall dropped" http.c \
    'if (pauses[i].unit) {
                rc = write_paced_units(fd, req + off, upto_next - off,
                                       pauses[i].ms, slept_ms);' \
    'if (pauses[i].unit) {
                rc = write_paced_units(fd, req + off, upto_next - off,
                                       pauses[i].ms * 0, slept_ms);' http_test

# The S-5 defect class one level up: the sleep is gutted but the counter is
# credited from the INTENT (`ms`) instead of sleep_ms()'s return, so the
# accounted number stays exactly right while the sleep never happens. An
# equality assertion on send_paced_ms alone cannot catch this -- the whole
# point of the defect is that the count is correct -- so this can only be
# caught by an assertion that corroborates the count against an independent
# witness of elapsed time (http_test.c's "corroborated by elapsed wall time"
# case). Kept as its own row rather than folded into the sleep-zeroed row
# above: that row changes the SLEEP call, this one changes the CREDIT site,
# and conflating them would leave either half able to regress unnoticed.
mutate "send_slow: inter-chunk sleep zeroed but intent credited anyway" http.c \
    'off += n;

        if (off < len) {
            long  slept = sleep_ms(ms);

            if (slept_ms != NULL) {
                *slept_ms += slept;
            }
        }' 'off += n;

        if (off < len) {
            long  slept = sleep_ms(ms * 0);

            (void) slept;

            if (slept_ms != NULL) {
                *slept_ms += ms;
            }
        }' http_test

mutate "send_slow: chunk ignored" http.c \
    'if (n > chunk) {
            n = chunk;
        }' 'if (0) {
            n = chunk;
        }' http_test

# ---- transport: chunk-unit pacing ------------------------------------------

mutate "send_slow_chunks: inter-unit sleep zeroed" http.c \
    'off += unit;

        if (off < len) {
            long  slept = sleep_ms(ms);' 'off += unit;

        if (off < len) {
            long  slept = sleep_ms(ms * 0);' http_test

# The pacer selection itself: a unit entry falling through to the byte-count
# pacer is the defect the directive exists to prevent, and chunk 0 there means
# "no clamp", so the whole span goes out in one write.
mutate "send_slow_chunks: paced by byte count instead of framing" http.c \
    'if (pauses[i].unit) {
                rc = write_paced_units(' \
    'if (0) {
                rc = write_paced_units(' http_test

# The data CRLF check: dropping it makes the walk accept a unit whose data is
# not CRLF-terminated and resume at the wrong offset, so later cuts land mid
# framing -- the same failure as pacing by byte count, reached differently.
mutate "send_slow_chunks: unit CRLF terminator unchecked" http.c \
    'if (start[unit] != '"'"'\r'"'"' || start[unit + 1] != '"'"'\n'"'"') {' \
    'if (0) {' http_test

# ---- transport: shutdown ----------------------------------------------------

mutate "shutdown: call skipped" http.c \
    '(void) shutdown(fd, shut_how);' \
    '(void) shut_how;' http_test

# ---- transport: abort -------------------------------------------------------

mutate "abort: SO_LINGER disabled" http.c \
    'lg.l_onoff = 1;' 'lg.l_onoff = 0;' http_test

mutate "abort: offset ignored" http.c \
    'abort_at < req_len ? abort_at : req_len' 'req_len' http_test

# ---- transport: receive-side pacing ----------------------------------------

# S-4: pacing is a per-leg gate, not a sleep, so the anchor is the gate width.
# A zero-width gate withholds nothing AND credits nothing -- both halves of the
# S-5 witness must red, not just the wall clock.
mutate "recv_slow: pacing gate zeroed" http.c \
    '                    st->not_before = now + st->recv_opt->ms;' \
    '                    st->not_before = now + st->recv_opt->ms * 0;' http_test

mutate "recv_slow: chunk cap ignored" http.c \
    'if (want > st->recv_opt->chunk) {
                want = st->recv_opt->chunk;
            }' 'if (0) {
                want = st->recv_opt->chunk;
            }' http_test

mutate "recv_slow: gates before the EOF read" http.c \
    'if (st->paced_full) {' 'if (st->paced_full || 1) {' http_test

mutate "so_rcvbuf: setsockopt dropped" http.c \
    'if (recv_opt != NULL && recv_opt->rcvbuf > 0) {' \
    'if (0) {' http_test

# ---- parser: zero-value sentinels ------------------------------------------
#
# Both of these are the trap the sentinels exist to prevent: a zeroed field
# silently applying the directive to every case in the file.

mutate "shutdown: default becomes SHUT_RD" rules.c \
    'cases[n - 1].shut_how = HTTP_SHUT_NONE;' \
    'cases[n - 1].shut_how = 0;' rules_test

mutate "abort: default becomes offset 0" rules.c \
    'cases[n - 1].abort_at = HTTP_ABORT_NONE;' \
    'cases[n - 1].abort_at = 0;' rules_test

# ---- parser: guards ---------------------------------------------------------

mutate "abort: response-expectation guard removed" rules.c \
    'if (tc->saw_abort && tc->n_expects > 0) {' 'if (0) {' rules_test

mutate "send_slow: post-parse ceiling not enforced" rules.c \
    'if (total > MAX_PAUSE_MS) {
                die("%s: case \"%s\" stalls %ld ms in total, over the %d ms "' \
    'if (0) {
                die("%s: case \"%s\" stalls %ld ms in total, over the %d ms "' \
    rules_test

# A unit entry costed as a plain stall: N units of sleep charged as one, so the
# ceiling passes a case that spends far past the prober's read timeout and the
# suite reports a harness timeout as if it were a server verdict.
mutate "send_slow_chunks: unit entry costed as a single stall" rules.c \
    'if (p->unit) {
        return pause_cost_ms_raw(p->offset, upto, MIN_CHUNK_UNIT_BYTES, p->ms);' \
    'if (0) {
        return pause_cost_ms_raw(p->offset, upto, MIN_CHUNK_UNIT_BYTES, p->ms);' \
    rules_test

# ---- transport: hold --------------------------------------------------------

# The wait is the directive. Zeroed, the connection is written and closed
# immediately, which still delivers the request and still ends with a FIN --
# every assertion but the timing one passes.
mutate "hold: wait zeroed" http.c \
    '        sleep_ms(hold_ms);' '        sleep_ms(hold_ms * 0);' http_test

# A hold that resets is an abort wearing a different name, and the FIN-not-RST
# assertion is the only thing standing between the two.
mutate "hold: ends with a reset instead of a FIN" http.c \
    '    if (hold_ms != HTTP_HOLD_NONE) {
        sleep_ms(hold_ms);' \
    '    if (hold_ms != HTTP_HOLD_NONE) {
        struct linger lg2; lg2.l_onoff = 1; lg2.l_linger = 0;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg2, sizeof(lg2));
        sleep_ms(hold_ms);' http_test

mutate "hold: response-expectation guard removed" rules.c \
    'if (tc->saw_hold && tc->n_expects > 0) {' 'if (0) {' rules_test

mutate "hold: ceiling not counted toward the stall budget" rules.c \
    '        total += tc->hold_ms;' '        total += tc->hold_ms * 0;' rules_test

# ---- expect_close_within ----------------------------------------------------

# The opt-in itself. Ignoring want_close puts the read timeout back to being a
# transport error, so a close-deadline case would abort with "request failed"
# instead of failing on the assertion that asked the question -- a server defect
# reported as a harness fault.
# Neutering this one takes care. `if (0)` leaves want_close unused and trips
# -Werror=unused-parameter; `if (want_close * 0)` then trips
# -Werror=int-in-bool-context. Both are failure mode 1 from this script's
# header, hit for real on two successive drafts. `< 0` keeps the parameter used
# AND the expression boolean, while never being true for any value the callers
# pass (0 or 1).
# S-4 re-anchored, and the move is the point. This mutant used to hit the EAGAIN
# branch, where SO_RCVTIMEO expiring meant "the server held the connection open".
# The drain now waits for readiness in poll() BEFORE reading, so that branch is
# effectively unreachable and mutating it SURVIVED -- correctly, since nothing
# reaches it. The behaviour did not become untested; it moved. The
# whole-exchange deadline is what produces the timeout verdict now, so the
# mutant anchors there: it reds assertions 120-122 (verdict, bytes kept, time
# measured).
mutate "close_within: want_close ignored" http.c \
    '                > HTTP_MAX_EXCHANGE_MS(st->timeout_ms)) {
            if (st->want_close) {' \
    '                > HTTP_MAX_EXCHANGE_MS(st->timeout_ms)) {
            if (st->want_close < 0) {' http_test

# The comparison itself, in both directions. `>=` passes a close that missed the
# deadline by exactly nothing; inverting it fails every prompt close.
mutate "close_within: deadline comparison inverted" assert.c \
    '        if (resp->close_ms > deadline_ms) {' \
    '        if (resp->close_ms < deadline_ms) {' assert_test

# A timeout judged as a pass is the whole failure this directive exists to
# prevent: the server never closed, and the case reports green.
#
# The mutation returns 1 rather than re-labelling the case. An earlier version
# changed `case HTTP_CLOSE_TIMEOUT:` to `case 999:`, which SURVIVED for an
# uninteresting reason: the label fell through to `default:`, which also fails,
# so the mutant behaved identically to the original. An equivalent mutant is not
# a coverage gap, and reading it as one sends you looking for a missing test
# that does not exist -- so the mutation targets the verdict itself.
mutate "close_within: timeout treated as a pass" assert.c \
    '    case HTTP_CLOSE_TIMEOUT:
        snprintf(why, whylen,
                 "connection still open %ld ms after the request; wanted a "
                 "close within %ld ms", resp->close_ms, deadline_ms);
        return 0;' \
    '    case HTTP_CLOSE_TIMEOUT:
        snprintf(why, whylen,
                 "connection still open %ld ms after the request; wanted a "
                 "close within %ld ms", resp->close_ms, deadline_ms);
        return 1;' assert_test

# "No close observed" must fail rather than pass. If the default branch returns
# 1, a case whose exchange never read the socket asserts nothing and says ok.
mutate "close_within: unobserved close treated as a pass" assert.c \
    '        snprintf(why, whylen,
                 "no connection close was observed, so a %ld ms close "
                 "deadline cannot be judged", deadline_ms);
        return 0;' \
    '        snprintf(why, whylen,
                 "no connection close was observed, so a %ld ms close "
                 "deadline cannot be judged", deadline_ms);
        return 1;' assert_test

# NOT MUTATED: the errno discrimination in the read loop's error branch
# (`errno == ECONNRESET ? RESET : NONE`).
#
# Widening it back to "every error is a reset" cannot be caught by an honest
# test, so no mutation is listed for it. On a connected loopback socket the only
# errno a fixture can actually provoke there is ECONNRESET; the branch exists for
# EBADF/ENOTCONN, which cannot be produced without corrupting the fd behind
# http_request()'s back. A test that reached them would be testing its own
# sabotage rather than the transport.
#
# Listed here rather than omitted silently: the next person to audit coverage
# will notice the gap, and the useful thing to know is that it was measured and
# judged unreachable, not overlooked. The discrimination is still worth having --
# it decides the text a rule author reads when a close deadline fails.

# The measurement, not just the verdict. A close_ms stuck at zero passes every
# deadline no matter how long the server actually took.
mutate "close_within: FIN time not measured" http.c \
    '        if (n == 0) {
            st->resp->close_reason = HTTP_CLOSE_FIN;
            st->resp->close_ms = elapsed_since(st->sent_at);' \
    '        if (n == 0) {
            st->resp->close_reason = HTTP_CLOSE_FIN;
            st->resp->close_ms = elapsed_since(st->sent_at) * 0;' http_test

# The ceiling. A deadline past the read timeout can never be missed, so without
# this bound the directive accepts values at which it cannot go red.
mutate "close_within: ceiling removed" rules.c \
    '            if (ms < 0 || ms > MAX_CLOSE_WITHIN_MS) {' \
    '            if (ms < 0) {' rules_test

# The guards against the two directives that never read the socket. Without
# them a case can ask for a deadline nothing will ever measure.
mutate "close_within: abort exclusion removed" rules.c \
    '            if (PX(saw_abort)) {
                die("%s:%d: abort and expect_close_within are mutually "' \
    '            if (0) {
                die("%s:%d: abort and expect_close_within are mutually "' \
    rules_test

# The slot reset. Without it a second load into the same array inherits the
# previous file'"'"'s saw_ flags and dies on a duplicate its own text never had.
mutate "close_within: case slot not reset between loads" rules.c \
    '            case_free(&cases[n - 1]);' \
    '            if (0) case_free(&cases[n - 1]);' rules_test

# The runtime half of the close-deadline ceiling. rules.c caps the directive at
# a compile-time constant; only prober.c can compare it against -t. Without this
# guard a deadline past the timeout parses fine and can never fail, which is the
# un-reddable gate the constant ceiling exists to prevent -- reached by the one
# path that ceiling cannot cover. (Found by CodeRabbit on PR #39.)
mutate "close_within: deadline-past-timeout guard removed" prober.c \
    '        if (cases[c].saw_close_within
            && cases[c].close_within_ms >= opt_timeout_ms)' \
    '        if (cases[c].saw_close_within
            && cases[c].close_within_ms >= opt_timeout_ms * 1000000)' \
    check_test.sh

# ---- expect_idle --------------------------------------------------------

# The wait not happening at all. A poll of 0 ms returns immediately, so every
# idle-wait case would report IDLE without observing anything -- the vacuous
# pass this directive is most vulnerable to, since its passing outcome is a
# non-event and an instant "nothing happened" looks identical to a real one.
mutate "idle: wait not actually spent" http.c \
    '            n = poll(&pfd, 1, (int) left);' \
    '            n = poll(&pfd, 1, 0);' http_test

# The readiness check itself. Ignoring POLLIN makes a server that answers or
# closes during the wait indistinguishable from one that stayed silent: the
# loop would run to its timeout and report IDLE either way.
mutate "idle: POLLIN ignored" http.c \
    '            if (pfd.revents & POLLIN) {' \
    '            if (pfd.revents & 0) {' http_test

# Data misreported as a close. Both are failures, so the verdict stays red and
# only the TEXT changes -- but "the server answered" and "the server hung up"
# want different fixes, and a rule author reading the wrong one looks in the
# wrong place. The distinction is the reason these are separate reasons.
mutate "idle: data reported as a close" http.c \
    '                resp->close_reason = HTTP_CLOSE_DATA;
                break;
            }' \
    '                resp->close_reason = HTTP_CLOSE_FIN;
                break;
            }' http_test

# The verdict. An idle wait that passes on data or a close is an assertion that
# can never go red -- it would report green for exactly the two server bugs it
# was written to catch.
mutate "idle: data treated as a pass" assert.c \
    '    case HTTP_CLOSE_DATA:' \
    '    case HTTP_CLOSE_DATA:
        return 1;' assert_test

mutate "idle: an unperformed wait treated as a pass" assert.c \
    '        snprintf(why, whylen,
                 "no idle wait was performed, so a %ld ms idle assertion "
                 "cannot be judged", wait_ms);
        return 0;' \
    '        snprintf(why, whylen,
                 "no idle wait was performed, so a %ld ms idle assertion "
                 "cannot be judged", wait_ms);
        return 1;' assert_test

# The floor. Zero is rejected because a wait of no time polls for nothing and
# passes unconditionally; without the bound a rule file can spell exactly that.
mutate "idle: zero-wait floor removed" rules.c \
    '            if (ms < 1 || ms > MAX_IDLE_MS) {
                die("%s:%d: expect_idle %ld out of range (1..%d ms)",' \
    '            if (ms < 0 || ms > MAX_IDLE_MS) {
                die("%s:%d: expect_idle %ld out of range (1..%d ms)",' \
    rules_test

# The guard against asserting on a response the wait never collected. Without
# it a case can carry expect_not against an empty buffer and report green
# having looked at nothing.
mutate "idle: response-expectation guard removed" rules.c \
    '        if (tc->saw_idle && tc->n_expects > 0) {' \
    '        if (0 && tc->n_expects > 0) {' rules_test

# The exclusion against the opposite assertion. Both directives would run, and
# whichever was evaluated first would decide a verdict the other contradicts.
mutate "idle: close-deadline exclusion removed" rules.c \
    '            if (PX(saw_close_within)) {
                die("%s:%d: expect_close_within and expect_idle are "' \
    '            if (0) {
                die("%s:%d: expect_close_within and expect_idle are "' \
    rules_test

# The runtime bound, the idle-wait counterpart of the close-deadline guard
# above. Without it a case parks past the per-request budget and stalls the run
# somewhere the operator has no reason to look.
mutate "idle: wait-past-timeout guard removed" prober.c \
    '        if (cases[c].saw_idle
            && cases[c].idle_ms >= opt_timeout_ms)' \
    '        if (cases[c].saw_idle
            && cases[c].idle_ms >= opt_timeout_ms * 1000000)' \
    check_test.sh

# ---- open_conns -------------------------------------------------------------

# The lower bound on the parked-connection count. Without it `open_conns 0` is
# accepted and parses to the off value, so a saturation case silently opens
# nothing -- the same class as repeat's count check.
mutate "open_conns: lower-bound check removed" rules.c \
    '            if (count < 1 || count > MAX_OPEN_CONNS) {' \
    '            if (count < 0 || count > MAX_OPEN_CONNS) {' rules_test

# The vacuity guard. Held connections that no probe assertion reads are a test
# that asserts nothing; without this a case can park connections and report
# green having observed none of them.
mutate "open_conns: probe-assertion guard removed" rules.c \
    '        if (tc->open_conns > 0 && tc->n_probes == 0) {' \
    '        if (0 && tc->n_probes == 0) {' rules_test

# ---- concurrent -------------------------------------------------------------

# The floor. `concurrent 1` is the ordinary single-request path wearing the
# directive's name, so without this a rule file can claim a concurrency test that
# holds nothing in flight and asserts nothing about overlap.
mutate "concurrent: floor of 2 lowered to 1" rules.c \
    '            if (count < 2 || count > MAX_CONCURRENT) {' \
    '            if (count < 1 || count > MAX_CONCURRENT) {' rules_test

# The observability guard. The probe snapshots bracketing the fan are the ONLY
# thing that observes the overlap; without this a case pays for N connections and
# asserts exactly what one request already asserted.
mutate "concurrent: delta/probe requirement removed" rules.c \
    '        if (tc->concurrent > 0 && tc->n_deltas == 0 && tc->n_probes == 0) {' \
    '        if (0 && tc->n_deltas == 0 && tc->n_probes == 0) {' rules_test

# abort/hold/expect_idle each return before the read half runs, so a fan carrying
# one collects no responses at all. Without this guard that case loads and
# reports green having read nothing.
mutate "concurrent: non-reading directive guard removed" rules.c \
    '        if (tc->concurrent > 0 && (tc->saw_abort || tc->saw_hold' \
    '        if (0 && (tc->saw_abort || tc->saw_hold' rules_test

# The pipeline exclusion. A pipeline is ordered on ONE connection, so without
# this guard a case can carry both and the driver silently picks the concurrent
# path -- running something other than what the file spells.
mutate "concurrent: block exclusion removed" rules.c \
    '        if (tc->concurrent > 0 && tc->n_blocks > 0) {' \
    '        if (0 && tc->n_blocks > 0) {' rules_test

# The timing guard that used to live here (`concurrent` + recv_slow /
# expect_close_within rejected at load time) was LIFTED by S-4, and its mutant
# was removed with it rather than left behind: a gate that no longer exists
# cannot be broken, so the mutant would have passed unconditionally and reported
# a false green. What follows are the two mutants that guard the drain behaviour
# the lift depends on.

# The drain. Restoring the in-order blocking read is the exact regression the
# lift would be unsafe under: it is what charged an earlier leg's read time to
# every later leg's clock. Caught by the readback fixture, which makes leg 0's
# answer depend on the client having drained a LATER leg -- a dependency an
# in-order drain deadlocks on. Note a reverse-answering fixture does NOT catch
# it (the kernel buffers the other legs while the drain blocks on leg 0), which
# is why the fixture is built the way it is.
#
# It must be a TRUE in-order drain, and getting this wrong once already
# produced a false green. The obvious `if (i > 0) continue` is NOT this
# control: it drops legs 1..N-1 from the pollfd set permanently, so they are
# never read even after leg 0 finishes. That breaks the fan far more broadly
# than the claim -- the earlier barrier assertion reds simply because N-1
# replies are never collected -- and it therefore proves nothing about whether
# assertion 165's later-leg readback dependency is pinned.
#
# What follows advances the LOWEST-INDEX non-terminal leg only, which is
# exactly the pre-S-4 semantics: leg i+1 is not read until leg i is terminal.
# Every leg is still eventually read, so a fan whose legs are independent still
# completes and the barrier assertion stays green; only a fan whose earlier leg
# depends on a LATER leg being drained deadlocks, which is assertion 165 and
# nothing else.
mutate "concurrent: drain serialized (legs read in index order, blocking)" http.c \
    '            if (!http_read_state_pollable(&sts[i], now)) {
                    continue;
                }' \
    '            if (!http_read_state_pollable(&sts[i], now) || nfds > 0) {
                    continue;
                }' \
    http_test

# The paced close-deadline triple must stay rejected. Dropping the gate lets a
# case load whose close_ms includes the client's own recv_slow gates while the
# README defines that number as the server's close time -- a prompt server
# reported as late, blamed by name. Narrow on purpose: the mutant only has to
# make the triple load, since each PAIR loading is correct and is asserted
# separately.
mutate "concurrent: paced close-deadline triple accepted (unmeasurable)" rules.c \
    '        if (tc->concurrent > 0 && tc->saw_recv_slow && tc->saw_close_within) {' \
    '        if (tc->concurrent < 0 && tc->saw_recv_slow && tc->saw_close_within) {' \
    rules_test

# The poll() timeout clamp. Removing it restores the raw narrowing the S-4
# drain shipped: the 8x whole-exchange budget of a large accepted -t exceeds
# INT_MAX, narrows to a negative int, and poll() reads that as "wait forever" --
# the harness hangs silently instead of timing out. Caught by the boundary
# assertions, which are the only way to reach these values (a real exchange
# would need weeks of wall time).
mutate "poll timeout: oversized wait not clamped (negative = infinite poll)" http.c \
    '    if (wait > INT_MAX) {
        return INT_MAX;
    }' \
    '    if (wait > INT_MAX && wait < 0) {
        return INT_MAX;
    }' \
    http_test

# The per-read idle deadline, in the wakeup calculation. Dropping it there is
# the F1 regression exactly as it shipped: the deadline still exists and is
# still checked, but poll() never wakes for it, so a silent peer sleeps until
# the 8x whole-exchange budget instead of timeout_ms. Measured at 2401 ms
# against a 300 ms timeout where the pre-S-4 blocking reader took 316 ms.
# Caught by the N=1 ceiling, which is the assertion that names WHICH deadline
# ended the read -- the pre-existing floor-only assertions stayed green through
# the entire regression and are why it shipped.
mutate "idle timeout: dropped from the poll wakeup (8x inflation)" http.c \
    '    } else if (st->idle_deadline > 0 && st->idle_deadline < wake) {
        wake = st->idle_deadline;
    }' \
    '    }' \
    http_test

# The idle deadline must be held PER LEG, not recomputed from timeout_ms
# whenever the leg is stepped. Refreshing it on every step means any reason the
# shared poll() loop wakes -- including a chatty sibling's traffic -- postpones
# a silent leg's deadline forever. This is invisible at N=1, where there is no
# sibling to do the postponing, so the N=1 ceiling does NOT catch it; the fan
# fixture with one talkative leg and three silent ones is what does.
mutate "idle timeout: clock refreshed every step (sibling postpones it)" http.c \
    '    if (st->not_before != 0 && now >= st->not_before) {
        st->paced_sleep_ms += st->not_before - st->gate_start;' \
    '    st->idle_deadline = now + st->timeout_ms;

    if (st->not_before != 0 && now >= st->not_before) {
        st->paced_sleep_ms += st->not_before - st->gate_start;' \
    http_test

# The pacing gate must not be cancelled by readiness. Polling a gated leg lets
# data arriving early satisfy the poll and step the leg before its delay has
# elapsed, which is recv_slow silently not pacing -- the defect S-5 exists to
# catch, rebuilt in the drain. Reds assertion 104 (N=1) and 169 (the fan).
mutate "concurrent: paced leg polled anyway (gate cancelled by readiness)" http.c \
    '    return !st->done && now >= st->not_before;' \
    '    return !st->done && now * 0 >= st->not_before * 0;' \
    http_test

# The FAN-ONLY half of the pacing gate, and the reason spawn_fan_paced() exists.
#
# The mutant above breaks the predicate itself, so it reds the N=1 pacing case
# too -- which is how it was being caught before there was any concurrent
# recv_slow fixture at all, making it a false control for the fan (PR #151 F4).
# This one disables the gate ONLY at the fan's pollfd-selection site, leaving
# http_read_response()'s N=1 path untouched. A gated leg then re-enters the
# pollfd set and a sibling's readiness steps it before its delay elapsed.
#
# VERIFIED to red assertion 169 ALONE, with 102/104/105 (the N=1 pacing case)
# staying GREEN -- which is exactly the isolation the single mutant above could
# not provide. Before spawn_fan_paced() existed this mutation SURVIVED the whole
# suite.
mutate "concurrent: fan re-polls a gated leg (fan-only pacing gate)" http.c \
    '                if (!http_read_state_pollable(&sts[i], now)) {' \
    '                if (0 && !http_read_state_pollable(&sts[i], now)) {' \
    http_test

# Failure attribution, half one: FIRST BY INDEX. Dropping the break lets each
# later failing index overwrite the verdict, so the HIGHEST failing index is
# reported instead of the lowest. Deterministic, not a timing race -- the
# attribution loop scans terminal legs in ascending index order -- but it
# inverts the documented rule, and the reported leg then depends on which
# legs happen to fail rather than on the contract. Needs two legs failing in
# ONE iteration to be visible at all, which is what spawn_fan_two_bad()
# supplies; before it existed this mutation SURVIVED. Reds 170 and 171.
mutate "concurrent: fan blames the last failing leg, not the first by index" http.c \
    '                rc = -1;
                break;' \
    '                rc = -1;' \
    http_test

# Failure attribution, half two: the blamed leg's OWN error slot. The leg NUMBER
# and the quoted TEXT come from different places (the index from the loop, the
# text from errs + i * HTTP_LEG_ERRLEN), so a slot-indexing drift names the right
# leg and quotes a sibling's failure -- exactly what the per-leg slots replaced a
# shared buffer to prevent. VERIFIED to red assertion 171 ALONE with 170 green,
# which is why the two assertions are separate rather than one combined check.
mutate "concurrent: fan quotes a sibling's error slot for the blamed leg" http.c \
    '                         i + 1, n, errs + (size_t) i * HTTP_LEG_ERRLEN);' \
    '                         i + 1, n, errs + (size_t) (i + 1) * HTTP_LEG_ERRLEN);' \
    http_test

# THE ordering mutant, and the reason the barrier fixture exists: read each leg's
# response inside the write loop instead of after it. Every request is still sent
# and every response still collected, so response-shape assertions alone cannot
# tell the difference -- only a server that refuses to answer until all N have
# arrived can, which is what spawn_barrier() does.
mutate "concurrent: fan serialized (leg read before the next is written)" http.c \
    '        sent_at[i] = now_ms();' \
    '        sent_at[i] = now_ms();
        { int mco = 0; (void) http_read_response(fds[i], timeout_ms, recv_opt,
              want_close, framed, sent_at[i], &resps[i], &mco, errbuf, errlen); }' \
    http_test

# ---- CLI --------------------------------------------------------------------

# The flag not taking effect is the failure that matters: --check would fall
# through to the request loop and try to connect, which against a host with no
# server reads as "the rule file is bad" rather than as a broken flag.
mutate "--check: flag does not take effect" prober.c \
    '            opt_check = 1;' '            opt_check = 0;' check_test.sh

# ---- probe schema -----------------------------------------------------------

# The schema exists to catch emitter drift on fields no rule happens to name,
# so the mutation is a rename in the emitter itself. ngx_test_probe.c is not
# compiled by build.sh (it needs real nginx headers), which is why the schema
# suite reads it as text -- and why mutating it does not break the build.
mutate "schema: emitter renames a field" ../src/ngx_test_probe.c \
    '"\"fds\":%i,"' \
    '"\"descriptors\":%i,"' \
    schema_emitter_test.sh

# The other direction: a member the schema does not name. Without the reverse
# sweep the schema decays into a subset that passes forever while describing
# less and less of the document.
mutate "schema: emitter adds an undeclared field" ../src/ngx_test_probe.c \
    '"\"page_size\":%uz,"' \
    '"\"page_size\":%uz,\"undeclared\":1,"' \
    schema_emitter_test.sh

# The fixture side: schema_test.c is what proves the DOCUMENT still carries
# what the schema promises, independently of the emitter's text.
mutate "schema: zone-absent variant leaks a zone member" schema_test.c \
    '"\"zone\":{\"present\":false}}";' \
    '"\"zone\":{\"present\":false,\"name\":\"stale\"}}";' \
    schema_test

# The reverse sweep's anchor. Without it the needle is a bare suffix match, so
# a stray member hides behind any declared key ending in the same text --
# "pages_free" behind "slab_pages_free" -- and is reported as covered.
# SC2016: the anchors are literal source text to match, not shell to expand --
# $leaf and $schema must reach the file as-is.
# shellcheck disable=SC2016
mutate "schema: reverse-sweep anchor removed" schema_emitter_test.sh \
    '        if ! grep -qE "\"([[:alnum:]_]+\.)?$leaf\"" "$schema"; then' \
    '        if ! grep -q "\"[[:alnum:]_.]*$leaf\"" "$schema"; then' \
    schema_emitter_test.sh


# ---- syscall budget parser -------------------------------------------------

# The errors column. strace's -c table emits `errors` only on rows that HAD
# errors, so counting the calls column backwards from the syscall name reads
# ERRORS on exactly those rows -- and reads them LOW, which is to say under
# every ceiling. A budgeted openat that starts failing would be compared as 7
# instead of 200 and the budget gate would pass while massively breached, which
# is the vacuous-gate class the syscall-allowlist scenario exists to catch.
#
# This is the mutation the parser was extracted from the driver FOR. CI's real
# captures are all clean rows, so the scenario cannot exercise the shape that
# breaks it: without a fixture test this revert stays green forever.
# SC2016: literal source text to match, not shell to expand.
# shellcheck disable=SC2016
mutate "syscall budget: calls column counted backwards past errors" lib.sh \
    'NF >= 5 && $NF ~ /^[a-z][a-z0-9_]*$/ && $4 ~ /^[0-9]+$/ { print $NF, $4 }' \
    'NF >= 5 && $NF ~ /^[a-z][a-z0-9_]*$/ && $(NF-1) ~ /^[0-9]+$/ { print $NF, $(NF-1) }' \
    syscall_budget_test.sh

# Absent-family-means-zero. If NOT ONE member of a budgeted family appears in
# the table, the capture is not what the caller thinks it is -- a changed strace
# format, a truncated summary, a typo in the family string -- and answering 0
# gives the most comfortable possible answer to a question that could not be
# evaluated. Every ceiling then passes. The rule is deliberately narrow: an
# absent member of a family that WAS observed still contributes zero, and
# assertion 13 pins that boundary, so this mutant cannot be "fixed" by making
# the whole thing stricter.
# shellcheck disable=SC2016
mutate "syscall budget: an absent family sums to zero instead of erroring" lib.sh \
    '    [ "$seen" -eq 1 ] || return 1' \
    '    [ "$seen" -eq 1 ] || sum=0' \
    syscall_budget_test.sh

# First-character-only member validation. `case "$name" in [a-z]*)` tests the
# first character and nothing else, so "open!", "open*" and "open-at" all pass
# it -- and family-wide `seen` then lets the one VALID member (openat) satisfy
# the whole family, returning rc=0 with openat's count alone. That is the
# name-wise budget the family form exists to replace, restored silently by any
# future edit to a family string. The "Openat" assertion does not catch it: that
# one tests the first-character rule, which this mutation keeps intact.
# shellcheck disable=SC2016
mutate "syscall budget: family member validated by first character only" lib.sh \
    "            '' | [!a-z]* | *[!a-z0-9_]*) return 1 ;;" \
    "            [a-z]*) ;; *) return 1 ;;" \
    syscall_budget_test.sh

# The pid-blind denominator. strace attaches to ONE pid and -f does not follow a
# replacement worker (the MASTER forks it, not the tracee), so counting any
# status line credits responses whose syscalls were never traced. The denominator
# inflates to the full burst while the numerator holds only the tracee's calls,
# and the mutant's extra opens land off-tracee -- every assertion passes on the
# exact behaviour they exist to catch. This restores the original matcher.
# shellcheck disable=SC2016
mutate "syscall budget: served counted without binding the response to the traced pid" lib.sh \
    "    grep -qE '^HTTP/1\.[01] 200( |\$)' <<<\"\${status_line%\$'\\r'}\" || return 1" \
    "    grep -qE '^HTTP/1\.[01] [0-9]{3}' <<<\"\$resp\" && return 0 || return 1" \
    syscall_budget_test.sh

# grep anchors ^/\$ per LINE, so matching the status over the WHOLE document
# accepts a status-shaped line anywhere in it -- including the body, which in
# this scenario echoes request-influenced content. A 500 carrying
# `HTTP/1.1 200 OK` on its own line then counts toward the denominator. The
# control this row protects has to use an UNPREFIXED body line: a prefixed one
# fails the regex on the buggy and the fixed implementation alike.
# shellcheck disable=SC2016
mutate "syscall budget: status matched over the whole response, not the status line" lib.sh \
    "    status_line=\"\${resp%%\$'\\n'*}\"" \
    "    status_line=\"\$resp\"" \
    syscall_budget_test.sh


# ---- probe_baseline --------------------------------------------------------

# The separate list. `probe_baseline` and `delta` share an evaluator but not an
# origin snapshot, so collecting them into one list still parses, still runs,
# and silently judges every baseline assertion against the per-case
# before-snapshot -- which is precisely the blind spot the directive exists to
# close. It would report green while asserting nothing new.
mutate "probe_baseline: collected into the delta list" rules.c \
    'parse_assert(cases[n - 1].baselines, &cases[n - 1].n_baselines,
                         directive, trim(arg), file, lineno);' \
    'parse_assert(cases[n - 1].deltas, &cases[n - 1].n_deltas,
                         directive, trim(arg), file, lineno);' \
    rules_test

# The substring-operator rejection. `~` on a numeric difference is meaningless;
# without the guard the case parses and the operator is judged at evaluation
# time against a subtraction, where its verdict is arbitrary rather than wrong.
mutate "probe_baseline: substring-operator guard removed" rules.c \
    'if ((strcmp(directive, "delta") == 0
         || strcmp(directive, "probe_baseline") == 0)
        && strcmp(op, "~") == 0)' \
    'if (strcmp(directive, "delta") == 0
        && strcmp(op, "~") == 0)' \
    rules_test

# The free of the baseline list. A plain build cannot catch this -- leaking the
# per-baseline strings is not a behavioural difference and rules_test exits 0 --
# so it is opted into a SAN=1 build (6th arg), where LSan reports the leak and
# the suite goes red exactly as the CI asan leg would. This is the mutant the
# per-mutant SAN opt-in was built for (proven s65).
mutate "probe_baseline: baseline strings leaked" rules.c \
    '    for (i = 0; i < tc->n_baselines; i++) {
        free(tc->baselines[i].path);
        free(tc->baselines[i].op);
        free(tc->baselines[i].literal);
    }' \
    '    for (i = 0; i < tc->n_baselines && 0; i++) {
        free(tc->baselines[i].path);
        free(tc->baselines[i].op);
        free(tc->baselines[i].literal);
    }' \
    rules_test san


# ---- dechunk ---------------------------------------------------------------

# The chunk-size overflow guard. A size wide enough to wrap size_t would be
# accepted and then handed to memcpy as a length -- the request-smuggling
# primitive this decoder exists not to reproduce.
mutate "dechunk: chunk-size overflow guard removed" http.c \
    'if (value > SIZE_MAX / 16 || value * 16 > SIZE_MAX - (size_t) d) {
            return HTTP_DECHUNK_BAD_SIZE;
        }' \
    'if (value > SIZE_MAX) {
            return HTTP_DECHUNK_BAD_SIZE;
        }' \
    http_test

# The bare-LF rejection in the size line. Scanning to the next CR alone walks
# THROUGH a bare-LF line ending and finds a later line's CRLF, so a malformed
# size line is accepted and the decode resumes at the wrong offset -- payload
# silently reinterpreted as framing. This is the parser differential that lets
# two hops disagree about where a chunk starts.
mutate "dechunk: bare-LF size line accepted" http.c \
    "while (p < end && *p != '\\r' && *p != '\\n') {" \
    "while (p < end && *p != '\\r') {" \
    http_test

# The declared-size bounds check. Without it a chunk header that claims more
# bytes than arrived reads past the end of the body buffer.
mutate "dechunk: declared-size bounds check removed" http.c \
    'if ((size_t) (end - p) < size) {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_TRUNCATED;
            return;
        }' \
    'if (size == SIZE_MAX) {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_TRUNCATED;
            return;
        }' \
    http_test

# The missing-terminator verdict. Reporting OK here would hand a rule the
# decoded prefix of a TRUNCATED response and let every body assertion pass on
# it -- the `[no-last-chunk]` false PASS in full.
mutate "dechunk: missing 0-chunk reported as success" http.c \
    'resp->dechunk_status = HTTP_DECHUNK_NO_LAST_CHUNK;' \
    'resp->dechunk_status = HTTP_DECHUNK_OK;' \
    http_test

# The CRLF-after-data check. Chunk data must be followed by its terminator;
# without the check a chunk whose length disagrees with its framing decodes
# into the next size line rather than failing.
mutate "dechunk: post-data CRLF check removed" http.c \
    'if (end - p < 2 || p[0] != '"'"'\r'"'"' || p[1] != '"'"'\n'"'"') {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_BAD_CRLF;
            return;
        }' \
    'if (end - p < 0) {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_BAD_CRLF;
            return;
        }' \
    http_test

# The digit requirement. An empty size line is not a zero-length chunk; without
# this an absent size decodes as a terminator and truncates the body silently.
mutate "dechunk: empty size line accepted" http.c \
    'if (digits == 0) {
        return HTTP_DECHUNK_BAD_SIZE;
    }' \
    'if (digits < 0) {
        return HTTP_DECHUNK_BAD_SIZE;
    }' \
    http_test

# The oracle routing. If the body assertions keep reading the raw wire bytes
# after a successful decode, `dechunk` becomes decorative: every body~ then
# matches against text that still carries the chunk size lines.
mutate "dechunk: body oracles read raw bytes after decode" assert.c \
    'if (resp->dechunk_status == HTTP_DECHUNK_OK && resp->decoded != NULL) {' \
    'if (0) {' \
    assert_test


# ---- gunzip ----------------------------------------------------------------

# The encoding gate. Reporting NOT_ENCODED as OK would hand a rule the raw
# compressed bytes as "the body" -- every body~ then matches gzip magic instead
# of the payload the client would have decompressed, a silent false verdict.
mutate "gunzip: unencoded body decoded as success" http.c \
    'resp->gunzip_status = HTTP_GUNZIP_NOT_ENCODED;' \
    'resp->gunzip_status = HTTP_GUNZIP_OK;' \
    gunzip_test

# The truncated-stream verdict. A gzip body cut before its terminator inflates
# cleanly up to the cut; reporting OK there hands a rule the decoded PREFIX of a
# response the server dropped mid-transfer -- the truncation false PASS gunzip
# exists to catch.
mutate "gunzip: truncated stream reported as success" http.c \
    'rc = HTTP_GUNZIP_TRUNCATED;
                break;' \
    'rc = HTTP_GUNZIP_OK;
                break;' \
    gunzip_test

# The oracle routing. If the body assertions keep reading the decoded (or raw)
# bytes after a successful inflate, `gunzip` becomes decorative: every body~
# then matches against still-compressed content.
mutate "gunzip: body oracles read compressed bytes after inflate" assert.c \
    'if (resp->gunzip_status == HTTP_GUNZIP_OK && resp->inflated != NULL) {' \
    'if (0) {' \
    assert_test


# ---- json_sort -------------------------------------------------------------

# The parse gate. Reporting a body that did not parse as OK would hand a rule the
# raw (un-canonicalized) bytes as "the body" -- a body_sha256 then hashes the
# wrong order, and the whole point of json_sort (key-order independence) is lost
# while the case still passes. This is the false PASS json_sort exists to catch.
mutate "json_sort: unparseable body reported as canonicalized" http.c \
    'resp->json_sort_status = HTTP_JSON_SORT_NOT_JSON;
        return;
    }

    if (json_canonicalize' \
    'resp->json_sort_status = HTTP_JSON_SORT_OK;
        return;
    }

    if (json_canonicalize' \
    http_test

# The oracle routing. If the body assertions keep reading the inflated (or lower)
# bytes after a successful json_sort, `json_sort` becomes decorative: a
# body_sha256 then hashes whatever key order the server sent, not the canonical
# one -- the key-order-independence guarantee silently gone.
mutate "json_sort: body oracles read un-canonicalized bytes" assert.c \
    'if (resp->json_sort_status == HTTP_JSON_SORT_OK && resp->canon != NULL) {' \
    'if (0) {' \
    assert_test

# Exponent normalization. If number_canon stops lowercasing the exponent and
# stripping its sign/leading zeros, then 1E+05 and 1e5 canonicalize to DIFFERENT
# bytes -- two spellings of the same value no longer hash alike, so a
# body_sha256 that should be spelling-independent fails against an equivalent
# server response. json_test's exponent case is the catch.
mutate "json_sort: exponent left un-normalized" json.c \
    "out[o++] = 'e';" \
    "out[o++] = *t;" \
    json_test

# The body-gate classifier. If expect_reads_body stops recognizing a body kind,
# the case-loop gate stops skipping it on a failed transform -- the exact "body
# oracle runs against a rejected lower tier" regression. assert_test's
# expect_reads_body cases are the catch. (The one-line loop guard in prober.c
# that consumes this classifier has no unit suite of its own; the classifier it
# calls is what carries the tested behavior, so the mutation lands here.)
mutate "json_sort: a body kind misclassified as non-body" assert.c \
    'case EXPECT_BODY_SHA256:
        return 1;' \
    'case EXPECT_BODY_SHA256:
        return 0;' \
    assert_test


# ---- fake backend: script parser -------------------------------------------

# The stated mutation proof for the daemon. A dropped fault leaves the scenario
# exercising the HAPPY path while its name and its TAP output both claim it is
# exercising a failure -- and a scenario that tests nothing passes very
# reliably. Skipping an unknown action rather than dying is how that ships.
mutate "backend: unknown action silently dropped" backend.c \
    '    die("%s:%d: unknown fault action \"%s\"", file, lineno, name);' \
    '    (void) file; (void) lineno; return BACKEND_ACT_RST;' \
    backend_test

# The parameter requirements. Every one of these actions is a no-op at its
# zeroed default, so a fault missing its parameter parses, runs, and does
# nothing the script asked for.
mutate "backend: truncate accepts a missing after=" backend.c \
    '        if (!have_after) {
            die("%s:%d: action=truncate needs after=<bytes>", file, lineno);
        }' \
    '        if (0) {
            die("%s:%d: action=truncate needs after=<bytes>", file, lineno);
        }' \
    backend_test

mutate "backend: lie_bytes accepts delta=0" backend.c \
    '        if (f->delta == 0) {' '        if (0) {' backend_test

# 1-based occurrences. Accepting 0 gives a fault that reads as configured in the
# file and never matches at run time -- configured and absent at once.
mutate "backend: a 0 occurrence is accepted" backend.c \
    '    if (f->nth < 1) {' '    if (f->nth < 0) {' backend_test

# The proto is deliberately not defaulted: guessing memcached makes a redis
# script that forgot the line answer memcached replies to RESP commands, and the
# parse errors then point at the client rather than at the missing line.
mutate "backend: a missing proto defaults instead of failing" backend.c \
    '    if (!have_proto) {' '    if (have_proto < 0) {' backend_test

# Specificity in fault lookup. Without the exact-match-wins rule a script cannot
# say "every get lies, except the third one, which resets": the wildcard would
# swallow the exception and the excepted case would never fire.
mutate "backend: an exact occurrence no longer beats a wildcard" backend.c \
    '        if (f->nth == nth) {' '        if (f->nth == nth && 0) {' backend_test

# ---- fake backend: protocol parsers ----------------------------------------

# The use-after-return that shipped in the first draft. Arguments must point
# into the CALLER's buffer; tokenising a stack copy leaves them dangling at
# return, and the daemon -- which returns before it uses them -- answered
# `get hello` with a key of "<\x7f". Every in-process test missed it, because a
# test reads args while the parser's frame is still live.
mutate "backend: memcached args point into a parser local" backend.c \
    '    line = (char *) buf;' \
    '    { static char sbuf[1024]; memcpy(sbuf, buf, line_len + 1); line = sbuf; }' \
    backend_test

# The set that is acknowledged but not stored. A fake answering STORED to a set
# it discarded makes the NEXT get a miss, which reads as a cache bug in whatever
# module is under test rather than as a defect in the fake.
mutate "backend: a memcached set is acknowledged but not stored" backend.c \
    '        if (cmd->n_args >= 1 && cmd->data != NULL && cmd->data_len >= 0) {' \
    '        if (0) {' \
    fakesrv_test.sh

# A malformed data length is a protocol error, not a fatal one: these bytes come
# off a socket, so dying lets any client take the daemon down mid-scenario and
# report a harness crash instead of the protocol error it actually saw.
mutate "backend: a malformed data length is accepted" backend.c \
    '    if (*stop != '"'"'\0'"'"' || errno == ERANGE) {
        return -2;
    }' \
    '    if (errno == ERANGE) {
        return -2;
    }' \
    backend_test

# The nil bulk string. A client that cannot tell $-1 from $0 cannot tell a
# missing key from a key holding "" -- a distinction cache code treats as
# load-bearing.
# SC2016: `$-1` and `$0` are RESP bulk-string markers in the C source being
# patched, not shell expansions -- the single quotes must keep them literal.
# shellcheck disable=SC2016
mutate "backend: a RESP miss renders an empty string, not nil" backend.c \
    '            buf_append(&buf, &len, &cap, "$-1\r\n", 5);' \
    '            buf_append(&buf, &len, &cap, "$0\r\n\r\n", 6);' \
    backend_test

# Incompleteness and error must stay distinct. Collapsed, a client sending
# garbage is indistinguishable from one that is merely slow, so the daemon waits
# for a completion that is never coming and the scenario fails on a timeout
# pointing nowhere near the cause.
mutate "backend: RESP trailing garbage read as incomplete" backend.c \
    '        if (*stop != '"'"'\0'"'"') {
            return -1;
        }
    }

    if (argc < 1 || argc > BACKEND_MAX_ARGS) {' \
    '        if (*stop != '"'"'\0'"'"') {
            return 0;
        }
    }

    if (argc < 1 || argc > BACKEND_MAX_ARGS) {' \
    backend_test

# ---- fake backend: the daemon ----------------------------------------------

# The atomic portfile. Writing in place is visible to a polling shell as a
# zero-length file, which parses as an empty port roughly one run in twenty --
# the kind of flake that gets a CI leg disabled rather than fixed.
mutate "backend: portfile written non-atomically" fakesrv.c \
    '    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp)) {' \
    '    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int) sizeof(tmp)) {' \
    fakesrv_test.sh

# The reply must actually reach the socket. A daemon whose codecs are perfect
# and whose write path is broken passes backend_test completely.
mutate "backend: replies are never written" fakesrv.c \
    '                n = write(c->fd, c->out + c->out_off, want);' \
    '                n = (ssize_t) want;' \
    fakesrv_test.sh

# The journal's accept count is the one observable that proves keepalive reuse.
# Stuck at a constant it reports reuse for every run, including the runs that
# opened a fresh connection every time.
mutate "backend: the accept count is not incremented" fakesrv.c \
    '                    accepts_total++;' \
    '                    accepts_total += 0;' \
    fakesrv_test.sh

# Destructive parsing vs retry-on-incomplete. The parser tokenises in place and
# the caller re-invokes it as more data arrives, so a return of 0 must leave the
# buffer byte-identical. Deciding completeness AFTER tokenising left the retry
# parsing NUL-punched bytes, and a valid `set` came back as a protocol error.
# It only reproduced when the data block landed in a later read() than its
# command line -- every local run wrote it in one go and passed; all four CI
# legs failed at once.
mutate "backend: completeness decided after the buffer is mutated" backend.c \
    '        if (len < need + 1) {
            return 0;                        /* buffer untouched */
        }' \
    '        if (len < need + 1 && 0) {
            return 0;                        /* buffer untouched */
        }' \
    backend_test

# The zero-length seed marker. A scenario that seeds `""` and gets two literal
# quote bytes stored instead asserts against the wrong payload -- and the
# framing edge case it exists to exercise (an empty value between two CRLFs) is
# never reached at all, while the scenario still passes.
mutate "backend: the empty-seed marker stores its quotes" backend.c \
    '                if (strcmp(value, "\"\"") == 0) {' \
    '                if (strcmp(value, "\"\"") == 0 && 0) {' \
    backend_test

# ---- framed-mode single-response reader (E1) --------------------------------

# The stop itself. Without the break a framed read runs on past the end of the
# one response -- against a keep-alive server that never closes, that is the
# whole-exchange deadline, so the test that expects a prompt HTTP_CLOSE_FRAMED
# hangs until the per-mutant timeout. A framed reader that does not stop is the
# defect this whole item exists to prevent.
# S-4: the loop's `break` is now `goto finish` -- the terminal that transfers
# buf to resp->raw. Removing it makes a framed response never terminate.
mutate "framed: completion exit removed" http.c \
    '                st->resp->close_ms = elapsed_since(st->sent_at);
                if (st->conn_open != NULL) {
                    *st->conn_open = 1;
                }
                goto finish;
            }' \
    '                st->resp->close_ms = elapsed_since(st->sent_at);
                if (st->conn_open != NULL) {
                    *st->conn_open = 1;
                }
            }' http_test

# The truncation to one response. Leaving len at the full read folds a pipelined
# second response into the first's body, which the pipelined-read test asserts
# must not happen -- and E3 will drive the next request off exactly the surplus
# this drops.
mutate "framed: pipelined surplus not truncated" http.c \
    '            if (fs == HTTP_FRAMED_COMPLETE) {
                len = resp_len;' \
    '            if (fs == HTTP_FRAMED_COMPLETE) {
                len += 0;' http_test

# The unframeable-is-a-failure verdict. Falling through instead of returning -1
# leaves a response with no knowable end being read to a close that never comes:
# the unframeable test would hang to the deadline rather than fail cleanly, and
# on a real keep-alive connection this is the smuggling primitive the harness
# exists never to emit.
mutate "framed: unframeable response not rejected" http.c \
    '            if (fs == HTTP_FRAMED_UNFRAMEABLE) {
                snprintf(errbuf, errlen,' \
    '            if (0 && fs == HTTP_FRAMED_UNFRAMEABLE) {
                snprintf(errbuf, errlen,' http_test

# The bodiless-status rule in the classifier. If 204/304/1xx are not recognised
# as bodiless, a 204 with no Content-Length becomes UNFRAMEABLE (or waits for a
# body that never arrives): the bodiless-204 framed test goes red.
mutate "framed: 204 not recognised as bodiless" http.c \
    '    return (status >= 100 && status < 200) || status == 204 || status == 304;' \
    '    return (status >= 100 && status < 200) || status == -204 || status == 304;' \
    http_test

# The chunked terminator scan. Never recognising the 0-chunk means a chunked
# framed read never completes and hangs to the deadline -- the chunked framed
# test catches it.
mutate "framed: chunked 0-chunk terminator ignored" http.c \
    '        if (size == 0) {
            /* Terminating chunk seen.' \
    '        if (size == 0 && 0) {
            /* Terminating chunk seen.' http_test

# The disagreeing-Content-Length rejection. Dropping it lets two different
# lengths through as if benign -- the classic request-smuggling desync -- and
# the MALFORMED classifier test goes green when it must be red.
mutate "framed: disagreeing Content-Length accepted" http.c \
    '            if (*have_cl && value != *content_length) {
                return -1;
            }' \
    '            if (*have_cl && value != *content_length) {
                (void) 0;
            }' http_test

# The Content-Length addition-overflow guard. Dropping it lets a near-SIZE_MAX
# length wrap `hdr_bytes + content_length` to a small `need`, so `len < need`
# is false and the classifier forges COMPLETE with a truncated resp_len -- the
# near-SIZE_MAX Content-Length test flips from INCOMPLETE to COMPLETE.
mutate "framed: Content-Length overflow guard removed" http.c \
    '        if (content_length > SIZE_MAX - hdr_bytes) {
            return HTTP_FRAMED_INCOMPLETE;
        }' \
    '        if (content_length > SIZE_MAX - hdr_bytes && 0) {
            return HTTP_FRAMED_INCOMPLETE;
        }' http_test

# NOTE -- deliberately NO mutant for the chunk-size short-read guard
# (chunked_complete `(end - p) - 2 < size`). Reverting it to the wrapping
# `size + 2` form is NOT behaviourally observable: a near-SIZE_MAX `size` makes
# `size + 2` wrap to 0, the `(end - p) < 0` test is false, and control falls
# through to `p += size` -- but that huge offset wraps the POINTER modulo 2^64
# back onto a valid heap address, so `p[0]` reads live memory and neither the
# INCOMPLETE assertion nor ASan fires deterministically (verified SURVIVED under
# both plain and SAN builds). A guard whose only failure mode is an
# address-space-wrap OOB that lands back in-bounds cannot be honestly mutation-
# caught; the near-SIZE_MAX chunk-size test in http_test.c documents the intended
# INCOMPLETE, and code review is the gate here. The Content-Length sibling guard
# above DOES wrap to a small arithmetic value with no OOB, so its mutant is
# caught deterministically.


# --- pipeline block parser (rules.c) --------------------------------------

# The last-block-only rule for connection-ending directives. Dropping it accepts
# an abort/hold/idle on a non-last block, which would strand every block after it
# -- rules_test's "an abort on a non-last block dies" stops dying.
mutate "block: connection-ending directive on a non-last block accepted" rules.c \
    '                if (ends_conn && b + 1 < tc->n_blocks) {' \
    '                if (ends_conn && b + 1 < tc->n_blocks && 0) {' rules_test

# The no-send-line-in-a-block guard. Dropping it accepts a block with no request,
# which at run time would put zero bytes on the wire and read a phantom response
# -- rules_test's "a block with no send line dies" stops dying.
mutate "block: an empty block (no send) accepted" rules.c \
    '                if (blk->request_len == 0) {' \
    '                if (blk->request_len == 0 && 0) {' rules_test

# The pre-block per-exchange-directive guard. Dropping it lets a case drive part
# of itself flat (before the first block) and part in blocks -- two disjoint
# request shapes for one case. rules_test's "a per-exchange directive before the
# first block dies" stops dying.
mutate "block: a per-exchange directive before the first block accepted" rules.c \
    '            if (tc->n_blocks == 0
                && (tc->request_len != 0 || tc->n_pauses != 0' \
    '            if (0 && tc->n_blocks == 0
                && (tc->request_len != 0 || tc->n_pauses != 0' rules_test


# --- scenarios/property-fuzz (generator, not module code) -------------------
#
# The scenario's non-vacuity claims 2 and 3 (see driver.sh's header) live in
# driver.sh itself, a bash+gawk generator, not in prober's C. mutate()'s "file"
# and "suite" arguments are generic (a literal string replace plus a named
# suite to rerun), so both are wired here exactly the same way a C mutant is --
# the "build" step is a no-op for a text file (./build.sh does not read
# driver.sh), which is expected and harmless; failure mode 1 (did not compile)
# simply cannot apply to a mutation that touches no compiled source.
#
# Claim 1 (leak oracle is live) has NO entry here -- it cannot be wired
# cleanly, because the leak this property hunts is reported by code that
# compiles INTO the nginx/angie module (src/ngx_test_probe.c), and catching a
# mutation there needs a full module rebuild that mutate.sh's fixed
# ./build.sh step does not perform. See driver.sh's header for the documented,
# manually-run negative control that proves it instead.

# Claim 2: the PRNG must be seed-sensitive. Collapsing the seed to a constant
# (`seed * 0` rather than the safe-mutation `x * 0` this file uses elsewhere,
# because here the ZERO is the point: every seed becomes the same starting
# state) makes seed and seed+1 generate byte-identical rules -- driver.sh's own
# test 2 ("seed+1 ... produced a different rule") must catch that and does not
# merely SURVIVE by accident, because a stuck PRNG is exactly what test 2 exists
# to catch.
# SC2016: the single-quoted text is the gawk source inside driver.sh being
# patched, not a shell expansion -- must stay literal.
# shellcheck disable=SC2016
mutate "property-fuzz: PRNG ignores its seed" scenarios/property-fuzz/driver.sh \
    'x = seed + 0' \
    'x = seed * 0' scenarios/property-fuzz/mutate-suite.sh

# Claim 3: the file replayed in test 4 must be the ACTUAL saved rule test 3 ran
# against, not a fresh regeneration. Redirecting the save to a decoy path means
# the main run (test 3) executes against a rule that was never persisted where
# the driver's own failure diagnostics point -- "replay is `./prober <path>`"
# stops being true. The mutant breaks earlier than test 4 alone (the --check
# gate and test 3 itself fail first, against a missing/stale $GENRULE), which
# still proves the point: the suite goes red, exactly what a broken persistence
# guarantee should do.
# SC2016: the single-quoted text is a line of driver.sh's own bash being
# patched, not a shell expansion at THIS file's parse time -- must stay literal.
# shellcheck disable=SC2016
mutate "property-fuzz: generated rule not persisted to the replay path" \
    scenarios/property-fuzz/driver.sh \
    'build_rule "$SEED" > "$GENRULE"' \
    'build_rule "$SEED" > "$GENRULE.decoy"' scenarios/property-fuzz/mutate-suite.sh

# --- scenarios/stateful-property-fuzz (P2-G5 generator, not module code) -----
#
# The stateful scenario's PRNG/plan-persistence non-vacuity claims live in its
# driver.sh (a bash+gawk generator), wired exactly like property-fuzz's above.
# The lifecycle CHECKPOINT oracles (C1..C5) are NOT wired here -- catching them
# needs a real reload/kill to land on a booted server inside the per-mutant
# budget, so they are proven by the documented manually-run driver mutations in
# the scenario's driver.sh header (the sanctioned fallback, same as
# property-fuzz's leak-oracle claim 1).

# Claim: the step-plan PRNG must be seed-sensitive. Collapsing the seed to a
# constant makes seed and seed+1 generate byte-identical plans -- driver.sh's
# own test 2 ("seed+1 ... produced a different step plan") must catch it.
# SC2016: the single-quoted text is gawk source inside driver.sh being patched.
# shellcheck disable=SC2016
mutate "stateful-property-fuzz: PRNG ignores its seed" \
    scenarios/stateful-property-fuzz/driver.sh \
    'x = seed + 0' \
    'x = seed * 0' scenarios/stateful-property-fuzz/mutate-suite.sh

# Claim: the executed step plan must be persisted where the driver's diagnostics
# point. Redirecting the save to a decoy path means test 3 ("the executed step
# plan is saved ... for replay") finds an empty/absent $PLAN and reds.
# SC2016: the single-quoted text is a line of driver.sh's own bash being patched.
# shellcheck disable=SC2016
mutate "stateful-property-fuzz: step plan not persisted to the replay path" \
    scenarios/stateful-property-fuzz/driver.sh \
    'build_plan "$SEED"          > "$PLAN"
' \
    'build_plan "$SEED"          > "$PLAN.decoy"
' scenarios/stateful-property-fuzz/mutate-suite.sh

# --- scenarios/fault-matrix (P2-G6 named fault matrix, not module code) ------
#
# The branch under test is nginx's own upstream cleanup, which this repo cannot
# mutate in-budget (see the scenario driver's NON-VACUITY header). The
# deterministic cycle_used oracle is proven load-bearing here by CORRUPTING its
# baseline: BASE_USED is knocked down by one, so every healthy row reads a
# cycle_used != baseline and reds. This proves the exact cycle-pool oracle fires
# and raises the exit status (not merely prints). The fds CEILING oracle is
# proven by the documented-only CONTROL A (fds oscillates with the keepalive
# pool, so it is not a deterministic in-budget mutant). Anchored on the pid line,
# which runs AFTER BASE_USED is assigned in the warmup loop, so the corruption
# lands on a set variable.
# SC2016: the single-quoted text is a line of driver.sh's own bash being patched.
# shellcheck disable=SC2016
mutate "fault-matrix: cycle_used oracle vacuous (baseline corrupted, suite must still red)" \
    scenarios/fault-matrix/driver.sh \
    '    BASE_PID="$(snap_field "$wbody" pid)" || {' \
    '    BASE_USED=$((BASE_USED - 1))
    BASE_PID="$(snap_field "$wbody" pid)" || {' \
    scenarios/fault-matrix/mutate-suite.sh

# --- scenarios/deploy-canary (P2-H deployment canary/shadow verifier) -------
#
# The default (unmutated) tree boots CANDIDATE identical to CONTROL (D-2, one
# conf, one binary) -- so every row below patches driver.sh, in one of two
# ways: O1/O2/O3 set driver.sh's CANARY_ARM_SED, which the driver applies to
# the RENDERED $PROBER_PREFIX/conf/nginx.conf strictly between the control
# capture and the candidate reboot (a real candidate-only behavioural
# difference on the SECOND boot; the checked-in nginx.conf is never patched --
# patching it would arm BOTH legs identically, see that variable's comment in
# driver.sh), or O5/O7 patch driver.sh's own oracle
# constant (corrupting the expectation/bound, same "cannot mutate
# nginx's own crash or pool-bookkeeping machinery in-budget" boundary
# fault-matrix's header documents for its cycle_used oracle), then requires
# scenarios/deploy-canary/mutate-suite.sh to go red on the named oracle.
# O4 (latency bucket), O6 (lineage) and O8 (fd neutrality) are documented-only
# manual neg-controls in driver.sh's header, same tier as rss-slope's and
# fault-matrix's own by-hand controls -- not wired here.

# O1/O2/O3 arm the fault via CANARY_ARM_SED (driver.sh), applied to the
# RENDERED conf strictly between the control capture and the candidate
# reboot -- see that variable's own comment for why patching the checked-in
# nginx.conf directly does NOT work (it arms both legs identically, since D-2
# reboots the same source conf for both).
# SC2016: the single-quoted text is a line of driver.sh's own bash being patched.
# shellcheck disable=SC2016
mutate "deploy-canary: O1 status differential (candidate 500s on /canary)" \
    scenarios/deploy-canary/driver.sh \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-}"' \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-s/return 200 \"canary-stable-payload/return 500 \"canary-stable-payload/}"' \
    scenarios/deploy-canary/mutate-suite.sh

# shellcheck disable=SC2016
mutate "deploy-canary: O2 header differential (candidate-only header on /canary)" \
    scenarios/deploy-canary/driver.sh \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-}"' \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-/location \\/canary/a\\            add_header X-Canary-Debug leaked always;}"' \
    scenarios/deploy-canary/mutate-suite.sh

# shellcheck disable=SC2016
mutate "deploy-canary: O3 body differential (candidate flips one byte of /canary)" \
    scenarios/deploy-canary/driver.sh \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-}"' \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-s/canary-stable-payload/canary-Stable-payload/}"' \
    scenarios/deploy-canary/mutate-suite.sh

# mask_probe_length masks /__probe's Content-Length VALUE so a boot-identity
# digit-width change cannot red O2 (see its comment in driver.sh). The mask is
# deliberately blind to that one value, so what must be pinned is that O2 still
# discriminates everything ELSE about /__probe's header set -- the path the mask
# actually touches, which the /canary rows above cannot speak for.
#
# This arms a candidate-only header on the /__probe location. It reds only if
# the masked capture still compares header NAMES on that path, which is the
# property separating "mask one value" from "stop looking at this path".
# shellcheck disable=SC2016
mutate "deploy-canary: O2 still catches a new /__probe header despite the length mask" \
    scenarios/deploy-canary/driver.sh \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-}"' \
    'CANARY_ARM_SED="${CANARY_ARM_SED:-s|location /__probe {|location /__probe { add_header X-Probe-Leak leaked always;|}"' \
    scenarios/deploy-canary/mutate-suite.sh

# SC2016: the single-quoted text is a line of driver.sh's own bash being patched.
# shellcheck disable=SC2016
mutate "deploy-canary: O5 death oracle vacuous (expectation corrupted, suite must still red)" \
    scenarios/deploy-canary/driver.sh \
    'EXPECT_SIG9=0
died=$(grep -cE' \
    'EXPECT_SIG9=1
died=$(grep -cE' \
    scenarios/deploy-canary/mutate-suite.sh

# SC2016: the single-quoted text is a line of driver.sh's own bash being patched.
# shellcheck disable=SC2016
mutate "deploy-canary: O7 growth oracle vacuous (slope bound corrupted, suite must still red)" \
    scenarios/deploy-canary/driver.sh \
    '    SLOPE_CEIL_ADJUST=0' \
    '    SLOPE_CEIL_ADJUST=-1' \
    scenarios/deploy-canary/mutate-suite.sh
