/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rules_test.c -- TAP self-test for the rule-file parser.
 *
 * load_rules() decides the exact bytes that go on the wire. A defect here does
 * not fail a test -- it silently tests something other than what the rule file
 * says, and the run still reports ok. So the cases below pin byte-exact
 * decoding (escapes, embedded NULs, repeat expansion, trailing spaces) and
 * verify that every malformed rule file is rejected up front rather than
 * parsed into something the author did not write.
 *
 * die() exits the process, so rejection cases run load_rules() in a fork()ed
 * child and assert on the exit status (util's die exits 2). The child's stdio
 * is pointed at /dev/null first: die() prints its reason to stderr, and the
 * inherited stdout buffer would otherwise replay the parent's TAP lines when
 * exit() flushes it.
 */

/* mkstemp(), fork(), waitpid() are POSIX, not C11, and the build asks for
 * -std=c11 strictly -- same dance as util.c. */
#define _GNU_SOURCE

#include "rules.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  274

static int  tests_run = 0;
static int  failures = 0;

static test_case  cases[MAX_CASES];


static void
ok(int cond, const char *name)
{
    tests_run++;

    printf("%sok %d - %s\n", cond ? "" : "not ", tests_run, name);

    if (!cond) {
        failures++;
    }
}


static void
free_all(size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        case_free(&cases[i]);
    }
}


/*
 * load_rules() reads a file, not a string, so every fixture takes a trip
 * through a temp file. The file is unlinked as soon as it has been consumed;
 * a failure between mkstemp and unlink leaks at most one file in $TMPDIR.
 */
static const char *
write_tmp(const char *text)
{
    static char  path[512];
    const char  *tmpdir = getenv("TMPDIR");
    int          fd;
    size_t       len = strlen(text);

    if (tmpdir == NULL || *tmpdir == '\0') {
        tmpdir = "/tmp";
    }

    snprintf(path, sizeof(path), "%s/rules_test.XXXXXX", tmpdir);

    fd = mkstemp(path);
    if (fd < 0) {
        die("mkstemp %s failed", path);
    }

    if (write(fd, text, len) != (ssize_t) len) {
        die("short write to %s", path);
    }

    close(fd);

    return path;
}


static size_t
load_str(const char *text)
{
    const char  *path = write_tmp(text);
    size_t       n;

    n = load_rules(path, cases, MAX_CASES);
    unlink(path);

    return n;
}


static void
die_on_path(const char *path, size_t max, const char *name)
{
    pid_t  pid;
    int    st;

    /* Without the flush, the child's copy of the stdout buffer still holds
     * every TAP line printed so far, and die()'s exit() would replay them. */
    fflush(stdout);

    pid = fork();
    if (pid < 0) {
        die("fork failed");
    }

    if (pid == 0) {
        if (freopen("/dev/null", "w", stdout) == NULL
            || freopen("/dev/null", "w", stderr) == NULL)
        {
            _exit(99);
        }

        load_rules(path, cases, max);
        _exit(0);                      /* parsed fine: the test below fails */
    }

    /* An interrupted wait leaves st indeterminate, so the assertion below would
     * read uninitialised stack rather than the child's exit status. */
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) {
            die("waitpid failed");
        }
    }

    ok(WIFEXITED(st) && WEXITSTATUS(st) == 2, name);
}


static void
expect_die(const char *text, const char *name)
{
    const char  *path = write_tmp(text);

    die_on_path(path, MAX_CASES, name);
    unlink(path);
}


/*
 * Byte-exact check of what a stanza's send/repeat lines put in the request
 * buffer. memcmp against an explicit length, never strcmp: several fixtures
 * embed NUL bytes on purpose, and the whole point is that the parser counts
 * them.
 */
static void
send_bytes_are(const char *body, const char *want, size_t want_len,
               const char *name)
{
    char    text[4096];
    size_t  n;
    int     good;

    snprintf(text, sizeof(text), "name t\n%s\n", body);

    n = load_str(text);

    good = (n == 1
            && cases[0].request_len == want_len
            && cases[0].request != NULL
            && memcmp(cases[0].request, want, want_len) == 0);

    if (!good) {
        printf("# %s: %zu cases, request_len %zu (want %zu)\n",
               name, n, n > 0 ? cases[0].request_len : 0, want_len);
    }

    ok(good, name);
    free_all(n);
}


int
main(void)
{
    size_t  n;

    printf("1..%d\n", PLANNED);

    /* ---- escape decoding ---------------------------------------------- */

    send_bytes_are("send a\\r\\n\\tb", "a\r\n\tb", 5,
                   "\\r \\n \\t decode to their control bytes");
    send_bytes_are("send \\\\\\\"", "\\\"", 2,
                   "\\\\ and \\\" decode to backslash and quote");
    send_bytes_are("send a\\0b", "a\0b", 3,
                   "an embedded \\0 is counted, not string-terminated");
    send_bytes_are("send \\x41\\x6a", "Aj", 2,
                   "two-digit hex escapes, either case");
    send_bytes_are("send \\xAq", "\nq", 2,
                   "a one-digit hex escape stops at the first non-hex byte");
    send_bytes_are("send \\xA", "\n", 1,
                   "a one-digit hex escape at end of line is complete");
    send_bytes_are("send a\\", "a\\", 2,
                   "a trailing lone backslash is a literal backslash");

    expect_die("name t\nsend \\xzz\n", "\\x with no hex digits dies");
    expect_die("name t\nsend a\\x\n", "\\x at end of line dies");
    expect_die("name t\nsend \\q\n", "an unknown escape dies");

    /* ---- send concatenation and whitespace ---------------------------- */

    /* Leading whitespace after the directive is eaten by the line splitter,
     * so a send line cannot start with a literal space -- that is the
     * documented reason \x20 exists. Pin both halves of that contract. */
    send_bytes_are("send GET\nsend  /x", "GET/x", 5,
                   "send lines concatenate with no implied separator");
    send_bytes_are("send \\x20x", " x", 2,
                   "a leading space must be spelled \\x20");
    send_bytes_are("send ab  ", "ab  ", 4,
                   "trailing spaces in a send line are preserved");

    /* ---- repeat ------------------------------------------------------- */

    send_bytes_are("repeat 3 ab", "ababab", 6,
                   "repeat appends count copies");
    send_bytes_are("repeat 2 \\r\\n", "\r\n\r\n", 4,
                   "repeat decodes escapes in its text");
    send_bytes_are("send X\nrepeat 2 y", "Xyy", 3,
                   "repeat appends after earlier send lines");

    n = load_str("name t\nrepeat 100000 x\n");
    ok(n == 1 && cases[0].request_len == 100000,
       "repeat at the upper bound builds the full length");
    free_all(n);

    expect_die("name t\nrepeat 10junk x\n",
               "a repeat count with trailing junk dies");
    expect_die("name t\nrepeat 0 x\n", "repeat 0 dies");
    expect_die("name t\nrepeat -1 x\n", "a negative repeat count dies");
    expect_die("name t\nrepeat 100001 x\n",
               "a repeat count over the bound dies");
    expect_die("name t\nrepeat 10\n", "repeat with no text dies");

    /* ---- pause --------------------------------------------------------- */

    /* The offset is what makes a pause mean anything: it has to land on the
     * byte count written so far, not on the send-line index, or the stall
     * happens somewhere other than where the rule file drew the split. */
    n = load_str("name t\nsend AB\npause 5\nsend CD\n");
    ok(n == 1 && cases[0].n_pauses == 1
       && cases[0].pauses[0].offset == 2 && cases[0].pauses[0].ms == 5,
       "pause records the byte offset of the split and its duration");
    free_all(n);

    n = load_str("name t\nsend AB\npause 5\nsend CD\n");
    ok(n == 1 && cases[0].request_len == 4
       && memcmp(cases[0].request, "ABCD", 4) == 0,
       "pause does not change the bytes of the request");
    free_all(n);

    n = load_str("name t\nsend AB\npause 5\npause 7\nsend CD\n");
    ok(n == 1 && cases[0].n_pauses == 2
       && cases[0].pauses[0].offset == 2 && cases[0].pauses[0].ms == 5
       && cases[0].pauses[1].offset == 2 && cases[0].pauses[1].ms == 7,
       "two pauses at the same point both record");
    free_all(n);

    n = load_str("name t\npause 5\nsend AB\n");
    ok(n == 1 && cases[0].n_pauses == 1 && cases[0].pauses[0].offset == 0,
       "a pause before any send stalls at offset 0");
    free_all(n);

    n = load_str("name t\nsend AB\npause 5\n");
    ok(n == 1 && cases[0].n_pauses == 1 && cases[0].pauses[0].offset == 2,
       "a trailing pause stalls after the last byte");
    free_all(n);

    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].n_pauses == 0,
       "a case with no pause directive records none");
    free_all(n);

    /* Offsets must come out ascending; write_request() walks them in order and
     * would write backwards on an unsorted list. */
    n = load_str("name t\nsend AB\npause 5\nsend CD\npause 6\nsend EF\n");
    ok(n == 1 && cases[0].n_pauses == 2
       && cases[0].pauses[0].offset == 2 && cases[0].pauses[1].offset == 4,
       "pause offsets are recorded in ascending order");
    free_all(n);

    expect_die("name t\npause\n", "pause with no argument dies");
    expect_die("name t\npause 5junk\n",
               "a pause duration with trailing junk dies");
    expect_die("name t\npause 0\n", "pause 0 dies");
    expect_die("name t\npause -1\n", "a negative pause dies");
    expect_die("name t\npause 10001\n", "a pause over the ceiling dies");
    expect_die("name t\npause 6000\npause 6000\n",
               "pauses summing over the ceiling die");
    expect_die("name t\npause 1\npause 1\npause 1\npause 1\npause 1\npause 1\n"
               "pause 1\npause 1\npause 1\npause 1\npause 1\npause 1\npause 1\n"
               "pause 1\npause 1\npause 1\npause 1\n",
               "more than MAX_PAUSES pause directives die");

    /* ---- send_slow ----------------------------------------------------- */

    n = load_str("name t\nsend AB\nsend_slow 4 5\nsend CDEFGH\n");
    ok(n == 1 && cases[0].n_pauses == 1
       && cases[0].pauses[0].offset == 2
       && cases[0].pauses[0].ms == 5
       && cases[0].pauses[0].chunk == 4,
       "send_slow records offset, duration and chunk size");
    free_all(n);

    n = load_str("name t\nsend AB\nsend_slow 4 5\nsend CD\n");
    ok(n == 1 && cases[0].request_len == 4
       && memcmp(cases[0].request, "ABCD", 4) == 0,
       "send_slow does not change the bytes of the request");
    free_all(n);

    /* A plain pause must stay a plain pause: chunk 0 is what keeps the
     * no-directive write path byte-identical. */
    n = load_str("name t\nsend AB\npause 5\n");
    ok(n == 1 && cases[0].n_pauses == 1 && cases[0].pauses[0].chunk == 0,
       "a plain pause records a zero chunk");
    free_all(n);

    n = load_str("name t\nsend_slow 2 3\nsend ABCD\n");
    ok(n == 1 && cases[0].n_pauses == 1 && cases[0].pauses[0].offset == 0,
       "send_slow before any send paces from offset 0");
    free_all(n);

    expect_die("name t\nsend_slow\n", "send_slow with no argument dies");
    expect_die("name t\nsend_slow 4\n", "send_slow without a duration dies");
    expect_die("name t\nsend_slow x 5\n", "a non-numeric chunk dies");
    expect_die("name t\nsend_slow 4 x\n", "a non-numeric duration dies");
    expect_die("name t\nsend_slow 4 5junk\n",
               "a send_slow duration with trailing junk dies");
    expect_die("name t\nsend_slow 0 5\n", "a zero chunk dies");
    expect_die("name t\nsend_slow -1 5\n", "a negative chunk dies");
    expect_die("name t\nsend_slow 4097 5\n",
               "a chunk over MAX_SEND_SLOW_CHUNK dies");
    expect_die("name t\nsend_slow 4 0\n", "a zero send_slow duration dies");
    expect_die("name t\nsend_slow 4 10001\n",
               "a send_slow duration over the ceiling dies");

    /* ---- shutdown ------------------------------------------------------ */

    n = load_str("name t\nsend AB\nshutdown 1\n");
    ok(n == 1 && cases[0].shut_how == 1,
       "shutdown records its mode");
    free_all(n);

    /* HTTP_SHUT_NONE is -1 rather than 0 precisely because SHUT_RD is 0: a
     * zeroed field would half-close every case that never asked. */
    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].shut_how == HTTP_SHUT_NONE,
       "a case with no shutdown directive defaults to none, not SHUT_RD");
    free_all(n);

    n = load_str("name t\nsend AB\nshutdown 0\n");
    ok(n == 1 && cases[0].shut_how == 0,
       "shutdown 0 is stored as SHUT_RD, distinct from the default");
    free_all(n);

    /* A second case in the same file must start from the default rather than
     * inheriting the first one's mode. */
    n = load_str("name a\nsend x\nshutdown 2\n\nname b\nsend y\n");
    ok(n == 2 && cases[0].shut_how == 2
       && cases[1].shut_how == HTTP_SHUT_NONE,
       "shutdown does not leak into the next case");
    free_all(n);

    expect_die("name t\nshutdown\n", "shutdown with no argument dies");
    expect_die("name t\nshutdown 3\n", "shutdown out of range dies");
    expect_die("name t\nshutdown -1\n", "a negative shutdown mode dies");
    expect_die("name t\nshutdown x\n", "a non-numeric shutdown mode dies");
    expect_die("name t\nshutdown 1junk\n",
               "a shutdown mode with trailing junk dies");
    expect_die("name t\nshutdown 1\nshutdown 2\n",
               "two shutdown directives in one case die");

    /* ---- abort --------------------------------------------------------- */

    n = load_str("name t\nsend ABCD\nabort 2\n");
    ok(n == 1 && cases[0].abort_at == 2 && cases[0].saw_abort,
       "abort records its offset");
    free_all(n);

    /* The mirror of the shut_how default test, and the same trap: offset 0 is
     * a legitimate value, so the sentinel cannot be 0. */
    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].abort_at == HTTP_ABORT_NONE && !cases[0].saw_abort,
       "a case with no abort directive defaults to none, not offset 0");
    free_all(n);

    n = load_str("name t\nsend AB\nabort 0\n");
    ok(n == 1 && cases[0].abort_at == 0 && cases[0].saw_abort,
       "abort 0 is stored as offset 0, distinct from the default");
    free_all(n);

    n = load_str("name a\nsend x\nabort 1\n\nname b\nsend y\n");
    ok(n == 2 && cases[0].abort_at == 1
       && cases[1].abort_at == HTTP_ABORT_NONE,
       "abort does not leak into the next case");
    free_all(n);

    /* An aborted case may still assert on what the server logged and on the
     * probe counters -- that is the whole point of the directive. */
    n = load_str("name t\nsend AB\nabort 1\nprobe zone.nodes == 1\n"
                 "no_error_log crashed\n");
    ok(n == 1 && cases[0].saw_abort && cases[0].n_probes == 1
       && cases[0].n_no_logs == 1,
       "an aborted case keeps its probe and log assertions");
    free_all(n);

    expect_die("name t\nabort\n", "abort with no argument dies");
    expect_die("name t\nabort x\n", "a non-numeric abort offset dies");
    expect_die("name t\nabort 2junk\n",
               "an abort offset with trailing junk dies");
    expect_die("name t\nabort -1\n", "a negative abort offset dies");
    expect_die("name t\nabort 1\nabort 2\n",
               "two abort directives in one case die");

    /* Both orders, because either directive may be read first and the check
     * lives in two places. */
    expect_die("name t\nabort 1\nshutdown 1\n",
               "shutdown after abort dies");
    expect_die("name t\nshutdown 1\nabort 1\n",
               "abort after shutdown dies");

    /*
     * The load-bearing guard. A reset connection has no response, so a
     * response-shaped expectation asserts against an empty buffer. The
     * expect_not case is the dangerous one: it would PASS unconditionally,
     * reporting green for an assertion that tested nothing at all.
     */
    expect_die("name t\nsend AB\nabort 1\nexpect status=200\n",
               "expect status on an aborted case dies");
    expect_die("name t\nsend AB\nabort 1\nexpect body~hello\n",
               "expect body on an aborted case dies");
    expect_die("name t\nsend AB\nabort 1\nexpect_not body~oops\n",
               "expect_not on an aborted case dies rather than passing vacuously");
    expect_die("name t\nsend AB\nabort 1\nerror_code_like ^4[0-9]{2}$\n",
               "error_code_like on an aborted case dies");

    /* ---- hold ----------------------------------------------------------- */

    n = load_str("name t\nsend AB\nhold 50\n");
    ok(n == 1 && cases[0].hold_ms == 50 && cases[0].saw_hold,
       "hold stores the millisecond count");
    free_all(n);

    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].hold_ms == HTTP_HOLD_NONE && !cases[0].saw_hold,
       "a case without hold defaults to no hold");
    free_all(n);

    expect_die("name t\nsend AB\nhold\n", "hold with no argument dies");
    expect_die("name t\nsend AB\nhold abc\n", "hold with a non-number dies");
    expect_die("name t\nsend AB\nhold -1\n", "a negative hold dies");

    /* Zero is rejected rather than silently meaning "no hold": a rule that
     * spells it is asking for a behaviour it would not get, and the case would
     * read as testing an idle connection while making an ordinary request. */
    expect_die("name t\nsend AB\nhold 0\n", "hold 0 dies rather than meaning no hold");

    expect_die("name t\nsend AB\nhold 10001\n",
               "a hold over the ceiling dies");
    expect_die("name t\nsend AB\nhold 10\nhold 20\n",
               "a second hold directive dies");

    /* Both walk away without reading, and abort destroys the very connection
     * hold means to keep open -- checked in both orders, since either may come
     * first in the file. */
    expect_die("name t\nsend AB\nabort 1\nhold 10\n",
               "abort then hold dies");
    expect_die("name t\nsend AB\nhold 10\nabort 1\n",
               "hold then abort dies");

    expect_die("name t\nsend AB\nrecv_slow 4 10\nhold 10\n",
               "recv_slow then hold dies");
    expect_die("name t\nsend AB\nhold 10\nrecv_slow 4 10\n",
               "hold then recv_slow dies");

    /*
     * The same vacuous-assertion trap the abort guard above closes, reached a
     * different way: a held case never reads, so expect_not would pass against
     * an empty buffer whatever the server actually wrote.
     */
    expect_die("name t\nsend AB\nhold 10\nexpect status=200\n",
               "expect status on a held case dies");
    expect_die("name t\nsend AB\nhold 10\nexpect_not body~oops\n",
               "expect_not on a held case dies rather than passing vacuously");

    /* The hold is wall-clock like a pause, so it answers to the same ceiling
     * rather than being free on top of it. */
    expect_die("name t\nsend ABCDEFGHIJ\nsend_slow 1 1200\nhold 9000\n",
               "hold counts toward the total stall ceiling");

    /* ---- expect_close_within -------------------------------------------- */

    n = load_str("name t\nsend AB\nexpect_close_within 250\n");
    ok(n == 1 && cases[0].close_within_ms == 250 && cases[0].saw_close_within,
       "expect_close_within stores its deadline");

    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].close_within_ms == CLOSE_WITHIN_NONE
       && !cases[0].saw_close_within,
       "a case without expect_close_within defaults to no deadline");

    /* Zero is a coherent (if unsatisfiable) deadline, unlike hold 0, so it
     * parses rather than dying -- and must be distinguishable from unset,
     * which is what the sentinel exists for. */
    n = load_str("name t\nsend AB\nexpect_close_within 0\n");
    ok(n == 1 && cases[0].close_within_ms == 0 && cases[0].saw_close_within,
       "a zero deadline parses and is distinct from unset");

    expect_die("name t\nsend AB\nexpect_close_within\n",
               "expect_close_within with no argument dies");
    expect_die("name t\nsend AB\nexpect_close_within abc\n",
               "expect_close_within with a non-number dies");
    expect_die("name t\nsend AB\nexpect_close_within -1\n",
               "a negative close deadline dies");

    /* The ceiling is the load-bearing bound: a deadline past the prober's read
     * timeout could never be missed, so the assertion could not go red. */
    expect_die("name t\nsend AB\nexpect_close_within 10001\n",
               "a close deadline over the ceiling dies");

    expect_die("name t\nsend AB\nexpect_close_within 10\n"
               "expect_close_within 20\n",
               "a second expect_close_within directive dies");

    /* Neither an aborted nor a held case ever reads the socket, so the
     * server's close is unobservable and the deadline would judge nothing.
     * Both orders, since either directive may come first. */
    expect_die("name t\nsend AB\nabort 1\nexpect_close_within 10\n",
               "abort then expect_close_within dies");
    expect_die("name t\nsend AB\nexpect_close_within 10\nabort 1\n",
               "expect_close_within then abort dies");
    expect_die("name t\nsend AB\nhold 10\nexpect_close_within 10\n",
               "hold then expect_close_within dies");
    expect_die("name t\nsend AB\nexpect_close_within 10\nhold 10\n",
               "expect_close_within then hold dies");

    /* It is NOT exclusive with the directives that keep reading: shutdown is
     * the pairing it exists for, and an ordinary case may assert a deadline
     * alongside its response expectations. */
    n = load_str("name t\nsend AB\nshutdown 1\nexpect_close_within 250\n");
    ok(n == 1 && cases[0].close_within_ms == 250 && cases[0].shut_how == 1,
       "expect_close_within combines with a half-close");

    n = load_str("name t\nsend AB\nexpect status=200\n"
                 "expect_close_within 250\n");
    ok(n == 1 && cases[0].close_within_ms == 250 && cases[0].n_expects == 1,
       "expect_close_within combines with response expectations");

    /* ---- expect_idle ------------------------------------------------ */

    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].idle_ms == IDLE_NONE
       && !cases[0].saw_idle,
       "a case without expect_idle defaults to no idle wait");

    n = load_str("name t\nsend AB\nexpect_idle 250\n");
    ok(n == 1 && cases[0].idle_ms == 250 && cases[0].saw_idle,
       "expect_idle records its wait");

    /* The transport keeps its own sentinel so http.c need not include rules.h;
     * the two must agree or a case with no idle wait would silently run one. */
    ok(IDLE_NONE == HTTP_IDLE_NONE,
       "the parser and transport idle-wait sentinels agree");

    expect_die("name t\nsend AB\nexpect_idle\n",
               "expect_idle with no argument dies");
    expect_die("name t\nsend AB\nexpect_idle abc\n",
               "expect_idle with a non-number dies");
    expect_die("name t\nsend AB\nexpect_idle -1\n",
               "a negative idle wait dies");

    /* Unlike the close deadline, zero is rejected: a wait of no time polls for
     * nothing and passes unconditionally -- an assertion that cannot go red. */
    expect_die("name t\nsend AB\nexpect_idle 0\n",
               "a zero idle wait dies");

    expect_die("name t\nsend AB\nexpect_idle 10001\n",
               "an idle wait over the ceiling dies");

    expect_die("name t\nsend AB\nexpect_idle 10\nexpect_idle 20\n",
               "a second expect_idle directive dies");

    /* Neither abort nor hold observes the socket, so the wait would report
     * this process's own behaviour as the server's. Both orders. */
    expect_die("name t\nsend AB\nabort 1\nexpect_idle 10\n",
               "abort then expect_idle dies");
    expect_die("name t\nsend AB\nexpect_idle 10\nabort 1\n",
               "expect_idle then abort dies");
    expect_die("name t\nsend AB\nhold 10\nexpect_idle 10\n",
               "hold then expect_idle dies");
    expect_die("name t\nsend AB\nexpect_idle 10\nhold 10\n",
               "expect_idle then hold dies");

    /* Contradictory, not merely redundant: one asserts the server ends the
     * connection, the other that it leaves it open. */
    expect_die("name t\nsend AB\nexpect_close_within 10\nexpect_idle 10\n",
               "expect_close_within then expect_idle dies");
    expect_die("name t\nsend AB\nexpect_idle 10\nexpect_close_within 10\n",
               "expect_idle then expect_close_within dies");

    /* The idle wait replaces the read loop, so pacing reads configures
     * something that never runs. */
    expect_die("name t\nsend AB\nrecv_slow 256 40\nexpect_idle 10\n",
               "recv_slow then expect_idle dies");
    expect_die("name t\nsend AB\nexpect_idle 10\nrecv_slow 256 40\n",
               "expect_idle then recv_slow dies");

    /* Nothing is ever read, so a response expectation would assert against an
     * empty buffer -- and expect_not would pass having looked at nothing. */
    expect_die("name t\nsend AB\nexpect_idle 10\nexpect status=200\n",
               "expect_idle carrying a response expectation dies");

    /* It DOES combine with a half-close: shutting down the sending side and
     * then asserting the server leaves the connection open is coherent. */
    n = load_str("name t\nsend AB\nshutdown 1\nexpect_idle 250\n");
    ok(n == 1 && cases[0].idle_ms == 250 && cases[0].shut_how == 1,
       "expect_idle combines with a half-close");

    /* The wait is wall-clock the suite spends, so it answers to the same
     * ceiling as pause and hold rather than being free on top of them. */
    expect_die("name t\nsend AB\npause 9000\nexpect_idle 9000\n",
               "a pause plus an idle wait over the stall ceiling dies");

    /* ---- recv_slow / so_rcvbuf ----------------------------------------- */

    n = load_str("name t\nsend AB\nrecv_slow 256 40\n");
    ok(n == 1 && cases[0].recv_opt.chunk == 256 && cases[0].recv_opt.ms == 40
       && cases[0].saw_recv_slow,
       "recv_slow records its chunk and interval");
    free_all(n);

    /* Zero IS the off value here, unlike abort_at and shut_how -- no sentinel
     * is needed, and the read loop treats chunk 0 as "no pacing". */
    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].recv_opt.chunk == 0 && cases[0].recv_opt.ms == 0
       && cases[0].recv_opt.rcvbuf == 0,
       "a case with no recv directives paces nothing and keeps the default buffer");
    free_all(n);

    n = load_str("name t\nsend AB\nso_rcvbuf 2048\n");
    ok(n == 1 && cases[0].recv_opt.rcvbuf == 2048 && cases[0].saw_rcvbuf,
       "so_rcvbuf records its size");
    free_all(n);

    n = load_str("name t\nsend AB\nrecv_slow 128 10\nso_rcvbuf 512\n");
    ok(n == 1 && cases[0].recv_opt.chunk == 128 && cases[0].recv_opt.rcvbuf == 512,
       "recv_slow and so_rcvbuf combine on one case");
    free_all(n);

    n = load_str("name a\nsend x\nrecv_slow 64 5\nso_rcvbuf 256\n\nname b\nsend y\n");
    ok(n == 2 && cases[0].recv_opt.chunk == 64
       && cases[1].recv_opt.chunk == 0 && cases[1].recv_opt.rcvbuf == 0,
       "recv directives do not leak into the next case");
    free_all(n);

    expect_die("name t\nrecv_slow\n", "recv_slow with no argument dies");
    expect_die("name t\nrecv_slow 100\n", "recv_slow with only a chunk dies");
    expect_die("name t\nrecv_slow x 10\n",
               "a non-numeric recv_slow chunk dies");
    expect_die("name t\nrecv_slow 100 x\n",
               "a non-numeric recv_slow interval dies");
    expect_die("name t\nrecv_slow 100 10junk\n",
               "a recv_slow interval with trailing junk dies");
    expect_die("name t\nrecv_slow 0 10\n", "recv_slow chunk 0 dies");
    expect_die("name t\nrecv_slow 4097 10\n",
               "a recv_slow chunk over the cap dies");
    expect_die("name t\nrecv_slow 100 0\n", "recv_slow interval 0 dies");
    expect_die("name t\nrecv_slow 100 10001\n",
               "a recv_slow interval over the ceiling dies");
    expect_die("name t\nrecv_slow 100 10\nrecv_slow 200 20\n",
               "two recv_slow directives in one case die");

    expect_die("name t\nso_rcvbuf\n", "so_rcvbuf with no argument dies");
    expect_die("name t\nso_rcvbuf x\n", "a non-numeric so_rcvbuf dies");
    expect_die("name t\nso_rcvbuf 127\n", "an so_rcvbuf under the floor dies");
    expect_die("name t\nso_rcvbuf 1048577\n",
               "an so_rcvbuf over the ceiling dies");
    expect_die("name t\nso_rcvbuf 1024\nso_rcvbuf 2048\n",
               "two so_rcvbuf directives in one case die");

    /* Pacing reads on a case that never reads a response is incoherent; both
     * orders, since the guard lives in two places. */
    expect_die("name t\nsend AB\nabort 1\nrecv_slow 100 10\n",
               "recv_slow after abort dies");
    expect_die("name t\nsend AB\nrecv_slow 100 10\nabort 1\n",
               "abort after recv_slow dies");

    /* The point of the post-parse pass: the dribble cost depends on bytes
     * appended AFTER the directive, so a case that looks cheap when the
     * directive is read can still blow the ceiling once the stanza closes.
     * 100 bytes at 1 byte per 200 ms is 20 s, well over the 10 s ceiling. */
    expect_die("name t\nsend_slow 1 200\n"
               "send 0123456789012345678901234567890123456789\n"
               "send 0123456789012345678901234567890123456789\n"
               "send 0123456789012345678901234567890123456789\n",
               "a send_slow whose dribble exceeds the ceiling dies at close");

    /* ---- stanza framing ----------------------------------------------- */

    n = load_str("");
    ok(n == 0, "an empty file parses to zero cases");
    free_all(n);

    n = load_str("# comment\n\n   \n# more\n");
    ok(n == 0, "comments and blank lines alone parse to zero cases");
    free_all(n);

    n = load_str("name first\nsend a\n\nname second\nsend b\n");
    ok(n == 2
       && strcmp(cases[0].name, "first") == 0
       && strcmp(cases[1].name, "second") == 0,
       "a blank line separates stanzas");
    free_all(n);

    n = load_str("name   padded name  \nsend a\n");
    ok(n == 1 && strcmp(cases[0].name, "padded name") == 0,
       "a case name is trimmed");
    free_all(n);

    n = load_str("name t\nsend a\n# interleaved comment\nsend b\n");
    ok(n == 1 && cases[0].request_len == 2
       && memcmp(cases[0].request, "ab", 2) == 0,
       "a comment does not end a stanza");
    free_all(n);

    n = load_str("name t\n   # indented comment\nsend a\n");
    ok(n == 1 && cases[0].request_len == 1,
       "an indented comment is still a comment");
    free_all(n);

    expect_die("send a\n", "a directive before any name dies");
    expect_die("name t\nsend a\n   \nsend b\n",
               "a whitespace-only line ends the stanza");
    expect_die("name t\nfrobnicate x\n", "an unknown directive dies");

    {
        const char  *path =
            write_tmp("name a\nsend x\n\nname b\nsend x\n\nname c\nsend x\n");

        die_on_path(path, 2, "more cases than the caller's max dies");
        unlink(path);
    }

    {
        char  text[4096];
        int   i, off;

        off = snprintf(text, sizeof(text), "name t\n");
        for (i = 0; i < MAX_ASSERTS + 1; i++) {
            off += snprintf(text + off, sizeof(text) - (size_t) off,
                            "expect status=200\n");
        }

        expect_die(text, "one expect line past MAX_ASSERTS dies");

        off = snprintf(text, sizeof(text), "name t\n");
        for (i = 0; i < MAX_ASSERTS; i++) {
            off += snprintf(text + off, sizeof(text) - (size_t) off,
                            "probe n == 1\n");
        }

        n = load_str(text);
        ok(n == 1 && cases[0].n_probes == MAX_ASSERTS,
           "exactly MAX_ASSERTS probe lines still load");
        free_all(n);
    }

    /* ---- expect parsing ----------------------------------------------- */

    n = load_str("name t\nexpect status=200\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_STATUS
       && cases[0].expects[0].number == 200,
       "expect status= parses the number");
    free_all(n);

    /* -1 is the prober's own "unparseable" convention; the rule syntax does
     * not forbid asserting on it, so pin that it loads rather than dies. */
    n = load_str("name t\nexpect status=-1\n");
    ok(n == 1 && cases[0].expects[0].number == -1,
       "expect status=-1 is accepted");
    free_all(n);

    n = load_str("name t\nexpect body~hello\n");
    ok(n == 1 && cases[0].expects[0].kind == EXPECT_BODY_CONTAINS
       && strcmp(cases[0].expects[0].text, "hello") == 0,
       "expect body~ stores its needle");
    free_all(n);

    n = load_str("name t\nexpect header~X-Test: on\n");
    ok(n == 1 && cases[0].expects[0].kind == EXPECT_HEADER_CONTAINS
       && strcmp(cases[0].expects[0].text, "X-Test: on") == 0,
       "expect header~ keeps the colon and inner spaces");
    free_all(n);

    n = load_str("name t\nexpect body~hi   \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "hi") == 0,
       "an expect needle is trimmed where a send line is not");
    free_all(n);

    expect_die("name t\nexpect status=200junk\n",
               "expect status= with trailing junk dies");
    expect_die("name t\nexpect status=\n", "expect status= with no number dies");
    expect_die("name t\nexpect claims~x\n", "an unknown expect form dies");

    /* ---- probe / delta ------------------------------------------------ */

    n = load_str("name t\nprobe zone.nodes == 1\n");
    ok(n == 1 && cases[0].n_probes == 1
       && strcmp(cases[0].probes[0].path, "zone.nodes") == 0
       && strcmp(cases[0].probes[0].op, "==") == 0
       && strcmp(cases[0].probes[0].literal, "1") == 0,
       "probe splits into path, op and literal");
    free_all(n);

    n = load_str("name t\ndelta fds == 0\n");
    ok(n == 1 && cases[0].n_deltas == 1
       && strcmp(cases[0].deltas[0].path, "fds") == 0,
       "delta parses like probe into its own list");
    free_all(n);

    n = load_str("name t\nprobe zone.name ~ demo zone  \n");
    ok(n == 1 && strcmp(cases[0].probes[0].literal, "demo zone") == 0,
       "a probe literal keeps inner spaces and drops trailing ones");
    free_all(n);

    n = load_str("name t\nprobe zone.name ~ demo\n");
    ok(n == 1 && cases[0].n_probes == 1,
       "probe accepts the substring operator");
    free_all(n);

    n = load_str("name t\nprobe_baseline fds <= 2\n");
    ok(n == 1 && cases[0].n_baselines == 1
       && strcmp(cases[0].baselines[0].path, "fds") == 0
       && strcmp(cases[0].baselines[0].op, "<=") == 0
       && strcmp(cases[0].baselines[0].literal, "2") == 0,
       "probe_baseline splits into path, op and literal");
    free_all(n);

    /*
     * The two subtracting directives must land in SEPARATE lists: they share
     * an evaluator but not an origin snapshot, so a case carrying both and
     * collecting them into one list would silently judge every assertion
     * against whichever snapshot the loop happened to pass.
     */
    n = load_str("name t\ndelta fds == 0\nprobe_baseline fds <= 2\n");
    ok(n == 1 && cases[0].n_deltas == 1 && cases[0].n_baselines == 1
       && strcmp(cases[0].deltas[0].op, "==") == 0
       && strcmp(cases[0].baselines[0].op, "<=") == 0,
       "delta and probe_baseline accumulate into separate lists");
    free_all(n);

    expect_die("name t\nprobe fds = 0\n", "an unknown operator dies");
    expect_die("name t\ndelta zone.name ~ x\n",
               "delta with the substring operator dies");
    expect_die("name t\nprobe_baseline zone.name ~ x\n",
               "probe_baseline with the substring operator dies");
    expect_die("name t\nprobe fds\n", "probe with only a path dies");
    expect_die("name t\nprobe fds == \t\n",
               "probe with a whitespace-only literal dies");

    /* ---- expect_not parsing -------------------------------------------- */

    n = load_str("name t\nexpect_not body~oops\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_NOT_BODY_CONTAINS
       && strcmp(cases[0].expects[0].text, "oops") == 0,
       "expect_not body~ parses to the negated body kind");
    free_all(n);

    n = load_str("name t\nexpect_not header~X-Debug\n");
    ok(n == 1 && cases[0].expects[0].kind == EXPECT_NOT_HEADER_CONTAINS
       && strcmp(cases[0].expects[0].text, "X-Debug") == 0,
       "expect_not header~ parses to the negated header kind");
    free_all(n);

    n = load_str("name t\nexpect_not body~  hi  \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "hi") == 0,
       "an expect_not needle is trimmed like expect's");
    free_all(n);

    n = load_str("name t\nexpect body~a\nexpect_not body~b\n");
    ok(n == 1 && cases[0].n_expects == 2
       && cases[0].expects[0].kind == EXPECT_BODY_CONTAINS
       && cases[0].expects[1].kind == EXPECT_NOT_BODY_CONTAINS,
       "expect and expect_not coexist in one stanza");
    free_all(n);

    expect_die("name t\nexpect_not body~\n",
               "expect_not body~ with an empty pattern dies");
    expect_die("name t\nexpect_not header~   \n",
               "expect_not header~ with a whitespace-only pattern dies");
    expect_die("name t\nexpect_not status=200\n",
               "expect_not has no status= form and dies");
    expect_die("name t\nexpect_not claims~x\n",
               "an unknown expect_not form dies");
    expect_die("name t\nexpect_not\n",
               "expect_not with no argument at all dies");

    /* ---- error_code_like parsing ---------------------------------------- */

    n = load_str("name t\nerror_code_like ^2[0-9]{2}$\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_STATUS_LIKE
       && strcmp(cases[0].expects[0].text, "^2[0-9]{2}$") == 0,
       "error_code_like compiles and stores its source pattern");
    free_all(n);

    n = load_str("name t\nerror_code_like   ^(4|5)[0-9]{2}$   \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "^(4|5)[0-9]{2}$") == 0,
       "error_code_like trims surrounding whitespace, not the regex itself");
    free_all(n);

    n = load_str("name t\nerror_code_like .\n");
    ok(n == 1, "a trivial one-byte regex compiles");
    free_all(n);

    expect_die("name t\nerror_code_like\n",
               "error_code_like with no pattern dies");
    expect_die("name t\nerror_code_like    \n",
               "error_code_like with a whitespace-only pattern dies");
    expect_die("name t\nerror_code_like [unclosed\n",
               "an unterminated bracket expression dies");
    expect_die("name t\nerror_code_like (unclosed\n",
               "an unbalanced group dies");
    expect_die("name t\nerror_code_like *nostart\n",
               "a pattern starting with a repetition operator dies");

    /* ---- xfail parsing --------------------------------------------------- */

    n = load_str("name t\nxfail\nsend a\n");
    ok(n == 1 && cases[0].xfail == 1 && cases[0].xfail_reason == NULL,
       "a bare xfail sets the flag with no reason");
    free_all(n);

    n = load_str("name t\nxfail known broken until #42\nsend a\n");
    ok(n == 1 && cases[0].xfail == 1
       && cases[0].xfail_reason != NULL
       && strcmp(cases[0].xfail_reason, "known broken until #42") == 0,
       "xfail stores a trimmed reason");
    free_all(n);

    n = load_str("name t\nxfail   padded reason   \nsend a\n");
    ok(n == 1 && strcmp(cases[0].xfail_reason, "padded reason") == 0,
       "an xfail reason is trimmed on both ends");
    free_all(n);

    n = load_str("name a\nsend x\n\nname b\nxfail\nsend y\n");
    ok(n == 2 && cases[0].xfail == 0 && cases[1].xfail == 1,
       "xfail applies only to the stanza it appears in");
    free_all(n);

    expect_die("name t\nxfail\nxfail\n",
               "a duplicate xfail in one stanza dies");
    expect_die("xfail\nname t\nsend a\n",
               "xfail before any name directive dies");

    /* ---- no_error_log / grep_error_log parsing ------------------------- */

    n = load_str("name t\nno_error_log \\[emerg\\]\n");
    ok(n == 1 && cases[0].n_no_logs == 1
       && strcmp(cases[0].no_logs[0].pattern, "\\[emerg\\]") == 0,
       "no_error_log compiles and stores its source pattern");
    free_all(n);

    n = load_str("name t\ngrep_error_log banned by rule\n");
    ok(n == 1 && cases[0].n_grep_logs == 1
       && strcmp(cases[0].grep_logs[0].pattern, "banned by rule") == 0,
       "grep_error_log keeps inner spaces in its pattern");
    free_all(n);

    n = load_str("name t\nno_error_log a\ngrep_error_log b\nno_error_log c\n");
    ok(n == 1 && cases[0].n_no_logs == 2 && cases[0].n_grep_logs == 1,
       "no_error_log and grep_error_log accumulate independently");
    free_all(n);

    n = load_str("name t\nno_error_log   pad  \n");
    ok(n == 1 && strcmp(cases[0].no_logs[0].pattern, "pad") == 0,
       "a log pattern is trimmed on both ends");
    free_all(n);

    expect_die("name t\nno_error_log\n",
               "no_error_log with no pattern dies");
    expect_die("name t\ngrep_error_log    \n",
               "grep_error_log with a whitespace-only pattern dies");
    expect_die("name t\nno_error_log [unclosed\n",
               "no_error_log with an invalid regex dies");
    expect_die("name t\ngrep_error_log (unclosed\n",
               "grep_error_log with an invalid regex dies");

    {
        char  text[4096];
        int   i, off;

        off = snprintf(text, sizeof(text), "name t\n");
        for (i = 0; i < MAX_ASSERTS + 1; i++) {
            off += snprintf(text + off, sizeof(text) - (size_t) off,
                            "no_error_log x\n");
        }

        expect_die(text, "one no_error_log past MAX_ASSERTS dies");
    }

    /* ---- raw_response_headers_like parsing ----------------------------- */

    n = load_str("name t\nexpect raw_response_headers_like~^Content-Type: text\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_RAW_RESPONSE_HEADERS_LIKE
       && strcmp(cases[0].expects[0].text, "^Content-Type: text") == 0,
       "raw_response_headers_like~ parses and stores its regex pattern");
    free_all(n);

    n = load_str("name t\nexpect raw_response_headers_like~  Content-Type  \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "Content-Type") == 0,
       "raw_response_headers_like~ trims surrounding whitespace");
    free_all(n);

    n = load_str("name t\nexpect raw_response_headers_like~[a-z]+\n");
    ok(n == 1,
       "a valid regex in raw_response_headers_like~ compiles");
    free_all(n);

    expect_die("name t\nexpect raw_response_headers_like~\n",
               "raw_response_headers_like~ with no pattern dies");
    expect_die("name t\nexpect raw_response_headers_like~    \n",
               "raw_response_headers_like~ with whitespace-only pattern dies");
    expect_die("name t\nexpect raw_response_headers_like~[unclosed\n",
               "raw_response_headers_like~ with an invalid regex dies");
    expect_die("name t\nexpect raw_response_headers_like~(unclosed\n",
               "raw_response_headers_like~ with an unbalanced group dies");

    /* ---- from / fault ------------------------------------------------- */

    n = load_str("name t\nfrom  127.0.0.9 \nfault  fault_slab=3 \n");
    ok(n == 1 && strcmp(cases[0].source, "127.0.0.9") == 0,
       "from stores a trimmed source address");
    ok(strcmp(cases[0].fault, "fault_slab=3") == 0,
       "fault stores a trimmed probe query");
    free_all(n);

    /* ---- pid_may_change ------------------------------------------------ */

    n = load_str("name t\npid_may_change\n");
    ok(n == 1 && cases[0].pid_may_change == 1,
       "pid_may_change sets the flag on its case");
    free_all(n);

    /* Strict is the DEFAULT, and it is the whole safety property: a case that
     * never says the word must not have the oracle relaxed under it. */
    n = load_str("name t\nsend GET / HTTP/1.0\\r\\n\\r\\n\n");
    ok(n == 1 && cases[0].pid_may_change == 0,
       "a case that omits pid_may_change is strict");
    free_all(n);

    /* Per-case, not per-file: the directive on one stanza must not leak into
     * the next, or a scenario would silently lose the strict oracle on every
     * case following its reload. */
    n = load_str("name a\npid_may_change\n\nname b\nsend X\n");
    ok(n == 2 && cases[0].pid_may_change == 1
       && cases[1].pid_may_change == 0,
       "pid_may_change does not leak into the following case");
    free_all(n);

    expect_die("name t\npid_may_change 1\n",
               "pid_may_change with an argument dies");
    expect_die("name t\npid_may_change\npid_may_change\n",
               "a repeated pid_may_change dies");

    /* ---- open_conns --------------------------------------------------- */

    n = load_str("name t\nsend GET / HTTP/1.0\\r\\n\\r\\n\n"
                 "open_conns 100\nprobe connections.free >= 0\n");
    ok(n == 1 && cases[0].open_conns == 100,
       "open_conns stores the connection count");
    free_all(n);

    /* Zero is the off value and the DEFAULT: a case that never says the word
     * parks no connections. */
    n = load_str("name t\nsend GET / HTTP/1.0\\r\\n\\r\\n\n");
    ok(n == 1 && cases[0].open_conns == 0,
       "a case without open_conns parks nothing");
    free_all(n);

    /* Per-case, not per-file -- the count on one stanza must not carry into the
     * next, or a following case would silently open connections it never asked
     * for. */
    n = load_str("name a\nsend X\nopen_conns 5\nprobe connections.free >= 0\n"
                 "\nname b\nsend Y\n");
    ok(n == 2 && cases[0].open_conns == 5 && cases[1].open_conns == 0,
       "open_conns does not leak into the following case");
    free_all(n);

    /* Case-level, so it is legal on a pipeline case and lands on the case, not
     * a block -- the probe/connection state it observes is case-level too. */
    n = load_str("name t\nblock a\nsend GET /a HTTP/1.1\\r\\n\\r\\n\n"
                 "open_conns 3\nprobe connections.free >= 0\n");
    ok(n == 1 && cases[0].open_conns == 3 && cases[0].n_blocks == 1,
       "open_conns is accepted on a pipeline case");
    free_all(n);

    expect_die("name t\nsend X\nopen_conns 5junk\nprobe fds >= 0\n",
               "an open_conns count with trailing junk dies");
    expect_die("name t\nsend X\nopen_conns 5 20\nprobe fds >= 0\n",
               "an open_conns count with a trailing token dies");
    expect_die("name t\nsend X\nopen_conns 0\nprobe fds >= 0\n",
               "open_conns 0 dies");
    expect_die("name t\nsend X\nopen_conns -1\nprobe fds >= 0\n",
               "a negative open_conns dies");
    expect_die("name t\nsend X\nopen_conns 513\nprobe fds >= 0\n",
               "an open_conns over MAX_OPEN_CONNS dies");
    expect_die("name t\nsend X\nopen_conns\nprobe fds >= 0\n",
               "open_conns with no argument dies");
    expect_die("name t\nsend X\nopen_conns 5\nopen_conns 6\nprobe fds >= 0\n",
               "a repeated open_conns dies");

    /* ---- concurrent ----------------------------------------------------- */

    n = load_str("name t\nsend GET / HTTP/1.0\\r\\n\\r\\n\n"
                 "concurrent 8\nprobe connections.free >= 0\n");
    ok(n == 1 && cases[0].concurrent == 8,
       "concurrent stores the in-flight count");
    free_all(n);

    n = load_str("name t\nsend GET / HTTP/1.0\\r\\n\\r\\n\n");
    ok(n == 1 && cases[0].concurrent == 0,
       "a case without concurrent runs the ordinary single-request path");
    free_all(n);

    n = load_str("name a\nsend X\nconcurrent 4\nprobe connections.free >= 0\n"
                 "\nname b\nsend Y\n");
    ok(n == 2 && cases[0].concurrent == 4 && cases[1].concurrent == 0,
       "concurrent does not leak into the following case");
    free_all(n);

    /* The floor is 2, not 1: `concurrent 1` is the ordinary path in costume, so
     * accepting it would let a file claim a concurrency test that asserts
     * nothing about overlap. */
    n = load_str("name t\nsend X\nconcurrent 2\nprobe fds >= 0\n");
    ok(n == 1 && cases[0].concurrent == 2, "concurrent 2 is the floor and loads");
    free_all(n);

    expect_die("name t\nsend X\nconcurrent 1\nprobe fds >= 0\n",
               "concurrent 1 dies -- one in flight is the ordinary path");
    expect_die("name t\nsend X\nconcurrent 0\nprobe fds >= 0\n",
               "concurrent 0 dies");
    expect_die("name t\nsend X\nconcurrent -1\nprobe fds >= 0\n",
               "a negative concurrent dies");
    expect_die("name t\nsend X\nconcurrent 65\nprobe fds >= 0\n",
               "a concurrent over MAX_CONCURRENT dies");
    expect_die("name t\nsend X\nconcurrent 4junk\nprobe fds >= 0\n",
               "a concurrent count with trailing junk dies");
    expect_die("name t\nsend X\nconcurrent 4 8\nprobe fds >= 0\n",
               "a concurrent count with a trailing token dies");
    expect_die("name t\nsend X\nconcurrent\nprobe fds >= 0\n",
               "concurrent with no argument dies");
    expect_die("name t\nsend X\nconcurrent 4\nconcurrent 8\nprobe fds >= 0\n",
               "a repeated concurrent dies");

    /* A fan whose results nothing compares is vacuous in exactly the way
     * open_conns without a probe is: the snapshots are the only thing that
     * observes the overlap. */
    expect_die("name t\nsend X\nconcurrent 4\n",
               "concurrent with no delta or probe assertion dies");

    n = load_str("name t\nsend X\nconcurrent 4\ndelta fds == 0\n");
    ok(n == 1 && cases[0].concurrent == 4,
       "a delta assertion satisfies concurrent's observability requirement");
    free_all(n);

    /* A pipeline is ORDERED on one connection; "N pipelines at once" is a
     * different and much larger feature, so the pair is rejected rather than
     * silently resolved toward either reading. */
    expect_die("name t\nblock a\nsend GET /a HTTP/1.1\\r\\n\\r\\n\n"
               "concurrent 4\nprobe fds >= 0\n",
               "concurrent on a pipeline case dies");

    /* abort/hold/expect_idle each end their connection WITHOUT reading, so a fan
     * carrying one would collect no responses at all -- the same vacuity the
     * delta/probe rule rejects, reached by a different route. */
    expect_die("name t\nsend X\nconcurrent 4\nabort 3\nprobe fds >= 0\n",
               "concurrent + abort dies -- abort never reads a response");
    expect_die("name t\nsend X\nconcurrent 4\nhold 50\nprobe fds >= 0\n",
               "concurrent + hold dies -- hold never reads a response");
    expect_die("name t\nsend X\nconcurrent 4\nexpect_idle 50\nprobe fds >= 0\n",
               "concurrent + expect_idle dies -- idle never reads a response");

    /* shutdown is deliberately NOT in that list: a half-close is a modifier on
     * the request, and the peer's answer to it is the whole point. */
    n = load_str("name t\nsend X\nconcurrent 4\nshutdown 1\n"
                 "probe fds >= 0\n");
    ok(n == 1 && cases[0].concurrent == 4,
       "concurrent + shutdown loads -- a half-close still expects a response");
    free_all(n);

    /* The fan drains its legs in order and blocking, so an earlier leg's read
     * time lands on every later leg's clock. Refused rather than reported as a
     * timing verdict measured against the wrong interval. */
    expect_die("name t\nsend X\nconcurrent 4\nexpect_close_within 100\n"
               "probe fds >= 0\n",
               "concurrent + expect_close_within dies -- in-order drain skews "
               "the later legs' clocks");
    expect_die("name t\nsend X\nconcurrent 4\nrecv_slow 100 10\n"
               "probe fds >= 0\n",
               "concurrent + recv_slow dies -- deliberate pacing on one leg is "
               "charged to the next");

    /* The load-bearing guard: held connections that no probe assertion reads
     * are a vacuous test, so the case is rejected at load time rather than
     * quietly passing over connections nothing observed. */
    expect_die("name t\nsend X\nopen_conns 5\n",
               "open_conns without a probe assertion dies");

    /* ---- pipeline blocks ---------------------------------------------- */

    /* Two blocks: each block's request/expects land in blocks[], the flat
     * fields stay empty, and n_blocks counts them. This is the core routing
     * contract -- a per-exchange directive after a `block` writes the block, not
     * the case. */
    n = load_str("name p\nblock one\nsend GET /a\\r\\n\\r\\n\n"
                 "expect status=200\nblock two\nsend GET /b\\r\\n\\r\\n\n"
                 "expect status=204\n");
    ok(n == 1 && cases[0].n_blocks == 2
       && cases[0].request_len == 0 && cases[0].n_expects == 0
       && cases[0].blocks[0].n_expects == 1
       && cases[0].blocks[0].expects[0].number == 200
       && cases[0].blocks[1].n_expects == 1
       && cases[0].blocks[1].expects[0].number == 204,
       "two blocks route request+expects into blocks[], flat fields stay empty");
    free_all(n);

    /* The block name is carried for diagnostics, like a case name. */
    n = load_str("name p\nblock reuse\nsend X\n");
    ok(n == 1 && cases[0].n_blocks == 1
       && cases[0].blocks[0].name != NULL
       && strcmp(cases[0].blocks[0].name, "reuse") == 0,
       "a block keeps its name for diagnostics");
    free_all(n);

    /* Each block's expects are judged against that block's own response, so a
     * saw_ flag / expect set on one block must not bleed into the next. */
    n = load_str("name p\nblock a\nsend X\ndechunk\nblock b\nsend Y\n");
    ok(n == 1 && cases[0].n_blocks == 2
       && cases[0].blocks[0].dechunk == 1
       && cases[0].blocks[1].dechunk == 0,
       "a per-exchange flag stays in its own block");
    free_all(n);

    /* Transport knobs route to the open block too, with the same sentinels the
     * flat fields get (abort_at defaults to the sentinel, not 0). */
    n = load_str("name p\nblock a\nsend X\nabort 5\n");
    ok(n == 1 && cases[0].n_blocks == 1
       && cases[0].blocks[0].saw_abort == 1
       && cases[0].blocks[0].abort_at == 5
       && cases[0].abort_at == HTTP_ABORT_NONE,
       "abort routes into the block and the flat sentinel is untouched");
    free_all(n);

    expect_die("name p\nsend X\nblock late\nsend Y\n",
               "a per-exchange directive before the first block dies");
    expect_die("name p\nblock a\nblock b\nsend Y\n",
               "a block with no send line dies");
    expect_die("name p\nblock a\nsend X\nabort 3\nblock b\nsend Y\n",
               "an abort on a non-last block dies");
    expect_die("name p\nblock a\nsend X\nhold 50\nblock b\nsend Y\n",
               "a hold on a non-last block dies");
    expect_die("name p\nblock a\nsend X\nexpect_idle 50\nblock b\nsend Y\n",
               "an expect_idle on a non-last block dies");
    expect_die("name p\nblock a\nsend X\nabort 3\nexpect status=200\n",
               "an abort block carrying an expect dies");
    expect_die("name p\nblock a\nsend X\nhold 50\nexpect status=200\n",
               "a hold block carrying an expect dies");

    /* MAX_BLOCKS + 1 blocks is rejected. Built rather than spelled so the test
     * tracks the cap. */
    {
        char     big[4096];
        size_t   off = 0;
        int      b;

        off += (size_t) snprintf(big + off, sizeof(big) - off, "name p\n");
        for (b = 0; b <= MAX_BLOCKS; b++) {
            off += (size_t) snprintf(big + off, sizeof(big) - off,
                                     "block b%d\nsend X\n", b);
        }
        expect_die(big, "more than MAX_BLOCKS blocks dies");
    }

    /* so_rcvbuf is connection-level: legal on the first block (applied at
     * connect), rejected on a later one (would silently never take effect). */
    n = load_str("name p\nblock a\nsend X\nso_rcvbuf 4096\n"
                 "block b\nsend Y\n");
    ok(n == 1 && cases[0].n_blocks == 2
       && cases[0].blocks[0].saw_rcvbuf == 1
       && cases[0].blocks[0].recv_opt.rcvbuf == 4096,
       "so_rcvbuf on the first block is accepted");
    free_all(n);

    expect_die("name p\nblock a\nsend X\nblock b\nsend Y\nso_rcvbuf 4096\n",
               "so_rcvbuf on a non-first block dies");

    /* A block-using case reloaded into a reused slot must not leak its blocks'
     * names/requests/expects -- case_free walks blocks[] for exactly this. Two
     * loads into the same array, second smaller, is the reuse LSan would catch. */
    n = load_str("name p\nblock a\nsend X\nexpect status=200\n"
                 "block b\nsend Y\nexpect status=204\n");
    free_all(n);
    n = load_str("name q\nsend Z\n");
    ok(n == 1 && cases[0].n_blocks == 0,
       "a flat case after a block case does not inherit blocks");
    free_all(n);

    /* ---- the file itself ---------------------------------------------- */

    die_on_path("/nonexistent/rules_test.does-not-exist", MAX_CASES,
                "an unopenable rule file dies");

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
