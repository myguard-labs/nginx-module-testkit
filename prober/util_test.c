/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * util_test.c -- TAP self-test for xstrtol() and the monotonic clock.
 *
 * xstrtol() replaced atoi() on the -p and -t flags, and it exists for one
 * reason: atoi() reports a conversion error the same way it reports a genuine
 * zero. `-p http` became port 0 and `-t junk` became a 0 ms timeout, which is
 * SO_RCVTIMEO's "block indefinitely" -- so a typo'd flag hung the run or reded
 * every case while pointing nowhere near the flag that caused it.
 *
 * That makes the REJECTIONS the interesting half of this file. A validator that
 * accepts everything still passes any test that only feeds it valid input, so
 * most of what follows checks that malformed values are refused rather than
 * quietly converted.
 *
 * xstrtol() dies rather than returning an error, so the rejection cases cannot
 * be called in-process: die() exits. Each one runs in a fork and the parent
 * asserts on the child's exit status (2, per util.h) and on the message it
 * printed. Testing the status alone would pass on a crash, which is why the
 * message is checked too.
 */

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  24

static int  tests_run = 0;
static int  failures = 0;


/*
 * prober_timespec_ms() on a hand-built timespec. The fields are assigned rather
 * than brace-initialised because struct timespec's member ORDER is not fixed by
 * the standard, and a positional initialiser that silently swaps them would
 * make every clock row below assert the wrong thing while still passing.
 */
static int64_t
ms_of(time_t sec, long nsec)
{
    struct timespec ts;

    ts.tv_sec = sec;
    ts.tv_nsec = nsec;

    return prober_timespec_ms(&ts);
}


static void
ok(int cond, const char *name)
{
    tests_run++;

    if (cond) {
        printf("ok %d - %s\n", tests_run, name);
    } else {
        printf("not ok %d - %s\n", tests_run, name);
        failures++;
    }
}


/*
 * Run xstrtol(s) in a child and report how it died.
 *
 * Returns the child's exit status, with the child's stderr captured into `msg`
 * so the caller can assert the diagnostic actually names the problem. A child
 * that is killed by a signal reports 128+signo, which no legitimate path
 * produces, so a crash cannot be mistaken for a clean rejection.
 */
static int
run_child(const char *s, const char *what, char *msg, size_t msglen)
{
    int    pipefd[2];
    int    status;
    pid_t  pid;

    msg[0] = '\0';

    if (pipe(pipefd) != 0) {
        return -1;
    }

    /*
     * Flush before forking. stdout is a pipe under `prove`, so it is fully
     * buffered: the TAP printed so far is still sitting in the parent's buffer,
     * the child inherits a copy of it, and the child's _exit()/die() path
     * flushes that copy too -- emitting every preceding line a second time, once
     * per fork. The run still exits 0, so the symptom is not a failure, it is a
     * TAP stream with duplicate plans that a harness either mis-counts or
     * rejects outright.
     */
    fflush(stdout);
    fflush(stderr);

    pid = fork();

    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        (void) xstrtol(s, what);

        /* Reached only if xstrtol returned where it should have died. Exit 0
         * so the parent's "expected 2" assertion fails loudly. */
        _exit(0);
    }

    close(pipefd[1]);

    /*
     * Drain to EOF rather than reading once.
     *
     * A single read() returns whatever one chunk is available and the close()
     * that followed it left the child writing into a pipe with no reader --
     * SIGPIPE, so the child died of signal 13 (reported here as 141) BEFORE
     * die() could exit 2, and the assertion below saw a crash instead of a
     * clean rejection. It only bit when the message was long enough or the
     * scheduler unlucky enough for the child to still be writing, which made it
     * flaky rather than dead: 2 runs in 5. Reading to EOF means the child is
     * never writing into a closed pipe.
     */
    {
        size_t   used = 0;
        ssize_t  n;

        while (used + 1 < msglen
               && (n = read(pipefd[0], msg + used, msglen - 1 - used)) > 0)
        {
            used += (size_t) n;
        }

        msg[used] = '\0';
    }

    close(pipefd[0]);

    /*
     * waitpid can fail (EINTR, or ECHILD if the child was somehow already
     * reaped), and on failure `status` is never written. Reading it through
     * WIFSIGNALED/WIFEXITED then interprets an uninitialized value, which is
     * undefined behaviour that would most likely surface as a confusing,
     * intermittent test result rather than an obvious crash. Retry on EINTR,
     * report anything else as -1 so the assertion fails loudly instead of on
     * garbage.
     */
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }

    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}


static void
rejects(const char *s, const char *expect_substr, const char *name)
{
    char  msg[512];
    int   status = run_child(s, "-t", msg, sizeof(msg));

    if (status != 2) {
        printf("# expected exit 2, got %d for input \"%s\"\n",
               status, s ? s : "(null)");
        ok(0, name);
        return;
    }

    if (strstr(msg, expect_substr) == NULL) {
        printf("# message did not mention \"%s\": %s\n", expect_substr, msg);
        ok(0, name);
        return;
    }

    ok(1, name);
}


int
main(void)
{
    printf("1..%d\n", PLANNED);

    /* The values that must be accepted, returned exactly. */
    ok(xstrtol("0", "-t") == 0, "zero parses");
    ok(xstrtol("1", "-t") == 1, "one parses");
    ok(xstrtol("18099", "-p") == 18099, "a port parses");
    ok(xstrtol("-5", "-t") == -5, "a negative value parses");
    ok(xstrtol("007", "-t") == 7, "leading zeros are decimal, not octal");
    ok(xstrtol("  12", "-t") == 12, "strtol's leading-space skip is preserved");

    /*
     * The rejections. "10junk" is the case that motivated this: atoi() returns
     * 10 and discards the rest, so a rule file or flag that says 10junk builds
     * a request the author did not write.
     */
    rejects("junk", "is not a number", "a non-numeric token is refused");
    rejects("10junk", "is not a number", "trailing garbage is refused");
    rejects("", "empty", "an empty value is refused");
    rejects(NULL, "empty", "a NULL value is refused");
    rejects("12 34", "is not a number", "an embedded space is refused");
    rejects("0x10", "is not a number", "hex is refused (base is 10, not 0)");

    /*
     * ERANGE. atoi() has undefined behaviour here; strtol saturates at
     * LONG_MAX/LONG_MIN and sets errno, which is the only reason this is
     * distinguishable from a legitimate huge value.
     */
    rejects("99999999999999999999999", "out of range",
            "a value past LONG_MAX is refused");
    rejects("-99999999999999999999999", "out of range",
            "a value past LONG_MIN is refused");

    /*
     * The clock. The conversion is exact and truncating, and the ENDPOINTS are
     * what these rows exist for: every value past INT32_MAX milliseconds
     * overflows a 32-bit long, which is what util.h's header describes and what
     * the arch-32bit workflow is the only leg able to execute. A test host is
     * never up for 24.9 days mid-run, so the wrap cannot be reached by reading
     * the real clock -- the timespec is handed in instead.
     *
     * These are CONTRACT PINS, not regression rows: on an LP64 build they pass
     * with the pre-fix `long` code too, because there long IS 64 bits. Reverting
     * the type is caught under -m32 and by nothing here. The value rows below
     * (truncation, the seconds-to-ms scale) are what a plain-arch mutation can
     * kill.
     */
    ok(ms_of(0, 0) == 0, "clock: a zero timespec is zero ms");
    ok(ms_of(1, 0) == 1000, "clock: seconds are scaled to ms");
    ok(ms_of(0, 999999999) == 999, "clock: the sub-second part is carried");
    ok(ms_of(0, 1999999) == 1, "clock: nanoseconds truncate, they do not round");

    /* INT32_MAX ms is 2147483.647 s of uptime. The three rows walk across it. */
    ok(ms_of(2147483, 0) == INT64_C(2147483000),
       "clock: just under INT32_MAX ms is exact");
    ok(ms_of(2147483, 648000000) == INT64_C(2147483648),
       "clock: the first ms past INT32_MAX is exact, not negative");
    ok(ms_of(2147484, 0) == INT64_C(2147484000),
       "clock: a 24.9-day uptime does not wrap");

    /* Past UINT32_MAX ms as well, so an unsigned 32-bit type is excluded too. */
    ok(ms_of(4294968, 0) == INT64_C(4294968000),
       "clock: a 49.7-day uptime does not wrap");

    {
        int64_t a = prober_monotonic_ms();
        int64_t b = prober_monotonic_ms();

        /*
         * Weak on purpose: the value is an unspecified epoch, so the only
         * things assertable without a second clock are that it advances in one
         * direction and that the syscall path is wired to the conversion at
         * all. A zero would mean clock_gettime failed -- or that the body was
         * replaced by its error return.
         */
        ok(a > 0, "clock: the monotonic reading is not the failure sentinel");
        ok(b >= a, "clock: successive readings do not go backwards");
    }

    if (tests_run != PLANNED) {
        printf("# planned %d tests but ran %d\n", PLANNED, tests_run);
        return 1;
    }

    return failures == 0 ? 0 : 1;
}
