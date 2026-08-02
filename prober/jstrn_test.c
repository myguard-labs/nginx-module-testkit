/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * jstrn_test.c -- TAP self-test for prober_jstrn(), the journal field
 * escaper shared by fakesrv.c's jstrn()/jstr().
 *
 * The journal is documented as JSONL, so every consumer -- `jq`, this repo's
 * own coverage-director.sh, a human piping through a parser -- is entitled
 * to treat each line as well-formed JSON. RESP command bytes are
 * attacker-shaped and are not required to be valid UTF-8, so a byte at or
 * above 0x80 (a lone high byte, e.g. 0xC0, is never valid on its own under
 * UTF-8: 0x80-0xBF are continuation-only, 0xF8-0xFF are unassigned) must not
 * be forwarded to the journal raw -- JSON text is required to be valid
 * Unicode (RFC 8259 SS8.1), and a raw high byte breaks that contract for
 * every downstream `jq`.
 *
 * Each case is checked two ways: the exact escape text prober_jstrn()
 * produced (so the round-trip is pinned to the honest \u00XX rendering of
 * the raw byte, not merely "parses somehow"), and, when jq is on PATH, that
 * a real JSON parser accepts the produced line. The second check is a SKIP
 * rather than a hard requirement so the suite still runs on a host without
 * jq installed, matching coverage_director_test.sh's guard.
 */

/* mkstemp() is POSIX, not C11, and the build asks for -std=c11 strictly --
 * same dance as util.c. */
#define _GNU_SOURCE

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  14

static int  tests_run = 0;
static int  failures = 0;
static int  have_jq = -1;   /* -1 = not probed yet, 0 = no, 1 = yes */


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
skip(const char *name)
{
    tests_run++;
    printf("ok %d - %s # SKIP jq not on PATH\n", tests_run, name);
}


/*
 * Run prober_jstrn() on `s`/`n` and return the escaped text (the quoted JSON
 * string, including its surrounding quotes) as a malloc'd, NUL-terminated
 * buffer. open_memstream() is glibc/POSIX.1-2008, available under the
 * _GNU_SOURCE already required above for mkstemp().
 */
static char *
escape(const char *s, size_t n)
{
    FILE    *fp;
    char    *buf = NULL;
    size_t   len = 0;

    fp = open_memstream(&buf, &len);
    if (fp == NULL) {
        die("open_memstream failed");
    }

    prober_jstrn(fp, s, n);
    fclose(fp);

    return buf;
}


/*
 * Is `jq` on PATH and actually runnable? Probed once, cached, so a missing
 * binary produces one SKIP block rather than N slow fork/exec failures.
 *
 * fork()+execlp(), not system(): the argument list is a fixed literal (no
 * interpolated input reaches a shell), same shape jq_accepts() below uses to
 * invoke jq itself.
 */
static int
jq_available(void)
{
    pid_t  pid;
    int    st;

    if (have_jq >= 0) {
        return have_jq;
    }

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

        execlp("jq", "jq", "--version", (char *) NULL);  /* flawfinder: ignore */
        _exit(98);      /* exec failed: jq is not on PATH */
    }

    if (waitpid(pid, &st, 0) < 0) {
        die("waitpid failed");
    }

    have_jq = (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 1 : 0;

    return have_jq;
}


/*
 * Wrap `escaped` (a complete quoted JSON string, quotes included) as
 * `{"v": <escaped>}\n` in a temp file, and hand it to `jq empty <path>`,
 * jq's own contract for "did this file parse as JSON". Returns jq's exit
 * status via WEXITSTATUS, or dies on any earlier plumbing failure -- those
 * are test-harness bugs, not fixture behaviour under test.
 */
static int
jq_accepts(const char *escaped)
{
    static char  path[512];
    const char  *tmpdir = getenv("TMPDIR");
    int          fd;
    FILE        *f;
    pid_t        pid;
    int          st;

    if (tmpdir == NULL || *tmpdir == '\0') {
        tmpdir = "/tmp";
    }

    snprintf(path, sizeof(path), "%s/jstrn_test.XXXXXX", tmpdir);

    fd = mkstemp(path);
    if (fd < 0) {
        die("mkstemp %s failed", path);
    }

    f = fdopen(fd, "w");
    if (f == NULL) {
        die("fdopen failed");
    }

    fprintf(f, "{\"v\": %s}\n", escaped);
    fclose(f);

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

        execlp("jq", "jq", "empty", path, (char *) NULL);  /* flawfinder: ignore */
        _exit(98);      /* exec failed */
    }

    if (waitpid(pid, &st, 0) < 0) {
        die("waitpid failed");
    }

    unlink(path);

    if (!WIFEXITED(st)) {
        die("jq did not exit normally");
    }

    return WEXITSTATUS(st);
}


/*
 * One case: a single raw byte `in`, expected to render as the exact literal
 * `want` (quotes included) inside the escaped string, and -- when jq is
 * available -- to parse.
 */
static void
case_byte(unsigned char in, const char *want, const char *name)
{
    char  *got = escape((const char *) &in, 1);
    char   label[128];

    snprintf(label, sizeof(label), "%s: exact escape", name);
    ok(strcmp(got, want) == 0, label);

    if (jq_available()) {
        snprintf(label, sizeof(label), "%s: jq accepts", name);
        ok(jq_accepts(got) == 0, label);
    } else {
        snprintf(label, sizeof(label), "%s: jq accepts", name);
        skip(label);
    }

    free(got);
}


int
main(void)
{
    printf("1..%d\n", PLANNED);

    /* The bug this test exists to catch: a RESP command byte >= 0x80 is not
     * valid on its own under UTF-8 and must be \u-escaped, not forwarded
     * raw. 0xC0 is the value named in the issue -- an overlong-encoding lead
     * byte, never legal as a standalone byte. */
    case_byte(0xC0, "\"\\u00c0\"", "0xc0 (issue byte)");

    /* 0x80: lowest continuation-only byte, never valid standalone. */
    case_byte(0x80, "\"\\u0080\"", "0x80 (low boundary)");

    /* 0xff: highest byte value, never assigned in UTF-8. */
    case_byte(0xFF, "\"\\u00ff\"", "0xff (high boundary)");

    /* 0x7f (DEL) and 0x1f (C0 control) are pre-existing behaviour, pinned
     * here so a future edit to the 0x80 branch cannot silently widen or
     * narrow the neighbouring cases. */
    case_byte(0x7F, "\"\\u007f\"", "0x7f (DEL, pre-existing)");
    case_byte(0x1F, "\"\\u001f\"", "0x1f (C0 control, pre-existing)");

    /* 0x41 ('A'): ordinary ASCII must still pass through unescaped. */
    case_byte(0x41, "\"A\"", "0x41 'A' (ordinary ASCII)");

    /* A multi-byte buffer mixing a high byte with ordinary text, so the
     * escaper is exercised on `n` > 1 as well as the single-byte cases
     * above -- prober_jstrn() is length-delimited, and a bug that only
     * shows up past the first byte would not be caught by case_byte(). */
    {
        const char  raw[] = "ok\xC0next";
        char       *got = escape(raw, sizeof(raw) - 1);

        ok(strcmp(got, "\"ok\\u00c0next\"") == 0,
           "mixed buffer: exact escape");

        if (jq_available()) {
            ok(jq_accepts(got) == 0, "mixed buffer: jq accepts");
        } else {
            skip("mixed buffer: jq accepts");
        }

        free(got);
    }

    return failures ? 1 : 0;
}
