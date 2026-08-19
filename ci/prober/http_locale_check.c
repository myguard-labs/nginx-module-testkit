/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http_locale_check.c -- dedicated Turkish-i regression case for
 * http_has_header(), run standalone under LC_ALL=tr_TR.UTF-8 by the
 * locale-hostility CI job.
 *
 * CONFIRMED, not refuted: glibc's tr_TR.UTF-8 LC_CTYPE table makes 'I' and
 * 'i' FIXED POINTS of tolower()/toupper() -- tolower('I') == 'I' (not 'i'),
 * toupper('i') == 'i' (not 'I') -- rather than the C-locale mapping where
 * they fold onto each other. glibc's strncasecmp()/strcasecmp() consult that
 * same LC_CTYPE table (POSIX permits, and glibc's implementation does, use
 * locale-aware case folding here -- this is NOT the ASCII-only guarantee an
 * earlier draft of this comment assumed; verified empirically, see below).
 * The practical effect: strncasecmp("ICE-Auth", "ice-auth", 8) == 0 under the
 * C locale and != 0 under tr_TR.UTF-8, because the two 'I'/'i' no longer fold
 * to the same case. http_has_header() in ci/prober/http.c is a direct
 * strncasecmp() consumer over raw response header bytes, so a header whose
 * name or value differs from the needle only in 'I'/'i' casing silently stops
 * matching under this locale.
 *
 * A near-miss while proving this: an earlier verification pass ran
 * `locale-gen tr_TR.UTF-8` without first uncommenting `tr_TR.UTF-8 UTF-8` in
 * /etc/locale.gen. locale-gen exits 0 and regenerates whatever IS listed
 * (en_US in that case) without complaint about the one that is not, so the
 * locale silently resolved back to "C" and every assertion below "passed"
 * for the wrong reason. Caught by mutation-testing this file against a
 * properly regenerated locale afterward -- the same house rule that applies
 * to every other gate in this repo applies to a locale fixture too: prove it
 * can fail before trusting that it passed. The CI job below generates the
 * locale from a heredoc-appended /etc/locale.gen line specifically to avoid
 * depending on whatever the runner image shipped commented out.
 */

#include "http.h"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLANNED  4

static int  tests_run = 0;
static int  failures = 0;

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
parse_bytes(http_response *resp, const char *bytes, size_t len)
{
    char *buf = malloc(len + 1);

    if (buf == NULL) {
        fprintf(stderr, "http_locale_check: out of memory\n");
        exit(2);
    }
    memcpy(buf, bytes, len);
    buf[len] = '\0';

    memset(resp, 0, sizeof(*resp));
    resp->raw = buf;
    resp->raw_len = len;

    http_parse_response(resp);
}

#define PARSE(resp, lit)  parse_bytes(resp, lit, sizeof(lit) - 1)

int
main(void)
{
    http_response  r;
    char          *loc;

    /* Fail loudly rather than silently running in "C" if the CI job's
     * locale-gen step regressed and the requested locale is not actually
     * installed -- a silently-substituted locale would make this whole leg
     * report a pass that proves nothing about tr_TR at all. */
    loc = setlocale(LC_ALL, "");
    if (loc == NULL || strncmp(loc, "tr_TR", 5) != 0) {
        /* This binary is meant to be invoked with LC_ALL=tr_TR.UTF-8
         * already in the environment (setlocale(LC_ALL, "") then reads it),
         * not to select the locale itself -- so a mismatch here means the
         * CALLER's environment was wrong, which is worth failing on rather
         * than silently testing the C locale and reporting green. */
        fprintf(stderr,
            "http_locale_check: expected LC_ALL=tr_TR.UTF-8 in the "
            "environment, setlocale() reports \"%s\" -- run with "
            "LC_ALL=tr_TR.UTF-8 set\n", loc != NULL ? loc : "(null)");
        return 2;
    }

    printf("1..%d\n", PLANNED);

    /* The header is spelled in all-caps, the needle in all-lowercase, and
     * both contain 'I'/'i'. Under the C locale this is an ordinary
     * case-insensitive match. Under tr_TR.UTF-8, glibc's strncasecmp() folds
     * 'I' to itself and 'i' to itself (fixed points, not onto each other),
     * so "ICE-Auth" vs "ice-auth" stops comparing equal at the very first
     * byte -- this is the exact regression this leg exists to catch, and it
     * DOES currently fail on http_has_header() as shipped. */
    PARSE(&r, "HTTP/1.1 200 OK\r\n"
              "ICE-Auth: token\r\n"
              "\r\n"
              "body");
    ok(http_has_header(&r, "ice-auth") == 1,
       "an all-lowercase needle matches an all-caps 'I'-leading header "
       "under tr_TR (fails on unmodified http_has_header -- see the "
       "http_has_header locale fix landed alongside this test)");
    http_response_free(&r);

    /* Same bug, opposite direction: lowercase header, needle upper-cased. */
    PARSE(&r, "HTTP/1.1 200 OK\r\n"
              "ice-auth: token\r\n"
              "\r\n"
              "body");
    ok(http_has_header(&r, "ICE-AUTH") == 1,
       "an all-caps needle matches an all-lowercase 'i'-leading header "
       "under tr_TR");
    http_response_free(&r);

    /* A byte outside 'I'/'i' still needs to fold normally -- this file must
     * not have weakened the search into matching everything. */
    PARSE(&r, "HTTP/1.1 200 OK\r\nX-Ban: active\r\n\r\nbody");
    ok(http_has_header(&r, "x-BAN") == 1,
       "non-i/I letters still fold normally under tr_TR");
    http_response_free(&r);

    /* Sanity: a genuine mismatch (different letter entirely) must still not
     * match -- this file must not have weakened the search into matching
     * everything to pass its own locale cases. */
    PARSE(&r, "HTTP/1.1 200 OK\r\nX-Other: y\r\n\r\nbody");
    ok(http_has_header(&r, "Ice-Auth") == 0,
       "an absent header still does not match under tr_TR");
    http_response_free(&r);

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }
    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
