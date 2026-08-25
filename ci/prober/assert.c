/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * assert.c -- see assert.h.
 */

/* memmem() is GNU/POSIX-2024, not C11, and the build asks for -std=c11
 * strictly -- same dance as util.c. */
#define _GNU_SOURCE

#include "assert.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* For body_sha256 hashing. */
#include <openssl/sha.h>
#include <openssl/err.h>


int
compare_number(double have, const char *op, double want)
{
    if (strcmp(op, "==") == 0) return have == want;
    if (strcmp(op, "!=") == 0) return have != want;
    if (strcmp(op, "<")  == 0) return have <  want;
    if (strcmp(op, "<=") == 0) return have <= want;
    if (strcmp(op, ">")  == 0) return have >  want;
    if (strcmp(op, ">=") == 0) return have >= want;

    /* The rule parser accepts only the operators above (plus "~", which never
     * reaches a numeric comparison), so arriving here means the two lists have
     * drifted apart -- a harness bug, not a user one. */
    die("unknown numeric operator \"%s\"", op);
}


const char *
unquote(const char *lit, char *scratch, size_t scratchlen)
{
    size_t len = strlen(lit);

    if (len >= 2 && lit[0] == '"' && lit[len - 1] == '"') {
        if (len - 1 >= scratchlen) {
            return NULL;
        }

        memcpy(scratch, lit + 1, len - 2);
        scratch[len - 2] = '\0';

        return scratch;
    }

    return lit;
}


/*
 * Parse a rule literal as a number, under the SAME grammar the document side
 * enforces -- by calling it, so the two cannot drift.
 *
 * strtod() stops at the first character it cannot use and reports success for
 * the prefix, so "1x" would otherwise compare as 1 and a mistyped expectation
 * would quietly assert something nobody wrote. It is also far more permissive
 * than JSON: it takes "nan", "inf", "0x7", "+1" and ".5". Those are worse than
 * a typo -- `probe fds != nan` is TRUE for every finite value, and `probe fds <
 * inf` is true for every value at all, so a line that reads like an assertion
 * cannot fail. json_number_parse() rejects all of them, and pins the radix
 * point to '.' whatever LC_NUMERIC the run inherits.
 */
static int
literal_number(const char *want, double *out)
{
    return json_number_parse(want, out);
}


/*
 * The bytes a body oracle should judge.
 *
 * The most-decoded buffer available: the CANONICAL JSON when the case asked for
 * `json_sort` and it succeeded, else the INFLATED body when it asked for
 * `gunzip` and that succeeded, else the DECODED body when it asked for
 * `dechunk` and that succeeded, else the raw wire body. The layers stack in the
 * order the transforms apply -- framing off, then decompression, then canonical
 * rewrite -- so `dechunk gunzip json_sort` reads the canonicalized inflated
 * bytes. Routed through one helper rather
 * than repeated at each oracle so the body assertions can never disagree about
 * which bytes they are looking at -- one of them still reading `resp->body`
 * after a decode would silently assert on chunk size lines or gzip magic.
 *
 * A FAILED decode at either layer deliberately falls back to the next-outer
 * buffer rather than reporting an empty one: prober.c has already failed the
 * case on the decode error, and an oracle inventing an empty body on top of
 * that would print a second, misleading diagnostic about content that was never
 * the problem.
 */
static const char *
body_bytes(const http_response *resp, size_t *len)
{
    if (resp->json_sort_status == HTTP_JSON_SORT_OK && resp->canon != NULL) {
        *len = resp->canon_len;
        return resp->canon;
    }

    if (resp->gunzip_status == HTTP_GUNZIP_OK && resp->inflated != NULL) {
        *len = resp->inflated_len;
        return resp->inflated;
    }

    if (resp->dechunk_status == HTTP_DECHUNK_OK && resp->decoded != NULL) {
        *len = resp->decoded_len;
        return resp->decoded;
    }

    *len = resp->body_len;
    return resp->body;
}


int
expect_reads_body(const expectation *e)
{
    switch (e->kind) {
    case EXPECT_BODY_CONTAINS:
    case EXPECT_NOT_BODY_CONTAINS:
    case EXPECT_BODY_SHA256:
        return 1;
    default:
        return 0;
    }
}


int
eval_expect(const expectation *e, const http_response *resp, char *why,
            size_t whylen)
{
    const char  *body;
    size_t       body_len;

    body = body_bytes(resp, &body_len);

    switch (e->kind) {

    case EXPECT_STATUS:
        if (resp->status != (int) e->number) {
            snprintf(why, whylen, "status: have %d, want %ld",
                     resp->status, e->number);
            return 0;
        }
        return 1;

    case EXPECT_BODY_CONTAINS:
        if (body == NULL
            || memmem(body, body_len,
                      e->text, strlen(e->text)) == NULL)
        {
            snprintf(why, whylen, "body does not contain \"%.128s\"", e->text);
            return 0;
        }
        return 1;

    case EXPECT_HEADER_CONTAINS:
        if (!http_has_header(resp, e->text)) {
            snprintf(why, whylen, "no header matching \"%.128s\"", e->text);
            return 0;
        }
        return 1;

    case EXPECT_NOT_BODY_CONTAINS:
        /* An absent body trivially does not contain the needle, so it PASSES
         * here -- the negative matcher asserts absence, and a response with
         * no body is the strongest form of absence there is. A rule that also
         * needs the body to exist says so with a positive expect. */
        if (body != NULL
            && memmem(body, body_len,
                      e->text, strlen(e->text)) != NULL)
        {
            snprintf(why, whylen, "body contains \"%.128s\", expected not to",
                     e->text);
            return 0;
        }
        return 1;

    case EXPECT_NOT_HEADER_CONTAINS:
        if (http_has_header(resp, e->text)) {
            snprintf(why, whylen, "header matches \"%.128s\", expected not to",
                     e->text);
            return 0;
        }
        return 1;

    case EXPECT_BODY_SHA256: {
        unsigned char  digest[SHA256_DIGEST_LENGTH];
        char           have_hex[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
        size_t         i;

        if (body == NULL) {
            snprintf(why, whylen, "no body to hash");
            return 0;
        }

        SHA256((const unsigned char *)body, body_len, digest);

        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            snprintf(&have_hex[i * 2], 3, "%02x", digest[i]);
        }

        if (strcmp(have_hex, e->text) != 0) {
            snprintf(why, whylen, "body sha256: have %.64s, want %.64s",
                     have_hex, e->text);
            return 0;
        }
        return 1;
    }

    case EXPECT_STATUS_LIKE: {
        char  code[16];
        int   n;

        /* -1 (unparseable status line) is rendered literally, so a rule can
         * assert on garbage on purpose: `error_code_like ^-1$`. */
        n = snprintf(code, sizeof(code), "%d", resp->status);

        if (n < 0 || (size_t) n >= sizeof(code)
            || regexec(&e->re, code, 0, NULL, 0) != 0)
        {
            snprintf(why, whylen, "status %d does not match /%.128s/",
                     resp->status, e->text);
            return 0;
        }
        return 1;
    }

    case EXPECT_RAW_RESPONSE_HEADERS_LIKE: {
        if (resp->headers == NULL
            || regexec(&e->re, resp->headers, 0, NULL, 0) != 0)
        {
            snprintf(why, whylen, "headers do not match /%.128s/", e->text);
            return 0;
        }
        return 1;
    }
    }

    /* Unreachable with a well-formed expectation; the parser assigns every
     * kind in the enum. Same drift guard as compare_number()'s. */
    die("unknown expect kind %d", (int) e->kind);
}


int
eval_close_within(const http_response *resp, long deadline_ms, char *why,
                  size_t whylen)
{
    switch (resp->close_reason) {

    case HTTP_CLOSE_FIN:
    case HTTP_CLOSE_RESET:
        if (resp->close_ms > deadline_ms) {
            /* Name the manner of the close, not just the miss. A server that
             * RESETS a connection it was supposed to close gracefully is doing
             * something different from one that is merely slow, and the two
             * want different fixes. */
            snprintf(why, whylen,
                     "server %s after %ld ms, wanted a close within %ld ms",
                     resp->close_reason == HTTP_CLOSE_RESET
                         ? "reset the connection" : "closed",
                     resp->close_ms, deadline_ms);
            return 0;
        }
        return 1;

    case HTTP_CLOSE_TIMEOUT:
        snprintf(why, whylen,
                 "connection still open %ld ms after the request; wanted a "
                 "close within %ld ms", resp->close_ms, deadline_ms);
        return 0;

    default:
        /*
         * No close was observed at all, which means the exchange never read
         * the socket -- an aborted or held case. The parser rejects those
         * combinations, so reaching here is a harness defect rather than a
         * rule-file one; report it as a failure rather than dying, so one bad
         * case does not truncate the TAP stream, and never as a pass, which is
         * what an unhandled reason would silently become.
         */
        snprintf(why, whylen,
                 "no connection close was observed, so a %ld ms close "
                 "deadline cannot be judged", deadline_ms);
        return 0;
    }
}


int
eval_idle(const http_response *resp, long wait_ms, char *why, size_t whylen)
{
    switch (resp->close_reason) {

    case HTTP_CLOSE_IDLE:
        return 1;

    case HTTP_CLOSE_DATA:
        /* The server answered instead of sitting still. Named as an answer
         * rather than as a generic miss, because a server that responds early
         * and one that hangs up early are different bugs -- see the FIN/RESET
         * arm below for the other half of that distinction. */
        snprintf(why, whylen,
                 "server sent data after %ld ms, wanted the connection left "
                 "open and silent for %ld ms", resp->close_ms, wait_ms);
        return 0;

    case HTTP_CLOSE_FIN:
    case HTTP_CLOSE_RESET:
        snprintf(why, whylen,
                 "server %s after %ld ms, wanted the connection left open and "
                 "silent for %ld ms",
                 resp->close_reason == HTTP_CLOSE_RESET
                     ? "reset the connection" : "closed",
                 resp->close_ms, wait_ms);
        return 0;

    default:
        /*
         * Reached only if the idle wait did not run -- an aborted or held case,
         * or a plain read-loop exchange. The parser rejects every one of those
         * combinations, so this is a harness defect rather than a rule-file
         * one. Reported as a failure rather than a pass for the same reason
         * eval_close_within()'s default is: an unhandled reason must never
         * become a silent green.
         */
        snprintf(why, whylen,
                 "no idle wait was performed, so a %ld ms idle assertion "
                 "cannot be judged", wait_ms);
        return 0;
    }
}


int
log_lines_match(const char *buf, size_t len, const regex_t *re)
{
    char   *copy, *line, *save = NULL;
    int     matched = 0;

    if (len == 0) {
        return 0;
    }

    /*
     * One heap copy with newlines turned into terminators, rather than a
     * fixed per-line stack buffer: nginx error-log lines routinely exceed any
     * comfortable stack bound (a request line is echoed into them verbatim),
     * and a matcher that silently truncates is a matcher that misses exactly
     * the oversized line worth catching.
     */
    copy = malloc(len + 1);
    if (copy == NULL) {
        die("out of memory");
    }

    memcpy(copy, buf, len);
    copy[len] = '\0';

    for (line = strtok_r(copy, "\n", &save);
         line != NULL && !matched;
         line = strtok_r(NULL, "\n", &save))
    {
        matched = (regexec(re, line, 0, NULL, 0) == 0);
    }

    free(copy);

    return matched;
}


int
eval_probe(const json_value *doc, const probe_assert *pa, char *why,
           size_t whylen)
{
    char              scratch[512];
    const char       *want;
    const json_value *v;

    v = json_get(doc, pa->path);

    if (v == NULL) {
        snprintf(why, whylen, "probe path \"%.128s\" not present in document",
                 pa->path);
        return 0;
    }

    want = unquote(pa->literal, scratch, sizeof(scratch));

    if (want == NULL) {
        snprintf(why, whylen,
                 "probe %.128s: literal is longer than %zu bytes",
                 pa->path, sizeof(scratch) - 1);
        return 0;
    }

    switch (v->type) {

    case JSON_NUMBER: {
        double wanted;

        if (!literal_number(want, &wanted)) {
            snprintf(why, whylen,
                     "%.128s is a number but the rule compares it to \"%.128s\"",
                     pa->path, want);
            return 0;
        }

        if (!compare_number(v->number, pa->op, wanted)) {
            snprintf(why, whylen, "%.128s: have %g, want %.16s %.128s",
                     pa->path, v->number, pa->op, want);
            return 0;
        }

        return 1;
    }

    case JSON_STRING:
        if (strcmp(pa->op, "==") == 0) {
            if (strcmp(v->string, want) != 0) {
                snprintf(why, whylen, "%.128s: have \"%.128s\", want \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "!=") == 0) {
            if (strcmp(v->string, want) == 0) {
                snprintf(why, whylen, "%.128s: have \"%.128s\", want != \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "~") == 0) {
            if (strstr(v->string, want) == NULL) {
                snprintf(why, whylen, "%.128s: \"%.128s\" does not contain \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        snprintf(why, whylen, "operator \"%.32s\" is not valid on a string",
                 pa->op);
        return 0;

    case JSON_BOOL: {
        int wanted = (strcmp(want, "true") == 0);

        if (strcmp(want, "true") != 0 && strcmp(want, "false") != 0) {
            snprintf(why, whylen,
                     "%.128s is a boolean but the rule compares it to \"%.128s\"",
                     pa->path, want);
            return 0;
        }

        if (strcmp(pa->op, "==") == 0) {
            if (v->boolean != wanted) {
                snprintf(why, whylen, "%.128s: have %s, want %.128s", pa->path,
                         v->boolean ? "true" : "false", want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "!=") == 0) {
            if (v->boolean == wanted) {
                snprintf(why, whylen, "%.128s: have %s, want != %.128s",
                         pa->path, v->boolean ? "true" : "false", want);
                return 0;
            }
            return 1;
        }

        snprintf(why, whylen, "operator \"%.32s\" is not valid on a boolean",
                 pa->op);
        return 0;
    }

    default:
        snprintf(why, whylen, "%.128s is of type %s, which cannot be compared",
                 pa->path, json_type_name(v->type));
        return 0;
    }
}


/*
 * The probe fields whose -1 is an "unreadable /proc" (for "timers", an
 * "uninitialised tree"; for the three "zone.slab_*" counters, a zone whose
 * slab pool the master has mapped but not yet initialised, so stats[] is still
 * NULL) sentinel rather than a real value. Kept as an explicit
 * list rather than a "-1 is always unavailable" blanket: a module hook could
 * legitimately render a signed field that reaches -1, and silently swallowing
 * a delta over it would be the very fail-open this check exists to prevent.
 *
 * This list is NOT structurally pinned to ../../src/ngx_test_probe.c -- ci/prober/
 * and src/ are on opposite sides of the module/harness boundary, with no
 * shared header, and src/ngx_test_probe.c needs real nginx headers to compile
 * so it cannot be #included here. What keeps the two from drifting apart is
 * ci/prober/sentinel_fields_test.sh, which greps the emitter for every function
 * whose doc comment claims the -1-sentinel discipline and fails if this array
 * is missing the field that function renders (this is exactly how "timers"
 * went missing: PR #165 added ngx_test_probe_timer_count() with that
 * discipline, PR #130 was the last to touch this array, and nothing cross-
 * checked the two).
 */
static int
path_is_proc_sentinel_field(const char *path)
{
    static const char *const fields[] = {
        "fds",
        "fds_by_kind.socket",
        "fds_by_kind.file",
        "fds_by_kind.anon",
        "fds_by_kind.other",
        "smaps.pss",
        "smaps.private_dirty",
        "timers",
        "zone.slab_reqs",
        "zone.slab_fails",
        "zone.slab_used",
    };
    size_t i;

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (strcmp(path, fields[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


int
eval_delta(const json_value *before, const json_value *after,
           const probe_assert *pa, const char *label, char *why, size_t whylen)
{
    char              scratch[512];
    double            wanted, change;
    const char       *want;
    const json_value *b, *a;

    b = json_get(before, pa->path);
    a = json_get(after, pa->path);

    if (b == NULL || a == NULL) {
        snprintf(why, whylen, "%s path \"%.128s\" is not present in the %s "
                 "snapshot", label, pa->path,
                 (b == NULL) ? "origin" : "after");
        return 0;
    }

    if (b->type != JSON_NUMBER || a->type != JSON_NUMBER) {
        snprintf(why, whylen, "%s path \"%.128s\" is %s/%s, not a number",
                 label, pa->path, json_type_name(b->type), json_type_name(a->type));
        return 0;
    }

    /*
     * The /proc-derived fields render -1 when the probe could not read /proc at
     * all: "fds", every "fds_by_kind.*" bucket, and both "smaps.*" figures.
     * Both snapshots then carry -1, and the subtraction below cancels them into
     * a delta of 0 -- so a `delta <field> == 0` rule would PASS while measuring
     * nothing. An assertion that cannot fail is worse than a missing one, so the
     * sentinel is rejected in EITHER snapshot before it can cancel. -1 is not a
     * reachable real value for any of these (a count is >= 0, and PSS/dirty kB
     * are >= 0), so treating it as "unavailable" never masks a legitimate
     * reading.
     */
    if (path_is_proc_sentinel_field(pa->path)
        && (b->number == -1 || a->number == -1))
    {
        snprintf(why, whylen,
                 "%s path \"%.128s\" is unavailable (-1) in the %s snapshot",
                 label, pa->path, (b->number == -1) ? "origin" : "after");
        return 0;
    }

    want = unquote(pa->literal, scratch, sizeof(scratch));

    if (want == NULL) {
        snprintf(why, whylen, "%s %.128s: literal is longer than %zu bytes",
                 label, pa->path, sizeof(scratch) - 1);
        return 0;
    }

    if (!literal_number(want, &wanted)) {
        snprintf(why, whylen, "%s %.128s: \"%.128s\" is not a number",
                 label, pa->path, want);
        return 0;
    }

    change = a->number - b->number;

    if (!compare_number(change, pa->op, wanted)) {
        snprintf(why, whylen,
                 "%s %.128s: %g -> %g is %+g, want %.16s %.128s",
                 label, pa->path, b->number, a->number, change, pa->op, want);
        return 0;
    }

    return 1;
}


/*
 * Fetch one required numeric field from both snapshots. Returns 0 with `why`
 * filled when either is missing or not a number -- the absence of a field the
 * generic probe renders unconditionally means the document is not the one this
 * oracle thinks it is, and treating that as "nothing to compare" would turn
 * the check off silently rather than loudly.
 */
static int
pid_field_pair(const json_value *before, const json_value *after,
               const char *field, const json_value **bp,
               const json_value **ap, char *why, size_t whylen)
{
    const json_value *b, *a;

    b = json_get(before, field);
    a = json_get(after, field);

    if (b == NULL || a == NULL) {
        snprintf(why, whylen, "\"%s\" is not present in the %s snapshot, so "
                 "worker survival cannot be established",
                 field, (b == NULL) ? "before" : "after");
        return 0;
    }

    if (b->type != JSON_NUMBER || a->type != JSON_NUMBER) {
        snprintf(why, whylen, "\"%s\" is %s/%s, not a number",
                 field, json_type_name(b->type), json_type_name(a->type));
        return 0;
    }

    *bp = b;
    *ap = a;
    return 1;
}


int
eval_pid_stable(const json_value *before, const json_value *after,
                int may_change, char *why, size_t whylen)
{
    const json_value *b, *a;

    if (may_change) {
        /*
         * The worker may be a different one, but it must belong to the same
         * master. Compared on "ppid" alone: the after-pid is free to be any
         * value at all, so reading it here would only invite an assertion
         * about it that does not hold across a reload.
         */
        if (!pid_field_pair(before, after, "ppid", &b, &a, why, whylen)) {
            return 0;
        }

        if (b->number != a->number) {
            snprintf(why, whylen, "worker master pid changed %g -> %g: the "
                     "worker answering now is not a child of the master that "
                     "served the before-snapshot", b->number, a->number);
            return 0;
        }

        return 1;
    }

    if (!pid_field_pair(before, after, "pid", &b, &a, why, whylen)) {
        return 0;
    }

    /*
     * Compared as doubles because that is how the JSON reader stores every
     * number. A pid is far below 2^53, so the representation is exact and
     * equality here means equality of the integers the probe printed.
     */
    if (b->number != a->number) {
        snprintf(why, whylen, "worker pid changed %g -> %g: the worker died "
                 "and was respawned during this case", b->number, a->number);
        return 0;
    }

    return 1;
}
