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
        "zone.digest",
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


/*
 * Count the DISTINCT values in `pids`. O(n^2) on purpose: n is bounded by
 * MAX_CONCURRENT (64), so the quadratic scan is a few thousand comparisons at
 * worst and needs neither an allocation that could fail on the assertion path
 * nor a sort that would reorder the caller's array.
 *
 * pids are doubles because that is how json.c stores every number it reads. A
 * pid is far below 2^53, so the representation is exact and == here means
 * equality of the integers the probe printed.
 */
size_t
fanout_distinct_pids(const double *pids, size_t n)
{
    size_t  i, j, distinct = 0;

    for (i = 0; i < n; i++) {
        int seen = 0;

        for (j = 0; j < i; j++) {
            if (pids[j] == pids[i]) {
                seen = 1;
                break;
            }
        }

        if (!seen) {
            distinct++;
        }
    }

    return distinct;
}


int
eval_fanout_coverage(const double *pids, size_t n, int min_workers,
                     size_t *distinct_out, char *why, size_t whylen)
{
    size_t  distinct;

    /*
     * No legs collected at all. Reached only if the caller's request loop
     * failed to record a single pid, which means the coverage claim rests on
     * nothing -- report it as the failure it is rather than letting a distinct
     * count of 0 compare against a min of 0 and pass.
     */
    if (n == 0) {
        snprintf(why, whylen, "fanout coverage: no responses carried a worker "
                 "pid, so nothing was sampled");

        if (distinct_out != NULL) {
            *distinct_out = 0;
        }

        return 0;
    }

    /*
     * A min of 0 or 1 asserts nothing: the parser floors it at 2 and defaults
     * it to 2 precisely so an unset value cannot mean "one worker is enough".
     * If one ever reaches here the oracle has been disarmed, and an oracle
     * that cannot fail must say so loudly rather than return the pass it is
     * structurally guaranteed to produce.
     */
    if (min_workers < 2) {
        snprintf(why, whylen, "fanout coverage: min_workers %d asserts nothing "
                 "(a valid bound is >= 2)", min_workers);

        if (distinct_out != NULL) {
            *distinct_out = 0;
        }

        return 0;
    }

    distinct = fanout_distinct_pids(pids, n);

    if (distinct_out != NULL) {
        *distinct_out = distinct;
    }

    if (distinct < (size_t) min_workers) {
        snprintf(why, whylen, "fanout coverage: %zu of %zu responses came from "
                 "%zu distinct worker%s, need >= %d -- the case sampled too few "
                 "workers to claim cross-worker agreement",
                 n, n, distinct, distinct == 1 ? "" : "s", min_workers);
        return 0;
    }

    return 1;
}


int
quiesce_underflowed(double v)
{
    /*
     * The probe renders every zone counter through ngx_int_t, so an
     * ngx_uint_t decremented once past zero does not arrive as -1: it arrives
     * as the bit pattern of ULONG_MAX reinterpreted, which the emitter prints
     * and json.c parses back as a double either enormous or negative
     * depending on the build's word size and the counter's own type.
     *
     * Both directions are refused, and NEITHER is a plausible honest reading
     * of a counter. A negative count of anything is meaningless. A count above
     * QUIESCE_SANE_MAX would require more allocations than the zone has bytes
     * to describe, so it is a wrapped value being read as a large one -- the
     * exact shape that makes an unbounded rule-file bound (`<= 1`, `>= 0`)
     * report ok on an underflow.
     *
     * -1 is deliberately NOT special-cased into "unavailable" here. The
     * @sentinel-schema fields render -1 when the pool is unmapped, and the
     * callers below must treat that as a failure too: an invariant judged
     * against a field the probe could not read is an invariant that did not
     * run, and a skip is indistinguishable from a pass in TAP.
     */
    return (v < 0) || (v > QUIESCE_SANE_MAX);
}


int
eval_zone_coherent(const char *path, const double *vals, size_t n,
                   char *why, size_t whylen)
{
    size_t  i;

    /*
     * Fewer than two readings cannot disagree. Refused rather than passed:
     * `coherent` over one worker's answer is the single-sample tautology the
     * parser's fanout requirement exists to prevent, and if one ever reaches
     * here the oracle has been disarmed on the executor side instead.
     */
    if (n < 2) {
        snprintf(why, whylen, "zone_invariant coherent %.128s: only %zu "
                 "reading%s collected, so nothing could disagree "
                 "(a coherence claim needs at least 2 workers)",
                 path, n, n == 1 ? "" : "s");
        return 0;
    }

    for (i = 0; i < n; i++) {
        if (quiesce_underflowed(vals[i])) {
            snprintf(why, whylen, "zone_invariant coherent %.128s: reading %zu "
                     "is %g, which is not an honest counter value (an unsigned "
                     "counter decremented past zero, or the -1 unavailable "
                     "sentinel)", path, i + 1, vals[i]);
            return 0;
        }
    }

    for (i = 1; i < n; i++) {
        if (vals[i] != vals[0]) {
            /*
             * Names the two readings and their index, because "the workers
             * disagree" is not actionable: which worker read what is the whole
             * content of the finding.
             */
            snprintf(why, whylen, "zone_invariant coherent %.128s: worker "
                     "reading 1 is %g but reading %zu is %g -- the zone is one "
                     "shared mapping, so at rest the workers cannot honestly "
                     "disagree about it", path, vals[0], i + 1, vals[i]);
            return 0;
        }
    }

    return 1;
}


int
eval_zone_at_rest(const char *path, const char *op, const char *literal,
                  double have, char *why, size_t whylen)
{
    char         scratch[512];
    const char  *want_s;
    double       want;

    /*
     * The literal is unquoted and converted HERE rather than by the caller, so
     * that the whole at_rest verdict -- literal handling included -- is one
     * seam that can be driven to red without a server. A caller that did the
     * conversion would own a failure path this function's tests never reach.
     */
    want_s = unquote(literal, scratch, sizeof(scratch));

    if (want_s == NULL) {
        snprintf(why, whylen, "zone_invariant at_rest %.128s: literal is "
                 "longer than %zu bytes", path, sizeof(scratch) - 1);
        return 0;
    }

    if (!literal_number(want_s, &want)) {
        snprintf(why, whylen, "zone_invariant at_rest %.128s: \"%.128s\" is "
                 "not a number, so the bound cannot be applied",
                 path, want_s);
        return 0;
    }

    /*
     * THE BOUND COMES FIRST, before the rule file's operator is applied.
     *
     * This ordering is the whole underflow defence and is not interchangeable
     * with checking afterwards. A shared inflight counter decremented once too
     * often reads as an enormous value, and the operators a rule author
     * naturally writes for a resting counter -- `>= 0`, `<= 1`, `!= 5` -- are
     * all SATISFIED by that value. The oracle would report ok on precisely the
     * defect it was written to catch, and COR-5's class is exactly a counter
     * that failed to return to zero.
     */
    if (quiesce_underflowed(have)) {
        snprintf(why, whylen, "zone_invariant at_rest %.128s: read %g, which "
                 "is not an honest resting value -- an unsigned counter "
                 "decremented past zero reads as a huge number, and the "
                 "unavailable sentinel reads as -1; either way the %.16s %g "
                 "bound was never meaningfully applied",
                 path, have, op, want);
        return 0;
    }

    if (!compare_number(have, op, want)) {
        snprintf(why, whylen, "zone_invariant at_rest %.128s: have %g, want "
                 "%.16s %g -- the counter did not return to its resting value "
                 "after the case quiesced", path, have, op, want);
        return 0;
    }

    return 1;
}


int
eval_zone_monotonic(const char *path, const double *vals, size_t n,
                    char *why, size_t whylen)
{
    size_t  i;

    /*
     * One reading is trivially non-decreasing, so it is refused for the same
     * reason a single-sample coherence claim is: a form that cannot fail is
     * not an oracle.
     */
    if (n < 2) {
        snprintf(why, whylen, "zone_invariant monotonic %.128s: only %zu "
                 "reading%s collected, so nothing could decrease "
                 "(a monotonicity claim needs at least 2 readings)",
                 path, n, n == 1 ? "" : "s");
        return 0;
    }

    for (i = 0; i < n; i++) {
        if (quiesce_underflowed(vals[i])) {
            snprintf(why, whylen, "zone_invariant monotonic %.128s: reading "
                     "%zu is %g, which is not an honest counter value (a wrap "
                     "past zero, or the -1 unavailable sentinel)",
                     path, i + 1, vals[i]);
            return 0;
        }
    }

    for (i = 1; i < n; i++) {
        if (vals[i] < vals[i - 1]) {
            snprintf(why, whylen, "zone_invariant monotonic %.128s: reading "
                     "%zu is %g but reading %zu was %g -- a cumulative counter "
                     "that decreases was reset, wrapped, or written from a "
                     "stale copy", path, i + 1, vals[i], i, vals[i - 1]);
            return 0;
        }
    }

    return 1;
}


int
eval_quiesce(const char *path, int settled, int polls, int timeout_ms,
             double last, double prev, char *why, size_t whylen)
{
    if (settled) {
        return 1;
    }

    /*
     * EXPIRY FAILS. Never a skip, never a quiet pass.
     *
     * A quiesce that timed out and let the at-rest oracles run would report
     * their verdict on a counter still in motion -- the timing-dependent
     * result the directive exists to remove, and one that goes green on an
     * idle host and red under load until somebody loosens the bound. A quiesce
     * that timed out and SKIPPED them would be indistinguishable from a pass
     * in TAP, which is worse still.
     *
     * The message carries the last two readings because "did not settle" and
     * "settled at the wrong value" are different bugs, and a counter that
     * moved by one over the whole window reads very differently from one that
     * doubled.
     */
    snprintf(why, whylen, "quiesce %.128s: did not settle within %d ms "
             "(%d poll%s; last two readings %g then %g) -- the at-rest "
             "oracles are not judged on a moving counter",
             path, timeout_ms, polls, polls == 1 ? "" : "s", prev, last);
    return 0;
}
