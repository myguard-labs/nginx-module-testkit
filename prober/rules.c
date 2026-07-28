/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rules.c -- see rules.h.
 */

/* fmemopen (load_rules_buf) is POSIX.1-2008; under -std=c11 glibc hides it
 * without a feature-test macro. Same _GNU_SOURCE the sibling .c files set. */
#define _GNU_SOURCE

#include "rules.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * append_escaped() lives in util.c: the backend script's `raw` reply spells out
 * wire bytes with the same escapes, and two copies of this table would let the
 * two formats drift on what a given escape means. See util.h.
 */


/*
 * Per-exchange field router. In pipeline mode (`blk != NULL`) a per-exchange
 * directive writes the open block; otherwise it writes the flat case fields on
 * `tc`. pipeline_block and test_case are distinct types sharing only the field
 * NAMES, so PX(field) picks the right lvalue explicitly at each access rather
 * than through one aliased pointer -- both `tc` and `blk` must be in scope. This
 * is what keeps every existing rule file (n_blocks == 0, blk == NULL) driving
 * the flat fields byte for byte unchanged while a `block`-using case fills the
 * parallel block shape. See design-e2-pipeline.md.
 */
#define PX(field)  (*(blk != NULL ? &blk->field : &tc->field))


void
case_free(test_case *tc)
{
    size_t i;

    free(tc->name);
    free(tc->fault);
    free(tc->source);
    free(tc->request);
    free(tc->xfail_reason);

    for (i = 0; i < tc->n_no_logs; i++) {
        free(tc->no_logs[i].pattern);
        regfree(&tc->no_logs[i].re);
    }

    for (i = 0; i < tc->n_grep_logs; i++) {
        free(tc->grep_logs[i].pattern);
        regfree(&tc->grep_logs[i].re);
    }

    for (i = 0; i < tc->n_expects; i++) {
        free(tc->expects[i].text);

        if (tc->expects[i].kind == EXPECT_STATUS_LIKE
            || tc->expects[i].kind == EXPECT_RAW_RESPONSE_HEADERS_LIKE)
        {
            regfree(&tc->expects[i].re);
        }
    }

    for (i = 0; i < tc->n_probes; i++) {
        free(tc->probes[i].path);
        free(tc->probes[i].op);
        free(tc->probes[i].literal);
    }

    for (i = 0; i < tc->n_deltas; i++) {
        free(tc->deltas[i].path);
        free(tc->deltas[i].op);
        free(tc->deltas[i].literal);
    }

    for (i = 0; i < tc->n_baselines; i++) {
        free(tc->baselines[i].path);
        free(tc->baselines[i].op);
        free(tc->baselines[i].literal);
    }

    /* Each pipeline block owns its own name, request buffer and expect texts/
     * regexes exactly as the flat fields above do; free them per block so a
     * case that used `block` does not leak them on reload (case_free runs at
     * every `name`, and rules_test.c reuses one array across loads). */
    for (i = 0; i < tc->n_blocks; i++) {
        pipeline_block *b = &tc->blocks[i];
        size_t          j;

        free(b->name);
        free(b->request);

        for (j = 0; j < b->n_expects; j++) {
            free(b->expects[j].text);

            if (b->expects[j].kind == EXPECT_STATUS_LIKE
                || b->expects[j].kind == EXPECT_RAW_RESPONSE_HEADERS_LIKE)
            {
                regfree(&b->expects[j].re);
            }
        }
    }

    memset(tc, 0, sizeof(*tc));
}


static void
parse_expect(expectation *list, size_t *count, char *arg,
             const char *file, int lineno)
{
    expectation *e;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many expect lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    e = &list[*count];

    if (strncmp(arg, "status=", 7) == 0) {
        char *stop;
        char *value = trim(arg + 7);

        e->kind = EXPECT_STATUS;
        e->text = NULL;
        e->number = strtol(value, &stop, 10);

        /* The whole token has to be the number. "status=200junk" silently
         * parsing as 200 would make a typo'd expectation assert something its
         * author did not write -- and, unlike a wrong number, it would keep
         * passing. `repeat` validates its count the same way and for the same
         * reason. */
        if (*value == '\0' || stop == value || *stop != '\0') {
            die("%s:%d: expect status=\"%s\" is not a number",
                file, lineno, value);
        }

    } else if (strncmp(arg, "body~", 5) == 0) {
        e->kind = EXPECT_BODY_CONTAINS;
        e->text = xstrdup(trim(arg + 5));

    } else if (strncmp(arg, "body_sha256=", 12) == 0) {
        e->kind = EXPECT_BODY_SHA256;
        e->text = xstrdup(trim(arg + 12));

    } else if (strncmp(arg, "header~", 7) == 0) {
        e->kind = EXPECT_HEADER_CONTAINS;
        e->text = xstrdup(trim(arg + 7));

    } else if (strncmp(arg, "raw_response_headers_like~", 26) == 0) {
        char *pattern = trim(arg + 26);

        if (*pattern == '\0') {
            die("%s:%d: raw_response_headers_like~ needs a non-empty pattern",
                file, lineno);
        }

        e->kind = EXPECT_RAW_RESPONSE_HEADERS_LIKE;
        e->text = xstrdup(pattern);

        if (regcomp(&e->re, e->text, REG_EXTENDED) != 0) {
            die("%s:%d: invalid regex in raw_response_headers_like~: %.128s",
                file, lineno, pattern);
        }

    } else {
        die("%s:%d: unknown expect form \"%s\" "
            "(want status=, body~, body_sha256=, header~, raw_response_headers_like~)",
            file, lineno, arg);
    }

    (*count)++;
}


/*
 * `expect_not` is the negative counterpart of `expect`, restricted to the two
 * substring forms -- `body~`/`header~`. Status has no negative form here on
 * purpose: `error_code_like` already covers status-class assertions
 * (including "anything but 2xx" via the regex itself), so this directive's
 * shape stays exactly `expect`'s two substring forms, inverted, per the
 * brief.
 */
static void
parse_expect_not(expectation *list, size_t *count, char *arg,
                 const char *file, int lineno)
{
    expectation *e;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many expect_not lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    e = &list[*count];

    if (strncmp(arg, "body~", 5) == 0) {
        e->kind = EXPECT_NOT_BODY_CONTAINS;
        e->text = xstrdup(trim(arg + 5));

        if (*e->text == '\0') {
            die("%s:%d: expect_not body~ needs a non-empty pattern",
                file, lineno);
        }

    } else if (strncmp(arg, "header~", 7) == 0) {
        e->kind = EXPECT_NOT_HEADER_CONTAINS;
        e->text = xstrdup(trim(arg + 7));

        if (*e->text == '\0') {
            die("%s:%d: expect_not header~ needs a non-empty pattern",
                file, lineno);
        }

    } else {
        die("%s:%d: unknown expect_not form \"%s\" (want body~, header~)",
            file, lineno, arg);
    }

    (*count)++;
}


/*
 * `error_code_like <regex>` -- a POSIX extended regex matched against the
 * status code rendered as decimal text (e.g. "404", "204").
 *
 * Compiled here, at load time, for the same reason op_is_known() validates
 * operators up front: a malformed pattern dying mid-run truncates the TAP
 * stream, and a consumer reading a short plan cannot distinguish that from a
 * crash. Reject an empty pattern explicitly too -- regcomp() happily compiles
 * "" and it matches every status code, which is never what a rule author
 * meant to write.
 */
static void
parse_error_code_like(expectation *list, size_t *count, char *arg,
                      const char *file, int lineno)
{
    expectation *e;
    char        *pattern;
    int          rc;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many error_code_like lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    pattern = trim(arg);

    if (*pattern == '\0') {
        die("%s:%d: error_code_like needs a non-empty regex", file, lineno);
    }

    e = &list[*count];
    e->kind = EXPECT_STATUS_LIKE;
    e->text = xstrdup(pattern);

    rc = regcomp(&e->re, pattern, REG_EXTENDED | REG_NOSUB);

    if (rc != 0) {
        char errbuf[256];

        regerror(rc, &e->re, errbuf, sizeof(errbuf));
        die("%s:%d: error_code_like \"%s\" is not a valid regex: %s",
            file, lineno, pattern, errbuf);
    }

    (*count)++;
}


/*
 * `no_error_log <regex>` / `grep_error_log <regex>` -- shared parser, same
 * shape either way: one POSIX extended regex, compiled at load time for the
 * same die-before-the-first-request reason as error_code_like's. The empty
 * pattern is rejected explicitly here too, and for the sharper of the two
 * reasons: regcomp("") matches EVERY line, so an empty grep_error_log would
 * pass on any log at all and an empty no_error_log would fail on any line --
 * one vacuous, one unsatisfiable, both silently not what the author wrote.
 */
static void
parse_log_assert(log_assert *list, size_t *count, const char *directive,
                 char *arg, const char *file, int lineno)
{
    char        *pattern;
    int          rc;
    log_assert  *la;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many %s lines (max %d)", file, lineno, directive,
            MAX_ASSERTS);
    }

    pattern = trim(arg);

    if (*pattern == '\0') {
        die("%s:%d: %s needs a non-empty regex", file, lineno, directive);
    }

    la = &list[*count];
    la->pattern = xstrdup(pattern);

    rc = regcomp(&la->re, pattern, REG_EXTENDED | REG_NOSUB);

    if (rc != 0) {
        char errbuf[256];

        regerror(rc, &la->re, errbuf, sizeof(errbuf));
        die("%s:%d: %s \"%s\" is not a valid regex: %s",
            file, lineno, directive, pattern, errbuf);
    }

    (*count)++;
}


/*
 * Operators are validated here, at load time, rather than where they are
 * applied.
 *
 * The evaluator cannot do better than die() on an operator it does not know,
 * and dying mid-run truncates the TAP stream: the cases already printed stand,
 * the ones after never run, and a consumer sees a short plan rather than a
 * failure. Rejecting the rule file before the first request means the run
 * either happens completely or does not start.
 */
static int
op_is_known(const char *op)
{
    static const char *const ops[] = {
        "==", "!=", "<", "<=", ">", ">=", "~", NULL
    };
    size_t i;

    for (i = 0; ops[i] != NULL; i++) {
        if (strcmp(op, ops[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


/*
 * Wall-clock cost of one pause entry that spans [offset, upto).
 *
 * A plain stall costs its `ms` once. For a paced entry, write_request() sleeps
 * once BEFORE the span and write_paced() sleeps BETWEEN chunks -- so N chunks
 * cost 1 + (N-1) sleeps, i.e. exactly N * ms. Mirror any change to either of
 * those two functions here: getting this wrong in the lenient direction is
 * what would let a rule file declare a dribble longer than the read timeout
 * and then report a harness timeout as if it were a server verdict.
 */
static long
pause_cost_ms_raw(size_t offset, size_t upto, size_t chunk, long ms)
{
    size_t  span, chunks;

    if (chunk == 0) {
        return ms;
    }

    span = upto > offset ? upto - offset : 0;

    if (span == 0) {
        return ms;                       /* the leading sleep still happens */
    }

    chunks = span / chunk + (span % chunk != 0);

    if (chunks > (size_t) (MAX_PAUSE_MS / (ms > 0 ? ms : 1)) + 1) {
        return MAX_PAUSE_MS + 1;         /* saturate rather than overflow */
    }

    return (long) chunks * ms;
}


static long
pause_cost_ms(const http_pause *p, size_t upto)
{
    return pause_cost_ms_raw(p->offset, upto, p->chunk, p->ms);
}


/*
 * Both `probe` and `delta` are <path> <op> <value>; they differ only in what
 * the left-hand side is measured against, so they share the parser and the
 * directive name is carried through purely for the error message.
 */
static void
parse_assert(probe_assert *list, size_t *count, const char *directive,
             char *arg, const char *file, int lineno)
{
    char         *path, *op, *lit;
    probe_assert *pa;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many %s lines (max %d)", file, lineno, directive,
            MAX_ASSERTS);
    }

    path = strtok(arg, " \t");
    op = strtok(NULL, " \t");
    lit = strtok(NULL, "");

    if (path == NULL || op == NULL || lit == NULL) {
        die("%s:%d: %s needs <path> <op> <value>", file, lineno, directive);
    }

    if (!op_is_known(op)) {
        die("%s:%d: %s: unknown operator \"%s\" "
            "(want ==, !=, <, <=, >, >=, ~)", file, lineno, directive, op);
    }

    /* `~` is a substring test, which only means anything on a string, and both
     * subtracting directives only mean anything on a number. Catching the
     * combination here rather than at evaluation time keeps the failure at the
     * line that caused it. */
    if ((strcmp(directive, "delta") == 0
         || strcmp(directive, "probe_baseline") == 0)
        && strcmp(op, "~") == 0)
    {
        die("%s:%d: %s: \"~\" is a substring test and cannot apply to a "
            "numeric difference", file, lineno, directive);
    }

    lit = trim(lit);

    if (*lit == '\0') {
        die("%s:%d: %s needs <path> <op> <value>", file, lineno, directive);
    }

    pa = &list[*count];
    pa->path = xstrdup(path);
    pa->op = xstrdup(op);
    pa->literal = xstrdup(lit);

    (*count)++;
}


/*
 * load_rules_fp -- the whole rule-file parser, reading lines from an already
 * open FILE*. The two public entries below differ ONLY in where that FILE*
 * comes from: load_rules() fopen()s a path, load_rules_buf() fmemopen()s an
 * in-memory buffer (the fuzz target's entry, so a hostile rule file is a byte
 * array rather than a temp file on disk). Neither the line loop nor any
 * directive's semantics change with the source, so the body lives here once.
 * The caller owns fp and closes it -- this function never does, so an error
 * that die()s (or, in the fuzz build, longjmps out via die's hook) does not
 * leave a half-closed stream either way.
 */
static size_t
load_rules_fp(FILE *fp, const char *file, test_case *cases, size_t max)
{
    char     line[4096];
    size_t   n = 0, cap = 0, i;
    int      lineno = 0;
    int      open_case = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p, *directive, *arg;

        lineno++;

        p = line;

        /* Strip the newline only -- trailing spaces can be significant inside
         * a send line, so trimming happens per-directive, not here. */
        p[strcspn(p, "\n")] = '\0';

        {
            char *probe = p;

            while (*probe != '\0' && isspace((unsigned char) *probe)) {
                probe++;
            }

            if (*probe == '\0') {
                open_case = 0;                        /* blank line ends stanza */
                continue;
            }

            if (*probe == '#') {
                continue;
            }

            p = probe;
        }

        directive = p;

        while (*p != '\0' && !isspace((unsigned char) *p)) {
            p++;
        }

        if (*p != '\0') {
            *p++ = '\0';
        }

        while (*p != '\0' && (*p == ' ' || *p == '\t')) {
            p++;
        }

        arg = p;

        if (strcmp(directive, "name") == 0) {
            if (n >= max) {
                die("%s:%d: too many cases (max %zu)", file, lineno, max);
            }

            n++;
            cap = 0;
            open_case = 1;

            /*
             * Release and clear the slot before filling it. `cases` belongs to
             * the CALLER and load_rules() has never reset it, so every field
             * here used to inherit whatever a PREVIOUS load left behind.
             * Loading two files into one array therefore made the second one
             * die on a duplicate-directive guard its own text never tripped:
             * saw_hold (and every other saw_ flag) was still set from the first
             * file. Latent in the prober, which loads once per process, and hit
             * immediately by rules_test.c, which reuses one array across loads.
             *
             * case_free() rather than a bare memset: the slot may still own a
             * name, a request buffer and compiled regexes from that earlier
             * load, and zeroing over them leaks every one (LSan: 1290 bytes in
             * 10 allocations). It already ends with a memset, so this clears
             * the struct as well as freeing it -- which is what makes the
             * sentinels below the only fields needing explicit defaults.
             *
             * Freeing the whole slot rather than resetting flags one by one is
             * deliberate: the failure mode of forgetting one is a guard that
             * fires on a valid file, and a per-field list would have to be kept
             * in sync with every directive added later.
             */
            case_free(&cases[n - 1]);

            cases[n - 1].name = xstrdup(trim(arg));

            /* Not zero: SHUT_RD is 0, so leaving this at the zeroed default
             * would half-close every case that never asked for a shutdown. */
            cases[n - 1].shut_how = HTTP_SHUT_NONE;

            /* Likewise not zero: offset 0 means "reset before the first byte",
             * so the zeroed default would abort every case in the file. */
            cases[n - 1].abort_at = HTTP_ABORT_NONE;

            /* Zero is a deadline a rule file can legitimately ask for, so the
             * zeroed default would read as "close immediately" on every case
             * that never mentioned the directive. */
            cases[n - 1].close_within_ms = CLOSE_WITHIN_NONE;

            /* Same trap as the deadline above: `expect_idle 0` is
             * spellable, so a zeroed default would read as a zero-length idle
             * wait on every case that never asked for one. */
            cases[n - 1].idle_ms = IDLE_NONE;
            continue;
        }

        if (!open_case || n == 0) {
            die("%s:%d: \"%s\" before any name directive",
                file, lineno, directive);
        }

        /*
         * A `block <name>` directive opens a new pipeline sub-block on the
         * current case's shared connection. From the first `block` onward, every
         * per-exchange directive (send/pause/expect/shutdown/abort/hold/idle/
         * recv/dechunk/gunzip/json_sort/...) writes the OPEN block instead of the
         * flat case fields; case-level directives (probe/delta/baseline/log/pid/
         * fault/from/xfail) are unaffected and still judge the whole pipeline.
         *
         * `blk` is the routing target: the open block in pipeline mode, or NULL
         * when the case has no block (n_blocks == 0 -- the legacy flat shape,
         * byte for byte unchanged). The PX() macro yields the lvalue of a
         * per-exchange field on whichever of the two is active; since
         * pipeline_block and test_case are distinct types that merely share the
         * field NAMES, the pick is explicit per access rather than one aliased
         * pointer. See design-e2-pipeline.md for why the two shapes are parallel
         * rather than test_case being one synthesized block.
         */
        if (strcmp(directive, "block") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *name = trim(arg);

            if (*name == '\0') {
                die("%s:%d: block needs a name", file, lineno);
            }

            /*
             * No per-exchange directive may precede the first `block` in a case
             * that uses blocks: it would land in the flat fields while the rest
             * of the case lives in blocks, so the case would silently drive two
             * disjoint request shapes. Detected by any flat per-exchange field
             * already being set when the first block opens.
             */
            if (tc->n_blocks == 0
                && (tc->request_len != 0 || tc->n_pauses != 0
                    || tc->saw_shutdown || tc->saw_abort || tc->saw_hold
                    || tc->saw_close_within || tc->saw_idle
                    || tc->saw_recv_slow || tc->saw_rcvbuf
                    || tc->n_expects != 0
                    || tc->dechunk || tc->gunzip || tc->json_sort))
            {
                die("%s:%d: block \"%s\" follows a per-exchange directive at "
                    "the case level; once a case uses `block`, every send/"
                    "pause/expect/transport directive must sit inside a block",
                    file, lineno, name);
            }

            if (tc->n_blocks >= MAX_BLOCKS) {
                die("%s:%d: too many block directives (max %d)",
                    file, lineno, MAX_BLOCKS);
            }

            {
                pipeline_block *nb = &tc->blocks[tc->n_blocks];

                nb->name = xstrdup(name);

                /* Same sentinels the flat fields get at `name`: a zeroed
                 * shut_how is SHUT_RD, a zeroed abort_at resets before byte 0,
                 * a zeroed close/idle reads as a spellable 0 ms deadline. */
                nb->shut_how = HTTP_SHUT_NONE;
                nb->abort_at = HTTP_ABORT_NONE;
                nb->close_within_ms = CLOSE_WITHIN_NONE;
                nb->idle_ms = IDLE_NONE;
            }

            tc->n_blocks++;
            cap = 0;               /* the new block's request builds from empty */
            continue;
        }

        /*
         * Shared routing targets for every per-exchange directive below. `tc` is
         * the current case; `blk` is its open pipeline block, or NULL in the
         * legacy flat shape. Per-exchange directives write through PX(); the
         * case-level directives (probe/delta/baseline/log/pid/fault/from/xfail)
         * ignore `blk` and address `tc` directly, since they judge the whole
         * pipeline once, not one exchange.
         */
        {
            test_case      *tc  = &cases[n - 1];
            pipeline_block *blk = tc->n_blocks > 0
                                      ? &tc->blocks[tc->n_blocks - 1] : NULL;

        if (strcmp(directive, "send") == 0) {
            append_escaped(&PX(request), &PX(request_len),
                           &cap, arg, "send line");

        } else if (strcmp(directive, "pause") == 0) {
            char       *ms_s = trim(arg);
            char       *stop;
            long        ms;
            size_t      k;
            long        total = 0;

            if (*ms_s == '\0') {
                die("%s:%d: pause needs <ms>", file, lineno);
            }

            /* Same whole-token check as `repeat`: a pause that silently became
             * zero would turn a timing test into a plain request and still
             * report ok. */
            ms = strtol(ms_s, &stop, 10);

            if (stop == ms_s || *stop != '\0') {
                die("%s:%d: pause \"%s\" is not a number", file, lineno, ms_s);
            }

            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: pause %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (PX(n_pauses) >= MAX_PAUSES) {
                die("%s:%d: too many pause directives (max %d)",
                    file, lineno, MAX_PAUSES);
            }

            for (k = 0; k < PX(n_pauses); k++) {
                total += PX(pauses)[k].ms;
            }

            /* The prober's read timeout bounds the whole exchange, so a case
             * that stalls longer than that would report a harness timeout
             * rather than whatever the server did. Fail the rule file instead
             * of shipping a test that cannot mean what it says. */
            if (total + ms > MAX_PAUSE_MS) {
                die("%s:%d: pause total %ld ms exceeds the %d ms ceiling",
                    file, lineno, total + ms, MAX_PAUSE_MS);
            }

            PX(pauses)[PX(n_pauses)].offset = PX(request_len);
            PX(pauses)[PX(n_pauses)].ms = ms;
            PX(pauses)[PX(n_pauses)].chunk = 0;
            PX(n_pauses)++;

        } else if (strcmp(directive, "send_slow") == 0) {
            char       *rest = trim(arg);
            char       *stop;
            long        chunk, ms;
            size_t      k;
            long        total = 0;

            if (*rest == '\0') {
                die("%s:%d: send_slow needs <chunk> <ms>", file, lineno);
            }

            chunk = strtol(rest, &stop, 10);

            if (stop == rest || (*stop != ' ' && *stop != '\t')) {
                die("%s:%d: send_slow \"%s\" is not <chunk> <ms>",
                    file, lineno, rest);
            }

            if (chunk < 1 || chunk > MAX_SEND_SLOW_CHUNK) {
                die("%s:%d: send_slow chunk %ld out of range (1..%d bytes)",
                    file, lineno, chunk, MAX_SEND_SLOW_CHUNK);
            }

            rest = trim(stop);
            ms = strtol(rest, &stop, 10);

            if (stop == rest || *stop != '\0') {
                die("%s:%d: send_slow \"%s\" is not a number", file, lineno,
                    rest);
            }

            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: send_slow %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (PX(n_pauses) >= MAX_PAUSES) {
                die("%s:%d: too many pause/send_slow directives (max %d)",
                    file, lineno, MAX_PAUSES);
            }

            for (k = 0; k < PX(n_pauses); k++) {
                total += pause_cost_ms(&PX(pauses)[k],
                                       k + 1 < PX(n_pauses)
                                           ? PX(pauses)[k + 1].offset
                                           : PX(request_len));
            }

            /* A paced entry costs ms per chunk, not ms once. Charging it as a
             * single pause would let a rule file declare a dribble that blows
             * through the read timeout and then reports a harness timeout
             * instead of whatever the server did -- the exact failure the
             * plain-pause ceiling exists to prevent. The bytes this entry will
             * pace are not known until the case closes, so cost it against the
             * request as it stands and re-check at close. */
            total += pause_cost_ms_raw(PX(request_len), PX(request_len),
                                       (size_t) chunk, ms);

            if (total > MAX_PAUSE_MS) {
                die("%s:%d: send_slow pushes the case to %ld ms, over the "
                    "%d ms ceiling", file, lineno, total, MAX_PAUSE_MS);
            }

            PX(pauses)[PX(n_pauses)].offset = PX(request_len);
            PX(pauses)[PX(n_pauses)].ms = ms;
            PX(pauses)[PX(n_pauses)].chunk = (size_t) chunk;
            PX(n_pauses)++;

        } else if (strcmp(directive, "shutdown") == 0) {
            char       *how_s = trim(arg);
            char       *stop;
            long        how;

            if (*how_s == '\0') {
                die("%s:%d: shutdown needs 0|1|2", file, lineno);
            }

            how = strtol(how_s, &stop, 10);

            if (stop == how_s || *stop != '\0') {
                die("%s:%d: shutdown \"%s\" is not a number",
                    file, lineno, how_s);
            }

            if (how < 0 || how > 2) {
                die("%s:%d: shutdown %ld out of range (0=RD, 1=WR, 2=RDWR)",
                    file, lineno, how);
            }

            /* One per case: two shutdowns would make the second a no-op at
             * best and contradict the first at worst, and silently keeping the
             * last would let a rule file read as if both applied. Keyed on a
             * dedicated flag rather than on shut_how still holding the
             * sentinel, so the check stays correct however that value is
             * chosen. */
            if (PX(saw_shutdown)) {
                die("%s:%d: a case may carry only one shutdown directive",
                    file, lineno);
            }

            /* The other half of the abort/shutdown exclusion; see the abort
             * directive below for why the two cannot both apply. */
            if (PX(saw_abort)) {
                die("%s:%d: abort and shutdown are mutually exclusive",
                    file, lineno);
            }

            PX(shut_how) = (int) how;
            PX(saw_shutdown) = 1;

        } else if (strcmp(directive, "abort") == 0) {
            char       *off_s = trim(arg);
            char       *stop;
            long        off;

            if (*off_s == '\0') {
                die("%s:%d: abort needs <offset>", file, lineno);
            }

            off = strtol(off_s, &stop, 10);

            if (stop == off_s || *stop != '\0') {
                die("%s:%d: abort \"%s\" is not a number", file, lineno, off_s);
            }

            /* Zero is allowed -- reset before the first byte -- but negative is
             * not, and would otherwise wrap into an enormous size_t that reads
             * as "never abort", turning a reset case into an ordinary request
             * that still reports ok. */
            if (off < 0) {
                die("%s:%d: abort offset %ld is negative", file, lineno, off);
            }

            if (PX(saw_abort)) {
                die("%s:%d: a case may carry only one abort directive",
                    file, lineno);
            }

            /* A half-close says "I have finished sending, answer me"; a reset
             * says "I am gone". Applying both would send a FIN the reset then
             * invalidates, so the case would test neither directive cleanly.
             * Checked in both directions below, since either may come first. */
            if (PX(saw_shutdown)) {
                die("%s:%d: abort and shutdown are mutually exclusive",
                    file, lineno);
            }

            /* The other half of the recv_slow exclusion; see that directive. */
            if (PX(saw_recv_slow)) {
                die("%s:%d: recv_slow and abort are mutually exclusive",
                    file, lineno);
            }

            /* The other half of the close-deadline exclusion; see that
             * directive. */
            if (PX(saw_close_within)) {
                die("%s:%d: abort and expect_close_within are mutually "
                    "exclusive -- an aborted connection is reset by the "
                    "client, so the server's close is never observed",
                    file, lineno);
            }

            /* The other half of the idle exclusion; see that directive. */
            if (PX(saw_idle)) {
                die("%s:%d: abort and expect_idle are mutually exclusive "
                    "-- an aborted connection is reset by the client, so the "
                    "server is never observed", file, lineno);
            }

            PX(abort_at) = (size_t) off;
            PX(saw_abort) = 1;

            /* The other half of the hold exclusion; see that directive. */
            if (PX(saw_hold)) {
                die("%s:%d: abort and hold are mutually exclusive",
                    file, lineno);
            }

        } else if (strcmp(directive, "hold") == 0) {
            char       *ms_s = trim(arg);
            char       *stop;
            long        ms;

            if (*ms_s == '\0') {
                die("%s:%d: hold needs <ms>", file, lineno);
            }

            ms = strtol(ms_s, &stop, 10);

            if (stop == ms_s || *stop != '\0') {
                die("%s:%d: hold \"%s\" is not a number", file, lineno, ms_s);
            }

            /* Zero is rejected rather than treated as "no hold". A rule that
             * spells `hold 0` is asking for a behaviour it will not get, and
             * accepting it would produce a case that reads as testing an idle
             * connection while making an ordinary request. The ceiling is the
             * same one send_slow answers to: the hold blocks the suite. */
            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: hold %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (PX(saw_hold)) {
                die("%s:%d: a case may carry only one hold directive",
                    file, lineno);
            }

            /* Both end the connection without reading, so the pair is not
             * merely redundant but contradictory: abort resets immediately at
             * its offset, which destroys the connection hold means to keep
             * open and idle. Whichever ran would silently win. */
            if (PX(saw_abort)) {
                die("%s:%d: abort and hold are mutually exclusive",
                    file, lineno);
            }

            /* hold skips the read loop entirely, so pacing reads under it
             * would configure something that never runs -- a rule file that
             * reads as testing backpressure while testing nothing. */
            if (PX(saw_recv_slow)) {
                die("%s:%d: recv_slow and hold are mutually exclusive",
                    file, lineno);
            }

            /* The other half of the close-deadline exclusion; see that
             * directive. */
            if (PX(saw_close_within)) {
                die("%s:%d: hold and expect_close_within are mutually "
                    "exclusive -- a held connection is never read, so the "
                    "server's close is never observed", file, lineno);
            }

            /* The other half of the idle exclusion; see that directive. */
            if (PX(saw_idle)) {
                die("%s:%d: hold and expect_idle are mutually exclusive "
                    "-- hold sleeps without polling, so the server is never "
                    "observed", file, lineno);
            }

            PX(hold_ms) = ms;
            PX(saw_hold) = 1;

        } else if (strcmp(directive, "expect_close_within") == 0) {
            char       *ms_s = trim(arg);
            char       *stop;
            long        ms;

            if (*ms_s == '\0') {
                die("%s:%d: expect_close_within needs <ms>", file, lineno);
            }

            ms = strtol(ms_s, &stop, 10);

            if (stop == ms_s || *stop != '\0') {
                die("%s:%d: expect_close_within \"%s\" is not a number",
                    file, lineno, ms_s);
            }

            /* The ceiling is the load-bearing half. A deadline at or past the
             * prober's read timeout can never be missed -- the read gives up
             * first -- so the assertion would report ok on a server that never
             * closes at all. The floor rejects a negative, which would collide
             * with the CLOSE_WITHIN_NONE sentinel; 0 is allowed through as a
             * coherent (always-failing) request rather than special-cased. */
            if (ms < 0 || ms > MAX_CLOSE_WITHIN_MS) {
                die("%s:%d: expect_close_within %ld out of range (0..%d ms)",
                    file, lineno, ms, MAX_CLOSE_WITHIN_MS);
            }

            if (PX(saw_close_within)) {
                die("%s:%d: a case may carry only one expect_close_within "
                    "directive", file, lineno);
            }

            /* Neither of these cases ever reads the socket, so no close is
             * observable from here and the deadline would be judging nothing.
             * abort resets from THIS side; hold closes from this side after a
             * blind sleep. See rules.h for why hold is not the pairing it
             * looks like. */
            if (PX(saw_abort)) {
                die("%s:%d: abort and expect_close_within are mutually "
                    "exclusive -- an aborted connection is reset by the "
                    "client, so the server's close is never observed",
                    file, lineno);
            }

            if (PX(saw_hold)) {
                die("%s:%d: hold and expect_close_within are mutually "
                    "exclusive -- a held connection is never read, so the "
                    "server's close is never observed", file, lineno);
            }

            /* The other half of the idle exclusion; see that directive. */
            if (PX(saw_idle)) {
                die("%s:%d: expect_close_within and expect_idle are "
                    "mutually exclusive -- one asserts the server ends the "
                    "connection, the other that it leaves it open",
                    file, lineno);
            }

            PX(close_within_ms) = ms;
            PX(saw_close_within) = 1;

        } else if (strcmp(directive, "expect_idle") == 0) {
            char       *ms_s = trim(arg);
            char       *stop;
            long        ms;

            if (*ms_s == '\0') {
                die("%s:%d: expect_idle needs <ms>", file, lineno);
            }

            ms = strtol(ms_s, &stop, 10);

            if (stop == ms_s || *stop != '\0') {
                die("%s:%d: expect_idle \"%s\" is not a number",
                    file, lineno, ms_s);
            }

            /* Floor at 1, unlike the close deadline's 0. A zero-length idle
             * wait is not merely unsatisfiable but vacuous -- it polls for no
             * time and passes unconditionally, which is an assertion that
             * cannot go red. The ceiling keeps one parked case from stalling
             * the serial suite; prober.c re-checks it against the runtime read
             * timeout, which this parser cannot see. */
            if (ms < 1 || ms > MAX_IDLE_MS) {
                die("%s:%d: expect_idle %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_IDLE_MS);
            }

            if (PX(saw_idle)) {
                die("%s:%d: a case may carry only one expect_idle "
                    "directive", file, lineno);
            }

            /* Neither observes the socket at all: abort resets from this side
             * before any wait could run, and hold blind-sleeps with the read
             * loop skipped. An idle wait under either would report its own
             * behaviour as the server's. */
            if (PX(saw_abort)) {
                die("%s:%d: abort and expect_idle are mutually exclusive "
                    "-- an aborted connection is reset by the client, so the "
                    "server is never observed", file, lineno);
            }

            if (PX(saw_hold)) {
                die("%s:%d: hold and expect_idle are mutually exclusive "
                    "-- hold sleeps without polling, so the server is never "
                    "observed (expect_idle is the directive hold cannot "
                    "stand in for)", file, lineno);
            }

            /* Contradictory rather than redundant: one demands the server end
             * the connection, the other that it leave it open. Accepting both
             * would let whichever assertion ran first decide the verdict. */
            if (PX(saw_close_within)) {
                die("%s:%d: expect_close_within and expect_idle are "
                    "mutually exclusive -- one asserts the server ends the "
                    "connection, the other that it leaves it open",
                    file, lineno);
            }

            /* The idle wait replaces the read loop, so receive pacing would
             * configure something that never runs -- the same trap recv_slow
             * already guards against under hold. */
            if (PX(saw_recv_slow)) {
                die("%s:%d: recv_slow and expect_idle are mutually "
                    "exclusive -- the idle wait never reads, so pacing reads "
                    "configures nothing", file, lineno);
            }

            PX(idle_ms) = ms;
            PX(saw_idle) = 1;

        } else if (strcmp(directive, "recv_slow") == 0) {
            char       *rest = trim(arg);
            char       *stop;
            long        chunk, ms;

            if (*rest == '\0') {
                die("%s:%d: recv_slow needs <chunk> <ms>", file, lineno);
            }

            chunk = strtol(rest, &stop, 10);

            if (stop == rest || (*stop != ' ' && *stop != '\t')) {
                die("%s:%d: recv_slow \"%s\" is not <chunk> <ms>",
                    file, lineno, rest);
            }

            if (chunk < 1 || chunk > MAX_RECV_SLOW_CHUNK) {
                die("%s:%d: recv_slow chunk %ld out of range (1..%d bytes)",
                    file, lineno, chunk, MAX_RECV_SLOW_CHUNK);
            }

            rest = trim(stop);
            ms = strtol(rest, &stop, 10);

            if (stop == rest || *stop != '\0') {
                die("%s:%d: recv_slow \"%s\" is not a number", file, lineno,
                    rest);
            }

            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: recv_slow %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (PX(saw_recv_slow)) {
                die("%s:%d: a case may carry only one recv_slow directive",
                    file, lineno);
            }

            /* Pacing reads on a case that resets the connection is incoherent:
             * abort tears the socket down before the response is read at all,
             * so the pacing would apply to nothing. Silently allowing it would
             * let a rule file read as though it tested backpressure. */
            if (PX(saw_abort)) {
                die("%s:%d: recv_slow and abort are mutually exclusive",
                    file, lineno);
            }

            /* The other half of the hold exclusion; see that directive. */
            if (PX(saw_hold)) {
                die("%s:%d: recv_slow and hold are mutually exclusive",
                    file, lineno);
            }

            /* The other half of the idle exclusion; see that directive. */
            if (PX(saw_idle)) {
                die("%s:%d: recv_slow and expect_idle are mutually "
                    "exclusive -- the idle wait never reads, so pacing reads "
                    "configures nothing", file, lineno);
            }

            PX(recv_opt).chunk = (size_t) chunk;
            PX(recv_opt).ms = ms;
            PX(saw_recv_slow) = 1;

        } else if (strcmp(directive, "so_rcvbuf") == 0) {
            char       *sz_s = trim(arg);
            char       *stop;
            long        sz;

            if (*sz_s == '\0') {
                die("%s:%d: so_rcvbuf needs <bytes>", file, lineno);
            }

            sz = strtol(sz_s, &stop, 10);

            if (stop == sz_s || *stop != '\0') {
                die("%s:%d: so_rcvbuf \"%s\" is not a number",
                    file, lineno, sz_s);
            }

            if (sz < MIN_RCVBUF || sz > MAX_RCVBUF) {
                die("%s:%d: so_rcvbuf %ld out of range (%d..%d bytes)",
                    file, lineno, sz, MIN_RCVBUF, MAX_RCVBUF);
            }

            if (PX(saw_rcvbuf)) {
                die("%s:%d: a case may carry only one so_rcvbuf directive",
                    file, lineno);
            }

            /* SO_RCVBUF is a property of the CONNECTION, not one exchange. In a
             * pipeline the connection is opened once, before the first block, so
             * only the first block can set the client buffer; a so_rcvbuf on a
             * later block would parse but silently never apply. Reject it rather
             * than accept a directive that does nothing. (The flat case and the
             * first block are both fine: blk is NULL or the first block.) */
            if (blk != NULL && tc->n_blocks > 1) {
                die("%s:%d: so_rcvbuf may only appear on the FIRST block -- the "
                    "connection is opened once, so a later block's buffer size "
                    "would never take effect", file, lineno);
            }

            PX(recv_opt).rcvbuf = (int) sz;
            PX(saw_rcvbuf) = 1;

        } else if (strcmp(directive, "expect") == 0) {
            parse_expect(&PX(expects)[0], &PX(n_expects), trim(arg),
                         file, lineno);

        } else if (strcmp(directive, "expect_not") == 0) {
            parse_expect_not(&PX(expects)[0], &PX(n_expects), trim(arg),
                             file, lineno);

        } else if (strcmp(directive, "error_code_like") == 0) {
            parse_error_code_like(&PX(expects)[0], &PX(n_expects), arg,
                                  file, lineno);

        } else if (strcmp(directive, "no_error_log") == 0) {
            parse_log_assert(cases[n - 1].no_logs, &cases[n - 1].n_no_logs,
                             directive, arg, file, lineno);

        } else if (strcmp(directive, "grep_error_log") == 0) {
            parse_log_assert(cases[n - 1].grep_logs, &cases[n - 1].n_grep_logs,
                             directive, arg, file, lineno);

        } else if (strcmp(directive, "dechunk") == 0) {
            if (*trim(arg) != '\0') {
                die("%s:%d: dechunk takes no arguments", file, lineno);
            }

            if (PX(dechunk)) {
                die("%s:%d: dechunk already set for this case", file, lineno);
            }

            PX(dechunk) = 1;

        } else if (strcmp(directive, "gunzip") == 0) {
            if (*trim(arg) != '\0') {
                die("%s:%d: gunzip takes no arguments", file, lineno);
            }

            if (PX(gunzip)) {
                die("%s:%d: gunzip already set for this case", file, lineno);
            }

            PX(gunzip) = 1;

        } else if (strcmp(directive, "json_sort") == 0) {
            if (*trim(arg) != '\0') {
                die("%s:%d: json_sort takes no arguments", file, lineno);
            }

            if (PX(json_sort)) {
                die("%s:%d: json_sort already set for this case", file, lineno);
            }

            PX(json_sort) = 1;

        } else if (strcmp(directive, "pid_may_change") == 0) {
            if (*trim(arg) != '\0') {
                die("%s:%d: pid_may_change takes no arguments", file, lineno);
            }

            if (cases[n - 1].pid_may_change) {
                die("%s:%d: pid_may_change already set for this case",
                    file, lineno);
            }

            cases[n - 1].pid_may_change = 1;

        } else if (strcmp(directive, "open_conns") == 0) {
            char   *count_s = trim(arg);
            char   *stop;
            long    count;

            if (*count_s == '\0') {
                die("%s:%d: open_conns needs <count>", file, lineno);
            }

            count = strtol(count_s, &stop, 10);

            /* The whole argument must be the number: "10junk" parsing as 10, or
             * "5 20" silently keeping only the 5 (strtok did before), would open
             * a different number of connections than the file spells, and a
             * saturation case that silently changes its connection count is the
             * same trap as repeat's silent size change above. trim + full-string
             * check matches every sibling single-arg directive. */
            if (stop == count_s || *stop != '\0') {
                die("%s:%d: open_conns count \"%s\" is not a number",
                    file, lineno, count_s);
            }

            if (count < 1 || count > MAX_OPEN_CONNS) {
                die("%s:%d: open_conns %ld out of range (1..%d)",
                    file, lineno, count, MAX_OPEN_CONNS);
            }

            /* A valid count is >= 1, so a non-zero field means a prior
             * open_conns already set it -- the field is its own duplicate
             * guard, no saw_ flag needed. Case-level like pid_may_change, so it
             * writes cases[n - 1] directly rather than routing through PX(). */
            if (cases[n - 1].open_conns != 0) {
                die("%s:%d: open_conns already set for this case",
                    file, lineno);
            }

            cases[n - 1].open_conns = (int) count;

        } else if (strcmp(directive, "concurrent") == 0) {
            char   *count_s = trim(arg);
            char   *stop;
            long    count;

            if (*count_s == '\0') {
                die("%s:%d: concurrent needs <count>", file, lineno);
            }

            count = strtol(count_s, &stop, 10);

            /* Whole-argument check, same reasoning as open_conns above: a case
             * that silently runs a different number of requests than the file
             * spells is a test whose subject changed without anyone noticing. */
            if (stop == count_s || *stop != '\0') {
                die("%s:%d: concurrent count \"%s\" is not a number",
                    file, lineno, count_s);
            }

            /* Floor is 2, not 1. `concurrent 1` is exactly the ordinary path
             * with extra machinery, so accepting it would let a rule file claim
             * a concurrency test while asserting nothing about overlap -- the
             * vacuous-gate shape this harness exists to catch. Reject it at
             * parse time with a line number instead. */
            if (count < 2 || count > MAX_CONCURRENT) {
                die("%s:%d: concurrent %ld out of range (2..%d)",
                    file, lineno, count, MAX_CONCURRENT);
            }

            if (cases[n - 1].concurrent != 0) {
                die("%s:%d: concurrent already set for this case",
                    file, lineno);
            }

            cases[n - 1].concurrent = (int) count;

        } else if (strcmp(directive, "xfail") == 0) {
            if (cases[n - 1].xfail) {
                die("%s:%d: xfail already set for this case", file, lineno);
            }

            cases[n - 1].xfail = 1;

            /* A blank reason is allowed -- the annotation itself is the
             * signal; the text is diagnostic only. */
            {
                char *reason = trim(arg);

                cases[n - 1].xfail_reason =
                    (*reason != '\0') ? xstrdup(reason) : NULL;
            }

        } else if (strcmp(directive, "repeat") == 0) {
            char   *count_s = strtok(arg, " \t");
            char   *text = strtok(NULL, "");
            char   *stop;
            long    count;
            long    k;

            if (count_s == NULL || text == NULL) {
                die("%s:%d: repeat needs <count> <text>", file, lineno);
            }

            count = strtol(count_s, &stop, 10);

            /* The whole token has to be the number. "10junk" parsing as 10
             * would build a different request than the file describes, and a
             * size-driven case that silently changes size is exactly the way a
             * limit test stops reaching its limit. */
            if (stop == count_s || *stop != '\0') {
                die("%s:%d: repeat count \"%s\" is not a number",
                    file, lineno, count_s);
            }

            if (count < 1 || count > 100000) {
                die("%s:%d: repeat count %ld out of range (1..100000)",
                    file, lineno, count);
            }

            for (k = 0; k < count; k++) {
                append_escaped(&PX(request), &PX(request_len),
                               &cap, text, "repeat line");
            }

        } else if (strcmp(directive, "from") == 0) {
            cases[n - 1].source = xstrdup(trim(arg));

        } else if (strcmp(directive, "fault") == 0) {
            cases[n - 1].fault = xstrdup(trim(arg));

        } else if (strcmp(directive, "probe") == 0) {
            parse_assert(cases[n - 1].probes, &cases[n - 1].n_probes,
                         directive, trim(arg), file, lineno);

        } else if (strcmp(directive, "delta") == 0) {
            parse_assert(cases[n - 1].deltas, &cases[n - 1].n_deltas,
                         directive, trim(arg), file, lineno);

        } else if (strcmp(directive, "probe_baseline") == 0) {
            parse_assert(cases[n - 1].baselines, &cases[n - 1].n_baselines,
                         directive, trim(arg), file, lineno);

        } else {
            die("%s:%d: unknown directive \"%s\"", file, lineno, directive);
        }

        }   /* per-exchange routing scope (tc/blk) */
    }

    /*
     * Re-check pause budgets now that every request buffer is final.
     *
     * A `send_slow` entry paces from its own offset to the NEXT entry's offset
     * (or the end of the request), so its true cost is not known while the
     * stanza is still open -- any `send` line after it adds bytes to dribble.
     * The check at parse time can only see the request so far, so it catches
     * an obviously-oversized value early with a line number; this pass is what
     * actually enforces the ceiling. Done over all cases rather than at each
     * stanza-close so neither close path (blank line, EOF) can skip it.
     */
    for (i = 0; i < n; i++) {
        test_case  *tc = &cases[i];
        long        total = 0;
        size_t      k;

        /*
         * open_conns holds idle connections open ONLY across the probe read
         * (they are closed before the delta/pid reads), so a `probe` assertion
         * is the only thing that can observe them. A case that opens
         * connections but carries no probe assertion parks fds where nothing
         * looks -- a vacuous test, the exact shape assert.h exists to reject.
         * Checked ahead of the pipeline early-continue so it covers both
         * flat and pipeline cases.
         */
        if (tc->open_conns > 0 && tc->n_probes == 0) {
            die("%s: case \"%s\" carries open_conns %d but no probe assertion; "
                "the held connections would be observed by nothing", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->open_conns);
        }

        /*
         * `concurrent` and `block` describe incompatible wire shapes: a
         * pipeline is an ORDERED sequence on ONE connection, and the whole
         * point of concurrent is N connections with no ordering between them.
         * "N pipelines at once" is a coherent feature but a much larger one
         * (per-connection block cursors, per-connection failure attribution),
         * and silently picking either interpretation would run something other
         * than what the file spells. Reject the pair with a line-free but
         * case-named error, the same shape as the open_conns rule above.
         */
        if (tc->concurrent > 0 && tc->n_blocks > 0) {
            die("%s: case \"%s\" carries both concurrent %d and %zu block(s); "
                "a pipeline is ordered on one connection and cannot also be "
                "issued concurrently", file,
                tc->name != NULL ? tc->name : "(unnamed)",
                tc->concurrent, tc->n_blocks);
        }

        /*
         * A concurrent fan whose results nothing compares is a vacuous test in
         * the same way open_conns without a probe is: the directive's entire
         * value is that the before/after snapshots bracket N OVERLAPPING
         * requests, so without a delta or probe assertion the case pays for N
         * connections and asserts only what a single request already asserted.
         * Requiring one of the two snapshot oracles is what makes the overlap
         * observable.
         */
        if (tc->concurrent > 0 && tc->n_deltas == 0 && tc->n_probes == 0) {
            die("%s: case \"%s\" carries concurrent %d but no delta or probe "
                "assertion; the overlap would be observed by nothing", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->concurrent);
        }

        /*
         * `abort`, `hold` and `expect_idle` each end their connection WITHOUT
         * ever reading a response -- in http_exchange() they return before the
         * read half runs at all. A concurrent fan carrying one of them would
         * open N connections, write N requests, read nothing, and then assert
         * its delta against a fan whose responses were never collected: the
         * overlap the directive pays for would be observed by nothing, which is
         * the same vacuity the delta/probe rule above rejects.
         *
         * Rejected at load time with the offending directive named, rather than
         * silently dropped in the driver, so a rule file cannot claim a
         * concurrency test that reads no responses.
         *
         * `shutdown` is deliberately NOT in this list: a half-close is a
         * modifier on the request, not a substitute for the response -- the peer
         * still answers, and collecting that answer is the point. See
         * http_exchange_concurrent()'s header in http.c.
         */
        if (tc->concurrent > 0 && (tc->saw_abort || tc->saw_hold
                                   || tc->saw_idle))
        {
            const char *which = tc->saw_abort ? "abort"
                                : (tc->saw_hold ? "hold" : "expect_idle");

            die("%s: case \"%s\" carries concurrent %d and %s; %s ends its "
                "connection without reading a response, so the fan would "
                "collect nothing to assert against", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->concurrent,
                which, which);
        }

        /*
         * Pipeline cases carry every per-exchange knob inside blocks[], so the
         * flat-field checks below are vacuous for them (all flat saw_ flags and
         * pauses are zero). Validate each block instead, then continue past the
         * flat pass. The per-block rules are the same three "no response to
         * assert on" traps applied to THIS block's own response, plus two rules
         * unique to a pipeline: a directive that ends the connection
         * (abort/hold/idle) is legal ONLY on the last block -- a mid-pipeline
         * one would strand every block after it -- and the pause/hold/idle
         * wall-clock ceiling is summed across the WHOLE pipeline, since the
         * blocks run serially on one connection within one case.
         */
        if (tc->n_blocks > 0) {
            size_t b;

            for (b = 0; b < tc->n_blocks; b++) {
                pipeline_block *blk = &tc->blocks[b];
                int             ends_conn =
                    blk->saw_abort || blk->saw_hold || blk->saw_idle;

                if (blk->request_len == 0) {
                    die("%s: case \"%s\" block \"%s\" has no send line",
                        file, tc->name != NULL ? tc->name : "(unnamed)",
                        blk->name != NULL ? blk->name : "(unnamed)");
                }

                /* Same three vacuous-assertion traps as the flat pass, judged
                 * against this block's own (empty, under these directives)
                 * response buffer. */
                if (blk->saw_abort && blk->n_expects > 0) {
                    die("%s: case \"%s\" block \"%s\" carries abort and %zu "
                        "response expectation(s); a reset connection has no "
                        "response to assert on", file,
                        tc->name != NULL ? tc->name : "(unnamed)",
                        blk->name != NULL ? blk->name : "(unnamed)",
                        blk->n_expects);
                }

                if (blk->saw_hold && blk->n_expects > 0) {
                    die("%s: case \"%s\" block \"%s\" carries hold and %zu "
                        "response expectation(s); a held connection is never "
                        "read, so there is no response to assert on", file,
                        tc->name != NULL ? tc->name : "(unnamed)",
                        blk->name != NULL ? blk->name : "(unnamed)",
                        blk->n_expects);
                }

                if (blk->saw_idle && blk->n_expects > 0) {
                    die("%s: case \"%s\" block \"%s\" carries expect_idle and "
                        "%zu response expectation(s); the idle wait never "
                        "reads, so there is no response to assert on", file,
                        tc->name != NULL ? tc->name : "(unnamed)",
                        blk->name != NULL ? blk->name : "(unnamed)",
                        blk->n_expects);
                }

                /* A directive that ends the connection may only appear on the
                 * last block: any block after it could never run, and its
                 * assertions would silently not be reached. Reject at load
                 * time -- the same principle as abort+expect above, one step
                 * up at the pipeline level. */
                if (ends_conn && b + 1 < tc->n_blocks) {
                    die("%s: case \"%s\" block \"%s\" ends the connection "
                        "(abort/hold/expect_idle) but is not the last block; "
                        "the %zu block(s) after it could never run", file,
                        tc->name != NULL ? tc->name : "(unnamed)",
                        blk->name != NULL ? blk->name : "(unnamed)",
                        tc->n_blocks - b - 1);
                }

                total += blk->hold_ms;

                if (blk->idle_ms != IDLE_NONE) {
                    total += blk->idle_ms;
                }

                for (k = 0; k < blk->n_pauses; k++) {
                    size_t upto = k + 1 < blk->n_pauses
                                      ? blk->pauses[k + 1].offset
                                      : blk->request_len;

                    total += pause_cost_ms(&blk->pauses[k], upto);
                }

                if (total > MAX_PAUSE_MS) {
                    die("%s: case \"%s\" stalls %ld ms across its pipeline, "
                        "over the %d ms ceiling", file,
                        tc->name != NULL ? tc->name : "(unnamed)",
                        total, MAX_PAUSE_MS);
                }
            }

            continue;
        }

        /*
         * An aborted connection is reset before the server can answer, so there
         * is no response for a status/body/header assertion to read. Left
         * alone, such an expectation would evaluate against an empty buffer:
         * `expect body~foo` would fail for a reason that has nothing to do with
         * the server, and `expect_not body~foo` would PASS unconditionally,
         * reporting green for an assertion that never tested anything. That
         * second case is why this is a load-time die() rather than a runtime
         * skip -- a silently vacuous assertion is worse than a missing one.
         *
         * What remains meaningful on an aborted case is evidence the server
         * itself produced: no_error_log / grep_error_log, and the probe and
         * delta counters. Those are exactly the assertions this directive
         * exists to serve -- did the worker log the reset, and did it release
         * the request's resources -- so the case is left with the checks that
         * can actually observe the behaviour under test.
         */
        if (tc->saw_abort && tc->n_expects > 0) {
            die("%s: case \"%s\" carries an abort directive and %zu response "
                "expectation(s); a reset connection has no response to assert "
                "on -- use no_error_log / grep_error_log / probe / delta / "
                "probe_baseline instead", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->n_expects);
        }

        /*
         * Same trap as the abort guard above, reached a different way. A held
         * case does not read the response, so the buffer it hands to the
         * assertions is empty no matter what the server wrote. `expect` would
         * fail every time and `expect_not` would pass every time -- the latter
         * being the dangerous half, since it reports a green result for an
         * assertion that never looked at anything.
         *
         * The distinction from abort is worth keeping in mind: there the
         * response does not exist, here it does and was simply never collected.
         * Either way it is not available to assert on.
         */
        if (tc->saw_hold && tc->n_expects > 0) {
            die("%s: case \"%s\" carries a hold directive and %zu response "
                "expectation(s); a held connection is never read, so there is "
                "no response to assert on -- use no_error_log / "
                "grep_error_log / probe / delta / probe_baseline instead", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->n_expects);
        }

        /*
         * A third way into the same trap. The idle wait polls without ever
         * reading, so like a held case the buffer handed to the assertions is
         * empty whatever the server wrote -- and `expect_not` would again
         * report green for an assertion that looked at nothing.
         *
         * Here the emptiness is the POINT rather than a side effect: a case
         * asserting the server stayed silent has, when it passes, nothing to
         * assert on by construction.
         */
        if (tc->saw_idle && tc->n_expects > 0) {
            die("%s: case \"%s\" carries an expect_idle directive and %zu "
                "response expectation(s); the idle wait never reads, so there "
                "is no response to assert on -- use no_error_log / "
                "grep_error_log / probe / delta / probe_baseline instead", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->n_expects);
        }

        /* The hold is wall-clock the suite spends on this case just like a
         * pause, so it is counted against the same ceiling rather than being
         * free on top of it: `send_slow` near the budget plus a long `hold`
         * would otherwise stall well past what the ceiling promises. */
        total += tc->hold_ms;

        /* The idle wait is spent the same way and counted the same way: it is
         * a deliberate sleep on the wire, serial with every other case. */
        if (tc->idle_ms != IDLE_NONE) {
            total += tc->idle_ms;
        }

        for (k = 0; k < tc->n_pauses; k++) {
            size_t  upto = k + 1 < tc->n_pauses ? tc->pauses[k + 1].offset
                                                : tc->request_len;

            total += pause_cost_ms(&tc->pauses[k], upto);

            if (total > MAX_PAUSE_MS) {
                die("%s: case \"%s\" stalls %ld ms in total, over the %d ms "
                    "ceiling", file,
                    tc->name != NULL ? tc->name : "(unnamed)",
                    total, MAX_PAUSE_MS);
            }
        }
    }

    return n;
}


size_t
load_rules(const char *file, test_case *cases, size_t max)
{
    FILE    *fp;
    size_t   n;

    fp = fopen(file, "r");
    if (fp == NULL) {
        die("cannot open rule file %s", file);
    }

    n = load_rules_fp(fp, file, cases, max);
    fclose(fp);
    return n;
}


/*
 * load_rules_buf -- parse a rule file supplied as an in-memory byte buffer
 * rather than a path. The fuzz target's entry point: it feeds libFuzzer's
 * (data, size) straight in without a temp file, so a malformed rule file is
 * exercised as untrusted bytes. fmemopen gives load_rules_fp() the same FILE*
 * line source fgets() reads from a real file, so the parser is byte-for-byte
 * the one production runs -- no fuzz-only reimplementation to drift.
 *
 * A NULL from fmemopen (only on an allocation failure here) yields 0 cases,
 * the same as an empty file; the fuzz target treats "no cases" as a non-event.
 */
size_t
load_rules_buf(const char *buf, size_t len, test_case *cases, size_t max)
{
    FILE    *fp;
    size_t   n;

    /* fmemopen's first parameter is void*, not const void*, even in "r" mode
     * where it only reads -- a historical POSIX signature wart. The cast
     * discards const, which -Werror=cast-qual flags; it is safe HERE because
     * the "r" mode means fmemopen never writes through the pointer. Suppressed
     * at this one line, not file-wide, the same way die()'s -Wformat-nonliteral
     * is. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    fp = fmemopen((void *) buf, len, "r");
#pragma GCC diagnostic pop
    if (fp == NULL) {
        return 0;
    }

    n = load_rules_fp(fp, "<buf>", cases, max);
    fclose(fp);
    return n;
}
