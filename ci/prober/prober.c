/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * prober.c -- rule-driven HTTP prober for nginx/angie modules.
 *
 * This file is the driver only: it walks the cases, issues the requests, and
 * prints TAP. The parts that decide anything live beside it, so they can be
 * tested without a server -- rules.c (text -> cases), assert.c (documents ->
 * verdicts), json.c (the oracle), http.c (the wire).
 *
 * Module-agnostic by construction: every case is data in a .rule file, and the
 * only thing this knows about the module under test is the probe endpoint's
 * JSON shape, which ngx_test_probe.c keeps generic.
 *
 * Why this exists alongside the Perl suite in t/ rather than replacing it:
 *
 *   1. It runs against ANGIE. Stock Test::Nginx::Socket probes the server's
 *      version banner and requires "nginx version: x.y" (Util.pm:1365); angie
 *      answers "Angie version: Angie/1.12.0", so the harness bails before the
 *      first test and the angie CI leg has only ever been build-and-load. This
 *      prober reads no banner, so the same rules run on both servers.
 *
 *   2. It asserts on IN-WORKER state, not just the response. A rule can require
 *      that the ban zone gained exactly one node, which no amount of response
 *      matching can establish.
 *
 * See rules.h for the rule-file syntax.
 *
 * `from 127.0.0.9` binds the client socket to a local source address, so a
 * rule can present itself as a distinct peer. Ban behaviour is keyed on the
 * peer, so this is what makes per-address ban logic testable at all.
 *
 * Every request must ask for Connection: close; see http.h for why.
 *
 * Output is TAP, so `prove` consumes it exactly like the Perl suite.
 */

#define _GNU_SOURCE

#include "assert.h"
#include "http.h"
#include "json.h"
#include "rules.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static const char  *opt_host = "127.0.0.1";
static int          opt_port = 18099;
static const char  *opt_probe_uri = "/__probe";
static int          opt_timeout_ms = 5000;
static int          opt_verbose = 0;

/*
 * TLS transport for every connection this process opens, armed by --tls.
 *
 * Process-wide rather than per-case because the transport is a property of the
 * LISTENER, not of a request: a scenario points the prober at one port, and
 * that port either speaks TLS or it does not. A per-case directive would have
 * to carry a second port with it to mean anything, and every rule file in the
 * repo would then have to say which of the two it wanted. Keeping it here
 * leaves the whole .rule grammar transport-agnostic -- the same rule file runs
 * unchanged against a plaintext listener and a TLS one, which is exactly what
 * makes it evidence that the transport, and not the rule, is what changed.
 *
 * Zeroed by default, so the tls_opt every call site now passes is an explicit
 * "off" that reaches the same plaintext code path as the NULL it replaced.
 */
static http_tls     opt_tls = { 0, 0 };

/* PROBER_TIMEOUT_SCALE, resolved once at the top of main() via
 * delta_settle_scale_from_env() (see its comment by DELTA_SETTLE_TRIES) and
 * read from here by the delta-settle loop. No CLI flag: see that function's
 * comment for why this is env-only and never fatal on a bad value. */
static int          opt_timeout_scale = 1;

/* --check: parse the rule files, report, and exit without sending a request.
 * Deliberately emits no TAP plan -- a run that never executed a case has not
 * asserted anything, and "1..0" reads to a consumer as a suite that passed. */
static int          opt_check = 0;

/* Path to the server's error log, from -e or PROBER_ERROR_LOG (run.sh exports
 * the latter). NULL means the no_error_log / grep_error_log directives cannot
 * be evaluated -- and a case that carries one then FAILS rather than skips. */
static const char  *opt_error_log = NULL;


/*
 * Current size of the error log, taken as the case's start mark.
 *
 * A missing file marks position 0: the server may simply not have logged yet,
 * and the first line it eventually writes belongs to whichever case is running
 * when it appears.
 */
static long
error_log_mark(void)
{
    long   size;
    FILE  *fp = fopen(opt_error_log, "rb");

    if (fp == NULL) {
        return 0;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        size = 0;
    } else {
        size = ftell(fp);

        if (size < 0) {
            size = 0;
        }
    }

    fclose(fp);

    return size;
}


/*
 * Read everything appended since `mark` -- the case's own slice of the log.
 *
 * Sliced by offset rather than re-grepping the whole file so that a line
 * logged by an EARLIER case can neither satisfy this case's grep_error_log
 * nor trip its no_error_log.
 *
 * Two outcomes that used to look identical are now distinct, because they mean
 * opposite things:
 *
 *   UNCHANGED file  -- a valid empty slice. "Nothing was logged" is exactly
 *                      what every no_error_log hopes for, so it is EVALUATED.
 *   UNREADABLE file -- the oracle could not run at all. Reporting that as an
 *                      empty slice made every no_error_log in the run pass
 *                      without reading anything: the consumer was
 *                      `if (slice != NULL && matched)`, so a NULL skipped the
 *                      assertion entirely, while grep_error_log's
 *                      `if (slice == NULL || !matched)` failed closed. That
 *                      asymmetry is what this split removes.
 *
 * Returns 0 on success and -1 when the log could not be read. On success
 * *out is a malloc'd buffer (caller frees) or NULL for a zero-length slice --
 * callers must key on the return value, never on *out.
 */
static int
read_log_slice(long mark, char **out, size_t *out_len)
{
    char   *buf;
    long    end;
    size_t  len;
    FILE   *fp;

    *out = NULL;
    *out_len = 0;

    fp = fopen(opt_error_log, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    end = ftell(fp);

    if (end < 0 || fseek(fp, mark, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    /* Nothing appended since the mark: a real, empty slice. */
    if (end <= mark) {
        fclose(fp);
        return 0;
    }

    len = (size_t) (end - mark);

    buf = malloc(len);
    if (buf == NULL) {
        die("out of memory");
    }

    /* A short read only shrinks the slice (the file cannot shrink while the
     * server appends); assert over what was actually read. */
    *out_len = fread(buf, 1, len, fp);
    fclose(fp);

    *out = buf;

    return 0;
}


/*
 * Issue a probe request carrying a fault directive, e.g. "fault_slab=1".
 * The reply is discarded: what matters is the side effect on the zone, and the
 * following case's own probe assertions verify it took.
 */
static int
arm_fault(const char *query, const char *source, char *errbuf, size_t errlen)
{
    char           req[512];
    int            n;
    http_response  resp;

    n = snprintf(req, sizeof(req),
                 "GET %s?%s HTTP/1.1\r\nHost: prober\r\n"
                 "Connection: close\r\n\r\n",
                 opt_probe_uri, query);

    /* snprintf reports what it WOULD have written, so on truncation n exceeds
     * the buffer; handing that length to http_request() would read off the end
     * of the stack. A long fault query is a rule-file mistake, so say so. */
    if (n < 0 || (size_t) n >= sizeof(req)) {
        snprintf(errbuf, errlen, "fault query \"%.64s\" does not fit in a "
                 "%zu-byte request buffer", query, sizeof(req));
        return -1;
    }

    if (http_request(opt_host, opt_port, (const unsigned char *) req,
                     (size_t) n, opt_timeout_ms, source, NULL, 0,
                     HTTP_SHUT_NONE, HTTP_ABORT_NONE, HTTP_HOLD_NONE,
                     NULL, 0, HTTP_IDLE_NONE, 0, &opt_tls, &resp,
                     errbuf, errlen) != 0)
    {
        return -1;
    }

    if (resp.status != 200) {
        snprintf(errbuf, errlen, "arming \"%.64s\" returned status %d",
                 query, resp.status);
        http_response_free(&resp);
        return -1;
    }

    http_response_free(&resp);
    return 0;
}


static json_value *
fetch_probe(char *errbuf, size_t errlen)
{
    char           req[512];
    int            n;
    const char    *jerr = NULL;
    json_value    *doc;
    http_response  resp;

    n = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n",
                 opt_probe_uri);

    if (n < 0 || (size_t) n >= sizeof(req)) {
        snprintf(errbuf, errlen, "probe URI \"%.64s\" does not fit in a "
                 "%zu-byte request buffer", opt_probe_uri, sizeof(req));
        return NULL;
    }

    if (http_request(opt_host, opt_port, (const unsigned char *) req,
                     (size_t) n, opt_timeout_ms, NULL, NULL, 0,
                     HTTP_SHUT_NONE, HTTP_ABORT_NONE, HTTP_HOLD_NONE,
                     NULL, 0, HTTP_IDLE_NONE, 0, &opt_tls, &resp,
                     errbuf, errlen) != 0)
    {
        return NULL;
    }

    if (resp.status != 200) {
        snprintf(errbuf, errlen, "probe endpoint returned status %d "
                 "(is the probe directive configured, and was the module built "
                 "with TEST_HARNESS=1?)", resp.status);
        http_response_free(&resp);
        return NULL;
    }

    if (resp.body == NULL) {
        snprintf(errbuf, errlen, "probe response had no body");
        http_response_free(&resp);
        return NULL;
    }

    /* AUD-11: parse the body by its true LENGTH, not by strlen. A probe reply
     * carrying an embedded NUL followed by trailing bytes would otherwise be
     * truncated at the NUL by json_parse, which accepts the valid prefix and
     * never sees the garbage the trailing-bytes check is meant to reject -- so a
     * corrupt or smuggled probe document would read as healthy. */
    doc = json_parse_n(resp.body, resp.body_len, &jerr);

    if (doc == NULL) {
        snprintf(errbuf, errlen, "probe JSON parse failed: %s",
                 jerr ? jerr : "unknown");
    }

    http_response_free(&resp);

    return doc;
}


/*
 * How many times to re-read the probe before believing a delta failure, and
 * how long to wait between reads.
 *
 * The worker closes the case's connection asynchronously, so an fd or
 * connection delta can read as +1 purely because the close has not been
 * processed yet -- a race, not a leak. Re-reading absorbs that. It cannot
 * absorb a real leak: a leaked fd never comes back, so every retry sees the
 * same delta and the case still fails, only later. Bounded so a genuine
 * failure costs a fifth of a second rather than hanging the run.
 */
#define DELTA_SETTLE_TRIES  8
#define DELTA_SETTLE_US     25000

/*
 * PROBER_TIMEOUT_SCALE multiplies DELTA_SETTLE_TRIES (never DELTA_SETTLE_US --
 * a longer SLEEP between reads would not help; more RE-READS would). Under
 * valgrind, connection teardown after a request's async close routinely takes
 * longer than the unscaled 8*25ms=200ms window, so a perfectly clean server
 * reports a FALSE leak: the fd/pool delta has not settled yet, not because
 * anything leaked. lib.sh's PROBER_TIMEOUT_SCALE is the same knob the boot
 * readiness loops and the prober's own -t read timeout scale by, normalized
 * there to a positive integer; this is the third and last of the three spots
 * that all have to move together or a valgrind run goes red for harness
 * reasons instead of module ones.
 *
 * Read via getenv rather than a CLI flag: -t already has a flag/env pair
 * (xstrtol backed) and adding a second would just be another thing for a
 * caller to forget. Unlike -t, a bad value here is NEVER fatal -- the prober
 * binary is invoked directly by consumers (not only through run.sh/
 * run-scenario.sh, which validate PROBER_TIMEOUT_SCALE before they ever get
 * here), and dying on a malformed scale would turn a harness ergonomics
 * problem into every consumer's hard failure. Silently falling back to 1
 * (unscaled) is the same shape prober_heap_env and prober_detect_load use
 * elsewhere in this repo for a value that is advisory, not a correctness
 * input. Clamped to a sane ceiling so a typo -- a stray zero, a copy-pasted
 * millisecond value -- cannot turn a hung server into a multi-hour case; 1000
 * is a full 1000x the unscaled 200ms budget, comfortably above the ~40x this
 * repo's own valgrind job uses.
 */
#define PROBER_TIMEOUT_SCALE_MAX  1000

static int
delta_settle_scale_from_env(void)
{
    const char *env = getenv("PROBER_TIMEOUT_SCALE");
    char       *stop;
    long        v;

    if (env == NULL || *env == '\0') {
        return 1;
    }

    errno = 0;
    v = strtol(env, &stop, 10);

    if (*stop != '\0' || errno == ERANGE
        || v < 1 || v > PROBER_TIMEOUT_SCALE_MAX)
    {
        return 1;
    }

    return (int) v;
}


/*
 * Evaluate the body transforms and response expectations of ONE exchange over an
 * already-received response. Shared by the flat single-exchange path and each
 * pipeline block, so the two decide a response identically -- the transform gate
 * ordering (dechunk -> gunzip -> json_sort, each failing the exchange outright
 * and suppressing the body oracles that would otherwise fall back to a lower
 * tier) is written once here rather than duplicated per path.
 *
 * `label` prefixes every diagnostic (e.g. `block "reuse": `) so a pipeline
 * failure names which exchange it came from; it is "" for the flat path. Returns
 * 1 if every assertion this exchange carries passed, 0 otherwise; never reads
 * probe/delta/log/pid state, which is case-level and judged once by the caller.
 */
static int
eval_exchange(const char *label,
              int dechunk, int gunzip, int json_sort,
              const expectation *expects, size_t n_expects,
              int saw_close_within, long close_within_ms,
              int saw_idle, long idle_ms,
              http_response *resp)
{
    char    why[512];
    int     ok = 1;
    int     body_transform_failed;
    size_t  i;

    /*
     * Decode before any oracle runs, and fail the exchange outright on a framing
     * error rather than letting the body expectations run anyway -- they would
     * fall back to the raw wire bytes (which still contain the chunk size lines),
     * so a `body~` looking for text inside a badly framed chunk would PASS on a
     * response the server got wrong. The framing verdict gates the body verdict.
     */
    if (dechunk) {
        http_dechunk(resp);

        if (resp->dechunk_status != HTTP_DECHUNK_OK) {
            printf("# %sdechunk: %s\n", label,
                   http_dechunk_reason(resp->dechunk_status));
            ok = 0;
        }
    }

    /* gunzip runs AFTER dechunk (a chunked gzip body must be de-framed before
     * its stream is coherent) and gates the body verdict the same way. */
    if (gunzip) {
        http_gunzip(resp);

        if (resp->gunzip_status != HTTP_GUNZIP_OK) {
            printf("# %sgunzip: %s\n", label,
                   http_gunzip_reason(resp->gunzip_status));
            ok = 0;
        }
    }

    /* json_sort runs LAST of the transforms: it canonicalizes whatever the
     * dechunk/gunzip tiers left, so a body_sha256 is key-order-independent. Like
     * the tiers above it gates the body verdict. */
    if (json_sort) {
        http_json_sort(resp);

        if (resp->json_sort_status != HTTP_JSON_SORT_OK) {
            printf("# %sjson_sort: %s\n", label,
                   http_json_sort_reason(resp->json_sort_status));
            ok = 0;
        }
    }

    /* If a requested transform failed, the exchange is already failed; do NOT
     * run body oracles now -- body_bytes() would hand them a lower fallback tier
     * and emit a misleading PASS against bytes the transform rejected.
     * Header/status expects still run; they do not read the body. */
    body_transform_failed =
        (dechunk && resp->dechunk_status != HTTP_DECHUNK_OK)
        || (gunzip && resp->gunzip_status != HTTP_GUNZIP_OK)
        || (json_sort && resp->json_sort_status != HTTP_JSON_SORT_OK);

    for (i = 0; i < n_expects; i++) {
        if (body_transform_failed && expect_reads_body(&expects[i])) {
            continue;
        }
        if (!eval_expect(&expects[i], resp, why, sizeof(why))) {
            printf("# %s%s\n", label, why);
            ok = 0;
        }
    }

    if (saw_close_within
        && !eval_close_within(resp, close_within_ms, why, sizeof(why)))
    {
        printf("# %s%s\n", label, why);
        ok = 0;
    }

    if (saw_idle && !eval_idle(resp, idle_ms, why, sizeof(why))) {
        printf("# %s%s\n", label, why);
        ok = 0;
    }

    return ok;
}


/*
 * Poll the probe until `path` reads the same number on two consecutive
 * snapshots, or `timeout_ms` elapses. Returns 1 on pass, 0 on fail with the
 * reason printed.
 *
 * A separate function rather than a block inside run_case() for two reasons.
 * run_case() is already the largest function in the harness and lizard flags
 * it, so a directive that grows it further makes the next one harder to add;
 * and the polling has a probe-read failure path of its own, which reads far
 * more clearly with one exit than folded into run_case()'s.
 *
 * A probe read that FAILS mid-poll ends the case rather than being retried:
 * the settled-state oracles about to run all read the same endpoint, so an
 * endpoint that stopped answering is a finding now, not a slower one later.
 *
 * A path that is absent or non-numeric is likewise a failure. `quiesce
 * zone.nodes` against a document with no such field is a rule-file mistake
 * whose only honest report is red -- treating it as "already settled" would
 * make every at-rest oracle in the case run against a state nobody waited for.
 */
static int
run_quiesce(const test_case *tc)
{
    char        errbuf[512];
    char        why[512];
    int         polls = 0;
    int         settled = 0;
    int         have_prev = 0;
    double      prev = 0;
    double      last = 0;
    int64_t     started;

    /*
     * A MEASURED clock, not a count of the sleeps.
     *
     * Each iteration costs one sleep AND one probe request, and only the sleep
     * is a known quantity. Accumulating the interval would let a case whose
     * probe reads are slow spend several times its stated budget while still
     * believing it was inside it -- a directive that silently overspends the
     * number the rule file wrote is the same class of unstated timing the
     * whole directive exists to remove.
     *
     * `polls == 0 ||` short-circuits the deadline on the FIRST iteration, so a
     * timeout shorter than one round trip still takes the sample it needs to
     * have something to report. A quiesce that expired having observed nothing
     * would fail every case that carried it for a reason unrelated to the code
     * under test, and its diagnostic would name two readings it never took.
     */
    started = prober_monotonic_ms();

    while ((polls == 0
            || prober_monotonic_ms() - started <= tc->quiesce_timeout_ms)
           && !settled)
    {
        json_value        *doc;
        const json_value  *v;

        if (polls > 0) {
            usleep(QUIESCE_POLL_US);
        }

        doc = fetch_probe(errbuf, sizeof(errbuf));

        if (doc == NULL) {
            printf("# quiesce %s: %s\n", tc->quiesce_path, errbuf);
            return 0;
        }

        v = json_get(doc, tc->quiesce_path);

        if (v == NULL || v->type != JSON_NUMBER) {
            printf("# quiesce %s: the probe document carries no numeric value "
                   "at that path, so there is nothing to wait for\n",
                   tc->quiesce_path);
            json_free(doc);
            return 0;
        }

        last = v->number;
        json_free(doc);
        polls++;

        if (have_prev && last == prev) {
            settled = 1;

        } else {
            prev = last;
            have_prev = 1;
        }
    }

    if (!eval_quiesce(tc->quiesce_path, settled, polls,
                      tc->quiesce_timeout_ms, last, prev, why, sizeof(why)))
    {
        printf("# %s\n", why);
        return 0;
    }

    if (opt_verbose) {
        printf("# quiesce %s: settled at %g after %d poll%s\n",
               tc->quiesce_path, last, polls, polls == 1 ? "" : "s");
    }

    return 1;
}


/*
 * Take `n_legs` probe snapshots and fill the n_invariants x n_legs matrix
 * `vals` (row-major) with each snapshot's reading of each invariant's field.
 * Returns 0 on failure, having printed the reason.
 *
 * A SEPARATE sweep from the one the coverage oracle uses, taken AFTER
 * `quiesce`, and the separation is the point rather than an inefficiency. The
 * coverage sweep's snapshots are interleaved with the case's own requests, so
 * the counters they read are mid-flight by construction -- an `at_rest`
 * oracle judged on one of them would be asking whether the counter was at rest
 * while the case was still driving it, which it has no reason to be. Every
 * reading here is taken once the counter the case quiesced on has settled.
 *
 * These are probe reads, not case requests: the probe endpoint is answered by
 * whichever worker accepts the connection exactly as any other request is, so
 * a sweep of n_legs reads still samples across workers.
 *
 * They are not, however, free of effect, and that is deliberate rather than
 * tolerated. Each read is an HTTP request the worker serves, so it allocates
 * in the zone like any other -- which is what keeps `monotonic` from being a
 * tautology here. A sweep that genuinely changed nothing would leave every
 * reading identical, and "never decreased" over a constant sequence is a claim
 * no defect could falsify. The traffic the sweep itself generates is what
 * gives the form something to be monotonic ABOUT.
 *
 * What the sweep does not do is drive the case's own request path, which is
 * why it is safe to run after a quiesce: the counters an `at_rest` oracle
 * names are the module's, and a probe read does not touch them.
 *
 * An absent or non-numeric field FAILS. A zone_invariant judged against a
 * field the probe does not render is an invariant that did not run, and a
 * skip is indistinguishable from a pass in TAP.
 */
static int
collect_zone_readings(const test_case *tc, double *vals, size_t n_legs)
{
    char    errbuf[512];
    size_t  leg;

    for (leg = 0; leg < n_legs; leg++) {
        json_value  *doc = fetch_probe(errbuf, sizeof(errbuf));
        size_t       i;

        if (doc == NULL) {
            printf("# zone_invariant: probe read %zu/%zu failed: %s\n",
                   leg + 1, n_legs, errbuf);
            return 0;
        }

        for (i = 0; i < tc->n_zone_invariants; i++) {
            const json_value *v = json_get(doc, tc->zone_invariants[i].path);

            if (v == NULL || v->type != JSON_NUMBER) {
                printf("# zone_invariant %s: the probe document carries no "
                       "numeric value at that path, so the invariant cannot "
                       "be judged\n", tc->zone_invariants[i].path);
                json_free(doc);
                return 0;
            }

            vals[i * n_legs + leg] = v->number;
        }

        json_free(doc);
    }

    return 1;
}


/*
 * Judge the case's `zone_invariant` lines against the per-leg readings a
 * `fanout` collected. Returns 1 when every line passed.
 *
 * `vals` is an n_invariants x n_legs matrix in row-major order: row i holds
 * every worker's reading of invariant i's field, in the order the legs ran.
 * Collected that way because all three forms want the same rows for different
 * reasons -- coherent compares them to each other, monotonic compares each to
 * its predecessor, and at_rest judges the LAST one, the reading taken closest
 * to the quiesced state.
 *
 * Split out of run_case() for the same reason run_quiesce() is.
 */
static int
eval_zone_invariants(const test_case *tc, const double *vals, size_t n_legs)
{
    char    why[512];
    int     ok = 1;
    size_t  i;

    for (i = 0; i < tc->n_zone_invariants; i++) {
        const zone_invariant  *zi = &tc->zone_invariants[i];
        const double          *row = &vals[i * n_legs];
        int                    pass;

        switch (zi->kind) {

        case ZONE_INV_COHERENT:
            pass = eval_zone_coherent(zi->path, row, n_legs, why, sizeof(why));
            break;

        case ZONE_INV_MONOTONIC:
            pass = eval_zone_monotonic(zi->path, row, n_legs, why,
                                       sizeof(why));
            break;

        case ZONE_INV_AT_REST:
            /*
             * Judged on the LAST reading -- the one taken furthest from the
             * case's own traffic. Judging the first would ask whether the
             * counter was at rest at the start of the sweep, which is a
             * weaker question than the directive asks.
             *
             * The literal is handed over raw: unquoting and conversion belong
             * to the evaluator, so their failure paths sit in the seam that
             * assert_test.c can drive rather than here.
             */
            pass = eval_zone_at_rest(zi->path, zi->op, zi->literal,
                                     row[n_legs - 1], why, sizeof(why));
            break;

        default:
            /*
             * Unreachable from a rule file -- the parser accepts exactly three
             * forms. A fourth arriving here is a harness defect, and it is
             * reported as a FAILURE rather than defaulted to a pass for the
             * reason eval_idle()'s default arm gives: an unhandled case must
             * never become a silent green.
             */
            snprintf(why, sizeof(why), "zone_invariant %.128s: unknown form "
                     "%d, so nothing was judged", zi->path, (int) zi->kind);
            pass = 0;
            break;
        }

        if (!pass) {
            printf("# %s\n", why);
            ok = 0;
        }
    }

    return ok;
}


/*
 * Returns 1 if the case passed. Diagnostics are printed as TAP comments.
 *
 * `baseline` is the run's origin snapshot for `probe_baseline` assertions, or
 * NULL when no case in the run carries one. It is owned by the caller and
 * outlives every case, which is the whole point of the directive.
 */
static int
run_case(const test_case *tc, const json_value *baseline)
{
    char           errbuf[512];
    char           why[512];
    int            ok = 1;
    size_t         i;
    json_value    *before = NULL;
    http_response  resp;

    int           *held = NULL;    /* open_conns: idle fds parked over the probe */
    size_t         n_held = 0;

    long           log_mark = 0;
    int            want_log = (tc->n_no_logs > 0 || tc->n_grep_logs > 0);

    if (tc->n_blocks == 0 && tc->request_len == 0) {
        printf("# no send line in case \"%s\"\n", tc->name);
        return 0;
    }

    /*
     * The log mark is taken before ANYTHING the case does -- fault arming and
     * the before-snapshot included -- so a line those provoke is attributed to
     * this case, not silently to nobody. A missing path is a failure, not a
     * skip: a log assertion that quietly cannot run reads as a pass, which is
     * the exact failure mode assert.h exists to rule out.
     */
    if (want_log) {
        if (opt_error_log == NULL) {
            printf("# case \"%s\" has no_error_log/grep_error_log but no "
                   "error-log path is configured (-e or PROBER_ERROR_LOG)\n",
                   tc->name);
            return 0;
        }

        log_mark = error_log_mark();
    }

    if (tc->fault != NULL
        && arm_fault(tc->fault, tc->source, errbuf, sizeof(errbuf)) != 0)
    {
        printf("# %s\n", errbuf);
        return 0;
    }

    /*
     * The before-snapshot is taken AFTER arming, so a fault counter reset does
     * not show up as a delta of its own, and immediately before the send, so
     * nothing but the case's own request sits between the two reads.
     *
     * Taken for EVERY case, not only those carrying a delta assertion: the pid
     * comparison below applies to all of them, and a case with no delta line is
     * exactly the one that would otherwise report a clean pass over a worker
     * that died and was replaced mid-run.
     */
    before = fetch_probe(errbuf, sizeof(errbuf));

    if (before == NULL) {
        printf("# %s\n", errbuf);
        return 0;
    }

    if (tc->concurrent > 0) {
        /*
         * Concurrent fan -- N copies of this case's request held in flight at
         * once. The parser guarantees a delta or probe assertion is present
         * (otherwise the overlap would be observed by nothing) and rejects the
         * directives that would make the fan read nothing, so this path only
         * ever runs on a case whose snapshots actually bracket N collected
         * responses.
         *
         * Every leg is evaluated against the case's own expectations: N
         * overlapping requests must each be answered exactly as one sequential
         * request is, so a leg that came back different is a finding even when
         * the aggregate delta is clean. The leg number is carried into the
         * label so a failure names which one.
         */
        http_response *resps;
        int            leg;

        /*
         * Checked BEFORE the allocation below, not after: this path returns
         * without running the exchange, and a guard placed after the calloc
         * leaks every byte of it (gcc -fanalyzer and cppcheck both caught
         * exactly that).
         *
         * http_exchange_concurrent() has no tls_opt parameter -- it drives its
         * own connect loop rather than going through http_connect(), so the
         * fd->SSL* side table is never populated for the fds it opens. Under
         * --tls it would therefore send plaintext at a TLS listener and report
         * the handshake garbage as a protocol failure of the server.
         *
         * Failing is the only honest answer. A silent plaintext fallback would
         * make a `concurrent` case pass or fail for a reason that has nothing
         * to do with what it asserts, and a SKIP here would be invisible
         * inside a rules run that is otherwise reporting real verdicts.
         */
        if (opt_tls.enable) {
            printf("# concurrent: not supported under --tls "
                   "(http_exchange_concurrent has no TLS transport)\n");
            json_free(before);
            return 0;
        }

        resps = calloc((size_t) tc->concurrent, sizeof(*resps));

        if (resps == NULL) {
            printf("# concurrent: out of memory for %d responses\n",
                   tc->concurrent);
            json_free(before);
            return 0;
        }

        if (http_exchange_concurrent(opt_host, opt_port, tc->concurrent,
                                     tc->request, tc->request_len,
                                     opt_timeout_ms, tc->source,
                                     tc->pauses, tc->n_pauses, tc->shut_how,
                                     &tc->recv_opt, tc->saw_close_within,
                                     0, resps, errbuf, sizeof(errbuf)) != 0)
        {
            printf("# concurrent request failed: %s\n", errbuf);

            for (leg = 0; leg < tc->concurrent; leg++) {
                http_response_free(&resps[leg]);
            }

            free(resps);
            json_free(before);
            return 0;
        }

        for (leg = 0; leg < tc->concurrent; leg++) {
            char  label[256];

            snprintf(label, sizeof(label), "concurrent leg %d/%d: ",
                     leg + 1, tc->concurrent);

            if (opt_verbose) {
                printf("# %s<- status %d, %zu body bytes\n",
                       label, resps[leg].status, resps[leg].body_len);
            }

            if (!eval_exchange(label, tc->dechunk, tc->gunzip, tc->json_sort,
                               tc->expects, tc->n_expects,
                               tc->saw_close_within, tc->close_within_ms,
                               tc->saw_idle, tc->idle_ms, &resps[leg]))
            {
                ok = 0;
            }

            http_response_free(&resps[leg]);
        }

        free(resps);

    } else if (tc->fanout > 0) {
        /*
         * Fanout -- N copies of this case's request sent so that several
         * WORKERS answer, and the distinct answering pids counted.
         *
         * Deliberately SEQUENTIAL, which is the semantic difference from
         * `concurrent` and not an implementation shortcut. `concurrent` holds
         * N requests in flight at once because it is asking what happens when
         * they OVERLAP; fanout only needs the requests to REACH distinct
         * workers and does not care whether they overlapped (rules.h documents
         * exactly this). Sequential dispatch also buys the transport back:
         * http_request() takes tls_opt and goes through http_connect(), so
         * unlike the concurrent path above this one works under --tls with no
         * fallback and no skip.
         *
         * Every leg is evaluated against the case's own expectations, same as
         * the concurrent path: a request answered differently by one worker is
         * a finding in its own right, and the leg number is carried into the
         * label so a failure names which one.
         *
         * The pid of each leg is read from the leg's own probe snapshot rather
         * than from the response, because the pid the coverage oracle needs is
         * the pid of the worker that served THAT request, which is what the
         * probe document renders.
         */
        double  *pids;
        int      leg;
        size_t   n_pids = 0;
        size_t   distinct = 0;

        /*
         * Allocated only once the path is committed to running. A guard placed
         * AFTER this calloc leaks every byte of it on the early return -- gcc
         * -fanalyzer and cppcheck both caught exactly that shape on the
         * concurrent branch above, so there is nothing between the allocation
         * and its owning loop here.
         */
        pids = calloc((size_t) tc->fanout, sizeof(*pids));

        if (pids == NULL) {
            printf("# fanout: out of memory for %d pids\n", tc->fanout);
            json_free(before);
            return 0;
        }

        for (leg = 0; leg < tc->fanout; leg++) {
            char               label[256];
            json_value        *doc;
            const json_value  *pid;

            snprintf(label, sizeof(label), "fanout leg %d/%d: ",
                     leg + 1, tc->fanout);

            if (http_request(opt_host, opt_port, tc->request, tc->request_len,
                             opt_timeout_ms, tc->source,
                             tc->pauses, tc->n_pauses, tc->shut_how,
                             tc->abort_at, tc->hold_ms, &tc->recv_opt,
                             tc->saw_close_within, tc->idle_ms, 0, &opt_tls,
                             &resp, errbuf, sizeof(errbuf)) != 0)
            {
                printf("# %srequest failed: %s\n", label, errbuf);
                free(pids);
                json_free(before);
                return 0;
            }

            if (opt_verbose) {
                printf("# %s<- status %d, %zu body bytes\n",
                       label, resp.status, resp.body_len);
            }

            if (!eval_exchange(label, tc->dechunk, tc->gunzip, tc->json_sort,
                               tc->expects, tc->n_expects,
                               tc->saw_close_within, tc->close_within_ms,
                               tc->saw_idle, tc->idle_ms, &resp))
            {
                ok = 0;
            }

            http_response_free(&resp);

            /*
             * A leg whose pid cannot be read is a FAILURE, not a leg quietly
             * dropped from the sample: silently shrinking n_pids would make
             * the coverage bound easier to miss and harder to explain, which
             * inverts the point of the oracle.
             */
            doc = fetch_probe(errbuf, sizeof(errbuf));

            if (doc == NULL) {
                printf("# %s%s\n", label, errbuf);
                free(pids);
                json_free(before);
                return 0;
            }

            pid = json_get(doc, "pid");

            if (pid == NULL || pid->type != JSON_NUMBER) {
                printf("# %sthe probe document carries no numeric \"pid\", so "
                       "the answering worker cannot be identified\n", label);
                json_free(doc);
                free(pids);
                json_free(before);
                return 0;
            }

            pids[n_pids++] = pid->number;
            json_free(doc);
        }

        /*
         * The coverage oracle. Incomplete coverage FAILS -- see
         * eval_fanout_coverage() for why a quiet pass here would make every
         * cross-worker assertion in the case vacuous.
         */
        if (!eval_fanout_coverage(pids, n_pids, tc->fanout_min_workers,
                                  &distinct, why, sizeof(why)))
        {
            printf("# %s\n", why);
            ok = 0;

        } else if (opt_verbose) {
            printf("# fanout: %zu of %d responses came from %zu distinct "
                   "workers (need >= %d)\n",
                   n_pids, tc->fanout, distinct, tc->fanout_min_workers);
        }

        free(pids);

        /*
         * The cross-worker invariants, judged last and only on this path: they
         * need several workers' readings, which is exactly what a fanout
         * produces and what the parser refuses to let them be written without.
         *
         * `quiesce` runs FIRST when the case carries one, because every
         * at_rest form below is a claim about a settled counter and judging it
         * on a moving one is the timing-dependent result the directive exists
         * to remove. Its expiry ends the case, so the invariants are never
         * judged against a state nobody waited for.
         */
        if (tc->n_zone_invariants > 0) {
            double  *vals;
            size_t   n_legs = (size_t) tc->fanout;

            if (tc->quiesce_path != NULL && !run_quiesce(tc)) {
                json_free(before);
                return 0;
            }

            /* Nothing between the allocation and its owning call, same shape
             * as the pids buffer above and for the same leak reason. */
            vals = calloc(tc->n_zone_invariants * n_legs, sizeof(*vals));

            if (vals == NULL) {
                printf("# zone_invariant: out of memory for %zu readings\n",
                       tc->n_zone_invariants * n_legs);
                json_free(before);
                return 0;
            }

            if (!collect_zone_readings(tc, vals, n_legs)) {
                free(vals);
                json_free(before);
                return 0;
            }

            if (!eval_zone_invariants(tc, vals, n_legs)) {
                ok = 0;
            }

            free(vals);
        }

    } else if (tc->n_blocks == 0) {
        /*
         * Legacy single-exchange path -- one connect/write/read/close, exactly
         * as before the `block` directive existed. http_request wraps
         * http_connect/http_exchange/http_close and always closes.
         */
        if (http_request(opt_host, opt_port, tc->request, tc->request_len,
                         opt_timeout_ms, tc->source,
                         tc->pauses, tc->n_pauses, tc->shut_how, tc->abort_at,
                         tc->hold_ms, &tc->recv_opt, tc->saw_close_within,
                         tc->idle_ms, 0, &opt_tls, &resp,
                         errbuf, sizeof(errbuf)) != 0)
        {
            printf("# request failed: %s\n", errbuf);
            json_free(before);
            return 0;
        }

        if (opt_verbose) {
            printf("# <- status %d, %zu body bytes\n",
                   resp.status, resp.body_len);
        }

        if (!eval_exchange("", tc->dechunk, tc->gunzip, tc->json_sort,
                           tc->expects, tc->n_expects,
                           tc->saw_close_within, tc->close_within_ms,
                           tc->saw_idle, tc->idle_ms, &resp))
        {
            ok = 0;
        }

        http_response_free(&resp);

    } else {
        /*
         * Pipeline path -- N blocks driven over ONE connection. Connect once,
         * run each block's exchange on the shared fd, close once. Every block
         * but the last is read framed (E1's single-response reader), so a server
         * that folded two responses together is caught rather than silently
         * absorbed by a read-to-EOF; the last block may drain to EOF, which is
         * how a trailing `Connection: close` exchange is meant to end.
         *
         * If a block ends the connection early (a peer FIN/RESET, a read error,
         * or an abort/hold/idle directive) before the last block, the blocks
         * after it did not run: they are reported FAILED, not skipped, since a
         * silently-skipped assertion reads as a pass -- the exact anti-pattern
         * this harness exists to rule out.
         */
        int     fd;
        size_t  b;

        /* SO_RCVBUF is a property of the CONNECTION, not one exchange, so a
         * block's so_rcvbuf is applied here at connect from the first block.
         * http_connect reads only recv_opt->rcvbuf (the recv-pacing chunk/ms are
         * per-exchange and applied by http_exchange below); the parser rejects
         * so_rcvbuf on any block but the first, so this is the only one that set
         * it. */
        fd = http_connect(opt_host, opt_port, opt_timeout_ms, tc->source,
                          &tc->blocks[0].recv_opt, &opt_tls, errbuf,
                          sizeof(errbuf));

        if (fd < 0) {
            printf("# connect failed: %s\n", errbuf);
            json_free(before);
            return 0;
        }

        for (b = 0; b < tc->n_blocks; b++) {
            const pipeline_block *blk = &tc->blocks[b];
            char                  label[256];
            int                   conn_open = 0;
            int                   framed = (b + 1 < tc->n_blocks);

            snprintf(label, sizeof(label), "block \"%s\": ",
                     blk->name != NULL ? blk->name : "(unnamed)");

            if (http_exchange(fd, blk->request, blk->request_len,
                              opt_timeout_ms,
                              blk->pauses, blk->n_pauses, blk->shut_how,
                              blk->abort_at, blk->hold_ms, &blk->recv_opt,
                              blk->saw_close_within, blk->idle_ms, framed,
                              &resp, &conn_open, errbuf, sizeof(errbuf)) != 0)
            {
                printf("# %sexchange failed: %s\n", label, errbuf);
                ok = 0;
                /* The fd's state is unknown after a harness-side failure; treat
                 * the connection as gone and fail every remaining block. */
                conn_open = 0;
            } else {
                if (opt_verbose) {
                    printf("# %s<- status %d, %zu body bytes\n",
                           label, resp.status, resp.body_len);
                }

                if (!eval_exchange(label, blk->dechunk, blk->gunzip,
                                   blk->json_sort, blk->expects, blk->n_expects,
                                   blk->saw_close_within, blk->close_within_ms,
                                   blk->saw_idle, blk->idle_ms, &resp))
                {
                    ok = 0;
                }
            }

            http_response_free(&resp);

            /* Connection ended before the last block: no further block can run.
             * Report each remaining one FAILED by name rather than skipping. */
            if (!conn_open && b + 1 < tc->n_blocks) {
                size_t r;

                for (r = b + 1; r < tc->n_blocks; r++) {
                    printf("# block \"%s\": not reached, connection ended by "
                           "block \"%s\"\n",
                           tc->blocks[r].name != NULL
                               ? tc->blocks[r].name : "(unnamed)",
                           blk->name != NULL ? blk->name : "(unnamed)");
                    ok = 0;
                }
                break;
            }
        }

        http_close(fd);
    }

    /*
     * open_conns: park N bare idle connections so the probe read below sees a
     * worker pushed toward its worker_connections / max_conns limit. Opened
     * AFTER the case's own exchange (whose connection is already closed), held
     * only across the probe snapshot, and torn down the instant it is taken --
     * the pid/delta reads that follow must observe a clean connection count.
     * The parser guarantees a `probe` assertion is present whenever open_conns
     * is set, so these are always observed by something. Reuses
     * http_connect/http_close; no request is ever written on them.
     */
    if (tc->open_conns > 0) {
        held = calloc((size_t) tc->open_conns, sizeof(int));

        if (held == NULL) {
            printf("# open_conns: out of memory for %d fds\n", tc->open_conns);
            json_free(before);
            return 0;
        }

        for (i = 0; i < (size_t) tc->open_conns; i++) {
            int cfd = http_connect(opt_host, opt_port, opt_timeout_ms,
                                   tc->source, NULL, &opt_tls, errbuf,
                                   sizeof(errbuf));

            if (cfd < 0) {
                /* Not enough slots to open what the case asked for is itself a
                 * finding -- the probe assertion below will read the shortfall
                 * -- but fail the case here too so a connect() error is never
                 * silently the reason the count looks the way it does. */
                printf("# open_conns: connection %zu/%d failed: %s\n",
                       i + 1, tc->open_conns, errbuf);
                ok = 0;
                break;
            }

            held[n_held++] = cfd;
        }
    }

    /*
     * `quiesce` for every case that is NOT driving the zone_invariant path
     * above (which runs its own, ahead of the readings those oracles need).
     * Placed here so the probe/delta/probe_baseline snapshots that follow are
     * taken on a settled counter -- the same reason the invariant path
     * quiesces before its sweep.
     *
     * Ahead of the open_conns close, which means the parked connections stay
     * open across the wait as well as across the probe read. That is the
     * correct order and not an oversight: the whole point of open_conns is
     * that the snapshot observes the ELEVATED connection count, so closing
     * them before the wait would leave the probe reading a state the case
     * never asked for. The cost is that a case combining the two directives
     * holds its fds for up to the quiesce budget, which is bounded by
     * QUIESCE_MAX_MS and by MAX_OPEN_CONNS on the other axis.
     */
    if (tc->quiesce_path != NULL && tc->n_zone_invariants == 0
        && !run_quiesce(tc))
    {
        for (i = 0; i < n_held; i++) {
            http_close(held[i]);
        }
        free(held);
        json_free(before);
        return 0;
    }

    if (tc->n_probes > 0) {
        json_value *doc = fetch_probe(errbuf, sizeof(errbuf));

        /*
         * Close the parked connections the moment the snapshot is in hand: the
         * probe has already captured the elevated count, so holding them any
         * longer only risks leaking fds on the early return below and skewing
         * the pid/delta reads. Done here rather than after the eval loop so no
         * path out of this block can leave them open.
         */
        for (i = 0; i < n_held; i++) {
            http_close(held[i]);
        }
        free(held);
        held = NULL;

        if (doc == NULL) {
            printf("# %s\n", errbuf);
            json_free(before);
            return 0;
        }

        for (i = 0; i < tc->n_probes; i++) {
            if (!eval_probe(doc, &tc->probes[i], why, sizeof(why))) {
                printf("# %s\n", why);
                ok = 0;
            }
        }

        json_free(doc);
    }

    /*
     * Defensive teardown: the primary close runs inside the n_probes block
     * above, AFTER the snapshot, because the connections must stay open across
     * the probe read for it to observe the elevated count -- closing them any
     * earlier would defeat the whole directive. The parser guarantees a `probe`
     * assertion whenever open_conns is set, so that block always runs; this
     * belt-and-braces guard makes it structurally impossible for any path to
     * leak the parked fds even if that invariant were ever weakened, without
     * moving the close ahead of the snapshot.
     */
    if (held != NULL) {
        for (i = 0; i < n_held; i++) {
            http_close(held[i]);
        }
        free(held);
        held = NULL;
    }

    /*
     * Worker survival, for every case. Checked before any delta retry loop and
     * without retries of its own: a respawned worker never settles back to the
     * pid that served the before-snapshot, so re-reading could only turn a real
     * failure into a slower one. Its own probe read, because the delta loop
     * below is conditional and this must not be.
     *
     * `pid_may_change` selects which invariant is asserted -- same worker, or
     * merely same master -- but never whether one is. A case that spans a
     * reload still has to answer for the master it came back under.
     */
    {
        json_value *now = fetch_probe(errbuf, sizeof(errbuf));

        if (now == NULL) {
            printf("# %s\n", errbuf);
            json_free(before);
            return 0;
        }

        if (!eval_pid_stable(before, now, tc->pid_may_change, why,
                             sizeof(why)))
        {
            printf("# %s\n", why);
            ok = 0;
        }

        json_free(now);
    }

    if (tc->n_deltas > 0 || tc->n_baselines > 0) {
        int try;
        int settled = 0;
        int settle_tries = DELTA_SETTLE_TRIES * opt_timeout_scale;

        for (try = 0; try < settle_tries && !settled; try++) {
            json_value *after;

            if (try > 0) {
                usleep(DELTA_SETTLE_US);
            }

            after = fetch_probe(errbuf, sizeof(errbuf));

            if (after == NULL) {
                printf("# %s\n", errbuf);
                json_free(before);
                return 0;
            }

            settled = 1;
            why[0] = '\0';

            for (i = 0; i < tc->n_deltas; i++) {
                char one[512];

                if (!eval_delta(before, after, &tc->deltas[i], "delta", one,
                                sizeof(one)))
                {
                    settled = 0;

                    /* Keep only the first failure of the last attempt: the
                     * retries exist to let a close land, so the interesting
                     * diagnostic is the one that survived them. */
                    if (why[0] == '\0') {
                        snprintf(why, sizeof(why), "%s", one);
                    }
                }
            }

            /*
             * Baselines judge the SAME after-snapshot, inside the same retry
             * loop: a connection closing late moves a baseline exactly as it
             * moves a delta, so evaluating them outside the loop would report
             * a close race as a leak on precisely the assertion written to
             * find leaks.
             */
            for (i = 0; i < tc->n_baselines; i++) {
                char one[512];

                if (!eval_delta(baseline, after, &tc->baselines[i],
                                "probe_baseline", one, sizeof(one)))
                {
                    settled = 0;

                    if (why[0] == '\0') {
                        snprintf(why, sizeof(why), "%s", one);
                    }
                }
            }

            json_free(after);
        }

        if (!settled) {
            printf("# %s (unchanged over %d re-reads, so not a close race)\n",
                   why, settle_tries);
            ok = 0;
        }
    }

    /*
     * Log assertions come last, after the delta settle loop: by then the
     * server has finished everything this case provoked, so the slice is as
     * complete as it will get without waiting on purpose. An empty slice is
     * evaluated, not skipped -- it is exactly what every no_error_log hopes
     * for and what every grep_error_log must be able to fail on.
     */
    if (want_log) {
        size_t  slice_len = 0;
        char   *slice = NULL;
        int     readable = (read_log_slice(log_mark, &slice, &slice_len) == 0);

        /* An unreadable log fails BOTH directions once, loudly, rather than
         * silently satisfying every no_error_log in the case. Neither oracle
         * ran, so neither may report a verdict. */
        if (!readable) {
            if (tc->n_no_logs > 0 || tc->n_grep_logs > 0) {
                printf("# error log %s could not be read, so %zu log assertion(s)"
                       " could not run\n",
                       opt_error_log, tc->n_no_logs + tc->n_grep_logs);
                ok = 0;
            }
        } else {
            for (i = 0; i < tc->n_no_logs; i++) {
                if (log_lines_match(slice, slice_len, &tc->no_logs[i].re)) {
                    printf("# error log matches /%s/, expected no line to\n",
                           tc->no_logs[i].pattern);
                    ok = 0;
                }
            }

            for (i = 0; i < tc->n_grep_logs; i++) {
                if (!log_lines_match(slice, slice_len, &tc->grep_logs[i].re)) {
                    printf("# no error-log line matches /%s/ during this case\n",
                           tc->grep_logs[i].pattern);
                    ok = 0;
                }
            }
        }

        free(slice);
    }

    json_free(before);

    return ok;
}


static void
usage(void)
{
    fprintf(stderr,
            "usage: prober [-H host] [-p port] [-u probe-uri] [-t ms]\n"
            "              [-e error-log] [-v] [--check] [--tls]"
            " <rulefile> [rulefile ...]\n"
            "  -e (or PROBER_ERROR_LOG) names the server error log, needed\n"
            "     by the no_error_log / grep_error_log directives\n"
            "  --check parses the rule files and exits without connecting;\n"
            "     nonzero status means a rule file is malformed\n"
            "  --tls speaks TLS to the port instead of plaintext, without\n"
            "     verifying the certificate -- for a local fixture listener\n");
    exit(2);
}


int
main(int argc, char **argv)
{
    int         i, argi, failures = 0, total = 0;
    size_t      n = 0, c;
    test_case  *cases;
    json_value *baseline = NULL;

    for (argi = 1; argi < argc; argi++) {
        if (argv[argi][0] != '-') {
            break;
        }

        if (strcmp(argv[argi], "-v") == 0) {
            opt_verbose = 1;
            continue;
        }

        /* Argument-less, so it must be handled before the "flag needs a value"
         * guard below rejects it as the last word on the command line. */
        if (strcmp(argv[argi], "--check") == 0) {
            opt_check = 1;
            continue;
        }

        /*
         * Argument-less like --check, so it has to be handled above the
         * "flag needs a value" guard as well.
         *
         * verify stays 0: the listener this is pointed at serves a
         * self-signed fixture certificate generated at scenario boot, and
         * there is no trust store that could ever contain it. See http.h's
         * comment on http_tls.verify -- this client is a transport for a test
         * harness, not a security boundary, and the claim a TLS scenario makes
         * is about the handshake and the bytes after it, not about PKI.
         */
        if (strcmp(argv[argi], "--tls") == 0) {
            opt_tls.enable = 1;
            continue;
        }

        if (argi + 1 >= argc) {
            usage();
        }

        if (strcmp(argv[argi], "-H") == 0) {
            opt_host = argv[++argi];

        } else if (strcmp(argv[argi], "-p") == 0) {
            long port = xstrtol(argv[++argi], "-p");

            if (port < 1 || port > 65535) {
                die("-p: port %ld is outside 1-65535", port);
            }

            opt_port = (int) port;

        } else if (strcmp(argv[argi], "-u") == 0) {
            opt_probe_uri = argv[++argi];

        } else if (strcmp(argv[argi], "-e") == 0) {
            opt_error_log = argv[++argi];

        } else if (strcmp(argv[argi], "-t") == 0) {
            long timeout = xstrtol(argv[++argi], "-t");

            /*
             * A zero timeout is not a valid "wait forever" here -- it is
             * SO_RCVTIMEO's "block indefinitely", which would hang the suite
             * on a server that never answers rather than failing the case.
             */
            if (timeout < 1 || timeout > INT_MAX) {
                die("-t: timeout %ld ms is outside 1-%d", timeout, INT_MAX);
            }

            opt_timeout_ms = (int) timeout;

        } else {
            usage();
        }
    }

    if (argi >= argc) {
        usage();
    }

    /* The flag wins over the environment: run.sh exports PROBER_ERROR_LOG for
     * every run, and a -e given explicitly is the more specific intent. */
    if (opt_error_log == NULL) {
        const char *env = getenv("PROBER_ERROR_LOG");

        if (env != NULL && *env != '\0') {
            opt_error_log = env;
        }
    }

    /* Env-only, resolved once here -- see delta_settle_scale_from_env's
     * comment by DELTA_SETTLE_TRIES for why this has no -t-shaped CLI flag
     * and never dies on a bad value. */
    opt_timeout_scale = delta_settle_scale_from_env();

    cases = calloc(MAX_CASES, sizeof(test_case));
    if (cases == NULL) {
        die("out of memory");
    }

    /*
     * Every rule file is parsed before the first request goes out. A syntax
     * error found halfway through a run would truncate the TAP stream, and a
     * consumer reading a short plan cannot tell that from a crash.
     */
    for (i = argi; i < argc; i++) {
        n += load_rules(argv[i], cases + n, MAX_CASES - n);
    }

    /*
     * A close deadline at or past the read timeout can never be missed.
     *
     * rules.c caps the directive at MAX_CLOSE_WITHIN_MS, but that is a
     * compile-time constant and the timeout is a RUNTIME value (-t, default
     * 5000), so the parser cannot see the relationship: `expect_close_within
     * 8000` parses fine and is unfalsifiable under the default timeout. The
     * read gives up first, every such case reports HTTP_CLOSE_TIMEOUT whatever
     * the server did, and the assertion is a gate that cannot go red -- the
     * exact failure the ceiling exists to prevent, reached by the one path the
     * ceiling cannot cover.
     *
     * Checked here, after load, because this is the first point where both
     * numbers are known. Fatal rather than a per-case failure: it is a mistake
     * in how the run was invoked, not a verdict about the server, and a case
     * that cannot fail must not be allowed to report ok. Deliberately before
     * the --check return, so `--check -t N` validates the combination too.
     */
    for (c = 0; c < n; c++) {
        if (cases[c].saw_close_within
            && cases[c].close_within_ms >= opt_timeout_ms)
        {
            die("case \"%s\": expect_close_within %ld is at or past the "
                "%d ms read timeout, so the read would give up first and the "
                "assertion could never fail -- lower the deadline or raise -t",
                cases[c].name != NULL ? cases[c].name : "(unnamed)",
                cases[c].close_within_ms, opt_timeout_ms);
        }
    }

    /*
     * An idle wait at or past the read timeout is rejected too, but for a
     * different and weaker reason -- worth stating plainly so this is not read
     * as the same bug as the one above.
     *
     * The idle wait POLLS, and poll() answers to its own deadline: SO_RCVTIMEO
     * never applies to it, so a long wait is not truncated and the assertion
     * remains perfectly falsifiable. Nothing is silently wrong.
     *
     * What is wrong is the rule file. `-t` reads as the ceiling on how long any
     * one case may spend on the wire, and a case that quietly parks for longer
     * than it breaks that expectation -- the run stalls somewhere the operator
     * has no reason to look. Rejecting it keeps one number meaning one thing.
     */
    for (c = 0; c < n; c++) {
        if (cases[c].saw_idle
            && cases[c].idle_ms >= opt_timeout_ms)
        {
            die("case \"%s\": expect_idle %ld is at or past the %d ms read "
                "timeout, so the case would outlast the per-request budget -- "
                "lower the wait or raise -t",
                cases[c].name != NULL ? cases[c].name : "(unnamed)",
                cases[c].idle_ms, opt_timeout_ms);
        }
    }

    /*
     * The same two runtime-vs-timeout checks for every pipeline block. A block
     * carries the per-exchange close/idle deadlines the flat case would, and is
     * read against the same -t, so an unfalsifiable close deadline or an
     * over-budget idle wait inside a block is the identical mistake reached one
     * level down. Kept as its own pass rather than folded above so the flat path
     * stays byte-for-byte unchanged.
     */
    for (c = 0; c < n; c++) {
        size_t b;

        for (b = 0; b < cases[c].n_blocks; b++) {
            const pipeline_block *blk = &cases[c].blocks[b];

            if (blk->saw_close_within
                && blk->close_within_ms >= opt_timeout_ms)
            {
                die("case \"%s\" block \"%s\": expect_close_within %ld is at or "
                    "past the %d ms read timeout, so the assertion could never "
                    "fail -- lower the deadline or raise -t",
                    cases[c].name != NULL ? cases[c].name : "(unnamed)",
                    blk->name != NULL ? blk->name : "(unnamed)",
                    blk->close_within_ms, opt_timeout_ms);
            }

            if (blk->saw_idle && blk->idle_ms >= opt_timeout_ms) {
                die("case \"%s\" block \"%s\": expect_idle %ld is at or past "
                    "the %d ms read timeout, so the block would outlast the "
                    "per-request budget -- lower the wait or raise -t",
                    cases[c].name != NULL ? cases[c].name : "(unnamed)",
                    blk->name != NULL ? blk->name : "(unnamed)",
                    blk->idle_ms, opt_timeout_ms);
            }
        }
    }

    /*
     * --check stops here. load_rules() dies on the first malformed directive,
     * so reaching this point IS the pass: every file parsed and every case
     * carries a coherent set of directives. Reported on stdout so a caller can
     * see which files contributed how much; the exit status is the verdict.
     */
    if (opt_check) {
        printf("# %zu cases parsed from %d rule file%s\n",
               n, argc - argi, (argc - argi) == 1 ? "" : "s");

        for (c = 0; c < n; c++) {
            case_free(&cases[c]);
        }

        free(cases);

        return 0;
    }

    /*
     * AUD-08: a normal run with zero cases is a FALSE GREEN. load_rules() can
     * legitimately yield nothing -- a blank file, a comment-only file, a glob
     * that matched files carrying no case -- and printing `1..0` then exiting 0
     * reports a passing suite that asserted nothing. A typo, a merge conflict or
     * a generated-empty rules file would silently remove coverage while CI
     * stayed green. The informational zero result belongs only to --check (which
     * returned above); in an execution run an empty plan is fatal.
     */
    if (n == 0) {
        die("no cases to run: the rule file set parsed to an empty plan "
            "(blank, comment-only or an empty glob) -- a normal run asserts "
            "nothing and would report a false pass; use --check to inspect a "
            "zero-case set on purpose");
    }

    /*
     * The origin snapshot for `probe_baseline`, read once before any case runs
     * and held for the whole run.
     *
     * Read only when some case asks for it, so a run without the directive
     * issues no extra request. A failed read is FATAL rather than a per-case
     * failure: without an origin every probe_baseline in the file would have
     * nothing to subtract from, and silently dropping them would turn off
     * exactly the assertions written to catch a slow leak. Fatal before the
     * plan line, so the run is unambiguously aborted rather than reported as a
     * suite whose cases happened to pass.
     */
    for (c = 0; c < n; c++) {
        if (cases[c].n_baselines > 0) {
            char errbuf[512];

            baseline = fetch_probe(errbuf, sizeof(errbuf));

            if (baseline == NULL) {
                die("probe_baseline needs an origin snapshot: %s", errbuf);
            }

            break;
        }
    }

    printf("1..%zu\n", n);

    for (c = 0; c < n; c++) {
        int ok = run_case(&cases[c], baseline);

        total++;

        if (cases[c].xfail) {
            /*
             * TAP's TODO convention: an xfail case that fails does not fail
             * the suite -- it is expected, so `failures` is not incremented
             * and the line reads "not ok N # TODO <reason>". A case that
             * unexpectedly PASSES is reported as "ok N # TODO <reason>"
             * rather than plain "ok N": most TAP consumers (prove included)
             * surface that distinctly as "unexpectedly succeeded", which is
             * the signal that the annotation is stale and should come off.
             * Either way the annotation itself, not the pass/fail bit, is
             * what keeps the suite green.
             */
            printf("%s %zu - %s # TODO%s%s\n",
                   ok ? "ok" : "not ok", c + 1, cases[c].name,
                   cases[c].xfail_reason ? " " : "",
                   cases[c].xfail_reason ? cases[c].xfail_reason : "");
            fflush(stdout);
            continue;
        }

        if (!ok) {
            failures++;
        }

        printf("%s %zu - %s\n", ok ? "ok" : "not ok", c + 1, cases[c].name);
        fflush(stdout);
    }

    for (c = 0; c < n; c++) {
        case_free(&cases[c]);
    }

    free(cases);
    json_free(baseline);

    if (failures > 0) {
        printf("# %d of %d cases failed\n", failures, total);
    }

    return failures > 0 ? 1 : 0;
}
