/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * assert.h -- evaluation of `probe` and `delta` assertions against probe
 * documents.
 *
 * Split out of prober.c so it can be exercised without a server. This code IS
 * the verdict: everything else in the harness exists to put a document in front
 * of it. An evaluator that returns "pass" where it should return "fail" makes
 * every rule that depends on it untestable-by-construction, and the run still
 * reports green -- which is worse than having no rule, because the green is
 * believed.
 *
 * Both entry points return 1 on pass and 0 on fail, and on fail write a
 * human-readable reason into `why`. There is no third outcome: a path that
 * cannot be evaluated (absent, wrong type, unusable literal) is a failure, not
 * a skip, because a skip would be indistinguishable from a pass in TAP.
 */

#ifndef NGX_TEST_HARNESS_ASSERT_H
#define NGX_TEST_HARNESS_ASSERT_H

#include <stddef.h>

#include "http.h"
#include "json.h"
#include "rules.h"

/* Compare two numbers with a rule-file operator. The operator must already
 * have been accepted by the rule parser; an unknown one here is a bug in the
 * harness rather than in the rule file, and is fatal. */
int compare_number(double have, const char *op, double want);

/*
 * Strip surrounding double quotes from a rule literal into `scratch`, or
 * return `lit` unchanged when it is not quoted.
 *
 * Returns NULL when a quoted literal does not fit in `scratch`. That is
 * reported by the caller as an assertion failure rather than being fatal: an
 * over-long literal is one bad line in one rule file, and killing the process
 * for it would truncate the TAP stream and take every later case down with it.
 */
const char *unquote(const char *lit, char *scratch, size_t scratchlen);

/*
 * Evaluate one `expect` / `expect_not` / `error_code_like` line against a
 * received response. Lived inline in the prober's case loop until expect_not
 * arrived; a negative matcher whose inversion no unit test can reach is
 * exactly the "evaluator that cannot fail" this header warns about, so the
 * whole switch moved here where assert_test.c can feed it fixed responses.
 */
int eval_expect(const expectation *e, const http_response *resp, char *why,
    size_t whylen);

/*
 * Whether this expectation judges the response BODY (as opposed to the status
 * line or headers). When a requested body transform (dechunk/gunzip/json_sort)
 * fails, the case is already failed, but the body oracles must not run: they
 * would read whatever lower tier body_bytes() falls back to and could emit a
 * misleading PASS (or a spurious NOT-contains PASS) against bytes the transform
 * rejected. The caller skips these once a transform has failed.
 */
int expect_reads_body(const expectation *e);

/*
 * Evaluate an `expect_close_within <ms>` deadline against a finished exchange.
 *
 * Judges resp->close_reason and resp->close_ms, not the response bytes: the
 * same body can come back from a server that closed promptly, one that closed
 * far too late, and one still holding the socket open.
 *
 * The three failure modes are reported distinctly because they are different
 * bugs. A late FIN says the server closes but too slowly; a timeout says it did
 * not close at all within the deadline; HTTP_CLOSE_NONE says no close was
 * observable in the first place (the case never read the socket), which is a
 * rule-file mistake rather than a server defect and must not read as a pass.
 *
 * Split out here, rather than living in the prober's case loop, for the reason
 * this header opens with: an assertion whose failing branch no unit test can
 * reach is one that reports green forever.
 */
int eval_close_within(const http_response *resp, long deadline_ms, char *why,
    size_t whylen);

/*
 * Judge an `expect_idle` idle wait: did the server leave the connection
 * open and silent for wait_ms? Returns 1 on pass, 0 on failure with *why filled.
 *
 * The mirror of eval_close_within() above and split out for the same reason,
 * but with the polarity reversed: here the server ACTING is the failure. Its
 * three failing modes are again kept distinct -- data arrived (the server
 * answered), FIN or RST arrived (the server hung up, named by manner), or no
 * idle wait ran at all, which like HTTP_CLOSE_NONE above is a harness defect
 * that must not read as a pass.
 */
int eval_idle(const http_response *resp, long wait_ms, char *why,
    size_t whylen);

/*
 * Does any complete line in buf[0..len) match the compiled regex?
 *
 * The unit both log directives share: grep_error_log wants the answer to be
 * yes, no_error_log wants it to be no, and the caller decides which. Matching
 * is per LINE, like grep -E, not against the buffer as one string -- an
 * unanchored pattern must not match across a newline. A trailing fragment
 * without its newline is still matched: the interesting line in a crash is
 * precisely the one the writer did not get to finish.
 */
int log_lines_match(const char *buf, size_t len, const regex_t *re);

/* Evaluate `<path> <op> <literal>` against a single probe document. */
int eval_probe(const json_value *doc, const probe_assert *pa, char *why,
    size_t whylen);

/*
 * Evaluate `(after - before) <op> <literal>` across two probe documents.
 *
 * `label` names the directive in the failure text ("delta" or
 * "probe_baseline"). The two share every rule of evaluation and differ only in
 * which snapshot is passed as `before`, so they share this evaluator -- but a
 * case may carry both, and a diagnostic that named the wrong one would send a
 * reader to the wrong line.
 */
int eval_delta(const json_value *before, const json_value *after,
    const probe_assert *pa, const char *label, char *why, size_t whylen);

/*
 * Verify the worker that answered the after-snapshot is the one that answered
 * the before-snapshot.
 *
 * This is not driven by a rule directive: it applies to every case, because a
 * worker that segfaults mid-request is respawned by the master, and the retry
 * the client never sees can still produce the status and body the rule asked
 * for. The case then reports ok while the module under test crashed. A changed
 * pid is that crash, and it is visible with no sanitizer and no module C.
 *
 * Unlike a delta, an absent or non-numeric "pid" is a failure rather than
 * something to compare: the pid is rendered unconditionally by the generic
 * half of the probe, so its absence means the document is not the document
 * this oracle thinks it is, and silently skipping would turn the check off
 * everywhere at once. The same holds for "ppid" whenever it is consulted.
 *
 * `may_change` selects WHICH invariant is asserted; it never disables the
 * oracle. It is 0 by default, and set by a case's `pid_may_change` directive.
 *
 *   0 -- same worker. The strict form: the after-pid must equal the before-pid.
 *        REQUIRES worker_processes 1. "The worker" is only a meaningful subject
 *        with one of them: several live workers answer consecutive probe
 *        requests in turn, so the pid changes on a server that is perfectly
 *        healthy and every case fails. The conf belongs to the consumer, so
 *        this cannot be enforced here -- run.sh checks the rendered file and
 *        bails before the first case instead.
 *
 *   1 -- same master. The after-pid may differ, but its "ppid" must equal the
 *        before-snapshot's "ppid". This is what a case spanning a reload needs:
 *        a SIGHUP replaces the worker ON PURPOSE, so pid equality reports a
 *        crash on a server doing exactly what the scenario asked. It is also
 *        what a multi-worker conf needs, for the same reason.
 *
 *        KNOW WHAT THIS GIVES UP. A crash-respawned worker has the SAME master
 *        as a reload-respawned one -- measured, not assumed: SIGKILLing a
 *        worker of master M yields a replacement whose ppid is still M. So
 *        this form does NOT distinguish a crash from a reload, and a module
 *        that segfaults inside a case carrying this directive is reported ok.
 *        What it still catches is a worker from a DIFFERENT master, i.e. the
 *        probe port being answered by a server the scenario did not start.
 *
 *        That is why the relaxation is per-case rather than a file-wide switch:
 *        it is strictly weaker, so it belongs only on the stanza that actually
 *        crosses the signal. A scenario that needs the crash caught across a
 *        reload has to assert it another way -- `no_error_log` on the worker
 *        exit message, or a delta that a respawned worker could not satisfy.
 *
 * Note the master's OWN pid is never asserted to be unchanged: a master that
 * dies takes the whole server with it, so the next probe read fails to connect
 * long before this oracle is reached.
 */
int eval_pid_stable(const json_value *before, const json_value *after,
    int may_change, char *why, size_t whylen);

#endif /* NGX_TEST_HARNESS_ASSERT_H */
