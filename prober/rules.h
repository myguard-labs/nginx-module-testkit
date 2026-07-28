/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rules.h -- the rule-file parser: text in, test cases out.
 *
 * Split out of prober.c so it can be exercised as a pure function by
 * rules_test.c. This parser decides the exact bytes that go on the wire, so a
 * defect here does not fail a test -- it silently tests something other than
 * what the rule file says, which no amount of running the suite would reveal.
 *
 * Rule file syntax -- one case per stanza, blank line separated:
 *
 *     name    ban arms after the configured count
 *     send    GET /guarded?id=1+union+select+1,2,3-- HTTP/1.1\r\n
 *     pause   50
 *     send    Host: t\r\nConnection: close\r\n\r\n
 *     expect  status=403
 *     expect  body~Forbidden
 *     expect  header~Content-Type: text/html
 *     expect  raw_response_headers_like~^Content-Type:.*text
 *     probe   zone.nodes == 1
 *     delta   fds == 0
 *     probe_baseline  fds == 0
 *     from    127.0.0.9
 *     fault   fault_slab=1
 *     expect_not      body~Internal Server Error
 *     error_code_like ^(2|3)[0-9]{2}$
 *     xfail   known broken until #42 lands
 *
 * `send` is repeatable and concatenates verbatim -- no implied CRLF, no
 * Content-Length synthesis, no header reordering -- so a stanza can spell out a
 * malformed request byte for byte. Escapes: \r \n \t \\ \" \0 \xNN.
 *
 * `pause <ms>` holds the connection open without writing for <ms>
 * milliseconds at the point it appears between `send` lines, so a rule can put
 * a request line on the wire and stall before its headers. That split is what
 * makes partial-header handling, request-header timeouts and smuggling
 * windows testable at all: a single write() hands the server a complete
 * request no matter how many `send` lines built it, because the bytes are
 * concatenated before they reach the socket. A `pause` before the first `send`
 * or after the last is accepted and stalls at that point (an opening stall
 * exercises the server's pre-request idle timeout; a trailing one holds the
 * connection open after a complete request). Bounded to 1..10000 ms per pause
 * and in sum, because a stall longer than the prober's read timeout would
 * report a harness timeout instead of the server behaviour under test.
 *
 * `repeat <count> <text>` appends its text N times, for the cases that need
 * kilobytes of filler to overrun a server limit without making the rule file
 * unreadable.
 *
 * `abort <offset>` writes the first <offset> bytes of the request and then
 * destroys the connection with a TCP reset (SO_LINGER{1,0}), so the server sees
 * ECONNRESET rather than a clean close. This is the client-vanishes-mid-request
 * primitive: it tests that a server releases a request's resources when the
 * peer disappears, instead of holding them until a timeout expires. Offset 0
 * resets before the first byte (connect-then-vanish); an offset past the
 * request end sends all of it and then resets. Pauses inside the written prefix
 * still apply, so `send_slow` followed by `abort` dribbles and then gives up --
 * a real slowloris client's exit.
 *
 * A reset case has NO response, so it may not carry `expect`, `expect_not` or
 * `error_code_like`: those would assert against an empty buffer, and an
 * `expect_not` in particular would pass unconditionally, reporting green for an
 * assertion that tested nothing. The parser rejects the combination at load
 * time. Judge an aborted case with `no_error_log` / `grep_error_log` / `probe`
 * / `delta` / `probe_baseline` -- evidence the server itself produced. For the
 * same reason `abort` and `shutdown` are mutually exclusive: a half-close asks to be answered, a
 * reset says the client is gone.
 *
 * `probe_baseline <path> <op> <value>` subtracts like `delta`, but from the
 * snapshot taken ONCE before the first case of the run rather than from this
 * case's own before-snapshot. It exists because `delta` cannot see a slow
 * drip: `delta` re-reads its before-snapshot per case, so a leak of one unit
 * per case is already present in BOTH of that case's reads and every
 * `delta X == 0` in the file passes while the resource climbs monotonically.
 * The same run judged against a fixed origin fails on the case that crosses
 * the bound.
 *
 * The two are complements, not alternatives: `delta` localises a jump to the
 * case that caused it, `probe_baseline` bounds the total. A file that cares
 * about a leak wants the accumulating one, usually on the LAST case, and
 * usually a bound rather than `== 0` -- a scenario that legitimately warms a
 * cache or opens a keepalive connection has a non-zero honest floor, and
 * writing `== 0` there fails on correct behaviour.
 *
 * The origin is read before any case runs, so it precedes every fault this
 * file arms and every request it sends; unlike `delta`'s, it is NOT taken
 * after arming, and a fault counter reset therefore DOES show up in it. The
 * probe read costs one request per run and is skipped entirely when no case
 * carries the directive.
 *
 * `expect raw_response_headers_like <regex>` asserts a POSIX extended regex
 * against the raw HTTP header block (colon-delimited lines with CRLF
 * terminators, no status line, no body).
 *
 * `expect_close_within <ms>` asserts the SERVER ended the connection within
 * <ms> of the request going on the wire. This is the assertion the transport
 * directives were missing: `hold`, `shutdown` and `send_slow` can all leave a
 * connection in a state the server is supposed to reclaim, but nothing could
 * say by when, so a server that reclaimed it eventually and one that never did
 * produced identical green runs.
 *
 * It judges HOW the connection ended, not what came back, and the three
 * outcomes are kept distinct on purpose:
 *
 *   - the peer sent FIN within the deadline                   -> pass
 *   - the peer sent FIN, but too late                         -> fail, with the
 *     measured time, because "closed at 4000 ms" and "never closed" are
 *     different bugs and a rule author needs to know which one this is
 *   - the deadline passed with the connection still open      -> fail
 *
 * That last one is why the directive changes the transport's timeout from an
 * error into a result: without it the read gives up, the case aborts with
 * "request failed", and the assertion that asked the question never runs.
 * A reset (RST) also counts as closed -- the connection is gone, which is what
 * was asserted -- but it is reported distinctly in the failure text when the
 * deadline was missed, since a server that resets is doing something other
 * than a graceful close.
 *
 * The deadline is measured from the last request byte, so a case that
 * deliberately dribbles its request with `pause` or `send_slow` is not billed
 * for its own pacing. Bounded to 1..10000 ms: a deadline at or past the
 * prober's read timeout could never fail, because the read would give up
 * first, and an assertion that cannot go red is worse than none.
 *
 * Mutually exclusive with `abort` and with `hold`, for the same underlying
 * reason in two costumes: neither case ever reads the socket, so this process
 * never observes a close and there is nothing to time. Under `abort` the
 * CLIENT resets, so the assertion would be judging this process's own
 * behaviour; under `hold` the connection is deliberately left unread and then
 * closed from this side, so the server's own close -- whenever it came -- is
 * invisible here. (`hold` looks like the natural pairing, and it is the right
 * IDEA: an idle-but-open connection is exactly the state worth putting a
 * deadline on. Observing it needs a read-side idle wait rather than hold's
 * blind sleep, which is a separate directive and deliberately not this one.)
 *
 * The pairing that does work today is `shutdown 1`: half-close the sending
 * side, keep reading, and assert the server closes its half within the
 * deadline -- the lingering-close path. A plain request whose response has
 * been fully received works too, and asserts the server does not then sit on
 * an idle connection.
 *
 * `expect_idle <ms>` is the opposite oracle on the same connection state:
 * it asserts the server left the connection OPEN AND SILENT for <ms> after the
 * request, rather than acting on it. It is the read-side idle wait the close
 * deadline's comment above calls for, and the pairing `hold` could not be --
 * `hold` blind-sleeps with the read loop skipped, so a server that closed or
 * answered during the sleep is indistinguishable from one that sat still.
 *
 * The wait POLLS the socket without reading it. Draining would defeat the
 * directive twice over: the response bytes would be collected (so a case could
 * no longer assert the server stayed silent) and the read would consume the
 * very readiness being asserted about. The connection is therefore left exactly
 * as an idle client would leave it.
 *
 * Three outcomes, kept distinct because they are three different server bugs:
 *
 *   - nothing arrived and the connection stayed open for <ms>  -> pass
 *   - the peer sent data before <ms> elapsed                   -> fail, naming
 *     that the server answered, since "answered early" and "hung up early" want
 *     different fixes
 *   - the peer closed (FIN or RST) before <ms> elapsed         -> fail, with the
 *     measured time and the manner of the close
 *
 * Like the close deadline it is measured from the last request byte, so `pause`
 * and `send_slow` pacing is not billed against the wait, and bounded to
 * 1..10000 ms (see MAX_IDLE_MS).
 *
 * Mutually exclusive with `abort` and `hold` for the reason those exclude the
 * close deadline: neither reads or polls the socket, so there is no observation
 * to make. Also mutually exclusive with `expect_close_within` -- one case
 * cannot coherently assert both that the server closes within <n> ms and that
 * it stays open for <m>, and accepting the pair would let whichever assertion
 * ran first decide the verdict.
 *
 * `expect_not` mirrors `expect` (`body~`, `header~`) but asserts the opposite:
 * the case fails if the pattern IS found. A distinct directive rather than a
 * `!~` operator on `expect`, so a rule file reads its polarity at the
 * directive name instead of a symbol easy to misread in a diff.
 *
 * `error_code_like <regex>` is `expect status=` generalised to a POSIX
 * extended regex against the status code rendered as decimal text (e.g.
 * "404"), for cases that accept a class of codes ("any 2xx") rather than one
 * exact value. Compiled at load time so a malformed pattern is a load-time
 * die(), not a run-time surprise on the one case that reaches it.
 *
 * `xfail [reason]` marks the whole case as a known failure: it still runs and
 * is still reported, but a failing xfail case does not fail the suite (TAP
 * `not ok N # TODO <reason>`), and a PASSING xfail case is flagged distinctly
 * (`ok N # TODO <reason>` -- TAP's convention for "this unexpectedly started
 * working"), because that is the signal that the annotation should be removed.
 *
 * `no_error_log <regex>` / `grep_error_log <regex>` assert over the server
 * error-log lines written DURING this case only: no line may match / at least
 * one line must match the POSIX extended regex. The prober records the log
 * file's size immediately before the case's request and evaluates only the
 * bytes appended after that mark -- grep-the-slice, not scrape-the-whole-log,
 * so an earlier case's lines can neither satisfy a grep_error_log nor trip a
 * no_error_log. Both need the log path (prober -e, or PROBER_ERROR_LOG, which
 * run.sh exports); a case carrying either directive FAILS when the path is
 * not configured, because a silently skipped assertion reads as a pass.
 * These are per-case and complement run.sh's whole-run alert/crit/emerg gate,
 * which stays authoritative for severities no rule thought to mention.
 *
 * `block <name>` turns a case into a PIPELINE: two or more request/response
 * exchanges driven over ONE keepalive connection, each judged against its own
 * response. It is the only way to test a defect that shows up ACROSS requests on
 * a reused connection -- module context bleeding from one request into the next,
 * a keepalive pool serving a stale response, a second response corrupted by the
 * first. From the first `block` onward, every per-exchange directive
 * (send/pause/expect/shutdown/abort/hold/idle/recv/dechunk/gunzip/json_sort/...)
 * attaches to the OPEN block instead of the flat case; the case-level directives
 * (probe/delta/probe_baseline/no_error_log/grep_error_log/pid_may_change/fault/
 * from) stay at the case level and judge server-wide state ONCE around the whole
 * pipeline. A case with no `block` (n_blocks == 0) is the legacy flat shape,
 * byte for byte unchanged.
 *
 * Load-time rules, each because the alternative is a case that silently tests
 * nothing: a per-exchange directive before the first `block` is rejected (a case
 * cannot drive part of itself flat and part in blocks); a block with no `send`
 * is rejected; a block carrying `abort`/`hold`/`expect_idle` -- which end or
 * never-read the connection -- must be the LAST block, since any block after it
 * could never run (same principle as abort+expect above, one level up); and such
 * a block may carry no response expectations, for the same empty-buffer reason a
 * flat abort/hold/idle case may not. Capped at MAX_BLOCKS. The block's name is
 * diagnostic only (it prefixes the block's failure text), the role `name` plays
 * for a case. At run time each block but the last is read framed (the E1
 * single-response reader) so a folded-together pair of responses is caught, not
 * absorbed by reading to EOF; a connection that ends before the last block
 * reports every remaining block FAILED ("not reached"), never skipped.
 */

#ifndef NGX_TEST_HARNESS_RULES_H
#define NGX_TEST_HARNESS_RULES_H

#include <regex.h>
#include <stddef.h>

#include "http.h"

#define MAX_ASSERTS  32
#define MAX_CASES    256
#define MAX_PAUSES   16

/* Upper bound on pipeline sub-blocks in one case (the `block` directive). A
 * rule file that drives an unbounded pipeline over one connection is a stress
 * test, not a correctness test, and belongs in a scenario driver; this cap
 * matches MAX_PAUSES's conservatism for the same reason -- a small fixed
 * ceiling on a per-case array that lives on the stack via the cases[] slot. */
#define MAX_BLOCKS  16

/* Upper bound on the idle connections a case may hold open (the `open_conns`
 * directive). These are bare accepted connections the case parks to push a
 * worker toward its worker_connections / max_conns limit while a `probe`
 * assertion reads the resulting connection count; each costs one client fd for
 * the life of the probe read. The ceiling keeps a rule from exhausting the
 * prober's own fd table (well under a default 1024 rlimit, leaving room for the
 * probe socket, error log, and the case's own exchange). A test that truly
 * needs thousands of connections is a load test and belongs in a scenario
 * driver, not a single case. */
#define MAX_OPEN_CONNS  512

/* Upper bound on the in-flight requests a case may issue (the `concurrent`
 * directive) is MAX_CONCURRENT, defined in http.h beside the driver that
 * enforces it. Deliberately NOT redefined here: the parser rejects an oversized
 * count with a line number and the driver rejects it again at its public entry
 * point, and two copies of that ceiling would eventually disagree -- at which
 * point the parser would admit a fan the transport then refuses. See http.h for
 * why the value is far below MAX_OPEN_CONNS. */

/* Upper bound on a single `pause`, and on the sum of a case's pauses. A rule
 * file that pauses longer than the prober's own read timeout would report a
 * harness timeout rather than the server behaviour under test, so the ceiling
 * is low enough to stay inside any plausible timeout. */
#define MAX_PAUSE_MS  10000

/* Upper bound on a `send_slow` chunk size. A chunk larger than the request is
 * merely a single write, so this only has to be big enough to be useful; the
 * cap exists to keep an obviously-wrong value (a typo'd byte count) from
 * silently degrading a pacing test into one plain write that still reports ok. */
#define MAX_SEND_SLOW_CHUNK  4096

/* Bounds on `recv_slow <chunk> <ms>`. The chunk shares send_slow's cap for the
 * same reason -- a chunk larger than the response is merely one read -- and the
 * stall shares the pause ceiling, since a receive-side stall spends the
 * prober's read timeout just as surely as a send-side one. The ceiling is per
 * READ here, not per case: the total depends on the response size, which the
 * rule file cannot know, so a rule that paces a large response can still exceed
 * the timeout and will report it as the harness timeout it is. */
#define MAX_RECV_SLOW_CHUNK  4096

/* Bounds on `so_rcvbuf <bytes>`. The floor is deliberately low -- the point is
 * a buffer small enough that a stalled reader is felt by the server -- and the
 * kernel silently raises anything under its own minimum, so a value below it is
 * a request for "as small as allowed" rather than an error. The ceiling only
 * rejects a typo'd value so large it would defeat the directive's purpose. */
#define MIN_RCVBUF  128
#define MAX_RCVBUF  1048576

/* `expect_close_within` off value. Zero cannot serve: a 0 ms deadline is
 * something a rule file can legitimately spell (and always fails), so a zeroed
 * field would be indistinguishable from a case that asked for one. */
#define CLOSE_WITHIN_NONE  (-1)

/* Upper bound on an `expect_close_within` deadline. A deadline at or past the
 * prober's read timeout can never fail: the read gives up first and reports
 * the timeout, so the assertion would pass on a server that never closes at
 * all -- a gate that cannot go red.
 *
 * This constant is only HALF the bound, and deliberately the weaker half. The
 * read timeout is a RUNTIME value (-t, default 5000) that this parser cannot
 * see, so a deadline between the timeout and this ceiling parses fine and is
 * still unfalsifiable. prober.c re-checks every loaded case against the actual
 * timeout and bails; see the loop after load_rules() there. Keeping a constant
 * here too catches an obviously-wrong value with a FILE AND LINE NUMBER, which
 * the runtime check cannot give. */
#define MAX_CLOSE_WITHIN_MS  10000

/* `expect_idle` off value, for the same reason CLOSE_WITHIN_NONE is not
 * zero: `expect_idle 0` is spellable (and asserts nothing), so a zeroed
 * field could not be told apart from a case that never used the directive. */
#define IDLE_NONE  (-1)

/* Upper bound on an `expect_idle` idle wait. Unlike the close deadline's
 * ceiling this one is not about falsifiability -- an idle wait fails by the
 * server ACTING, so any value can go red -- but about the suite: the wait is a
 * real sleep on the wire, serial with every other case, and a rule that parks
 * for a minute stalls the run.
 *
 * The idle wait polls rather than reads, so unlike the close deadline it is NOT
 * truncated by the runtime read timeout -- poll() answers to its own deadline
 * and SO_RCVTIMEO never applies. prober.c still rejects a wait at or past that
 * timeout, but for a readability reason rather than a correctness one; see the
 * check there. */
#define MAX_IDLE_MS  10000


/*
 * A case's `pause` list is kept beside the request buffer rather than
 * splitting the request into segments, so a case with no `pause` produces the
 * exact same single write() it did before this directive existed -- the wire
 * behaviour of every existing rule file is unchanged by construction, not by
 * testing. The element type belongs to the transport (http.h), which is what
 * turns an offset and a duration into actual wire timing.
 */


typedef enum {
    EXPECT_STATUS,
    EXPECT_BODY_CONTAINS,
    EXPECT_BODY_SHA256,
    EXPECT_HEADER_CONTAINS,
    EXPECT_NOT_BODY_CONTAINS,
    EXPECT_NOT_HEADER_CONTAINS,
    EXPECT_STATUS_LIKE,
    EXPECT_RAW_RESPONSE_HEADERS_LIKE
} expect_kind;

typedef struct {
    expect_kind  kind;
    long         number;
    char        *text;
    regex_t      re;         /* compiled only for EXPECT_STATUS_LIKE */
} expectation;

typedef struct {
    char  *path;
    char  *op;
    char  *literal;
} probe_assert;

/* One no_error_log / grep_error_log line. The pattern source text is kept
 * beside the compiled form purely for diagnostics: a failure must be able to
 * say WHICH regex missed or matched, and regex_t cannot be printed. */
typedef struct {
    char     *pattern;
    regex_t   re;
} log_assert;

/*
 * One pipeline sub-block: a single request/response exchange on the shared
 * connection, introduced by a `block <name>` directive. It carries exactly the
 * per-EXCHANGE knobs -- the request bytes, the pacing, the transport lifecycle
 * (shutdown/abort/hold/idle/recv), the body transforms, and the response
 * expectations judged against THIS block's own response. Everything that judges
 * server-wide state instead (probe/delta/baseline/log/pid) stays at the case
 * level: it is snapshotted once around the whole pipeline, not per block.
 *
 * The field set duplicates the legacy flat fields on test_case deliberately.
 * When a case uses no `block` directive (n_blocks == 0) the flat fields drive
 * it exactly as before -- byte for byte -- and the blocks[] array is untouched;
 * when it uses >= 1 block, the flat fields are unused and every per-exchange
 * directive fills the OPEN block instead. Two parallel shapes gated on
 * n_blocks == 0, rather than one shape with a synthesized block for legacy
 * cases, so no existing rule file or rules_test.c assertion that addresses
 * tc->expects[i]/tc->request directly has to change. See design-e2-pipeline.md.
 */
typedef struct {
    char           *name;              /* diagnostic label, block-local     */
    unsigned char  *request;
    size_t          request_len;
    http_pause      pauses[MAX_PAUSES];
    size_t          n_pauses;
    int             shut_how;
    int             saw_shutdown;
    size_t          abort_at;
    int             saw_abort;
    long            hold_ms;
    int             saw_hold;
    long            close_within_ms;
    int             saw_close_within;
    long            idle_ms;
    int             saw_idle;
    http_recv       recv_opt;
    int             saw_recv_slow;
    int             saw_rcvbuf;
    expectation     expects[MAX_ASSERTS];
    size_t          n_expects;
    int             dechunk;
    int             gunzip;
    int             json_sort;
} pipeline_block;

typedef struct {
    char           *name;
    char           *fault;      /* probe query armed before the send, or NULL */
    char           *source;     /* local address to connect from, or NULL     */
    unsigned char  *request;
    size_t          request_len;
    http_pause      pauses[MAX_PAUSES];
    size_t          n_pauses;

    /* shutdown(2) mode applied once the request is written, or HTTP_SHUT_NONE.
     * Initialised to HTTP_SHUT_NONE when a stanza opens -- a zeroed field would
     * mean SHUT_RD, silently half-closing every case that never asked. */
    int             shut_how;

    /* Whether a shutdown directive was seen, tracked separately from the mode.
     * The duplicate check must not ask "is shut_how still the sentinel?": that
     * conflates "unset" with "set", and would break the moment HTTP_SHUT_NONE
     * were ever given a value a rule file can also spell. */
    int             saw_shutdown;

    /* Byte offset at which to reset the connection, or HTTP_ABORT_NONE.
     * Initialised to the sentinel when a stanza opens: offset 0 is a legitimate
     * value meaning "reset before writing anything", so a zeroed field would
     * abort every case that never asked -- the same trap as shut_how above, and
     * the reason the duplicate check keys on saw_abort rather than on the
     * offset still holding the sentinel. */
    size_t          abort_at;
    int             saw_abort;

    /* Milliseconds to hold the connection open, idle and unread, after the
     * request is written, or HTTP_HOLD_NONE. Zero is the off value -- holding
     * for no time is indistinguishable from not holding -- so like recv_opt
     * below this needs no sentinel, and saw_hold exists only to reject a case
     * that sets it twice. */
    long            hold_ms;
    int             saw_hold;

    /* Deadline in milliseconds for the server to close the connection, or
     * CLOSE_WITHIN_NONE.
     *
     * Kept beside the transport knobs rather than in `expects[]` because it is
     * judged against how the connection ENDED, not against the bytes that came
     * back -- the response may be byte-identical whether the server closed
     * promptly, closed late, or is still holding the socket open. Zero is not
     * usable as the off value here (a 0 ms deadline is a coherent, if
     * unsatisfiable, thing to ask for), so this carries a sentinel and
     * saw_close_within records whether the directive appeared at all. */
    long            close_within_ms;
    int             saw_close_within;

    /* Milliseconds the server must leave the connection open and silent, or
     * IDLE_NONE. The mirror of close_within_ms above and judged the same
     * way -- against what the connection DID, not against the response bytes --
     * and carrying a sentinel for the same reason: `expect_idle 0` is
     * spellable, so zero cannot mean "absent". */
    long            idle_ms;
    int             saw_idle;

    /* Relax the worker-survival oracle from "same worker" to "same master"
     * for this case: set by `pid_may_change`, for a case that spans a SIGHUP,
     * a binary upgrade, or a conf with several workers, where a changed worker
     * pid is the designed behaviour rather than a crash. See eval_pid_stable()
     * in assert.h for what each form asserts.
     *
     * Zero is the off value and needs no sentinel: the directive takes no
     * argument, so "absent" and "strict" are the same state, and case_free()'s
     * memset already leaves it strict. Doubles as its own duplicate guard. */
    int             pid_may_change;

    /* Number of bare idle connections to open and hold across the probe read,
     * or 0 for none. Set by `open_conns <N>` (case-level, never per-block). The
     * connections carry no request -- they exist only to occupy worker
     * connection slots so a `probe connections...` assertion can observe a
     * worker approaching its worker_connections / max_conns limit. Opened after
     * the case's own exchange and closed the instant the probe snapshot is
     * taken, so the delta/pid reads that follow see a clean count. Zero is the
     * off value and doubles as the duplicate guard: a valid count is >= 1, so a
     * second `open_conns` finds a non-zero field and dies. Capped at
     * MAX_OPEN_CONNS. Requires at least one `probe` assertion (load-time check)
     * -- held connections nothing observes are a vacuous test. */
    int             open_conns;

    /* Number of copies of this case's request to hold IN FLIGHT at once, or 0
     * for the ordinary one-request-at-a-time path. Set by `concurrent <N>`
     * (case-level, never per-block).
     *
     * The distinction from open_conns is the whole point of the directive.
     * open_conns parks bare connections that never send anything; concurrent
     * opens N connections, writes the case's request on ALL of them before
     * reading ANY response, and then drains the N responses with poll(). So
     * every request is genuinely outstanding in the worker at the same moment,
     * which is the only state in which a shared-memory or per-worker race can
     * be reached at all -- a sequential prober cannot construct it no matter how
     * many requests it sends.
     *
     * The before/after probe snapshots bracket the whole fan, so the case's
     * existing `delta` oracles then assert that N overlapping requests leave the
     * worker exactly as N sequential ones would: no extra descriptor, no pool
     * growth, no slab page. A leak that only manifests under overlap shows up as
     * a non-zero delta here and nowhere else in the suite.
     *
     * Mutually exclusive with `block` (a pipeline is by definition ordered on
     * one connection, so "N of them concurrently" would be a different and much
     * larger feature) -- the parser rejects the combination rather than picking
     * a winner. Zero is the off value and doubles as the duplicate guard, since
     * a valid count is >= 2. Capped at MAX_CONCURRENT. */
    int             concurrent;

    /* Receive-side pacing and the client's SO_RCVBUF. Both zero by default,
     * which is "read as fast as the peer sends, system-default buffer" -- the
     * behaviour of every rule that predates these directives. Unlike the two
     * fields above, zero is genuinely the off value here, so neither needs a
     * sentinel or a saw_ flag for defaulting; the duplicate guards below exist
     * only to reject a case that sets one twice. */
    http_recv       recv_opt;
    int             saw_recv_slow;
    int             saw_rcvbuf;
    expectation     expects[MAX_ASSERTS];
    size_t          n_expects;
    probe_assert    probes[MAX_ASSERTS];
    size_t          n_probes;
    probe_assert    deltas[MAX_ASSERTS];   /* asserted on after minus before */
    size_t          n_deltas;
    probe_assert    baselines[MAX_ASSERTS];  /* after minus the RUN's first  */
    size_t          n_baselines;
    /* 1 if the case is annotated `dechunk`: the body oracles then read the
     * DECODED chunked body instead of the raw wire bytes, and a framing error
     * fails the case outright. Off by default, so no rule written before this
     * directive existed changes meaning. */
    int             dechunk;
    /* 1 if the case is annotated `gunzip`: the body oracles then read the
     * INFLATED gzip/deflate body, and a decode error fails the case outright.
     * Chains after `dechunk` (inflate the post-dechunk bytes). Off by default,
     * so no rule written before this directive existed changes meaning. */
    int             gunzip;
    /* 1 if the case is annotated `json_sort`: the body oracles then read the
     * CANONICAL JSON body (object keys byte-sorted), so a body_sha256 assertion
     * is independent of key order, and a body that will not parse as JSON fails
     * the case outright. Chains after `dechunk`/`gunzip` (canonicalize the
     * most-decoded bytes). Off by default, so no pre-existing rule changes. */
    int             json_sort;
    int             xfail;      /* 1 if the case is annotated `xfail`        */
    char           *xfail_reason;  /* text after `xfail`, or NULL            */
    log_assert      no_logs[MAX_ASSERTS];    /* no line may match            */
    size_t          n_no_logs;
    log_assert      grep_logs[MAX_ASSERTS];  /* some line must match         */
    size_t          n_grep_logs;

    /* Pipeline sub-blocks, filled by `block <name>`. Empty (n_blocks == 0) for
     * every case that drives a single exchange the flat fields above -- the
     * legacy shape, unchanged. When non-empty, ALL per-exchange directives
     * attached to the blocks below and the flat fields are unused; probe/delta/
     * baseline/log/pid above still apply once to the whole pipeline. */
    pipeline_block  blocks[MAX_BLOCKS];
    size_t          n_blocks;
} test_case;


/*
 * Parse `file` into `cases`, at most `max` of them. Returns the number parsed.
 * Any syntax error is fatal via die(): a rule file that does not say what its
 * author meant must not run at all, because a case that silently parses into
 * something else still reports ok.
 */
size_t load_rules(const char *file, test_case *cases, size_t max);

/*
 * As load_rules(), but reads the rule text from an in-memory buffer instead of
 * a path -- the fuzz target's entry, so a hostile rule file is (data, size)
 * with no temp file. Same parser, same fatal-on-syntax-error contract (the
 * fuzz build installs a die() hook that longjmps out instead of exiting, so a
 * malformed input returns to the harness rather than aborting the process).
 */
size_t load_rules_buf(const char *buf, size_t len, test_case *cases, size_t max);

void case_free(test_case *tc);

#endif /* NGX_TEST_HARNESS_RULES_H */
