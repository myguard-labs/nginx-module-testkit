/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http.c -- see http.h.
 */

/* _GNU_SOURCE for memmem(): the response body is binary, so the header
 * terminator must be located by length-bounded search, never by strstr(). */
#define _GNU_SOURCE

#include "http.h"
#include "json.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>


void
http_response_free(http_response *resp)
{
    if (resp == NULL) {
        return;
    }

    free(resp->raw);
    free(resp->headers);
    free(resp->decoded);
    free(resp->inflated);
    free(resp->canon);

    resp->raw = NULL;
    resp->headers = NULL;
    resp->body = NULL;
    resp->decoded = NULL;
    resp->inflated = NULL;
    resp->canon = NULL;
    resp->raw_len = 0;
    resp->body_len = 0;
    resp->decoded_len = 0;
    resp->dechunk_status = HTTP_DECHUNK_NONE;
    resp->inflated_len = 0;
    resp->gunzip_status = HTTP_GUNZIP_NONE;
    resp->canon_len = 0;
    resp->json_sort_status = HTTP_JSON_SORT_NONE;
}


/*
 * Parse one hex chunk-size line at `p`, stopping at `end`.
 *
 * The size is accumulated with an overflow check BEFORE each shift rather than
 * after: a chunk size is attacker-controlled text, and "0xFFFFFFFFFFFFFFFF0"
 * wrapping to a small value is the primitive behind a whole family of request
 * smuggling bugs. A wrapped size would be accepted here and then used as a
 * memcpy length, so the check has to happen while the value is still growing.
 * SIZE_MAX / 16 is the largest value that can survive another hex digit.
 *
 * A chunk extension (";name=value" after the size) is skipped, not rejected --
 * it is legal HTTP/1.1 framing. Everything up to the CRLF is discarded once at
 * least one hex digit has been seen; a size line with NO hex digit at all is a
 * BAD_SIZE, since "" and ";foo" are not lengths.
 */
/* Defined below, near the header-search helpers; used by the framed-mode
 * classifier above them. Byte-wise ASCII case-insensitive compare of `len`
 * bytes -- deliberately NOT strncasecmp(), which consults the locale table (see
 * ascii_fold()'s comment for the tr_TR breakage that motivated it). */
static int ascii_case_eq(const char *a, const char *b, size_t len);

/*
 * One leg's response-read state, S-4.
 *
 * The read loop used to be a blocking for(;;) over a single fd. The concurrent
 * fan drained its legs by running that loop once per leg IN INDEX ORDER, which
 * meant leg i+1 was not read at all until leg i completed or timed out: a fan
 * could not observe its legs out of index order under any circumstance, so a
 * server answering leg 5 first was indistinguishable from one answering in
 * order. Fixing that requires every leg to be advanceable independently, which
 * requires the loop's locals to become addressable state -- this struct.
 *
 * OWNERSHIP INVARIANT, and it replaces #144's weaker one. #144 could say "no
 * allocation crosses the seam" because the buffer was born and died inside one
 * call; a state machine breaks that by construction, since `buf` now lives
 * across returns. The replacement, enforced by http_read_state_free():
 *
 *   Every terminal state either frees `buf` or transfers it to resp->raw, and
 *   NULLs st->buf either way. A leg left non-terminal still owns its buffer, so
 *   a caller abandoning the drain frees every leg unconditionally.
 *
 * That last clause is new with the fan: the old blocking drain returned on the
 * first failing leg with every earlier leg already terminal, so there was never
 * a live buffer to leak. Under poll() there is.
 */
/* Per-leg error-text width for the concurrent drain. Sized to the same 256 the
 * driver's existing `detail` buffers use, so a leg's message survives being
 * re-rendered into the caller's errbuf without a second truncation. */
#define HTTP_LEG_ERRLEN  256


typedef struct {
    int               fd;
    int               timeout_ms;
    const http_recv  *recv_opt;
    int               want_close;
    int               framed;
    long long         sent_at;
    http_response    *resp;
    int              *conn_open;

    char             *buf;
    size_t            cap;
    size_t            len;

    /* Whether the previous read filled its chunk, deciding if the next one
     * paces; see the gate in http_read_state_step(). */
    int               paced_full;

    /* Deliberate recv pacing, discounted from the whole-exchange deadline.
     * not_before is the gate: while it is in the future the leg is excluded
     * from the pollfd set instead of sleeping, so pacing one leg does not
     * stall the others. gate_start is stamped when the gate is set so the
     * credit can be the interval actually withheld rather than the intended
     * one -- the distinction S-5 exists to preserve. */
    long long         paced_sleep_ms;
    long long         not_before;
    long long         gate_start;

    /* The value of resp->reads when the pacing gate was last armed. A gate is
     * owed a read; see the guard at the gate. 0 is the never-gated state and
     * cannot collide with a legitimate arm, which needs a chunk-filling read
     * first and so sees reads >= 1. */
    size_t            gate_reads;

    /* The per-read idle deadline: the instant this leg gives up waiting for the
     * NEXT byte. Restamped after every read that delivered data, so it bounds
     * silence between reads rather than the exchange as a whole.
     *
     * This exists because the S-4 drain stopped bounding that silence. The
     * pre-S-4 reader sat in a blocking read() and SO_RCVTIMEO=timeout_ms cut it
     * off; the drain waits in poll() instead, where SO_RCVTIMEO does not apply,
     * so the only remaining server-side boundary was the 8x whole-exchange
     * budget -- an 8x inflation of every silent-peer case, measured at 2401 ms
     * against a 300 ms timeout where the old reader took 316 ms. That
     * contradicts want_close's contract in http.h, which promises a
     * non-closing server is answered after timeout_ms.
     *
     * Held per leg, never recomputed from a fresh timeout_ms on each poll
     * iteration: the fan polls all legs together, so a chatty sibling waking
     * the loop must not postpone a silent leg's own deadline. */
    long long         idle_deadline;

    int               done;
    int               rc;
} http_read_state;


/* Defined immediately after http_exchange(), which is its only caller. Declared
 * here rather than moved above it so the file still reads in exchange order --
 * write, then read -- matching the order the two halves actually run in. */
static int http_read_response(int fd, int timeout_ms,
                              const http_recv *recv_opt, int want_close,
                              int framed, long long sent_at,
                              http_response *resp, int *conn_open,
                              char *errbuf, size_t errlen);

static int http_read_state_init(http_read_state *st, int fd, int timeout_ms,
                                const http_recv *recv_opt, int want_close,
                                int framed, long long sent_at,
                                http_response *resp, int *conn_open,
                                char *errbuf, size_t errlen);
static void http_read_state_free(http_read_state *st);
static int http_read_state_pollable(const http_read_state *st, long long now);
static long http_read_state_next_wakeup(const http_read_state *st,
                                        long long now);
static int http_read_state_step(http_read_state *st, int readable,
                                char *errbuf, size_t errlen);


static int
parse_chunk_size(const char *p, const char *end, size_t *size, const char **next)
{
    size_t  value = 0;
    int     digits = 0;

    while (p < end) {
        int  d;

        if (*p >= '0' && *p <= '9') {
            d = *p - '0';
        } else if (*p >= 'a' && *p <= 'f') {
            d = *p - 'a' + 10;
        } else if (*p >= 'A' && *p <= 'F') {
            d = *p - 'A' + 10;
        } else {
            break;
        }

        if (value > SIZE_MAX / 16 || value * 16 > SIZE_MAX - (size_t) d) {
            return HTTP_DECHUNK_BAD_SIZE;
        }

        value = value * 16 + (size_t) d;
        digits++;
        p++;
    }

    if (digits == 0) {
        return HTTP_DECHUNK_BAD_SIZE;
    }

    /* Skip the extension, if any, then require the CRLF that ends the line.
     * A bare LF is NOT accepted: nginx and angie both emit CRLF, and being
     * lenient about line endings here is precisely the parser differential
     * that lets two hops disagree about where a chunk starts.
     *
     * The scan stops at a LF as well as a CR. Skipping to the next CR alone
     * would walk THROUGH a bare-LF line ending and find the CRLF belonging to a
     * later line, accepting the malformed size line and resuming the decode at
     * the wrong offset -- silently turning payload into framing. */
    while (p < end && *p != '\r' && *p != '\n') {
        p++;
    }

    if (end - p < 2 || p[0] != '\r' || p[1] != '\n') {
        return HTTP_DECHUNK_BAD_SIZE;
    }

    *size = value;
    *next = p + 2;

    return HTTP_DECHUNK_OK;
}


const char *
http_dechunk_reason(int status)
{
    switch (status) {
    case HTTP_DECHUNK_NONE:          return "not decoded";
    case HTTP_DECHUNK_OK:            return "ok";
    case HTTP_DECHUNK_NOT_CHUNKED:   return "response is not Transfer-Encoding: chunked";
    case HTTP_DECHUNK_BAD_SIZE:      return "malformed or overflowing chunk size line";
    case HTTP_DECHUNK_BAD_CRLF:      return "chunk data not followed by CRLF";
    case HTTP_DECHUNK_TRUNCATED:     return "chunk shorter than its declared size";
    case HTTP_DECHUNK_NO_LAST_CHUNK: return "no terminating 0-chunk";

    /* The status is an int rather than an enum, so the compiler cannot prove
     * this switch is exhaustive and a bare fallthrough after it reads as an
     * uncovered case. Spelled as a default so the gap is closed where the
     * checker looks for it -- and so a status added to the header without a
     * string here still renders as an obviously wrong diagnostic instead of
     * falling off the end of a function that returns a pointer. */
    default: return "unknown dechunk status";
    }
}


void
http_dechunk(http_response *resp)
{
    const char  *p, *end;
    char        *out;
    size_t       out_len = 0;

    if (resp == NULL) {
        return;
    }

    free(resp->decoded);
    resp->decoded = NULL;
    resp->decoded_len = 0;

    /* Matched as two independent substrings rather than the literal
     * "Transfer-Encoding: chunked": the spacing after the colon is not fixed,
     * and a coding list ("chunked, gzip") still means the body on the wire is
     * chunked. Demanding the exact spelling would report a chunked response as
     * NOT_CHUNKED, which reads as "nothing to check here" -- a quiet skip is
     * the worst outcome for an oracle. */
    if (resp->body == NULL || resp->body_len == 0
        || !http_has_header(resp, "Transfer-Encoding:")
        || !http_has_header(resp, "chunked"))
    {
        resp->dechunk_status = HTTP_DECHUNK_NOT_CHUNKED;
        return;
    }

    /* The decoded body is strictly shorter than the raw one -- every chunk
     * costs at least a size line and a CRLF -- so body_len is a safe bound and
     * the loop below never needs to grow this. */
    out = malloc(resp->body_len);
    if (out == NULL) {
        resp->dechunk_status = HTTP_DECHUNK_TRUNCATED;
        return;
    }

    p = resp->body;
    end = resp->body + resp->body_len;

    for ( ;; ) {
        size_t       size;
        const char  *next;
        int          rc;

        rc = parse_chunk_size(p, end, &size, &next);
        if (rc != HTTP_DECHUNK_OK) {
            free(out);
            resp->dechunk_status = rc;
            return;
        }

        p = next;

        if (size == 0) {
            /* The terminating chunk. Trailers may follow; they are not body
             * bytes, so decoding stops here and whatever remains is ignored. */
            break;
        }

        /* `size` came off the wire, so this comparison is the bounds check that
         * keeps a lying chunk header from reading past the buffer. Written as a
         * subtraction on the REMAINING span rather than `p + size > end`, which
         * would be undefined pointer arithmetic on overflow. */
        if ((size_t) (end - p) < size) {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_TRUNCATED;
            return;
        }

        memcpy(out + out_len, p, size);
        out_len += size;
        p += size;

        if (end - p < 2 || p[0] != '\r' || p[1] != '\n') {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_BAD_CRLF;
            return;
        }

        p += 2;

        /* Ran out of input with no 0-chunk: every chunk so far was well formed,
         * which is what makes this worth its own code. A truncated response
         * that ends on a chunk boundary is indistinguishable from a complete
         * one to anything that only checks the chunks it did receive. */
        if (p >= end) {
            free(out);
            resp->dechunk_status = HTTP_DECHUNK_NO_LAST_CHUNK;
            return;
        }
    }

    resp->decoded = out;
    resp->decoded_len = out_len;
    resp->dechunk_status = HTTP_DECHUNK_OK;
}


const char *
http_gunzip_reason(int status)
{
    switch (status) {
    case HTTP_GUNZIP_NONE:        return "not decoded";
    case HTTP_GUNZIP_OK:          return "ok";
    case HTTP_GUNZIP_NOT_ENCODED: return "response is not Content-Encoding: gzip or deflate";
    case HTTP_GUNZIP_BAD_STREAM:  return "not a valid gzip/deflate stream";
    case HTTP_GUNZIP_TRUNCATED:   return "stream ended before its terminator";
    case HTTP_GUNZIP_NOMEM:       return "zlib out of memory";

    /* Spelled as a default for the same reason http_dechunk_reason() is: the
     * status is an int, so the compiler cannot prove the switch exhaustive, and
     * a code added to the header without a string here must render as an
     * obviously wrong diagnostic rather than fall off a pointer-returning
     * function. */
    default: return "unknown gunzip status";
    }
}


/*
 * 32 KiB inflate output chunk. The window is at most 32 KiB, so a chunk this
 * size lets zlib make progress on every call without a pathological number of
 * grow-and-retry rounds; the buffer grows geometrically below, so the constant
 * only sets the first allocation, not a ceiling.
 */
#define GUNZIP_CHUNK  (32 * 1024)

void
http_gunzip(http_response *resp)
{
    const char  *in;
    size_t       in_len;
    z_stream     zs;
    char        *out;
    size_t       cap, len;
    int          rc, zrc;

    if (resp == NULL) {
        return;
    }

    free(resp->inflated);
    resp->inflated = NULL;
    resp->inflated_len = 0;

    /* Content-Encoding, not Transfer-Encoding: the compression is a property of
     * the representation, not the framing. Matched as a substring with the
     * header name so "gzip" appearing in some other header value cannot be
     * mistaken for the encoding. `deflate` is accepted alongside `gzip` because
     * zlib's windowBits=47 auto-detects gzip, zlib and (via the fallback below)
     * raw deflate, so one code path serves both encoding names. */
    if (!http_has_header(resp, "Content-Encoding:")
        || (!http_has_header(resp, "gzip")
            && !http_has_header(resp, "deflate")))
    {
        resp->gunzip_status = HTTP_GUNZIP_NOT_ENCODED;
        return;
    }

    /* Inflate the POST-dechunk body when the case chained `dechunk gunzip`: the
     * chunk size lines are framing, not part of the compressed stream, and
     * feeding them to zlib would report BAD_STREAM on a response the server got
     * right. Falls back to the raw body when the case did not dechunk. */
    if (resp->dechunk_status == HTTP_DECHUNK_OK && resp->decoded != NULL) {
        in = resp->decoded;
        in_len = resp->decoded_len;
    } else {
        in = resp->body;
        in_len = resp->body_len;
    }

    if (in == NULL || in_len == 0) {
        resp->gunzip_status = HTTP_GUNZIP_TRUNCATED;
        return;
    }

    memset(&zs, 0, sizeof(zs));

    /* windowBits 15 | 32 (== 47): the +32 tells zlib to accept EITHER a gzip or
     * a zlib header automatically. Raw headerless deflate (which some servers
     * send under the `deflate` name) is handled by a second attempt below. */
    zrc = inflateInit2(&zs, 15 + 32);
    if (zrc != Z_OK) {
        resp->gunzip_status = (zrc == Z_MEM_ERROR)
                              ? HTTP_GUNZIP_NOMEM : HTTP_GUNZIP_BAD_STREAM;
        return;
    }

    cap = GUNZIP_CHUNK;
    out = malloc(cap);
    if (out == NULL) {
        (void) inflateEnd(&zs);
        resp->gunzip_status = HTTP_GUNZIP_NOMEM;
        return;
    }
    len = 0;

    /* zlib's next_in is non-const in older headers (pre-z_const), and inflate()
     * only ever reads it. Launder the const through memcpy rather than a cast:
     * -Wcast-qual forbids the direct cast and clang-tidy's bugprone-casting-
     * through-void forbids the (Bytef*)(void*) dodge, so copy the pointer value
     * into a non-const Bytef* and hand zlib that. */
    memcpy(&zs.next_in, &in, sizeof zs.next_in);
    zs.avail_in = (uInt) in_len;

    /* rc is assigned on every path out of the loop below (it has no fall-through
     * exit), so it is deliberately left uninitialised here -- an initialiser
     * would be a dead store clang-tidy flags. */
    for ( ;; ) {
        size_t  room;

        if (len == cap) {
            char   *bigger;
            size_t  ncap;

            /* Geometric growth so a large body does not pay O(n^2) copies. The
             * overflow check keeps a crafted "expands to SIZE_MAX" stream from
             * wrapping cap to a small value and then overrunning `out`. */
            if (cap > SIZE_MAX / 2) {
                rc = HTTP_GUNZIP_BAD_STREAM;
                break;
            }
            ncap = cap * 2;

            bigger = realloc(out, ncap);
            if (bigger == NULL) {
                rc = HTTP_GUNZIP_NOMEM;
                break;
            }
            out = bigger;
            cap = ncap;
        }

        room = cap - len;
        zs.next_out = (Bytef *) (out + len);
        zs.avail_out = (uInt) (room > UINT_MAX ? UINT_MAX : room);

        zrc = inflate(&zs, Z_NO_FLUSH);

        len = cap - zs.avail_out;

        if (zrc == Z_STREAM_END) {
            rc = HTTP_GUNZIP_OK;
            break;
        }

        if (zrc == Z_OK || zrc == Z_BUF_ERROR) {
            /* Z_BUF_ERROR with no output room left means grow and retry. With
             * room left but no input left, the stream was cut before its
             * terminator -- a truncated body, reported as such rather than as a
             * clean decode of a partial stream. */
            if (zrc == Z_BUF_ERROR && zs.avail_out != 0) {
                rc = HTTP_GUNZIP_TRUNCATED;
                break;
            }
            continue;
        }

        /* Any other return (Z_DATA_ERROR, Z_MEM_ERROR, ...) is a corrupt or
         * unsupported stream. Z_DATA_ERROR on the FIRST call may just mean the
         * server sent raw headerless deflate; that retry is handled below. */
        rc = (zrc == Z_MEM_ERROR) ? HTTP_GUNZIP_NOMEM : HTTP_GUNZIP_BAD_STREAM;
        break;
    }

    (void) inflateEnd(&zs);

    /* Raw-deflate fallback: a server that labels a body `deflate` but sends it
     * with no zlib header trips Z_DATA_ERROR above. Retry once with
     * windowBits = -15 (raw, no header), which is the only case that path
     * covers. Nothing was appended to `out` on a header-level failure, so
     * decoding from scratch is correct. */
    if (rc == HTTP_GUNZIP_BAD_STREAM) {
        z_stream  rzs;

        memset(&rzs, 0, sizeof(rzs));
        if (inflateInit2(&rzs, -15) == Z_OK) {
            memcpy(&rzs.next_in, &in, sizeof rzs.next_in);
            rzs.avail_in = (uInt) in_len;
            rzs.next_out = (Bytef *) out;
            rzs.avail_out = (uInt) (cap > UINT_MAX ? UINT_MAX : cap);

            zrc = inflate(&rzs, Z_FINISH);
            if (zrc == Z_STREAM_END) {
                len = cap - rzs.avail_out;
                rc = HTTP_GUNZIP_OK;
            }
            (void) inflateEnd(&rzs);
        }
    }

    if (rc != HTTP_GUNZIP_OK) {
        free(out);
        resp->gunzip_status = rc;
        return;
    }

    resp->inflated = out;
    resp->inflated_len = len;
    resp->gunzip_status = HTTP_GUNZIP_OK;
}


const char *
http_json_sort_reason(int status)
{
    switch (status) {
    case HTTP_JSON_SORT_NONE:     return "not canonicalized";
    case HTTP_JSON_SORT_OK:       return "ok";
    case HTTP_JSON_SORT_NOT_JSON: return "body did not parse as JSON";
    case HTTP_JSON_SORT_NOMEM:    return "canonical serializer out of memory";

    /* Default for the same reason http_gunzip_reason() carries one. */
    default: return "unknown json_sort status";
    }
}


void
http_json_sort(http_response *resp)
{
    const char  *in;
    size_t       in_len;
    json_value  *doc;
    const char  *jerr;
    char        *canon;
    size_t       canon_len;

    if (resp == NULL) {
        return;
    }

    free(resp->canon);
    resp->canon = NULL;
    resp->canon_len = 0;

    /* Canonicalize the most-decoded body the earlier tiers left, in the same
     * inflated > decoded > raw order the body oracles judge -- so `dechunk
     * gunzip json_sort` canonicalizes the inflated bytes, not the chunk-framed
     * gzip magic. This is a transform of an existing buffer, not a wire decode,
     * so it never reads the socket. */
    if (resp->gunzip_status == HTTP_GUNZIP_OK && resp->inflated != NULL) {
        in = resp->inflated;
        in_len = resp->inflated_len;
    } else if (resp->dechunk_status == HTTP_DECHUNK_OK
               && resp->decoded != NULL) {
        in = resp->decoded;
        in_len = resp->decoded_len;
    } else {
        in = resp->body;
        in_len = resp->body_len;
    }

    if (in == NULL || in_len == 0) {
        resp->json_sort_status = HTTP_JSON_SORT_NOT_JSON;
        return;
    }

    /* json_parse_n, not json_parse: the body may carry an embedded NUL, and the
     * length-delimited parse rejects trailing garbage after it rather than
     * truncating -- the same reason the body oracles were length-aware. */
    doc = json_parse_n(in, in_len, &jerr);
    if (doc == NULL) {
        resp->json_sort_status = HTTP_JSON_SORT_NOT_JSON;
        return;
    }

    if (json_canonicalize(doc, &canon, &canon_len) != 0) {
        json_free(doc);
        /* The only json_canonicalize failure reachable from a parsed document
         * is allocation (the non-finite-number path cannot arise -- json_parse
         * already rejected those), so report NOMEM rather than NOT_JSON: the
         * body WAS valid JSON, the harness just could not render it. */
        resp->json_sort_status = HTTP_JSON_SORT_NOMEM;
        return;
    }

    json_free(doc);

    resp->canon = canon;
    resp->canon_len = canon_len;
    resp->json_sort_status = HTTP_JSON_SORT_OK;
}


/*
 * send(MSG_NOSIGNAL) rather than write(): several rule files deliberately
 * provoke the server into closing mid-request (malformed framing, oversized
 * headers), and a plain write() to a closed peer raises SIGPIPE, whose default
 * action would kill the whole prober. A harness that dies on the case it was
 * written to exercise reports a crash as a missing test, so the failure has to
 * arrive as EPIPE on this one request instead.
 */
static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n == 0) {
            return -1;
        }

        off += (size_t) n;
    }

    return 0;
}


/*
 * The status code of a well-formed "HTTP/<digit>+.<digit>+ <code> <reason>"
 * status line, or -1 for anything else.
 *
 * A bare "HTTP/" prefix check followed by "find the first space anywhere" would
 * accept "HTTP/xyz 200 OK" -- the garbage after the slash never gets looked at,
 * so it parses a real status out of a malformed version line. Worse, with no
 * status line at all it finds the first space inside a HEADER VALUE:
 * "HTTP/1.1\r\nX: 204 y\r\n..." yields 204. That is a false PASS for any rule
 * asserting a status, the worst failure mode for a harness -- it reports
 * success on input the server (or an attacker) never sent as valid HTTP. So the
 * version token is walked byte by byte and the terminating space must be the
 * one that ends *that* token, not merely the first space in the buffer.
 *
 * What is required is the SHAPE `HTTP/<digits>.<digits> `, not a specific
 * version number: the walk is digit-run based, so "HTTP/10.99 200" parses (
 * pinned by http_test.c "multi-digit major.minor still parses") while a bare
 * major-only "HTTP/2 200" does not, because it has no minor version. nginx and
 * angie only ever put HTTP/1.0 or HTTP/1.1 on the wire for the framing this
 * prober reads -- h2/h3 are negotiated, not spelled out in a text status line --
 * so a well-formed but implausible version is left to the rules to assert on
 * rather than rejected here.
 *
 * Version-number filtering would add nothing to framing safety: a status code is
 * bodiless (or not) by RFC 9110 regardless of the version token that preceded
 * it, and a 204 carrying a Content-Length is a lying server whose declared body
 * this code correctly refuses to consume for HTTP/1.1 exactly as for HTTP/2.0.
 *
 * SHARED by http_parse_response() and http_framed_state() on purpose. The
 * classifier used to keep its own looser copy of this walk while its comment
 * claimed it matched this one; the two disagreed, and a response the strict
 * parser scored -1 was classified as bodiless 204 by the loose one -- ending
 * the response at the header terminator and leaving its declared body on the
 * socket for the next pipelined read to consume as a response head. One
 * definition, so they cannot drift apart again.
 */
static int
status_line_code(const char *raw, size_t raw_len)
{
    size_t  i = 5;
    int     saw_major = 0;
    int     saw_minor = 0;

    if (raw == NULL || raw_len <= 5 || memcmp(raw, "HTTP/", 5) != 0) {
        return -1;
    }

    while (i < raw_len && raw[i] >= '0' && raw[i] <= '9') {
        i++;
        saw_major = 1;
    }

    if (saw_major && i < raw_len && raw[i] == '.') {
        i++;

        while (i < raw_len && raw[i] >= '0' && raw[i] <= '9') {
            i++;
            saw_minor = 1;
        }
    }

    if (saw_major && saw_minor && i < raw_len && raw[i] == ' ') {
        char *end;
        long  code = strtol(raw + i + 1, &end, 10);

        /* strtol reports "no digits" by leaving end at the start, and returns 0
         * for it -- indistinguishable from a literal "0" status unless the end
         * pointer is checked. The contract promises -1 for anything
         * unparseable, so a non-numeric token must not surface as a status a
         * rule could match on. */
        if (end != raw + i + 1 && code >= 0 && code <= INT_MAX) {
            return (int) code;
        }
    }

    return -1;
}


void
http_parse_response(http_response *resp)
{
    char   *sep;
    size_t  header_len;

    resp->status = -1;
    resp->body = NULL;
    resp->body_len = 0;
    resp->headers = NULL;

    if (resp->raw == NULL || resp->raw_len == 0) {
        return;
    }

    /*
     * A status line is "HTTP/<digit>+.<digit>+ <code> <reason>". A bare
     * "HTTP/" prefix check followed by "find the first space anywhere" would
     * accept "HTTP/xyz 200 OK" -- the garbage after the slash never gets
     * looked at, so it parses a real status out of a malformed version line.
     * That is a false PASS for any rule asserting status=200, the worst
     * failure mode for a harness: it reports success on input the server
     * (or an attacker) never sent as valid HTTP. So the version token is
     * walked byte by byte and the terminating space must be the one that
     * ends *that* token, not merely the first space in the buffer.
     *
     * Only HTTP/1.x is accepted. nginx and angie only ever put HTTP/1.0 or
     * HTTP/1.1 on the wire for the framing this prober reads (h2/h3 are
     * negotiated, not spelled out in a text status line), so a bare
     * "HTTP/2" with no minor version is exactly the kind of malformed input
     * this fix exists to reject, not a real case to special-case for.
     */
    resp->status = status_line_code(resp->raw, resp->raw_len);

    /*
     * Split on the header terminator. A response with no CRLFCRLF is left with
     * headers == NULL and no body rather than being guessed at -- silently
     * treating a truncated response as "all headers" would make a connection
     * reset look like a successful empty reply.
     */
    sep = memmem(resp->raw, resp->raw_len, "\r\n\r\n", 4);
    if (sep == NULL) {
        return;
    }

    header_len = (size_t) (sep - resp->raw);

    resp->headers = malloc(header_len + 1);
    if (resp->headers != NULL) {
        memcpy(resp->headers, resp->raw, header_len);
        resp->headers[header_len] = '\0';
    }

    resp->body = sep + 4;
    resp->body_len = resp->raw_len - header_len - 4;
}


/*
 * Case-insensitively test whether the header line starting at `line` (bounded by
 * `line_end`) begins with `name` -- a field name followed by a colon. Used by
 * the framed-mode classifier, which works on a raw byte range before
 * http_parse_response() has run, so it cannot lean on http_has_header().
 *
 * Whole-line-prefix rather than the substring match http_has_header() uses: the
 * classifier reads a LENGTH off the matched line, so it must anchor on the field
 * name at the start of the line and not on the same text appearing inside some
 * other header's value (an "X-Content-Length-Note:" header must not be mistaken
 * for the framing Content-Length).
 */
static int
header_line_is(const char *line, const char *line_end, const char *name)
{
    size_t  nlen = strlen(name);

    if ((size_t) (line_end - line) < nlen) {
        return 0;
    }

    return ascii_case_eq(line, name, nlen);
}


/*
 * Scan the header block [hdr, hdr_end) for framing headers.
 *
 * Writes, when found: *content_length / *have_cl (a Content-Length value), and
 * *chunked (Transfer-Encoding whose coding list contains "chunked"). Returns 0
 * on success, -1 on a malformed framing header that makes the response length
 * unknowable: a Content-Length that is non-numeric, overflows, or appears twice
 * with differing values -- each of which is a request-smuggling primitive if
 * guessed past rather than rejected.
 *
 * Transfer-Encoding is detected by substring, matching http_dechunk()'s reading
 * so the two agree on what "chunked" means; when it is present the caller
 * ignores Content-Length entirely, which is the RFC 9112 precedence.
 */
static int
scan_framing(const char *hdr, const char *hdr_end,
             size_t *content_length, int *have_cl, int *chunked)
{
    const char  *line = hdr;

    *have_cl = 0;
    *chunked = 0;
    *content_length = 0;

    while (line < hdr_end) {
        const char  *eol = memchr(line, '\n', (size_t) (hdr_end - line));
        const char  *line_end = (eol != NULL) ? eol : hdr_end;

        /* Trim a trailing CR so the value scan below does not treat it as data. */
        if (line_end > line && line_end[-1] == '\r') {
            line_end--;
        }

        if (header_line_is(line, line_end, "Content-Length:")) {
            const char  *v = line + strlen("Content-Length:");
            size_t       value = 0;
            int          digits = 0;

            while (v < line_end && (*v == ' ' || *v == '\t')) {
                v++;
            }

            while (v < line_end && *v >= '0' && *v <= '9') {
                size_t  d = (size_t) (*v - '0');

                /* Same growing-value overflow guard parse_chunk_size() uses: a
                 * Content-Length is attacker-controlled text and a wrap to a
                 * small value would let the loop stop short of the real body. */
                if (value > SIZE_MAX / 10 || value * 10 > SIZE_MAX - d) {
                    return -1;
                }

                value = value * 10 + d;
                digits++;
                v++;
            }

            /* Trailing whitespace is tolerated; anything else on the line (a
             * second value, a stray character) makes the length ambiguous. */
            while (v < line_end && (*v == ' ' || *v == '\t')) {
                v++;
            }

            if (digits == 0 || v != line_end) {
                return -1;
            }

            /* A repeated Content-Length is only benign when the values agree;
             * two different lengths are the classic smuggling desync. */
            if (*have_cl && value != *content_length) {
                return -1;
            }

            *content_length = value;
            *have_cl = 1;

        } else if (header_line_is(line, line_end, "Transfer-Encoding:")) {
            size_t  span = (size_t) (line_end - line);
            size_t  i;

            for (i = 0; i + 7 <= span; i++) {
                if (ascii_case_eq(line + i, "chunked", 7)) {
                    *chunked = 1;
                    break;
                }
            }
        }

        if (eol == NULL) {
            break;
        }
        line = eol + 1;
    }

    return 0;
}


/*
 * Does a response with this status code carry no body regardless of its framing
 * headers? RFC 9110 6.4.1: 1xx, 204 and 304 responses have no message body, so
 * a Content-Length or Transfer-Encoding on them describes a body that is not
 * there and the response ends at the header terminator.
 */
static int
status_is_bodiless(int status)
{
    return (status >= 100 && status < 200) || status == 204 || status == 304;
}


/*
 * Walk the chunked body at [body, end) to decide whether the terminating
 * 0-chunk (and its trailer section) has fully arrived. Returns HTTP_FRAMED_*.
 *
 * Deliberately re-parses framing rather than decoding: the read loop needs the
 * END OFFSET of the whole chunked stream, including the trailer lines and the
 * final blank line, which http_dechunk() (which stops at the 0-chunk and drops
 * trailers) does not compute. On COMPLETE, *consumed is the byte count from
 * `body` to the end of the terminating blank line.
 */
static int
chunked_complete(const char *body, const char *end, size_t *consumed)
{
    const char  *p = body;

    for ( ;; ) {
        size_t       size;
        const char  *next;
        int          rc;

        rc = parse_chunk_size(p, end, &size, &next);
        if (rc == HTTP_DECHUNK_BAD_SIZE) {
            /* A size line that is malformed is only MALFORMED once the whole
             * line is present. While the CRLF has not yet arrived the line is
             * merely unfinished -- reporting MALFORMED here would fail a valid
             * response whose size line was split across two reads. memchr for
             * the LF that would end the line tells the two apart. */
            if (memchr(p, '\n', (size_t) (end - p)) == NULL) {
                return HTTP_FRAMED_INCOMPLETE;
            }
            return HTTP_FRAMED_MALFORMED;
        }

        p = next;

        if (size == 0) {
            /* Terminating chunk seen. The stream ends at the blank line that
             * closes the (possibly empty) trailer section: scan for a CRLF that
             * is immediately followed by another CRLF, i.e. an empty line. */
            const char  *q = p;

            for ( ;; ) {
                const char  *nl = memchr(q, '\n', (size_t) (end - q));

                if (nl == NULL) {
                    return HTTP_FRAMED_INCOMPLETE;
                }

                /* An empty line is "\r\n" or a bare "\n": the LF with nothing
                 * (or only a CR) before it since the previous line start. */
                if (nl == q || (nl == q + 1 && q[0] == '\r')) {
                    *consumed = (size_t) (nl + 1 - body);
                    return HTTP_FRAMED_COMPLETE;
                }

                q = nl + 1;
            }
        }

        /* Need the chunk data plus its trailing CRLF before this chunk is done.
         * `size` is server-supplied and may reach SIZE_MAX: test the shortfall
         * as a subtraction against the bytes on hand so a maximal size cannot
         * wrap `size + 2` to a small value, slip past the short-read check, and
         * drive `p += size` off the end of the buffer. */
        if ((size_t) (end - p) < 2 || (size_t) (end - p) - 2 < size) {
            return HTTP_FRAMED_INCOMPLETE;
        }

        p += size;

        if (p[0] != '\r' || p[1] != '\n') {
            return HTTP_FRAMED_MALFORMED;
        }

        p += 2;
    }
}


int
http_framed_state(const char *buf, size_t len, size_t *resp_len)
{
    const char  *sep;
    const char  *hdr_end;
    const char  *body;
    size_t       content_length = 0;
    int          have_cl = 0, chunked = 0;
    int          status = -1;

    *resp_len = 0;

    if (buf == NULL || len == 0) {
        return HTTP_FRAMED_INCOMPLETE;
    }

    /* The header block must be complete before any framing can be read. */
    sep = memmem(buf, len, "\r\n\r\n", 4);
    if (sep == NULL) {
        return HTTP_FRAMED_INCOMPLETE;
    }

    hdr_end = sep;          /* end of the header field lines (before CRLFCRLF) */
    body = sep + 4;

    /* The same walk http_parse_response() uses -- literally the same function,
     * so the two cannot disagree about what a status line is. A malformed one
     * leaves status -1, which is not bodiless, so such a response is classified
     * by its length headers or judged unframeable, never silently treated as
     * empty. Bounded to the header block: a status line cannot span the
     * terminator, and letting the walk see the body would let body bytes decide
     * the framing of the response that carries them. */
    status = status_line_code(buf, (size_t) (hdr_end - buf));

    if (scan_framing(buf, hdr_end, &content_length, &have_cl, &chunked) != 0) {
        return HTTP_FRAMED_MALFORMED;
    }

    if (status_is_bodiless(status)) {
        *resp_len = (size_t) (body - buf);
        return HTTP_FRAMED_COMPLETE;
    }

    /* RFC 9112 6.3: Transfer-Encoding takes precedence over Content-Length. */
    if (chunked) {
        size_t  consumed;
        int     rc = chunked_complete(body, buf + len, &consumed);

        if (rc == HTTP_FRAMED_COMPLETE) {
            *resp_len = (size_t) (body - buf) + consumed;
        }
        return rc;
    }

    if (have_cl) {
        size_t  hdr_bytes = (size_t) (body - buf);
        size_t  need;

        /* content_length is server-supplied and may reach SIZE_MAX: adding it
         * to the header length could wrap `need` to a small value, making
         * `len < need` false and forging HTTP_FRAMED_COMPLETE with a truncated
         * resp_len -- exactly the smuggling primitive this classifier rejects
         * elsewhere. Guard the addition first: a length that cannot fit the
         * address space can never be fully present, so it is INCOMPLETE. */
        if (content_length > SIZE_MAX - hdr_bytes) {
            return HTTP_FRAMED_INCOMPLETE;
        }

        need = hdr_bytes + content_length;

        if (len < need) {
            return HTTP_FRAMED_INCOMPLETE;
        }

        *resp_len = need;
        return HTTP_FRAMED_COMPLETE;
    }

    return HTTP_FRAMED_UNFRAMEABLE;
}


/*
 * Sleep `ms`, resuming across signals rather than returning early: a pause cut
 * short by a stray signal would silently write the rest of the request sooner
 * than the rule file asked for, turning a timing test into a flaky one.
 *
 * RETURNS the milliseconds actually slept, which is `ms` on every path that
 * reaches the end of the loop. The return value exists so a caller accounting
 * for its own pacing can credit the sleep that HAPPENED rather than the one it
 * intended: a caller that increments a counter beside the call site is writing
 * down its intent, and that counter stays truthful even if this function is
 * later gutted to a no-op. Feeding the result back is what couples the two, so
 * removing the sleep necessarily removes the credit.
 */
static long
sleep_ms(long ms)
{
    struct timespec  ts;

    /* A non-positive duration is not a short sleep, it is no sleep. Returning
     * `ms` for it would credit a caller's pacing account for time that never
     * passed, and nanosleep() rejects a negative tv_nsec with EINVAL anyway. */
    if (ms <= 0) {
        return 0;
    }

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;

    while (nanosleep(&ts, &ts) != 0) {
        /* EINTR is the resumable case: ts now holds the remaining time, so go
         * again rather than returning early. A pause cut short by a stray
         * signal would silently write the rest of the request sooner than the
         * rule file asked for, turning a timing test into a flaky one. */
        if (errno != EINTR) {
            /* EINVAL or EFAULT: nothing was slept, and the whole point of this
             * return value is that it cannot report a sleep that did not
             * happen. Crediting `ms` here would rebuild the exact defect the
             * return exists to prevent, one layer down. */
            return 0;
        }
    }

    return ms;
}


/*
 * Write `len` bytes `chunk` at a time, sleeping `ms` between writes. The sleep
 * goes BETWEEN chunks only -- a trailing sleep after the final chunk would
 * delay the response rather than the request, which is a different test.
 *
 * `*slept_ms` is credited with sleep_ms()'s RETURN at every inter-chunk sleep,
 * not with `ms` itself -- see sleep_ms()'s comment. `slept_ms` may be NULL for
 * a caller that does not account send-side pacing.
 *
 * `chunk == 0` means NO CLAMP: the whole span goes out in one write, with no
 * inter-chunk sleep to perform. Two other places already read it that way --
 * rules.c's pause_cost_ms_raw() charges a chunk-0 entry as a plain stall, and
 * mutate.sh's byte-count mutant is commented "chunk 0 there means no clamp, so
 * the whole span goes out in one write". This function did not implement that
 * reading: it clamped `n` to 0, so `off` never advanced and the loop spun
 * forever. write_request() never passes 0 (it routes chunk-0 entries to the
 * plain-pause path) and rules.c rejects `send_slow` below 1, so no rule file
 * could reach it -- but the mutation that flips the unit/byte-count dispatch
 * did, and hung for the full 120 s suite timeout instead of failing an
 * assertion. A contract three places state and one implements is a defect in
 * the one.
 */
static int
write_paced(int fd, const unsigned char *buf, size_t len,
            size_t chunk, long ms, long long *slept_ms)
{
    size_t  off = 0;

    while (off < len) {
        size_t  n = len - off;

        if (chunk > 0 && n > chunk) {
            n = chunk;
        }

        if (write_all(fd, buf + off, n) != 0) {
            return -1;
        }

        off += n;

        if (off < len) {
            long  slept = sleep_ms(ms);

            if (slept_ms != NULL) {
                *slept_ms += slept;
            }
        }
    }

    return 0;
}


/*
 * Write `len` bytes one CHUNKED-FRAMING UNIT at a time, sleeping `ms` between
 * units. A unit is a complete `<hex>[;ext]\r\n<data>\r\n` -- size line, data,
 * and the data's trailing CRLF go out in ONE write, so the peer never sees a
 * partial chunk header. As in write_paced(), the sleep goes BETWEEN units only.
 *
 * Framing is located with parse_chunk_size(), the same strict parser the
 * response decoder uses, over the span the caller is pacing. Two consequences,
 * both deliberate:
 *
 *   * The terminating 0-chunk is a unit like any other; its trailing CRLF and
 *     any trailers after it are whatever remains, flushed as the final write.
 *   * Framing this parser rejects -- a bare-LF size line, a lying length, a
 *     truncated tail -- is NOT an error here. The remainder from the first
 *     unparseable byte is written in a single write_all() and the pacing simply
 *     stops. This harness exists to put malformed framing on the wire, so
 *     refusing to send it would remove the only interesting case; and the
 *     alternative -- guessing where the next unit starts -- means slicing at an
 *     offset the framing does not have, which is what the byte-count pacer
 *     already does. The bytes are always identical to an unpaced write; only
 *     the timing of the tail changes.
 *
 * `*slept_ms` is credited with sleep_ms()'s RETURN at every inter-unit sleep,
 * the send-side counterpart of write_paced() above. `slept_ms` may be NULL.
 */
static int
write_paced_units(int fd, const unsigned char *buf, size_t len, long ms,
                  long long *slept_ms)
{
    size_t  off = 0;

    while (off < len) {
        const char  *start = (const char *) buf + off;
        const char  *end = (const char *) buf + len;
        const char  *data;
        size_t       size, unit, avail;

        if (parse_chunk_size(start, end, &size, &data) != HTTP_DECHUNK_OK) {
            break;
        }

        /* size line + data + the data's CRLF. Bounded against the span rather
         * than trusted: a size line may declare more data than was actually
         * written, and this walk must not read past the request buffer to
         * honour it. Written as a subtraction on the REMAINING length so a
         * declared size near SIZE_MAX cannot wrap the comparison -- the same
         * reason parse_chunk_size() checks its accumulator before each shift. */
        avail = (size_t) (end - data);

        if (size > avail || avail - size < 2) {
            break;
        }

        unit = (size_t) (data - start) + size;

        if (start[unit] != '\r' || start[unit + 1] != '\n') {
            break;
        }

        unit += 2;

        if (write_all(fd, buf + off, unit) != 0) {
            return -1;
        }

        off += unit;

        if (off < len) {
            long  slept = sleep_ms(ms);

            if (slept_ms != NULL) {
                *slept_ms += slept;
            }
        }
    }

    if (off < len) {
        return write_all(fd, buf + off, len - off);
    }

    return 0;
}


/*
 * Write the request, stalling at each pause offset. With no pauses this is a
 * single write_all() of the whole buffer -- byte-identical to what this
 * function did before pauses existed.
 *
 * `*slept_ms`, if non-NULL, is credited with sleep_ms()'s RETURN at every
 * sleep this function or its two pacing helpers perform -- the leading stall
 * before a paced span, the plain-pause sleep, and every inter-chunk/inter-unit
 * sleep inside write_paced()/write_paced_units(). Never the `ms`/`pauses[i].ms`
 * value beside the call: see sleep_ms()'s comment for why that distinction is
 * the whole point.
 */
static int
write_request(int fd, const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses, long long *slept_ms)
{
    size_t  off = 0, i;

    for (i = 0; i < n_pauses; i++) {
        size_t  upto = pauses[i].offset;

        if (upto > req_len) {
            upto = req_len;
        }

        if (upto > off) {
            if (write_all(fd, req + off, upto - off) != 0) {
                return -1;
            }
            off = upto;
        }

        if (pauses[i].unit || pauses[i].chunk > 0) {
            /* Paced entry: dribble from here to the next entry's offset (or
             * the end), rather than stalling once. The leading sleep keeps a
             * paced entry's `ms` meaning the same "hold off, then act" as a
             * plain pause, so the two read alike in a rule file. */
            size_t  upto_next = req_len;
            int     rc;
            long    slept;

            if (i + 1 < n_pauses && pauses[i + 1].offset < upto_next) {
                upto_next = pauses[i + 1].offset;
            }

            if (upto_next < off) {
                upto_next = off;
            }

            slept = sleep_ms(pauses[i].ms);

            if (slept_ms != NULL) {
                *slept_ms += slept;
            }

            /* `unit` first, so an entry carrying both paces by framing rather
             * than silently by byte count -- the same precedence http.h
             * documents, kept in one place. rules.c rejects the combination, so
             * this only decides what http_test.c and any future caller get. */
            if (pauses[i].unit) {
                rc = write_paced_units(fd, req + off, upto_next - off,
                                       pauses[i].ms, slept_ms);
            } else {
                rc = write_paced(fd, req + off, upto_next - off,
                                 pauses[i].chunk, pauses[i].ms, slept_ms);
            }

            if (rc != 0) {
                return -1;
            }

            off = upto_next;
            continue;
        }

        {
            long  slept = sleep_ms(pauses[i].ms);

            if (slept_ms != NULL) {
                *slept_ms += slept;
            }
        }
    }

    if (off < req_len) {
        return write_all(fd, req + off, req_len - off);
    }

    return 0;
}


/*
 * Milliseconds on a monotonic clock.
 *
 * CLOCK_MONOTONIC rather than any wall clock: a close deadline is a duration,
 * and a wall clock can step (NTP, an operator, libfaketime -- which the
 * clock-jump scenario LD_PRELOADs on purpose) and make a correct server look
 * like it answered before it was asked, or a decade late.
 */
static long long
now_ms(void)
{
    struct timespec  ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    /*
     * long long, and the multiply is done in it.
     *
     * `long` is 32 bits under -m32 (a CI leg here, and a real consumer
     * platform), where tv_sec * 1000 overflows once the machine has been up
     * about 24 days -- CLOCK_MONOTONIC counts from boot, so this is not a
     * far-future problem but an ordinary uptime. The result would go negative
     * mid-run and every close deadline would misjudge: a prompt close reported
     * as impossibly late, or a late one as instant, on a box whose only sin was
     * staying up a month. The cast is on tv_sec so the multiply itself is
     * 64-bit; casting the product would preserve the overflow.
     */
    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}


/*
 * Milliseconds elapsed since `start`, narrowed to the `long` the response
 * carries.
 *
 * The narrowing is safe and the cast is deliberate rather than a way to quiet
 * -Wconversion: the absolute timestamps must be 64-bit (see now_ms()), but
 * their DIFFERENCE is bounded by the read timeout -- single-digit seconds --
 * and fits a 32-bit long with room to spare. Done in one place so the reasoning
 * lives once instead of at each of the three call sites, where a bare cast
 * would look like someone silencing the warning wall.
 */
static long
elapsed_since(long long start)
{
    return (long) (now_ms() - start);
}


int
http_connect(const char *host, int port, int timeout_ms,
             const char *source, const http_recv *recv_opt,
             char *errbuf, size_t errlen)
{
    int                 fd, one = 1;
    struct sockaddr_in  sin;
    struct timeval      tv;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port);

    if (inet_pton(AF_INET, host, &sin.sin_addr) != 1) {
        snprintf(errbuf, errlen, "bad host address \"%s\"", host);
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(errbuf, errlen, "socket: %s", strerror(errno));
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Nagle would coalesce the deliberately-split writes some rules depend on
     * to exercise request smuggling and partial-header handling. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    /*
     * Set BEFORE connect(): the receive window is advertised during the
     * handshake, so a SO_RCVBUF applied afterwards may not shrink the window
     * the peer has already been told about. Getting this order wrong would
     * leave a recv_slow case looking correct while the server never actually
     * felt the backpressure -- the failure mode is a passing test, not an
     * error, which is why it is set here rather than beside the read loop it
     * belongs to.
     */
    if (recv_opt != NULL && recv_opt->rcvbuf > 0) {
        int  rcvbuf = recv_opt->rcvbuf;

        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0)
        {
            snprintf(errbuf, errlen, "SO_RCVBUF: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (source != NULL) {
        struct sockaddr_in  local;

        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = 0;

        if (inet_pton(AF_INET, source, &local.sin_addr) != 1) {
            snprintf(errbuf, errlen, "bad source address \"%s\"", source);
            close(fd);
            return -1;
        }

        /* SO_REUSEADDR so a rule can reuse a source address while an earlier
         * connection from it is still in TIME_WAIT. */
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(fd, (struct sockaddr *) &local, sizeof(local)) != 0) {
            snprintf(errbuf, errlen, "bind %s: %s", source, strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        snprintf(errbuf, errlen, "connect %s:%d: %s",
                 host, port, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}


void
http_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}


/*
 * One write+read cycle on an already-open fd. NEVER closes fd -- the caller
 * owns teardown via http_close(). Extracted verbatim from http_request()'s
 * post-connect body; the only change is that the trailing close() and every
 * early-return close() moved out to the wrapper, and each path that ends the
 * connection now reports it through *conn_open instead of closing here.
 */
int
http_exchange(int fd,
              const unsigned char *req, size_t req_len,
              int timeout_ms,
              const http_pause *pauses, size_t n_pauses,
              int shut_how, size_t abort_at, long hold_ms,
              const http_recv *recv_opt, int want_close,
              long idle_ms, int framed,
              http_response *resp, int *conn_open,
              char *errbuf, size_t errlen)
{
    long long           sent_at;

    memset(resp, 0, sizeof(*resp));
    resp->status = -1;

    /*
     * Witness the effective receive buffer of the connection http_connect()
     * just configured. Read here, on the live fd before any exchange work, so
     * every caller records it with no signature change. This is the
     * deterministic replacement for inferring "was SO_RCVBUF applied?" from the
     * read count: getsockopt reports the kernel's clamped value directly, so a
     * shrunk socket always reads strictly smaller than an untouched one
     * regardless of load. A failure leaves the field 0 (its memset value).
     */
    {
        int        eff = 0;
        socklen_t  efflen = sizeof(eff);

        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &eff, &efflen) == 0) {
            resp->effective_rcvbuf = eff;
        }
    }

    /* Presume the exchange ends the connection; the read-loop's framed-stop
     * path (the only one that leaves the socket reusable) opts back in. Every
     * error return leaves it 0, so a driver never reuses a broken fd. */
    if (conn_open != NULL) {
        *conn_open = 0;
    }

    /*
     * An aborting case writes only the prefix it means to send. Truncating
     * req_len here rather than adding a mode to write_request() keeps the
     * pacing logic untouched: the pauses that fall inside the prefix still
     * apply, so `send_slow` followed by `abort` dribbles and then resets, which
     * is the shape a real slowloris client presents when it gives up.
     */
    if (write_request(fd, req,
                      abort_at < req_len ? abort_at : req_len,
                      pauses, n_pauses, &resp->send_paced_ms) != 0)
    {
        snprintf(errbuf, errlen, "write: %s", strerror(errno));
        return -1;
    }

    /*
     * The clock starts with the request fully on the wire, not at connect():
     * what a close deadline or an idle wait asks about is how long the SERVER
     * took to act on a complete request. Starting earlier would bill the connect
     * handshake and any deliberate `pause`/`send_slow` pacing to the server, so
     * a rule that dribbles its request for 200 ms would fail a 100 ms deadline
     * no matter how promptly the server answered.
     *
     * Taken here, at the single point where the write has finished, so the idle
     * wait and the read loop below measure from the same instant rather than
     * each starting its own clock.
     */
    sent_at = now_ms();

    /*
     * SO_LINGER{on, 0} turns the close below into a reset instead of a FIN.
     * The socket is discarded with whatever is still queued, so the server's
     * next read fails with ECONNRESET rather than reporting a clean EOF.
     *
     * There is deliberately no read loop after this: the peer has been told the
     * connection no longer exists, so waiting for a response would only spend
     * timeout_ms proving that nothing arrives. The case is judged from the
     * server's own log and counters, and returning success with an empty
     * response is what lets those assertions run at all.
     *
     * setsockopt's return is checked because a failure here would silently
     * downgrade the reset to an ordinary close -- the connection would end with
     * a FIN, the server would see a well-behaved client, and the case would
     * report a pass for the opposite of the behaviour it asked to test.
     */
    if (abort_at != HTTP_ABORT_NONE) {
        struct linger  lg;

        lg.l_onoff = 1;
        lg.l_linger = 0;

        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) != 0) {
            snprintf(errbuf, errlen, "SO_LINGER: %s", strerror(errno));
            return -1;
        }

        /* The abort's reset happens when http_close() discards this fd with
         * SO_LINGER{on,0} armed; the connection is over either way, so
         * conn_open stays 0 (set at entry). */
        resp->raw = malloc(1);
        if (resp->raw == NULL) {
            snprintf(errbuf, errlen, "out of memory");
            return -1;
        }

        resp->raw[0] = '\0';
        resp->raw_len = 0;

        return 0;
    }

    /*
     * Request fully written, and now nothing happens on purpose: no read, no
     * shutdown, the connection simply idles for hold_ms and then closes with an
     * ordinary FIN.
     *
     * The read loop is skipped rather than merely delayed. Draining the socket
     * afterwards would defeat the directive -- the point is that the response is
     * written to a peer that never collects it, so the bytes must be left in the
     * kernel's buffers when close() discards them.
     *
     * No SO_LINGER here, which is the whole distinction from `abort`: the
     * connection ends the way a normal client ends one. The server sees a
     * well-behaved peer that asked a question and left without waiting for the
     * answer, not a peer that vanished.
     */
    if (hold_ms != HTTP_HOLD_NONE) {
        sleep_ms(hold_ms);
        /* Ordinary FIN when http_close() discards the fd (no SO_LINGER, unlike
         * abort); the connection is done, conn_open stays 0. */
        resp->raw = malloc(1);
        if (resp->raw == NULL) {
            snprintf(errbuf, errlen, "out of memory");
            return -1;
        }

        resp->raw[0] = '\0';
        resp->raw_len = 0;

        return 0;
    }

    /*
     * The idle wait: park on the connection for idle_ms and report what the
     * peer did, without ever reading. Like the read loop below, the clock starts
     * with the request fully on the wire so a case's own `pause`/`send_slow`
     * pacing is not billed against the wait.
     *
     * poll() rather than read() is the whole directive. A read would collect the
     * response -- destroying the evidence that nothing arrived -- and would
     * consume the readiness the assertion is about. Polling leaves the socket
     * exactly as an idle client leaves it, so what the server saw is what a real
     * parked connection looks like.
     *
     * POLLIN covers both failure modes and they are told apart afterwards: a
     * peer that sent bytes and a peer that sent FIN both make the socket
     * readable. One MSG_PEEK distinguishes them without consuming anything --
     * 0 means FIN, >0 means real data. POLLERR/POLLHUP arrive on a reset.
     *
     * EINTR resumes on the REMAINING time rather than restarting the wait, so a
     * signal cannot silently extend it past what the rule asked for.
     */
    if (idle_ms != HTTP_IDLE_NONE) {
        struct pollfd  pfd;
        long long      wait_start = now_ms();
        long           left = idle_ms;

        resp->raw = malloc(1);
        if (resp->raw == NULL) {
            snprintf(errbuf, errlen, "out of memory");
            return -1;
        }

        resp->raw[0] = '\0';
        resp->raw_len = 0;
        resp->close_reason = HTTP_CLOSE_IDLE;

        for ( ;; ) {
            int  n;

            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;

            n = poll(&pfd, 1, (int) left);

            if (n < 0) {
                if (errno == EINTR) {
                    long  spent = (long) (now_ms() - wait_start);

                    left = idle_ms - spent;

                    if (left > 0) {
                        continue;
                    }

                    /* The signal landed at the very end of the wait; the peer
                     * stayed silent for the whole of it, which is the pass. */
                    break;
                }

                snprintf(errbuf, errlen, "poll: %s", strerror(errno));
                return -1;
            }

            if (n == 0) {
                /* Timed out with nothing to report: silent and still open. */
                break;
            }

            if (pfd.revents & (POLLERR | POLLHUP)) {
                resp->close_reason = HTTP_CLOSE_RESET;
                break;
            }

            if (pfd.revents & POLLIN) {
                char     peek;
                ssize_t  got = recv(fd, &peek, 1, MSG_PEEK);

                if (got == 0) {
                    resp->close_reason = HTTP_CLOSE_FIN;
                    break;
                }

                if (got < 0) {
                    if (errno == EINTR) {
                        continue;
                    }

                    resp->close_reason = (errno == ECONNRESET)
                                             ? HTTP_CLOSE_RESET
                                             : HTTP_CLOSE_DATA;
                    break;
                }

                resp->close_reason = HTTP_CLOSE_DATA;
                break;
            }

            /* Readiness this wait does not judge (POLLNVAL cannot happen on a
             * live fd we own). Charge the elapsed time and keep waiting rather
             * than spinning on an unmasked event. */
            left = idle_ms - (long) (now_ms() - wait_start);

            if (left <= 0) {
                break;
            }
        }

        resp->close_ms = elapsed_since(sent_at);

        /* idle never reads for reuse; the connection is handed back closed-in-
         * intent (conn_open stays 0), http_close() ends it. */
        return 0;
    }

    /*
     * The return value is deliberately ignored. shutdown() fails with ENOTCONN
     * when the peer has already torn the connection down -- which is a normal
     * outcome for the malformed-input cases this directive exists to serve, not
     * a harness fault. Whatever the server did is judged from the response and
     * the log, so failing the case here would report a harness error for the
     * very behaviour under test.
     */
    if (shut_how != HTTP_SHUT_NONE) {
        (void) shutdown(fd, shut_how);
    }

    return http_read_response(fd, timeout_ms, recv_opt, want_close, framed,
                              sent_at, resp, conn_open, errbuf, errlen);
}


/*
 * Initialize one leg's read state. Separated from the step function because a
 * fan must be able to arm every leg BEFORE polling any of them: a leg whose
 * buffer was not yet allocated cannot be in the pollfd set, and allocating
 * lazily on first readiness would make the failure path depend on arrival
 * order.
 *
 * Returns 0, or -1 with errbuf set when the initial allocation fails. On -1 the
 * state is left safe to pass to http_read_state_free() (buf is NULL).
 */
static int
http_read_state_init(http_read_state *st, int fd, int timeout_ms,
                     const http_recv *recv_opt, int want_close, int framed,
                     long long sent_at, http_response *resp, int *conn_open,
                     char *errbuf, size_t errlen)
{
    memset(st, 0, sizeof(*st));

    st->fd = fd;
    st->timeout_ms = timeout_ms;
    st->recv_opt = recv_opt;
    st->want_close = want_close;
    st->framed = framed;
    st->sent_at = sent_at;
    st->resp = resp;
    st->conn_open = conn_open;
    st->cap = 8192;

    /* Armed here rather than on first step: the wait for the FIRST byte is
     * exactly as much a per-read idle wait as the wait for any later one, and
     * it is the one a silent peer exercises. */
    st->idle_deadline = now_ms() + timeout_ms;

    st->buf = malloc(st->cap);
    if (st->buf == NULL) {
        snprintf(errbuf, errlen, "out of memory");
        st->done = 1;
        st->rc = -1;
        return -1;
    }

    return 0;
}


/*
 * Release a leg's buffer if it is still owned by the state.
 *
 * This is the enforcement point for the OWNERSHIP INVARIANT stated on the
 * http_read_state struct above:
 * a terminal leg has already either freed `buf` or transferred it to
 * resp->raw, and both paths NULL it here, so calling this on any leg -- live,
 * terminal, or never started -- is safe and idempotent. That is what lets the
 * fan free every leg unconditionally when it abandons a drain, without
 * tracking which legs had reached a terminal state.
 */
static void
http_read_state_free(http_read_state *st)
{
    free(st->buf);
    st->buf = NULL;
}


/*
 * Whether this leg wants to be in the pollfd set right now.
 *
 * A leg gated by recv pacing is deliberately NOT polled: its `not_before` is in
 * the future and readiness is irrelevant until then. This is what keeps pacing
 * from blocking the other legs -- see the not_before/gate_start field comments
 * on http_read_state above, and the credit rule in http_read_state_step().
 */
static int
http_read_state_pollable(const http_read_state *st, long long now)
{
    return !st->done && now >= st->not_before;
}


/*
 * How long, in ms, until this leg next needs attention: its pacing gate opens,
 * its per-read idle deadline expires, or its whole-exchange deadline expires.
 * The drain loop takes the minimum across live legs as its poll() timeout, so
 * no leg oversleeps its own deadline because another leg had nothing to say.
 *
 * The idle deadline is in this minimum, not merely checked after poll() returns:
 * a silent peer produces no readiness event, so a wakeup that ignored it would
 * sleep until the 8x whole-exchange budget and the idle bound would never fire.
 * That omission IS the F1 regression this restores.
 *
 * A gate that is open (`not_before` in the past) is excluded, and so is an idle
 * deadline while a gate is closed: a leg deliberately withheld by pacing is not
 * idle, and charging the client's own sip interval to the server's silence
 * budget would fail a paced case that the server was answering promptly.
 *
 * Never negative: a leg already past any boundary wants an immediate wakeup.
 */
static long
http_read_state_next_wakeup(const http_read_state *st, long long now)
{
    long long  deadline_at, wake;

    deadline_at = st->sent_at + st->paced_sleep_ms
                  + HTTP_MAX_EXCHANGE_MS(st->timeout_ms);

    wake = deadline_at;
    if (st->not_before > now) {
        if (st->not_before < wake) {
            wake = st->not_before;
        }

    } else if (st->idle_deadline > 0 && st->idle_deadline < wake) {
        wake = st->idle_deadline;
    }

    if (wake <= now) {
        return 0;
    }

    return (long) (wake - now);
}


/*
 * Narrow a millisecond wait to poll()'s int timeout without letting it go
 * negative, which poll() reads as "wait forever".
 *
 * `-t` accepts any positive int and HTTP_MAX_EXCHANGE_MS multiplies it by 8, so
 * a large-but-accepted timeout (up to INT_MAX) produces a long above INT_MAX
 * here. The implicit conversion is implementation-defined and in practice comes
 * out negative, turning a bounded wait into an indefinite hang -- the harness
 * silently stops instead of reporting a timeout.
 *
 * Clamping rather than rejecting keeps the arithmetic total: every caller loops
 * on absolute deadlines and recomputes the remaining wait each iteration, so a
 * clamped wait costs at most one extra poll() round-trip and the deadline it
 * was derived from still decides when the leg gives up.
 */
int
http_poll_timeout_ms(long wait)
{
    if (wait < 0) {
        return 0;
    }

    if (wait > INT_MAX) {
        return INT_MAX;
    }

    return (int) wait;
}


/*
 * Drive one leg by one step, having been told whether its fd is readable.
 *
 * This is the former read loop's body. Every exit that used to `break` now
 * marks the leg done and falls into the same finalize path; every exit that
 * used to `return -1` marks it done with rc -1 after freeing the buffer. The
 * semantics of each individual exit are unchanged -- that is the property the
 * mutation corpus checks.
 *
 * `readable` is 0 when the caller is stepping the leg for a reason other than
 * data (a deadline sweep, or a pacing gate that just opened). Such a step
 * performs the deadline check and the pacing gate and then returns without
 * reading, so a leg is never blocked in read() waiting for a peer that is
 * silent.
 *
 * Returns 1 while the leg wants more steps, 0 once it is terminal.
 */
static int
http_read_state_step(http_read_state *st, int readable,
                     char *errbuf, size_t errlen)
{
    ssize_t     n;
    size_t      want;
    long long   now = now_ms();
    char       *buf = st->buf;
    size_t      len = st->len;

    /*
     * Close out a pacing gate that has opened and credit it.
     *
     * WHAT IS CREDITED, and this is the load-bearing decision of the S-4
     * rewrite. The credit is the width of the gate that was actually enforced
     * (`not_before - gate_start`), taken HERE on the far side of it -- never
     * `recv_opt->ms` at gate-set time, which would record what this code
     * intended and would survive the gate being gutted. Reaching this line is
     * itself the evidence: it is reachable only once `now >= not_before`, so a
     * gate that never held cannot pay out.
     *
     * NOT the raw elapsed wall time (`now - gate_start`). That was the first
     * cut and it is subtly wrong: poll() returns late under load, so the credit
     * picked up scheduling jitter and drifted a millisecond or two above the
     * gate width -- measured at 120-121 ms for four 30 ms gates. That turns a
     * counter the machine fully controls into a second wall clock, and the
     * whole point of this counter (see http.h) is to be the ONE pacing witness
     * that is not a wall clock. The assertion built on it is an exact equality
     * precisely because the quantity is supposed to be exact; crediting jitter
     * would have forced that equality to be widened into a tolerance, and a
     * tolerance is a defect of that size chosen not to be detected.
     *
     * The deadline is discounted by this same figure, so under-crediting the
     * jitter is also the conservative direction there: a paced leg is charged
     * for the few ms of lateness rather than being handed extra budget.
     */
    if (st->not_before != 0 && now >= st->not_before) {
        st->paced_sleep_ms += st->not_before - st->gate_start;
        st->resp->paced_sleep_ms = st->paced_sleep_ms;

        st->not_before = 0;
        st->gate_start = 0;

        /* Restart the idle clock on the far side of the gate. The interval the
         * client deliberately withheld is not the server being silent, so
         * charging it to the idle budget would fail a paced case whose gate is
         * merely wider than timeout_ms -- the client's own sip interval killing
         * the exchange it was configured for. Same reasoning as discounting the
         * gate from the whole-exchange deadline, one clock down. */
        st->idle_deadline = now + st->timeout_ms;
    }

    {
        /*
         * AUD-07: the whole-exchange deadline, checked before every read. The
         * per-read SO_RCVTIMEO does not bound a peer that trickles one byte per
         * window, so without this the loop could run and allocate forever. A
         * want_close caller treats the deadline as its answer (the server held
         * the connection open too long); otherwise it is a harness failure of
         * this case, not a silent pass.
         */
        if (elapsed_since(st->sent_at) - st->paced_sleep_ms
                > HTTP_MAX_EXCHANGE_MS(st->timeout_ms)) {
            if (st->want_close) {
                st->resp->close_reason = HTTP_CLOSE_TIMEOUT;
                st->resp->close_ms = elapsed_since(st->sent_at);
                goto finish;
            }

            snprintf(errbuf, errlen,
                     "response did not complete within %ld ms whole-exchange "
                     "budget (%zu bytes so far); a server trickling bytes under "
                     "the per-read timeout never trips it",
                     HTTP_MAX_EXCHANGE_MS(st->timeout_ms), len);
            goto fail;
        }

        /*
         * AUD-07: the response-size ceiling. A runaway or endless body would
         * otherwise double the buffer until malloc fails and kills the run.
         * A response of EXACTLY the ceiling is allowed -- the read below that
         * would take len past it is what fails -- so this triggers only once a
         * byte over the limit has been collected.
         */
        if (len > HTTP_MAX_RESPONSE) {
            snprintf(errbuf, errlen,
                     "response exceeded the %d-byte ceiling; a server emitting "
                     "an unbounded body is a failure, not a payload",
                     HTTP_MAX_RESPONSE);
            goto fail;
        }

        if (len + 4096 > st->cap) {
            char *bigger;

            /* Never grow past the ceiling (plus one chunk of headroom so the
             * len > ceiling check above still gets to fire on the collected
             * bytes rather than the allocation aborting first). */
            st->cap *= 2;
            if (st->cap > HTTP_MAX_RESPONSE + 4096) {
                st->cap = HTTP_MAX_RESPONSE + 4096;
            }
            bigger = realloc(buf, st->cap);
            if (bigger == NULL) {
                snprintf(errbuf, errlen, "out of memory");
                goto fail;
            }
            buf = bigger;
            st->buf = bigger;
        }

        want = st->cap - len - 1;

        /*
         * Pacing caps how much is taken per read and sleeps between reads, so
         * the socket buffer is drained in deliberate sips rather than emptied
         * as fast as the kernel can hand it over.
         *
         * The sleep is conditional on the PREVIOUS read having filled its
         * chunk. A short read means the buffer is already drained, so the next
         * read is the one that collects the EOF -- stalling before it paces
         * nothing and merely delays this process's own teardown, long after the
         * server stopped caring. Sleeping unconditionally would also make a
         * response smaller than one chunk cost a full stall, which is the
         * read-side mirror of the trailing-sleep bug write_paced() avoids.
         */
        if (st->recv_opt != NULL && st->recv_opt->chunk > 0) {
            if (want > st->recv_opt->chunk) {
                want = st->recv_opt->chunk;
            }

            if (st->paced_full) {
                /* AUD-07: this pacing is the harness's OWN deliberate delay, not
                 * the server being slow, so it must not count against the
                 * whole-exchange deadline -- otherwise a legitimately paced
                 * recv_slow case that needs many chunks would trip the trickle
                 * guard despite the server making continuous progress.
                 *
                 * S-4: this used to be an inline sleep_ms(). Under a shared
                 * poll() drain a sleep here would block EVERY leg, reintroducing
                 * exactly the serialization the fan exists to remove -- so the
                 * delay became a per-leg GATE. The leg sets not_before, drops out
                 * of the pollfd set, and is stepped again once the gate opens.
                 *
                 * The witness S-5 built survives the change, but only because the
                 * credit is taken on the FAR side of the gate: gate_start is
                 * stamped when the gate is set and the credit is the interval
                 * actually withheld, measured, when the leg resumes. Crediting
                 * recv_opt->ms here at gate-set time would record what this code
                 * meant to do -- the intent-not-witness defect S-5 fixed, rebuilt
                 * in a new place. If the gate is later gutted, no time passes and
                 * the counter reports none. */
                /* A non-positive delay is not a short pause, it is no pause --
                 * the same guard sleep_ms() carries, and for the same reason:
                 * without it `not_before` lands in the past, the gate opens
                 * immediately, and the credit above goes NEGATIVE, reporting
                 * pacing that ran backwards. rules.c clamps to 1..MAX_PAUSE_MS
                 * so a rule file cannot reach this, but http_exchange() is a
                 * public entry point and the parser is not the only way in.
                 * Assertion 108 drives it directly from C. */
                if (st->recv_opt->ms > 0) {
                    /* Every gate must be paid for by a read. `paced_full` is
                     * set only by a read that filled its chunk and cleared
                     * here, so in correct code the reads counter has advanced
                     * between any two gates on this leg. If it has not, the
                     * gate is re-arming without collecting anything, and that
                     * state is unrecoverable rather than slow: the gate width
                     * is discounted from BOTH deadlines above (whole-exchange
                     * via paced_sleep_ms, idle via the restamp on the far
                     * side), so a leg that only ever gates advances no clock
                     * that could ever cut it off. Left unguarded it is an
                     * unbounded loop that the harness can only end by being
                     * killed from outside -- a 120 s timeout with no assertion
                     * behind it, indistinguishable from a hang anywhere else.
                     * Fail here instead, naming the invariant. */
                    if (st->resp->reads == st->gate_reads) {
                        snprintf(errbuf, errlen,
                                 "recv pacing gate re-armed after %zu reads "
                                 "without collecting any bytes; a gate that "
                                 "never reads discounts both deadlines and "
                                 "never completes",
                                 st->gate_reads);
                        goto fail;
                    }

                    st->gate_reads = st->resp->reads;
                    st->gate_start = now;
                    st->not_before = now + st->recv_opt->ms;
                    st->paced_full = 0;
                    return 1;
                }

                st->paced_full = 0;
            }
        }

        if (!readable) {
            /*
             * Stepped for a deadline sweep or a newly-opened pacing gate, with
             * nothing known to be waiting on the socket. The checks above have
             * run; reading now would block this leg -- and under a shared drain,
             * every other leg with it.
             *
             * The per-read idle deadline is enforced HERE, on the not-readable
             * path, because that is the state it describes: the peer has said
             * nothing since the last read. Its expiry is deliberately routed
             * into the SAME verdict the blocking reader's SO_RCVTIMEO produced
             * -- HTTP_CLOSE_TIMEOUT under want_close, otherwise the read-timed-
             * out failure naming timeout_ms -- so the observable contract is the
             * pre-S-4 one rather than a new third outcome. The text is shared
             * with the EAGAIN branch below for the same reason.
             *
             * A leg still inside a pacing gate never reaches this: the gate
             * above returns first while it is closed, and the wakeup function
             * excludes the idle deadline for exactly that window.
             */
            if (st->idle_deadline > 0 && now >= st->idle_deadline) {
                if (st->want_close) {
                    st->resp->close_reason = HTTP_CLOSE_TIMEOUT;
                    st->resp->close_ms = elapsed_since(st->sent_at);
                    goto finish;
                }

                snprintf(errbuf, errlen,
                         "read timed out after %d ms (%zu bytes so far); "
                         "does the request ask for Connection: close?",
                         st->timeout_ms, len);
                goto fail;
            }

            return 1;
        }

        n = read(st->fd, buf + len, want);

        if (n < 0) {
            if (errno == EINTR) {
                return 1;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /*
                 * A caller asking about the close treats this as the answer,
                 * not as a failure: the server held the connection open past
                 * the deadline, which is a fact about the server. Keep the
                 * bytes that did arrive and let the assertion layer judge --
                 * see want_close in http.h for why this cannot be an error.
                 *
                 * S-4: this branch is now RARELY reached and is kept as a
                 * backstop, not as the mechanism. The drain waits for readiness
                 * in poll() before stepping a leg, so a read that would have
                 * blocked until SO_RCVTIMEO expired generally does not happen;
                 * the whole-exchange deadline above is what produces the
                 * want_close timeout verdict now (proven by mutation -- it reds
                 * assertions 120-122, while mutating THIS branch survives
                 * because nothing reaches it).
                 *
                 * Kept because the sockets are still blocking and SO_RCVTIMEO
                 * is still set: a read that begins after poll() reported
                 * readiness can still time out if the peer sends a partial
                 * segment and stalls. Deleting it would turn that case into the
                 * generic read-error path below, which reports HTTP_CLOSE_NONE
                 * and would blame the server for a close it never made.
                 */
                if (st->want_close) {
                    st->resp->close_reason = HTTP_CLOSE_TIMEOUT;
                    st->resp->close_ms = elapsed_since(st->sent_at);
                    goto finish;
                }

                snprintf(errbuf, errlen,
                         "read timed out after %d ms (%zu bytes so far); "
                         "does the request ask for Connection: close?",
                         st->timeout_ms, len);
                goto fail;
            }

            /* A reset after a complete response is a legitimate outcome for
             * malformed-input cases; keep what we have and let the rule judge.
             *
             * Only ECONNRESET is labelled a reset. This branch catches every
             * read error that is not EINTR or the EAGAIN timeout above, so
             * labelling it all RESET would report "server reset the
             * connection" for an EBADF or ENOTCONN -- and that text is what a
             * rule author acts on when a close deadline fails. Anything else
             * ended the connection without saying how, which is what
             * HTTP_CLOSE_NONE means; the deadline then reports that it could
             * not be judged rather than blaming the server for a reset it
             * never sent. */
            st->resp->close_reason = (errno == ECONNRESET) ? HTTP_CLOSE_RESET
                                                           : HTTP_CLOSE_NONE;
            st->resp->close_ms = elapsed_since(st->sent_at);
            goto finish;
        }

        if (n == 0) {
            st->resp->close_reason = HTTP_CLOSE_FIN;
            st->resp->close_ms = elapsed_since(st->sent_at);
            goto finish;
        }

        /* Whether this read filled its chunk decides if the NEXT one is paced;
         * see the gate above. */
        st->paced_full = (st->recv_opt != NULL && st->recv_opt->chunk > 0
                          && (size_t) n == want);

        /* The peer spoke, so the idle clock restarts. This is what makes the
         * deadline per-READ: a server making steady progress renews it on every
         * read and is never cut off by it, while the whole-exchange budget above
         * remains the bound on a peer that trickles a byte per window forever.
         * Stamped from a fresh now_ms() rather than the `now` at the top of this
         * step, so the read's own duration is not charged to the next wait. */
        st->idle_deadline = now_ms() + st->timeout_ms;

        st->resp->reads++;
        len += (size_t) n;
        st->len = len;

        /*
         * Framed mode: stop at the framed end of ONE response rather than at
         * EOF. Checked after every read that added bytes, because a keep-alive
         * server never closes and so the loop above would otherwise run until
         * the whole-exchange deadline. The classifier reads the same
         * Content-Length / chunked / bodiless-status framing http_dechunk() and
         * http_parse_response() do, and reports one of four states.
         *
         * COMPLETE truncates `len` to exactly the first response: a pipelined
         * second response already in the buffer must not be folded into this
         * one's body, and dropping the surplus here keeps http_parse_response()
         * below operating on a single well-framed message. This is the ONE exit
         * that leaves the connection reusable -- the read stopped at a framed
         * boundary, not on a close -- so it is the only path that reports
         * conn_open. A single-exchange caller (http_request) still closes the
         * fd, discarding any pipelined surplus; a pipeline caller keeps the fd
         * to drive the next block. Any surplus already in `buf` past resp_len is
         * dropped here either way (E3's next exchange re-reads the wire); the
         * split proves out when the keepalive-bleed cases send block 2 on this
         * same fd.
         *
         * UNFRAMEABLE / MALFORMED are failures, not a fall back to read-to-EOF:
         * a response with no knowable length on a connection that will not close
         * has no end to read to, and guessing one is the smuggling primitive
         * this harness exists to catch. They are reported as harness failures of
         * this case so the assertion layer never runs against a boundary that
         * was invented.
         */
        if (st->framed) {
            size_t  resp_len = 0;
            int     fs = http_framed_state(buf, len, &resp_len);

            if (fs == HTTP_FRAMED_COMPLETE) {
                len = resp_len;
                st->len = len;
                st->resp->close_reason = HTTP_CLOSE_FRAMED;
                st->resp->close_ms = elapsed_since(st->sent_at);
                if (st->conn_open != NULL) {
                    *st->conn_open = 1;
                }
                goto finish;
            }

            if (fs == HTTP_FRAMED_UNFRAMEABLE) {
                snprintf(errbuf, errlen,
                         "framed read: response has no Content-Length, no "
                         "chunked coding, and is not a bodiless status -- its "
                         "end is unknowable on a connection that stays open");
                goto fail;
            }

            if (fs == HTTP_FRAMED_MALFORMED) {
                snprintf(errbuf, errlen,
                         "framed read: malformed Content-Length or chunk framing "
                         "(%zu bytes collected); the response boundary cannot be "
                         "trusted",
                         len);
                goto fail;
            }

            /* HTTP_FRAMED_INCOMPLETE: keep reading. */
        }
    }

    return 1;

finish:

    /* The success terminal. Ownership of buf transfers to resp->raw here, and
     * st->buf is cleared so http_read_state_free() cannot double-free it. */
    buf[len] = '\0';
    st->resp->raw = buf;
    st->resp->raw_len = len;
    st->buf = NULL;

    http_parse_response(st->resp);

    st->done = 1;
    st->rc = 0;
    return 0;

fail:

    /* The failure terminal. errbuf is already set by the branch that jumped
     * here. Freeing through the state (rather than the local) is what keeps a
     * later http_read_state_free() safe. */
    http_read_state_free(st);
    st->done = 1;
    st->rc = -1;
    return 0;
}


/*
 * The response-reading half of an exchange: drive one leg's state machine to
 * completion, blocking on poll() between steps.
 *
 * This is the N=1 case of the same machine the concurrent fan drives, and that
 * is deliberate -- a second single-leg implementation would be a copy of the
 * framing, dechunk, deadline and pacing logic that has to be kept in agreement
 * forever, and every mutant in the corpus would cover only one of the two.
 * Every existing single-exchange test is therefore also a test of the machine
 * the fan uses.
 *
 * `sent_at` is passed in because the whole-exchange deadline and every close_ms
 * measure from the instant the request finished going out, which only the
 * writer knows; taking a fresh timestamp here would silently restart the clock
 * and hand a trickling server the budget twice over.
 *
 * Return and errbuf semantics are http_exchange()'s: 0 when the exchange
 * completed (the verdict belongs to the assertion layer), -1 with errbuf set
 * on a harness-side failure.
 */
static int
http_read_response(int fd, int timeout_ms,
                   const http_recv *recv_opt, int want_close, int framed,
                   long long sent_at,
                   http_response *resp, int *conn_open,
                   char *errbuf, size_t errlen)
{
    http_read_state  st;

    if (http_read_state_init(&st, fd, timeout_ms, recv_opt, want_close, framed,
                             sent_at, resp, conn_open, errbuf, errlen) != 0)
    {
        return -1;
    }

    while (!st.done) {
        struct pollfd  pfd;
        long long      now = now_ms();
        int            readable = 0;

        if (http_read_state_pollable(&st, now)) {
            int  pr;

            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;

            pr = poll(&pfd, 1,
                      http_poll_timeout_ms(
                          http_read_state_next_wakeup(&st, now)));

            if (pr < 0) {
                if (errno == EINTR) {
                    continue;
                }

                snprintf(errbuf, errlen, "poll: %s", strerror(errno));
                http_read_state_free(&st);
                return -1;
            }

            /* POLLERR/POLLHUP mean the read below will report the real reason
             * (a reset, or EOF), so they are treated as readable rather than
             * diagnosed here -- the read loop's own error classification is
             * what the close_reason contract is written against. */
            readable = (pr > 0);

        } else {
            /* Pacing gate is closed: wait it out rather than spinning. In the
             * N=1 case there is nothing else to do with the time; in the fan
             * this leg simply stays out of the pollfd set. */
            long  wait = http_read_state_next_wakeup(&st, now);

            if (wait > 0) {
                (void) poll(NULL, 0, http_poll_timeout_ms(wait));
            }
        }

        (void) http_read_state_step(&st, readable, errbuf, errlen);
    }

    http_read_state_free(&st);

    return st.rc;
}


/*
 * The historical single-exchange entry point: open one connection, run one
 * write+read exchange on it, close it. Kept as the wrapper every existing caller
 * uses so the connect/exchange/close split is invisible to them, and it closes
 * unconditionally so a pipelined surplus a framed read left on the wire is
 * discarded (conn_open is ignored here for exactly that reason).
 */
int
http_request(const char *host, int port,
             const unsigned char *req, size_t req_len,
             int timeout_ms, const char *source,
             const http_pause *pauses, size_t n_pauses,
             int shut_how, size_t abort_at, long hold_ms,
             const http_recv *recv_opt, int want_close,
             long idle_ms, int framed,
             http_response *resp,
             char *errbuf, size_t errlen)
{
    int  fd, rc;

    fd = http_connect(host, port, timeout_ms, source, recv_opt, errbuf, errlen);
    if (fd < 0) {
        memset(resp, 0, sizeof(*resp));
        resp->status = -1;
        return -1;
    }

    rc = http_exchange(fd, req, req_len, timeout_ms, pauses, n_pauses,
                       shut_how, abort_at, hold_ms, recv_opt, want_close,
                       idle_ms, framed, resp, NULL, errbuf, errlen);

    http_close(fd);
    return rc;
}


/*
 * The `concurrent N` driver: open N connections, write the SAME request on all
 * of them before reading ANY response, then drain the N responses.
 *
 * The write-all-then-read-all ordering IS the directive. A sequential prober
 * cannot construct the state this exists to reach: every request must be
 * outstanding in the worker at the same instant for a shared-memory or
 * per-worker race to have a window at all. Reading response i before writing
 * request i+1 would collapse the fan back into N ordinary exchanges, so the two
 * loops below must stay separate no matter how tempting it looks to fuse them.
 *
 * Only the FIRST leg carries the case's pacing; the other N-1 send the request
 * plain. `shut_how` is the exception and applies to every leg -- see below.
 * Two reasons, both load-bearing:
 *
 *   - `abort`, `hold` and `expect_idle` are not parameters of this function at
 *     all. Each ends its connection WITHOUT reading (http_exchange returns
 *     before http_read_response), so a fan carrying one would collect nothing
 *     to assert against; they are refused at load time in load_rules_fp()
 *     rather than handled here. Named only so nobody "restores" a knob that was
 *     deliberately never plumbed through.
 *   - `send_slow`/`pause` pacing on every leg would multiply the pre-fan delay
 *     by N. The write loop is sequential, so leg 0's pauses elapse in full
 *     before leg 1 is written regardless; pacing only the first leg bounds that
 *     cost instead of paying it N times. Note this does NOT put a slow request
 *     in flight while the others pile in behind it -- that would need the paced
 *     write interleaved with the other legs' writes, which this does not do.
 *
 * `shut_how` is the exception and is applied to EVERY leg, because a half-close
 * is a modifier on the request rather than a substitute for the response: after
 * SHUT_WR the peer still answers, and the answer is the point. Treating it as
 * read-skipping would silently drop every response the directive exists to
 * provoke.
 *
 * Responses land in resps[0..n-1] positionally, so an assertion layer can name
 * the leg that misbehaved. resps[] is fully initialized on every return path,
 * including the error ones, so a caller may http_response_free() the whole array
 * unconditionally.
 *
 * Return is 0 when the fan completed (each leg's verdict belongs to the
 * assertion layer) or -1 with errbuf set on a harness-side failure. A leg that
 * fails to connect is a harness failure of the whole case: N-1 overlapping
 * requests are not the test the file asked for, and reporting a pass on a
 * narrower fan than the file spells is the silent-scope-change this harness
 * exists to rule out.
 */
int
http_exchange_concurrent(const char *host, int port, int n,
                         const unsigned char *req, size_t req_len,
                         int timeout_ms, const char *source,
                         const http_pause *pauses, size_t n_pauses,
                         int shut_how, const http_recv *recv_opt,
                         int want_close, int framed,
                         http_response *resps,
                         char *errbuf, size_t errlen)
{
    int        *fds;
    int         i, rc = 0;
    long long  *sent_at;

    /*
     * Initialize BEFORE validating, so the "resps[] is safe to free on every
     * return path" contract holds for the rejection returns too. A caller that
     * follows the header's instruction after an argument rejection would
     * otherwise free indeterminate pointers -- the rejection path is exactly
     * where a caller is least likely to have initialized them itself.
     *
     * Bounded by MAX_CONCURRENT rather than by n, because n is not yet known to
     * be in range: an oversized n means the array is only guaranteed to hold
     * what the ceiling allows, and touching n slots would be the overflow the
     * check below exists to prevent.
     */
    for (i = 0; i < n && i < MAX_CONCURRENT; i++) {
        memset(&resps[i], 0, sizeof(resps[i]));
        resps[i].status = -1;
    }

    if (n < 2) {
        snprintf(errbuf, errlen,
                 "concurrent fan of %d: the floor is 2 (one request in flight "
                 "is the ordinary path)", n);
        return -1;
    }

    /* The same ceiling the parser enforces with a line number. Repeated here
     * because this is a public entry point: a direct C caller does not go
     * through load_rules(), and without this it could demand an unbounded fd
     * and buffer count that the rule-file path is protected from. */
    if (n > MAX_CONCURRENT) {
        snprintf(errbuf, errlen,
                 "concurrent fan of %d exceeds the ceiling of %d", n,
                 MAX_CONCURRENT);
        return -1;
    }

    fds = malloc((size_t) n * sizeof(*fds));
    sent_at = malloc((size_t) n * sizeof(*sent_at));

    if (fds == NULL || sent_at == NULL) {
        free(fds);
        free(sent_at);
        snprintf(errbuf, errlen, "out of memory for a %d-way concurrent fan", n);
        return -1;
    }

    for (i = 0; i < n; i++) {
        fds[i] = -1;
        sent_at[i] = 0;
    }

    /*
     * Phase 1: connect every leg. Done before any write so the write phase is
     * not interleaved with connect latency -- a connect that blocks would
     * otherwise let an already-written request be answered and retired before
     * the last leg had even opened, shrinking the real overlap below N.
     */
    for (i = 0; i < n; i++) {
        fds[i] = http_connect(host, port, timeout_ms, source, recv_opt,
                              errbuf, errlen);

        if (fds[i] < 0) {
            char  detail[256];

            snprintf(detail, sizeof(detail), "%s", errbuf);
            snprintf(errbuf, errlen,
                     "concurrent leg %d/%d: connect failed: %s", i + 1, n,
                     detail);
            rc = -1;
            goto done;
        }
    }

    /*
     * Phase 2: write every request. Nothing is read here, so when this loop
     * ends all N requests are outstanding in the server at once -- the state the
     * whole directive exists to construct.
     */
    for (i = 0; i < n; i++) {
        const http_pause  *leg_pauses = (i == 0) ? pauses : NULL;
        size_t             leg_n_pauses = (i == 0) ? n_pauses : 0;

        if (write_request(fds[i], req, req_len,
                          leg_pauses, leg_n_pauses,
                          &resps[i].send_paced_ms) != 0)
        {
            snprintf(errbuf, errlen, "concurrent leg %d/%d: write: %s",
                     i + 1, n, strerror(errno));
            rc = -1;
            goto done;
        }

        /* Per-leg, for the same reason http_exchange() takes it at the end of
         * its own write: every deadline and close_ms measures from the instant
         * THIS request finished going out. A single shared timestamp would bill
         * leg 0's pacing to leg N-1's server response time. */
        sent_at[i] = now_ms();

        /* Applied to every leg -- see the header comment: SHUT_WR is a request
         * modifier, and the peer's answer to it is what the case reads. */
        if (shut_how != HTTP_SHUT_NONE) {
            (void) shutdown(fds[i], shut_how);
        }
    }

    /*
     * Phase 3: drain every leg through ONE poll() loop, S-4.
     *
     * Each leg's read is charged against its own sent_at, so a server that
     * answers leg 0 promptly and stalls leg N-1 is reported as a stall on leg
     * N-1 rather than being absorbed by leg 0's headroom.
     *
     * This used to read the legs in index order with a blocking read per leg.
     * That was not merely a timing-attribution flaw: leg i+1 was not read at
     * all until leg i finished or timed out, so the fan could not observe its
     * legs out of index order under ANY circumstance -- a server answering leg
     * 5 first and leg 0 last was indistinguishable from one answering strictly
     * in order, and time spent draining an earlier leg was charged to every
     * later leg's clock. Polling all live legs together removes both.
     *
     * FAILURE ATTRIBUTION IS FIRST-BY-INDEX, not first-by-time. Several legs
     * can now fail within one poll() iteration, so the rule has to be stated
     * rather than left emergent from loop order. Index order preserves the
     * existing "concurrent leg %d/%d" message and, more importantly, is
     * reproducible: first-by-time is the more truthful account of what the
     * server did, but it makes the reported leg depend on scheduling, and a
     * harness whose failure text moves between runs is one nobody can bisect.
     */
    {
        http_read_state  *sts;
        struct pollfd    *pfds;
        int              *pidx;
        char             *errs;
        int               live;

        sts = calloc((size_t) n, sizeof(*sts));
        pfds = calloc((size_t) n, sizeof(*pfds));
        pidx = calloc((size_t) n, sizeof(*pidx));

        /* Per-leg error text. A single shared errbuf cannot serve first-by-
         * index attribution: the step function writes errbuf on every failure,
         * so a later leg failing in the same iteration overwrites the message
         * belonging to the leg that will actually be reported. Each leg gets
         * its own slot and the winner's is copied out at the end. */
        errs = calloc((size_t) n, HTTP_LEG_ERRLEN);

        if (sts == NULL || pfds == NULL || pidx == NULL || errs == NULL) {
            free(sts);
            free(pfds);
            free(pidx);
            free(errs);
            snprintf(errbuf, errlen,
                     "out of memory draining a %d-way concurrent fan", n);
            rc = -1;
            goto done;
        }

        /* Arm every leg BEFORE polling any of them: a leg whose buffer was not
         * allocated cannot be in the pollfd set, and allocating lazily on first
         * readiness would make the failure path depend on arrival order. */
        for (i = 0; i < n; i++) {
            /*
             * NULL, not the address of a local. The state outlives this
             * iteration, so storing a pointer to a per-iteration `conn_open`
             * would leave every leg holding a dangling pointer that the framed
             * exit later writes through -- caught by ASan as a
             * stack-use-after-scope, and invisible in the plain build.
             *
             * NULL is also the correct VALUE here, not merely a safe one: the
             * fan closes every leg in its `done` block, so there is no reusable
             * connection to report and http_read_state_step() already treats a
             * NULL conn_open as "nobody is asking".
             */
            if (http_read_state_init(&sts[i], fds[i], timeout_ms, recv_opt,
                                     want_close, framed, sent_at[i], &resps[i],
                                     NULL, errbuf, errlen) != 0)
            {
                char  detail[256];
                int   j;

                snprintf(detail, sizeof(detail), "%s", errbuf);
                snprintf(errbuf, errlen, "concurrent leg %d/%d: %s",
                         i + 1, n, detail);

                for (j = 0; j <= i; j++) {
                    http_read_state_free(&sts[j]);
                }

                free(sts);
                free(pfds);
                free(pidx);
                free(errs);
                rc = -1;
                goto done;
            }
        }

        for ( ;; ) {
            long long  now;
            long       timeout = -1;
            int        nfds = 0;
            int        pr;

            live = 0;
            now = now_ms();

            for (i = 0; i < n; i++) {
                long  wake;

                if (sts[i].done) {
                    continue;
                }

                live++;

                wake = http_read_state_next_wakeup(&sts[i], now);
                if (timeout < 0 || wake < timeout) {
                    timeout = wake;
                }

                /* A leg held by its pacing gate stays OUT of the set: it has
                 * nothing to wait for on the socket, and including it would let
                 * data readiness cancel a delay the case asked for. The timeout
                 * above still accounts for it, so it is stepped when the gate
                 * opens. */
                if (!http_read_state_pollable(&sts[i], now)) {
                    continue;
                }

                pfds[nfds].fd = sts[i].fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                pidx[nfds] = i;
                nfds++;
            }

            if (live == 0) {
                break;
            }

            pr = poll(nfds > 0 ? pfds : NULL, (nfds_t) nfds,
                      http_poll_timeout_ms(timeout));

            if (pr < 0) {
                if (errno == EINTR) {
                    continue;
                }

                snprintf(errbuf, errlen, "concurrent drain: poll: %s",
                         strerror(errno));

                for (i = 0; i < n; i++) {
                    http_read_state_free(&sts[i]);
                }

                free(sts);
                free(pfds);
                free(pidx);
                free(errs);
                rc = -1;
                goto done;
            }

            /*
             * Step every leg that is ready, then sweep the rest. The sweep is
             * not optional: a leg whose deadline expired or whose pacing gate
             * opened has no readiness event to announce it, and would otherwise
             * sit un-stepped for as long as its siblings kept the loop busy.
             */
            for (i = 0; i < nfds; i++) {
                if (pfds[i].revents != 0) {
                    (void) http_read_state_step(&sts[pidx[i]], 1,
                                                errs + (size_t) pidx[i]
                                                       * HTTP_LEG_ERRLEN,
                                                HTTP_LEG_ERRLEN);
                }
            }

            for (i = 0; i < n; i++) {
                if (!sts[i].done) {
                    (void) http_read_state_step(&sts[i], 0,
                                                errs + (size_t) i
                                                       * HTTP_LEG_ERRLEN,
                                                HTTP_LEG_ERRLEN);
                }
            }
        }

        /* First-by-index, as documented above, reading the winning leg's OWN
         * error slot rather than the shared buffer -- which by now holds
         * whichever leg wrote to it last. */
        for (i = 0; i < n; i++) {
            if (sts[i].rc != 0) {
                snprintf(errbuf, errlen, "concurrent leg %d/%d: %s",
                         i + 1, n, errs + (size_t) i * HTTP_LEG_ERRLEN);
                rc = -1;
                break;
            }
        }

        /* Unconditional, per the ownership invariant on http_read_state: a
         * terminal leg has already released or transferred its buffer and a
         * non-terminal one still owns it, so this is correct for both and is
         * what makes abandoning a drain leak-free. */
        for (i = 0; i < n; i++) {
            http_read_state_free(&sts[i]);
        }

        free(sts);
        free(pfds);
        free(pidx);
        free(errs);

        if (rc != 0) {
            goto done;
        }
    }

done:

    for (i = 0; i < n; i++) {
        http_close(fds[i]);
    }

    free(fds);
    free(sent_at);

    return rc;
}


/*
 * ASCII-only case fold, deliberately NOT tolower()/strncasecmp().
 *
 * Measured under LC_ALL=tr_TR.UTF-8 (locale-hostility CI leg,
 * http_locale_check.c): glibc's tr_TR LC_CTYPE table makes 'I' and 'i'
 * fixed points of tolower()/toupper() -- tolower('I') == 'I', not 'i' --
 * rather than folding them onto each other the way the C locale does, and
 * glibc's strncasecmp()/strcasecmp() consult that same table. The practical
 * effect on the unmodified code: strncasecmp("ICE-Auth", "ice-auth", 8)
 * compared equal under the C locale and did not under tr_TR, so a header
 * name or value differing from the needle only in 'I'/'i' casing silently
 * stopped matching whenever the calling process' environment set a Turkish
 * locale -- which nothing in this codebase controls, since it is inherited
 * from whatever invoked the prober.
 *
 * HTTP header names are ASCII by construction (RFC 9110 token syntax), so
 * this search has no business consulting ANY locale table at all -- byte
 * comparison with a hand-rolled fold over 'A'-'Z' only is both correct and,
 * unlike strncasecmp(), immune to the invoking process' environment.
 */
static unsigned char
ascii_fold(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (unsigned char) (c - 'A' + 'a');
    }
    return c;
}


static int
ascii_case_eq(const char *a, const char *b, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (ascii_fold((unsigned char) a[i]) != ascii_fold((unsigned char) b[i])) {
            return 0;
        }
    }

    return 1;
}


int
http_has_header(const http_response *resp, const char *needle)
{
    const char *line;
    size_t      nlen;

    if (resp->headers == NULL) {
        return 0;
    }

    nlen = strlen(needle);
    line = resp->headers;

    while (line != NULL && *line != '\0') {
        const char *eol = strstr(line, "\r\n");
        size_t      llen = (eol != NULL) ? (size_t) (eol - line) : strlen(line);

        if (llen >= nlen) {
            size_t i;

            for (i = 0; i + nlen <= llen; i++) {
                if (ascii_case_eq(line + i, needle, nlen)) {
                    return 1;
                }
            }
        }

        line = (eol != NULL) ? eol + 2 : NULL;
    }

    return 0;
}
