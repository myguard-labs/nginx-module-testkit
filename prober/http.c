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

/* Defined immediately after http_exchange(), which is its only caller. Declared
 * here rather than moved above it so the file still reads in exchange order --
 * write, then read -- matching the order the two halves actually run in. */
static int http_read_response(int fd, int timeout_ms,
                              const http_recv *recv_opt, int want_close,
                              int framed, long long sent_at,
                              http_response *resp, int *conn_open,
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
    if (resp->raw_len > 5 && memcmp(resp->raw, "HTTP/", 5) == 0) {
        size_t  i = 5;
        int     saw_major = 0;
        int     saw_minor = 0;

        while (i < resp->raw_len && resp->raw[i] >= '0' && resp->raw[i] <= '9') {
            i++;
            saw_major = 1;
        }

        if (saw_major && i < resp->raw_len && resp->raw[i] == '.') {
            i++;

            while (i < resp->raw_len
                   && resp->raw[i] >= '0' && resp->raw[i] <= '9')
            {
                i++;
                saw_minor = 1;
            }
        }

        if (saw_major && saw_minor
            && i < resp->raw_len && resp->raw[i] == ' ')
        {
            char *end;
            long  code = strtol(resp->raw + i + 1, &end, 10);

            /* strtol reports "no digits" by leaving end at the start, and
             * returns 0 for it -- indistinguishable from a literal "0" status
             * unless the end pointer is checked. The header promises -1 for
             * anything unparseable, so a non-numeric token must not surface
             * as a status a rule could match on. */
            if (end != resp->raw + i + 1 && code >= 0 && code <= INT_MAX) {
                resp->status = (int) code;
            }
        }
    }

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

    /* Pull the status code the same way http_parse_response() does, but only far
     * enough to recognise a bodiless code. A malformed status line leaves status
     * -1, which is not bodiless, so such a response is classified by its length
     * headers or judged unframeable -- never silently treated as empty. */
    if (len > 5 && memcmp(buf, "HTTP/", 5) == 0) {
        const char  *sp = memchr(buf, ' ', (size_t) (hdr_end - buf));

        if (sp != NULL) {
            char  *cend;
            long   code = strtol(sp + 1, &cend, 10);

            if (cend != sp + 1 && code >= 0 && code <= INT_MAX) {
                status = (int) code;
            }
        }
    }

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
 */
static void
sleep_ms(long ms)
{
    struct timespec  ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;

    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        /* ts now holds the remaining time; go again. */
    }
}


/*
 * Write `len` bytes `chunk` at a time, sleeping `ms` between writes. The sleep
 * goes BETWEEN chunks only -- a trailing sleep after the final chunk would
 * delay the response rather than the request, which is a different test.
 */
static int
write_paced(int fd, const unsigned char *buf, size_t len,
            size_t chunk, long ms)
{
    size_t  off = 0;

    while (off < len) {
        size_t  n = len - off;

        if (n > chunk) {
            n = chunk;
        }

        if (write_all(fd, buf + off, n) != 0) {
            return -1;
        }

        off += n;

        if (off < len) {
            sleep_ms(ms);
        }
    }

    return 0;
}


/*
 * Write the request, stalling at each pause offset. With no pauses this is a
 * single write_all() of the whole buffer -- byte-identical to what this
 * function did before pauses existed.
 */
static int
write_request(int fd, const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses)
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

        if (pauses[i].chunk > 0) {
            /* Paced entry: dribble from here to the next entry's offset (or
             * the end), rather than stalling once. The leading sleep keeps a
             * paced entry's `ms` meaning the same "hold off, then act" as a
             * plain pause, so the two read alike in a rule file. */
            size_t  upto_next = req_len;

            if (i + 1 < n_pauses && pauses[i + 1].offset < upto_next) {
                upto_next = pauses[i + 1].offset;
            }

            if (upto_next < off) {
                upto_next = off;
            }

            sleep_ms(pauses[i].ms);

            if (write_paced(fd, req + off, upto_next - off,
                            pauses[i].chunk, pauses[i].ms) != 0)
            {
                return -1;
            }

            off = upto_next;
            continue;
        }

        sleep_ms(pauses[i].ms);
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
                      pauses, n_pauses) != 0)
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
 * The response-reading half of an exchange, split out of http_exchange() so a
 * concurrent driver can write N requests before reading ANY response -- that
 * overlap is the whole point of concurrency, and it is unreachable while the
 * read loop is welded to the write that preceded it.
 *
 * This is a pure extraction: the body below is http_exchange()'s former tail
 * verbatim, and every path that used to skip it (abort's SO_LINGER reset,
 * hold, expect_idle) still returns before reaching this call rather than
 * entering and short-circuiting.
 *
 * `shutdown` is deliberately NOT in that list: a half-close is a modifier on
 * the request, not a substitute for the response. It shuts the write side and
 * then reads normally -- which is the entire point of SHUT_WR, since the peer
 * has to answer the EOF for the case to prove anything. A concurrency driver
 * must therefore treat shut_how as compatible with reading, not as a
 * read-skipping mode.
 *
 * `sent_at` is passed in because the whole-
 * exchange deadline and every close_ms measure from the instant the request
 * finished going out, which only the writer knows; taking a fresh timestamp
 * here would silently restart the clock and hand a trickling server the budget
 * twice over.
 *
 * The response buffer is allocated, grown, and either freed or transferred to
 * resp->raw entirely within this function -- no allocation crosses the seam,
 * which is what makes the split safe to review as a move rather than a
 * lifetime change.
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
    char       *buf;
    size_t      cap = 8192, len = 0, want;
    int         paced_full = 0;
    long        paced_sleep_ms = 0;   /* intentional recv pacing, AUD-07 */

    buf = malloc(cap);
    if (buf == NULL) {
        snprintf(errbuf, errlen, "out of memory");
        return -1;
    }

    for ( ;; ) {
        ssize_t n;

        /*
         * AUD-07: the whole-exchange deadline, checked before every read. The
         * per-read SO_RCVTIMEO does not bound a peer that trickles one byte per
         * window, so without this the loop could run and allocate forever. A
         * want_close caller treats the deadline as its answer (the server held
         * the connection open too long); otherwise it is a harness failure of
         * this case, not a silent pass.
         */
        if (elapsed_since(sent_at) - paced_sleep_ms
                > HTTP_MAX_EXCHANGE_MS(timeout_ms)) {
            if (want_close) {
                resp->close_reason = HTTP_CLOSE_TIMEOUT;
                resp->close_ms = elapsed_since(sent_at);
                break;
            }

            snprintf(errbuf, errlen,
                     "response did not complete within %ld ms whole-exchange "
                     "budget (%zu bytes so far); a server trickling bytes under "
                     "the per-read timeout never trips it",
                     HTTP_MAX_EXCHANGE_MS(timeout_ms), len);
            free(buf);
            return -1;
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
            free(buf);
            return -1;
        }

        if (len + 4096 > cap) {
            char *bigger;

            /* Never grow past the ceiling (plus one chunk of headroom so the
             * len > ceiling check above still gets to fire on the collected
             * bytes rather than the allocation aborting first). */
            cap *= 2;
            if (cap > HTTP_MAX_RESPONSE + 4096) {
                cap = HTTP_MAX_RESPONSE + 4096;
            }
            bigger = realloc(buf, cap);
            if (bigger == NULL) {
                snprintf(errbuf, errlen, "out of memory");
                free(buf);
                return -1;
            }
            buf = bigger;
        }

        want = cap - len - 1;

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
        if (recv_opt != NULL && recv_opt->chunk > 0) {
            if (want > recv_opt->chunk) {
                want = recv_opt->chunk;
            }

            if (paced_full) {
                sleep_ms(recv_opt->ms);
                /* AUD-07: this sleep is the harness's OWN deliberate pacing, not
                 * the server being slow, so it must not count against the
                 * whole-exchange deadline -- otherwise a legitimately paced
                 * recv_slow case that needs many chunks would trip the trickle
                 * guard despite the server making continuous progress. */
                paced_sleep_ms += recv_opt->ms;
            }
        }

        n = read(fd, buf + len, want);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /*
                 * A caller asking about the close treats this as the answer,
                 * not as a failure: the server held the connection open past
                 * the deadline, which is a fact about the server. Keep the
                 * bytes that did arrive and let the assertion layer judge --
                 * see want_close in http.h for why this cannot be an error.
                 */
                if (want_close) {
                    resp->close_reason = HTTP_CLOSE_TIMEOUT;
                    resp->close_ms = elapsed_since(sent_at);
                    break;
                }

                snprintf(errbuf, errlen,
                         "read timed out after %d ms (%zu bytes so far); "
                         "does the request ask for Connection: close?",
                         timeout_ms, len);
                free(buf);
                return -1;
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
            resp->close_reason = (errno == ECONNRESET) ? HTTP_CLOSE_RESET
                                                       : HTTP_CLOSE_NONE;
            resp->close_ms = elapsed_since(sent_at);
            break;
        }

        if (n == 0) {
            resp->close_reason = HTTP_CLOSE_FIN;
            resp->close_ms = elapsed_since(sent_at);
            break;
        }

        /* Whether this read filled its chunk decides if the NEXT one is paced;
         * see the sleep above. */
        paced_full = (recv_opt != NULL && recv_opt->chunk > 0
                      && (size_t) n == want);

        resp->reads++;
        len += (size_t) n;

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
        if (framed) {
            size_t  resp_len = 0;
            int     fs = http_framed_state(buf, len, &resp_len);

            if (fs == HTTP_FRAMED_COMPLETE) {
                len = resp_len;
                resp->close_reason = HTTP_CLOSE_FRAMED;
                resp->close_ms = elapsed_since(sent_at);
                if (conn_open != NULL) {
                    *conn_open = 1;
                }
                break;
            }

            if (fs == HTTP_FRAMED_UNFRAMEABLE) {
                snprintf(errbuf, errlen,
                         "framed read: response has no Content-Length, no "
                         "chunked coding, and is not a bodiless status -- its "
                         "end is unknowable on a connection that stays open");
                free(buf);
                return -1;
            }

            if (fs == HTTP_FRAMED_MALFORMED) {
                snprintf(errbuf, errlen,
                         "framed read: malformed Content-Length or chunk framing "
                         "(%zu bytes collected); the response boundary cannot be "
                         "trusted",
                         len);
                free(buf);
                return -1;
            }

            /* HTTP_FRAMED_INCOMPLETE: keep reading. */
        }
    }

    buf[len] = '\0';
    resp->raw = buf;
    resp->raw_len = len;

    http_parse_response(resp);

    return 0;
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
                          leg_pauses, leg_n_pauses) != 0)
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
     * Phase 3: drain. Each leg's read is charged against its own sent_at, so a
     * server that answers leg 0 promptly and stalls leg N-1 is reported as a
     * stall on leg N-1 rather than being absorbed by leg 0's headroom.
     *
     * Legs are read in order rather than by poll() readiness. The responses are
     * collected in full either way and each carries its own timing, so readiness
     * ordering would change which leg is read first without changing any
     * assertion -- and an in-order drain keeps the failure attribution simple
     * enough to trust. The overlap has already happened by the time this loop
     * starts; nothing here can undo it.
     */
    for (i = 0; i < n; i++) {
        int  conn_open = 0;

        if (http_read_response(fds[i], timeout_ms, recv_opt, want_close, framed,
                               sent_at[i], &resps[i], &conn_open,
                               errbuf, errlen) != 0)
        {
            char  detail[256];

            snprintf(detail, sizeof(detail), "%s", errbuf);
            snprintf(errbuf, errlen, "concurrent leg %d/%d: %s",
                     i + 1, n, detail);
            rc = -1;
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
