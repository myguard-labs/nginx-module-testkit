/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * h2.c -- see h2.h. The h2 mechanism H2-2 adds: one request/response over an
 * ALPN-negotiated h2 connection, driven by the system libnghttp2 rather than
 * hand-rolled HTTP/2 framing (SUPERVISOR D1). The hostile-framing attacks a
 * real h2 client makes possible -- oversized HEADERS, HPACK bombs, stream
 * resets mid-body -- are deliberately NOT here; those are H2-3/H2-4/H2-5, and
 * this file's only job is to prove the mechanism carries one clean exchange
 * end to end.
 */

#define _GNU_SOURCE

#include "h2.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nghttp2/nghttp2.h>
#include <openssl/err.h>

/*
 * Collected across the one stream this file ever opens. A struct rather than
 * file-scope statics: nghttp2's callbacks take a `void *user_data` for
 * exactly this reason, and a second h2_exchange() call (there is only ever
 * one live at a time in this harness, but nothing enforces that) must not
 * silently share state with the first.
 */
typedef struct {
    int      status;        /* -1 until the :status pseudo-header arrives */
    char    *body;          /* growable, owned; NULL until first DATA byte */
    size_t   body_len;
    size_t   body_cap;
    char    *headers;       /* growable "Name: value\r\n" lines, owned */
    size_t   headers_len;
    size_t   headers_cap;
    int      stream_closed;
    int      oom;           /* a callback hit malloc/realloc failure */
} h2_collect;

/*
 * Append `len` bytes to a buf/len/cap growable buffer, doubling capacity as
 * needed. Every caller below is a callback invoked from inside
 * nghttp2_session_mem_recv(), which has no way to propagate a C errno or an
 * errbuf -- the only channel back out is the callback's own int return, so an
 * allocation failure here is recorded in `h2_collect.oom` and read back by
 * the caller once mem_recv() returns, rather than reported inline.
 */
static int
h2_append(char **buf, size_t *len, size_t *cap, const char *data, size_t n)
{
    if (n == 0) {
        return 0;
    }

    if (*len + n + 1 > *cap) {
        size_t  want = (*cap == 0) ? 256 : *cap;
        char   *grown;

        while (want < *len + n + 1) {
            want *= 2;
        }

        grown = realloc(*buf, want);
        if (grown == NULL) {
            return -1;
        }

        *buf = grown;
        *cap = want;
    }

    memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = '\0';

    return 0;
}

/*
 * nghttp2_nv's name/value fields are `uint8_t *`, not `const uint8_t *`.
 * -Wcast-qual flags a plain `(uint8_t *) some_const_char_ptr` as discarding
 * const, which is correct in general but not what is happening here:
 * nghttp2_submit_request() below is called with none of the NO_COPY flags
 * set, so nghttp2 copies every name/value byte into its own storage before
 * this function returns (see nghttp2_submit_request2()'s doc comment, which
 * nghttp2_submit_request() shares) and never writes through the pointer.
 * This helper names that fact once instead of repeating a `(uint8_t *)
 * (uintptr_t)` cast at each of the eight call sites below.
 */
static uint8_t *
nv_bytes(const char *s)
{
    return (uint8_t *) (uintptr_t) s;
}

static int
on_header_cb(nghttp2_session *session, const nghttp2_frame *frame,
             const uint8_t *name, size_t namelen,
             const uint8_t *value, size_t valuelen,
             uint8_t flags, void *user_data)
{
    h2_collect  *c = user_data;

    (void) session;
    (void) frame;
    (void) flags;

    /*
     * The :status pseudo-header is the h2 analogue of the h1 status line, and
     * the only pseudo-header this row's one GET case needs to read back --
     * synthesizing the rest of an h1-shaped response (see h2_exchange() below)
     * needs nothing else out of the pseudo-header set. Ordinary header fields
     * (never starting with ':' on a well-formed response) are collected
     * verbatim so http_has_header() keeps working against an h2 response the
     * same way it does against an h1 one.
     */
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        char  tmp[8];
        size_t  n = valuelen < sizeof(tmp) - 1 ? valuelen : sizeof(tmp) - 1;

        memcpy(tmp, value, n);
        tmp[n] = '\0';
        c->status = atoi(tmp);
        return 0;
    }

    if (namelen > 0 && name[0] == ':') {
        /* Every other pseudo-header on a response (there are none nginx
         * sends today) is not part of the h1-shaped header block this
         * function synthesizes -- h1 has no wire spelling for it. */
        return 0;
    }

    if (h2_append(&c->headers, &c->headers_len, &c->headers_cap,
                  (const char *) name, namelen) != 0)
    {
        c->oom = 1;
        return 0;
    }
    h2_append(&c->headers, &c->headers_len, &c->headers_cap, ": ", 2);
    if (h2_append(&c->headers, &c->headers_len, &c->headers_cap,
                  (const char *) value, valuelen) != 0)
    {
        c->oom = 1;
        return 0;
    }
    h2_append(&c->headers, &c->headers_len, &c->headers_cap, "\r\n", 2);

    return 0;
}

static int
on_data_chunk_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                  const uint8_t *data, size_t len, void *user_data)
{
    h2_collect  *c = user_data;

    (void) session;
    (void) flags;
    (void) stream_id;

    if (h2_append(&c->body, &c->body_len, &c->body_cap,
                  (const char *) data, len) != 0)
    {
        c->oom = 1;
    }

    return 0;
}

static int
on_stream_close_cb(nghttp2_session *session, int32_t stream_id,
                    uint32_t error_code, void *user_data)
{
    h2_collect  *c = user_data;

    (void) session;
    (void) stream_id;
    (void) error_code;

    c->stream_closed = 1;

    return 0;
}

/*
 * Parse an HTTP/1-shaped request (as every existing `send` directive still
 * writes it -- "METHOD SP PATH SP HTTP/x.y\r\nName: value\r\n...\r\n\r\n"...)
 * into the four h2 pseudo-headers a GET needs. Deliberately narrow: this
 * reads exactly the request shape http_test.c and every .rule file already
 * produce for the h1 path, not an arbitrary HTTP/1 grammar. A malformed or
 * exotic request line is not this row's job -- H2-3 owns hostile h2 framing,
 * and until then a case that wants one keeps using the h1 arm (ALPN not
 * offering "h2" at all, or a listener that refuses it, as H2-1 already
 * covers).
 *
 * `host` is read from the request's own "Host:" header when present, falling
 * back to "prober" (this harness always talks to 127.0.0.1 by IP, so
 * :authority is never used for routing here -- it only has to be non-empty,
 * since h2 clients are not required to duplicate it as a Host: field the way
 * curl does, and nginx accepts either).
 *
 * Returns 0 on success (method/path point into `req`, not copied) or -1 if
 * the request line does not have the METHOD SP PATH SP HTTP/x.y shape.
 */
static int
parse_h1_request_line(const unsigned char *req, size_t req_len,
                      const char **method, size_t *method_len,
                      const char **path, size_t *path_len,
                      const char **host, size_t *host_len)
{
    const char  *p = (const char *) req;
    const char  *end = (const char *) req + req_len;
    const char  *sp1, *sp2, *line_end;

    *host = "prober";
    *host_len = strlen("prober");

    sp1 = memchr(p, ' ', (size_t) (end - p));
    if (sp1 == NULL) {
        return -1;
    }

    *method = p;
    *method_len = (size_t) (sp1 - p);

    sp2 = memchr(sp1 + 1, ' ', (size_t) (end - (sp1 + 1)));
    if (sp2 == NULL) {
        return -1;
    }

    *path = sp1 + 1;
    *path_len = (size_t) (sp2 - (sp1 + 1));

    line_end = memmem(sp2, (size_t) (end - sp2), "\r\n", 2);
    if (line_end == NULL) {
        return -1;
    }

    /* Walk the header block for a "Host:" line, case-sensitively -- every
     * existing .rule file spells it "Host:", and matching only that spelling
     * is enough for the one round trip this row ships; a case-insensitive or
     * folded-header reader is scope this row does not need. */
    {
        const char  *h = line_end + 2;

        while (h < end) {
            const char  *hend = memmem(h, (size_t) (end - h), "\r\n", 2);

            if (hend == NULL || hend == h) {
                break;
            }

            if ((size_t) (hend - h) > 5 && memcmp(h, "Host:", 5) == 0) {
                const char  *v = h + 5;

                while (v < hend && *v == ' ') {
                    v++;
                }

                *host = v;
                *host_len = (size_t) (hend - v);
                break;
            }

            h = hend + 2;
        }
    }

    return 0;
}

int
h2_exchange(int fd, SSL *ssl, const unsigned char *req, size_t req_len,
           int timeout_ms, http_response *resp,
           char *errbuf, size_t errlen)
{
    nghttp2_session_callbacks  *cbs;
    nghttp2_session            *session;
    h2_collect                  c;
    nghttp2_nv                  nva[4];
    const char                  *method, *path, *host;
    size_t                       method_len, path_len, host_len;
    int32_t                      sid;
    int                          poll_ms;

    memset(&c, 0, sizeof(c));
    c.status = -1;

    if (parse_h1_request_line(req, req_len, &method, &method_len,
                              &path, &path_len, &host, &host_len) != 0)
    {
        snprintf(errbuf, errlen,
                 "h2: request is not a METHOD SP PATH SP HTTP/x.y line "
                 "(H2-2 translates the same request shape the h1 arm "
                 "takes; a case needing a malformed request line stays on "
                 "h1 by not offering h2 ALPN)");
        return -1;
    }

    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        snprintf(errbuf, errlen, "h2: out of memory (session_callbacks_new)");
        return -1;
    }

    nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
        on_data_chunk_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs,
        on_stream_close_cb);

    if (nghttp2_session_client_new(&session, cbs, &c) != 0) {
        nghttp2_session_callbacks_del(cbs);
        snprintf(errbuf, errlen, "h2: out of memory (session_client_new)");
        return -1;
    }

    nghttp2_session_callbacks_del(cbs);

    /* An empty client SETTINGS frame: this row asks for nothing beyond
     * nghttp2's own defaults (SETTINGS_MAX_CONCURRENT_STREAMS etc.), which
     * are already what a bare `h2load`/`curl --http2` client sends. Tuning
     * settings is not part of the mechanism H2-2 ships. */
    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, NULL, 0) != 0) {
        snprintf(errbuf, errlen, "h2: submit_settings failed");
        nghttp2_session_del(session);
        return -1;
    }

    nva[0].name = nv_bytes(":method");
    nva[0].namelen = strlen(":method");
    nva[0].value = nv_bytes(method);
    nva[0].valuelen = method_len;
    nva[0].flags = NGHTTP2_NV_FLAG_NONE;

    nva[1].name = nv_bytes(":path");
    nva[1].namelen = strlen(":path");
    nva[1].value = nv_bytes(path);
    nva[1].valuelen = path_len;
    nva[1].flags = NGHTTP2_NV_FLAG_NONE;

    nva[2].name = nv_bytes(":scheme");
    nva[2].namelen = strlen(":scheme");
    nva[2].value = nv_bytes("https");
    nva[2].valuelen = strlen("https");
    nva[2].flags = NGHTTP2_NV_FLAG_NONE;

    nva[3].name = nv_bytes(":authority");
    nva[3].namelen = strlen(":authority");
    nva[3].value = nv_bytes(host);
    nva[3].valuelen = host_len;
    nva[3].flags = NGHTTP2_NV_FLAG_NONE;

    /* NULL data_prd: no request body on this row's one GET case. A `send`
     * directive with a body past the header terminator is not read here --
     * H2-3+ is where a request body over h2 becomes relevant. */
    sid = nghttp2_submit_request(session, NULL, nva, 4, NULL, NULL);
    if (sid < 0) {
        snprintf(errbuf, errlen, "h2: submit_request failed: %s",
                 nghttp2_strerror(sid));
        nghttp2_session_del(session);
        return -1;
    }

    poll_ms = (timeout_ms < 0) ? 0 : timeout_ms;

    for ( ;; ) {
        const uint8_t  *data;
        struct pollfd    pfd;
        int              n;

        for ( ;; ) {
            ssize_t  sent = nghttp2_session_mem_send(session, &data);

            if (sent < 0) {
                snprintf(errbuf, errlen, "h2: mem_send failed: %s",
                         nghttp2_strerror((int) sent));
                nghttp2_session_del(session);
                return -1;
            }

            if (sent == 0) {
                break;
            }

            {
                size_t  off = 0;

                while (off < (size_t) sent) {
                    int  w = SSL_write(ssl, data + off,
                                       (int) ((size_t) sent - off));

                    if (w <= 0) {
                        int  se = SSL_get_error(ssl, w);

                        if (se == SSL_ERROR_WANT_READ
                            || se == SSL_ERROR_WANT_WRITE)
                        {
                            continue;
                        }

                        snprintf(errbuf, errlen,
                                 "h2: SSL_write failed (SSL_get_error=%d)",
                                 se);
                        nghttp2_session_del(session);
                        return -1;
                    }

                    off += (size_t) w;
                }
            }
        }

        if (c.stream_closed) {
            break;
        }

        if (!nghttp2_session_want_read(session)
            && !nghttp2_session_want_write(session))
        {
            break;
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        n = poll(&pfd, 1, poll_ms);

        if (n == 0) {
            snprintf(errbuf, errlen,
                     "h2: timed out waiting for the response "
                     "(%d ms, stream %d)", timeout_ms, sid);
            nghttp2_session_del(session);
            return -1;
        }

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            snprintf(errbuf, errlen, "h2: poll: %s", strerror(errno));
            nghttp2_session_del(session);
            return -1;
        }

        {
            unsigned char    buf[8192];
            int              r = SSL_read(ssl, buf, (int) sizeof(buf));
            ssize_t          consumed;

            if (r <= 0) {
                int  se = SSL_get_error(ssl, r);

                if (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE) {
                    continue;
                }

                if (se == SSL_ERROR_ZERO_RETURN && c.stream_closed) {
                    /* A close_notify that arrived exactly as the stream
                     * finished is the ordinary end of this exchange, not a
                     * failure -- nginx tears the TLS connection down right
                     * after the last DATA frame on a non-keepalive fetch. */
                    break;
                }

                snprintf(errbuf, errlen,
                         "h2: SSL_read failed (SSL_get_error=%d)", se);
                nghttp2_session_del(session);
                return -1;
            }

            consumed = nghttp2_session_mem_recv(session, buf, (size_t) r);

            if (consumed < 0) {
                snprintf(errbuf, errlen, "h2: mem_recv failed: %s",
                         nghttp2_strerror((int) consumed));
                nghttp2_session_del(session);
                return -1;
            }
        }
    }

    nghttp2_session_del(session);

    if (c.oom) {
        free(c.body);
        free(c.headers);
        snprintf(errbuf, errlen, "h2: out of memory collecting the response");
        return -1;
    }

    /*
     * Synthesize an HTTP/1-shaped `raw` buffer so every existing assertion
     * (`expect status=`, `expect body~`, http_has_header()) reads an h2
     * response exactly the way it reads an h1 one -- see h2.h's comment on
     * why this is a normalization for the assertion layer and never a claim
     * about what crossed the wire. The reason phrase is a fixed placeholder
     * ("h2"): h2 carries no reason phrase on the wire at all (RFC 9113 SS8.3),
     * so there is no wire value to preserve here, and no shipped assertion in
     * this row or H2-1 reads it.
     */
    {
        char    head[64];
        int     head_len;
        size_t  total;

        head_len = snprintf(head, sizeof(head), "HTTP/1.1 %d h2\r\n",
                            c.status);
        if (head_len < 0) {
            head_len = 0;
        }

        total = (size_t) head_len
              + c.headers_len
              + 2 /* CRLF terminator */
              + c.body_len;

        resp->raw = malloc(total + 1);
        if (resp->raw == NULL) {
            free(c.body);
            free(c.headers);
            snprintf(errbuf, errlen, "h2: out of memory (raw)");
            return -1;
        }

        memcpy(resp->raw, head, (size_t) head_len);
        if (c.headers != NULL) {
            memcpy(resp->raw + head_len, c.headers, c.headers_len);
        }
        memcpy(resp->raw + (size_t) head_len + c.headers_len, "\r\n", 2);
        if (c.body != NULL) {
            memcpy(resp->raw + (size_t) head_len + c.headers_len + 2,
                  c.body, c.body_len);
        }
        resp->raw[total] = '\0';
        resp->raw_len = total;
    }

    free(c.body);
    free(c.headers);

    http_parse_response(resp);
    resp->close_reason = HTTP_CLOSE_FIN;

    return 0;
}
