/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * h2.h -- the h2 transport arm, driven by the system libnghttp2 rather than
 * hand-rolled framing (H2-2). Not a public API: http.h's http_exchange() is
 * still the only entry point a caller uses, and it dispatches into
 * h2_exchange() internally once ALPN has already negotiated "h2" on `fd` (see
 * the dispatch comment in http.c). Declared in its own header, rather than
 * folded into http.h, because nothing outside http.c needs to know this arm
 * exists -- the contract callers see is still http_exchange()'s.
 */

#ifndef PROBER_H2_H
#define PROBER_H2_H

#include "http.h"

#include <openssl/ssl.h>

/*
 * Run one h2 request/response over `fd`/`ssl`, which must already have
 * completed a TLS handshake that negotiated the "h2" ALPN protocol -- this
 * function does not check that itself, because http.c's dispatch already
 * established it before calling in.
 *
 * `req`/`req_len` is the SAME byte-oriented request http_exchange() always
 * took: an HTTP/1-shaped request line and header block, exactly as a `send`
 * directive in a .rule file writes it for the h1 path today (e.g.
 * "GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n"). Reusing
 * that shape rather than inventing a pseudo-header directive is what keeps
 * H2-2's callers (a .rule file, http_test.c) writing the request exactly as
 * they always have; this function is what translates it into `:method`,
 * `:path`, `:scheme`, `:authority` and ordinary header fields on the wire.
 * The request line and each header line are parsed literally -- no attempt
 * is made to normalize a malformed one, since a case exercising malformed h1
 * framing on this path is H2-3's job, not this one's.
 *
 * `resp` gets the fields the assertion layer reads: `raw` holds a
 * synthesized "HTTP/1.1 <status> <reason>\r\n<headers>\r\n\r\n<body>"
 * buffer (never what actually crossed the wire -- h2 has no such bytes) so
 * every existing assertion (`expect status=`, `expect body~`,
 * http_has_header()) keeps working unmodified against an h2 response, the
 * same way it already does against an h1 one. The h1-side diagnostic
 * fields with no h2 analogue -- `reads`, `paced_sleep_ms`, `send_paced_ms`,
 * `close_ms` -- stay at the zero http_exchange() memsets them to (there is
 * no per-read pacing and no measured close latency on this path); an
 * assertion on any of them after an h2 exchange would be vacuous. `close_reason` is set to
 * HTTP_CLOSE_FIN once the stream and connection both end, since this function
 * always closes the h2 session at the end of the one exchange it drives --
 * H2-2 ships one request per connection, not a multiplexed session a caller
 * can keep using afterward.
 *
 * Returns 0 on success (resp filled, http_exchange()'s verdict is still left
 * to the caller's assertion layer) or -1 with errbuf set, matching
 * http_exchange()'s own contract exactly.
 */
int h2_exchange(int fd, SSL *ssl, const unsigned char *req, size_t req_len,
                int timeout_ms, http_response *resp,
                char *errbuf, size_t errlen);

#endif /* PROBER_H2_H */
