/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http_test.c -- TAP self-test for response splitting and header search.
 *
 * http_parse_response() is exported precisely for this file: the inputs worth
 * testing -- no header terminator, a body that itself contains CRLFCRLF, an
 * embedded NUL, a truncated status line -- are the ones a live server will not
 * produce on demand, so testing through a socket would leave exactly the
 * interesting cases untested.
 *
 * Every fixture goes through parse_bytes(), which mimics what http_request()
 * hands the parser: a malloc'd buffer of raw_len bytes with a convenience NUL
 * after them. Length-bounded fixtures throughout -- several embed NULs, and
 * the point is that the parser counts bytes, not C strings.
 */

/* _GNU_SOURCE for the socket/clock/fork machinery the pacing fixtures need:
 * -std=c11 alone hides CLOCK_MONOTONIC and friends behind the POSIX guards. */
#define _GNU_SOURCE

#include "http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Only for the TLS fixtures below: a throwaway self-signed cert generated at
 * test time via the OpenSSL API (never shelled out to `openssl`, which would
 * be an undeclared test dependency the rest of this file has none of), and a
 * minimal TLS server loop in the forked child to answer the handshake. */
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  203

/* Ceiling on spawn_barrier()'s connection array. Sized for the fixtures here,
 * not for MAX_CONCURRENT: the barrier holds every connection open at once in a
 * forked child, and the tests below fan 4 legs. A `want` above this is a test
 * bug, so the child exits non-zero rather than overflowing the array. */
#define MAX_BARRIER  16

static int  tests_run = 0;
static int  failures = 0;


static void
ok(int cond, const char *name)
{
    tests_run++;

    printf("%sok %d - %s\n", cond ? "" : "not ", tests_run, name);

    if (!cond) {
        failures++;
    }
}


static void
parse_bytes(http_response *resp, const char *bytes, size_t len)
{
    char  *buf = malloc(len + 1);

    if (buf == NULL) {
        fprintf(stderr, "http_test: out of memory\n");
        exit(2);
    }

    memcpy(buf, bytes, len);
    buf[len] = '\0';

    memset(resp, 0, sizeof(*resp));
    resp->raw = buf;
    resp->raw_len = len;

    http_parse_response(resp);
}


/* sizeof-1 only works on literals; a macro keeps the call sites honest about
 * that and spares every fixture a hand-counted length. */
#define PARSE(resp, lit)  parse_bytes(resp, lit, sizeof(lit) - 1)


/*
 * The fixture's canned reply. Padded to a few hundred bytes rather than the
 * bare status line it used to be, so the recv_slow cases have something to pace
 * over: a 19-byte response is one read at any plausible chunk size, and the
 * pacing would be unobservable. Nothing asserts on the body, so the padding is
 * invisible to every other case.
 */
#define SPAWN_REPLY \
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" \
    "0123456789012345678901234567890123456789012345678901234567890123" \
    "0123456789012345678901234567890123456789012345678901234567890123" \
    "0123456789012345678901234567890123456789012345678901234567890123" \
    "0123456789012345678901234567890123456789012345678901234567890123" \
    "0123456789012345678901234567890123456789012345678901234567890123" \
    "01234567890123456789012345678901234567890123456789012"

#define SPAWN_REPLY_LEN  (sizeof(SPAWN_REPLY) - 1)


/* Wall-clock helper for the receive-side timing assertions. The send-side
 * cases time the request inside the fixture child, but recv_slow paces reads in
 * THIS process, so the observable is here rather than over there. */
static long long
now_ms(void)
{
    struct timespec  ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* long long, and the multiply done in it, for the reason http.c's
     * now_ms() carries: CLOCK_MONOTONIC counts from boot, so tv_sec * 1000
     * overflows a 32-bit long after ~24 days of uptime. This one only feeds
     * test assertions, but those assertions are the timing floors that judge
     * whether pacing and close deadlines work -- an overflowed elapsed here
     * would mask exactly the failures they exist to catch. */
    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}


/*
 * A `pause` is the one directive whose whole meaning is timing, so recording
 * the offsets in the parser proves nothing on its own -- write_request() has
 * to actually stall. These fixtures run a throwaway loopback server in a child
 * process, which reads the request and reports how long the bytes took to
 * arrive and what they were.
 *
 * Timing assertions are one-sided on purpose: the test asserts a floor (the
 * pause happened) and never a ceiling (it was not much longer), because a
 * loaded CI box can stretch any interval but cannot make a nanosleep return
 * early. A two-sided assertion here would be a flake generator.
 */
typedef struct {
    long    elapsed_ms;     /* time from first byte to complete request */
    char    got[256];
    size_t  got_len;
    size_t  reads;          /* successful read() calls that returned bytes */
    size_t  max_read;       /* largest single read, in bytes */

    /* Size of each read, in order, truncated at ECHO_SEGS entries.
     *
     * `reads` and `max_read` bound how the request was segmented; they cannot
     * say WHERE it was cut, and for chunk-unit pacing that is the whole claim.
     * A byte-count pacer and a unit pacer over the same body can agree on both
     * summary numbers while splitting at completely different offsets -- one of
     * them mid size-line -- so proving `send_slow_chunks` paces by framing needs
     * the boundaries themselves. Coalescing still applies (see the read loop),
     * so assertions on this look for the framing offsets among the boundaries
     * rather than demanding an exact segment list. */
    size_t  segs[16];
    size_t  n_segs;
    int     saw_eof;        /* the client half-closed: read() returned 0 */

    /* The client reset the connection: read() failed with ECONNRESET rather
     * than reporting a clean EOF. This is the ONLY observable that separates an
     * `abort` from an ordinary close -- both end the connection, and the byte
     * count the server managed to read is identical either way. Recording the
     * offset in the parser proves nothing about the wire. */
    int     saw_reset;

    /* How http_request() judged the end of the connection, lifted off the
     * response before it is freed. These are the CLIENT's view, unlike every
     * field above, which the fixture child records from the server side --
     * kept here anyway so one struct carries the whole exchange. */
    int     close_reason;
    long    close_ms;

    /* The connection's effective SO_RCVBUF as http_request() saw it, lifted off
     * the response like close_reason above. The deterministic witness that a
     * requested rcvbuf reached the socket. */
    int     effective_rcvbuf;

    /* How many read() calls the CLIENT needed to collect the response, lifted
     * off the response like the fields above. This is recv_slow's deterministic
     * witness: the chunk cap is what forces a response that would arrive in one
     * read to be collected in several, and a read count cannot be inflated by a
     * loaded box the way the elapsed-time floor beside it can. */
    size_t  client_reads;

    /* Milliseconds the CLIENT deliberately slept between reads, lifted off the
     * response like the fields above. recv_slow's other deterministic witness:
     * client_reads gates the chunk cap, this gates the SLEEP the cap paces the
     * reads apart with. Neither can be moved by a loaded box. */
    long long  paced_sleep_ms;

    /* Milliseconds the CLIENT deliberately slept while WRITING the request,
     * lifted off the response like paced_sleep_ms above -- the send-side
     * twin. send_slow's deterministic witness: unlike elapsed_ms, a loaded
     * box cannot inflate or shrink it, because it is credited from
     * sleep_ms()'s return rather than measured off a wall clock. */
    long long  send_paced_ms;
} echo_result;


/*
 * Serve exactly one connection on an ephemeral port, reading `want_len` bytes
 * and timing their arrival. The port is handed back through *port, the result
 * through a pipe, so the parent can connect without racing on a fixed port.
 */
static pid_t
spawn_echo(int *port, size_t want_len, int want_eof, int result_fd)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    /* The listener is created before the fork so the parent knows the port is
     * already bound the moment spawn_echo() returns -- connecting cannot race
     * the child reaching accept(). */
    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int              c = accept(srv, NULL, NULL);
        echo_result      r;
        struct timespec  t0, t1;
        size_t           len = 0;

        memset(&r, 0, sizeof(r));

        if (c < 0) {
            _exit(2);
        }

        clock_gettime(CLOCK_MONOTONIC, &t0);

        while (len < want_len && len < sizeof(r.got)) {
            ssize_t n = read(c, r.got + len, sizeof(r.got) - len);

            if (n < 0) {
                /* ECONNRESET here is the abort case's whole signal, so it is
                 * recorded rather than treated as a fixture failure. */
                if (errno == ECONNRESET) {
                    r.saw_reset = 1;
                }
                break;
            }

            if (n == 0) {
                break;
            }

            /* Read counts are indicative, not exact: TCP may coalesce two
             * writes into one read or split one write across two, so tests
             * assert loose bounds (more than one read, no read larger than the
             * chunk) rather than an exact segment count. With TCP_NODELAY and
             * a pace far longer than loopback latency, those bounds are still
             * decisive -- a single unpaced write cannot satisfy them. */
            r.reads++;

            if ((size_t) n > r.max_read) {
                r.max_read = (size_t) n;
            }

            if (r.n_segs < sizeof(r.segs) / sizeof(r.segs[0])) {
                r.segs[r.n_segs++] = (size_t) n;
            }

            len += (size_t) n;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        /*
         * One more read, to distinguish "the client sent its request and is
         * waiting for a reply" from "the client half-closed". Only done when
         * the caller asked (want_eof), because without a shutdown this read
         * blocks until the socket timeout and would add that to every case.
         *
         * This is what makes a SHUT_WR assertion mean anything: recording the
         * mode in the parser proves nothing about the wire, and the response
         * still arrives either way, so EOF here is the only observable that
         * distinguishes the two.
         */
        if (want_eof) {
            char            scratch[16];
            ssize_t         n;
            struct timeval  rtv;

            /* Bounded, because the no-shutdown case deliberately reaches this
             * read with the client still open: without a timeout it would sit
             * here until the parent tore the connection down, making the
             * negative assertion depend on teardown order rather than on the
             * shutdown. A timeout leaves saw_eof at 0, which is exactly the
             * "still open" verdict that case asserts. */
            rtv.tv_sec = 0;
            rtv.tv_usec = 300000;
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

            do {
                n = read(c, scratch, sizeof(scratch));
            } while (n < 0 && errno == EINTR);

            if (n == 0) {
                r.saw_eof = 1;
            }

            /* Same read serves the abort cases: when the client wrote its whole
             * prefix, the loop above ended on the byte count rather than on the
             * reset, so the reset is only observable here. EOF and reset are
             * mutually exclusive outcomes of that one read, which is precisely
             * the distinction the abort tests assert on. */
            if (n < 0 && errno == ECONNRESET) {
                r.saw_reset = 1;
            }
        }

        r.got_len = len;
        r.elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000
                       + (t1.tv_nsec - t0.tv_nsec) / 1000000L;

        /*
         * Answer so the parent's read loop ends on a real response rather
         * than on its own timeout, which would add timeout_ms to every case.
         *
         * MSG_NOSIGNAL because the abort cases reach here with the connection
         * already reset: a plain write() to a reset socket raises SIGPIPE,
         * whose default action would kill this child BEFORE it reports through
         * the pipe. The parent would then see a short read and fail the case as
         * a fixture error -- an abort test that can never pass, for a reason
         * having nothing to do with the code under test.
         *
         * A failed send is therefore not fatal here: on an aborted connection
         * there is no peer left to answer, and the report below is the only
         * thing the parent actually needs.
         */
        (void) send(c, SPAWN_REPLY, SPAWN_REPLY_LEN, MSG_NOSIGNAL);

        close(c);

        if (write(result_fd, &r, sizeof(r)) != (ssize_t) sizeof(r)) {
            _exit(2);
        }

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Drive http_request() against the throwaway server and collect what it saw.
 * Returns 0 when the exchange and the report both completed.
 */
static int
run_echo_full(const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses, int shut_how,
              size_t abort_at, long hold_ms, const http_recv *recv_opt,
              int want_eof, int want_close, long idle_ms,
              echo_result *out)
{
    int            fds[2], port = 0;
    pid_t          pid;
    http_response  resp;
    char           errbuf[256];
    int            rc, st;
    int            close_reason = HTTP_CLOSE_NONE;
    long           close_ms = 0;
    int            effective_rcvbuf = 0;
    size_t         client_reads = 0;
    long long      paced_sleep_ms = 0;
    long long      send_paced_ms = 0;

    if (pipe(fds) != 0) {
        return -1;
    }

    pid = spawn_echo(&port, req_len, want_eof, fds[1]);
    close(fds[1]);

    rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                      pauses, n_pauses, shut_how, abort_at, hold_ms,
                      recv_opt, want_close, idle_ms, 0, NULL, &resp,
                      errbuf, sizeof(errbuf));

    if (rc == 0) {
        /* The close metadata is the point of the want_close cases, and it
         * lives on the response the caller never sees, so lift it out before
         * the buffers go away. */
        close_reason = resp.close_reason;
        close_ms = resp.close_ms;
        effective_rcvbuf = resp.effective_rcvbuf;
        client_reads = resp.reads;
        paced_sleep_ms = resp.paced_sleep_ms;
        send_paced_ms = resp.send_paced_ms;
        http_response_free(&resp);
    }

    memset(out, 0, sizeof(*out));

    if (read(fds[0], out, sizeof(*out)) != (ssize_t) sizeof(*out)) {
        rc = -1;
    }

    close(fds[0]);
    waitpid(pid, &st, 0);

    /* AFTER the pipe read, which fills *out from the child's report and would
     * otherwise overwrite these. The child cannot know them: they are what
     * this process concluded about the close. */
    out->close_reason = close_reason;
    out->close_ms = close_ms;
    out->effective_rcvbuf = effective_rcvbuf;
    out->client_reads = client_reads;
    out->paced_sleep_ms = paced_sleep_ms;
    out->send_paced_ms = send_paced_ms;

    return rc;
}


/*
 * Build a throwaway self-signed certificate + RSA key, entirely via the
 * OpenSSL API (never by shelling out to the `openssl` binary, which would be
 * an undeclared test dependency and the one thing this fixture must not
 * become). Returns 0 and fills *out_cert and *out_pkey on success, or -1 on any
 * OpenSSL failure -- the caller SKIPs loudly rather than treating that as a
 * pass, since an environment with no usable OpenSSL cannot prove the TLS leg
 * either way.
 *
 * 2048-bit RSA and a 1-day validity window: this cert lives for the length of
 * one test process and is never written to disk or reused across runs, so
 * there is nothing here worth hardening beyond "OpenSSL accepts it".
 */
static int
make_self_signed_cert(X509 **out_cert, EVP_PKEY **out_pkey)
{
    EVP_PKEY_CTX  *pctx = NULL;
    EVP_PKEY      *pkey = NULL;
    X509          *cert = NULL;
    X509_NAME     *name;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL
        || EVP_PKEY_keygen_init(pctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0
        || EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        goto fail;
    }

    cert = X509_new();
    if (cert == NULL) {
        goto fail;
    }

    if (X509_set_version(cert, 2) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1
        || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L) == NULL
        || X509_set_pubkey(cert, pkey) != 1)
    {
        goto fail;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL
        || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      (const unsigned char *)
                                      "prober-http-test.invalid",
                                      -1, -1, 0) != 1
        || X509_set_issuer_name(cert, name) != 1)
    {
        goto fail;
    }

    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        goto fail;
    }

    EVP_PKEY_CTX_free(pctx);
    *out_cert = cert;
    *out_pkey = pkey;
    return 0;

fail:
    if (cert != NULL) {
        X509_free(cert);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return -1;
}


/*
 * Serve up to SPAWN_TLS_ECHO_MAX_CONNS TLS connections, one after another, on
 * an ephemeral port: accept, complete a TLS server-side handshake with a
 * throwaway self-signed cert, read the request, and write SPAWN_REPLY back --
 * then loop and accept the next one. Modeled on spawn_echo() -- same
 * fork-after-listen shape so the parent can never race the child to accept()
 * -- but looped, because callers that prove fd-reuse/teardown behaviour open
 * a second, independent connection against the same fixture after closing
 * the first. The child exits after serving the cap or on any handshake/I/O
 * error; the caller is responsible for reaping it (SIGKILL + waitpid) once
 * it is done driving connections, since a child that served fewer than the
 * cap is still blocked in accept() waiting for a connection that will never
 * come.
 *
 * Returns the child pid, or -1 if this environment cannot produce a usable
 * TLS server fixture (cert generation or context setup failed) -- the SKIP
 * decision belongs to the caller, which knows what TAP line it owes.
 */
#define SPAWN_TLS_ECHO_MAX_CONNS  4

static pid_t
spawn_tls_echo(int *port)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;
    X509               *cert;
    EVP_PKEY           *pkey;
    SSL_CTX            *ctx;

    if (make_self_signed_cert(&cert, &pkey) != 0) {
        return -1;
    }

    /*
     * Built and validated BEFORE the fork on purpose. A context failure has
     * to be reportable as -1 so the caller can SKIP; a child that only
     * discovers it after the fork can do nothing but _exit(2), by which time
     * the parent already holds a valid pid and would take the non-SKIP branch
     * -- turning "this environment has no usable OpenSSL server context" into
     * a hard assertion failure instead of the loud SKIP it is meant to be.
     */
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL
        || SSL_CTX_use_certificate(ctx, cert) != 1
        || SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
    {
        if (ctx != NULL) {
            SSL_CTX_free(ctx);
        }
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, SPAWN_TLS_ECHO_MAX_CONNS) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        close(srv);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    *port = ntohs(sin.sin_port);

    /* Listener bound before the fork, exactly as spawn_echo() does it, so
     * connecting in the parent cannot race the child reaching accept(). */
    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        close(srv);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (pid == 0) {
        int  n;

        /* Serve up to the cap, one connection at a time, so a caller that
         * closes one TLS connection and opens a fresh one against the same
         * fixture (proving http_close() tore down the old side-table slot
         * rather than leaking it) still has a live peer to handshake with.
         * A handshake/I/O error on any one connection is fatal to the whole
         * fixture, same as the original single-shot behaviour. */
        for (n = 0; n < SPAWN_TLS_ECHO_MAX_CONNS; n++) {
            SSL   *ssl;
            int    c;
            char   scratch[512];

            c = accept(srv, NULL, NULL);
            if (c < 0) {
                _exit(2);
            }

            ssl = SSL_new(ctx);
            if (ssl == NULL || SSL_set_fd(ssl, c) != 1
                || SSL_accept(ssl) != 1)
            {
                _exit(2);
            }

            /* Read whatever the client sent (best-effort; the reply below
             * is unconditional so a short or slow request still gets an
             * answer to round-trip) and write the fixture's canned
             * response. */
            (void) SSL_read(ssl, scratch, sizeof(scratch));
            (void) SSL_write(ssl, SPAWN_REPLY, (int) SPAWN_REPLY_LEN);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(c);
        }

        SSL_CTX_free(ctx);
        _exit(0);
    }

    close(srv);
    SSL_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return pid;
}


/*
 * Serve one connection with a LARGE response and report how many reads the
 * client needed. Separate from spawn_echo() because the two want opposite
 * things: that fixture reads a fixed request and answers briefly, this one
 * answers with more than fits in a shrunken receive window.
 *
 * The child writes without waiting for the whole request, so a client that
 * shrank its window cannot deadlock the exchange -- the reply is already on its
 * way while the client is still reading.
 */
/*
 * Serve one connection, answer it, and then deliberately DO NOT close: the
 * child sleeps with the socket still open until the parent is done.
 *
 * This is the fixture the close-deadline assertion exists for, and no existing
 * one can stand in. spawn_echo() always closes, so every case built on it
 * measures a server that behaves; the failure being tested here is a server
 * that answers and then sits on the connection forever. Without this, the
 * TIMEOUT branch is unreachable and the whole directive would be tested only on
 * its passing path -- an assertion whose failing branch nothing can reach is
 * the vacuous gate this repo keeps rediscovering.
 *
 * `linger_ms` bounds the child's life so a hung test cannot wedge the suite;
 * it must comfortably exceed the timeout the parent gives http_request().
 *
 * `reply` chooses which silence is being tested. With it set the child answers
 * and then sits on the open connection, which is what a close deadline judges.
 * With it clear the child answers NOTHING and merely holds the socket open --
 * the idle-but-open state expect_idle asserts, and the one state no other
 * fixture here produces: every other server either replies or closes, and both
 * are failures for an idle wait rather than the pass it needs to observe.
 */
static pid_t
spawn_lingering(int *port, int linger_ms, int reply)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        struct timespec  ts;
        char             scratch[256];
        int              c = accept(srv, NULL, NULL);

        if (c < 0) {
            _exit(2);
        }

        /* Drain one read so the request is off the wire before the reply --
         * otherwise the answer could race ahead of a request still in flight.
         * The count is genuinely uninteresting, but glibc marks read() as
         * warn_unused_result and a bare (void) cast does not silence it, so the
         * result is consumed into a variable the compiler can see. */
        if (read(c, scratch, sizeof(scratch)) < 0) {
            _exit(2);
        }
        if (reply) {
            (void) send(c, SPAWN_REPLY, SPAWN_REPLY_LEN, MSG_NOSIGNAL);
        }

        ts.tv_sec = linger_ms / 1000;
        ts.tv_nsec = (linger_ms % 1000) * 1000000L;
        while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
            /* keep sleeping; the point is to hold the socket open */
        }

        close(c);
        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Fan fixture for the per-read idle deadline: accept `n` connections, answer
 * every one of them, then hold ALL of them open and silent for `linger_ms`.
 *
 * `chatty_ms` is what makes this a fan test rather than N copies of the N=1
 * one. Leg 0 keeps talking -- it emits a byte every `chatty_ms` for the life of
 * the fixture -- while legs 1..n-1 answer once and then go silent. That is the
 * precondition for the failure mode the idle deadline has to survive under a
 * SHARED poll() loop: a chatty sibling wakes the loop constantly, so an
 * implementation that recomputed the idle bound from a fresh timeout_ms on
 * every poll iteration, or kept one idle clock for the whole fan, would let
 * leg 0's traffic postpone the silent legs' deadlines forever. With the
 * deadline held per leg the silent legs expire on their own schedule
 * regardless of how loud leg 0 is.
 *
 * Every leg is answered first (rather than some legs staying wholly silent) so
 * the case under test is specifically the idle-AFTER-response state that
 * want_close judges, not a connect-time failure.
 *
 * All accepts happen before any reply: the client opens every leg before
 * draining any, so accepting lazily would deadlock against its own fan.
 */
static pid_t
spawn_fan_lingering(int *port, int n, int linger_ms, int chatty_ms)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, n) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int              conns[MAX_CONCURRENT];
        int              i;
        long             waited = 0;
        struct timespec  ts;
        char             scratch[256];

        /* Same guard the sibling fixtures carry, and for the same reason: `n`
         * indexes a fixed array in the FORKED CHILD, so an oversized fan would
         * write past it there rather than in the test process -- surfacing as
         * an ASan report with no obvious connection to the caller instead of a
         * clear failure. `chatty_ms <= 0` is fatal for a different reason:
         * nanosleep(0) with `waited += 0` never advances, so the child spins
         * forever and the case hangs instead of failing. */
        if (n > MAX_CONCURRENT || chatty_ms <= 0) {
            _exit(2);
        }

        for (i = 0; i < n; i++) {
            conns[i] = accept(srv, NULL, NULL);
            if (conns[i] < 0) {
                _exit(2);
            }

            if (read(conns[i], scratch, sizeof(scratch)) < 0) {
                _exit(2);
            }

            (void) send(conns[i], SPAWN_REPLY, SPAWN_REPLY_LEN, MSG_NOSIGNAL);
        }

        /* Leg 0 keeps the poll loop busy; every other leg stays silent. The
         * trailing byte is deliberately not valid HTTP framing -- this fixture
         * is read to EOF, and the point is only that leg 0 produces readiness
         * events while its siblings produce none. */
        ts.tv_sec = chatty_ms / 1000;
        ts.tv_nsec = (chatty_ms % 1000) * 1000000L;

        while (waited < linger_ms) {
            struct timespec  rem = ts;

            while (nanosleep(&rem, &rem) != 0 && errno == EINTR) {
                /* keep sleeping */
            }

            (void) send(conns[0], ".", 1, MSG_NOSIGNAL);
            waited += chatty_ms;
        }

        for (i = 0; i < n; i++) {
            close(conns[i]);
        }

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Framed-mode fixture: write `bytes` verbatim (one or two whole framed
 * responses), then HOLD the connection open without closing for `linger_ms`.
 *
 * This is the keep-alive shape no other fixture here produces: spawn_echo()
 * always closes after answering, so a read-to-EOF client ends cleanly against
 * it and framed mode would never be under test. A framed reader must instead
 * stop at the framed end of the response WHILE the peer keeps the socket up --
 * exactly what a keep-alive server does -- and the only way to prove it stops
 * for the right reason (framing, not a FIN it was handed) is a server that never
 * sends the FIN. `linger_ms` bounds the child's life so a framed reader that
 * fails to stop cannot wedge the suite; it must exceed the client's timeout.
 */
static pid_t
spawn_keepalive(int *port, const char *bytes, size_t len, int linger_ms)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        struct timespec  ts;
        char             scratch[256];
        int              c = accept(srv, NULL, NULL);

        if (c < 0) {
            _exit(2);
        }

        /* Drain the request so the reply cannot race ahead of it. */
        if (read(c, scratch, sizeof(scratch)) < 0) {
            _exit(2);
        }

        (void) send(c, bytes, len, MSG_NOSIGNAL);

        /* Hold the socket open: the whole point is that no FIN follows the
         * framed response, so a framed reader must stop on framing alone. */
        ts.tv_sec = linger_ms / 1000;
        ts.tv_nsec = (linger_ms % 1000) * 1000000L;
        while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
            /* keep sleeping */
        }

        close(c);
        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * AUD-07 fixture: send a valid header, then DRIP one byte every `step_ms`
 * forever, never closing. Each byte arrives inside the client's per-read
 * SO_RCVTIMEO window, so that timeout never fires -- the only thing that can
 * end the exchange is the whole-exchange deadline the client now enforces.
 * Without that deadline this loop and the client's read loop run until one of
 * them is killed, which is exactly the hang AUD-07 describes.
 */
static pid_t
spawn_trickle(int *port, int step_ms)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        struct timespec  ts;
        char             scratch[256];
        int              c = accept(srv, NULL, NULL);

        if (c < 0) {
            _exit(2);
        }

        if (read(c, scratch, sizeof(scratch)) < 0) {
            _exit(2);
        }

        (void) send(c, "HTTP/1.1 200 OK\r\n", 17, MSG_NOSIGNAL);

        ts.tv_sec = step_ms / 1000;
        ts.tv_nsec = (step_ms % 1000) * 1000000L;

        for ( ;; ) {
            while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
                /* finish the interval */
            }
            ts.tv_sec = step_ms / 1000;
            ts.tv_nsec = (step_ms % 1000) * 1000000L;

            if (send(c, "x", 1, MSG_NOSIGNAL) != 1) {
                /* client gave up and closed -- the deadline did its job */
                break;
            }
        }

        close(c);
        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * The overlap barrier: accept exactly `want` connections, read a request from
 * each, and reply to NONE of them until all `want` are simultaneously connected
 * and have sent their request.
 *
 * This fixture is the whole reason http_exchange_concurrent() can be tested at
 * all. Every other assertion available to a concurrent fan -- N responses
 * arrived, N are well-formed, the delta is clean -- is satisfied just as well by
 * N sequential exchanges, so none of them can tell the directive from a loop
 * around http_request(). A barrier can: if the driver ever reads leg 0's
 * response before writing leg 1's request, the reply to leg 0 does not exist
 * yet, nothing further is written, and the exchange dies on its deadline rather
 * than passing.
 *
 * Note what this does and does not establish. It is a genuine negative control
 * for the CLIENT-SIDE write-all-before-read-any ordering, which is the property
 * the driver actually implements. It does not prove N request lifetimes overlap
 * in a real server -- the overlap here exists because this fixture deliberately
 * withholds every reply, i.e. the barrier supplies the server-side hold itself.
 * A live nginx offers no such guarantee.
 *
 * `listen(srv, want)` because all `want` connects land before any accept: a
 * shorter backlog would drop the tail and deadlock the barrier for a reason
 * unrelated to the code under test.
 */
static pid_t
spawn_barrier(int *port, int want)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, want) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int   conns[MAX_BARRIER];
        char  scratch[512];
        int   i;

        if (want > MAX_BARRIER) {
            _exit(2);
        }

        /* Phase 1: collect all `want` connections and their requests. Nothing
         * is written back here -- that is the barrier. */
        for (i = 0; i < want; i++) {
            conns[i] = accept(srv, NULL, NULL);

            if (conns[i] < 0) {
                _exit(2);
            }

            if (read(conns[i], scratch, sizeof(scratch)) < 0) {
                _exit(2);
            }
        }

        /* Phase 2: only now does anyone get an answer. A Content-Length reply
         * so the client's reader has a framed end and never waits on EOF. */
#define BARRIER_REPLY  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

        for (i = 0; i < want; i++) {
            /* Length from sizeof, never a hand-counted literal: a short count
             * here truncates the body and the client reads a well-formed but
             * WRONG response, which reads as a driver bug rather than a fixture
             * typo. */
            (void) send(conns[i], BARRIER_REPLY, sizeof(BARRIER_REPLY) - 1,
                        MSG_NOSIGNAL);
            close(conns[i]);
        }

#undef BARRIER_REPLY

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Paced-fan fixture: accept `want` connections and answer EVERY one of them
 * immediately with the same read-to-EOF body, then close.
 *
 * This exists because `recv_slow` had no concurrent runtime fixture at all, so
 * the fan-pacing mutant ("concurrent: paced leg polled anyway") was killed by
 * the N=1 pacing assertion instead of by anything that exercises a fan. That
 * made the mutant a false control: it proved the gate is consulted SOMEWHERE,
 * not that a fan honours one gate per leg.
 *
 * The mistakes it has to discriminate are all fan-only, and all invisible at
 * N=1 because one leg cannot be confused with its siblings:
 *
 *   - one leg's closed gate blocking the whole poll loop (pacing back to being
 *     a sleep, which is the serialization S-4 exists to remove);
 *   - a gated fd left in the pollfd set, so a sibling's readiness cancels a
 *     delay the case asked for;
 *   - per-leg pacing state shared or aliased across legs, so the fan sleeps
 *     once rather than once per leg.
 *
 * Every leg gets the SAME reply and the same gate schedule, so each leg's own
 * `paced_sleep_ms` is an independent witness and the assertion is an equality
 * per leg rather than an aggregate. An aggregate would not discriminate: a fan
 * that slept once for the whole fan and one that slept per leg are told apart
 * only by asking each leg what IT slept. This is the same per-leg-witness rule
 * the idle-deadline fan case had to learn -- see the note at that loop.
 *
 * Answering immediately and closing (rather than stalling like the readback
 * fixture) is deliberate: the quantity under test is the CLIENT's withheld
 * read, so the server must contribute no delay of its own for the counter to
 * mean what it says.
 */
static pid_t
spawn_fan_paced(int *port, int want)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, want) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int   conns[MAX_CONCURRENT];
        char  scratch[512];
        int   i;

        /* Same bound-check the sibling fan fixtures carry: `want` indexes a
         * fixed array in the FORKED CHILD, so an oversized fan corrupts memory
         * over there and surfaces as an ASan report with no visible link to the
         * caller. */
        if (want > MAX_CONCURRENT) {
            _exit(2);
        }

        /* Every accept before any reply, as the other fan fixtures do: the
         * client opens all N legs before draining any, so answering lazily
         * would deadlock against its own fan. */
        for (i = 0; i < want; i++) {
            conns[i] = accept(srv, NULL, NULL);

            if (conns[i] < 0) {
                _exit(2);
            }

            if (read(conns[i], scratch, sizeof(scratch)) < 0) {
                _exit(2);
            }
        }

        for (i = 0; i < want; i++) {
            (void) send(conns[i], SPAWN_REPLY, SPAWN_REPLY_LEN, MSG_NOSIGNAL);
            close(conns[i]);
        }

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Two-legs-fail fixture: accept `want` connections and answer them so that
 * legs 1 and 2 fail in the SAME drain iteration with DISTINGUISHABLE errors,
 * while legs 0 and 3 succeed.
 *
 * The fan's failure contract is first-by-index (http.c, the loop after the
 * drain): when several legs failed, the reported error is the lowest-indexed
 * failing leg's, read out of that leg's OWN error slot. Both halves were
 * unpinned -- no test made two legs fail at once, so nothing distinguished
 * first-by-index from last-to-fail, and nothing caught the slot bookkeeping
 * reading whichever leg wrote to the shared buffer last (PR #151 F4).
 *
 * The two failures are deliberately made in framed mode and given different
 * shapes so the MESSAGE identifies which leg was blamed:
 *
 *   leg 1: a 200 with no Content-Length, no chunked coding and a body -- its
 *          end is unknowable, so the framed reader calls it UNFRAMEABLE;
 *   leg 2: a Content-Length that is not a number -- MALFORMED framing.
 *
 * Both are terminal on the first read, so both legs fail within one iteration
 * of the drain loop rather than one failing several polls after the other.
 * That simultaneity is the point: it is what makes "first by INDEX" a
 * different prediction from "first by TIME", which is the whole reason the
 * driver documents the index rule (index is reproducible across runs and can
 * be bisected; arrival order moves).
 *
 * Legs 0 and 3 answer correctly so the case cannot pass by the fan simply
 * collapsing -- a driver that failed every leg would satisfy an assertion that
 * only looked for "leg 2" in the message.
 */
static pid_t
spawn_fan_two_bad(int *port, int want)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, want) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int   conns[MAX_CONCURRENT];
        char  scratch[512];
        int   i;

        /* The forked-child bound check the sibling fan fixtures carry. This
         * fixture additionally REQUIRES want == 4: the reply chosen per leg is
         * indexed below, so a different width would silently give some leg a
         * reply the assertions do not model. */
        if (want != 4 || want > MAX_CONCURRENT) {
            _exit(2);
        }

        for (i = 0; i < want; i++) {
            conns[i] = accept(srv, NULL, NULL);

            if (conns[i] < 0) {
                _exit(2);
            }

            if (read(conns[i], scratch, sizeof(scratch)) < 0) {
                _exit(2);
            }
        }

/* Framed and correct: legs 0 and 3. */
#define TWOBAD_GOOD    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
/* No Content-Length, no chunking, but a body: end unknowable -> UNFRAMEABLE. */
#define TWOBAD_UNFRAM  "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi"
/* A Content-Length that is not a number -> MALFORMED. */
#define TWOBAD_MALF    "HTTP/1.1 200 OK\r\nContent-Length: xx\r\n\r\nhi"

        for (i = 0; i < want; i++) {
            const char  *reply;
            size_t       len;

            if (i == 1) {
                reply = TWOBAD_UNFRAM;
                len = sizeof(TWOBAD_UNFRAM) - 1;

            } else if (i == 2) {
                reply = TWOBAD_MALF;
                len = sizeof(TWOBAD_MALF) - 1;

            } else {
                reply = TWOBAD_GOOD;
                len = sizeof(TWOBAD_GOOD) - 1;
            }

            /* Length from sizeof, never hand-counted: a short count truncates
             * the reply and the client sees a well-formed but WRONG response,
             * which reads as a driver bug rather than a fixture typo. */
            (void) send(conns[i], reply, len, MSG_NOSIGNAL);
        }

#undef TWOBAD_GOOD
#undef TWOBAD_UNFRAM
#undef TWOBAD_MALF

        /*
         * Hold every connection OPEN. The unframeable leg is only unframeable
         * while the connection stays up -- closing it would supply an EOF that
         * frames the body after all, and leg 1 would succeed. The parent kills
         * this child once the case is done.
         */
        {
            struct timespec  ts;

            ts.tv_sec = 30;
            ts.tv_nsec = 0;

            while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
                /* held open until the parent kills us */
            }
        }

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * The out-of-order fixture, S-4. Accept `want` connections, then make answering
 * leg 0 DEPEND on the client having drained the last leg.
 *
 * >> WHY THE OBVIOUS FIXTURE DOES NOT WORK, because it was tried first and it
 * passed against the very drain it was written to catch.
 *
 * The intuitive version simply answers the legs in reverse order and stalls
 * before leg 0. It does not discriminate: while the in-order drain blocks in
 * leg 0's read(), the kernel is receiving legs 1..N-1 concurrently into their
 * socket buffers, so once leg 0 finally answers the remaining legs are already
 * complete and are collected instantly. Both drains finish at
 * max(answer_time) -- measured at 401 ms against a 400 ms stall for BOTH. Any
 * fixture whose server answers on its own schedule is therefore blind to drain
 * order, and an elapsed-time bound over it is vacuous in the S-3 sense.
 *
 * What an in-order drain genuinely cannot do is REACT to a later leg before an
 * earlier one completes. So the dependency has to run through the client: this
 * server sends a body on the last leg that is far larger than the socket
 * buffer, so its own send() blocks partway until the client drains it, and only
 * once that send completes does it answer leg 0.
 *
 *   - poll() drain: legs 1..N-1 are readable, so the client drains the big
 *     body, the server's send() completes, leg 0 is answered, the fan finishes.
 *   - in-order drain: the client is blocked in leg 0's read(); it never drains
 *     the big body; the server stays blocked in send() and never answers leg 0.
 *     Deadlock, broken only by the whole-exchange deadline -- a hard failure,
 *     not a slow pass.
 *
 * That makes this a true negative control: the property under test is the only
 * thing standing between the fan and a timeout.
 */
static pid_t
spawn_readback(int *port, int want, size_t big_len)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    /*
     * FORCE the small receive window this fixture's dependency rests on,
     * rather than assuming the platform's default is smaller than `big_len`.
     *
     * The dependency exists only while the server's send() cannot be absorbed
     * whole: the body has to sit unsent until the CLIENT drains it. The
     * original fixture argued that from a comment -- "4 MiB is far above any
     * socket buffer this test could meet" -- which is an assumption about
     * loopback autotuning, not a precondition the test establishes (PR #151
     * F4). If a kernel, container or future tuning ever buffered 4 MiB, the
     * send() would complete immediately, leg 0 would be answered without the
     * client having read anything, and the case would pass against the very
     * in-order drain it exists to catch: vacuous, and still green.
     *
     * Set on the LISTENING socket because accepted sockets inherit it, and it
     * must be set before listen() for the value to be carried into the
     * handshake's advertised window. This bounds the SERVER's receive side --
     * the ~40-byte request -- and is NOT by itself what blocks the big send().
     * The load-bearing half is the SO_SNDBUF on the big-body connection in the
     * child, which cannot absorb `big_len` whatever the client's own (untouched)
     * receive window turns out to be. Both ends are pinned so neither is
     * inherited from the host's tuning; do not drop the SO_SNDBUF believing
     * this call already covered the client side.
     *
     * Advisory, and deliberately unchecked: Linux doubles the request for
     * bookkeeping and enforces a floor, so the effective size is larger than
     * asked but still three orders of magnitude below `big_len`. A kernel that
     * refuses the hint outright leaves the autotuned behaviour this fixture
     * used to rely on, so the hint can only improve the precondition.
     */
    {
        int  small = 16 * 1024;

        (void) setsockopt(srv, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, want) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int   conns[MAX_BARRIER];
        char  scratch[512];
        int   i;

        if (want > MAX_BARRIER) {
            _exit(2);
        }

        /* Collect every connection and its request first, exactly as the
         * barrier does: the reversal must be in the ANSWERING order, not in
         * which connections exist. */
        for (i = 0; i < want; i++) {
            conns[i] = accept(srv, NULL, NULL);

            if (conns[i] < 0) {
                _exit(2);
            }

            if (read(conns[i], scratch, sizeof(scratch)) < 0) {
                _exit(2);
            }
        }

#define SMALL_REPLY  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

        /* Middle legs: small, immediate, closed. Nothing depends on them; they
         * exist so the fan is genuinely N-way rather than a special-cased 2. */
        for (i = 1; i < want - 1; i++) {
            (void) send(conns[i], SMALL_REPLY, sizeof(SMALL_REPLY) - 1,
                        MSG_NOSIGNAL);
            close(conns[i]);
        }

        /*
         * The LAST leg carries a body far larger than the socket buffer, so
         * this send() cannot complete until the client reads most of it. This
         * is the dependency the whole fixture turns on -- see the header.
         */
        {
            char   *hdr;
            char   *body;
            size_t  off;
            int     small = 16 * 1024;

            /* The send side of the same precondition -- see the note at the
             * listening socket. Bounding BOTH buffers is what makes "this
             * send() blocks partway" a property the fixture establishes rather
             * than one it inherits from the host's tuning. */
            (void) setsockopt(conns[want - 1], SOL_SOCKET, SO_SNDBUF,
                              &small, sizeof(small));

            hdr = malloc(128);
            body = malloc(big_len);

            if (hdr == NULL || body == NULL) {
                _exit(2);
            }

            memset(body, 'x', big_len);
            snprintf(hdr, 128,
                     "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", big_len);

            (void) send(conns[want - 1], hdr, strlen(hdr), MSG_NOSIGNAL);

            off = 0;
            while (off < big_len) {
                ssize_t w = send(conns[want - 1], body + off, big_len - off,
                                 MSG_NOSIGNAL);

                if (w <= 0) {
                    /* The client gave up (in-order drain deadlocked and the
                     * case timed out). Leave leg 0 unanswered: that is the
                     * failure the assertion is there to see. */
                    _exit(0);
                }

                off += (size_t) w;
            }

            close(conns[want - 1]);
            free(hdr);
            free(body);
        }

        /* Only now -- the big body is fully handed over, which proves the
         * client drained a LATER leg while leg 0 was still outstanding. */
        (void) send(conns[0], SMALL_REPLY, sizeof(SMALL_REPLY) - 1,
                    MSG_NOSIGNAL);
        close(conns[0]);

#undef SMALL_REPLY

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Serve one connection and RESET it instead of closing cleanly.
 *
 * The mirror of the abort fixtures: those have the CLIENT reset and observe it
 * from the server side, which says nothing about how http_request() classifies
 * a reset arriving at the client. SO_LINGER{1,0} makes the child's close(2)
 * emit RST, so the prober's read fails with ECONNRESET rather than seeing EOF.
 *
 * That distinction is load-bearing for the close deadline: the read loop's
 * error branch catches every failure that is not EINTR or the EAGAIN timeout,
 * so without a fixture that produces a genuine ECONNRESET there is nothing to
 * stop an EBADF being reported to a rule author as "the server reset the
 * connection".
 */
static pid_t
spawn_resetting(int *port, int reply_first)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        struct linger  lg;
        char           scratch[256];
        int            c = accept(srv, NULL, NULL);

        if (c < 0) {
            _exit(2);
        }

        if (read(c, scratch, sizeof(scratch)) < 0) {
            _exit(2);
        }

        /* Optionally answer first, so the reset lands on a connection that
         * already carried a complete response -- the case a rule would judge
         * with both an `expect status=` and a close deadline. */
        if (reply_first) {
            (void) send(c, SPAWN_REPLY, SPAWN_REPLY_LEN, MSG_NOSIGNAL);
        }

        lg.l_onoff = 1;
        lg.l_linger = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

        close(c);
        _exit(0);
    }

    close(srv);

    return pid;
}


/* The common case: no shutdown, no abort, so the cases that predate those
 * directives read exactly as they did. */
static int
run_echo(const unsigned char *req, size_t req_len,
         const http_pause *pauses, size_t n_pauses, echo_result *out)
{
    return run_echo_full(req, req_len, pauses, n_pauses, HTTP_SHUT_NONE,
                         HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, 0, 0,
                         HTTP_IDLE_NONE, out);
}


static int
run_echo_shut(const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses, int shut_how,
              int want_eof, echo_result *out)
{
    return run_echo_full(req, req_len, pauses, n_pauses, shut_how,
                         HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, want_eof, 0,
                         HTTP_IDLE_NONE, out);
}


/*
 * Drive an aborting request. `want_len` is passed separately from req_len
 * because the client writes only the prefix before the reset: telling the
 * fixture to expect the whole request would leave its read loop blocked on
 * bytes that are never sent, and the reset would be observed by the timeout
 * rather than by the read. want_eof is always on -- the extra read is what
 * turns the reset into ECONNRESET rather than an unnoticed teardown.
 */
static int
run_echo_abort(const unsigned char *req, size_t req_len, size_t want_len,
               const http_pause *pauses, size_t n_pauses, size_t abort_at,
               echo_result *out)
{
    int            fds[2], port = 0;
    pid_t          pid;
    http_response  resp;
    char           errbuf[256];
    int            rc, st;

    if (pipe(fds) != 0) {
        return -1;
    }

    pid = spawn_echo(&port, want_len, 1, fds[1]);
    close(fds[1]);

    rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                      pauses, n_pauses, HTTP_SHUT_NONE, abort_at,
                      HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 0, NULL, &resp,
                      errbuf, sizeof(errbuf));

    if (rc == 0) {
        http_response_free(&resp);
    }

    memset(out, 0, sizeof(*out));

    if (read(fds[0], out, sizeof(*out)) != (ssize_t) sizeof(*out)) {
        rc = -1;
    }

    close(fds[0]);
    waitpid(pid, &st, 0);

    return rc;
}


int
main(void)
{
    http_response  r;

    printf("1..%d\n", PLANNED);

    /* ---- splitting a well-formed response ----------------------------- */

    PARSE(&r, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello");
    ok(r.status == 200, "the status code is parsed");
    ok(r.headers != NULL
       && strcmp(r.headers, "HTTP/1.1 200 OK\r\nContent-Type: text/plain") == 0,
       "the header block ends before the terminator, no trailing CRLF");
    ok(r.body_len == 5 && r.body != NULL && memcmp(r.body, "hello", 5) == 0,
       "the body starts after the terminator");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 204 No Content\r\nServer: t\r\n\r\n");
    ok(r.body != NULL && r.body_len == 0,
       "an empty body is present with length zero, not missing");
    http_response_free(&r);

    /* ---- no header terminator ----------------------------------------- */

    /* A truncated response must not be guessed at: headers == NULL is the
     * signal that distinguishes a reset mid-headers from an empty reply. */
    PARSE(&r, "HTTP/1.1 200 OK\r\nContent-Ty");
    ok(r.headers == NULL, "no CRLFCRLF leaves headers NULL");
    ok(r.body == NULL && r.body_len == 0, "no CRLFCRLF leaves no body");
    ok(r.status == 200, "the status still parses without a terminator");
    http_response_free(&r);

    /* ---- bodies the framing must not trip over ------------------------ */

    PARSE(&r, "HTTP/1.1 200 OK\r\n\r\nfirst\r\n\r\nsecond");
    ok(r.body_len == 15 && memcmp(r.body, "first\r\n\r\nsecond", 15) == 0,
       "a body containing CRLFCRLF splits at the FIRST terminator");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 200 OK\r\n\r\nab\0cd");
    ok(r.body_len == 5 && r.body[2] == '\0' && memcmp(r.body, "ab\0cd", 5) == 0,
       "an embedded NUL in the body is counted, not terminating");
    http_response_free(&r);

    /* ---- dechunk ------------------------------------------------------- */

#define CHUNKED_HDR  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

    PARSE(&r, CHUNKED_HDR "5\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK, "a single chunk decodes");
    ok(r.decoded_len == 5 && memcmp(r.decoded, "hello", 5) == 0,
       "the decoded body is the chunk payload without its framing");
    ok(r.body_len == 15 && memcmp(r.body, "5\r\nhello\r\n0\r\n\r\n", 15) == 0,
       "the RAW body still holds the wire bytes after a decode");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK
       && r.decoded_len == 11 && memcmp(r.decoded, "hello world", 11) == 0,
       "consecutive chunks are concatenated in order");
    http_response_free(&r);

    /* Hex is case-insensitive and a size may carry leading zeros; both spellings
     * are legal framing that a stricter reader would reject as malformed. */
    PARSE(&r, CHUNKED_HDR "00A\r\n0123456789\r\n0\r\n\r\n");
    ok((http_dechunk(&r), r.dechunk_status) == HTTP_DECHUNK_OK
       && r.decoded_len == 10,
       "a zero-padded hex size decodes");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "b\r\n0123456789a\r\nB\r\nbcdefghijkl\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK && r.decoded_len == 22,
       "mixed-case hex in a size line decodes");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "5;name=value\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK
       && r.decoded_len == 5 && memcmp(r.decoded, "hello", 5) == 0,
       "a chunk extension is skipped, not treated as part of the size");
    http_response_free(&r);

    /* Chunk data is opaque: CRLF and NUL inside a chunk are payload, and a
     * decoder that scanned for delimiters instead of honouring the declared
     * length would cut the body short right here. */
    PARSE(&r, CHUNKED_HDR "8\r\na\r\n\r\nb\0c\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK
       && r.decoded_len == 8 && memcmp(r.decoded, "a\r\n\r\nb\0c", 8) == 0,
       "CRLF and NUL inside a chunk are payload, counted by the declared size");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK && r.decoded_len == 0,
       "a body of only the terminating chunk decodes to zero bytes");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK
       && r.decoded_len == 5 && memcmp(r.decoded, "hello", 5) == 0,
       "trailers after the 0-chunk are not decoded as body bytes");
    http_response_free(&r);

    /* The roadmap's [no-last-chunk]: every chunk well formed, terminator
     * missing. This is the one that looks like a complete response to anything
     * that only validates the chunks it did receive. */
    PARSE(&r, CHUNKED_HDR "5\r\nhello\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_NO_LAST_CHUNK,
       "a body ending on a chunk boundary with no 0-chunk is NO_LAST_CHUNK");
    ok(r.decoded == NULL,
       "a framing error yields no decoded body to assert on");
    http_response_free(&r);

    /* The declared size must exceed everything still in the buffer, not merely
     * the intended payload: with more chunks following, the decoder finds the
     * bytes and fails the CRLF check instead, which is a different verdict. */
    PARSE(&r, CHUNKED_HDR "20\r\nhello");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_TRUNCATED,
       "a chunk declaring more bytes than arrived is TRUNCATED");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "5\r\nhelloXX0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_BAD_CRLF,
       "chunk data not followed by CRLF is BAD_CRLF");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "zz\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_BAD_SIZE,
       "a non-hex chunk size is BAD_SIZE");
    http_response_free(&r);

    PARSE(&r, CHUNKED_HDR "\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_BAD_SIZE,
       "an empty chunk size line is BAD_SIZE, not a zero-length chunk");
    http_response_free(&r);

    /* A size wide enough to wrap size_t. Accepting this would hand a small
     * value to the memcpy below a huge declared length -- the request smuggling
     * primitive the overflow check exists to stop. */
    PARSE(&r, CHUNKED_HDR "FFFFFFFFFFFFFFFFF\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_BAD_SIZE,
       "a chunk size that overflows size_t is rejected, not wrapped");
    http_response_free(&r);

    /* A bare LF instead of CRLF: lenient framing here is the parser
     * differential that lets two hops disagree about where a chunk starts. */
    PARSE(&r, CHUNKED_HDR "5\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_BAD_SIZE,
       "a size line ended by a bare LF is rejected");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_NOT_CHUNKED,
       "an identity body reports NOT_CHUNKED rather than a framing error");
    http_response_free(&r);

    /* Spacing after the colon is not fixed and a coding list still means the
     * wire body is chunked; reporting either as NOT_CHUNKED would quietly skip
     * the oracle. */
    PARSE(&r, "HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n\r\n"
              "5\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK,
       "no space after the Transfer-Encoding colon still decodes");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked\r\n\r\n"
              "5\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK,
       "a lowercase header naming a coding list still decodes");
    http_response_free(&r);

    /* Calling it twice must recompute rather than leak or double-free the
     * first buffer -- the decode is idempotent by contract. */
    PARSE(&r, CHUNKED_HDR "5\r\nhello\r\n0\r\n\r\n");
    http_dechunk(&r);
    http_dechunk(&r);
    ok(r.dechunk_status == HTTP_DECHUNK_OK && r.decoded_len == 5,
       "decoding twice recomputes the same result");
    http_response_free(&r);

    ok(strcmp(http_dechunk_reason(HTTP_DECHUNK_NO_LAST_CHUNK),
              "no terminating 0-chunk") == 0
       && strcmp(http_dechunk_reason(-1), "unknown dechunk status") == 0,
       "every status renders a reason, unknown codes included");

#undef CHUNKED_HDR

    /* ---- json_sort ----------------------------------------------------- */

#define JHDR  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"

    /* A JSON body canonicalizes: keys sorted, so resp->canon is order-normalized
     * and body_bytes (via the assertion layer) reads it. Here we test the
     * transform + its status directly. */
    PARSE(&r, JHDR "{\"b\":1,\"a\":2}");
    http_json_sort(&r);
    ok(r.json_sort_status == HTTP_JSON_SORT_OK
       && r.canon != NULL
       && r.canon_len == strlen("{\"a\":2,\"b\":1}")
       && memcmp(r.canon, "{\"a\":2,\"b\":1}", r.canon_len) == 0,
       "json_sort canonicalizes the body with keys sorted");
    ok(r.body_len == strlen("{\"b\":1,\"a\":2}")
       && memcmp(r.body, "{\"b\":1,\"a\":2}", r.body_len) == 0,
       "the RAW body still holds the pre-canonical wire bytes");
    http_response_free(&r);

    /* Two orderings, one canonical form -- the property json_sort exists for. */
    {
        http_response  a, b;

        PARSE(&a, JHDR "{\"x\":1,\"y\":2}");
        PARSE(&b, JHDR "{\"y\":2,\"x\":1}");
        http_json_sort(&a);
        http_json_sort(&b);
        ok(a.json_sort_status == HTTP_JSON_SORT_OK
           && b.json_sort_status == HTTP_JSON_SORT_OK
           && a.canon_len == b.canon_len
           && memcmp(a.canon, b.canon, a.canon_len) == 0,
           "two key orderings produce the same canonical body");
        http_response_free(&a);
        http_response_free(&b);
    }

    /* A body that is not JSON is a FAILURE here, not a quiet skip: NOT_JSON so
     * the prober fails the case rather than falling back to raw bytes. */
    PARSE(&r, JHDR "this is not json");
    http_json_sort(&r);
    ok(r.json_sort_status == HTTP_JSON_SORT_NOT_JSON && r.canon == NULL,
       "a non-JSON body reports NOT_JSON and leaves canon NULL");
    http_response_free(&r);

    /* An empty body has nothing to canonicalize -> NOT_JSON, not a vacuous OK. */
    PARSE(&r, JHDR);
    http_json_sort(&r);
    ok(r.json_sort_status == HTTP_JSON_SORT_NOT_JSON && r.canon == NULL,
       "an empty body reports NOT_JSON rather than a vacuous canonical form");
    http_response_free(&r);

    /* Trailing garbage after a valid document is rejected (json_parse_n length-
     * delimited) -- valid-prefix-then-junk must not canonicalize the prefix. */
    PARSE(&r, JHDR "{\"a\":1}trailing");
    http_json_sort(&r);
    ok(r.json_sort_status == HTTP_JSON_SORT_NOT_JSON && r.canon == NULL,
       "valid JSON followed by trailing garbage reports NOT_JSON");
    http_response_free(&r);

    /* Idempotent: canonicalizing twice recomputes the same result and does not
     * leak the first buffer (checked under ASan in CI). */
    PARSE(&r, JHDR "{\"b\":1,\"a\":2}");
    http_json_sort(&r);
    http_json_sort(&r);
    ok(r.json_sort_status == HTTP_JSON_SORT_OK
       && memcmp(r.canon, "{\"a\":2,\"b\":1}", r.canon_len) == 0,
       "canonicalizing twice recomputes the same result");
    http_response_free(&r);

    ok(strcmp(http_json_sort_reason(HTTP_JSON_SORT_NOT_JSON),
              "body did not parse as JSON") == 0
       && strcmp(http_json_sort_reason(-1), "unknown json_sort status") == 0,
       "every json_sort status renders a reason, unknown codes included");

#undef JHDR

    PARSE(&r, "\r\n\r\nbody");
    ok(r.headers != NULL && r.headers[0] == '\0' && r.body_len == 4,
       "a leading terminator yields an empty header block");
    http_response_free(&r);

    /* ---- status line edge cases --------------------------------------- */

    PARSE(&r, "HTTP/1.0 302 Found\r\n\r\n");
    ok(r.status == 302, "HTTP/1.0 parses like HTTP/1.1");
    http_response_free(&r);

    /* http.h promises -1 for anything unparseable. Bare strtol returns 0 here,
     * which a rule could match against a literal "0" status, so the end pointer
     * decides instead. */
    PARSE(&r, "HTTP/1.1 abc def\r\n\r\n");
    ok(r.status == -1, "a non-numeric status is unparseable, not 0");
    http_response_free(&r);

    /* A one-digit token is not a status-code: RFC 9110 spells it 3DIGIT. This
     * used to parse as 0 because strtol takes any digit count. */
    PARSE(&r, "HTTP/1.1 0 Zero\r\n\r\n");
    ok(r.status == -1, "a one-digit status token is unparseable, not 0");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 000 Zero\r\n\r\n");
    ok(r.status == 0, "a three-digit 000 is a status and is not confused with unparseable");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1_200_OK\r\n\r\n");
    ok(r.status == -1, "a response with no space anywhere has no status");
    http_response_free(&r);

    /* A doubled space is a malformed status line. strtol used to skip it
     * silently, which is the same looseness that made "204junk" a 204. */
    PARSE(&r, "HTTP/1.1  200 OK\r\n\r\n");
    ok(r.status == -1, "a doubled space before the code yields no status");
    http_response_free(&r);

    /* The old ">12 bytes" guard existed only to make sure a status line
     * fragment had room for "HTTP/1.1 200". That magic number is gone: the
     * version-token walk itself proves there is a well-formed "HTTP/x.y "
     * prefix, and the three digits may be ended by end-of-buffer as well as by
     * a delimiter, so a buffer that stops right after the code still parses.
     * Length is no longer what gates this; token well-formedness is. */
    PARSE(&r, "HTTP/1.1 200");
    ok(r.status == 200, "the buffer may end right after the code, no trailing byte needed");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 200 ");
    ok(r.status == 200, "a trailing space after the code also parses fine");
    http_response_free(&r);

    /* ---- the status token must be exactly three digits ----------------- */

    /* The framing defect this section exists for: a numeric PREFIX used to
     * parse, so a lying "204junk" was classified bodiless and its declared
     * body was left on the socket for the next pipelined read. */
    PARSE(&r, "HTTP/1.1 204junk\r\nContent-Length: 4\r\n\r\nbody");
    ok(r.status == -1, "a status code with garbage fused onto it yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 2000 OK\r\n\r\n");
    ok(r.status == -1, "a four-digit status token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 20 OK\r\n\r\n");
    ok(r.status == -1, "a two-digit status token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 +200 OK\r\n\r\n");
    ok(r.status == -1, "a signed status token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 -200 OK\r\n\r\n");
    ok(r.status == -1, "a negative status token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 20\r\n\r\n");
    ok(r.status == -1, "a short status token ended by CR yields no status");
    http_response_free(&r);

    /* Two digits followed by a SP that is then followed by another SP: the
     * third position holds a delimiter, and the position after it holds one
     * too. Only checking that all three positions are digits rejects this --
     * dropping the third-digit check alone leaves the shape looking terminated
     * and scores a code computed from a space. */
    PARSE(&r, "HTTP/1.1 20  x\r\n\r\n");
    ok(r.status == -1,
       "a two-digit code padded to three positions by a space yields no status");
    http_response_free(&r);

    /* CR ends the token as legitimately as SP: the reason phrase is optional. */
    PARSE(&r, "HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n");
    ok(r.status == 204, "a status line with no reason phrase parses");
    http_response_free(&r);

    PARSE(&r, "SMTP/1.1 200 OK\r\nX: y\r\n\r\nbody");
    ok(r.status == -1, "a non-HTTP prefix yields no status");
    ok(r.headers != NULL && r.body_len == 4,
       "the header/body split does not depend on the status line");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 99999999999999999999 OK\r\n\r\n");
    ok(r.headers != NULL,
       "a status far past the integer range still parses the response");
    http_response_free(&r);

    /* ---- malformed version tokens (the false-PASS class) --------------- */

    /* This is the exact defect: "HTTP/" matched, garbage after it, first
     * space in the buffer happened to precede a real-looking status. A rule
     * asserting status=200 against this must fail, not pass on garbage. */
    PARSE(&r, "HTTP/xyz 200 OK\r\n\r\n");
    ok(r.status == -1, "a non-numeric version token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/ 200 OK\r\n\r\n");
    ok(r.status == -1, "an empty version token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1 200 OK\r\n\r\n");
    ok(r.status == -1, "a version with no '.' and no minor yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1. 200 OK\r\n\r\n");
    ok(r.status == -1, "a '.' with no minor digits yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/.1 200 OK\r\n\r\n");
    ok(r.status == -1, "a '.' with no major digits yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1x 200 OK\r\n\r\n");
    ok(r.status == -1,
       "trailing garbage fused onto the minor version yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/2 200 OK\r\n\r\n");
    ok(r.status == -1,
       "a bare major-only \"HTTP/2\" (no minor) yields no status");
    http_response_free(&r);

    /* Multi-digit major/minor must still be accepted -- the token walk is
     * digit-run based, not single-digit. */
    PARSE(&r, "HTTP/10.99 200 OK\r\n\r\n");
    ok(r.status == 200, "multi-digit major.minor still parses");
    http_response_free(&r);

    /* A version token that runs off the end of the buffer with no space to
     * terminate it must not read past raw_len or parse a status. */
    PARSE(&r, "HTTP/1.1");
    ok(r.status == -1,
       "a version token with nothing past it yields no status");
    http_response_free(&r);

    /* An embedded NUL inside what would be the version token must not be
     * treated as a terminator or as a digit -- the scan is byte-counted
     * against raw_len, never a C-string scan. */
    PARSE(&r, "HTTP/1\0.1 200 OK\r\n\r\n");
    ok(r.status == -1, "an embedded NUL inside the version token yields no status");
    http_response_free(&r);

    /* ---- the empty and the absent ------------------------------------- */

    PARSE(&r, "");
    ok(r.status == -1 && r.headers == NULL && r.body == NULL,
       "an empty response parses to nothing without crashing");
    http_response_free(&r);

    memset(&r, 0, sizeof(r));
    http_parse_response(&r);
    ok(r.status == -1 && r.headers == NULL,
       "a NULL raw buffer parses to nothing without crashing");

    http_response_free(NULL);
    ok(1, "http_response_free tolerates NULL");

    PARSE(&r, "HTTP/1.1 200 OK\r\n\r\nx");
    http_response_free(&r);
    ok(r.raw == NULL && r.headers == NULL && r.body == NULL
       && r.raw_len == 0 && r.body_len == 0,
       "http_response_free clears every field it owns");

    /* ---- http_has_header ---------------------------------------------- */

    PARSE(&r, "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain\r\n"
              "X-Ban: active\r\n"
              "\r\n"
              "X-Body: not a header");

    ok(http_has_header(&r, "Content-Type: text/plain") == 1,
       "a whole header line matches");
    ok(http_has_header(&r, "content-TYPE") == 1,
       "the search is case-insensitive");
    ok(http_has_header(&r, "Type: text") == 1,
       "a substring within one line matches");
    ok(http_has_header(&r, "plain\r\nX-Ban") == 0,
       "a needle spanning two lines does not match across the CRLF");
    ok(http_has_header(&r, "X-Ban: active") == 1,
       "the last line matches without a trailing CRLF");
    ok(http_has_header(&r, "X-Body: not a header") == 0,
       "the body is not searched");
    ok(http_has_header(&r,
       "a needle longer than any single header line matches nothing") == 0,
       "a needle longer than every line does not match");

    /* An empty needle matches any non-empty header block. Odd, but pinned:
     * if this ever changes it should change on purpose, not by accident. */
    ok(http_has_header(&r, "") == 1,
       "an empty needle matches a non-empty header block");

    http_response_free(&r);

    memset(&r, 0, sizeof(r));
    ok(http_has_header(&r, "X-Ban") == 0,
       "a NULL header block matches nothing");

    PARSE(&r, "\r\n\r\nbody");
    ok(http_has_header(&r, "") == 0,
       "an empty needle does not match an empty header block");
    http_response_free(&r);

    /* ---- write_request pacing ------------------------------------------ */

    {
        static const unsigned char  req[] = "GET / HTTP/1.0\r\n\r\n";
        const size_t                req_len = sizeof(req) - 1;
        /* Zeroed so `chunk` and `unit` are both 0 (plain stall) in every case
         * that does not set them -- an uninitialized chunk would turn the pause
         * cases into pacing cases at random. Written as {0} rather than a
         * field-count list so adding a pacing field to http_pause cannot leave
         * this fixture partly indeterminate. */
        http_pause                  p[2] = {{0}, {0}};
        echo_result                 er;
        int                         rc;

        ok(run_echo(req, req_len, NULL, 0, &er) == 0
           && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "with no pauses the whole request arrives");

        /* The floor is deliberately below the requested 200 ms: coarse clocks
         * and scheduling can shave a few ms off the measured interval without
         * the pause having failed to happen. 150 still cannot be reached by a
         * write that never slept. */
        p[0].offset = 5;
        p[0].ms = 200;

        /* rc is kept rather than folded into the ok() expression: the next
         * case asserts over the SAME er, and a short-circuited `&&` would
         * leave it reading a struct from an exchange that never completed --
         * reporting a content mismatch when the real fault was the transfer. */
        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.elapsed_ms >= 150,
           "a pause delays the rest of the request by its duration");

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a paused request still arrives byte-identical and in order");

        p[0].offset = 5;
        p[0].ms = 120;
        p[1].offset = 10;
        p[1].ms = 120;

        ok(run_echo(req, req_len, p, 2, &er) == 0 && er.elapsed_ms >= 180,
           "two pauses both delay, and their durations add up");

        /* An offset past the end must not walk off the buffer, and must still
         * send every byte -- the stall simply lands after the last one. */
        p[0].offset = req_len + 99;
        p[0].ms = 50;

        ok(run_echo(req, req_len, p, 1, &er) == 0
           && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a pause offset past the end still sends the whole request");

        /* An offset-0 stall lands after connect() but before the first byte,
         * which is what makes a server's pre-request idle timeout reachable.
         * The fixture's clock starts at accept() -- which returns on the TCP
         * handshake, before any data -- so that leading stall IS inside the
         * measured window, and the request still arrives whole once it starts. */
        p[0].offset = 0;
        p[0].ms = 150;

        ok(run_echo(req, req_len, p, 1, &er) == 0
           && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0
           && er.elapsed_ms >= 100,
           "a pause at offset 0 stalls before the request, which still arrives whole");

        /*
         * send_slow: pace the whole request in 8-byte chunks, 10 ms apart.
         *
         * req_len is 18, so this is 3 chunks (8, 8, 2): one leading sleep
         * before the paced span, then two BETWEEN the three chunks (none
         * after the last) -- 3 sleeps of 10 ms each, 30 ms accounted in all.
         *
         * Two assertions, because the equality alone is not enough. The
         * equality catches a sleep gutted to a no-op, but NOT the other half
         * of the S-5 defect class: a counter credited from `ms`/`pauses[i].ms`
         * (the INTENT) beside a gutted sleep_ms() call still reports 30 --
         * the number stays right while the sleep never happens, which is
         * exactly the vacuous oracle this accounting exists to rule out. An
         * accounting number alone cannot distinguish "credited from the
         * return" from "credited from the intent"; only comparing it against
         * an INDEPENDENT witness of real elapsed time can.
         *
         * So the second assertion derives its floor from `send_paced_ms`
         * itself rather than a hardcoded constant, and checks `elapsed_ms`
         * against it with a one-sided tolerance: the fixture's clock starts
         * at accept(), before the connect() and the leading sleep at offset 0
         * fully overlap it (see the offset-0 case above, which uses a
         * separate margin for the same reason), so `elapsed_ms` can read
         * slightly under 30 even when every sleep genuinely happened.
         * Measured at 30 across dozens of runs, including under artificial
         * CPU load, so a 10 ms tolerance (floor of 20) is generous rather than
         * tight. It stays one-sided and load-immune in the safe direction: a
         * loaded runner can only STRETCH elapsed_ms, never shrink it, so this
         * can never fail on a real pass. A sleep gutted with intent credited
         * intact collapses elapsed_ms to ~10 ms (the untouched leading stall
         * alone) against an accounted 30, which fails `10 >= 20` and reds.
         */
        p[0].offset = 0;
        p[0].ms = 10;
        p[0].chunk = 8;

        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a paced request arrives byte-identical and in order");

        ok(rc == 0 && er.reads > 1 && er.max_read <= 8,
           "send_slow splits the request into chunks no larger than asked");

        ok(rc == 0 && er.send_paced_ms == 30,
           "send_slow accounts the leading stall plus both inter-chunk sleeps");

        ok(rc == 0 && er.elapsed_ms >= er.send_paced_ms - 10,
           "send_slow's accounted sleep is corroborated by elapsed wall time, "
           "not merely credited from intent");

        /* A cheap guard, not a load-immunity control: with no pauses,
         * write_request() takes the single write_all() path and every
         * crediting site sits inside the pause loop or the pacing helpers, so
         * none of them run -- send_paced_ms reads 0 by CONTROL FLOW, not
         * because any accounting logic was exercised and found correct. Worth
         * keeping anyway, as a guard against a future refactor that hoists a
         * credit above the loop and would otherwise start crediting an
         * unpaced request as a side effect. */
        ok(run_echo(req, req_len, NULL, 0, &er) == 0
           && er.send_paced_ms == 0,
           "an unpaced request accounts zero send-side sleep");

        /* A chunk at or above the request length degrades to one write, but
         * still honours the leading sleep -- the pacing knob must not become a
         * way to accidentally skip the stall it was configured with. */
        p[0].offset = 0;
        p[0].ms = 120;
        p[0].chunk = 4096;

        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0
           && er.elapsed_ms >= 80,
           "a chunk larger than the request is one write after the stall");

        /* Pacing that starts partway in: the first 10 bytes go out at once,
         * then the remainder dribbles. This is the shape a slowloris rule
         * actually uses -- a complete request line, then a slow header block. */
        p[0].offset = 10;
        p[0].ms = 10;
        p[0].chunk = 4;

        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0
           && er.reads > 1,
           "send_slow can begin partway through the request");

        p[0].chunk = 0;

        /* ---- send_slow_chunks: pacing at chunked-framing granularity ----- */

        {
            /*
             * Three units of DELIBERATELY UNEQUAL length -- 6, 8, 5 -- after a
             * 48-byte header block. Unequal because equal ones cannot tell the
             * two pacers apart: any fixed chunk size that happens to match the
             * unit length segments an equal-unit body identically, so the test
             * would pass with the byte-count pacer wired in by mistake. With
             * 6/8/5 the boundaries fall at 54, 62 and 67 bytes, which no single
             * chunk size reproduces.
             */
            static const unsigned char  creq[] =
                "POST /c HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"
                "1\r\nX\r\n"
                "3\r\nYYY\r\n"
                "0\r\n\r\n";
            const size_t  creq_len = sizeof(creq) - 1;
            const size_t  head_len = 48;   /* through the header terminator */
            size_t        cum, s;
            int           saw_first, saw_second, attempt;

            /* Pace only the body: a rule file that dribbles the header block
             * too is a different (slowloris) test, and the framing walk has
             * nothing to parse before the body starts. */
            p[0].offset = head_len;
            p[0].ms = 20;
            p[0].chunk = 0;
            p[0].unit = 1;

            /*
             * Retry while the receiver coalesced the paced writes into fewer
             * reads than there are units. The sender does one write_all() per
             * unit with an inter-unit sleep and TCP_NODELAY set, so the
             * boundaries are always ON THE WIRE; whether they survive as
             * separate read() returns depends on when the receiving thread is
             * scheduled, which is load-dependent and not a property of the
             * code under test. Retrying (rather than asserting on the first
             * sample) is what makes the framing assertions below deterministic
             * on a loaded CI runner -- with a single sample, full coalescing
             * reds case 99 and makes case 100 pass VACUOUSLY, since its
             * !saw_second holds trivially when every boundary is gone.
             *
             * The guard is the FULL expected read count (4 here: the header
             * block plus one per unit), not merely "more than one" -- a
             * partially coalesced sample can still be missing exactly the
             * boundary under test.
             *
             * Bounded, and the bound is not silent: falling through still
             * leaves the assertions to run and report honestly rather than
             * skipping, which would read as a pass.
             */
            for (attempt = 0; attempt < 20; attempt++) {
                rc = run_echo(creq, creq_len, p, 1, &er);

                if (rc != 0 || er.n_segs >= 4) {
                    break;
                }
            }

            ok(rc == 0 && er.got_len == creq_len
               && memcmp(er.got, creq, creq_len) == 0,
               "a unit-paced request arrives byte-identical and in order");

            /*
             * The framing claim: the cut after the first unit (offset 54 =
             * 48 + 6) and after the second (62 = 54 + 8) both appear as read
             * boundaries. Searched among the cumulative boundaries rather than
             * compared to an exact segment list, because TCP may coalesce the
             * later writes -- which can only ever REMOVE a boundary, so finding
             * both is decisive while missing one is not attributable to
             * coalescing alone.
             */
            cum = 0;
            saw_first = 0;
            saw_second = 0;

            for (s = 0; s < er.n_segs; s++) {
                cum += er.segs[s];

                if (cum == head_len + 6) {
                    saw_first = 1;
                }

                if (cum == head_len + 6 + 8) {
                    saw_second = 1;
                }
            }

            ok(rc == 0 && saw_first && saw_second,
               "send_slow_chunks cuts on the chunk-unit boundaries, not on a "
               "byte count");

            /*
             * The negative control for the assertion above, and the reason this
             * directive exists at all: the byte-count pacer over the SAME body,
             * with the chunk size set to the first unit's length. It agrees on
             * the first boundary and must then drift -- 6 bytes into an 8-byte
             * unit is mid size-line -- so the second framing boundary is absent.
             * If this passed, `send_slow` already did the job and the whole
             * directive would be dead weight.
             */
            p[0].chunk = 6;
            p[0].unit = 0;

            /* Same coalescing retry as above, for the same reason: this
             * assertion is `!saw_second`, so a fully coalesced sample would
             * satisfy it while proving nothing about where the byte-count
             * pacer cuts. Five reads here, not four: the 6-byte chunk size
             * cuts the 19-byte body into 6/6/6/1. */
            for (attempt = 0; attempt < 20; attempt++) {
                rc = run_echo(creq, creq_len, p, 1, &er);

                if (rc != 0 || er.n_segs >= 5) {
                    break;
                }
            }

            cum = 0;
            saw_second = 0;

            for (s = 0; s < er.n_segs; s++) {
                cum += er.segs[s];

                if (cum == head_len + 6 + 8) {
                    saw_second = 1;
                }
            }

            ok(rc == 0 && !saw_second,
               "the byte-count pacer misses the second unit boundary, which is "
               "what send_slow_chunks exists to hit");

            /* One sleep per unit, two of them inside the fixture's measured
             * window for the same reason case 53 states: the clock starts at
             * accept(), so the leading sleep may already be underway. Floor of
             * 30 against a nominal 3 x 20 = 60. */
            p[0].chunk = 0;
            p[0].unit = 1;

            rc = run_echo(creq, creq_len, p, 1, &er);

            ok(rc == 0 && er.elapsed_ms >= 30,
               "send_slow_chunks paces the units apart in time");

            /*
             * Framing this parser rejects is still SENT, in full, byte-identical
             * -- the harness exists to put malformed framing on the wire. Bare
             * LF after the size, which parse_chunk_size() refuses on purpose (a
             * lenient reading of it is the smuggling differential), so the walk
             * bails on the first unit and the whole body goes out as one write.
             */
            {
                static const unsigned char  bad[] =
                    "POST /c HTTP/1.1\r\n"
                    "Transfer-Encoding: chunked\r\n\r\n"
                    "1\nX\r\n0\r\n\r\n";
                const size_t  bad_len = sizeof(bad) - 1;

                rc = run_echo(bad, bad_len, p, 1, &er);

                ok(rc == 0 && er.got_len == bad_len
                   && memcmp(er.got, bad, bad_len) == 0,
                   "unparseable chunked framing is still written whole and "
                   "unaltered");
            }

            /*
             * A LYING LENGTH: the size line parses cleanly, and only the data's
             * trailing CRLF says the unit is wrong. `2\r\nX\r\n` declares two
             * data bytes where one and a terminator follow, so the walk consumes
             * `X\r` as data and then finds `\n0` where the terminator must be.
             *
             * This is the case the terminator check exists for, and it needs its
             * own fixture because the bare-LF case above never reaches it -- that
             * one is rejected in the SIZE line, one step earlier. With the check
             * removed the walk accepts the unit and resumes two bytes into the
             * next one, so the body is cut at an offset the framing does not
             * have. The observable is segmentation, not the bytes: a bail writes
             * the remainder in one go, so the only read boundary inside the body
             * is its end.
             */
            {
                static const unsigned char  lying[] =
                    "POST /c HTTP/1.1\r\n"
                    "Transfer-Encoding: chunked\r\n\r\n"
                    "2\r\nX\r\n0\r\n\r\n";
                const size_t  lying_len = sizeof(lying) - 1;
                int           cut_inside;

                rc = run_echo(lying, lying_len, p, 1, &er);

                cum = 0;
                cut_inside = 0;

                for (s = 0; s < er.n_segs; s++) {
                    cum += er.segs[s];

                    if (cum > head_len && cum < lying_len) {
                        cut_inside = 1;
                    }
                }

                ok(rc == 0 && er.got_len == lying_len
                   && memcmp(er.got, lying, lying_len) == 0 && !cut_inside,
                   "a chunk whose declared length runs past its CRLF terminator "
                   "stops the pacing instead of resuming mid-framing");
            }

            p[0].unit = 0;
            p[0].offset = 0;
            p[0].ms = 0;
        }

        /*
         * shutdown SHUT_WR half-closes the sending side once the request is
         * out. The response still arrives -- that is the whole point, and it
         * is also why the response alone cannot prove the shutdown happened.
         * The fixture's extra read is the observable: it sees EOF instead of
         * blocking, which only happens if the client really half-closed.
         */
        rc = run_echo_shut(req, req_len, NULL, 0, SHUT_WR, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a half-closed request still arrives whole");

        ok(rc == 0 && er.saw_eof,
           "shutdown SHUT_WR reaches the server as EOF");

        /* Without the directive the client stays open, so the same fixture
         * must NOT see EOF -- otherwise the assertion above would pass for a
         * connection that merely closed on its own. */
        rc = run_echo_shut(req, req_len, NULL, 0, HTTP_SHUT_NONE, 1, &er);

        ok(rc == 0 && er.got_len == req_len && !er.saw_eof,
           "without shutdown the sending side stays open");
    }

    /*
     * abort resets the connection after a prefix of the request.
     *
     * Two independent things have to hold, and testing only the first is the
     * trap: the server must receive exactly the prefix (not the whole request),
     * AND the connection must end in a RESET rather than an ordinary close. A
     * plain close would also truncate the request and would also satisfy a byte
     * count -- so without the ECONNRESET assertion, a version of this directive
     * that forgot SO_LINGER entirely would still report green.
     */
    {
        static const unsigned char  req[] =
            "GET /slow HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\nBODY";
        size_t                      req_len = sizeof(req) - 1;
        echo_result                 er;
        http_pause                  p[1];
        int                         rc;

        rc = run_echo_abort(req, req_len, 20, NULL, 0, 20, &er);

        ok(rc == 0 && er.got_len == 20 && memcmp(er.got, req, 20) == 0,
           "abort sends exactly the bytes before its offset");

        ok(rc == 0 && er.saw_reset,
           "abort reaches the server as ECONNRESET, not a clean close");

        /* The negative control for the assertion above: the same fixture, the
         * same byte count, no abort. It must NOT see a reset -- otherwise
         * saw_reset would be measuring the fixture's own teardown rather than
         * the directive. */
        rc = run_echo_full(req, 20, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, 1, 0,
                           HTTP_IDLE_NONE, &er);

        ok(rc == 0 && er.got_len == 20 && !er.saw_reset,
           "without abort the connection ends without a reset");

        /* Offset 0 is a real value, not "unset": the connection is reset before
         * a single request byte goes out. This is the case a zeroed abort_at
         * field would inflict on every rule in the file. */
        rc = run_echo_abort(req, req_len, 1, NULL, 0, 0, &er);

        ok(rc == 0 && er.got_len == 0,
           "abort 0 resets before writing any request bytes");

        /* An offset past the end writes everything and then resets, rather
         * than clamping to something shorter or refusing outright. */
        rc = run_echo_abort(req, req_len, req_len, NULL, 0, req_len + 500, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0 && er.saw_reset,
           "an abort offset past the request end sends all of it, then resets");

        /*
         * Pauses inside the written prefix still apply: this is the
         * slowloris-then-give-up shape, and it is the combination most likely
         * to break if the abort path were bolted on by skipping write_request()
         * rather than by shortening what it is asked to write.
         */
        p[0].offset = 0;
        p[0].ms = 30;
        p[0].chunk = 8;

        rc = run_echo_abort(req, req_len, 24, p, 1, 24, &er);

        ok(rc == 0 && er.got_len == 24 && er.reads > 1,
           "send_slow paces the prefix an abort then truncates");

        ok(rc == 0 && er.elapsed_ms >= 25,
           "the paced prefix before an abort is actually paced");
    }

    /*
     * hold writes the whole request, waits without reading, then closes with an
     * ordinary FIN. The three properties that distinguish it from the two
     * directives it sits between are each pinned separately below: the request
     * arrives COMPLETE (unlike abort, which truncates), the connection ends
     * WITHOUT a reset (unlike abort, which resets), and the wait actually
     * happens (or the directive is decoration).
     */
    {
        const unsigned char  req[] = "GET /held HTTP/1.1\r\nHost: p\r\n\r\n";
        size_t               req_len = sizeof(req) - 1;
        echo_result          er;
        long long            t0, t1;
        int                  rc;

        t0 = now_ms();
        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, 120, NULL, 1, 0,
                           HTTP_IDLE_NONE, &er);
        t1 = now_ms();

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "hold sends the complete request before going quiet");

        /* The distinction from abort, and the reason hold exists as its own
         * directive: the server must see a well-behaved peer, not a vanished
         * one. A hold that reset would be an abort with extra steps. */
        ok(rc == 0 && !er.saw_reset,
           "hold ends the connection with a FIN, not a reset");

        /* Without this the directive could be a no-op that still passes the two
         * assertions above -- the request would arrive and the connection would
         * close cleanly whether or not anything waited. */
        ok(rc == 0 && t1 - t0 >= 100,
           "hold actually waits before closing");

        /* A hold must not spend the read timeout on top of its own wait. The
         * whole exchange is bounded by the hold, so a hold that fell through to
         * the read loop would take timeout_ms (5s) longer -- passing the three
         * assertions above while quietly stalling every held case in a suite. */
        ok(rc == 0 && t1 - t0 < 1000,
           "hold skips the read loop rather than also waiting for a response");
    }

    /*
     * recv_slow paces the READ side. The observable is this process's own
     * elapsed time: a response that arrives in one burst but is consumed in
     * timed sips takes at least (reads - 1) * ms to collect, however fast the
     * peer wrote it.
     *
     * The timing assertion is a floor only, like every other one here -- a
     * loaded box can stretch a sleep but cannot make nanosleep return early.
     * The floor counts sleeps BETWEEN reads (there is no sleep before the
     * first), so a 400-byte response read 100 bytes at a time is 3 sleeps, not
     * 4. Asserting 4 would be the mirror of the send-side timing bug that
     * clang+ASan caught last time: deterministically wrong, not flaky.
     */
    {
        static const unsigned char  req[] = "GET /big HTTP/1.1\r\n\r\n";
        size_t                      req_len = sizeof(req) - 1;
        echo_result                 er;
        http_recv                   rv;
        int                         rc;
        long long                   t0, t1;

        memset(&rv, 0, sizeof(rv));
        rv.chunk = 100;
        rv.ms = 30;

        t0 = now_ms();
        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, &rv, 0, 0,
                           HTTP_IDLE_NONE, &er);
        t1 = now_ms();

        ok(rc == 0, "a recv_slow request completes");

        /* SPAWN_REPLY is 418 bytes; at 100 per read that is 5 reads and 4
         * sleeps of 30 ms. */
        ok(rc == 0 && t1 - t0 >= 85,
           "recv_slow paces the reads apart in time");

        /*
         * The chunk cap's DETERMINISTIC witness, beside the timing floor above.
         *
         * The floor alone does not gate the cap: it is a wall-clock minimum, so
         * a loaded runner can satisfy it out of scheduling overhead while the
         * cap does nothing -- observed for real, as a mutation removing the cap
         * surviving in CI while going red locally. A read count cannot be
         * inflated that way. Without the cap this whole reply arrives in ONE
         * read (the receive buffer is 8 KiB and nothing else bounds `want`), so
         * requiring several is exactly the assertion the cap is answerable for.
         *
         * A floor rather than an equality: the peer may hand the bytes over in
         * more segments than the cap forces, which adds reads. It can never
         * subtract them -- the cap bounds every single read at 100 bytes, so
         * collecting 418 needs at least ceil(418/100) of them however the wire
         * delivered them.
         */
        ok(rc == 0 && er.client_reads >= (SPAWN_REPLY_LEN + 99) / 100,
           "recv_slow bounds each read by the chunk, so the reply needs several");

        /*
         * The SLEEP's witness, and the half the assertion above does not reach.
         * `client_reads` gates the chunk cap; a mechanism that capped every read
         * and slept for none of them satisfies it in full, which left the sleep
         * standing on the wall clock alone.
         *
         * An EQUALITY, and the count is MEASURED rather than derived: 5 reads
         * and 120 ms, stable across 8 consecutive runs on loopback. The
         * arithmetic agrees (418 bytes at a 100-byte cap is 5 reads, and
         * `paced_full` sleeps only before a read the loop expects to fill, so
         * the final short read is unpaced -- 4 sleeps of 30 ms), but the
         * measurement is what this assertion rests on.
         *
         * It was briefly `>= 3 * rv.ms`, hedged one sleep low against a peer
         * handing the bytes over in more segments than the cap forces. That
         * hedge was wrong twice over: the fragmentation does not occur here, and
         * a floor one under the real count ADMITS the single-sleep regression it
         * was supposed to be tolerant of -- a mutant sleeping 3 times of 4
         * passed the entire suite. If loopback ever does fragment this reply the
         * assertion reds, and that is the correct outcome: fix the fixture, not
         * the bound. Widening it back to a floor re-opens the hole.
         *
         * The value is credited from `sleep_ms()`'s return rather than from
         * `recv_opt->ms` beside the call, so gutting the sleep to a no-op zeroes
         * this counter instead of leaving it reporting sleeps that never
         * happened. See the field comment in http.h.
         */
        ok(rc == 0 && er.paced_sleep_ms == 4 * rv.ms,
           "recv_slow actually sleeps between the reads it paces");
        /*
         * The negative control: the same exchange unpaced must NOT cost what
         * the paced one did, or the assertions above would be measuring the
         * fixture rather than the pacing. Proved below by two counters the
         * machine cannot move, deliberately WITHOUT a wall-clock assertion.
         *
         * A wall-clock version of this control was tried and reverted twice.
         * `(t1 - t0) * 2 < paced_ms` (paced elapsed time measured above,
         * before that variable was removed) was relative rather than a fixed
         * constant, which fixes the ceiling-side failure mode (a fixed bound
         * reds on a sanitizer build or a contended runner with nothing
         * wrong), but a relative comparison of two wall clocks measured at
         * different times has a failure mode of its own: a stall landing on
         * the PACED run inflates the paced elapsed time and makes the
         * comparison easier (load-tolerant, the direction the comment here
         * used to analyse), but a stall landing on THIS unpaced run inflates
         * `t1 - t0` and reds the assertion with nothing wrong -- observed for
         * real (assertion #122, PRs #182 and #185, host load 5.71/6.83 at the
         * failures, clean at 0.13). Neither direction is fixable by widening
         * the multiplier: that only trades which stall size still reds.
         *
         * `er.client_reads == 1` and `er.paced_sleep_ms == 0` below prove the
         * identical claim -- the unpaced run took the uncapped, unslept path --
         * from counters `sleep_ms()`'s real return value feeds (see the field
         * comments in http.h): a mutant cannot satisfy them without actually
         * skipping the cap and the sleep, and neither counter can be moved by
         * scheduler noise in either direction. They fully subsume the
         * wall-clock claim, so there is deliberately no timing assertion here;
         * re-adding one would be a regression back to a flaky gate.
         */
        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, 0, 0,
                           HTTP_IDLE_NONE, &er);

        /*
         * The read-count mirror of the control, and the half of it no load
         * condition can move.
         *
         * An EQUALITY, not a bound. The fixture writes SPAWN_REPLY in a single
         * send() and nothing below the 8 KiB receive buffer bounds `want`, so
         * unpaced this is exactly one read. Stated as
         * `< (SPAWN_REPLY_LEN + 99) / 100` it would also admit a cap of 200 or
         * 256 -- 418 bytes splits into 3 or 2 reads, both under that floor --
         * so it would prove only that the 100-byte cap specifically is absent,
         * not that the read path is uncapped. The strict form is what makes
         * this the counterpart to the floor above rather than a weaker
         * restatement of it.
         *
         * If the loopback ever hands these bytes over in more than one segment
         * this reds, and that is intended: an assertion widened to accommodate
         * fragmentation starts admitting exactly the caps it exists to exclude.
         * Fix the fixture, not the bound.
         */
        ok(rc == 0 && er.client_reads == 1,
           "without recv_slow the whole reply arrives in a single uncapped read");

        /*
         * The sleep mirror of the control, and an EQUALITY because zero is the
         * only defensible value: with no `recv_slow` the pacing branch is never
         * entered, so any nonzero total means the client slept for a reason
         * nothing asked it to.
         *
         * Paired with `er.client_reads == 1` above, this is the whole negative
         * control: together they say the paced run slept and capped its reads
         * and the unpaced one did neither, with neither claim resting on how
         * busy the box was. See the comment above the unpaced call for why
         * that pairing replaced a wall-clock assertion here rather than
         * supplementing one.
         */
        ok(rc == 0 && er.paced_sleep_ms == 0,
           "without recv_slow the client never sleeps between reads");

        /*
         * A pacing request nanosleep() cannot honour must credit NOTHING.
         *
         * `chunk` is set, so the cap engages and the reply is collected in
         * several reads exactly as above -- only the duration is unusable. A
         * negative `tv_nsec` is EINVAL, so nothing sleeps; the question is
         * whether the counter says so. Returning the requested `ms` on a failed
         * sleep would rebuild the defect the return value exists to prevent one
         * layer down: the account would show four sleeps of a duration that was
         * never waited.
         *
         * Reachable only from C. The rule parser clamps recv_slow's ms to
         * 1..MAX_PAUSE_MS (rules.c), and this drives the transport directly, so
         * the guard is here rather than left to the caller -- http_exchange()
         * is a public entry point and the parser is not the only way in.
         */
        memset(&rv, 0, sizeof(rv));
        rv.chunk = 100;
        rv.ms = -1;

        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, &rv, 0, 0,
                           HTTP_IDLE_NONE, &er);

        ok(rc == 0 && er.client_reads >= (SPAWN_REPLY_LEN + 99) / 100
           && er.paced_sleep_ms == 0,
           "a pacing delay nanosleep cannot honour credits no sleep at all");

        /* A chunk larger than the whole response is one read and no sleep --
         * the read-side mirror of send_slow's large-chunk case. */
        memset(&rv, 0, sizeof(rv));
        rv.chunk = 65536;
        rv.ms = 200;

        t0 = now_ms();
        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, &rv, 0, 0,
                           HTTP_IDLE_NONE, &er);
        t1 = now_ms();

        ok(rc == 0 && t1 - t0 < 200,
           "a recv chunk larger than the response costs no sleeps");

        /* SO_RCVBUF alone must not change what arrives. */
        memset(&rv, 0, sizeof(rv));
        rv.rcvbuf = 1024;

        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, &rv, 0, 0,
                           HTTP_IDLE_NONE, &er);

        ok(rc == 0, "so_rcvbuf alone still collects the whole response");

        /*
         * ...and it must actually be APPLIED. The assertion above passes just
         * as happily when the setsockopt is never made, so on its own it leaves
         * the directive's entire effect untested -- a version of this code that
         * dropped the call would report green.
         *
         * Asserted by reading the option back on a socket configured the same
         * way, rather than through http_request(): the kernel doubles the
         * request for bookkeeping and enforces its own floor, so the effective
         * value is neither the number passed nor knowable in advance. What IS
         * decidable is the comparison -- a socket asked for a small buffer must
         * end up with a smaller one than an untouched socket on the same box.
         */
        {
            int        a = socket(AF_INET, SOCK_STREAM, 0);
            int        b = socket(AF_INET, SOCK_STREAM, 0);
            int        want = 1024, got_a = 0, got_b = 0;
            socklen_t  slen = sizeof(got_a);

            setsockopt(a, SOL_SOCKET, SO_RCVBUF, &want, sizeof(want));

            getsockopt(a, SOL_SOCKET, SO_RCVBUF, &got_a, &slen);
            slen = sizeof(got_b);
            getsockopt(b, SOL_SOCKET, SO_RCVBUF, &got_b, &slen);

            ok(got_a < got_b,
               "so_rcvbuf's setsockopt really shrinks the receive buffer");

            close(a);
            close(b);
        }

        /*
         * That the option is APPLIED by http_request(), not merely accepted.
         *
         * The two assertions above are both satisfied by a version of this code
         * that never calls setsockopt at all -- the response still arrives, and
         * the kernel still behaves as tested on a socket configured by hand. A
         * mutation dropping the call survived them both, which is what this
         * case exists to fix.
         *
         * There is no error path to probe: Linux never fails SO_RCVBUF, it
         * silently clamps whatever it is given (verified: even INT_MIN returns
         * 0 and leaves the default in place). The witness is the effective
         * buffer read back off the very connection http_request() configured
         * (http_response.effective_rcvbuf, getsockopt on the live fd): a socket
         * asked for a small buffer always reports a strictly smaller value than
         * an untouched one on the same box, and the comparison is decided by
         * kernel policy, not timing.
         *
         * This replaces an earlier read-count inequality
         * (probe_reads_big(shrunk) > probe_reads_big(default)). That was flaky
         * under a loaded CI fleet: when the whole 256 KB response is already
         * queued in the socket before the client's first recv(), the grown read
         * buffer drains it in the same number of reads regardless of the
         * receive window, so the strict `>` occasionally failed and let the
         * setsockopt-dropping mutation survive. getsockopt has no such race.
         */
        {
            echo_result  er_small, er_plain;
            http_recv    rv_small;
            static const unsigned char rreq[] =
                "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

            memset(&rv_small, 0, sizeof(rv_small));
            rv_small.rcvbuf = 1024;

            /* Same exchange twice: once asking for a small receive buffer,
             * once leaving it at the default. The requested run must end up
             * with a strictly smaller effective buffer -- false, and this
             * assertion reddens, exactly when http_request() never makes the
             * setsockopt call. */
            if (run_echo_full(rreq, sizeof(rreq) - 1, NULL, 0, HTTP_SHUT_NONE,
                              HTTP_ABORT_NONE, HTTP_HOLD_NONE, &rv_small, 0, 0,
                              HTTP_IDLE_NONE, &er_small) == 0
                && run_echo_full(rreq, sizeof(rreq) - 1, NULL, 0,
                                 HTTP_SHUT_NONE, HTTP_ABORT_NONE, HTTP_HOLD_NONE,
                                 NULL, 0, 0, HTTP_IDLE_NONE, &er_plain) == 0)
            {
                ok(er_small.effective_rcvbuf > 0
                   && er_plain.effective_rcvbuf > 0
                   && er_small.effective_rcvbuf < er_plain.effective_rcvbuf,
                   "so_rcvbuf's setsockopt really shrinks the connection's "
                   "receive buffer, read back off the live socket");
            } else {
                ok(0, "so_rcvbuf effective-buffer probe: exchange failed");
            }
        }
    }

    /*
     * Close accounting: how the connection ended, and how long it took.
     *
     * These are the transport half of expect_close_within. The assertion layer
     * is tested separately over fixed values in assert_test.c; what can only be
     * established here is that the values it judges are produced correctly from
     * a real socket.
     */
    {
        static const unsigned char  req[] =
            "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
        const size_t                req_len = sizeof(req) - 1;
        echo_result                 er;
        int                         rc;

        /* A server that closes: FIN, and a time that is measured rather than
         * left at whatever the struct was initialised to. */
        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, 1, 1,
                           HTTP_IDLE_NONE, &er);

        ok(rc == 0 && er.close_reason == HTTP_CLOSE_FIN,
           "a server that closes is reported as a FIN");

        ok(rc == 0 && er.close_ms >= 0 && er.close_ms < 5000,
           "a prompt close is timed well inside the read timeout");

        /*
         * ...and the time is MEASURED, not merely present.
         *
         * The assertion above is satisfied by a close_ms hardcoded to zero, so
         * on its own it leaves the measurement entirely untested -- a mutation
         * zeroing it survived. The observable has to be a close that takes a
         * known-nonzero amount of time, which needs a server that waits before
         * closing rather than the prompt fixture used above.
         *
         * A floor only, never a ceiling: a loaded box can stretch the interval
         * but cannot make the server close before it was told to.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];

            /* Linger 150 ms, comfortably inside the 5000 ms read timeout, so
             * this exercises a real FIN rather than the timeout path. */
            pid = spawn_lingering(&port, 150, 1);

            memset(&resp, 0, sizeof(resp));
            rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 1, HTTP_IDLE_NONE, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));

            ok(rc == 0 && resp.close_reason == HTTP_CLOSE_FIN
               && resp.close_ms >= 100,
               "a delayed close is timed, not reported as instant");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        /*
         * want_close is opt-in, and must stay so: every case that predates this
         * directive still reads a closing server the same way. Asserted because
         * the flag is threaded through the whole call chain, and a version that
         * ignored it would pass every OTHER test in this file.
         */
        rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, 1, 0,
                           HTTP_IDLE_NONE, &er);

        ok(rc == 0 && er.close_reason == HTTP_CLOSE_FIN,
           "close accounting is recorded even without want_close");

        /*
         * A server that RESETS is reported as a reset, not as a clean FIN and
         * not as "no close observed".
         *
         * The abort fixtures above have the CLIENT reset and watch it from the
         * server side, which says nothing about how this code classifies a
         * reset arriving here. Without this, the read loop's error branch --
         * which catches every failure that is not EINTR or the EAGAIN timeout
         * -- could label an EBADF a reset and no test would notice, reporting
         * "the server reset the connection" to a rule author for something the
         * server never did.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];

            pid = spawn_resetting(&port, 1);

            memset(&resp, 0, sizeof(resp));
            rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 1, HTTP_IDLE_NONE, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));

            /* A reset can arrive either as ECONNRESET on the read or, if the
             * response was fully buffered first, as an ordinary EOF -- the
             * kernel hands over what it already has. Both are legitimate; what
             * must never happen is the reason being left unset, which would
             * make the deadline report that it could not judge the case. */
            ok(rc == 0 && (resp.close_reason == HTTP_CLOSE_RESET
                           || resp.close_reason == HTTP_CLOSE_FIN),
               "a resetting server yields a definite close reason");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        /*
         * A reset with NO response written first. Nothing is buffered, so the
         * read genuinely fails with ECONNRESET rather than draining bytes and
         * reporting EOF -- this is the case that actually exercises the errno
         * branch, and it must come back as RESET rather than as unobserved.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];

            pid = spawn_resetting(&port, 0);

            memset(&resp, 0, sizeof(resp));
            rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 1, HTTP_IDLE_NONE, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));

            ok(rc == 0 && resp.close_reason == HTTP_CLOSE_RESET,
               "a bare reset is classified as a reset, not as an unknown close");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        /*
         * The case the directive exists for: a server that answers and then
         * holds the connection open past the deadline.
         *
         * Two distinct claims, and both matter. Without want_close the read
         * timeout is a transport ERROR -- which is why the assertion could not
         * previously run at all. With it, the same wire behaviour comes back as
         * a successful call carrying HTTP_CLOSE_TIMEOUT, leaving the verdict to
         * the rule. If these two ever agree, the opt-in has stopped working and
         * a close-deadline case would abort instead of failing.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];

            /* Linger well past the 300 ms timeout below, so the child is still
             * holding the socket when the parent gives up -- but not so long
             * that a failing test wedges the suite. */
            pid = spawn_lingering(&port, 3000, 1);

            memset(&resp, 0, sizeof(resp));
            rc = http_request("127.0.0.1", port, req, req_len, 300, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));

            ok(rc != 0,
               "without want_close a non-closing server is a transport error");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];
            long long      t0, t1;

            pid = spawn_lingering(&port, 3000, 1);

            memset(&resp, 0, sizeof(resp));
            t0 = now_ms();
            rc = http_request("127.0.0.1", port, req, req_len, 300, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 1, HTTP_IDLE_NONE, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));
            t1 = now_ms();

            ok(rc == 0 && resp.close_reason == HTTP_CLOSE_TIMEOUT,
               "with want_close a non-closing server returns a timeout verdict");

            /* The response bytes that DID arrive are kept, so a case can still
             * assert on them alongside the close deadline. A timeout that threw
             * the buffer away would make expect and expect_close_within
             * mutually unusable. */
            ok(rc == 0 && resp.status == 200,
               "a timed-out exchange still carries the bytes that arrived");

            /* The measured time reflects the wait, not a zero left over from
             * initialisation -- floor only, never a ceiling, since a loaded box
             * can stretch any interval but cannot shorten a timeout. */
            ok(rc == 0 && resp.close_ms >= 250 && t1 - t0 >= 250,
               "the timeout verdict carries the time actually waited");

            /*
             * WHICH deadline ended the read, and this is the assertion the
             * floor above cannot make.
             *
             * The per-read idle bound is timeout_ms (300); the whole-exchange
             * budget is 8x that (2400). A floor-only assertion is satisfied by
             * BOTH, which is exactly how the S-4 poll() drain regressed this
             * without reddening anything: waiting in poll() rather than in
             * read() dropped SO_RCVTIMEO as the idle bound, and this case went
             * from 316 ms to a measured 2401 ms while staying green.
             *
             * The ceiling is therefore the witness, and it is not a tuning
             * knob: it separates the two deadlines rather than describing this
             * box's speed. Placed at 4x timeout_ms it sits far above any
             * plausible scheduling stretch of a 300 ms wait and still far below
             * the 2400 ms budget, so it distinguishes the two mechanisms
             * without being load-sensitive in the way a tight wall-clock bound
             * would be. If the idle bound is removed again, this reds; the
             * trickle case below is the negative control that keeps the
             * whole-exchange budget honest at the same time.
             */
            ok(rc == 0 && t1 - t0 < 4 * 300,
               "the idle read timeout -- not the 8x whole-exchange budget -- "
               "is what ends a silent non-closing exchange");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        /*
         * AUD-07: a server that DRIPS a byte inside every per-read window never
         * trips SO_RCVTIMEO, so before the whole-exchange deadline the client
         * read loop would run -- and grow its buffer -- forever. With a 200 ms
         * per-read timeout the exchange budget is 8x = 1600 ms; the server drips
         * every ~120 ms, so each read succeeds yet the exchange is still cut off
         * a little past the budget. Assert it (a) fails rather than hanging,
         * (b) returns bounded in time, and (c) says why.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];
            long long      t0, t1;

            pid = spawn_trickle(&port, 120);

            memset(&resp, 0, sizeof(resp));
            t0 = now_ms();
            rc = http_request("127.0.0.1", port, req, req_len, 200, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));
            t1 = now_ms();

            ok(rc != 0, "a trickling server is a failure, not an infinite read "
               "(AUD-07)");

            /* Bounded ABOVE: comfortably under a wall-clock ceiling far below
             * "forever" (budget 1600 ms; generous slack for a loaded box).
             * Bounded BELOW too: the exchange must have SURVIVED repeated
             * successful trickle reads before the deadline cut it off -- a
             * deadline that fired immediately (e.g. off a zeroed sent_at) would
             * satisfy the failure and upper-bound assertions while proving
             * nothing about the trickle. The server drips every 120 ms and the
             * budget is 1600 ms, so a real cut-off cannot happen in under
             * ~1 second; require a clear floor below that. */
            ok(t1 - t0 < 10000,
               "the trickle is cut off in bounded time, not left to hang "
               "(AUD-07)");
            ok(t1 - t0 >= 800,
               "the exchange survived repeated trickle reads before the "
               "deadline, not fired instantly (AUD-07)");

            ok(rc != 0 && strstr(errbuf, "whole-exchange") != NULL,
               "the failure names the whole-exchange budget (AUD-07)");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }
    }

    /*
     * The idle wait: the transport half of expect_idle.
     *
     * Its pass is a NON-event -- the server did nothing for the whole wait --
     * which is the hardest kind of thing to test honestly, because a wait that
     * silently did nothing at all would also report it. So each case here pins
     * the outcome AND the elapsed time: the pass must actually have spent the
     * wait, and each failure must be detected before it.
     */
    {
        static const unsigned char  req[] =
            "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
        const size_t                req_len = sizeof(req) - 1;
        int                         rc;

        /*
         * A server that accepts and then says nothing: the pass. `reply` clear,
         * so the child holds the socket open in silence for longer than the
         * wait -- the idle-but-open state no other fixture produces.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];
            long long      t0, t1;

            pid = spawn_lingering(&port, 3000, 0);

            memset(&resp, 0, sizeof(resp));
            t0 = now_ms();
            rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 0, 200, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));
            t1 = now_ms();

            ok(rc == 0 && resp.close_reason == HTTP_CLOSE_IDLE,
               "a silent server leaves the idle wait reporting IDLE");

            /* The wait was actually spent. Without this the whole directive is
             * satisfied by a poll() that returns immediately -- the vacuous
             * pass this fixture exists to rule out. Floor only. */
            ok(rc == 0 && t1 - t0 >= 180,
               "the idle wait spends the time it was given");

            ok(rc == 0 && resp.close_ms >= 180,
               "the idle wait reports the time it actually waited");

            /* Nothing was read, by construction: the assertion is that nothing
             * arrived, so collecting bytes would destroy the evidence. */
            ok(rc == 0 && resp.raw_len == 0,
               "the idle wait collects no response bytes");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        /*
         * A server that ANSWERS during the wait: failure, reported as data
         * rather than as a close. This is the arm that separates expect_idle
         * from a close deadline -- both fail here, but for different reasons and
         * with different text.
         */
        {
            int            port = 0, st;
            pid_t          pid;
            http_response  resp;
            char           errbuf[256];
            long long      t0, t1;

            pid = spawn_lingering(&port, 3000, 1);

            memset(&resp, 0, sizeof(resp));
            t0 = now_ms();
            rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 0, 2000, 0,
                              NULL, &resp, errbuf, sizeof(errbuf));
            t1 = now_ms();

            ok(rc == 0 && resp.close_reason == HTTP_CLOSE_DATA,
               "a server that answers is reported as data, not as a close");

            /* And it is detected EARLY -- the wait returns when the data
             * arrives rather than sitting out its full 2000 ms. A wait that
             * ignored POLLIN would pass the assertion above by timing out with
             * the wrong reason; this is what pins the difference. */
            ok(rc == 0 && t1 - t0 < 1500,
               "data ends the idle wait early rather than at the deadline");

            if (rc == 0) {
                http_response_free(&resp);
            }

            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
        }

        /*
         * A server that CLOSES during the wait: failure, and named as a close
         * rather than as data. spawn_echo() answers and closes, so the FIN
         * follows its reply -- either observable is a legitimate way for the
         * poll to notice, and what matters is that neither reads as IDLE.
         */
        {
            echo_result  er;

            rc = run_echo_full(req, req_len, NULL, 0, HTTP_SHUT_NONE,
                               HTTP_ABORT_NONE, HTTP_HOLD_NONE, NULL, 1, 0,
                               2000, &er);

            ok(rc == 0 && er.close_reason != HTTP_CLOSE_IDLE,
               "a server that acts never leaves the idle wait reporting IDLE");

            ok(rc == 0 && (er.close_reason == HTTP_CLOSE_FIN
                           || er.close_reason == HTTP_CLOSE_DATA),
               "a closing server yields a definite idle-wait outcome");
        }
    }

    /* ---- framed-mode classifier (http_framed_state) ------------------- */

    /*
     * Driven over fixed byte strings for the same reason http_parse_response()
     * is: the boundaries worth testing -- a Content-Length body split across two
     * reads, a chunk terminator that lands a byte at a time, a pipelined SECOND
     * response that must not be folded into the first -- are precisely what a
     * live server will not produce on demand. E1's read loop calls this exact
     * function after every read, so pinning it here pins the loop's decision.
     */
    {
        size_t  n;
        int     s;

#define FRAMED(lit)  http_framed_state((lit), sizeof(lit) - 1, &n)

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel");
        ok(s == HTTP_FRAMED_INCOMPLETE,
           "a Content-Length body not yet fully arrived is INCOMPLETE");

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        ok(s == HTTP_FRAMED_COMPLETE && n == 43,
           "a fully-received Content-Length response is COMPLETE at its exact end");

        n = 0;
        s = http_framed_state(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye",
                43 + 41, &n);
        ok(s == HTTP_FRAMED_COMPLETE && n == 43,
           "a pipelined second response is NOT folded into the first's length");

        n = 0;
        s = FRAMED("HTTP/1.1 204 No Content\r\nServer: t\r\n\r\n");
        ok(s == HTTP_FRAMED_COMPLETE && n == 38,
           "a 204 ends at the header terminator with no body");

        n = 0;
        s = FRAMED("HTTP/1.1 304 Not Modified\r\n\r\n");
        ok(s == HTTP_FRAMED_COMPLETE,
           "a 304 is bodiless regardless of framing headers");

        n = 0;
        s = FRAMED("HTTP/1.1 100 Continue\r\n\r\n");
        ok(s == HTTP_FRAMED_COMPLETE, "a 1xx response is bodiless");

        /* A bodiless status wins over a Content-Length that lies about a body:
         * RFC 9110 says 204/304 have none, so its end is the header terminator
         * and the CL is describing bytes that will never come. */
        n = 0;
        s = FRAMED("HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n");
        ok(s == HTTP_FRAMED_COMPLETE && n == 46,
           "a 204 with a spurious Content-Length still ends at the terminator");

        /*
         * A malformed status line must NOT yield a bodiless status.
         *
         * The classifier used to take the first space anywhere in the header
         * block and strtol whatever followed it, while its comment claimed it
         * matched http_parse_response()'s strict walk. It did not. Each input
         * below scored a bodiless 204 from bytes that are not a status line, so
         * the response was declared to end at the header terminator while the 9
         * bytes its Content-Length declares stayed on the socket -- and the next
         * pipelined block read them as ITS response head. A desync of exactly
         * the kind this harness exists to detect in someone else's server.
         *
         * The assertion is `n == sizeof(lit) - 1`, i.e. the classifier consumed
         * the WHOLE buffer and left nothing behind. Asserting only "not
         * bodiless" would pass on a wrong-but-nonzero split; the leftover byte
         * count is the thing that actually smuggles.
         *
         * The third case is the sharpest: there is no status line at all, and
         * the loose walk read "204" out of a header VALUE.
         */
        n = 0;
        s = FRAMED("HTTP/xyz 204 Nope\r\nContent-Length: 9\r\n\r\nbodybody!");
        ok(s == HTTP_FRAMED_COMPLETE && n == 49,
           "a malformed version token is not bodiless: the declared body is "
           "consumed, not left on the wire");

        /* The status-code token itself, not the version: "204junk" used to
         * score 204 because the parse stopped wherever the digits stopped. The
         * response is then declared over at the header terminator and "junk"
         * plus nine body bytes stay in the buffer, so the next pipelined read
         * starts mid-body -- body bytes framing the response that carries them.
         * All 48 bytes must be consumed. */
        n = 0;
        s = FRAMED("HTTP/1.1 204junk\r\nContent-Length: 9\r\n\r\nbodybody!");
        ok(s == HTTP_FRAMED_COMPLETE && n == 48,
           "a status code with garbage fused onto it is not bodiless: the "
           "declared body is consumed, not left on the wire");

        n = 0;
        s = FRAMED("HTTP/2 204 x\r\nContent-Length: 9\r\n\r\nbodybody!");
        ok(s == HTTP_FRAMED_COMPLETE && n == 44,
           "a versionless HTTP/2 status line is not bodiless: the declared "
           "body is consumed, not left on the wire");

        n = 0;
        s = FRAMED("HTTP/1.1\r\nX: 204 y\r\nContent-Length: 9\r\n\r\nbodybody!");
        ok(s == HTTP_FRAMED_COMPLETE && n == 50,
           "a status code appearing in a header value is not read as the "
           "response's status");

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "5\r\nhello\r\n0\r\n\r\n");
        ok(s == HTTP_FRAMED_COMPLETE,
           "a chunked body ended by its 0-chunk is COMPLETE");

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "5\r\nhello\r\n");
        ok(s == HTTP_FRAMED_INCOMPLETE,
           "a chunked body missing its terminating 0-chunk is INCOMPLETE");

        /* A size line split mid-arrival is unfinished, NOT malformed -- reporting
         * MALFORMED here would fail a valid response whose "1a\r\n" size line
         * landed one byte at a time. */
        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5");
        ok(s == HTTP_FRAMED_INCOMPLETE,
           "a chunk size line not yet CRLF-terminated is INCOMPLETE, not MALFORMED");

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\nhello");
        ok(s == HTTP_FRAMED_MALFORMED,
           "a non-numeric Content-Length is MALFORMED, never guessed past");

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                   "Content-Length: 9\r\n\r\nhello");
        ok(s == HTTP_FRAMED_MALFORMED,
           "two disagreeing Content-Length headers are MALFORMED (smuggling desync)");

        /* Two AGREEING Content-Lengths are benign -- the classifier must not
         * reject a response that is merely repetitive. */
        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                   "Content-Length: 5\r\n\r\nhello");
        ok(s == HTTP_FRAMED_COMPLETE,
           "two identical Content-Length headers agree and are COMPLETE");

        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nServer: t\r\n\r\nbody");
        ok(s == HTTP_FRAMED_UNFRAMEABLE,
           "a 200 with no length, no chunking, and a body is UNFRAMEABLE");

        /* A huge Content-Length must NEVER be classified COMPLETE. The
         * invariant under test is "no forged COMPLETE / no truncated resp_len",
         * and two safe rejections satisfy it depending on word size: on a 64-bit
         * build 18446744073709551614 (SIZE_MAX-1) parses but the addition-overflow
         * guard returns INCOMPLETE (can never be present in the address space);
         * on a 32-bit build the same digits exceed SIZE_MAX so the length parser
         * rejects them first as MALFORMED. Assert on the invariant (not COMPLETE),
         * not on which safe branch a given word size takes. */
        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\n"
                   "Content-Length: 18446744073709551614\r\n\r\nhello");
        ok((s == HTTP_FRAMED_INCOMPLETE || s == HTTP_FRAMED_MALFORMED) && n == 0,
           "a huge Content-Length is never forged COMPLETE (wrap or reject)");

        /* A huge chunk size must NEVER slip past the short-read check into an
         * out-of-bounds `p += size` walk. Same two safe outcomes: 64-bit
         * INCOMPLETE via the subtraction-form bounds test; 32-bit MALFORMED via
         * the chunk-size overflow guard rejecting fffffffffffffffe > SIZE_MAX. */
        n = 0;
        s = FRAMED("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "fffffffffffffffe\r\nhello");
        ok(s == HTTP_FRAMED_INCOMPLETE || s == HTTP_FRAMED_MALFORMED,
           "a huge chunk size never slips past the short-read check (wrap or reject)");

#undef FRAMED
    }

    /* ---- framed mode against a live keep-alive server ----------------- */

    /*
     * The classifier above proves the DECISION; these prove the read LOOP acts
     * on it -- stopping at the framed end of one response while the peer holds
     * the connection open, which no read-to-EOF loop can do.
     */
    {
        const unsigned char  req[] = "GET / HTTP/1.1\r\nHost: t\r\n\r\n";
        size_t               req_len = sizeof(req) - 1;
        char                 errbuf[256];
        int                  st, rc;
        pid_t                pid;
        int                  port = 0;

#define KA_RESP  "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

        /* 1. A framed read stops on framing against a server that never closes,
         *    and reports HTTP_CLOSE_FRAMED with exactly the one response. */
        pid = spawn_keepalive(&port, KA_RESP, sizeof(KA_RESP) - 1, 3000);
        rc = http_request("127.0.0.1", port, req, req_len, 1000, NULL,
                          NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                          HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 1,
                          NULL, &r, errbuf, sizeof(errbuf));
        ok(rc == 0 && r.close_reason == HTTP_CLOSE_FRAMED,
           "a framed read stops on framing against a peer that never closes");
        ok(rc == 0 && r.status == 200 && r.body_len == 5
           && r.body != NULL && memcmp(r.body, "hello", 5) == 0,
           "the framed read collected exactly the one framed response");
        if (rc == 0) {
            http_response_free(&r);
        }
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);

        /* 2. Negative control: the SAME never-closing server, read WITHOUT
         *    framed mode and without want_close, must exhaust the timeout and
         *    fail -- proving framed mode is what makes case 1 stop, not the
         *    server closing. */
        pid = spawn_keepalive(&port, KA_RESP, sizeof(KA_RESP) - 1, 3000);
        rc = http_request("127.0.0.1", port, req, req_len, 300, NULL,
                          NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                          HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 0,
                          NULL, &r, errbuf, sizeof(errbuf));
        ok(rc != 0,
           "without framed mode the same server hangs to timeout and fails");
        if (rc == 0) {
            http_response_free(&r);
        }
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);

        /* 3. Two whole responses pipelined on one connection: the framed read
         *    collects only the FIRST, never swallowing the second's bytes. */
        pid = spawn_keepalive(&port, KA_RESP KA_RESP,
                              2 * (sizeof(KA_RESP) - 1), 3000);
        rc = http_request("127.0.0.1", port, req, req_len, 1000, NULL,
                          NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                          HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 1,
                          NULL, &r, errbuf, sizeof(errbuf));
        ok(rc == 0 && r.raw_len == sizeof(KA_RESP) - 1
           && r.body_len == 5 && memcmp(r.body, "hello", 5) == 0,
           "a pipelined second response is left on the wire, not read into the first");
        if (rc == 0) {
            http_response_free(&r);
        }
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);

        /* 4. An unframeable response on a never-closing connection is a failure,
         *    not a hang: SPAWN_REPLY carries no length and no chunking. */
        pid = spawn_keepalive(&port, SPAWN_REPLY, SPAWN_REPLY_LEN, 3000);
        errbuf[0] = '\0';
        rc = http_request("127.0.0.1", port, req, req_len, 1000, NULL,
                          NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                          HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 1,
                          NULL, &r, errbuf, sizeof(errbuf));
        /* The verdict is pinned to the UNFRAMEABLE rejection, not merely to a
         * non-zero return: if the rejection is removed the loop falls through to
         * read-to-EOF and still fails -- but on the per-read TIMEOUT, a
         * different error whose message this test would no longer match. Without
         * anchoring on the message a mutant that deletes the rejection survives
         * (measured: it did). */
        ok(rc != 0 && strstr(errbuf, "unknowable on a connection") != NULL,
           "a framed read of an unframeable response is rejected as unframeable");
        if (rc == 0) {
            http_response_free(&r);
        }
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);

        /* 5. A chunked response terminates the framed read on its 0-chunk. */
        {
#define KA_CHUNKED \
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"

            pid = spawn_keepalive(&port, KA_CHUNKED,
                                  sizeof(KA_CHUNKED) - 1, 3000);
            rc = http_request("127.0.0.1", port, req, req_len, 1000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 1,
                              NULL, &r, errbuf, sizeof(errbuf));
            if (rc == 0) {
                http_dechunk(&r);
            }
            ok(rc == 0 && r.close_reason == HTTP_CLOSE_FRAMED
               && r.dechunk_status == HTTP_DECHUNK_OK
               && r.decoded_len == 5 && memcmp(r.decoded, "hello", 5) == 0,
               "a chunked framed read stops on the 0-chunk and decodes cleanly");
            if (rc == 0) {
                http_response_free(&r);
            }
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
#undef KA_CHUNKED
        }

        /* 6. A bodiless 204 completes the framed read at the header terminator
         *    without waiting for a body that will never come. */
        {
#define KA_204  "HTTP/1.1 204 No Content\r\nServer: t\r\n\r\n"

            pid = spawn_keepalive(&port, KA_204, sizeof(KA_204) - 1, 3000);
            rc = http_request("127.0.0.1", port, req, req_len, 1000, NULL,
                              NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                              HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 1,
                              NULL, &r, errbuf, sizeof(errbuf));
            ok(rc == 0 && r.close_reason == HTTP_CLOSE_FRAMED
               && r.status == 204 && r.body_len == 0,
               "a bodiless 204 framed read ends at the terminator, no body wait");
            if (rc == 0) {
                http_response_free(&r);
            }
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
#undef KA_204
        }
#undef KA_RESP
    }

    /* ---- http_exchange_concurrent ---------------------------------------
     *
     * The barrier fixture is what gives these assertions teeth: it answers
     * nobody until all N requests have arrived, so a driver that read leg 0
     * before writing leg 1 would hang until the deadline instead of passing.
     * That makes the first case below a negative control for the ordering, not
     * merely a check that N responses came back.
     */
    {
        static const unsigned char  creq[] =
            "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
        const size_t                creq_len = sizeof(creq) - 1;

        int            port, st;
        pid_t          pid;
        int            rc;
        char           errbuf[256];
        int            i;

        /* Sized to the ceiling, not to the 4-leg fan below: the over-ceiling
         * rejection case passes MAX_CONCURRENT + 1, and the driver initializes
         * up to MAX_CONCURRENT slots before it validates n. A 4-element array
         * would be written past by the very check being tested. */
        http_response  resps[MAX_CONCURRENT];

        /* 1. The load-bearing one: four requests must be in flight together
         *    before ANY of them is answered. */
        pid = spawn_barrier(&port, 4);
        rc = http_exchange_concurrent("127.0.0.1", port, 4, creq, creq_len,
                                      2000, NULL, NULL, 0, HTTP_SHUT_NONE,
                                      NULL, 0, 1, resps,
                                      errbuf, sizeof(errbuf));

        {
            /*
             * The ordering control, and it must assert the RESPONSES, not just
             * the return code. Verified by mutation: a driver that reads leg i
             * before writing leg i+1 still returns 0 here (its fused read fails
             * softly and the loop runs on), so an `rc == 0` assertion passes
             * with the ordering destroyed -- the exact overclaim shape of a test
             * whose name promises more than its condition checks. Requiring all
             * four legs to carry a real 200 is what the barrier can actually
             * distinguish, since under a serialized fan the reply to leg 0 does
             * not exist when leg 0 is read.
             */
            int all_200 = (rc == 0);

            for (i = 0; rc == 0 && i < 4; i++) {
                if (resps[i].status != 200) {
                    all_200 = 0;
                }
            }

            ok(all_200,
               "a 4-way fan is written in full before any leg is read -- all 4 "
               "get a 200 from a server that answers only once all 4 arrived");
        }

        {
            int all_body = (rc == 0);

            for (i = 0; rc == 0 && i < 4; i++) {
                if (resps[i].body_len != 2
                    || memcmp(resps[i].body, "hi", 2) != 0)
                {
                    all_body = 0;
                }
            }

            ok(all_body, "each leg's response body is collected independently");
        }

        /* Unconditional, which is the contract this section tests: on a failed
         * fan the earlier legs' buffers are already populated, so gating the
         * free on rc == 0 would attach a leak report to any red assertion under
         * SAN=1 and muddy the diagnosis. */
        for (i = 0; i < 4; i++) {
            http_response_free(&resps[i]);
        }

        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);

        /* 2. The floor is enforced in the driver too, not only in the parser --
         *    a caller reaching this directly must not get a one-leg "fan". */
        rc = http_exchange_concurrent("127.0.0.1", 1, 1, creq, creq_len,
                                      1000, NULL, NULL, 0, HTTP_SHUT_NONE,
                                      NULL, 0, 1, resps,
                                      errbuf, sizeof(errbuf));
        ok(rc == -1 && strstr(errbuf, "floor is 2") != NULL,
           "a fan of 1 is refused by the driver, not silently run");

        /* The rejection paths must still leave resps[] initialized, because the
         * header tells callers they may free unconditionally -- and a rejection
         * is exactly where a caller is least likely to have done it itself.
         * Freeing here is the assertion: under the pre-fix code resps[0] held
         * indeterminate stack, and this call would free a wild pointer. */
        ok(resps[0].status == -1 && resps[0].raw == NULL,
           "an argument rejection still initializes resps[], so the documented "
           "unconditional free is safe");
        http_response_free(&resps[0]);

        /* The ceiling is enforced at the public entry point too, not only by the
         * parser: a direct C caller never goes through load_rules(). */
        rc = http_exchange_concurrent("127.0.0.1", 1, MAX_CONCURRENT + 1,
                                      creq, creq_len, 1000, NULL, NULL, 0,
                                      HTTP_SHUT_NONE, NULL, 0, 1, resps,
                                      errbuf, sizeof(errbuf));
        ok(rc == -1 && strstr(errbuf, "exceeds the ceiling") != NULL,
           "a fan above MAX_CONCURRENT is refused by the driver, not opened");

        /* 3. A leg that cannot connect fails the whole case: N-1 overlapping
         *    requests are not the test the file asked for. Port 1 on loopback
         *    is closed, so every leg refuses. resps[] must still be safe to
         *    free after the failure. */
        rc = http_exchange_concurrent("127.0.0.1", 1, 3, creq, creq_len,
                                      1000, NULL, NULL, 0, HTTP_SHUT_NONE,
                                      NULL, 0, 1, resps,
                                      errbuf, sizeof(errbuf));
        ok(rc == -1 && strstr(errbuf, "connect failed") != NULL,
           "a leg that cannot connect fails the fan rather than narrowing it");

        for (i = 0; i < 3; i++) {
            http_response_free(&resps[i]);
        }

        /*
         * 4. S-4: the fan collects its legs OUT OF INDEX ORDER.
         *
         * This is the assertion the poll() drain exists for, and the one no
         * other case in this file can make. The barrier above proves the fan
         * writes all N before reading any -- a property of the WRITE phase.
         * Nothing there constrains the drain, because the barrier releases
         * every leg simultaneously and an in-order drain collects them all.
         *
         * spawn_readback() makes leg 0's answer DEPEND on the client having
         * drained the last leg: that leg carries a body far larger than the
         * socket buffer, so the server blocks in send() until the client reads
         * it, and only then answers leg 0. An in-order drain is blocked in leg
         * 0's read and never drains the big body, so neither side can proceed
         * and the fan dies on its deadline.
         *
         * >> THE FIRST VERSION OF THIS FIXTURE WAS VACUOUS AND THE MUTANT IS
         * THE ONLY REASON THAT IS KNOWN. It answered the legs in reverse order
         * and stalled before leg 0, then asserted an elapsed-time bound. It
         * PASSED against a restored in-order drain -- 401 ms for BOTH
         * implementations against a 400 ms stall -- because while the in-order
         * drain blocks on leg 0 the kernel is buffering the other legs
         * concurrently, so they are already complete when it reaches them. Any
         * fixture whose server answers on its own schedule cannot see drain
         * order at all, and an elapsed-time bound over it is vacuous in the S-3
         * sense. The dependency has to run through the CLIENT, which is what
         * this one does.
         *
         * VERIFIED AS A CONTROL: with phase 3 reverted to the in-order
         * `for (i...) http_read_response(...)` loop, this case fails BY THIS
         * ASSERTION while the barrier case above still passes -- the barrier
         * being exactly what an in-order drain satisfies.
         *
         * Asserted on completion, not on elapsed time. Under the poll() drain
         * every leg carries its response; under the in-order drain leg 0 never
         * arrives and the fan returns a harness error. There is no tolerance to
         * choose and nothing for load to inflate.
         */
        {
            int            port2, st2, k;
            pid_t          pid2;
            int            all_ok;

            /*
             * 1 MiB against the 16 KiB SO_RCVBUF/SO_SNDBUF the fixture now
             * FORCES on both ends (see spawn_readback()), so the server's
             * send() is guaranteed to block partway rather than being absorbed
             * whole -- which is what creates the dependency. The margin is
             * ~64x the forced window even after the kernel's doubling, and it
             * no longer rests on loopback autotuning happening to be smaller
             * than the body.
             *
             * SMALLER than the 4 MiB it replaces, and that is a consequence of
             * forcing the buffers rather than an unrelated tuning change. The
             * old size was chosen to beat an UNKNOWN, possibly-large autotuned
             * window; with the window pinned at 16 KiB the precondition is
             * established with far less data. It has to be less: a 16 KiB
             * receive window also throttles how fast the client can drain the
             * body, and 4 MiB through it does not complete inside the case's
             * 1000 ms deadline -- the assertion reddened against CORRECT code
             * when the buffers were first forced without shrinking the body.
             * Widening the deadline would have been the wrong fix; the body
             * size is what the buffer change actually invalidated.
             *
             * Still well under HTTP_MAX_RESPONSE, so the ceiling is not what is
             * being tested.
             */
            pid2 = spawn_readback(&port2, 4, 1024 * 1024);

            rc = http_exchange_concurrent("127.0.0.1", port2, 4, creq, creq_len,
                                          1000, NULL, NULL, 0, HTTP_SHUT_NONE,
                                          NULL, 0, 1, resps,
                                          errbuf, sizeof(errbuf));

            all_ok = (rc == 0);
            for (k = 0; rc == 0 && k < 4; k++) {
                if (resps[k].status != 200) {
                    all_ok = 0;
                }
            }

            ok(all_ok,
               "the fan drains legs by readiness, so a leg whose answer depends "
               "on a LATER leg being read still completes");

            for (k = 0; k < 4; k++) {
                http_response_free(&resps[k]);
            }

            kill(pid2, SIGKILL);
            waitpid(pid2, &st2, 0);
        }

        /*
         * The per-read idle deadline is PER LEG, and a chatty sibling does not
         * postpone it.
         *
         * This is the fan half of the F1 regression. The N=1 case proves the
         * idle bound exists again; it cannot prove the bound is held per leg,
         * because with one leg there is nothing to confuse it with. Under a
         * shared poll() loop the natural wrong implementations -- one idle
         * clock for the fan, or a bound recomputed from timeout_ms whenever
         * poll() returns -- are indistinguishable from the correct one at N=1
         * and fail only here.
         *
         * Leg 0 emits a byte every 50 ms for 3 s; legs 1-3 answer once and go
         * silent. With a 300 ms timeout the silent legs must give up at about
         * 300 ms even though poll() is being woken roughly every 50 ms by leg 0
         * throughout. want_close makes that expiry the verdict rather than an
         * error, so the fan completes and each leg carries its own close_reason.
         *
         * The ceiling is again the witness and is set the same way as the N=1
         * one: 4x timeout_ms sits far above scheduling noise on a 300 ms wait
         * and far below the 2400 ms whole-exchange budget, so it names WHICH
         * deadline fired. It is applied to each silent leg's own close_ms
         * rather than to the fan's elapsed time -- see the note at the loop
         * below for why the fan-wide wall clock cannot express this. A shared
         * or postponed idle clock keeps the silent legs alive behind leg 0's
         * traffic and reds this.
         */
        {
            int            port3, st3, k;
            pid_t          pid3;
            int            silent_timed_out = 1;
            int            silent_bounded = 1;

            pid3 = spawn_fan_lingering(&port3, 4, 3000, 50);

            memset(resps, 0, sizeof(resps));
            rc = http_exchange_concurrent("127.0.0.1", port3, 4, creq, creq_len,
                                          300, NULL, NULL, 0, HTTP_SHUT_NONE,
                                          NULL, 1, 0, resps,
                                          errbuf, sizeof(errbuf));

            /*
             * The silent legs, not leg 0: leg 0 is still being fed, so it is
             * not idle and is entitled to run to the whole-exchange budget.
             *
             * That is also why the witness is each leg's OWN close_ms and not
             * the fan's elapsed wall time. The fan does not return until every
             * leg is terminal, so leg 0 pins fan completion at the 8x budget
             * (measured: 2401 ms) no matter how promptly the silent legs
             * expire. A wall-clock bound over the whole fan therefore cannot
             * express this property at all -- it reds against correct code, as
             * the first cut of this assertion did. close_ms is per leg and
             * measured from that leg's own sent_at, which is exactly the
             * quantity the claim is about.
             */
            for (k = 1; rc == 0 && k < 4; k++) {
                if (resps[k].close_reason != HTTP_CLOSE_TIMEOUT) {
                    silent_timed_out = 0;
                }

                if (resps[k].close_ms >= 4 * 300) {
                    silent_bounded = 0;
                }
            }

            ok(rc == 0 && silent_timed_out,
               "every silent leg of a fan reaches its own idle timeout verdict");

            ok(rc == 0 && silent_bounded,
               "a chatty leg does not postpone its silent siblings' per-read "
               "idle deadlines");

            /* Unconditional, matching the sibling fan blocks and the contract
             * on http_exchange_concurrent(): resps[] is safe to free on every
             * return, including a failed one. Gating this on rc == 0 would
             * attach an LSan leak report to any red assertion under SAN=1 --
             * and this fan returns non-zero precisely when the idle behaviour
             * regresses, so the leak noise would land on top of the diagnosis
             * worth reading. */
            for (k = 0; k < 4; k++) {
                http_response_free(&resps[k]);
            }

            kill(pid3, SIGKILL);
            waitpid(pid3, &st3, 0);
        }

        /*
         * `recv_slow` paces EVERY leg of a fan, independently, and one leg's
         * gate does not stand in for its siblings'.
         *
         * This is the fan half of the pacing witness, and until it existed the
         * fan-pacing mutant was killed by assertion 104 -- the N=1 case. That
         * made the mutant a false control in the F4 sense: it proved the gate is
         * consulted somewhere, not that a fan consults one per leg. The three
         * fan-only mistakes it now discriminates are listed at spawn_fan_paced().
         *
         * The witness is per leg and an EQUALITY, for the same reason the N=1
         * case uses one: `paced_sleep_ms` is credited from sleep_ms()'s RETURN,
         * so gutting the sleep zeroes it rather than leaving it reporting sleeps
         * that never happened. The count is the same 4 the N=1 case measures and
         * rests on the same two facts -- the 418-byte reply at a 100-byte cap is
         * 5 reads, and `paced_full` paces only before a read the loop expects to
         * fill, so the final short read is unpaced.
         *
         * Deliberately NOT an aggregate over the fan. A fan that slept once for
         * all four legs and one that sleeps four times each are indistinguishable
         * by any sum, floor or total; only asking each leg what IT slept
         * separates them. Same rule the idle-deadline case above had to learn
         * from a first cut that was red against correct code.
         *
         * No wall-clock bound appears here at all. Under a correct drain the
         * four legs pace CONCURRENTLY, so fan elapsed time is about one leg's
         * pacing rather than four legs' worth -- but that is a property of the
         * scheduler as much as of the drain, and pinning it would re-introduce
         * exactly the load-sensitive assertion the s155 fix removed. The per-leg
         * counters say what the pacing did without asking the clock.
         */
        {
            int         port4, st4, k;
            pid_t       pid4;
            http_recv   rv4;
            int         paced_each = 1;
            int         all_answered;

            memset(&rv4, 0, sizeof(rv4));
            rv4.chunk = 100;
            rv4.ms = 30;

            pid4 = spawn_fan_paced(&port4, 4);

            memset(resps, 0, sizeof(resps));
            rc = http_exchange_concurrent("127.0.0.1", port4, 4, creq, creq_len,
                                          2000, NULL, NULL, 0, HTTP_SHUT_NONE,
                                          &rv4, 0, 0, resps,
                                          errbuf, sizeof(errbuf));

            all_answered = (rc == 0);

            for (k = 0; rc == 0 && k < 4; k++) {
                if (resps[k].status != 200) {
                    all_answered = 0;
                }

                if (resps[k].paced_sleep_ms != 4 * rv4.ms) {
                    paced_each = 0;
                }
            }

            ok(all_answered,
               "a fan carrying recv_slow still collects every leg's response");

            ok(rc == 0 && paced_each,
               "recv_slow paces every leg of a fan on its own gate, not once "
               "for the fan");

            /* Unconditional, per http_exchange_concurrent()'s contract and for
             * the reason spelled out at the sibling fan above: this fan returns
             * non-zero exactly when the behaviour under test regresses, so a
             * success-gated free would pin an LSan report to the red assertion
             * that matters. */
            for (k = 0; k < 4; k++) {
                http_response_free(&resps[k]);
            }

            kill(pid4, SIGKILL);
            waitpid(pid4, &st4, 0);
        }

        /*
         * When two legs fail in one iteration, the fan blames the FIRST BY
         * INDEX and quotes THAT leg's own error.
         *
         * Both halves of this were unpinned: no case in this file made two legs
         * fail at once, so nothing separated first-by-index from last-to-fail,
         * and nothing caught the error being read out of the wrong slot (PR
         * #151 F4). The driver documents index order specifically because it is
         * reproducible and bisectable where arrival order is not, so an
         * undetected drift to "whoever failed last" would quietly make fan
         * diagnostics non-deterministic -- the failure mode where the harness
         * blames a different leg on each run of the same broken server.
         *
         * The fixture fails leg 1 as UNFRAMEABLE and leg 2 as MALFORMED, both
         * terminal on their first read, so they land in the same drain
         * iteration with messages that name which one was blamed. Legs 0 and 3
         * answer correctly, so a driver that failed the whole fan cannot pass
         * this by accident.
         *
         * Asserted on the message TEXT rather than on a leg number alone
         * because the leg number and the error string come from different
         * places -- the index from the loop, the text from `errs + i *
         * HTTP_LEG_ERRLEN`. Checking only "leg 2/4" would still pass if the
         * prefix were right and the quoted error came from leg 3's slot, which
         * is precisely the shared-buffer bug the per-leg slots exist to
         * prevent. Both are checked, so the assertion reds if either drifts.
         *
         * Both substrings are lifted from http.c, not paraphrased -- the
         * UNFRAMEABLE text at http.c:2163 and the MALFORMED text at
         * http.c:2171. That matters most for the NEGATIVE clause: if the
         * MALFORMED message did not literally contain "malformed
         * Content-Length", the clause would be true whichever slot was quoted
         * and the wrong-slot regression would walk straight through it.
         * MUTATION-PROVEN rather than argued: the slot-index mutant
         * ("fan quotes a sibling's error slot") reds THIS assertion alone,
         * with 170 green.
         */
        {
            int    port5, st5, k;
            pid_t  pid5;
            int    blamed_leg_2;
            int    quoted_its_own_error;

            pid5 = spawn_fan_two_bad(&port5, 4);

            memset(resps, 0, sizeof(resps));
            errbuf[0] = '\0';

            /* framed = 1: the framing verdict is what makes these two legs
             * fail, and with distinguishable reasons. */
            rc = http_exchange_concurrent("127.0.0.1", port5, 4, creq, creq_len,
                                          1000, NULL, NULL, 0, HTTP_SHUT_NONE,
                                          NULL, 0, 1, resps,
                                          errbuf, sizeof(errbuf));

            /* Leg 1 of 4 in the driver's 1-based reporting is index 1, i.e.
             * "leg 2/4" -- the lower-indexed of the two failing legs. */
            blamed_leg_2 = (strstr(errbuf, "concurrent leg 2/4:") != NULL);

            /* Leg 1's own failure is the UNFRAMEABLE one. Seeing the MALFORMED
             * text here would mean the right leg was named but leg 2's slot was
             * quoted. */
            quoted_its_own_error =
                (strstr(errbuf, "no Content-Length") != NULL
                 && strstr(errbuf, "malformed Content-Length") == NULL);

            ok(rc == -1 && blamed_leg_2,
               "two legs failing at once are attributed to the first BY INDEX");

            ok(rc == -1 && quoted_its_own_error,
               "the blamed leg's error comes from its OWN slot, not a "
               "sibling's");

            /* Unconditional, per the contract and for the reason given at the
             * sibling fan blocks -- and it matters most here, where rc == -1 is
             * the EXPECTED outcome rather than a failure. */
            for (k = 0; k < 4; k++) {
                http_response_free(&resps[k]);
            }

            kill(pid5, SIGKILL);
            waitpid(pid5, &st5, 0);
        }
    }

    /* ---- optional TLS transport (T-1 part 1) ------------------------------
     *
     * Three things worth proving, per the item's own instructions:
     *
     *   1. The plaintext path is unchanged -- every test above this block IS
     *      that control, since none of them pass a non-NULL tls_opt and all of
     *      them still exercise write_all()/the reader/the idle-wait peek with
     *      tls_table_get() returning NULL on every call. A new plaintext-only
     *      assertion here would duplicate that rather than add to it.
     *   2. A TLS handshake against a locally-spawned TLS server actually
     *      completes and a request/response round-trips.
     *   3. Teardown clears the slot: an fd reused after http_close() does NOT
     *      inherit the previous SSL handle.
     *
     * spawn_tls_echo() returning -1 means this environment could not produce a
     * working OpenSSL server context (cert/key generation or SSL_CTX setup
     * failed) -- SKIP loudly rather than silently pass, since neither the
     * handshake test nor the fd-reuse test can say anything true without a
     * live TLS peer to prove it against.
     */
    {
        int  tls_port = 0;
        pid_t  tls_pid = spawn_tls_echo(&tls_port);

        if (tls_pid < 0) {
            printf("ok %d - TLS handshake completes against a locally "
                   "spawned TLS server "
                   "# SKIP no usable OpenSSL server context in this "
                   "environment\n", ++tests_run);
            printf("ok %d - a request/response round-trips over the TLS leg "
                   "with the expected status and body "
                   "# SKIP no usable OpenSSL server context in this "
                   "environment\n", ++tests_run);
            printf("ok %d - a second TLS connection is established after "
                   "the first is closed "
                   "# SKIP no usable OpenSSL server context in this "
                   "environment\n", ++tests_run);
            printf("ok %d - the closed fd is handed back by the kernel for "
                   "the second connection "
                   "# SKIP no usable OpenSSL server context in this "
                   "environment\n", ++tests_run);
            printf("ok %d - a second, independent TLS connection also "
                   "round-trips after the first is closed "
                   "# SKIP no usable OpenSSL server context in this "
                   "environment\n", ++tests_run);
            printf("ok %d - TLS handshake fails loudly against a plaintext "
                   "peer rather than silently downgrading "
                   "# SKIP no usable OpenSSL server context in this "
                   "environment\n", ++tests_run);
        } else {
            static const unsigned char  req[] =
                "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
            http_tls       tls_on;
            http_response  resp;
            char           errbuf[256];
            int            rc, first_fd, second_fd;
            int            st;

            memset(&tls_on, 0, sizeof(tls_on));
            tls_on.enable = 1;
            tls_on.verify = 0;  /* self-signed fixture cert; see http.h */

            /*
             * http_connect()+http_exchange()+http_close() rather than
             * http_request(), because proving fd reuse needs the raw fd
             * number back -- http_request() would close it before this code
             * ever saw it.
             */
            first_fd = http_connect("127.0.0.1", tls_port, 5000, NULL, NULL,
                                    &tls_on, errbuf, sizeof(errbuf));

            ok(first_fd >= 0, "TLS handshake completes against a locally "
                              "spawned TLS server");

            memset(&resp, 0, sizeof(resp));

            if (first_fd >= 0) {
                rc = http_exchange(first_fd, req, sizeof(req) - 1, 5000,
                                   NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                                   HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 0,
                                   &resp, NULL, errbuf, sizeof(errbuf));

                /* Content assertion, not a byte-count one: SPAWN_REPLY's
                 * body is the repeating "0123...63" digit run, so the body
                 * the client received must END in that same run regardless
                 * of how many header bytes precede it -- a header edit that
                 * changes SPAWN_REPLY_LEN must not turn this red. */
#define SPAWN_REPLY_BODY_TAIL  "67890123456789012345678901234567890123456789012"
                ok(rc == 0 && resp.status == 200
                   && resp.body_len > sizeof(SPAWN_REPLY_BODY_TAIL) - 1
                   && resp.body != NULL
                   && memcmp(resp.body + resp.body_len
                                       - (sizeof(SPAWN_REPLY_BODY_TAIL) - 1),
                             SPAWN_REPLY_BODY_TAIL,
                             sizeof(SPAWN_REPLY_BODY_TAIL) - 1) == 0,
                   "a request/response round-trips over the TLS leg with "
                   "the expected status and body");

                http_response_free(&resp);
                http_close(first_fd);
            } else {
                /* Cannot round-trip a request over a connection that never
                 * existed; report the dependent assertion as a failure
                 * rather than silently omitting it -- a skipped-because-
                 * unreachable assertion reads as a pass, which is the
                 * anti-pattern this whole item is written to avoid. */
                ok(0, "a request/response round-trips over the TLS leg with "
                      "the expected status and body");
            }

            /*
             * fd-reuse / teardown proof: open a second TLS connection. Under
             * normal kernel fd-allocation behaviour the just-closed fd number
             * is the lowest free one and gets handed back immediately, so
             * second_fd is very likely == first_fd here -- but the assertion
             * does not depend on that coincidence. What it depends on is that
             * http_close() called tls_table_del() on first_fd: if it had not,
             * tls_table_put() below would either collide with a live slot (if
             * the kernel reused the number) or simply coexist with a leaked
             * stale entry (if it did not) -- neither of which this test can
             * tell apart from outside. So the direct proof is that a FRESH
             * handshake and round-trip on a new connection succeeds cleanly
             * with no interference from the torn-down one; a stale slot
             * pointing tls_table_get(second_fd) at the OLD, freed SSL* would
             * make SSL_write/SSL_read below operate on freed memory, which
             * ASan (this repo's default build) turns into a hard crash rather
             * than a quiet wrong answer.
             */
            second_fd = http_connect("127.0.0.1", tls_port, 5000, NULL, NULL,
                                     &tls_on, errbuf, sizeof(errbuf));

            ok(second_fd >= 0, "a second TLS connection is established after "
                               "the first is closed");

            /* Separate, clearly-labelled observation carrying the reuse
             * claim: the kernel hands the lowest free fd back first, so if
             * http_close() actually removed first_fd from the fd table this
             * is normally == first_fd. This does NOT by itself prove the
             * TLS side-table slot was cleared -- see the comment above for
             * why that real proof is the ASan-backed round-trip below.
             *
             * Reported as a TODO rather than a hard gate, because "lowest
             * free fd" is a kernel policy this harness does not control:
             * anything that opens a descriptor between the http_close() and
             * the http_connect() above -- an OpenSSL internal, a resolver
             * socket, a sanitizer -- legitimately breaks the equality
             * without any defect in http_close(). Asserting it outright
             * would buy a flake on other environments in exchange for a
             * fact the round-trip below already proves properly. */
            if (second_fd == first_fd) {
                printf("ok %d - the closed fd is handed back by the kernel "
                       "for the second connection\n", ++tests_run);
            } else {
                printf("ok %d - the closed fd is handed back by the kernel "
                       "for the second connection # TODO kernel returned fd "
                       "%d, not %d; fd-reuse is not guaranteed here\n",
                       ++tests_run, second_fd, first_fd);
            }

            if (second_fd >= 0) {
                memset(&resp, 0, sizeof(resp));

                rc = http_exchange(second_fd, req, sizeof(req) - 1, 5000,
                                   NULL, 0, HTTP_SHUT_NONE, HTTP_ABORT_NONE,
                                   HTTP_HOLD_NONE, NULL, 0, HTTP_IDLE_NONE, 0,
                                   &resp, NULL, errbuf, sizeof(errbuf));

                ok(rc == 0 && resp.status == 200,
                   "a second, independent TLS connection also round-trips "
                   "after the first is closed");

                http_response_free(&resp);
                http_close(second_fd);
            } else {
                ok(0, "a second, independent TLS connection also round-trips "
                      "after the first is closed");
            }

            /* spawn_tls_echo()'s child loops accepting up to
             * SPAWN_TLS_ECHO_MAX_CONNS connections; this block only ever
             * drives two, so the child is still blocked in accept() waiting
             * for a connection that will never come. SIGKILL it rather than
             * a bare waitpid(), which would hang here. */
            kill(tls_pid, SIGKILL);
            waitpid(tls_pid, &st, 0);

            /*
             * Negative control for the handshake assertion above: ask for TLS
             * against a PLAINTEXT server (spawn_echo(), which speaks raw HTTP,
             * never TLS records). A client that silently fell back to
             * plaintext on a failed/skipped handshake would make this
             * indistinguishable from success -- exactly the anti-pattern
             * http.h's http_tls comment and the item's own instructions both
             * call out. The handshake must fail outright.
             */
            {
                int    plain_port = 0;
                int    fds[2];
                pid_t  plain_pid;
                int    plain_fd;
                char   perrbuf[256];

                if (pipe(fds) == 0) {
                    plain_pid = spawn_echo(&plain_port, sizeof(req) - 1, 0,
                                           fds[1]);
                    close(fds[1]);

                    plain_fd = http_connect("127.0.0.1", plain_port, 1000,
                                            NULL, NULL, &tls_on, perrbuf,
                                            sizeof(perrbuf));

                    ok(plain_fd < 0, "TLS handshake fails loudly against a "
                                     "plaintext peer rather than silently "
                                     "downgrading");

                    if (plain_fd >= 0) {
                        http_close(plain_fd);
                    }

                    {
                        echo_result  discard;
                        int          pst;

                        /* Drain the fixture's result pipe and reap it like
                         * every other spawn_echo() user does, so this block
                         * leaves no zombie or blocked writer behind even
                         * though the exchange above never sent a request. The
                         * result is discarded on purpose -- this control cares
                         * only that the TLS handshake itself failed, and the
                         * child's own read/timing report is unused; the
                         * assignment silences -Wunused-result without
                         * pretending a short read here is a fixture bug. */
                        ssize_t  ndiscard = read(fds[0], &discard,
                                                 sizeof(discard));

                        (void) ndiscard;
                        close(fds[0]);
                        kill(plain_pid, SIGKILL);
                        waitpid(plain_pid, &pst, 0);
                    }
                } else {
                    ok(0, "TLS handshake fails loudly against a plaintext "
                          "peer rather than silently downgrading");
                }
            }
        }
    }

    /* ---- http_poll_timeout_ms -------------------------------------------
     *
     * The narrowing that feeds poll(). `-t` accepts up to INT_MAX and the
     * whole-exchange budget is 8x that, so the values that matter here are
     * above INT_MAX -- an exchange would need weeks of wall time to reach one,
     * which is why this boundary cannot be tested through a socket and went
     * untested when the S-4 drain first started passing the 8x budget straight
     * to the poll() API.
     *
     * The failure being excluded is specific: an oversized long narrowed to int
     * comes out NEGATIVE in practice, and a negative poll() timeout means "wait
     * forever". The harness would hang with no error rather than time out.
     */
    {
        ok(http_poll_timeout_ms(0) == 0,
           "a zero wait narrows to an immediate poll, not a blocking one");

        ok(http_poll_timeout_ms(1000) == 1000,
           "an ordinary wait passes through unchanged");

        ok(http_poll_timeout_ms(INT_MAX) == INT_MAX,
           "a wait at exactly INT_MAX is still representable and is kept");

        /* The whole point: 8 * INT_MAX as HTTP_MAX_EXCHANGE_MS would produce it
         * on a 64-bit long. Must clamp to a finite bound, never go negative. */
        ok(http_poll_timeout_ms((long) INT_MAX + 1) == INT_MAX,
           "a wait past INT_MAX clamps to INT_MAX rather than wrapping "
           "negative into an infinite poll");

        ok(HTTP_MAX_EXCHANGE_MS(INT_MAX) > INT_MAX
           && http_poll_timeout_ms(HTTP_MAX_EXCHANGE_MS(INT_MAX)) == INT_MAX,
           "the 8x whole-exchange budget of the largest accepted -t clamps to a "
           "finite poll timeout");

        /* Defensive: nothing should hand this a negative wait, but a wait that
         * is already past is a reason to poll immediately, not forever. */
        ok(http_poll_timeout_ms(-1) == 0,
           "a negative wait polls immediately rather than blocking forever");
    }

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
