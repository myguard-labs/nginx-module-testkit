/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fakesrv.c -- the fake upstream daemon: main(), the poll() loop, syscalls.
 *
 * Everything that decides WHAT to say lives in backend.c and is a pure function
 * over bytes; this file decides WHEN to say it and puts it on a socket. The
 * split is what lets backend_test.c prove the codecs and the script parser
 * without a port, and it keeps the sharp end -- fault timing, resets,
 * half-written replies -- in one reviewable file.
 *
 * Usage:
 *   fakesrv -script PATH [-listen HOST:PORT] [-portfile PATH]
 *           [-journal PATH] [-errfile PATH] [-idle-ms N]
 *
 *
 * FOUR HARD RULES, each of which has a recorded failure behind it:
 *
 * 1. NOTHING is ever written to stdout. The journal goes to a file, errors go
 *    to -errfile. This daemon is started by a shell script that is itself
 *    emitting TAP on stdout, and a single stray line interleaved into that
 *    stream corrupts the test report of a run that otherwise passed.
 *
 * 2. SINGLE PROCESS, poll(), no fork per connection. A forked child inherits
 *    the journal's stdio buffer and flushes a duplicate copy of every buffered
 *    record on exit, so the journal grows records nobody wrote. It also makes
 *    the accept count -- the one observable that proves keepalive reuse -- into
 *    a number that depends on process scheduling.
 *
 * 3. SIGPIPE is ignored and EPIPE is a normal close. This daemon deliberately
 *    writes to sockets it is about to reset and to peers that have already
 *    gone; with the default disposition the FIRST such write kills it with
 *    status 141, and the scenario reports a harness crash where the module was
 *    behaving exactly as the script asked.
 *
 * 4. The portfile is written atomically (tmp + fsync + rename) BEFORE the
 *    listener starts accepting. A shell polling for the port otherwise reads a
 *    zero-length file and parses "" as a port number, roughly one run in
 *    twenty -- the kind of flake that gets a CI leg disabled rather than fixed.
 */

#define _GNU_SOURCE

#include "backend.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>


#define MAX_CONNS   64
#define READ_CHUNK  4096

/*
 * AUD-06: an absolute ceiling on one connection's unconsumed input. The RESP
 * and memcached parsers reject an over-long incomplete frame as a protocol
 * error, so in normal operation the buffer never approaches this. It is the
 * backstop for the class: the largest LEGAL frame is a full RESP array of
 * BACKEND_MAX_ARGS bulk strings at BACKEND_MAX_VALUE each (~66 KB), so 256 KB
 * leaves generous headroom while keeping a single misbehaving or fuzzing peer
 * from growing the shared daemon's heap without bound and die()ing it -- which
 * would turn a targeted PR run into an infra failure rather than a test result.
 */
#define MAX_CONN_INPUT  (256 * 1024)

/* Default idle threshold for an `on=idle` fault, overridable with -idle-ms. */
#define DEFAULT_IDLE_MS  50


typedef struct {
    int             fd;
    int             in_use;

    unsigned char  *in;          /* unconsumed bytes read from the peer */
    size_t          in_len;
    size_t          in_cap;

    unsigned char  *out;         /* reply bytes not yet written */
    size_t          out_len;
    size_t          out_off;
    int             send_started;/* a "send" event was journalled for this reply */

    long            id;          /* journal connection id */
    long            cmds;        /* commands seen on this connection */

    /*
     * Deferred actions, armed by a fault and serviced by the loop.
     *
     * Every absolute time here is int64_t rather than long: they are all
     * derived from prober_monotonic_ms(), whose header explains why 32 bits
     * is not enough (a wrapped deadline reads as "disarmed" through the
     * `close_at_ms >= 0` sentinel below).
     */
    int64_t         close_at_ms; /* close_after: absolute deadline, or -1 */
    long            drip_bytes;  /* drip: piece size, or 0 for "write it all" */
    int64_t         drip_ms;
    int64_t         drip_next_ms;/* absolute time the next piece may go */
    int             close_after_write;
    int             rst_after_write;

    int64_t         last_active_ms;
} conn;


static FILE           *journal;
static FILE           *errout;
static backend_script  script;

static long  conn_seq;
static long  accepts_total;
static long  cmds_total;
static long  conns_max;
static long  conns_now;

/* Per-command occurrence counters, so `on=get:3` means the third get this
 * daemon has seen across every connection -- which is what a scenario can
 * predict, unlike a per-connection count. */
typedef struct {
    char  name[32];
    long  count;
} cmd_counter;

static cmd_counter counters[64];
static size_t      n_counters;

static volatile sig_atomic_t stop_flag;


static void
on_signal(int sig)
{
    (void) sig;
    stop_flag = 1;
}


/*
 * The clock itself lives in util.c so a self-test can reach it: this file has
 * a main() and links into no test binary, so a helper defined here is testable
 * only through the daemon, and the property that matters (the width of the
 * millisecond count) cannot be observed from outside at all.
 */
static int64_t
now_ms(void)
{
    return prober_monotonic_ms();
}


static void
jlog(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void
jlog(const char *fmt, ...)
{
    va_list ap;

    if (journal == NULL) {
        return;
    }

    va_start(ap, fmt);
    /* Same reasoning as die()'s vfprintf in util.c: jlog() is
     * __attribute__((format(printf, 1, 2))) and -Wformat=2 -Werror rejects a
     * non-literal format at every call site, so flawfinder's CWE-134 case
     * cannot arise. Journal VALUES are attacker-shaped and go through jstrn(),
     * which is a different check. */
    vfprintf(journal, fmt, ap);  /* flawfinder: ignore */
    va_end(ap);

    fputc('\n', journal);

    /*
     * Flushed per record rather than relying on line buffering. A daemon killed
     * by its scenario's teardown -- which is the normal way this process ends --
     * would otherwise lose the tail of the journal, and the missing records
     * would be exactly the ones describing whatever went wrong last.
     */
    fflush(journal);
}


/*
 * JSON string escaping for journal fields. Values come from a client's wire
 * bytes, so a quote, control character or non-UTF-8 byte in a key must not be
 * able to break out of the record, forge a field, or hand a downstream `jq`
 * an invalid JSONL line. The escaper itself lives in util.c as
 * prober_jstrn() -- same reasoning as now_ms() above: this file has a
 * main() and links into no test binary, so a self-test can only reach the
 * escaping logic if it lives somewhere else.
 */
static void
jstrn(FILE *fp, const char *s, size_t n)
{
    prober_jstrn(fp, s, n);
}


static void
jstr(FILE *fp, const char *s)
{
    jstrn(fp, s, strlen(s));
}


static long
bump_counter(const char *name)
{
    size_t i;

    for (i = 0; i < n_counters; i++) {
        if (strcmp(counters[i].name, name) == 0) {
            return ++counters[i].count;
        }
    }

    if (n_counters >= sizeof(counters) / sizeof(counters[0])) {
        /* Not fatal: a script with more distinct verbs than this table holds
         * still works, it just cannot target the overflow verbs by occurrence.
         * Reported so the omission is visible rather than silent. */
        if (errout != NULL) {
            fprintf(errout, "fakesrv: counter table full, \"%s\" untracked\n",
                    name);
            fflush(errout);
        }
        return -1;
    }

    snprintf(counters[n_counters].name, sizeof(counters[n_counters].name),
             "%s", name);
    counters[n_counters].count = 1;
    n_counters++;

    return 1;
}


static void
conn_close(conn *c, const char *by)
{
    if (!c->in_use) {
        return;
    }

    jlog("{\"ev\":\"close\",\"conn\":%ld,\"by\":\"%s\",\"cmds\":%ld}",
         c->id, by, c->cmds);

    close(c->fd);

    free(c->in);
    free(c->out);

    memset(c, 0, sizeof(*c));
    conns_now--;
}


/* Reset rather than close: SO_LINGER{1,0} makes close() send RST, so the peer
 * sees ECONNRESET instead of a clean FIN. Same primitive as the rule DSL's
 * `abort`, for the same reason -- a module's error path for a reset upstream is
 * not the path it takes for an orderly close. */
static void
conn_reset(conn *c)
{
    struct linger lg;

    lg.l_onoff = 1;
    lg.l_linger = 0;

    (void) setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    conn_close(c, "reset");
}


static void
out_set(conn *c, unsigned char *buf, size_t len)
{
    free(c->out);

    c->out = buf;
    c->out_len = len;
    c->out_off = 0;
    c->send_started = 0;
}


/* Action spelling for the journal, so a scenario can assert which fault the
 * server actually applied rather than inferring it from a wire side effect. */
static const char *
action_name(backend_action a)
{
    switch (a) {
    case BACKEND_ACT_TRUNCATE:          return "truncate";
    case BACKEND_ACT_LIE_BYTES:         return "lie_bytes";
    case BACKEND_ACT_RST:               return "rst";
    case BACKEND_ACT_ACCEPT_CLOSE:      return "accept_close";
    case BACKEND_ACT_DRIP:              return "drip";
    case BACKEND_ACT_CLOSE_AFTER:       return "close_after";
    case BACKEND_ACT_RAW:               return "raw";
    case BACKEND_ACT_CURSOR_NEVER_ZERO: return "cursor_never_zero";
    }
    return "unknown";
}


/* Journal that a fault fired (or, with applied=false, that it could not).
 * AUD-05: a fault that loads clean but silently runs the happy path is a
 * false-green; making "the fault was applied" a falsifiable journal record lets
 * a scenario assert the failure path it claims to exercise really ran. The
 * record carries `on` and `nth` as well as the action so a scenario arming
 * several faults with the same action on one connection can prove WHICH one
 * fired, not merely that some fault with that action did. */
static void
journal_fault(const conn *c, const backend_fault *f, int applied)
{
    if (journal == NULL) {
        return;
    }

    fputs("{\"ev\":\"fault\",\"conn\":", journal);
    fprintf(journal, "%ld", c->id);
    fputs(",\"on\":", journal);
    jstr(journal, f->cmd);
    fprintf(journal, ",\"nth\":%ld", f->nth);
    fprintf(journal, ",\"action\":\"%s\",\"applied\":%s}\n",
            action_name(f->action), applied ? "true" : "false");
    fflush(journal);
}


/*
 * Apply the fault (if any) for this command to the correct reply, arming
 * whatever deferred behaviour it asks for. Returns 0 when the connection has
 * been destroyed and the caller must stop touching it.
 */
static int
apply_fault(conn *c, const backend_fault *f, unsigned char *reply,
            size_t reply_len)
{
    if (f == NULL) {
        out_set(c, reply, reply_len);
        return 1;
    }

    /*
     * AUD-05 (apply-time half): truncate, drip and close_after all perturb an
     * OUTGOING reply, so a command that produces none -- memcached `quit`, whose
     * reply is empty and whose connection the caller then closes -- gives them
     * nothing to act on. The fault would journal applied:true and change nothing
     * on the wire, the same false green the lie_bytes path closes below. Load
     * time cannot catch it (empty-reply is a proto+verb property); fail loud
     * here instead. rst/accept_close need no reply, and raw/cursor_never_zero
     * synthesise their own, so none of those are caught by this guard.
     */
    if (reply_len == 0
        && (f->action == BACKEND_ACT_TRUNCATE
            || f->action == BACKEND_ACT_DRIP
            || f->action == BACKEND_ACT_CLOSE_AFTER))
    {
        journal_fault(c, f, 0);
        free(reply);
        conn_reset(c);
        return 0;
    }

    switch (f->action) {
    case BACKEND_ACT_RST:
        journal_fault(c, f, 1);
        free(reply);
        conn_reset(c);
        return 0;

    case BACKEND_ACT_ACCEPT_CLOSE:
        journal_fault(c, f, 1);
        free(reply);
        conn_close(c, "fault");
        return 0;

    case BACKEND_ACT_TRUNCATE:
        /*
         * Send the first `after` bytes of the reply and then cut. Clamped
         * rather than rejected when the reply is shorter than the cut point:
         * the script is asking for "the reply, severed here", and a get whose
         * value happens to be short should still exercise the sever.
         */
        if ((size_t) f->after < reply_len) {
            reply_len = (size_t) f->after;
        }

        journal_fault(c, f, 1);
        out_set(c, reply, reply_len);
        c->rst_after_write = 1;
        return 1;

    case BACKEND_ACT_LIE_BYTES: {
        size_t         lied_len;
        unsigned char *lied = backend_apply_lie(script.proto, reply, reply_len,
                                                f->delta, &lied_len);

        if (lied == NULL) {
            /*
             * The reply this command produced carries no declared length to
             * falsify (an END, a +OK, a nil). Load-time validation cannot know
             * this: the reply shape is a proto+verb property, so `lie_bytes
             * on=set` loads clean and only fails here. AUD-05: previously this
             * sent the reply UNTOUCHED, so the scenario ran the happy path
             * under a name claiming a length lie -- a false green. Fail loud
             * instead: journal that the fault could not apply and reset the
             * connection, so the scenario breaks on the wire rather than
             * silently passing. A script that reaches this has asked for a lie
             * on a reply that cannot carry one, which is an author error worth
             * surfacing, not swallowing.
             */
            journal_fault(c, f, 0);
            free(reply);
            conn_reset(c);
            return 0;
        }

        journal_fault(c, f, 1);
        free(reply);
        out_set(c, lied, lied_len);
        return 1;
    }

    case BACKEND_ACT_DRIP:
        journal_fault(c, f, 1);
        out_set(c, reply, reply_len);
        c->drip_bytes = f->bytes;
        c->drip_ms = f->ms;
        c->drip_next_ms = now_ms();
        return 1;

    case BACKEND_ACT_RAW:
        journal_fault(c, f, 1);
        free(reply);
        {
            unsigned char *copy = malloc(f->raw_len ? f->raw_len : 1);

            if (copy == NULL) {
                die("out of memory");
            }

            memcpy(copy, f->raw, f->raw_len);
            out_set(c, copy, f->raw_len);
        }
        return 1;

    case BACKEND_ACT_CLOSE_AFTER:
        journal_fault(c, f, 1);
        out_set(c, reply, reply_len);
        c->close_at_ms = now_ms() + f->ms;
        return 1;

    case BACKEND_ACT_CURSOR_NEVER_ZERO: {
        /*
         * Rewrite the SCAN cursor so it never returns to 0. The client loops
         * "until cursor 0", so this is the shape that hangs it -- a bug class a
         * real redis will never hand you, which is why it needs a fault.
         */
        unsigned char *buf = NULL;
        size_t         len = 0;
        const char    *frame = "*2\r\n$1\r\n7\r\n*0\r\n";

        journal_fault(c, f, 1);
        free(reply);

        len = strlen(frame);
        buf = malloc(len);

        if (buf == NULL) {
            die("out of memory");
        }

        memcpy(buf, frame, len);
        out_set(c, buf, len);
        return 1;
    }

    default:
        out_set(c, reply, reply_len);
        return 1;
    }
}


/*
 * Consume as many complete commands as the read buffer holds. Returns 0 when
 * the connection has been destroyed.
 */
static int
drain_commands(conn *c)
{
    while (c->in_len > 0 && c->out_len == 0) {
        backend_cmd    cmd;
        long           used;
        unsigned char *reply = NULL;
        size_t         reply_len = 0;
        long           nth;
        const backend_fault *f;

        if (script.proto == BACKEND_PROTO_MEMCACHED) {
            used = backend_parse_memcached(c->in, c->in_len, &cmd);
        } else {
            used = backend_parse_resp(c->in, c->in_len, &cmd);
        }

        if (used == 0) {
            /* Incomplete: wait for more bytes. Distinct from the error below,
             * which is why backend_parse_* separates the two returns. */
            return 1;
        }

        if (used < 0) {
            if (errout != NULL) {
                fprintf(errout, "fakesrv: protocol error on conn %ld\n", c->id);
                fflush(errout);
            }

            conn_close(c, "protocol-error");
            return 0;
        }

        c->cmds++;
        cmds_total++;

        nth = bump_counter(cmd.name);

        {
            size_t i;

            fprintf(journal ? journal : stderr,
                    "{\"ev\":\"cmd\",\"conn\":%ld,\"n\":%ld,\"cmd\":",
                    c->id, c->cmds);
            jstr(journal ? journal : stderr, cmd.name);
            fputs(",\"args\":[", journal ? journal : stderr);

            for (i = 0; i < cmd.n_args; i++) {
                if (i > 0) {
                    fputc(',', journal ? journal : stderr);
                }
                jstrn(journal ? journal : stderr, cmd.args[i],
                      cmd.args_len[i]);
            }

            fputs("]}\n", journal ? journal : stderr);

            if (journal != NULL) {
                fflush(journal);
            }
        }

        if (script.proto == BACKEND_PROTO_MEMCACHED) {
            backend_reply_memcached(&script, &cmd, &reply, &reply_len);
        } else {
            backend_reply_resp(&script, &cmd, &reply, &reply_len);
        }

        /* Consume the bytes BEFORE any fault can destroy the connection --
         * after conn_close() the buffer is freed and this arithmetic would run
         * on a dangling pointer. */
        memmove(c->in, c->in + used, c->in_len - (size_t) used);
        c->in_len -= (size_t) used;

        f = backend_fault_for(&script, cmd.name, nth);

        if (!apply_fault(c, f, reply, reply_len)) {
            return 0;
        }

        /* memcached `quit` produces no reply and ends the connection. */
        if (strcmp(cmd.name, "quit") == 0 && c->out_len == 0) {
            conn_close(c, "quit");
            return 0;
        }
    }

    return 1;
}


static void
write_portfile(const char *path, int port)
{
    char  tmp[4096];
    FILE *fp;
    int   fd;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp)) {
        die("portfile path too long: %s", path);
    }

    fp = fopen(tmp, "w");
    if (fp == NULL) {
        die("cannot write portfile %s: %s", tmp, strerror(errno));
    }

    fprintf(fp, "%d\n", port);
    fflush(fp);

    /*
     * fsync before rename. Without it the rename can be visible while the
     * contents are not yet on disk, and the polling shell reads an empty file
     * -- the zero-length-read flake this sequence exists to prevent.
     */
    fd = fileno(fp);
    if (fd >= 0) {
        (void) fsync(fd);
    }

    fclose(fp);

    if (rename(tmp, path) != 0) {
        die("cannot rename portfile into place: %s", strerror(errno));
    }
}


static void
usage(void)
{
    die("usage: fakesrv -script PATH [-listen HOST:PORT] [-portfile PATH] "
        "[-journal PATH] [-errfile PATH] [-idle-ms N]");
}


int
main(int argc, char **argv)
{
    const char        *opt_script = NULL;
    const char        *opt_listen = "127.0.0.1:0";
    const char        *opt_portfile = NULL;
    const char        *opt_journal = NULL;
    const char        *opt_errfile = NULL;
    int64_t            opt_idle_ms = DEFAULT_IDLE_MS;

    int                lfd, i;
    struct sockaddr_in addr;
    socklen_t          alen;
    conn               conns[MAX_CONNS];
    char               host[64];
    int                port = 0;
    struct sigaction   sa;

    memset(conns, 0, sizeof(conns));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-script") == 0 && i + 1 < argc) {
            opt_script = argv[++i];

        } else if (strcmp(argv[i], "-listen") == 0 && i + 1 < argc) {
            opt_listen = argv[++i];

        } else if (strcmp(argv[i], "-portfile") == 0 && i + 1 < argc) {
            opt_portfile = argv[++i];

        } else if (strcmp(argv[i], "-journal") == 0 && i + 1 < argc) {
            opt_journal = argv[++i];

        } else if (strcmp(argv[i], "-errfile") == 0 && i + 1 < argc) {
            opt_errfile = argv[++i];

        } else if (strcmp(argv[i], "-idle-ms") == 0 && i + 1 < argc) {
            opt_idle_ms = xstrtol(argv[++i], "-idle-ms");

        } else {
            usage();
        }
    }

    if (opt_script == NULL) {
        usage();
    }

    /*
     * Rule 3. Installed before the first socket exists, so there is no window
     * in which a write can take the default disposition.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* TERM/INT set a flag rather than exiting, so the summary record is still
     * written -- teardown kills this process, and a journal missing its summary
     * is a journal the scenario cannot assert on. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (opt_errfile != NULL) {
        errout = fopen(opt_errfile, "w");
        if (errout == NULL) {
            die("cannot open errfile %s: %s", opt_errfile, strerror(errno));
        }
    } else {
        errout = stderr;
    }

    backend_load(opt_script, &script);

    if (opt_journal != NULL) {
        journal = fopen(opt_journal, "w");
        if (journal == NULL) {
            die("cannot open journal %s: %s", opt_journal, strerror(errno));
        }
        setvbuf(journal, NULL, _IOLBF, 0);
    }

    /* Parse HOST:PORT. */
    {
        const char *colon = strrchr(opt_listen, ':');

        if (colon == NULL || (size_t) (colon - opt_listen) >= sizeof(host)) {
            die("bad -listen \"%s\", want HOST:PORT", opt_listen);
        }

        memcpy(host, opt_listen, (size_t) (colon - opt_listen));
        host[colon - opt_listen] = '\0';
        port = (int) xstrtol(colon + 1, "-listen port");
    }

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        die("socket: %s", strerror(errno));
    }

    {
        int one = 1;
        (void) setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short) port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        die("bad -listen host \"%s\"", host);
    }

    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        die("bind %s: %s", opt_listen, strerror(errno));
    }

    if (listen(lfd, 16) != 0) {
        die("listen: %s", strerror(errno));
    }

    /* Read back the bound port, which is the whole point of -listen :0. */
    alen = sizeof(addr);
    if (getsockname(lfd, (struct sockaddr *) &addr, &alen) != 0) {
        die("getsockname: %s", strerror(errno));
    }

    port = ntohs(addr.sin_port);

    /* Rule 4: the portfile lands before the first accept(), so a shell that
     * sees the file can always connect. */
    if (opt_portfile != NULL) {
        write_portfile(opt_portfile, port);
    }

    jlog("{\"ev\":\"listen\",\"port\":%d}", port);

    while (!stop_flag) {
        struct pollfd  pfd[MAX_CONNS + 1];
        int            nfd = 0, idx[MAX_CONNS + 1];
        int            timeout = 100;
        int64_t        t = now_ms();

        pfd[nfd].fd = lfd;
        pfd[nfd].events = POLLIN;
        idx[nfd] = -1;
        nfd++;

        for (i = 0; i < MAX_CONNS; i++) {
            conn *c = &conns[i];

            if (!c->in_use) {
                continue;
            }

            pfd[nfd].fd = c->fd;
            pfd[nfd].events = 0;

            /* Only ask for writability when there is something to write AND,
             * for a dripping reply, the next piece is actually due -- otherwise
             * poll() returns immediately every iteration and the drip becomes a
             * busy loop that writes the whole reply at once. */
            if (c->out_len > c->out_off) {
                if (c->drip_bytes == 0 || t >= c->drip_next_ms) {
                    pfd[nfd].events |= POLLOUT;
                } else {
                    int64_t wait = c->drip_next_ms - t;

                    if (wait < timeout) {
                        timeout = (int) wait;
                    }
                }
            } else {
                pfd[nfd].events |= POLLIN;
            }

            idx[nfd] = i;
            nfd++;
        }

        if (poll(pfd, (nfds_t) nfd, timeout) < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("poll: %s", strerror(errno));
        }

        t = now_ms();

        /* New connections. */
        if (pfd[0].revents & POLLIN) {
            int cfd = accept(lfd, NULL, NULL);

            if (cfd >= 0) {
                int slot = -1;

                for (i = 0; i < MAX_CONNS; i++) {
                    if (!conns[i].in_use) {
                        slot = i;
                        break;
                    }
                }

                if (slot < 0) {
                    close(cfd);

                } else {
                    conn *c = &conns[slot];
                    const backend_fault *f;
                    long nth;

                    memset(c, 0, sizeof(*c));
                    c->fd = cfd;
                    c->in_use = 1;
                    c->id = ++conn_seq;
                    c->close_at_ms = -1;
                    c->last_active_ms = t;

                    accepts_total++;
                    conns_now++;

                    if (conns_now > conns_max) {
                        conns_max = conns_now;
                    }

                    {
                        int one = 1;
                        (void) setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
                                          &one, sizeof(one));
                    }

                    jlog("{\"ev\":\"accept\",\"conn\":%ld,\"t_ms\":%" PRId64 "}",
                         c->id, t);

                    nth = bump_counter("connect");
                    f = backend_fault_for(&script, "connect", nth);

                    if (f != NULL && f->action == BACKEND_ACT_ACCEPT_CLOSE) {
                        journal_fault(c, f, 1);
                        conn_close(c, "fault");

                    } else if (f != NULL && f->action == BACKEND_ACT_RST) {
                        journal_fault(c, f, 1);
                        conn_reset(c);
                    }
                }
            }
        }

        /* Established connections. */
        for (i = 1; i < nfd; i++) {
            conn *c = &conns[idx[i]];

            if (!c->in_use) {
                continue;
            }

            if (pfd[i].revents & POLLIN) {
                ssize_t n;

                /* AUD-06: refuse to grow one connection past the ceiling.
                 * Close only this connection with a journaled protocol error;
                 * the daemon and every other connection carry on, so a hostile
                 * peer degrades to a closed socket rather than a dead daemon. */
                if (c->in_len + READ_CHUNK > MAX_CONN_INPUT) {
                    jlog("{\"ev\":\"proto_error\",\"conn\":%ld,"
                         "\"reason\":\"input over %d bytes\"}",
                         c->id, MAX_CONN_INPUT);
                    conn_close(c, "input-limit");
                    continue;
                }

                if (c->in_len + READ_CHUNK > c->in_cap) {
                    size_t         want = c->in_cap ? c->in_cap * 2 : READ_CHUNK * 2;
                    unsigned char *bigger;

                    while (want < c->in_len + READ_CHUNK) {
                        want *= 2;
                    }

                    bigger = realloc(c->in, want);
                    if (bigger == NULL) {
                        die("out of memory");
                    }

                    c->in = bigger;
                    c->in_cap = want;
                }

                n = read(c->fd, c->in + c->in_len, READ_CHUNK);

                if (n > 0) {
                    c->in_len += (size_t) n;
                    c->last_active_ms = t;

                    if (!drain_commands(c)) {
                        continue;
                    }

                } else if (n == 0) {
                    conn_close(c, "peer");
                    continue;

                } else if (errno != EAGAIN && errno != EWOULDBLOCK
                           && errno != EINTR)
                {
                    conn_close(c, "read-error");
                    continue;
                }
            }

            if ((pfd[i].revents & POLLOUT) && c->out_len > c->out_off) {
                size_t  want = c->out_len - c->out_off;
                ssize_t n;

                if (c->drip_bytes > 0 && (size_t) c->drip_bytes < want) {
                    want = (size_t) c->drip_bytes;
                }

                n = write(c->fd, c->out + c->out_off, want);

                if (n > 0) {
                    /* AUD-10: a distinct "reply output began" event, emitted
                     * once when the FIRST byte of this reply reaches the wire.
                     * The "cmd" event proves only that the get was RECEIVED;
                     * "send" proves the backend has started dripping bytes back
                     * toward nginx, so a scenario polling for it before a reload
                     * knows the reply is genuinely in flight -- not merely that
                     * the request arrived a moment before the drip could start.
                     * out_set() clears the flag when a new reply is armed, so a
                     * connection serving several replies journals one "send" per
                     * reply, not one per connection. */
                    if (!c->send_started) {
                        c->send_started = 1;
                        jlog("{\"ev\":\"send\",\"conn\":%ld,\"n\":%ld}",
                             c->id, c->cmds);
                    }

                    c->out_off += (size_t) n;
                    c->last_active_ms = t;

                    if (c->drip_bytes > 0) {
                        c->drip_next_ms = t + c->drip_ms;
                    }

                    if (c->out_off >= c->out_len) {
                        /* Reply fully written. */
                        free(c->out);
                        c->out = NULL;
                        c->out_len = 0;
                        c->out_off = 0;
                        c->drip_bytes = 0;

                        if (c->rst_after_write) {
                            conn_reset(c);
                            continue;
                        }

                        if (c->close_after_write) {
                            conn_close(c, "fault");
                            continue;
                        }

                        /* More pipelined commands may be waiting. */
                        if (!drain_commands(c)) {
                            continue;
                        }
                    }

                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK
                           && errno != EINTR)
                {
                    /* Rule 3: EPIPE is a normal close here, not an error. */
                    conn_close(c, errno == EPIPE ? "peer" : "write-error");
                    continue;
                }
            }

            if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                conn_close(c, "peer");
                continue;
            }
        }

        /* Deferred closes: close_after deadlines and idle faults. */
        for (i = 0; i < MAX_CONNS; i++) {
            conn *c = &conns[i];

            if (!c->in_use) {
                continue;
            }

            if (c->close_at_ms >= 0 && t >= c->close_at_ms) {
                conn_close(c, "close_after");
                continue;
            }

            if (c->out_len == 0 && t - c->last_active_ms >= opt_idle_ms) {
                const backend_fault *f = backend_fault_for(&script, "idle",
                                                           BACKEND_NTH_ANY);

                if (f != NULL && f->action == BACKEND_ACT_CLOSE_AFTER
                    && t - c->last_active_ms >= f->ms)
                {
                    /* The keepalive-pool case: the peer parked this connection
                     * and the backend hangs up underneath it. */
                    journal_fault(c, f, 1);
                    conn_close(c, "idle");
                    continue;
                }
            }
        }
    }

    for (i = 0; i < MAX_CONNS; i++) {
        conn_close(&conns[i], "shutdown");
    }

    close(lfd);

    /*
     * The summary. This single record is what makes the keepalive claim
     * falsifiable in one line: accepts==1 with cmds==5 proves the connection
     * was reused, accepts==5 proves it was not, and no amount of reading the
     * module's own logs settles it as directly.
     */
    jlog("{\"ev\":\"summary\",\"accepts\":%ld,\"conns_max\":%ld,\"cmds\":%ld}",
         accepts_total, conns_max, cmds_total);

    if (journal != NULL) {
        fclose(journal);
    }

    if (errout != NULL && errout != stderr) {
        fclose(errout);
    }

    backend_free(&script);

    return 0;
}
