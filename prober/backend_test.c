/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * backend_test.c -- TAP self-test for the fake upstream's parser and codecs.
 *
 * Covers backend.c only: the script parser, the fault model, both protocol
 * parsers, both reply builders and the lie_bytes rewriter. Everything here is a
 * pure function over bytes, which is exactly why they were split out of
 * fakesrv.c -- no port is bound and no process is spawned, so this suite proves
 * the daemon's decisions before the daemon exists to make them.
 *
 * THE REJECTIONS ARE THE INTERESTING HALF. A fault that the parser silently
 * dropped leaves a scenario exercising the happy path while its name and its
 * TAP output both claim it is exercising a failure -- and a scenario that tests
 * nothing passes very reliably. So most of what follows feeds malformed scripts
 * and asserts they are REFUSED, not that valid ones are accepted.
 *
 * backend_load() dies rather than returning an error, so those cases cannot be
 * called in-process. Each runs in a fork and the parent asserts on the exit
 * status (2, per util.h) and on the message, following util_test.c -- checking
 * the status alone would pass on a crash.
 */

/* mkstemp()/fdopen() are POSIX, not C11, and the build asks for -std=c11. */
#define _GNU_SOURCE

#include "backend.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  110

static int  tests_run = 0;
static int  failures = 0;


static void
ok(int cond, const char *name)
{
    tests_run++;

    if (cond) {
        printf("ok %d - %s\n", tests_run, name);
    } else {
        printf("not ok %d - %s\n", tests_run, name);
        failures++;
    }
}


/* Write `text` to a temporary file and return its path in `path`. */
static void
write_script(char *path, size_t pathlen, const char *text)
{
    FILE *fp;
    int   fd;

    snprintf(path, pathlen, "/tmp/backend_test.%d.XXXXXX", (int) getpid());

    fd = mkstemp(path);
    if (fd < 0) {
        die("mkstemp failed");
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        die("fdopen failed");
    }

    fputs(text, fp);
    fclose(fp);
}


/*
 * Load a script in a child and report how it died, with the child's stderr in
 * `msg` so the caller can assert the diagnostic names the problem.
 *
 * Same shape as util_test.c's run_child, and for the same reasons: stdout is
 * flushed before the fork (a fully-buffered TAP stream would otherwise be
 * re-emitted by every child), and the pipe is drained to EOF (closing it early
 * left the child writing into a pipe with no reader, so it died of SIGPIPE
 * before die() could exit 2 -- a flake, not a failure).
 */
static int
load_child(const char *text, char *msg, size_t msglen)
{
    int     pipefd[2];
    int     status;
    pid_t   pid;
    char    path[256];

    msg[0] = '\0';

    write_script(path, sizeof(path), text);

    if (pipe(pipefd) != 0) {
        return -1;
    }

    fflush(stdout);
    fflush(stderr);

    pid = fork();

    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        backend_script s;

        close(pipefd[0]);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        backend_load(path, &s);

        /* Reached only if backend_load returned where it should have died.
         * Exit 0 so the parent's "expected 2" assertion fails loudly. */
        _exit(0);
    }

    close(pipefd[1]);

    {
        size_t   used = 0;
        ssize_t  n;

        while (used + 1 < msglen
               && (n = read(pipefd[0], msg + used, msglen - 1 - used)) > 0)
        {
            used += (size_t) n;
        }

        msg[used] = '\0';
    }

    close(pipefd[0]);

    if (waitpid(pid, &status, 0) < 0) {
        unlink(path);
        return -1;
    }

    unlink(path);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    /* 128+signo, which no legitimate path produces, so a crash cannot be
     * mistaken for a clean rejection. */
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}


/* Load a script that is expected to PARSE, in-process. */
static void
load_ok(backend_script *s, const char *text)
{
    char path[256];

    write_script(path, sizeof(path), text);
    backend_load(path, s);
    unlink(path);
}


static void
test_script_parser(void)
{
    backend_script s;
    char           msg[1024];
    int            rc;

    /* ---- the happy path ---- */

    load_ok(&s, "proto memcached\nseed hello world\n");
    ok(s.proto == BACKEND_PROTO_MEMCACHED, "proto memcached is parsed");
    ok(s.n_entries == 1, "seed creates one entry");
    {
        const backend_entry *e = backend_get(&s, "hello");
        ok(e != NULL && e->value_len == 5 && memcmp(e->value, "world", 5) == 0,
           "seed stores the value verbatim");
    }
    backend_free(&s);

    load_ok(&s, "proto redis\n");
    ok(s.proto == BACKEND_PROTO_REDIS, "proto redis is parsed");
    backend_free(&s);

    /* Escapes in a seed value: a cache client's least-handled input. */
    load_ok(&s, "proto redis\nseed k a\\r\\nb\n");
    {
        const backend_entry *e = backend_get(&s, "k");
        ok(e != NULL && e->value_len == 4
           && memcmp(e->value, "a\r\nb", 4) == 0,
           "seed value decodes \\r\\n escapes");
    }
    backend_free(&s);

    load_ok(&s, "proto redis\nseed k a\\x00b\n");
    {
        const backend_entry *e = backend_get(&s, "k");
        ok(e != NULL && e->value_len == 3
           && memcmp(e->value, "a\0b", 3) == 0,
           "seed value carries an embedded NUL");
    }
    backend_free(&s);

    /* A zero-length value is a LEGAL memcached entry and a classic
     * reply-framing off-by-one: `VALUE k 0 0\r\n\r\nEND\r\n` has an empty
     * payload between two CRLFs, so a client that miscounts either eats the
     * terminating CRLF as payload or rejects a frame that is correct. The
     * script format could not express it at all until now. */
    load_ok(&s, "proto memcached\nseed k \"\"\n");
    {
        const backend_entry *e = backend_get(&s, "k");
        ok(e != NULL && e->value_len == 0,
           "seed \"\" stores a zero-length value");
    }
    backend_free(&s);

    /* Only the exact token is special: the format has no general quoting rule,
     * so a quoted-looking value keeps its quotes. Without this a scenario
     * seeding `"a"` would silently store `a` and assert against the wrong
     * bytes. */
    load_ok(&s, "proto memcached\nseed k \"a\"\n");
    {
        const backend_entry *e = backend_get(&s, "k");
        ok(e != NULL && e->value_len == 3
           && memcmp(e->value, "\"a\"", 3) == 0,
           "a quoted value keeps its quotes -- only bare \"\" is the marker");
    }
    backend_free(&s);

    /* A bare `seed k` stays FATAL. Far more often a typo than an intention,
     * and a silently-empty seed would make a scenario assert against a value
     * it never stored -- the reason the empty case needs an explicit marker
     * rather than a relaxed parser. */
    rc = load_child("proto memcached\nseed k\n", msg, sizeof(msg));
    ok(rc == 2 && strstr(msg, "has no value") != NULL,
       "a bare seed with no value is still fatal");

    /* Comments and blank lines. */
    load_ok(&s, "# a comment\n\nproto memcached\n\n# another\nseed a b\n");
    ok(s.n_entries == 1, "comments and blank lines are skipped");
    backend_free(&s);

    /* ---- faults parse into the right shape ---- */

    load_ok(&s, "proto memcached\nfault on=get:3 action=truncate after=8\n");
    ok(s.n_faults == 1, "one fault is parsed");
    ok(strcmp(s.faults[0].cmd, "get") == 0, "fault command is stored");
    ok(s.faults[0].nth == 3, "fault occurrence is stored");
    ok(s.faults[0].action == BACKEND_ACT_TRUNCATE, "truncate action is stored");
    ok(s.faults[0].after == 8, "truncate after= is stored");
    backend_free(&s);

    load_ok(&s, "proto memcached\nfault on=get:* action=lie_bytes delta=+5\n");
    ok(s.faults[0].nth == BACKEND_NTH_ANY, "on=cmd:* means every occurrence");
    ok(s.faults[0].delta == 5, "a leading + is accepted on delta");
    backend_free(&s);

    load_ok(&s, "proto memcached\nfault on=get:1 action=lie_bytes delta=-2\n");
    ok(s.faults[0].delta == -2, "a negative delta is accepted");
    backend_free(&s);

    load_ok(&s, "proto memcached\nfault on=idle action=close_after ms=100\n");
    ok(s.faults[0].nth == BACKEND_NTH_ANY,
       "a bare on=cmd means every occurrence");
    ok(s.faults[0].ms == 100, "close_after ms= is stored");
    backend_free(&s);

    /* raw: the escape hatch, through the same lexer as a rule file's send. */
    load_ok(&s, "proto memcached\n"
                "fault on=get:1 action=raw data=VALUE k 0 3\\r\\nAB\\0\\r\\n\n");
    ok(s.faults[0].action == BACKEND_ACT_RAW, "raw action is stored");
    ok(s.faults[0].raw_len == 18,
       "raw data decodes escapes and keeps its spaces");
    ok(memcmp(s.faults[0].raw, "VALUE k 0 3\r\nAB\0\r\n", 18) == 0,
       "raw data carries an embedded NUL through the lexer");
    backend_free(&s);

    /* ---- rejections ---- */

    rc = load_child("proto memcached\nfault on=get:1 action=nonesuch\n",
                    msg, sizeof(msg));
    ok(rc == 2, "an unknown action is fatal");
    ok(strstr(msg, "unknown fault action") != NULL,
       "the unknown-action message names the problem");

    rc = load_child("seed a b\n", msg, sizeof(msg));
    ok(rc == 2, "a script with no proto is fatal");
    ok(strstr(msg, "no proto directive") != NULL,
       "the missing-proto message names the problem");

    rc = load_child("proto sqlite\n", msg, sizeof(msg));
    ok(rc == 2, "an unknown proto is fatal");

    rc = load_child("proto memcached\nnonesuch x\n", msg, sizeof(msg));
    ok(rc == 2, "an unknown directive is fatal");

    rc = load_child("proto memcached\nfault action=rst\n", msg, sizeof(msg));
    ok(rc == 2, "a fault with no on= is fatal");

    rc = load_child("proto memcached\nfault on=get:1\n", msg, sizeof(msg));
    ok(rc == 2, "a fault with no action= is fatal");

    rc = load_child("proto memcached\nfault on=get:1 action=truncate\n",
                    msg, sizeof(msg));
    ok(rc == 2, "truncate without after= is fatal");
    ok(strstr(msg, "needs after=") != NULL,
       "the missing-after message names the parameter");

    rc = load_child("proto memcached\nfault on=get:1 action=drip bytes=1\n",
                    msg, sizeof(msg));
    ok(rc == 2, "drip without ms= is fatal");

    rc = load_child("proto memcached\n"
                    "fault on=get:1 action=drip bytes=0 ms=5\n",
                    msg, sizeof(msg));
    ok(rc == 2, "drip bytes=0 is fatal (it would make no progress)");

    rc = load_child("proto memcached\n"
                    "fault on=get:1 action=lie_bytes delta=0\n",
                    msg, sizeof(msg));
    ok(rc == 2, "lie_bytes delta=0 is fatal (it would not lie)");

    rc = load_child("proto memcached\nfault on=get:0 action=rst\n",
                    msg, sizeof(msg));
    ok(rc == 2, "a 0 occurrence is fatal (1-based, would never match)");

    rc = load_child("proto memcached\nfault on=get:1 action=rst after=8\n",
                    msg, sizeof(msg));
    ok(rc == 2, "a parameter the action does not take is fatal");

    rc = load_child("proto memcached\nfault on=get:1 action=nonesuch\n",
                    msg, sizeof(msg));
    ok(rc == 2, "an unknown action is still fatal with other tokens present");

    rc = load_child("proto memcached\nfault nonsense action=rst on=get:1\n",
                    msg, sizeof(msg));
    ok(rc == 2, "a fault token that is not key=value is fatal");

    rc = load_child("proto memcached\n"
                    "fault on=get:1 action=close_after ms=999999\n",
                    msg, sizeof(msg));
    ok(rc == 2, "a wait past the ceiling is fatal");

    /* ---- AUD-05: target/action compatibility ---- */

    /* `connect` has no reply, so a reply-perturbing action on it would load
     * clean and then silently run the happy path -- the false-green this check
     * closes. Only rst / accept_close are acted on for connect. */
    rc = load_child("proto memcached\n"
                    "fault on=connect:1 action=lie_bytes delta=1\n",
                    msg, sizeof(msg));
    ok(rc == 2 && strstr(msg, "on=connect") != NULL,
       "lie_bytes on connect is fatal (connect has no reply to lie about)");

    rc = load_child("proto memcached\n"
                    "fault on=connect:1 action=truncate after=4\n",
                    msg, sizeof(msg));
    ok(rc == 2, "truncate on connect is fatal");

    /* rst / accept_close ARE the two legal connect actions: they must still
     * load, so the check rejects the wrong pairs without breaking the right
     * ones. */
    load_ok(&s, "proto memcached\nfault on=connect:1 action=rst\n");
    backend_free(&s);
    load_ok(&s, "proto memcached\nfault on=connect:2 action=accept_close\n");
    backend_free(&s);

    /* `idle` fires with no command and only close_after is acted on for it. */
    rc = load_child("proto memcached\nfault on=idle action=rst\n",
                    msg, sizeof(msg));
    ok(rc == 2 && strstr(msg, "on=idle") != NULL,
       "rst on idle is fatal (only close_after applies to idle)");

    load_ok(&s, "proto memcached\nfault on=idle action=close_after ms=50\n");
    backend_free(&s);
}


static void
test_fault_lookup(void)
{
    backend_script s;

    /* An exact occurrence beats a wildcard, which is what lets a script state a
     * general rule and then except one occurrence from it. */
    load_ok(&s, "proto memcached\n"
                "fault on=get:* action=rst\n"
                "fault on=get:3 action=accept_close\n");

    {
        const backend_fault *f = backend_fault_for(&s, "get", 3);
        ok(f != NULL && f->action == BACKEND_ACT_ACCEPT_CLOSE,
           "an exact occurrence match wins over a wildcard");
    }

    {
        const backend_fault *f = backend_fault_for(&s, "get", 1);
        ok(f != NULL && f->action == BACKEND_ACT_RST,
           "an unexcepted occurrence still matches the wildcard");
    }

    {
        const backend_fault *f = backend_fault_for(&s, "set", 1);
        ok(f == NULL, "a command with no fault matches nothing");
    }

    backend_free(&s);

    /* Among equals the first in file order wins, so the file reads top-down. */
    load_ok(&s, "proto memcached\n"
                "fault on=get:2 action=rst\n"
                "fault on=get:2 action=accept_close\n");
    {
        const backend_fault *f = backend_fault_for(&s, "get", 2);
        ok(f != NULL && f->action == BACKEND_ACT_RST,
           "the first matching fault in file order wins");
    }
    backend_free(&s);
}


static void
test_store(void)
{
    backend_script s;

    load_ok(&s, "proto memcached\n");

    backend_set(&s, "k", (const unsigned char *) "v1", 2);
    ok(s.n_entries == 1, "set creates an entry");

    /* Overwrite in place: without the existing-key scan first, a second set
     * would take a free slot and leave two entries with one name. */
    backend_set(&s, "k", (const unsigned char *) "v2", 2);
    ok(s.n_entries == 1, "setting an existing key does not add an entry");
    {
        const backend_entry *e = backend_get(&s, "k");
        ok(e != NULL && e->value_len == 2 && memcmp(e->value, "v2", 2) == 0,
           "setting an existing key overwrites its value");
    }

    ok(backend_get(&s, "absent") == NULL, "get on a missing key returns NULL");

    ok(backend_delete(&s, "k") == 1, "delete reports the key was present");
    ok(backend_get(&s, "k") == NULL, "delete removes the key");
    ok(backend_delete(&s, "k") == 0, "delete reports a missing key");

    backend_set(&s, "a", (const unsigned char *) "1", 1);
    backend_set(&s, "b", (const unsigned char *) "2", 1);
    backend_flush_all(&s);
    ok(s.n_entries == 0 && backend_get(&s, "a") == NULL,
       "flush_all empties the store");

    /*
     * An over-limit key or value off the WIRE must be refused, not fatal.
     * backend_set() die()s -- correct for a .backend authoring mistake, fatal
     * in the wrong sense for input a peer controls: fakesrv is one process
     * behind every connection in a scenario, so a module sending a 300-byte key
     * used to exit the daemon and take every other live connection with it.
     *
     * Asserting the store is UNCHANGED as well as the return value: a refusal
     * that still wrote a truncated key would satisfy `!= 0` while corrupting
     * the store the rest of the scenario reads.
     */
    {
        char           bigkey[BACKEND_MAX_KEY + 64];
        unsigned char  bigval[BACKEND_MAX_VALUE + 64];
        size_t         before = s.n_entries;

        memset(bigkey, 'A', sizeof(bigkey) - 1);
        bigkey[sizeof(bigkey) - 1] = '\0';
        memset(bigval, 'B', sizeof(bigval));

        ok(backend_set_checked(&s, bigkey, (const unsigned char *) "v", 1) != 0,
           "a key over BACKEND_MAX_KEY is refused rather than fatal");
        ok(s.n_entries == before && backend_get(&s, bigkey) == NULL,
           "a refused over-long key leaves the store untouched");

        ok(backend_set_checked(&s, "okkey", bigval, sizeof(bigval)) != 0,
           "a value over BACKEND_MAX_VALUE is refused rather than fatal");
        ok(s.n_entries == before && backend_get(&s, "okkey") == NULL,
           "a refused over-long value leaves the store untouched");

        ok(backend_set_checked(&s, "okkey", (const unsigned char *) "v", 1) == 0
           && backend_get(&s, "okkey") != NULL,
           "the checked store still accepts a key and value within limits");

        backend_delete(&s, "okkey");
    }

    /* A value with an embedded NUL survives, since the store is length-based
     * rather than NUL-terminated -- the shape a cache client mishandles. */
    backend_set(&s, "n", (const unsigned char *) "a\0b", 3);
    {
        const backend_entry *e = backend_get(&s, "n");
        ok(e != NULL && e->value_len == 3 && memcmp(e->value, "a\0b", 3) == 0,
           "a value containing NUL is stored by length");
    }

    backend_free(&s);
}


static void
test_memcached_codec(void)
{
    backend_script s;
    backend_cmd    cmd;
    unsigned char  buf[512];
    long           used;

    load_ok(&s, "proto memcached\nseed hello world\n");

    /* ---- parsing ---- */

    snprintf((char *) buf, sizeof(buf), "get hello\r\n");
    used = backend_parse_memcached(buf, strlen((char *) buf), &cmd);
    ok(used == 11, "a get consumes its whole line");
    ok(strcmp(cmd.name, "get") == 0, "the verb is parsed");
    ok(cmd.n_args == 1 && strcmp(cmd.args[0], "hello") == 0,
       "the key is parsed");

    /* ASCII-only case folding. The locale leg found a real bug where a Turkish
     * locale made 'I' a fixed point of tolower(); a verb table consulted
     * through the locale table would reintroduce it. */
    snprintf((char *) buf, sizeof(buf), "GET hello\r\n");
    (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
    ok(strcmp(cmd.name, "get") == 0, "the verb is folded to lower case");

    /* Incompleteness and error must stay distinct: collapsing them makes a
     * client sending garbage look like one that is merely slow. */
    snprintf((char *) buf, sizeof(buf), "get hel");
    used = backend_parse_memcached(buf, strlen((char *) buf), &cmd);
    ok(used == 0, "a partial line reports incomplete, not an error");

    /* A storage command is incomplete until its data block arrives. */
    snprintf((char *) buf, sizeof(buf), "set k 0 0 5\r\nab");
    used = backend_parse_memcached(buf, strlen((char *) buf), &cmd);
    ok(used == 0, "a set is incomplete until its data block arrives");

    memcpy(buf, "set k 0 0 5\r\nabcde\r\n", 20);
    used = backend_parse_memcached(buf, 20, &cmd);
    ok(used == 20, "a complete set consumes its command line and data block");
    ok(cmd.data_len == 5, "the declared data length is parsed");

    /* The payload must be reachable, not merely counted. A set whose data the
     * parser framed and discarded can only be acknowledged, and the following
     * get then answers a miss -- which reads as a cache bug in the module under
     * test rather than as a defect in the fake. */
    ok(cmd.data != NULL && memcmp(cmd.data, "abcde", 5) == 0,
       "the data block is reachable from the parsed command");

    /* A malformed length is a protocol error, not a fatal one. These bytes come
     * off a socket, so dying here would let any client take the daemon down
     * mid-scenario and report a harness crash instead of the protocol error. */
    memcpy(buf, "set k 0 0 junk\r\n", 16);
    used = backend_parse_memcached(buf, 16, &cmd);
    ok(used == -1, "a non-numeric data length is an error, not fatal");

    /*
     * An incomplete parse must leave the buffer BYTE-IDENTICAL.
     *
     * The parser tokenises in place and the caller re-invokes it as more data
     * arrives, so a return of 0 that had already punched NULs into the line
     * left the retry parsing mangled bytes -- and a valid `set` came back as a
     * protocol error. It only reproduced when the data block landed in a later
     * read() than its command line, so every local run (one write, one read)
     * passed and all four CI legs failed at once.
     *
     * Comparing the BUFFER is the assertion; checking the return value alone
     * cannot see the mutation that causes the next call to fail.
     */
    {
        unsigned char before[32];
        const char   *partial = "set k 0 0 3\r\n";
        size_t        plen = strlen(partial);

        memset(buf, 0, sizeof(buf));
        memcpy(buf, partial, plen);
        memcpy(before, buf, sizeof(before));

        used = backend_parse_memcached(buf, plen, &cmd);
        ok(used == 0, "a set whose data block has not arrived reports incomplete");
        ok(memcmp(buf, before, sizeof(before)) == 0,
           "an incomplete parse leaves the buffer untouched for the retry");

        /* And the retry, once the block lands, must succeed. */
        memcpy(buf + plen, "abc\r\n", 5);
        used = backend_parse_memcached(buf, plen + 5, &cmd);
        ok(used == (long) (plen + 5),
           "the retry parses the set once its data block arrives");
        ok(cmd.data != NULL && cmd.data_len == 3
           && memcmp(cmd.data, "abc", 3) == 0,
           "the retried set carries its payload");
    }

    /* Pipelining: the parser must consume exactly one command so the caller can
     * hand it the rest. */
    memcpy(buf, "get a\r\nget b\r\n", 14);
    used = backend_parse_memcached(buf, 14, &cmd);
    ok(used == 7, "a pipelined pair consumes only the first command");

    /*
     * Arguments must point into the CALLER's buffer, not into a parser local.
     *
     * The first draft copied the command line into a stack buffer and
     * tokenised that, so args pointed into a frame that died at return -- and
     * the daemon, which returns before it uses them, answered `get hello` with
     * a key of "<\x7f". Every test above missed it because a test reads args
     * while the parser's frame is still live and its bytes happen to survive.
     * Checking the POINTER lands inside the caller's buffer is what actually
     * pins the lifetime; reading the string cannot.
     */
    snprintf((char *) buf, sizeof(buf), "get hello\r\n");
    (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
    ok(cmd.n_args == 1
       && (unsigned char *) cmd.args[0] >= buf
       && (unsigned char *) cmd.args[0] < buf + sizeof(buf),
       "parsed arguments point into the caller's buffer, not a parser local");

    /* ---- replies ---- */

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        snprintf((char *) buf, sizeof(buf), "get hello\r\n");
        (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
        backend_reply_memcached(&s, &cmd, &out, &out_len);

        ok(out_len == 29
           && memcmp(out, "VALUE hello 0 5\r\nworld\r\nEND\r\n", 29) == 0,
           "a get hit renders VALUE + payload + END");
        free(out);
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        snprintf((char *) buf, sizeof(buf), "get absent\r\n");
        (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
        backend_reply_memcached(&s, &cmd, &out, &out_len);

        /* A miss is an absent VALUE block, not a signalled one -- the detail a
         * client's miss handling most often gets wrong. */
        ok(out_len == 5 && memcmp(out, "END\r\n", 5) == 0,
           "a get miss renders a bare END");
        free(out);
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        snprintf((char *) buf, sizeof(buf), "version\r\n");
        (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
        backend_reply_memcached(&s, &cmd, &out, &out_len);

        ok(out_len == 21
           && memcmp(out, "VERSION 1.6.38-fake\r\n", 21) == 0,
           "version renders a correctly shaped reply");
        free(out);
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        /* The whole point of the wide verb table: an unimplemented-but-real
         * verb must not draw an accidental ERROR, or a scenario ends up testing
         * our omission rather than the module. */
        snprintf((char *) buf, sizeof(buf), "stats\r\n");
        (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
        backend_reply_memcached(&s, &cmd, &out, &out_len);

        ok(out_len > 0 && memcmp(out, "STAT ", 5) == 0,
           "stats renders a STAT block, not ERROR");
        free(out);
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        snprintf((char *) buf, sizeof(buf), "nonesuch\r\n");
        (void) backend_parse_memcached(buf, strlen((char *) buf), &cmd);
        backend_reply_memcached(&s, &cmd, &out, &out_len);

        ok(out_len == 7 && memcmp(out, "ERROR\r\n", 7) == 0,
           "a genuinely unknown verb renders ERROR");
        free(out);
    }

    backend_free(&s);
}


static void
test_resp_codec(void)
{
    backend_script s;
    backend_cmd    cmd;
    unsigned char  buf[512];
    long           used;

    load_ok(&s, "proto redis\nseed hello world\n");

    memcpy(buf, "*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n", 24);
    used = backend_parse_resp(buf, 24, &cmd);
    ok(used == 24, "a RESP array consumes its whole frame");
    ok(strcmp(cmd.name, "get") == 0, "the RESP verb is folded to lower case");
    ok(cmd.n_args == 1 && strcmp(cmd.args[0], "hello") == 0,
       "the RESP argument is parsed");

    memcpy(buf, "*2\r\n$3\r\nGET\r\n$5\r\nhel", 20);
    used = backend_parse_resp(buf, 20, &cmd);
    ok(used == 0, "a truncated RESP frame reports incomplete");

    /*
     * A multi-bulk frame whose LATER argument is still on the wire must report
     * incomplete AND leave the buffer byte-identical, so the caller's retry --
     * once the rest arrives -- parses the same bytes. The parser NUL-terminates
     * each argument in place by overwriting its trailing CR; doing that inside
     * the arg loop mutated an EARLIER, already-parsed argument's CR before the
     * frame was known to be complete, so the retry saw `k\0` where `k\r` had
     * been and rejected a valid frame as a protocol error. That surfaced as a
     * fragmentation-dependent flake: a SET split across two reads failed
     * intermittently. Feed `SET k` complete but the final value bulk truncated,
     * and require both incomplete AND an untouched buffer.
     */
    {
        const char frame[] = "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv";
        size_t     flen = sizeof(frame) - 1;   /* no value CRLF yet */

        memcpy(buf, frame, flen);
        used = backend_parse_resp(buf, flen, &cmd);
        ok(used == 0, "an incomplete multi-bulk frame reports incomplete");
        ok(memcmp(buf, frame, flen) == 0,
           "an incomplete parse leaves the buffer byte-identical for the retry");
    }

    memcpy(buf, "*3x\r\n", 5);
    used = backend_parse_resp(buf, 5, &cmd);
    ok(used == -1, "trailing garbage in the array header is an error");

    /* AUD-06: an array header with no newline is normally "read more" (0), so
     * the daemon grows the buffer and reads again. But once the unterminated
     * run passes the header field's width it can never become a valid count, so
     * it must be an error -- otherwise a `*` trailing endless non-newline bytes
     * is forever incomplete and the growth loop OOMs the shared daemon. */
    memset(buf, 'x', sizeof(buf));
    buf[0] = '*';
    used = backend_parse_resp(buf, 8, &cmd);
    ok(used == 0, "a short unterminated array header still asks for more");
    used = backend_parse_resp(buf, 200, &cmd);
    ok(used == -1, "an over-long unterminated array header is an error (AUD-06)");

    /* The same guard on the bulk-length header: `*1\r\n$` then endless bytes. */
    memset(buf, 'x', sizeof(buf));
    memcpy(buf, "*1\r\n$", 5);
    used = backend_parse_resp(buf, 200, &cmd);
    ok(used == -1, "an over-long unterminated bulk header is an error (AUD-06)");

    /* Inline commands: what a human at the socket sends, and what a scenario's
     * `printf | nc` smoke test emits. */
    memcpy(buf, "PING\r\n", 6);
    used = backend_parse_resp(buf, 6, &cmd);
    ok(used == 6 && strcmp(cmd.name, "ping") == 0,
       "an inline command is parsed and its verb folded to lower case");

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        memcpy(buf, "*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n", 24);
        (void) backend_parse_resp(buf, 24, &cmd);
        backend_reply_resp(&s, &cmd, &out, &out_len);

        ok(out_len == 11 && memcmp(out, "$5\r\nworld\r\n", 11) == 0,
           "a RESP get hit renders a bulk string");
        free(out);
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        memcpy(buf, "*2\r\n$3\r\nGET\r\n$6\r\nabsent\r\n", 25);
        (void) backend_parse_resp(buf, 25, &cmd);
        backend_reply_resp(&s, &cmd, &out, &out_len);

        /* The nil bulk string, distinct from an empty one. A client that
         * conflates them cannot tell a missing key from a key holding "". */
        ok(out_len == 5 && memcmp(out, "$-1\r\n", 5) == 0,
           "a RESP get miss renders the nil bulk string, not $0");
        free(out);
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;

        memcpy(buf, "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n", 27);
        (void) backend_parse_resp(buf, 27, &cmd);
        backend_reply_resp(&s, &cmd, &out, &out_len);

        ok(out_len == 5 && memcmp(out, "+OK\r\n", 5) == 0,
           "a RESP set renders +OK");
        free(out);

        {
            const backend_entry *e = backend_get(&s, "k");
            ok(e != NULL && e->value_len == 1 && e->value[0] == 'v',
               "a RESP set actually stores the value");
        }
    }

    /* AUD-03: a RESP bulk string is binary-safe. A value of "a\0b" must persist
     * all three bytes; strlen truncated it to "a". The frame is
     * *3 SET binkey $3 a\0b. */
    {
        static const unsigned char frame[] =
            "*3\r\n$3\r\nSET\r\n$6\r\nbinkey\r\n$3\r\na\x00""b\r\n";
        const backend_entry *e;
        unsigned char *out = NULL;
        size_t         out_len = 0;

        memcpy(buf, frame, sizeof(frame) - 1);
        used = backend_parse_resp(buf, sizeof(frame) - 1, &cmd);
        ok(used == (long) (sizeof(frame) - 1),
           "a RESP set with an embedded-NUL value consumes its whole frame");
        ok(cmd.n_args == 2 && cmd.args_len[1] == 3,
           "the binary value's length survives as 3, not strlen's 1");

        backend_reply_resp(&s, &cmd, &out, &out_len);
        free(out);
        e = backend_get(&s, "binkey");
        ok(e != NULL && e->value_len == 3
           && memcmp(e->value, "a\x00""b", 3) == 0,
           "a RESP set stores the full binary value, NUL included");
    }

    /* AUD-04: the trailing CRLF of a bulk string is mandatory. A frame whose
     * terminator CR is replaced by another byte must be rejected, not
     * resynchronised onto the wrong offset and answered as if well-formed. */
    {
        static const unsigned char bad[] =
            "*2\r\n$3\r\nGET\r\n$5\r\nhelloXY";  /* payload then XY, not \r\n */
        memcpy(buf, bad, sizeof(bad) - 1);
        used = backend_parse_resp(buf, sizeof(bad) - 1, &cmd);
        ok(used == -1,
           "a RESP bulk string with a corrupt CRLF terminator is an error");
    }
    {
        /* Negative control: the same frame WITH a correct terminator parses,
         * so the assertion above is rejecting the terminator and nothing else. */
        static const unsigned char good[] =
            "*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n";
        memcpy(buf, good, sizeof(good) - 1);
        used = backend_parse_resp(buf, sizeof(good) - 1, &cmd);
        ok(used == (long) (sizeof(good) - 1),
           "control: the well-terminated frame parses");
    }

    /* AUD-02: an inline `set`/`get` must not leave args pointing into a dead
     * stack buffer. Parse, then read the arg AFTER the parser returned -- the
     * daemon does exactly this. A dangling pointer shows as corrupted bytes. */
    {
        memcpy(buf, "set ik iv\r\n", 11);
        used = backend_parse_resp(buf, 11, &cmd);
        ok(used == 11 && strcmp(cmd.name, "set") == 0,
           "an inline set is parsed and folded to lower case");
        ok(cmd.n_args == 2
           && cmd.args_len[0] == 2 && memcmp(cmd.args[0], "ik", 2) == 0
           && cmd.args_len[1] == 2 && memcmp(cmd.args[1], "iv", 2) == 0,
           "inline args are read correctly after the parser returned (no UAR)");
    }

    backend_free(&s);
}


static void
test_lie_bytes(void)
{
    unsigned char *out;
    size_t         out_len;
    const char    *mc = "VALUE k 0 5\r\nhello\r\nEND\r\n";
    const char    *resp = "$5\r\nhello\r\n";

    /*
     * The payload must be left alone. The test is about a client trusting a
     * declared length, so a rewriter that also changed the bytes would no
     * longer be isolating the disagreement.
     */
    out = backend_apply_lie(BACKEND_PROTO_MEMCACHED,
                            (const unsigned char *) mc, strlen(mc), 5,
                            &out_len);
    ok(out != NULL && memcmp(out, "VALUE k 0 10\r\n", 14) == 0,
       "lie_bytes rewrites the memcached declared length");
    ok(out != NULL && out_len == strlen(mc) + 1,
       "lie_bytes leaves the memcached payload untouched");
    free(out);

    out = backend_apply_lie(BACKEND_PROTO_REDIS,
                            (const unsigned char *) resp, strlen(resp), -2,
                            &out_len);
    ok(out != NULL && memcmp(out, "$3\r\n", 4) == 0,
       "lie_bytes rewrites the RESP declared length");
    /* nosem: double-free -- `out` is REASSIGNED by the backend_apply_lie() call
     * above between the two frees, so these release two distinct allocations. */
    free(out);  /* nosem: double-free */

    /* A reply carrying no declared length cannot be falsified. Returning NULL
     * rather than mangling it is what lets the server send it untouched
     * instead of swallowing it and hanging the client. */
    out = backend_apply_lie(BACKEND_PROTO_MEMCACHED,
                            (const unsigned char *) "END\r\n", 5, 1, &out_len);
    ok(out == NULL, "lie_bytes declines a reply with no declared length");

    /* A delta that would drive the length negative is refused rather than
     * wrapping into a huge unsigned value at the client. */
    out = backend_apply_lie(BACKEND_PROTO_REDIS,
                            (const unsigned char *) resp, strlen(resp), -99,
                            &out_len);
    ok(out == NULL, "lie_bytes refuses a delta that would go negative");
}


int
main(void)
{
    printf("1..%d\n", PLANNED);

    test_script_parser();
    test_fault_lookup();
    test_store();
    test_memcached_codec();
    test_resp_codec();
    test_lie_bytes();

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        return 1;
    }

    return failures == 0 ? 0 : 1;
}
