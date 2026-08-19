/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * backend.h -- the fake upstream: protocol codecs, script parser, fault model.
 *
 * Split from fakesrv.c on the same principle as rules.h: everything here is a
 * pure function over bytes, so backend_test.c can exercise the parser and the
 * codecs without a socket, a port or a running server. fakesrv.c owns main(),
 * poll() and the syscalls; this unit never touches a file descriptor.
 *
 * WHY A FAKE AT ALL. A real redis or memcached is the wrong instrument for the
 * cases that matter here. It cannot be made to truncate a reply mid-VALUE, to
 * declare a length it then contradicts, to reset a connection after eight
 * bytes, or to close a parked keepalive connection at the moment of a reload --
 * and those are precisely the paths where an upstream module's error handling
 * either releases its resources or leaks them. Nor can a real daemon REPORT
 * what it saw: the JSONL journal this unit's server half writes is what makes
 * "the connection was reused" a falsifiable claim rather than an assumption.
 *
 * Deliberately NOT a real cache. The moment a scenario needs eviction or
 * expiry semantics it should point at a real daemon instead; a fake that grows
 * toward being a real redis is a second implementation to keep correct, and its
 * bugs would be indistinguishable from the module's.
 *
 *
 * SCRIPT FORMAT -- `.backend` files, stanza style mirroring `.rule`:
 *
 *     proto   memcached
 *     seed    hello  world
 *     fault   on=get:3     action=truncate    after=8
 *     fault   on=get:*     action=lie_bytes   delta=+5
 *     fault   on=set:1     action=rst
 *     fault   on=connect:2 action=accept_close
 *     fault   on=get:2     action=drip        bytes=1 ms=5
 *     fault   on=idle      action=close_after ms=100
 *     fault   on=get:4     action=raw         data=VALUE k 0 3\r\nAB\0\r\nEND\r\n
 *
 * The default behaviour with no faults is a CORRECT server backed by a real
 * in-memory key/value store. That is the load-bearing design decision, and the
 * alternative was considered and rejected: a positional list of canned replies
 * cannot express a keepalive test, because the number of `get`s nginx will
 * issue is exactly what such a test is trying to discover. Encoding the reply
 * count into the script encodes the answer into the question. Faults are
 * therefore OVERLAYS on correct behaviour, keyed by (command glob : occurrence
 * index), so a script says what goes wrong and when, and says nothing at all
 * about the traffic it does not perturb.
 *
 * `on=` is `<command-glob>:<nth>` where `<nth>` is a 1-based occurrence counter
 * or `*` for every occurrence. The counter is per-command and per-run, not
 * per-connection: `get:3` means the third `get` this daemon sees, which is what
 * a scenario can predict. Two pseudo-commands cover what is not a command at
 * all: `connect:<nth>` fires as the nth connection is accepted, and `idle`
 * fires on a connection that has gone quiet.
 *
 * `action=raw` is the escape hatch, and carries most of the adversarial
 * surface: embedded NULs, an oversize declared length, a reply that arrives
 * when none was due, RESP `$-1` nil against a malformed near-miss. It uses the
 * same `\r \n \t \\ \" \0 \xNN` escapes as a rule file's `send`, through the
 * same lexer (util.h), so the two formats cannot drift on what a byte means.
 */

#ifndef NGX_TEST_HARNESS_BACKEND_H
#define NGX_TEST_HARNESS_BACKEND_H

#include <stddef.h>

/* Bounds. Small on purpose: a script that needs more than this is describing a
 * cache, not a fault, and the note above applies. */
#define BACKEND_MAX_FAULTS   64
#define BACKEND_MAX_ENTRIES  64
#define BACKEND_MAX_KEY      256
#define BACKEND_MAX_VALUE    4096

/* Ceiling on a single drip/close_after wait. A fault that parks longer than a
 * scenario's own timeout reports as a harness stall rather than as the server
 * behaviour under test -- the same reasoning that bounds `pause` in rules.h. */
#define BACKEND_MAX_MS       10000


typedef enum {
    BACKEND_PROTO_MEMCACHED = 0,
    BACKEND_PROTO_REDIS
} backend_proto;


typedef enum {
    /*
     * Reply correctly, then cut the connection after `after` bytes. The
     * truncation point is a byte offset into the reply this command would
     * otherwise have sent, so a script can sever a VALUE header mid-field.
     */
    BACKEND_ACT_TRUNCATE = 0,

    /*
     * Send a correct reply whose declared length disagrees with the payload by
     * `delta`. memcached's `VALUE <key> <flags> <bytes>` and RESP's `$<len>`
     * both carry a length the client is expected to trust; a module that trusts
     * it without bounding against what actually arrived is the bug this finds.
     */
    BACKEND_ACT_LIE_BYTES,

    /* Destroy the connection with a TCP reset (SO_LINGER{1,0}) instead of
     * replying, so the client sees ECONNRESET rather than a clean close. */
    BACKEND_ACT_RST,

    /* Accept the connection and immediately close it without reading. The
     * connect succeeds, so this is distinct from a refused connection. */
    BACKEND_ACT_ACCEPT_CLOSE,

    /* Emit the correct reply `bytes` at a time with `ms` between pieces, so the
     * client's read path is entered once per piece rather than once. */
    BACKEND_ACT_DRIP,

    /* Close the connection `ms` after it goes idle. The keepalive-pool case:
     * a module must reconnect rather than reuse an fd the peer has closed. */
    BACKEND_ACT_CLOSE_AFTER,

    /* Send these exact bytes instead of the correct reply. */
    BACKEND_ACT_RAW,

    /* RESP SCAN that never returns to cursor 0. A real redis will never hand
     * you this, and a client looping until cursor 0 hangs forever. */
    BACKEND_ACT_CURSOR_NEVER_ZERO
} backend_action;


typedef struct {
    char            *cmd;        /* command glob: "get", "connect", "idle" */
    long             nth;        /* 1-based occurrence, or BACKEND_NTH_ANY */
    backend_action   action;

    long             after;      /* truncate: byte offset to cut at */
    long             delta;      /* lie_bytes: signed adjustment */
    long             bytes;      /* drip: piece size */
    long             ms;         /* drip / close_after: wait */

    unsigned char   *raw;        /* raw: literal reply bytes */
    size_t           raw_len;    /* raw: length, which may contain NULs */
} backend_fault;

#define BACKEND_NTH_ANY  (-1)


typedef struct {
    char            key[BACKEND_MAX_KEY];
    /*
     * Length of `key` in bytes, for the same reason `value_len` exists: a RESP
     * key is a binary-safe bulk string, so "a\0b" is a three-byte key and NOT
     * the one-byte key "a". Everything that compares or emits a key must use
     * this rather than strlen(). `key` is still NUL-terminated at
     * key[key_len] so the memcached and inline text paths, whose keys cannot
     * contain a NUL, can keep printing it with "%s".
     */
    size_t          key_len;
    unsigned char   value[BACKEND_MAX_VALUE];
    size_t          value_len;
    int             used;
} backend_entry;


typedef struct {
    backend_proto   proto;

    backend_entry   entries[BACKEND_MAX_ENTRIES];
    size_t          n_entries;

    backend_fault   faults[BACKEND_MAX_FAULTS];
    size_t          n_faults;
} backend_script;


/*
 * Parse a `.backend` file. Dies (util.h) on any malformed line rather than
 * skipping it.
 *
 * Dying is the whole point and is worth stating: a fault the parser silently
 * dropped leaves a scenario exercising the HAPPY path while its name, its
 * comments and its TAP output all claim it is exercising a failure. That is a
 * green run proving nothing -- the exact class this repo's mutation ritual
 * exists to catch -- and it is invisible, because a scenario that tests nothing
 * passes very reliably. An unknown `action=` is therefore fatal, not ignored.
 */
void backend_load(const char *file, backend_script *s);

/*
 * Parse a .backend script from an in-memory byte buffer rather than a path.
 * The fuzz target's entry point (fuzz/fuzz_backend.c): drives the SAME parser
 * as backend_load() via fmemopen, so no fuzz-only reimplementation can drift.
 * die()s on any malformed line and on a missing proto directive, exactly as
 * backend_load() does; a fuzz caller arms prober_die_jmp (util.h) to survive
 * it. Returns without dying (and without touching *s) only if fmemopen fails;
 * the fuzz caller's static script is already cleared by backend_free between
 * inputs, so a no-op parse leaves it in the same swept state.
 */
void backend_load_buf(const char *buf, size_t len, backend_script *s);

/* Release everything backend_load() allocated, and zero the struct. */
void backend_free(backend_script *s);


/*
 * Look up the fault that applies to `cmd` on its `nth` occurrence, or NULL.
 *
 * An exact `nth` match wins over a `*` match, so a script can state a general
 * rule and then except one occurrence from it. Among equals the FIRST matching
 * fault in file order wins, so the file reads top-down.
 */
const backend_fault *backend_fault_for(const backend_script *s,
                                       const char *cmd, long nth);


/*
 * The in-memory store. `get` returns NULL when the key is absent.
 *
 * Each operation comes in two spellings. The plain form takes an explicit key
 * length and is the binary-safe one: RESP keys arrive as bulk strings and may
 * contain a NUL, so the RESP command handlers must use it or two distinct keys
 * collapse into one. The `_cstr` form takes a C string, derives the length
 * with strlen(), and exists for the memcached and inline text paths, whose
 * grammar is whitespace-delimited and therefore cannot express an embedded
 * NUL, and for .backend script keys.
 *
 * A key is `key_len` bytes compared with memcmp, so "a" and "a\0b" are
 * different keys and neither prefixes the other.
 */
const backend_entry *backend_get_cstr(const backend_script *s,
                                      const char *key);
const backend_entry *backend_get(const backend_script *s, const char *key,
                                 size_t key_len);
void backend_set_cstr(backend_script *s, const char *key,
                      const unsigned char *value, size_t len);

/*
 * backend_set_cstr() for input that came off the SOCKET rather than out of a
 * .backend file: returns 0 stored, -1 refused (key or value over its limit, or
 * the store is full) instead of exiting the process. Callers answer with their
 * protocol's error token.
 *
 * The distinction matters because fakesrv is one process behind every
 * connection in a scenario: an over-long key from a peer used to die() and take
 * every other live connection down with it, turning a module bug into what
 * looked like harness flakiness.
 */
int  backend_set_checked_cstr(backend_script *s, const char *key,
                              const unsigned char *value, size_t len);
int  backend_set_checked(backend_script *s, const char *key, size_t key_len,
                         const unsigned char *value, size_t len);
int  backend_delete_cstr(backend_script *s, const char *key);
int  backend_delete(backend_script *s, const char *key, size_t key_len);
void backend_flush_all(backend_script *s);


/*
 * One parsed client command. `args` point into the caller's buffer, so a
 * backend_cmd does not outlive the read buffer it was parsed from.
 */
#define BACKEND_MAX_ARGS  16

typedef struct {
    char    name[32];
    char   *args[BACKEND_MAX_ARGS];
    /*
     * Length of each arg in bytes, so a binary-safe RESP bulk string (a value
     * or key containing an embedded NUL) is carried faithfully rather than
     * truncated at the first NUL by a strlen. args[i] still points into the
     * caller's buffer and is NUL-terminated at args[i][args_len[i]] for the
     * benefit of the memcached/inline text paths, but consumers that must be
     * binary-exact (the RESP store and journal) use args_len[i].
     */
    size_t  args_len[BACKEND_MAX_ARGS];
    size_t  n_args;

    /* memcached storage commands carry a data block after the command line;
     * this is its declared length, or -1 when the command has no block. */
    long    data_len;

    /* The data block itself, pointing into the caller's buffer like `args`.
     * NULL when the command carries none. Without this a `set` can only be
     * acknowledged, never stored -- and a fake that answers STORED to a set it
     * discarded will answer the following get with a miss, which reads as a
     * cache bug in whatever module is under test. */
    unsigned char *data;
} backend_cmd;


/*
 * Parse one command out of `buf`.
 *
 * Returns the number of bytes consumed, 0 when the buffer holds no complete
 * command yet (the caller should read more), or -1 on a protocol error.
 *
 * Incompleteness and error are deliberately distinct return values. Collapsing
 * them -- returning 0 for both, say -- makes a client that sends garbage
 * indistinguishable from one that is merely slow, so the daemon would wait for
 * a completion that is never coming instead of reporting the error, and the
 * scenario would fail on a timeout pointing nowhere near the cause.
 *
 * `buf` is NOT const: the RESP parser NUL-terminates each bulk argument in
 * place, overwriting the CR of its own terminator, so `args` can point into the
 * buffer instead of copying every argument. The signature says so rather than
 * casting the qualifier away at the write -- a const parameter the body writes
 * through is a lie the compiler is entitled to optimise against, and -Wcast-qual
 * is in this build's warning wall to keep that lie unspellable.
 */
long backend_parse_memcached(unsigned char *buf, size_t len, backend_cmd *out);
long backend_parse_resp(unsigned char *buf, size_t len, backend_cmd *out);


/*
 * Build the correct reply for `cmd` into a malloc'd buffer (*out / *out_len).
 * The caller owns it. Faults are applied by the server half, not here: this
 * function answers "what would a correct server say", which is what the fault
 * overlays then perturb.
 */
void backend_reply_memcached(backend_script *s, const backend_cmd *cmd,
                             unsigned char **out, size_t *out_len);
void backend_reply_resp(backend_script *s, const backend_cmd *cmd,
                        unsigned char **out, size_t *out_len);

/*
 * Apply `lie_bytes` to a correct reply: find the declared length and adjust it
 * by `delta` without changing the payload. Returns a new malloc'd buffer.
 *
 * Separate from reply construction so the lie is applied to a reply already
 * proven correct -- a fault that built its own malformed reply from scratch
 * could differ from the real one in ways the script never asked for, and the
 * test would no longer be isolating the length disagreement.
 */
unsigned char *backend_apply_lie(backend_proto proto, const unsigned char *in,
                                 size_t in_len, long delta, size_t *out_len);

#endif /* NGX_TEST_HARNESS_BACKEND_H */
