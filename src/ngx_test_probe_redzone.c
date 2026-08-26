/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe_redzone.c -- guard bytes around pool allocations, for the
 * overflow class ASan structurally cannot see.
 *
 * WHY THIS EXISTS AT ALL, GIVEN ASAN
 *
 * The reflex answer to "who catches a heap overflow" is AddressSanitizer, and
 * for ordinary malloc it is the right answer. nginx's pool allocator defeats
 * it, and the reason is worth stating precisely because it decides the whole
 * design of this file.
 *
 * ngx_palloc_small() is a bump allocator. It does not call malloc per object:
 * it slices objects out of one large block that ngx_palloc_block() obtained
 * from ngx_memalign(), by advancing p->d.last. So a request pool holding two
 * hundred small objects is, to ASan, ONE live allocation. ASan's redzones sit
 * at the two ends of that block. Between the objects there is nothing to
 * poison, because from ASan's point of view there are no boundaries there --
 * the whole block is addressable and live.
 *
 * The consequence, demonstrated rather than assumed (2026-08-26, gcc 14 ASan,
 * a 4096-byte block sliced into two 16-byte objects, the first memset to 32
 * bytes): the process exits 0, ASan prints nothing, and the second object's
 * contents are silently replaced by the first object's overflow. That is the
 * bug class this file exists for. It is not a hypothetical, and it is not one
 * ASan will start catching if you configure it differently.
 *
 * valgrind memcheck is blind here for the same structural reason, and for one
 * more: it tracks addressability and definedness of malloc'd blocks, and every
 * byte of that pool block is both addressable and defined.
 *
 * WHAT THIS DOES NOT DO
 *
 * This is NOT a replacement for ASan and it must not be described as one. It
 * catches exactly one class -- a linear overflow out of one pool object into
 * the next -- and it catches it at DETECTION time (the next probe read or the
 * pool's destruction), not at the instruction that wrote the byte. ASan
 * catches its own classes at the faulting instruction with a stack trace,
 * which is strictly more useful when ASan can see the bug at all. Run both.
 *
 * Specifically not covered here: use-after-free (a destroyed pool's memory
 * goes back to libc, where ASan's quarantine is already the better tool),
 * overflow of a LARGE allocation (ngx_palloc_large calls ngx_alloc, so it is
 * an ordinary malloc block and ASan already guards it), and any read that
 * merely reads past an object without writing (nothing is disturbed, so no
 * check can notice after the fact).
 *
 * HOW IT WORKS
 *
 * A module under test routes its allocations through
 * ngx_test_probe_palloc() instead of ngx_palloc(). That call reserves
 * NGX_TEST_PROBE_REDZONE bytes on each side of the object, fills them with a
 * known pattern, and records the object in a per-pool registry hung off the
 * pool's cleanup chain. Verification walks the registry and reports any guard
 * byte that no longer holds the pattern.
 *
 * The indirection is deliberate and is the honest cost of this approach: an
 * un-adapted module gets nothing. Interposing ngx_palloc() globally was
 * considered and rejected -- it is a core symbol called by nginx itself
 * thousands of times per request, the overhead would be charged to code that
 * is not under test, and the registry would grow without bound on the cycle
 * pool. Making the consumer opt in per call site keeps the cost proportional
 * to what is actually being tested.
 *
 * See ngx_test_probe.h.
 */

/*
 * NGX_TEST_PROBE_POOL_SHIM is defined only by the direct-call unit harness in
 * t/, which builds this file against t/ngx_pool_shim.h instead of a configured
 * nginx. A real build defines nothing and gets the pool types from ngx_core.h
 * by way of ngx_test_probe.h, exactly as the other probe sources do.
 *
 * The shim has to be included BEFORE ngx_test_probe.h, because that header
 * declares ngx_test_probe_palloc() in terms of ngx_pool_t and t/ngx_config.h
 * -- which is what ngx_test_probe.h reaches for under the harness -- defines
 * no allocator at all.
 */
#ifdef NGX_TEST_PROBE_POOL_SHIM
#include "ngx_pool_shim.h"
#endif

#include "ngx_test_probe.h"

#ifdef NGX_TEST_HARNESS


/*
 * The guard pattern. Chosen so that the three ways a guard is most likely to
 * be destroyed are all distinguishable from each other on inspection:
 *
 *   0xDB       -- the pattern itself ("debug"); an intact guard
 *   0x00       -- the overwhelmingly common overflow, a zero-terminated
 *                 string or a memset/ngx_memzero running past its object
 *   anything   -- a structured write, reported with the byte that was found
 *
 * A single-byte pattern rather than a multi-byte cookie because the check is
 * a byte-wise scan either way, and a repeated byte makes a partial overwrite
 * (the common case: three bytes of a four-byte write land in the guard)
 * visible at whichever offset it starts, instead of only when it happens to
 * be aligned with a cookie boundary.
 */
#define NGX_TEST_PROBE_REDZONE_BYTE   0xDB


/*
 * One registry entry per guarded allocation.
 *
 * `user` is what the caller was handed; the guards live immediately before and
 * after it. `size` is the caller's requested size, not the padded size, so
 * that the reported overflow offset is expressed in the caller's terms.
 */
typedef struct ngx_test_probe_rz_s  ngx_test_probe_rz_t;

struct ngx_test_probe_rz_s {
    u_char               *user;
    size_t                size;
    ngx_test_probe_rz_t  *next;
};


/*
 * Per-pool registry head.
 *
 * Hung off the pool's own cleanup chain rather than kept in a process global,
 * for two reasons that are both correctness rather than taste:
 *
 *   1. Lifetime. The registry must not outlive the memory it points at. A
 *      request pool is destroyed at the end of the request; a global registry
 *      would be left holding dangling pointers into freed blocks, and the
 *      verification pass would then read freed memory -- turning a leak
 *      detector into a use-after-free of its own.
 *
 *   2. Concurrency. Nothing here is shared between workers, and per-pool
 *      state inherits the pool's single-threaded discipline for free. A
 *      process global would need to answer what happens when two connections
 *      in the same worker interleave, which is a question worth not having.
 *
 * The cleanup handler runs at pool destruction and is where the final,
 * unmissable verification happens -- see ngx_test_probe_rz_cleanup().
 */
typedef struct {
    ngx_test_probe_rz_t  *entries;
    ngx_pool_t           *pool;
    ngx_uint_t            count;
    ngx_uint_t            violations;
} ngx_test_probe_rz_head_t;


/*
 * Cumulative violation count for this worker, surfaced in the probe document
 * as `redzone.violations` so a rule file can assert on it.
 *
 * Process-global and cumulative rather than per-pool because the oracle a
 * consumer writes is "no request corrupted a guard", which spans every pool
 * the run created -- most of which are destroyed and gone by the time the
 * probe request arrives. A per-pool figure would be unreadable for the pool
 * that mattered, since that pool no longer exists.
 *
 * Not volatile and not atomic: one worker, one event loop, no concurrent
 * writer. The same reasoning ngx_test_probe_config_gen is documented with.
 */
static ngx_uint_t  ngx_test_probe_rz_violations = 0;
static ngx_uint_t  ngx_test_probe_rz_checked = 0;


/*
 * Verify one entry's two guards. Returns the number of corrupted guard BYTES,
 * and logs the first corruption in each guard at NGX_LOG_ALERT.
 *
 * ALERT rather than ERR deliberately: memory corruption is not a condition a
 * test run should have to grep for at the right log level, and the scenario
 * oracles that consume this use no_error_log patterns which are easier to
 * write against a level that nothing else in a healthy run emits.
 */
static ngx_uint_t
ngx_test_probe_rz_verify(ngx_test_probe_rz_t *e, ngx_log_t *log)
{
    u_char      *head, *tail;
    ngx_uint_t   i, bad;

    bad = 0;

    head = e->user - NGX_TEST_PROBE_REDZONE;
    tail = e->user + e->size;

    for (i = 0; i < NGX_TEST_PROBE_REDZONE; i++) {
        if (head[i] != NGX_TEST_PROBE_REDZONE_BYTE) {
            if (bad == 0) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "test probe redzone: UNDERFLOW %ui byte(s) "
                              "before a %uz-byte allocation at %p "
                              "(guard byte %ui reads 0x%02Xd)",
                              NGX_TEST_PROBE_REDZONE - i, e->size, e->user,
                              i, (ngx_uint_t) head[i]);
            }
            bad++;
        }
    }

    for (i = 0; i < NGX_TEST_PROBE_REDZONE; i++) {
        if (tail[i] != NGX_TEST_PROBE_REDZONE_BYTE) {
            if (bad == 0) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "test probe redzone: OVERFLOW %ui byte(s) "
                              "past a %uz-byte allocation at %p "
                              "(guard byte %ui reads 0x%02Xd)",
                              i + 1, e->size, e->user,
                              i, (ngx_uint_t) tail[i]);
            }
            bad++;
        }
    }

    return bad;
}


/*
 * Pool-destruction handler: the verification that cannot be skipped.
 *
 * A consumer is free to call ngx_test_probe_redzone_check() whenever it likes,
 * but a check that only runs when someone remembers to call it is a check that
 * silently stops running. Registering this on the pool's cleanup chain means
 * every guarded allocation is verified exactly once, at the moment its pool
 * goes away, whether or not the module under test cooperated.
 *
 * Runs BEFORE the blocks are freed: ngx_destroy_pool() walks the cleanup chain
 * first and calls ngx_free() afterwards, so the guard bytes are still readable
 * here. That ordering is load-bearing and is pinned by a test.
 */
static void
ngx_test_probe_rz_cleanup(void *data)
{
    ngx_test_probe_rz_head_t  *h = data;

    ngx_test_probe_rz_t  *e;

    for (e = h->entries; e != NULL; e = e->next) {
        ngx_test_probe_rz_checked++;

        if (ngx_test_probe_rz_verify(e, h->pool->log) > 0) {
            ngx_test_probe_rz_violations++;
        }
    }
}


/*
 * Find this pool's registry, creating it on first use.
 *
 * The head is itself allocated from the pool it describes, which is safe
 * because it is only ever read from the cleanup handler -- which nginx runs
 * before releasing the blocks.
 */
static ngx_test_probe_rz_head_t *
ngx_test_probe_rz_head(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t        *c;
    ngx_test_probe_rz_head_t  *h;

    for (c = pool->cleanup; c != NULL; c = c->next) {
        if (c->handler == ngx_test_probe_rz_cleanup) {
            return c->data;
        }
    }

    c = ngx_pool_cleanup_add(pool, sizeof(ngx_test_probe_rz_head_t));
    if (c == NULL) {
        return NULL;
    }

    h = c->data;

    h->entries = NULL;
    h->pool = pool;
    h->count = 0;
    h->violations = 0;

    c->handler = ngx_test_probe_rz_cleanup;

    return h;
}


void *
ngx_test_probe_palloc(ngx_pool_t *pool, size_t size)
{
    u_char                    *p;
    size_t                     padded;
    ngx_test_probe_rz_t       *e;
    ngx_test_probe_rz_head_t  *h;

    if (pool == NULL) {
        return NULL;
    }

    /*
     * Overflow check before the addition, not after. size comes from the
     * module under test and in a fault-injection scenario may be attacker
     * influenced; `size + 2 * REDZONE` wrapping would allocate a few bytes and
     * then have the guard writes below scribble across the heap -- this file
     * would become the memory-safety bug it exists to find.
     */
    if (size > (size_t) -1 - (2 * NGX_TEST_PROBE_REDZONE)) {
        return NULL;
    }

    padded = size + 2 * NGX_TEST_PROBE_REDZONE;

    h = ngx_test_probe_rz_head(pool);
    if (h == NULL) {
        return NULL;
    }

    /*
     * ngx_pnalloc, not ngx_palloc: an aligned allocation would let nginx skip
     * bytes between the previous object and this one, and those skipped bytes
     * sit outside our guard. An overflow that lands entirely in alignment
     * padding would then go unreported. Unaligned packing is what makes the
     * guard immediately adjacent to the neighbour, which is the whole point.
     *
     * The caller's pointer is therefore NOT aligned, which is correct for
     * byte-buffer use (the ngx_pnalloc contract) and wrong for a struct. A
     * consumer wanting a guarded struct must align its own size; documented
     * in the header.
     */
    p = ngx_pnalloc(pool, padded);
    if (p == NULL) {
        return NULL;
    }

    e = ngx_palloc(pool, sizeof(ngx_test_probe_rz_t));
    if (e == NULL) {
        return NULL;
    }

    ngx_memset(p, NGX_TEST_PROBE_REDZONE_BYTE, NGX_TEST_PROBE_REDZONE);
    ngx_memset(p + NGX_TEST_PROBE_REDZONE + size, NGX_TEST_PROBE_REDZONE_BYTE,
               NGX_TEST_PROBE_REDZONE);

    e->user = p + NGX_TEST_PROBE_REDZONE;
    e->size = size;
    e->next = h->entries;

    h->entries = e;
    h->count++;

    return e->user;
}


ngx_uint_t
ngx_test_probe_redzone_check(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t        *c;
    ngx_test_probe_rz_t       *e;
    ngx_test_probe_rz_head_t  *h;
    ngx_uint_t                 bad;

    bad = 0;

    if (pool == NULL) {
        return 0;
    }

    for (c = pool->cleanup; c != NULL; c = c->next) {
        if (c->handler != ngx_test_probe_rz_cleanup) {
            continue;
        }

        h = c->data;

        for (e = h->entries; e != NULL; e = e->next) {
            if (ngx_test_probe_rz_verify(e, pool->log) > 0) {
                bad++;
            }
        }

        break;
    }

    return bad;
}


ngx_uint_t
ngx_test_probe_redzone_violations(void)
{
    return ngx_test_probe_rz_violations;
}


ngx_uint_t
ngx_test_probe_redzone_checked(void)
{
    return ngx_test_probe_rz_checked;
}


void
ngx_test_probe_redzone_reset(void)
{
    ngx_test_probe_rz_violations = 0;
    ngx_test_probe_rz_checked = 0;
}

#endif /* NGX_TEST_HARNESS */
