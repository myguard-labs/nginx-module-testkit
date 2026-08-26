/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe_canary.c -- guard bytes around SHARED-MEMORY slab
 * allocations, plus freed-chunk poisoning.
 *
 * This is the shm counterpart to ngx_test_probe_redzone.c, which does the same
 * job for the per-request/per-cycle pool. They are separate files because the
 * two allocators differ in the one way that decides what a guard can catch:
 *
 *   POOL   ngx_palloc_small() is a bump allocator with NO per-object free.
 *          A guard can catch an overflow. Use-after-free is not expressible,
 *          because nothing is freed until the pool dies wholesale.
 *
 *   SLAB   ngx_slab_alloc()/ngx_slab_free() is a real allocator with a real
 *          free. A guard catches an overflow AND, by poisoning the chunk on
 *          free, a use-after-WRITE on freed shared memory.
 *
 * WHY THE SANITIZERS CANNOT DO THIS EITHER
 *
 * A shm zone is one mmap. nginx maps it once, in the master, before forking;
 * every worker inherits the same mapping. To AddressSanitizer that is a single
 * region -- it never saw a malloc for the individual chunks inside it, so it
 * has no boundaries to poison and no metadata to consult. The same is true of
 * valgrind memcheck, and for the additional reason that the region is fully
 * addressable and (after ngx_slab_init) fully defined.
 *
 * Worse than the pool case: shm is shared across PROCESSES. A corruption
 * written by worker A is observed by worker B, and no single-address-space
 * tool models that at all. ASan's shadow memory is per-process; a worker's
 * shadow says nothing about what another worker did to the shared mapping.
 *
 * THE SLACK PROBLEM, WHICH IS SPECIFIC TO SLAB
 *
 * ngx_slab_alloc_locked() rounds a request UP TO A POWER OF TWO
 * (`for (s = size - 1; s >>= 1; shift++)`). A 20-byte request is served from a
 * 32-byte chunk. Those 12 slack bytes belong to the allocation as far as the
 * allocator is concerned, so a module overflowing 20 into 24 corrupts nothing
 * and no allocator-level check can ever notice.
 *
 * That is precisely the bug this file has to catch, and it is why the canary
 * is placed at the CALLER'S requested size rather than at the chunk boundary:
 * we ask for size + 2*CANARY, and put the guards immediately around the
 * caller's own span. The overflow into slack becomes an overflow into a guard.
 *
 * WHAT THIS IS NOT
 *
 * Not a race detector. It observes the CONSEQUENCE of a corruption, never the
 * interleaving that produced it, and it cannot say which worker wrote the
 * byte. For cross-process invariant checking see the shm-coherence lens; for
 * the interleaving itself, nothing here helps and nothing else does either --
 * helgrind and TSan model pthread races in one address space, which is not
 * what nginx workers are.
 *
 * See ngx_test_probe.h.
 */

#ifdef NGX_TEST_PROBE_POOL_SHIM
#include "ngx_pool_shim.h"
#endif

#include "ngx_test_probe.h"

#ifdef NGX_TEST_HARNESS


/*
 * Guard and poison patterns, deliberately distinct from each other and from
 * the pool redzone's 0xDB, so a corrupted byte names its own origin on sight:
 *
 *   0xCA  an intact slab guard
 *   0xFE  a freed chunk's poison
 *   0xDB  a pool redzone (ngx_test_probe_redzone.c)
 *
 * Reading 0xFE where data was expected says "this chunk was freed and then
 * read", which is a different bug from "something ran off the end of the
 * previous allocation" (0xCA) even though both surface as corruption.
 */
#define NGX_TEST_PROBE_CANARY_BYTE   0xCA
#define NGX_TEST_PROBE_POISON_BYTE   0xFE


/*
 * Header carried immediately before the caller's span, inside the same slab
 * chunk.
 *
 * An in-band header rather than a side table, which is the opposite of the
 * choice ngx_test_probe_redzone.c made, and for a reason that only applies
 * here: a side registry would have to live in the SHARED zone to be visible to
 * every worker, would itself need slab allocations (recursing into the
 * allocator under test), and would need its own locking discipline on top of
 * shpool->mutex. In-band metadata inherits the chunk's own lifetime and the
 * caller's own locking for free.
 *
 * `magic` is what makes ngx_test_probe_slab_free() refuse a pointer this file
 * did not hand out -- freeing a plain ngx_slab_alloc() pointer through here
 * would compute a header address inside someone else's chunk and corrupt it.
 *
 * `size` is the caller's requested size, not the chunk size, so the guard sits
 * where the CALLER's allocation ends rather than where the allocator's chunk
 * does. See the slack discussion above.
 */
#define NGX_TEST_PROBE_CANARY_MAGIC  0x43414E59u   /* "CANY" */

/*
 * LAYOUT, and the ordering bug it exists to avoid.
 *
 *   [ hdr: magic | size | size_dup ][ head guard ][ user span ][ tail guard ]
 *
 * The head guard sits BETWEEN the header and the user span, not inside the
 * header. The first cut of this file overlaid the guard on the header's own
 * trailing bytes to save space, and that was wrong in a way the tests caught
 * immediately: an overflow out of the PREVIOUS chunk lands on the header
 * before it reaches any guard, so `size` was corrupted and the verifier then
 * walked `user + <garbage>` and segfaulted. A corruption detector that
 * crashes on the corruption it is meant to report is worse than none.
 *
 * `size_dup` is a redundant copy checked against `size` before either is
 * trusted. A single overflowing write that reaches the header will disagree
 * the two (it writes a contiguous run, so it cannot leave a plausible pair),
 * which turns "my metadata is corrupt" into a reportable finding rather than
 * an out-of-bounds read. This is belt and braces on top of the layout fix
 * above, because the layout only guarantees the guard is hit FIRST -- it
 * cannot stop a wild write from landing directly on the header.
 */
typedef struct {
    uint32_t    magic;
    uint32_t    pad;        /* keep the user span pointer-aligned */
    size_t      size;
    size_t      size_dup;
} ngx_test_probe_canary_hdr_t;


/*
 * Cumulative per-worker counters, rendered as `canary.*`.
 *
 * IMPORTANT AND EASY TO GET WRONG: these are per-WORKER process globals, not
 * shared state, even though what they describe lives in shared memory. A
 * violation written by worker A and detected by worker B is counted by B --
 * the process that looked, not the process that broke it.
 *
 * That is a real limitation and it is stated in the docs rather than papered
 * over: this lens tells you a shared zone is corrupt, never who corrupted it.
 * Putting the counters in the zone itself was considered and rejected -- they
 * would then need their own slab allocation and their own mutex discipline,
 * i.e. the counters would become another user of the allocator they exist to
 * audit.
 */
static ngx_uint_t  ngx_test_probe_canary_violations = 0;
static ngx_uint_t  ngx_test_probe_canary_checked = 0;
static ngx_uint_t  ngx_test_probe_canary_live = 0;


/*
 * Total bytes reserved ahead of the caller's span: the header, then the head
 * guard. Kept as one expression so alloc, free and verify cannot disagree
 * about where the user span begins -- they did once, and it segfaulted.
 */
#define NGX_TEST_PROBE_CANARY_PREFIX \
    (sizeof(ngx_test_probe_canary_hdr_t) + NGX_TEST_PROBE_CANARY)


static ngx_test_probe_canary_hdr_t *
ngx_test_probe_canary_hdr(void *p)
{
    return (ngx_test_probe_canary_hdr_t *)
               ((u_char *) p - NGX_TEST_PROBE_CANARY_PREFIX);
}


/*
 * Verify one chunk's two guards. Returns 1 if either is corrupt.
 *
 * Logged at NGX_LOG_ALERT for the same reason the pool redzone does: shared
 * memory corruption is not something a test run should have to grep for at the
 * right level, and a scenario's no_error_log pattern is easier to write
 * against a level nothing else in a healthy run emits.
 */
static ngx_uint_t
ngx_test_probe_canary_verify(ngx_test_probe_canary_hdr_t *h, ngx_log_t *log)
{
    u_char      *user, *head, *tail;
    ngx_uint_t   i, bad;

    bad = 0;

    head = (u_char *) h + sizeof(ngx_test_probe_canary_hdr_t);
    user = head + NGX_TEST_PROBE_CANARY;

    /*
     * The head guard FIRST, and the size check before any arithmetic on it.
     *
     * A write running forward out of the previous chunk reaches the header
     * before it reaches anything else, so `size` is the one field that cannot
     * be trusted at this point. Computing `user + h->size` on a corrupted size
     * is an out-of-bounds read -- the detector crashing on the corruption it
     * exists to report, which is how the first cut of this file behaved.
     */
    for (i = 0; i < NGX_TEST_PROBE_CANARY; i++) {
        if (head[i] != NGX_TEST_PROBE_CANARY_BYTE) {
            if (bad == 0) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "test probe canary: SLAB UNDERFLOW before a "
                              "%uz-byte shm allocation at %p",
                              h->size, user);
            }
            bad = 1;
        }
    }

    if (h->size != h->size_dup) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "test probe canary: HEADER CORRUPT on the allocation at "
                      "%p (size %uz vs %uz) -- something wrote across this "
                      "chunk's metadata; the tail guard cannot be located",
                      user, h->size, h->size_dup);
        return 1;
    }

    tail = user + h->size;

    for (i = 0; i < NGX_TEST_PROBE_CANARY; i++) {
        if (tail[i] != NGX_TEST_PROBE_CANARY_BYTE) {
            if (bad == 0) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "test probe canary: SLAB OVERFLOW past a "
                              "%uz-byte shm allocation at %p "
                              "(guard byte %ui reads 0x%02Xd)",
                              h->size, user, i, (ngx_uint_t) tail[i]);
            }
            bad = 1;
        }
    }

    return bad;
}


void *
ngx_test_probe_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    u_char                       *p;
    size_t                        padded;
    ngx_test_probe_canary_hdr_t  *h;

    if (pool == NULL) {
        return NULL;
    }

    /*
     * Overflow check BEFORE the addition. `size` may be attacker-influenced in
     * a fault-injection scenario; a wrap here would allocate a few bytes and
     * then have the guard writes below scribble across the shared zone -- this
     * file becoming the corruption it exists to detect, in memory every worker
     * can see.
     */
    if (size > (size_t) -1 - NGX_TEST_PROBE_CANARY_PREFIX
                        - NGX_TEST_PROBE_CANARY)
    {
        return NULL;
    }

    padded = NGX_TEST_PROBE_CANARY_PREFIX + size + NGX_TEST_PROBE_CANARY;

    /*
     * ngx_slab_alloc, not ngx_slab_alloc_locked: this takes shpool->mutex
     * itself. A caller already holding the mutex must use the _locked variant
     * below, and the two are kept as separate entry points rather than a flag
     * because getting that wrong is a self-deadlock, which is the worst
     * possible failure mode for a test aid.
     */
    p = ngx_slab_alloc(pool, padded);
    if (p == NULL) {
        return NULL;
    }

    h = (ngx_test_probe_canary_hdr_t *) p;

    h->magic = NGX_TEST_PROBE_CANARY_MAGIC;
    h->pad = 0;
    h->size = size;
    h->size_dup = size;

    /* Head guard sits AFTER the header, immediately before the caller's first
     * byte -- see the layout comment on ngx_test_probe_canary_hdr_t. */
    ngx_memset(p + sizeof(ngx_test_probe_canary_hdr_t),
               NGX_TEST_PROBE_CANARY_BYTE, NGX_TEST_PROBE_CANARY);

    ngx_memset(p + NGX_TEST_PROBE_CANARY_PREFIX + size,
               NGX_TEST_PROBE_CANARY_BYTE, NGX_TEST_PROBE_CANARY);

    ngx_test_probe_canary_live++;

    return p + NGX_TEST_PROBE_CANARY_PREFIX;
}


ngx_uint_t
ngx_test_probe_slab_free(ngx_slab_pool_t *pool, void *p, ngx_log_t *log)
{
    ngx_uint_t                    bad;
    ngx_test_probe_canary_hdr_t  *h;

    if (pool == NULL || p == NULL) {
        return 0;
    }

    h = ngx_test_probe_canary_hdr(p);

    /*
     * Refuse a pointer this file did not hand out. Without the magic check a
     * plain ngx_slab_alloc() pointer passed here would have its "header" read
     * from the tail of the PREVIOUS chunk, and the poison memset below would
     * then run for whatever garbage `size` happened to hold -- destroying live
     * shared memory in the name of checking it.
     *
     * Counted as a violation rather than silently ignored: it is a real defect
     * in the module under test (a mismatched alloc/free pair), and a detector
     * that quietly tolerates one is how mismatches survive to production.
     */
    if (h->magic != NGX_TEST_PROBE_CANARY_MAGIC) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "test probe canary: slab_free of %p, which this probe "
                      "did not allocate (magic 0x%08XD) -- mismatched "
                      "alloc/free pair", p, h->magic);
        ngx_test_probe_canary_violations++;
        return 1;
    }

    ngx_test_probe_canary_checked++;

    bad = ngx_test_probe_canary_verify(h, log);
    if (bad) {
        ngx_test_probe_canary_violations++;
    }

    /*
     * Poison the caller's span before handing the chunk back.
     *
     * This is what the pool redzone cannot offer: the slab has a real free, so
     * a use-after-free is expressible here. A module that keeps reading a
     * freed shm chunk gets 0xFE bytes rather than plausible stale data, which
     * turns a silent wrong answer into an obvious one. It does NOT detect the
     * read -- nothing here can -- it makes the read's RESULT unmistakable.
     *
     * The magic is cleared too, so a double free is caught by the check above
     * rather than passing a second time.
     */
    ngx_memset(p, NGX_TEST_PROBE_POISON_BYTE, h->size);
    h->magic = 0;

    if (ngx_test_probe_canary_live > 0) {
        ngx_test_probe_canary_live--;
    }

    ngx_slab_free(pool, h);

    return bad;
}


ngx_uint_t
ngx_test_probe_canary_check(void *p, ngx_log_t *log)
{
    ngx_test_probe_canary_hdr_t  *h;

    if (p == NULL) {
        return 0;
    }

    h = ngx_test_probe_canary_hdr(p);

    if (h->magic != NGX_TEST_PROBE_CANARY_MAGIC) {
        return 0;
    }

    ngx_test_probe_canary_checked++;

    if (ngx_test_probe_canary_verify(h, log)) {
        ngx_test_probe_canary_violations++;
        return 1;
    }

    return 0;
}


ngx_uint_t
ngx_test_probe_canary_violations_get(void)
{
    return ngx_test_probe_canary_violations;
}


ngx_uint_t
ngx_test_probe_canary_checked_get(void)
{
    return ngx_test_probe_canary_checked;
}


ngx_uint_t
ngx_test_probe_canary_live_get(void)
{
    return ngx_test_probe_canary_live;
}


void
ngx_test_probe_canary_reset(void)
{
    ngx_test_probe_canary_violations = 0;
    ngx_test_probe_canary_checked = 0;
    ngx_test_probe_canary_live = 0;
}

#endif /* NGX_TEST_HARNESS */
