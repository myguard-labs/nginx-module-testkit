/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_pool_shim.h -- just enough nginx to compile ngx_test_probe_redzone.c
 * on its own.
 *
 * A SECOND shim rather than an extension of ngx_shim.h, following the reason
 * that file's own header gives for not merging shims: each one stubs exactly
 * the surface its target touches, and a superset couples every consumer to
 * declarations it does not use. ngx_shim.h exists for a query-string parser
 * that needs no allocator at all; this one needs a working bump allocator and
 * a cleanup chain, because the code under test is an allocator wrapper.
 *
 * WHAT IS REAL HERE, AND WHY IT HAS TO BE
 *
 * The pool is not a stub -- it is a faithful reimplementation of nginx's bump
 * allocator, because the bug class under test is CREATED by bump allocation.
 * A shim that forwarded each ngx_pnalloc() to malloc() would give every object
 * its own libc block with its own ASan redzones, and the overflow this file
 * exists to catch would either be caught by ASan (proving nothing about our
 * code) or land in unmapped memory (crashing instead of corrupting). Objects
 * must be adjacent slices of one block for the test to mean anything.
 *
 * ngx_palloc and ngx_pnalloc differ exactly as they do upstream: the former
 * aligns, the latter does not.
 *
 * It EXTENDS ngx_shim.h rather than restating it. t/ngx_config.h and
 * t/ngx_core.h both include ngx_shim.h unconditionally, and ngx_test_probe.h
 * includes ngx_config.h -- so ngx_shim.h is already in every translation unit
 * that reaches this file, and redeclaring ngx_str_t or ngx_int_t here is a
 * hard compile error rather than a stylistic duplication. What is added below
 * is only what ngx_shim.h lacks: the pool, the cleanup chain, the allocators
 * and the log macro.
 */

#ifndef NGX_TEST_HARNESS_POOL_SHIM_H
#define NGX_TEST_HARNESS_POOL_SHIM_H

#include <stdio.h>
#include <stdlib.h>

#include "ngx_shim.h"

#define NGX_LOG_ALERT  1

/* The redzone verifier passes pool->log straight to ngx_log_error and never
 * dereferences it, so an opaque tag is enough. */
typedef struct ngx_log_s  ngx_log_t;

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    void                (*handler)(void *data);
    void                 *data;
    ngx_pool_cleanup_t   *next;
};

/*
 * One block, sized at creation. Upstream chains blocks when one fills; the
 * code under test never depends on that, and a single block keeps the
 * adjacency the test relies on obvious rather than incidental.
 */
typedef struct ngx_pool_s  ngx_pool_t;

struct ngx_pool_s {
    u_char              *last;
    u_char              *end;
    ngx_pool_cleanup_t  *cleanup;
    ngx_log_t           *log;
    u_char              *base;
};

/*
 * A slab pool that really allocates, for ngx_test_probe_canary.c.
 *
 * As with the bump allocator above, the fidelity that matters is the bug class
 * under test. Two properties are reproduced deliberately:
 *
 *   POWER-OF-TWO ROUNDING. ngx_slab_alloc_locked() rounds a request up to the
 *   next power of two, so a 20-byte request is served from a 32-byte chunk and
 *   the 12 slack bytes are invisible to any allocator-level check. That slack
 *   is the reason the canary is placed at the caller's requested size, and a
 *   shim that handed back exactly `size` bytes would make the tests pass for
 *   the wrong reason -- there would be no slack to overflow into.
 *
 *   ADJACENCY. Chunks come out of one contiguous arena, so an overflow past
 *   one chunk lands in the next rather than in unmapped memory.
 *
 * Freeing is a no-op: nothing here reuses a chunk, because none of the
 * assertions depend on reuse and a free list would be a second allocator to
 * get wrong. The poison-on-free path under test writes to the chunk before
 * calling this, which is what the tests read back.
 */
typedef struct {
    u_char  *base;
    u_char  *last;
    u_char  *end;
} ngx_slab_pool_t;


static inline ngx_slab_pool_t *
ngx_slab_pool_shim_create(size_t size)
{
    ngx_slab_pool_t  *p;

    p = malloc(sizeof(ngx_slab_pool_t));
    if (p == NULL) {
        return NULL;
    }

    p->base = malloc(size);
    if (p->base == NULL) {
        free(p);
        return NULL;
    }

    p->last = p->base;
    p->end = p->base + size;

    return p;
}


static inline void
ngx_slab_pool_shim_destroy(ngx_slab_pool_t *pool)
{
    free(pool->base);
    free(pool);
}


static inline void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    size_t   rounded;
    u_char  *m;

    /* Round up to a power of two, as ngx_slab_alloc_locked() does. */
    rounded = 8;
    while (rounded < size) {
        rounded <<= 1;
    }

    if ((size_t) (pool->end - pool->last) < rounded) {
        return NULL;
    }

    m = pool->last;
    pool->last += rounded;

    return m;
}


static inline void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    (void) pool;
    (void) p;
}


/* Not in ngx_shim.h, which has no allocator and so never needed them. */
#define NGX_ALIGNMENT  sizeof(unsigned long)

#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) (a) - 1)) & ~((uintptr_t) (a) - 1))

#define ngx_memset(buf, c, n)    memset(buf, c, n)

/*
 * Diagnostics are captured rather than printed so a test can assert on them.
 * The redzone verifier logs at ALERT on every corruption it finds, and "did it
 * report" is half of what these tests check -- a detector that finds the
 * corruption but says nothing is as useless as one that misses it.
 */
extern int   ngx_shim_log_count;
extern char  ngx_shim_log_last[512];

/*
 * The format string is stored VERBATIM, not rendered.
 *
 * nginx's ngx_log_error() is not printf: it uses ngx_vslprintf(), whose
 * conversions (%ui, %uz, %P, %i) are nginx's own and are not valid printf
 * specifiers. Passing the same string to snprintf() produced three -Wformat
 * warnings and would have read the varargs with the wrong widths -- a shim
 * whose own diagnostics are undefined behaviour is not a foundation for
 * memory-safety tests.
 *
 * The tests here assert on the LITERAL text of the message ("OVERFLOW",
 * "UNDERFLOW"), never on an interpolated value, so storing the template is
 * sufficient. Arguments are cast to void to keep them evaluated-but-unused
 * without tripping -Wunused-value.
 */
#define ngx_log_error(level, log, err, fmt, ...)                              \
    do {                                                                      \
        ngx_shim_log_count++;                                                 \
        (void) (level); (void) (log); (void) (err);                           \
        snprintf(ngx_shim_log_last, sizeof(ngx_shim_log_last), "%s", fmt);    \
    } while (0)


static inline ngx_pool_t *
ngx_create_pool_shim(size_t size)
{
    ngx_pool_t  *p;

    p = malloc(sizeof(ngx_pool_t));
    if (p == NULL) {
        return NULL;
    }

    p->base = malloc(size);
    if (p->base == NULL) {
        free(p);
        return NULL;
    }

    p->last = p->base;
    p->end = p->base + size;
    p->cleanup = NULL;
    p->log = NULL;

    return p;
}


static inline void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    u_char  *m;

    if ((size_t) (pool->end - pool->last) < size) {
        return NULL;
    }

    m = pool->last;
    pool->last += size;

    return m;
}


static inline void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    u_char  *m;

    m = ngx_align_ptr(pool->last, NGX_ALIGNMENT);

    if ((size_t) (pool->end - m) < size) {
        return NULL;
    }

    pool->last = m + size;

    return m;
}


static inline ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(pool, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    c->handler = NULL;
    c->data = size ? ngx_palloc(pool, size) : NULL;

    if (size && c->data == NULL) {
        return NULL;
    }

    c->next = pool->cleanup;
    pool->cleanup = c;

    return c;
}


/*
 * Runs the cleanup chain and then releases the block, in that order --
 * upstream's ngx_destroy_pool() ordering, which the redzone cleanup handler
 * depends on: it reads guard bytes that the free would otherwise have
 * released. A shim that freed first would turn every cleanup-path assertion
 * into a use-after-free, so the ordering is part of what this file has to get
 * right.
 */
static inline void
ngx_destroy_pool_shim(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *c;

    for (c = pool->cleanup; c != NULL; c = c->next) {
        if (c->handler) {
            c->handler(c->data);
        }
    }

    free(pool->base);
    free(pool);
}

#endif /* NGX_TEST_HARNESS_POOL_SHIM_H */
