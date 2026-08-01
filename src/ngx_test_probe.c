/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe.c -- in-worker test probe renderer (CI only).
 *
 * See ngx_test_probe.h for what this is and why it is split from the HTTP
 * module that exposes it.
 *
 * The hook registry and the fault_slab= parser live in ngx_test_probe_arm.c.
 * Both files are part of the same unit and consumers build both; they are
 * separate only because the parser depends on nothing but the query bytes,
 * which lets it be tested against a 50-line shim instead of a configured
 * server. What is rendered here cannot be: it reads ngx_cycle, the slab pool
 * and /proc/self/fd, so it is checked by compiling against real nginx and real
 * angie headers in CI, and by the live prober run.
 */

#include "ngx_test_probe.h"

#ifdef NGX_TEST_HARNESS

/* offsetof() for the ABI pins below only; the disabled build must not gain a
 * dependency this translation unit did not already have. */
#include <stddef.h>

/* ngx_event_timer_rbtree, for the "timers" gauge. ngx_core.h does not pull the
 * event headers in, and this is inside NGX_TEST_HARNESS for the same reason
 * stddef.h is: the disabled build must not acquire a dependency it lacked. */
#include <ngx_event.h>


extern ngx_test_probe_hooks_t  ngx_test_probe_hooks;


/*
 * Config loads counted so far. See ngx_test_probe_config_loaded() in the
 * header for why a plain process global is the right home for this and why
 * angie's cycle->generation is not used.
 *
 * Not volatile and not atomic on purpose: the only writer is the master, in
 * its single-threaded config-load path, and every reader is a worker that was
 * forked after that write completed. There is no concurrent access to order.
 */
static ngx_uint_t  ngx_test_probe_config_gen = 0;


void
ngx_test_probe_config_loaded(void)
{
    ngx_test_probe_config_gen++;
}


ngx_uint_t
ngx_test_probe_config_generation(void)
{
    return ngx_test_probe_config_gen;
}


/*
 * ngx_test_probe_pool_stats() walks the cycle pool's block chain and treats
 * the head block as carrying the full ngx_pool_t header while every later
 * block carries only ngx_pool_data_t -- see the comment there. That split
 * only produces the right `start` pointer if ngx_pool_data_t is genuinely the
 * FIRST member of ngx_pool_t, i.e. at offset 0: the head block's ngx_pool_t
 * and a later block's ngx_pool_data_t must be reachable through the same
 * address for `p->d.next` to walk the chain uniformly regardless of which
 * kind of header is actually there. If a future nginx/angie reorders
 * ngx_pool_s to put `d` anywhere but first, this cast silently walks into the
 * wrong bytes and reports a fabricated pool_used figure instead of failing --
 * exactly the kind of wrong-but-plausible number this probe exists to avoid
 * producing.
 */
NGX_TEST_PROBE_ABI_PIN(offsetof(ngx_pool_t, d) == 0,
    "ngx_pool_t layout changed: ngx_pool_data_t (\"d\") is no longer the "
    "first member -- ngx_test_probe_pool_stats()'s per-block start-pointer "
    "arithmetic now reads the wrong offset in every block after the head");

/*
 * The same walk also assumes a later block's header really is exactly
 * sizeof(ngx_pool_data_t) bytes, distinct from the head block's
 * sizeof(ngx_pool_t) -- if those two ever collapsed to the same size (e.g.
 * ngx_pool_t shrank to hold nothing but ngx_pool_data_t) the `p == pool`
 * branch would stop mattering, which is harmless, but the reverse -- the
 * struct growing new members ahead of `d` -- is caught by the offset pin
 * above, not this one. This pin exists to catch the one drift that offset
 * pin cannot: ngx_pool_data_t itself growing or shrinking without ngx_pool_t
 * following, which would desync every block after the first from where its
 * usable memory actually starts.
 */
NGX_TEST_PROBE_ABI_PIN(sizeof(ngx_pool_data_t) < sizeof(ngx_pool_t),
    "ngx_pool_t no longer strictly larger than ngx_pool_data_t -- "
    "ngx_test_probe_pool_stats() assumes the head block's header "
    "(sizeof(ngx_pool_t)) and every later block's header "
    "(sizeof(ngx_pool_data_t)) are different sizes; if they ever match, "
    "verify the per-block start-pointer arithmetic by hand before trusting "
    "this pin's silence");


/*
 * Open file descriptors held by THIS worker.
 *
 * The delta of this across a request is the fd-leak signal: a connection,
 * upstream socket or temp file the module forgot to close stays visible here
 * long after the response body is on the wire, where the response itself shows
 * nothing. Linux-only by construction (/proc/self/fd); elsewhere the field is
 * reported as -1 so a rule asserting on it fails loudly rather than silently
 * comparing against a fabricated zero.
 */
static ngx_int_t
ngx_test_probe_fd_count(void)
{
#if (NGX_LINUX)
    ngx_dir_t   dir;
    ngx_err_t   err;
    ngx_int_t   n;
    ngx_str_t   name = ngx_string("/proc/self/fd");

    if (ngx_open_dir(&name, &dir) == NGX_ERROR) {
        return -1;
    }

    n = 0;
    err = 0;

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            /* End of directory leaves errno at the 0 set above; anything else
             * is a real read failure, and a partial count would understate the
             * fd total -- i.e. hide the very leak this exists to catch. */
            err = ngx_errno;
            break;
        }

        if (ngx_de_name(&dir)[0] == '.') {
            continue;                     /* "." and ".." */
        }

        n++;
    }

    (void) ngx_close_dir(&dir);

    if (err != 0) {
        return -1;
    }

    /* The directory handle was itself one of the entries it just listed, and
     * it is closed again by the time the caller sees this number. */
    return n > 0 ? n - 1 : n;
#else
    return -1;
#endif
}


/*
 * File descriptors held by THIS worker, split by kind.
 *
 * The bare "fds" count above answers "did the module leak a descriptor"; this
 * answers "what KIND", which is what separates a leaked upstream socket from a
 * leaked temp file when both push the total up by one. Kinds are read from the
 * /proc/self/fd/<n> symlink target: a "socket:[...]" or "anon_inode:..." link
 * is not a path, a link that begins with '/' is a real file (regular, device,
 * pipe-as-fifo on disk), and everything else -- most importantly "pipe:[...]"
 * -- falls in "other".
 *
 * Every field shares the -1 sentinel discipline of ngx_test_probe_fd_count():
 * if /proc cannot be read at all, or a readlink fails mid-scan, EVERY bucket is
 * reported as -1 so a delta over it cannot cancel to a passing zero. A partial
 * count would understate exactly the leak this exists to catch, so it is not
 * reported as a smaller-but-real number.
 */
static void
ngx_test_probe_fd_kinds(ngx_int_t *sockets, ngx_int_t *files, ngx_int_t *anon,
    ngx_int_t *other)
{
    *sockets = -1;
    *files = -1;
    *anon = -1;
    *other = -1;

#if (NGX_LINUX)
    {
    ngx_dir_t   dir;
    ngx_err_t   err;
    ngx_int_t   nsock, nfile, nanon, noth;
    ngx_str_t   name = ngx_string("/proc/self/fd");

    if (ngx_open_dir(&name, &dir) == NGX_ERROR) {
        return;
    }

    nsock = 0;
    nfile = 0;
    nanon = 0;
    noth = 0;
    err = 0;

    for ( ;; ) {
        u_char   path[64];
        u_char   target[256];
        u_char  *end;
        ssize_t  len;

        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;
            break;
        }

        if (ngx_de_name(&dir)[0] == '.') {
            continue;                     /* "." and ".." and the dir handle */
        }

        end = ngx_snprintf(path, sizeof(path) - 1, "/proc/self/fd/%s",
                           ngx_de_name(&dir));
        *end = '\0';

        /* path is /proc/self/fd/<N> built from our own readdir() walk above,
         * not attacker-controlled, and target[len] is explicitly
         * NUL-terminated right below using the length readlink() itself
         * returns (never assumed via strlen()). The race the tool flags is
         * the one the comment below already documents and treats as benign:
         * our own fd table changing under us mid-walk, not a symlink an
         * attacker can redirect. */
        len = readlink((const char *) path, (char *) target,  /* flawfinder: ignore */
                       sizeof(target) - 1);

        if (len < 0) {
            /* The fd may have closed between readdir and readlink -- a benign
             * race for our own descriptors, but we cannot tell that from a real
             * failure, and a dropped entry understates a kind. Fail closed. */
            err = ngx_errno ? ngx_errno : EIO;
            break;
        }

        target[len] = '\0';

        if (ngx_strncmp(target, "socket:", 7) == 0) {
            nsock++;

        } else if (ngx_strncmp(target, "anon_inode:", 11) == 0) {
            nanon++;

        } else if (target[0] == '/') {
            nfile++;

        } else {
            noth++;                       /* pipe:[...], and anything unknown */
        }
    }

    (void) ngx_close_dir(&dir);

    if (err != 0) {
        return;                           /* leave all four at -1 */
    }

    /* The directory handle was one of the entries just listed and is a real
     * path under /proc, so it landed in "files"; it is closed by the time the
     * caller sees these numbers. Discount it there, matching the total's -1. */
    *sockets = nsock;
    *files = nfile > 0 ? nfile - 1 : nfile;
    *anon = nanon;
    *other = noth;
    }
#endif
}


/*
 * Resident-set lineage from /proc/self/smaps_rollup: PSS and Private_Dirty, in
 * kB, as the kernel reports them.
 *
 * These are the external-observer memory signals the cycle-pool walk cannot
 * give -- they see growth in ANY mapping (mmap'd temp files, a module's own
 * malloc arena, thread stacks), not just the nginx pool. PSS shares each page's
 * cost across the processes mapping it, so a per-request leak in a single
 * worker shows as a monotonic PSS climb; Private_Dirty is the pages this worker
 * alone has written, the tightest signal for its own heap growth.
 *
 * smaps_rollup is a single pre-summed record (unlike smaps, which is per-VMA
 * and expensive to sum in userspace). It appeared in Linux 4.14; on a kernel or
 * sandbox without it, both fields are -1, the same fail-loud sentinel as fds so
 * a delta cannot cancel to a passing zero.
 */
static void
ngx_test_probe_smaps(ngx_int_t *pss, ngx_int_t *private_dirty)
{
    *pss = -1;
    *private_dirty = -1;

#if (NGX_LINUX)
    {
    FILE   *f;
    char    line[256];

    f = fopen("/proc/self/smaps_rollup", "re");

    if (f == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        long        kb;
        const char *rest = NULL;

        if (ngx_strncmp(line, "Pss:", 4) == 0) {
            rest = line + 4;

            kb = strtol(rest, NULL, 10);
            if (kb >= 0) {
                *pss = (ngx_int_t) kb;
            }

        } else if (ngx_strncmp(line, "Private_Dirty:", 14) == 0) {
            rest = line + 14;

            kb = strtol(rest, NULL, 10);
            if (kb >= 0) {
                *private_dirty = (ngx_int_t) kb;
            }
        }
    }

    (void) fclose(f);
    }
#endif
}


/*
 * Bytes handed out from the CYCLE pool, plus its block, large-alloc and
 * cleanup-handler counts.
 *
 * Request pools are freed wholesale at request end, so a per-request pool leak
 * is invisible from outside -- which is exactly why this measures the cycle
 * pool instead. Nothing in normal request handling may allocate there: it lives
 * as long as the worker does, so an allocation on it per request is an
 * unbounded leak. The delta across a request is therefore expected to be 0,
 * and any other value is a bug even though ASan and valgrind both stay quiet
 * (the memory is still reachable and still freed at exit).
 *
 * cycle_cleanup is the length of the pool's cleanup-handler chain. A module
 * that registers an ngx_pool_cleanup_t on the CYCLE pool per request (rather
 * than the request pool) leaks a handler node AND grows an unbounded callback
 * list the master walks at shutdown -- a leak the byte count also reflects, but
 * the handler count names it precisely as "a cleanup was parked on the wrong
 * pool" rather than as anonymous bytes.
 */
static void
ngx_test_probe_pool_stats(ngx_pool_t *pool, size_t *used, ngx_uint_t *blocks,
    ngx_uint_t *large, ngx_uint_t *cleanup)
{
    u_char              *start;
    ngx_pool_t          *p;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    *used = 0;
    *blocks = 0;
    *large = 0;
    *cleanup = 0;

    if (pool == NULL) {
        return;
    }

    /* Only the first block carries the full ngx_pool_t header; the blocks
     * chained after it carry ngx_pool_data_t alone. */
    for (p = pool; p != NULL; p = p->d.next) {
        start = (u_char *) p + ((p == pool) ? sizeof(ngx_pool_t)
                                            : sizeof(ngx_pool_data_t));
        (*blocks)++;
        *used += (size_t) (p->d.last - start);
    }

    /* Large allocations hang off the head pool regardless of which block was
     * current when ngx_palloc_large() ran. */
    for (l = pool->large; l != NULL; l = l->next) {
        if (l->alloc != NULL) {
            (*large)++;
        }
    }

    /* The cleanup chain likewise hangs off the head pool. */
    for (c = pool->cleanup; c != NULL; c = c->next) {
        (*cleanup)++;
    }
}


/*
 * Armed entries in this worker's event-timer rbtree.
 *
 * The leak this names is one nothing else here can see. A module that arms an
 * ngx_event_t timer per request and fails to disarm it on an ABORTED request
 * (client reset, 499, reload mid-flight) leaves a live timer behind while fds,
 * cycle-pool bytes and slab pages all stay flat -- so every delta oracle we
 * ship reads clean while the worker accumulates callbacks that will fire
 * against freed request state.
 *
 * ngx_event_timer_rbtree is a plain extern ngx_rbtree_t in both nginx and
 * angie, which is why it is read directly. Deliberately NOT ngx_event_find_timer()
 * (it answers "how long until the next one", not "how many"), and deliberately
 * not gated on NGX_STAT_STUB the way ngx_stat_active would be -- the same
 * reasoning the connection counters above are documented with.
 *
 * The tree is PER WORKER and lives in the event loop, so this is only meaningful
 * read from the worker that owns it -- the probe request runs in that worker,
 * which is what makes the count attributable at all. It is also a point-in-time
 * reading taken while the probe request is itself in flight: nginx's own timers
 * (resolver, upstream, keepalive, the probe connection) are counted too, so the
 * oracle a consumer writes is a DELTA back to baseline across a burst, never an
 * absolute value.
 *
 * -1 on an uninitialised tree rather than 0, sharing the sentinel discipline of
 * ngx_test_probe_fd_count(): before ngx_event_timer_init() runs, root and
 * sentinel are both NULL, and reporting that as a genuine zero would let a
 * delta over it cancel to a passing zero.
 */
static ngx_int_t
ngx_test_probe_timer_count(void)
{
    ngx_rbtree_node_t  *root, *sentinel, *node;
    ngx_int_t           n;

    root = ngx_event_timer_rbtree.root;
    sentinel = ngx_event_timer_rbtree.sentinel;

    if (root == NULL || sentinel == NULL) {
        return -1;
    }

    if (root == sentinel) {
        return 0;
    }

    /* Ordered walk via ngx_rbtree_next(), the same traversal
     * ngx_event_expire_timers() uses, rather than a hand-rolled recursion:
     * the tree can be deep and this runs inside a request. */
    n = 0;

    for (node = ngx_rbtree_min(root, sentinel);
         node != NULL;
         node = ngx_rbtree_next(&ngx_event_timer_rbtree, node))
    {
        n++;
    }

    return n;
}


u_char *
ngx_test_probe_json(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    size_t           pool_used;
    u_char          *p;
    ngx_int_t        fds, fd_sock, fd_file, fd_anon, fd_other, pss, priv_dirty;
    ngx_int_t        timers;
    ngx_uint_t       pages_free, pool_blocks, pool_large, pool_cleanup;
    ngx_slab_pool_t *shpool;

    pages_free = 0;

    fds = ngx_test_probe_fd_count();
    timers = ngx_test_probe_timer_count();
    ngx_test_probe_fd_kinds(&fd_sock, &fd_file, &fd_anon, &fd_other);
    ngx_test_probe_smaps(&pss, &priv_dirty);
    ngx_test_probe_pool_stats(ngx_cycle->pool, &pool_used, &pool_blocks,
                              &pool_large, &pool_cleanup);

    /*
     * Worker identity and connection accounting.
     *
     * "ppid" is ngx_parent, which ngx_spawn_process() sets in the PARENT just
     * before forking, so a worker reads the master's pid from it. It is the
     * oracle for `pid_may_change`: a reload legitimately replaces the worker,
     * and the surviving invariant is not "same pid" but "still a child of the
     * same master". Deliberately NOT getppid(): once a master exits, a worker
     * is reparented to init and getppid() would report a pid unrelated to
     * nginx -- which is precisely the crash the assertion has to catch.
     *
     * connection_n / free_connection_n are plain ngx_cycle fields present in
     * both nginx and angie. Deliberately NOT ngx_stat_active and friends: those
     * exist only under NGX_STAT_STUB, so reading them would silently couple the
     * harness to whether stub_status was configured into the build.
     */
    p = ngx_slprintf(buf, last,
                     "{\"flavor\":\"%s\","
                     "\"flavor_version\":\"%s\","
                     "\"pid\":%P,"
                     "\"ppid\":%P,"
                     "\"config_generation\":%ui,"
                     "\"page_size\":%uz,"
                     "\"connections\":{\"total\":%ui,\"free\":%ui},"
                     "\"fds\":%i,"
                     "\"timers\":%i,"
                     "\"fds_by_kind\":{\"socket\":%i,\"file\":%i,"
                     "\"anon\":%i,\"other\":%i},"
                     "\"smaps\":{\"pss\":%i,\"private_dirty\":%i},"
                     "\"pool\":{\"cycle_used\":%uz,\"cycle_blocks\":%ui,"
                     "\"cycle_large\":%ui,\"cycle_cleanup\":%ui}",
                     (u_char *) NGX_TEST_PROBE_FLAVOR,
                     (u_char *) NGX_TEST_PROBE_FLAVOR_VER,
                     ngx_pid,
                     ngx_parent,
                     ngx_test_probe_config_gen,
                     (size_t) ngx_pagesize,
                     (ngx_uint_t) ngx_cycle->connection_n,
                     (ngx_uint_t) ngx_cycle->free_connection_n,
                     fds,
                     timers,
                     fd_sock, fd_file, fd_anon, fd_other,
                     pss, priv_dirty,
                     pool_used,
                     pool_blocks,
                     pool_large,
                     pool_cleanup);

    if (zone == NULL) {
        return ngx_slprintf(p, last, ",\"zone\":{\"present\":false}}");
    }

    /*
     * shm.addr is filled when the master allocates the zone, before any worker
     * forks, and IS the slab pool: every nginx shm zone starts with an
     * ngx_slab_pool_t. A probe that races a reload can legitimately see a zone
     * whose memory is not mapped yet -- report that instead of dereferencing
     * it. Reading pfree needs no module knowledge, which is why zone occupancy
     * works for any module without a hook.
     *
     * Deliberately NOT given an offsetof() pin like the pool-block walk above:
     * "the slab pool starts at offset 0 of shm.addr" is not a struct-layout
     * fact this translation unit can observe from either side. It is nginx's
     * shared-memory allocator (ngx_shm_alloc + ngx_init_zone_pool, outside
     * this file entirely) that places the ngx_slab_pool_t header at the front
     * of the segment it hands back; there is no second struct here whose
     * member offset could be compared against it, so any assert we could
     * write would just restate the cast and pass by construction rather than
     * catch drift. If that placement ever changes, mutex and pfree accesses
     * below read arbitrary bytes as an ngx_shmtx_t and an ngx_uint_t -- this
     * is real UB risk, it is just not one offsetof() can pin from this side;
     * the probe-compiles CI job (real nginx/angie headers) is what actually
     * guards it, same as the compiler already guards `mutex`/`pfree` existing
     * on ngx_slab_pool_t by name.
     */
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (shpool == NULL) {
        /*
         * Same "present":false tail as the zone == NULL case above, and for
         * the same reason: probe-schema.json promises that when present is
         * false, name/size/slab_pages_free are not rendered at all, not that
         * they are rendered as a fabricated 0/empty. Emitting them here would
         * let a probe that legitimately races a reload (see the comment
         * above) return slab_pages_free:0, and a delta oracle over it would
         * subtract that fabricated zero and pass -- exactly the R-10 failure
         * mode. Module-specific zone members (zone_render, below) only run
         * past this point, so returning here also correctly skips them.
         */
        return ngx_slprintf(p, last, ",\"zone\":{\"present\":false}}");
    }

    ngx_shmtx_lock(&shpool->mutex);

    /* pfree is the free-page count the slab allocator maintains
     * unconditionally. pool->stats[] is the richer source but is only
     * populated under NGX_DEBUG_MALLOC-style builds, so it is not a
     * portable signal for a harness that must run on release-ish CI
     * builds of both nginx and angie. */
    pages_free = shpool->pfree;

    ngx_shmtx_unlock(&shpool->mutex);

    /* Reaching here means present is unconditionally true: both false cases
     * (zone == NULL, shpool == NULL) already returned above. */
    p = ngx_slprintf(p, last,
                     ",\"zone\":{"
                     "\"present\":true,"
                     "\"name\":\"%V\","
                     "\"size\":%uz,"
                     "\"slab_pages_free\":%ui",
                     &zone->shm.name,
                     (size_t) zone->shm.size,
                     pages_free);

    /*
     * Module-specific members go inside the zone object, so a consuming
     * module's rules can assert on "zone.nodes" alongside the generic
     * "zone.slab_pages_free" without knowing which side rendered which.
     */
    if (ngx_test_probe_hooks.zone_render != NULL) {
        p = ngx_test_probe_hooks.zone_render(p, last, zone);
    }

    return ngx_slprintf(p, last, "}}");
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_test_probe_not_built_t;

#endif /* NGX_TEST_HARNESS */
