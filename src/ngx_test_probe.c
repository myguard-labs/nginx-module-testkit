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
 *
 * @sentinel-schema: fds
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
 *
 * @sentinel-schema: fds_by_kind.socket fds_by_kind.file fds_by_kind.anon fds_by_kind.other
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
 *
 * @sentinel-schema: smaps.pss smaps.private_dirty
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
 *
 * @sentinel-schema: timers
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


/* ngx_test_probe_escape_json_string() depends on nothing but the input bytes
 * (no ngx_cycle, no slab pool, no /proc), so it lives in ngx_test_probe_arm.c
 * next to ngx_test_probe_arm() for the same reason that one is split out:
 * reachability from a direct-call unit harness built against the t/ shim
 * instead of a configured server. See ngx_test_probe_arm.c and
 * ngx_test_probe.h for the declaration. */


/*
 * Renders the whole probe document, and is itself the emitter for the three
 * slab-counter fields: unlike the fd/smaps/timer figures it delegates to
 * helper functions, the zone's stats[] sum is computed inline here because it
 * must happen under the slab mutex this function already holds.
 *
 * Those three carry the -1-sentinel discipline. shpool->stats is a pointer set
 * by ngx_slab_init(), so a worker probing a zone the master has mapped but not
 * yet initialised reads NULL; rendering 0 there would be a fabricated zero
 * indistinguishable from an honest "no allocations yet", and a `delta
 * zone.slab_reqs <= K` ceiling would pass while measuring nothing. -1 is not
 * reachable as a real value (all three are counts), so the sentinel never
 * masks a legitimate reading.
 *
 * @sentinel-schema: zone.slab_reqs zone.slab_fails zone.slab_used
 */
u_char *
ngx_test_probe_json(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    size_t           pool_used;
    u_char          *p;
    ngx_int_t        fds, fd_sock, fd_file, fd_anon, fd_other, pss, priv_dirty;
    ngx_int_t        timers;
    ngx_int_t        slab_reqs, slab_fails, slab_used;
    ngx_uint_t       pages_free, pool_blocks, pool_large, pool_cleanup;
    ngx_uint_t       slot, slab_slots;
    ngx_uint_t       reqs_sum, fails_sum, used_sum;
    ngx_slab_pool_t *shpool;

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

    /*
     * The zone-independent module members, BEFORE the zone object and before
     * either present:false early return below. A module with no shm zone
     * reaches the document only through here; rendering it after the zone
     * branch would put it behind two returns that a zoneless module always
     * takes, which is the defect this ordering exists to prevent.
     */
    p = ngx_test_probe_render_module(p, last);

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

    /*
     * pfree is the free-page count the slab allocator maintains
     * unconditionally.
     *
     * pool->stats[] is the richer source, and IS portable: an earlier version
     * of this comment claimed it was populated only under NGX_DEBUG_MALLOC-
     * style builds, which was measured false. Every write site in
     * src/core/ngx_slab.c is unconditional -- `stats[slot].reqs++` on each
     * ngx_slab_alloc_locked(), `.fails++` on the exhaustion return, `.used--`
     * in ngx_slab_free_locked(); the file's only #if is NGX_DEBUG_MALLOC
     * around a memset, nowhere near the counters. Verified on nginx 1.31.4 and
     * angie 1.12.1, whose ngx_slab_stat_t is layout-identical. This is NOT the
     * ngx_stat_active situation noted above: those really are NGX_STAT_STUB-
     * gated, these are not.
     *
     * WHY THE COUNTERS EARN THEIR PLACE. Every other memory oracle here reads
     * net OCCUPANCY, which is structurally blind to churn: ten thousand
     * matched alloc/free pairs in one request net to zero and read as a clean
     * result. reqs is cumulative and never decreases, so it exposes the
     * allocation TRAFFIC that occupancy cancels out -- the difference between
     * "does this module leak" and "does this module thrash the slab".
     *
     * Summed across slots rather than rendered per-slot. A per-slot array
     * would let a rule assert on one size class, but every consumer would then
     * have to know which slot its allocation lands in -- a function of
     * ngx_pagesize and min_shift, i.e. of the build, not of the module. The
     * sum is the figure a ceiling oracle actually wants.
     *
     * The slot COUNT is ngx_pagesize_shift - min_shift, computed exactly as
     * ngx_slab_init() sizes the array (ngx_slab.c:116). It is a runtime value,
     * not a constant: ngx_pagesize_shift is the host's page size and min_shift
     * is per-pool. Hardcoding a slot count here would read past the array on
     * any build where either differs -- a shared-memory overread inside the
     * slab mutex.
     */
    ngx_shmtx_lock(&shpool->mutex);

    pages_free = shpool->pfree;

    /*
     * stats is a pointer INTO the zone, set by ngx_slab_init(). A worker that
     * probes a zone the master has mapped but not yet initialised can see it
     * NULL, the same race the shpool == NULL branch above handles. Render the
     * -1 sentinel rather than 0: a zero here is indistinguishable from a real
     * "no allocations yet" and would let a ceiling oracle pass vacuously,
     * which is the failure mode this whole file exists to refuse.
     */
    if (shpool->stats == NULL || ngx_pagesize_shift <= shpool->min_shift) {
        slab_reqs = -1;
        slab_fails = -1;
        slab_used = -1;

    } else {
        slab_slots = (ngx_uint_t) ngx_pagesize_shift - shpool->min_shift;

        reqs_sum = 0;
        fails_sum = 0;
        used_sum = 0;

        /*
         * Accumulate in the UNSIGNED type the counters actually are, and
         * convert once at the end. Summing straight into ngx_int_t would be
         * signed overflow -- undefined behaviour, not a wrap -- and the
         * saturation below could not then be trusted to run at all.
         */
        for (slot = 0; slot < slab_slots; slot++) {
            reqs_sum += shpool->stats[slot].reqs;
            fails_sum += shpool->stats[slot].fails;
            used_sum += shpool->stats[slot].used;
        }

        /*
         * SATURATE rather than wrap. reqs and fails are CUMULATIVE and never
         * reset for the life of the zone, so on a 32-bit build (ngx_uint_t is
         * 32 bits there, and .github/workflows/arch-32bit.yml builds exactly
         * that) reqs passes NGX_MAX_INT_T_VALUE after roughly half an hour at
         * a million allocations a second. A wrap would not merely report a
         * wrong number: it would eventually land on -1 and impersonate the
         * uninitialised-pool sentinel above, turning a busy zone into "this
         * field is unavailable" and passing every ceiling built on it.
         *
         * NGX_MAX_INT_T_VALUE is itself outside the reachable range of an
         * honest reading, so a delta oracle that sees it stops making sense
         * arithmetically rather than silently certifying a bound -- the same
         * fail-loud preference as the -1 sentinel, one value in from it.
         */
        slab_reqs = (reqs_sum > (ngx_uint_t) NGX_MAX_INT_T_VALUE)
                    ? NGX_MAX_INT_T_VALUE : (ngx_int_t) reqs_sum;
        slab_fails = (fails_sum > (ngx_uint_t) NGX_MAX_INT_T_VALUE)
                     ? NGX_MAX_INT_T_VALUE : (ngx_int_t) fails_sum;
        slab_used = (used_sum > (ngx_uint_t) NGX_MAX_INT_T_VALUE)
                    ? NGX_MAX_INT_T_VALUE : (ngx_int_t) used_sum;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    /* Reaching here means present is unconditionally true: both false cases
     * (zone == NULL, shpool == NULL) already returned above. */
    p = ngx_slprintf(p, last,
                     ",\"zone\":{"
                     "\"present\":true,"
                     "\"name\":\"");
    p = ngx_test_probe_escape_json_string(p, last, &zone->shm.name);
    p = ngx_slprintf(p, last,
                     "\","
                     "\"size\":%uz,"
                     "\"slab_pages_free\":%ui,"
                     "\"slab_reqs\":%i,"
                     "\"slab_fails\":%i,"
                     "\"slab_used\":%i",
                     (size_t) zone->shm.size,
                     pages_free,
                     slab_reqs,
                     slab_fails,
                     slab_used);

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
