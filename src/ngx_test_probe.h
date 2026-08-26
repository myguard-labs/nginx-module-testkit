/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe.h -- in-worker test probe for nginx/angie modules (CI only).
 *
 * A read-only introspection endpoint that reports worker and shm-zone state as
 * JSON, so an external prober can assert on state the HTTP response alone does
 * not reveal -- slab occupancy, fd count, cycle-pool growth -- and diff it
 * across a request. Those deltas are the leak detection sanitizers cannot give
 * you: a leaked fd is not a memory error at all, and a request-pool allocation
 * is freed wholesale at request end, so a per-request leak inside it is
 * invisible from outside.
 *
 * Everything here is generic to nginx and angie. What a probe cannot know
 * generically is the SEMANTICS of a module's shared memory -- how many nodes,
 * how many are banned, which fault sites exist -- so a consuming module
 * registers two small hooks for that (see ngx_test_probe_hooks_t). Everything
 * else, including the whole prober under ci/prober/, is module-agnostic.
 *
 * The feature compiles out entirely unless NGX_TEST_HARNESS is defined. It must
 * never be defined for a packaged build: the probe walks queues under the slab
 * mutex and scans /proc, and it exposes internal state unauthenticated.
 *
 * Like a well-behaved renderer this depends only on <ngx_core.h> and never on
 * <ngx_http.h>: everything request-shaped (the directive, the content handler,
 * the response) stays in the consuming module, which keeps this reachable from
 * a direct-call unit harness.
 */

#ifndef NGX_TEST_PROBE_H_INCLUDED_
#define NGX_TEST_PROBE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#ifdef NGX_TEST_HARNESS

/*
 * Compile-time pin for a structural assumption about nginx/angie internals.
 *
 * nginx's own headers are C89-clean and this file follows that outside of
 * NGX_TEST_HARNESS, but a compile-time assertion is worth stepping past C89
 * for: the alternative is the assumption silently rotting until a version
 * bump makes the probe read garbage in production CI, which is a much worse
 * place to find out than a build failure here. _Static_assert is used when
 * the compiler advertises C11 (nginx itself is built with gnu99/gnu11
 * depending on distro, both of which define __STDC_VERSION__ >= 201112L via
 * the GNU extension even in -std=gnu89-ish setups is NOT guaranteed, hence
 * the guard rather than assuming it). Where it is not available, a
 * negative-array-size trick stands in: `int name[(cond) ? 1 : -1]` fails to
 * compile with a size-of-array-is-negative diagnostic, which is not as
 * readable as a custom message but still turns drift into a build break
 * instead of a runtime one. Both forms are file-scope declarations with no
 * storage, so neither one costs anything in the object the harness ships.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define NGX_TEST_PROBE_ABI_PIN(cond, msg)  _Static_assert(cond, msg)
#else
#define NGX_TEST_PROBE_ABI_PIN_CONCAT_(a, b)  a##b
#define NGX_TEST_PROBE_ABI_PIN_NAME_(line) \
    NGX_TEST_PROBE_ABI_PIN_CONCAT_(ngx_test_probe_abi_pin_, line)
#define NGX_TEST_PROBE_ABI_PIN(cond, msg) \
    typedef int NGX_TEST_PROBE_ABI_PIN_NAME_(__LINE__)[(cond) ? 1 : -1]
#endif


/*
 * nginx-vs-angie detection.
 *
 * Angie reaches module code as ANGIE_VERSION via ngx_core.h -> ngx_module.h ->
 * <angie.h>, so plain <ngx_core.h> is enough and no __has_include is needed.
 *
 * Do NOT test NGINX_VERSION to tell them apart: angie defines that too (its
 * src/core/nginx.h carries the nginx version it tracks), so the test is true on
 * both. Verified against angie 1.12.1 / nginx 1.30.3, 2026-07-18.
 */
#ifdef ANGIE_VERSION
#define NGX_TEST_PROBE_FLAVOR      "angie"
#define NGX_TEST_PROBE_FLAVOR_VER  ANGIE_VERSION
#else
#define NGX_TEST_PROBE_FLAVOR      "nginx"
#define NGX_TEST_PROBE_FLAVOR_VER  NGINX_VERSION
#endif


/*
 * Digit limit for a fault_*= value.
 *
 * The counter it feeds is an nth-event index -- rules arm the 1st or 2nd
 * slab allocation -- so four digits is already far past anything meaningful,
 * while an unbounded accumulate overflows ngx_int_t and lands as an arbitrary
 * fault index instead of the refusal a caller expects for garbage.
 */
#define NGX_TEST_PROBE_FAULT_MAX_DIGITS  4


/*
 * The fault sites the probe knows how to arm.
 *
 * Fault injection is CONSUMER-DRIVEN: the probe recognises WHICH site a query
 * names and hands the parsed nth to the module's fault_set hook tagged with
 * that site, but the module owns every actual injection point. A module arms
 * only the sites it has wired up and returns NGX_DECLINED for the rest, so a
 * query naming a site the module does not implement is refused, not silently
 * dropped on the floor as if it took.
 *
 * WHY SIBLING KEYS (fault_slab=, fault_palloc=, ...) RATHER THAN ONE
 * fault_site=NAME:nth. The arm parser is a parser of attacker-shaped text and
 * its whole reason for existing is the boundary/digit-bound/malformed contract
 * around a single whole-query-arg match. A sibling key reuses that exact match
 * shape verbatim -- start-or-after-'&', value ends at the arg boundary -- so
 * every site inherits the same proven contract and is independently unit
 * testable against it. A single fault_site=NAME:nth would fold a second parser
 * (the NAME:nth split, its own boundary and malformed cases) inside the first,
 * multiplying the attacker-text surface the file was split out to keep small.
 *
 * The values are stable across builds only in that fault_slab stays first and
 * that new sites are APPENDED, never inserted; a consumer switches on the
 * enum, never on its integer value.
 */
typedef enum {
    NGX_TEST_PROBE_FAULT_SLAB = 0,   /* ngx_slab_alloc failure          */
    NGX_TEST_PROBE_FAULT_PALLOC,     /* ngx_palloc/ngx_pnalloc failure  */
    NGX_TEST_PROBE_FAULT_TEMPFILE,   /* temp-file creation failure      */
    NGX_TEST_PROBE_FAULT_ACCEPT,     /* accept() EMFILE                 */

    /*
     * Codec sites, for compression/decompression filter modules.
     *
     * Deliberately spelled for the LAYER, not for a library: every codec
     * module in the fleet -- gzip, brotli, zstd, and whatever comes next --
     * drives the same two-call shape, so a zstd-specific spelling would
     * force the next codec to add a third and fourth synonym for the same
     * two failure sites and leave the prober's rule vocabulary keyed to
     * whichever library happened to arrive first.
     *
     * CODEC covers the streaming body call (ZSTD_compressStream2 with a
     * continue op, deflate() with Z_NO_FLUSH, BrotliEncoderCompressStream);
     * CODEC_END covers the flush/end-of-frame call, which is a distinct
     * site because it runs on a different request path (the last buffer,
     * often after the body call already succeeded) and because a codec that
     * only fails on end-of-frame leaves a half-written body -- the bug
     * class the body-call site cannot reach.
     */
    NGX_TEST_PROBE_FAULT_CODEC,      /* streaming compress/decompress call */
    NGX_TEST_PROBE_FAULT_CODEC_END   /* flush / end-of-frame call          */
} ngx_test_probe_fault_e;


/*
 * Upper bound on the fixed part of the JSON document, before the zone name and
 * whatever the module hook appends. Rendering is ngx_slprintf-based and
 * truncates at `last` rather than overflowing, so this is a quality-of-output
 * bound, not a safety boundary -- but a truncated document fails to parse in
 * the prober, which reads as a broken probe rather than a silent wrong answer.
 */
#define NGX_TEST_PROBE_JSON_MAX  1024


/*
 * Zone-addressed module hooks. Both are optional; a module that registers
 * neither still gets the whole generic document (flavor, pid, connections,
 * fds, cycle-pool stats, and the zone's name/size/slab-page accounting),
 * which is enough for fd and memory leak assertions without a line of
 * module C.
 *
 * Both are handed the shm zone the probe was pointed at, and the probe skips
 * them when there is no zone (or its shm is not mapped yet), because they
 * exist to describe and to fault-inject SHARED state. A module with no shm
 * zone wants ngx_test_probe_module_hooks_t instead -- see below.
 *
 * THIS STRUCT IS FROZEN. New hooks go in the struct below, never here. Ten
 * consumer modules initialise this one POSITIONALLY (shield's
 * src/ngx_shield_probe_hooks.c:160 is `{ zone_render, fault_set }`), and
 * -Wmissing-field-initializers -- which -Wextra turns on, and which this
 * repo's own CI pairs with -Werror -- makes appending a member a BUILD
 * FAILURE in every one of those repos, not a silent zero-init. Verified by
 * compiling shield's initializer both ways, 2026-08-25.
 */
typedef struct {
    /*
     * Append this module's own zone members to the "zone" object, e.g.
     *
     *     ,"nodes":3,"banned":1
     *
     * Called with the zone the probe was pointed at, after the generic members
     * and inside the same object, so a leading comma is required and the
     * caller must NOT close the brace. Rendering must be ngx_slprintf-based
     * against `last`.
     *
     * The hook is responsible for its own locking. The probe does not hold the
     * slab mutex when it calls this: acquiring it here keeps the lock scope
     * honest and lets a module that keeps state outside the slab skip it.
     */
    u_char    *(*zone_render)(u_char *buf, u_char *last, ngx_shm_zone_t *zone);

    /*
     * Arm or clear fault injection for `fault` at nth (a negative value
     * disarms).
     *
     * The probe parses and validates the query argument and identifies which
     * fault site the query named; the module only stores the result for the
     * site it was handed, because where that counter lives (shm vs process
     * global) is a module decision with correctness consequences -- a counter
     * in a process global is armed in one worker and tripped in another.
     *
     * A module implements only the sites it has fault points for and returns
     * NGX_DECLINED for any other `fault` value: the same answer as "no fault
     * site at all", so a query naming an unimplemented site is refused rather
     * than reported applied. Returns NGX_OK if applied, NGX_DECLINED if this
     * module has no such fault site or the zone is not ready.
     */
    ngx_int_t  (*fault_set)(ngx_shm_zone_t *zone, ngx_test_probe_fault_e fault,
        ngx_int_t nth);
} ngx_test_probe_hooks_t;


/*
 * Register the module hooks. Call once, from module init or postconfiguration.
 * Passing NULL clears them. The last registration wins -- the probe serves one
 * module per binary by construction, since it is compiled into that module.
 */
void ngx_test_probe_register(const ngx_test_probe_hooks_t *hooks);


/*
 * Zone-INDEPENDENT module hooks: the path into the probe for a module that
 * has no shm zone at all.
 *
 * A body filter -- every compression module is one -- keeps every byte of its
 * state in the request pool and in per-worker globals. Under the zone-
 * addressed hooks alone such a module could register, compile, link and then
 * never be called once: ngx_test_probe_json()'s present:false early returns
 * fire before the zone_render dispatch, and ngx_test_probe_arm() used to
 * refuse outright on a NULL zone. Both are silent false greens -- the module
 * looks instrumented and asserts nothing -- which is why this exists.
 *
 * A SEPARATE STRUCT, not two more members on ngx_test_probe_hooks_t, and the
 * reason is a hard compatibility constraint rather than taste: existing
 * consumers initialise that struct positionally, and under
 * -Wextra -Werror (this repo's own CI settings) a new member there is a build
 * failure in ten downstream repos. A new struct with its own registration
 * function is additive by construction -- a module that never calls
 * ngx_test_probe_register_module() is byte-for-byte unaffected.
 *
 * Both members are optional, and a module with BOTH a zone and per-worker
 * state may register both structs.
 */
typedef struct {
    /*
     * Append this module's zone-independent members, e.g.
     *
     *     "frames":3,"flushes":1
     *
     * Rendered into a top-level "module" object of its own -- NOT into "zone"
     * -- so a document keeps saying what it means when a module has both a
     * zone and per-worker counters. The probe writes the object's braces and
     * calls this hook between them, so unlike zone_render there is NO leading
     * comma and the hook must not close the brace. A hook that writes nothing
     * yields "module":{}, which is a valid empty object rather than malformed
     * JSON.
     *
     * Called unconditionally when registered, before the zone object and
     * independently of whether a zone exists, which is the whole point: this
     * is the path a module with no shm zone has to the document. Rendering
     * must be bounded against `last`.
     *
     * The hook is responsible for its own locking; the probe holds no lock
     * when it calls this.
     */
    u_char    *(*module_render)(u_char *buf, u_char *last);

    /*
     * Arm or clear fault injection for `fault` at nth (a negative value
     * disarms), for a module whose fault counters do not live in a zone.
     *
     * Same contract as fault_set otherwise: the probe has already parsed and
     * validated the value and identified the site, the module stores it, and
     * a module returns NGX_DECLINED for any site it has no fault point for.
     *
     * DISPATCH ORDER, and why it is this way round. ngx_test_probe_arm() calls
     * fault_set when a zone is present and fault_set is registered; otherwise
     * it falls back to fault_set_global. So a zone-carrying module that
     * registers only fault_set behaves exactly as it did before this hook
     * existed, while a zoneless module -- which could not be armed AT ALL,
     * because arm() refused on zone == NULL before it ever reached a hook --
     * now has a path. A module that registers both gets the zone-addressed
     * hook whenever a zone is actually available, and the global one on the
     * zoneless probe endpoint.
     *
     * The counter this feeds is a per-worker global by construction (there is
     * no shared memory to put it in), so it is armed and tripped in the SAME
     * worker only. A test that arms through one connection and asserts through
     * another must pin itself to one worker (worker_processes 1, or a
     * keepalive connection) -- the same hazard fault_set's comment describes,
     * except here it is unavoidable rather than a module's choice.
     */
    ngx_int_t  (*fault_set_global)(ngx_test_probe_fault_e fault, ngx_int_t nth);
} ngx_test_probe_module_hooks_t;


/*
 * Register the zone-independent hooks. Call once, from module init or
 * postconfiguration; NULL clears them. Independent of
 * ngx_test_probe_register() in both directions -- registering one never
 * disturbs the other.
 */
void ngx_test_probe_register_module(const ngx_test_probe_module_hooks_t *hooks);


/*
 * Count one config load, and report how many have happened.
 *
 * Rendered as the top-level "config_generation" field. Its ONLY guaranteed
 * property is the one a reload gate needs: the value a worker reports is
 * strictly greater after a config load than before it. It is deliberately not
 * documented as "the cycle number" -- a consumer that calls the bump from
 * somewhere other than a config-load path gets a different absolute origin,
 * and no assertion should depend on the origin.
 *
 * WHY THIS IS NOT cycle->generation. Angie carries a uint64_t `generation` in
 * ngx_cycle_t (ngx_cycle.h) that nginx does not have at all -- reading it
 * would compile only against angie and make the field, and therefore any gate
 * built on it, silently absent on every nginx leg. The whole point of this
 * counter is to be available where the reload races actually get tested, so
 * the harness maintains its own rather than borrowing a field that exists on
 * one flavor.
 *
 * WHY A PROCESS GLOBAL IS SUFFICIENT, given fault_set's comment above warns
 * that a process global "is armed in one worker and tripped in another": the
 * hazard there is two DIFFERENT workers disagreeing about state written at
 * request time. This counter is written only by the MASTER, during config
 * load, strictly before it forks the workers of that cycle -- so every worker
 * inherits the finished value through fork() and they all agree by
 * construction. No shared memory, and no zone: the reference fixture module
 * deliberately configures none, and a reload gate that required one could not
 * run against it.
 *
 * The counter therefore does NOT survive a binary upgrade (execve replaces the
 * image, resetting it), which is correct for a SIGHUP gate and is why a USR2
 * state machine must use the pidfile/.oldbin observables instead.
 */
void ngx_test_probe_config_loaded(void);
ngx_uint_t ngx_test_probe_config_generation(void);


/*
 * Render the probe document into [buf, last) and return the end pointer.
 *
 * `zone` may be NULL, or may name a zone whose memory has not been allocated
 * yet; both are reported as "present": false rather than treated as errors, so
 * the prober can tell "no zone configured" from "zone empty".
 *
 * A registered module_render hook is dispatched into a top-level "module"
 * object BEFORE the zone object and regardless of which of those three zone
 * states holds -- a zoneless module's members are not conditional on a zone it
 * does not have. zone_render still runs only on the present:true path.
 *
 * Costs that only a test build may pay: a /proc/self/fd scan ("fds"), a walk of
 * the cycle pool's block chain ("pool.cycle_*"), and whatever the module hook
 * does under the slab mutex.
 *
 * "fds" is -1 where /proc is unavailable (non-Linux, or a sandbox without it)
 * or unreadable mid-scan. That sentinel is deliberate: a rule asserting on it
 * then fails loudly instead of comparing against a fabricated zero. Consumers
 * computing a DELTA must reject the sentinel explicitly -- -1 minus -1 is 0,
 * which looks exactly like a clean result.
 *
 * The resource-scoreboard additions share that discipline. "fds_by_kind"
 * (socket/file/anon/other) splits the same descriptor total by the kind read
 * from each /proc/self/fd link; every bucket is -1 together if the scan cannot
 * complete. "smaps" (pss, private_dirty, in kB from /proc/self/smaps_rollup)
 * gives external-observer memory lineage the cycle-pool walk cannot -- growth
 * in ANY mapping, not just the nginx pool -- and is -1 where smaps_rollup is
 * absent. "pool.cycle_cleanup" is the cleanup-handler chain length, naming a
 * cleanup parked on the cycle pool per request. The prober's delta/slope
 * oracles reject each -1 sentinel the same way they reject it for "fds".
 */
u_char *ngx_test_probe_json(u_char *buf, u_char *last, ngx_shm_zone_t *zone);


/*
 * Arm or clear fault injection from a query string, e.g.
 *
 *     GET /__probe?fault_slab=1      fail the next slab allocation
 *     GET /__probe?fault_slab=-1     disarm
 *     GET /__probe?fault_palloc=1    fail the next ngx_palloc/ngx_pnalloc
 *     GET /__probe?fault_tempfile=1  fail the next temp-file creation
 *     GET /__probe?fault_accept=1    return EMFILE from the next accept()
 *     GET /__probe?fault_codec=1     fail the next streaming compress call
 *     GET /__probe?fault_codec_end=1 fail the next flush/end-of-frame call
 *
 * Each site has its own sibling key (see ngx_test_probe_fault_e); the first
 * one present in the query wins. Returns NGX_OK if a fault directive was found
 * and applied, NGX_DECLINED otherwise -- including a malformed value, which is
 * ignored rather than guessed at, and including "no fault hook registered at
 * all" or "the module does not implement the named site".
 *
 * `zone` may be NULL. It is passed through to fault_set when both it and that
 * hook are present; otherwise the parsed site and nth go to fault_set_global,
 * which is how a module with no shm zone arms a fault. A query is refused
 * before parsing when neither hook is registered.
 *
 * Each key is matched as a whole query argument and the value must end at the
 * argument boundary, so neither "not_fault_slab=1" nor "fault_slab=1junk" arms
 * anything. Both of those armed the injector in an earlier version of this
 * code; the prober rule files pin them. The same contract holds for every
 * sibling key.
 *
 * A side effect on GET is not REST-clean, and that is a deliberate trade: the
 * alternative is reading a request body inside the probe handler, which means
 * the harness exercises a different nginx code path than the plain-GET
 * introspection it also has to serve.
 */
ngx_int_t ngx_test_probe_arm(ngx_shm_zone_t *zone, ngx_str_t *args);

/*
 * Escape `str` into a JSON string body written to [p, last), applying the
 * RFC 8259 short escapes (\", \\, \b, \f, \n, \r, \t) and \uXXXX for other C0
 * controls. Never writes a dangling escape byte: a two-byte short escape or a
 * six-byte \uXXXX escape is omitted whole when it would not fit before last.
 * Returns the new buffer position. Declared here (not just in
 * ngx_test_probe_arm.c) so probe_escape_json_string_test.c can call it
 * without pulling in the renderer's real-nginx dependencies.
 */
u_char *ngx_test_probe_escape_json_string(u_char *p, u_char *last,
    const ngx_str_t *str);

/*
 * Render the top-level "module" object into [p, last): the literal
 * `,"module":{`, whatever the registered module_render hook appends, then `}`.
 * Writes nothing at all when no module_render hook is registered, so the
 * document simply has no "module" member. Returns the new buffer position.
 *
 * Called by ngx_test_probe_json() before the zone object. It lives beside
 * ngx_test_probe_arm() in ngx_test_probe_arm.c rather than in the renderer for
 * the reason that whole file is split out: it depends on nothing but the hook
 * registry and the output bytes -- no ngx_cycle, no slab pool, no /proc -- so
 * it is reachable from the direct-call unit harness in t/. That reachability
 * is the point. The dispatch it performs is exactly the thing a zoneless
 * module's instrumentation hangs on, and a dispatch that is only exercised
 * through a configured server fails silently: the hook is registered, never
 * called, and the module looks instrumented while asserting nothing.
 *
 * Truncation is bounded, not safe-by-luck: each literal is written only when
 * it fits whole, so a short buffer yields a prefix, never a partial escape or
 * an out-of-bounds write. As everywhere else in the document, truncation
 * surfaces as a prober parse error.
 */
u_char *ngx_test_probe_render_module(u_char *p, u_char *last);


/*
 * ---------------------------------------------------------------------------
 * Pool redzones -- guard bytes around a pool allocation.
 * ---------------------------------------------------------------------------
 *
 * THE GAP THIS FILLS, AND WHY ASAN DOES NOT FILL IT
 *
 * ngx_palloc_small() is a bump allocator: it slices objects out of one large
 * block by advancing p->d.last, so a pool holding two hundred small objects is
 * ONE malloc'd allocation as far as AddressSanitizer is concerned. ASan's
 * redzones are at the two ends of that block; between the objects there is
 * nothing for it to poison. An overflow out of one small pool object into its
 * neighbour is therefore invisible to ASan, to LeakSanitizer and to valgrind
 * memcheck -- all three see one large, live, addressable, defined block.
 *
 * Demonstrated rather than assumed (2026-08-26, gcc 14 + ASan): a 4096-byte
 * block sliced into two 16-byte objects, the first memset to 32 bytes, exits
 * 0 with no diagnostic while the second object's contents are replaced.
 *
 * This is NOT an ASan replacement. It catches ONE class -- a linear overflow
 * out of a guarded object -- and it catches it at detection time (the next
 * check, or pool destruction), not at the faulting instruction. Where ASan can
 * see a bug at all it remains the better tool because it reports the write
 * itself. Run both; they overlap almost nowhere.
 *
 * NOT covered: use-after-free (a destroyed pool's blocks go back to libc where
 * ASan's quarantine already applies), overflow of a LARGE allocation
 * (ngx_palloc_large uses ngx_alloc, an ordinary malloc block ASan guards
 * already), and any over-READ that disturbs nothing.
 *
 * USAGE
 *
 * Route the allocations under test through ngx_test_probe_palloc() instead of
 * ngx_palloc(). Verification is automatic at pool destruction; a module may
 * also call ngx_test_probe_redzone_check() at any point for an earlier answer.
 * Violations are counted per worker and rendered as `redzone.violations`, so a
 * rule file asserts on them with an ordinary `probe` line:
 *
 *     probe  redzone.violations == 0
 *
 * ALIGNMENT -- the one sharp edge. The returned pointer is NOT aligned: the
 * padded block comes from ngx_pnalloc(), because an aligned allocation lets
 * nginx skip bytes between the previous object and this one, and an overflow
 * landing entirely in that skipped padding would go unreported. Immediate
 * adjacency to the neighbour is what makes the guard meaningful. That is the
 * ngx_pnalloc contract and it is correct for byte buffers; a caller wanting a
 * guarded struct must round its own size up itself.
 */

/*
 * Guard width, in bytes, on EACH side of the allocation.
 *
 * 16 rather than 8: the common overflow is a copy whose length was computed
 * wrong, and byte-count mistakes cluster at small powers of two and at the
 * width of a pointer or a length prefix. A 16-byte guard catches an 8-byte
 * overshoot whole, which a 8-byte guard would only catch if nothing else
 * happened to be written after it. Rather than 32+ because every guarded
 * allocation pays twice this in pool bytes, and pool growth is itself measured
 * by the delta oracles -- a fat guard would move the numbers those assert on.
 */
#define NGX_TEST_PROBE_REDZONE  16


/*
 * The three declarations taking an ngx_pool_t are gated on there BEING one.
 *
 * A real build always has it (ngx_core.h). The direct-call unit harness in t/
 * does not: t/ngx_shim.h is deliberately minimal and stubs no allocator, and
 * the suites built against it -- probe_arm_test, probe_escape_json_string_test
 * -- include this header. Declaring a function in terms of a type that
 * translation unit has never heard of is a hard error there, so the suites
 * that do not use redzones must not be made to pay for the ones that do.
 *
 * NGX_TEST_PROBE_POOL_SHIM is what t/ngx_pool_shim.h sets; NGX_CORE_H_INCLUDED_
 * is nginx's own guard, which is defined in every real build. The counters
 * below take no pool and stay unconditional.
 */
#if defined(_NGX_CORE_H_INCLUDED_) || defined(NGX_TEST_PROBE_POOL_SHIM)

/*
 * Guarded allocation. Returns a pointer to `size` usable bytes with a guard
 * on each side, or NULL -- on pool==NULL, on allocation failure, or when
 * `size` is within 2*NGX_TEST_PROBE_REDZONE of SIZE_MAX (the padded size would
 * wrap, and the guard writes would then scribble across the heap).
 *
 * A NULL return is an ordinary allocation failure and the caller must handle
 * it exactly as it would handle ngx_palloc() returning NULL. It is emphatically
 * not a violation report.
 */
void *ngx_test_probe_palloc(ngx_pool_t *pool, size_t size);


/*
 * Verify every guarded allocation in `pool` NOW, without waiting for the pool
 * to be destroyed. Returns the number of allocations with at least one
 * corrupted guard byte, and logs each at NGX_LOG_ALERT.
 *
 * Does not reset anything: the same corruption is reported again by the
 * cleanup handler at pool destruction, and counted once there. This is a
 * read-only early look, for a module that wants to localise a corruption to a
 * specific point in its own processing rather than to "somewhere in this
 * request".
 */
ngx_uint_t ngx_test_probe_redzone_check(ngx_pool_t *pool);

#endif /* pool type available */


/*
 * Cumulative counts for this worker, rendered as `redzone.violations` and
 * `redzone.checked`.
 *
 * `checked` exists to make `violations == 0` falsifiable. Zero violations out
 * of zero checked allocations is the vacuous pass this suite hunts: it is what
 * a consumer gets when it wires the header in but never actually routes an
 * allocation through ngx_test_probe_palloc(), and it is indistinguishable from
 * a clean run on the violations figure alone. An honest oracle asserts BOTH:
 *
 *     probe  redzone.checked    >  0
 *     probe  redzone.violations == 0
 */
ngx_uint_t ngx_test_probe_redzone_violations(void);
ngx_uint_t ngx_test_probe_redzone_checked(void);


/*
 * Zero both counters. For a test that wants a fresh origin mid-run; nothing in
 * the normal path calls it.
 */
void ngx_test_probe_redzone_reset(void);

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_TEST_PROBE_H_INCLUDED_ */
