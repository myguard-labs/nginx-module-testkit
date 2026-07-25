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
 * else, including the whole prober under prober/, is module-agnostic.
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
 * The values are stable across builds only in that fault_slab stays first; a
 * consumer switches on the enum, never on its integer value.
 */
typedef enum {
    NGX_TEST_PROBE_FAULT_SLAB = 0,   /* ngx_slab_alloc failure          */
    NGX_TEST_PROBE_FAULT_PALLOC,     /* ngx_palloc/ngx_pnalloc failure  */
    NGX_TEST_PROBE_FAULT_TEMPFILE,   /* temp-file creation failure      */
    NGX_TEST_PROBE_FAULT_ACCEPT      /* accept() EMFILE                 */
} ngx_test_probe_fault_e;


/*
 * Upper bound on the fixed part of the JSON document, before the zone name and
 * whatever the module hook appends. Rendering is ngx_slprintf-based and
 * truncates at `last` rather than overflowing, so this is a quality-of-output
 * bound, not a safety boundary -- but a truncated document fails to parse in
 * the prober, which reads as a broken probe rather than a silent wrong answer.
 */
#define NGX_TEST_PROBE_JSON_MAX  768


/*
 * Module-specific hooks. Both are optional; a module that registers neither
 * still gets the whole generic document (flavor, pid, connections, fds,
 * cycle-pool stats, and the zone's name/size/slab-page accounting), which is
 * enough for fd and memory leak assertions without a line of module C.
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
 * Costs that only a test build may pay: a /proc/self/fd scan ("fds"), a walk of
 * the cycle pool's block chain ("pool.cycle_*"), and whatever the module hook
 * does under the slab mutex.
 *
 * "fds" is -1 where /proc is unavailable (non-Linux, or a sandbox without it)
 * or unreadable mid-scan. That sentinel is deliberate: a rule asserting on it
 * then fails loudly instead of comparing against a fabricated zero. Consumers
 * computing a DELTA must reject the sentinel explicitly -- -1 minus -1 is 0,
 * which looks exactly like a clean result.
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
 *
 * Each site has its own sibling key (see ngx_test_probe_fault_e); the first
 * one present in the query wins. Returns NGX_OK if a fault directive was found
 * and applied, NGX_DECLINED otherwise -- including a malformed value, which is
 * ignored rather than guessed at, and including "no fault_set hook registered"
 * or "the module does not implement the named site".
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

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_TEST_PROBE_H_INCLUDED_ */
