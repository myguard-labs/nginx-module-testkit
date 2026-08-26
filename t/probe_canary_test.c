/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * probe_canary_test.c -- TAP tests for ngx_test_probe_canary.c.
 *
 * As in probe_redzone_test.c, the load-bearing test is the VACUITY PROOF, and
 * here it has two halves because the slab defeats the sanitizers twice over:
 *
 *   1. A shm zone is one mmap, so ASan sees a single region with no per-chunk
 *      boundaries. An overflow from one chunk into the next is invisible.
 *
 *   2. The slab rounds a request UP TO A POWER OF TWO, so a 20-byte request
 *      gets a 32-byte chunk. Writing 24 bytes into that 20-byte allocation
 *      stays inside the chunk the allocator handed out -- so even an allocator
 *      that DID check its own bounds would see nothing wrong. That slack is
 *      the specific reason the guard is placed at the caller's requested size.
 *
 * Both halves run under -fsanitize=address,undefined and both must stay green
 * (i.e. must keep demonstrating that the tools say nothing). If either ever
 * fails, the corresponding justification needs revisiting -- the correct
 * outcome, not a nuisance.
 */

#include "ngx_pool_shim.h"
#include "ngx_test_probe.h"

int   ngx_shim_log_count = 0;
char  ngx_shim_log_last[512];

static int  tests_run = 0;
static int  failures = 0;

static void
ok(int cond, const char *name)
{
    tests_run++;
    if (cond) {
        printf("ok %d - %s\n", tests_run, name);
    } else {
        failures++;
        printf("not ok %d - %s\n", tests_run, name);
    }
}


/*
 * A guarded allocation the test cannot continue without. Same reasoning as
 * probe_redzone_test.c's must_alloc: every case below dereferences what it
 * allocates, an unchecked NULL would be undefined behaviour, and returning
 * early would desynchronise the TAP plan from the assertions actually run.
 */
static u_char *
must_alloc(ngx_slab_pool_t *pool, size_t size)
{
    u_char  *p;

    p = ngx_test_probe_slab_alloc(pool, size);

    if (p == NULL) {
        printf("Bail out! the %zu-byte guarded slab allocation the harness "
               "itself needs failed\n", size);
        exit(1);
    }

    return p;
}


/*
 * Test 1 -- VACUITY PROOF, half one: adjacency inside one mapping.
 */
static void
test_sanitizers_are_blind_to_intra_slab_overflow(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a, *b;

    pool = ngx_slab_pool_shim_create(65536);

    a = ngx_slab_alloc(pool, 16);
    b = ngx_slab_alloc(pool, 16);

    ngx_memset(b, 'B', 16);
    ngx_memset(a, 'A', 32);          /* 32 into a 16-byte chunk */

    ok(b == a + 16, "two unguarded slab chunks are adjacent in one mapping");
    ok(b[0] == 'A',
       "VACUITY PROOF: the overflow corrupted the neighbouring chunk and "
       "neither ASan nor the allocator said a word");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 2 -- VACUITY PROOF, half two: the power-of-two slack.
 *
 * This is the half that is specific to slab and has no pool equivalent. A
 * 20-byte request is served from a 32-byte chunk; writing 24 bytes overflows
 * the ALLOCATION while staying inside the CHUNK. No allocator-level bounds
 * check, however careful, could ever notice.
 */
static void
test_power_of_two_slack_hides_an_overflow(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a, *b;

    pool = ngx_slab_pool_shim_create(65536);

    a = ngx_slab_alloc(pool, 20);    /* served from a 32-byte chunk */
    b = ngx_slab_alloc(pool, 16);

    ok(b == a + 32,
       "a 20-byte request really was rounded up to a 32-byte chunk");

    ngx_memset(a, 'A', 24);          /* past the request, inside the chunk */

    ok(b[0] != 'A',
       "VACUITY PROOF: writing 24 bytes into a 20-byte allocation disturbs "
       "nothing the allocator owns -- the overflow hides in the slack");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 3 -- the same slack overflow, guarded, is caught.
 *
 * The pair with test 2 is the whole argument for placing the guard at the
 * caller's size rather than at the chunk boundary.
 */
static void
test_guard_catches_the_slack_overflow(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a;

    ngx_test_probe_canary_reset();
    ngx_shim_log_count = 0;

    pool = ngx_slab_pool_shim_create(65536);

    a = must_alloc(pool, 20);

    ok(ngx_test_probe_canary_check(a, NULL) == 0,
       "an untouched guarded chunk reports no violation");

    ngx_memset(a, 'A', 24);          /* the overflow test 2 could not see */

    ok(ngx_test_probe_canary_check(a, NULL) == 1,
       "the slack overflow IS caught once the chunk is guarded");
    ok(ngx_shim_log_count > 0, "the violation is logged, not merely counted");
    ok(strstr(ngx_shim_log_last, "SLAB OVERFLOW") != NULL,
       "the log names the direction");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 4 -- freed memory is poisoned.
 *
 * The capability the pool redzone cannot offer, because a pool has no
 * per-object free. This does not DETECT the use-after-free -- nothing here
 * can -- it makes the result unmistakable rather than plausible stale data.
 */
static void
test_free_poisons_the_chunk(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a;

    ngx_test_probe_canary_reset();

    pool = ngx_slab_pool_shim_create(65536);

    a = must_alloc(pool, 16);
    ngx_memset(a, 'A', 16);

    ok(a[0] == 'A' && a[15] == 'A', "the chunk holds the caller's data");

    ngx_test_probe_slab_free(pool, a, NULL);

    ok(a[0] == 0xFE && a[15] == 0xFE,
       "after free the span reads as poison, not as plausible stale data");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 5 -- a double free is refused rather than corrupting the zone.
 *
 * The second free finds the magic cleared. Without that check it would compute
 * a header inside another chunk and poison whatever `size` it found there --
 * destroying live shared memory in the name of checking it.
 */
static void
test_double_free_is_refused(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a;

    ngx_test_probe_canary_reset();
    ngx_shim_log_count = 0;

    pool = ngx_slab_pool_shim_create(65536);

    a = must_alloc(pool, 16);

    ok(ngx_test_probe_slab_free(pool, a, NULL) == 0, "the first free is clean");
    ok(ngx_test_probe_slab_free(pool, a, NULL) == 1, "the second is refused");
    ok(ngx_test_probe_canary_violations_get() == 1,
       "and is counted as a violation, not silently tolerated");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 6 -- freeing a pointer this probe never handed out is refused.
 *
 * A mismatched alloc/free pair is a real defect in the module under test, and
 * this is the check that stops it destroying the zone on the way through.
 */
static void
test_foreign_pointer_is_refused(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *foreign;

    ngx_test_probe_canary_reset();

    pool = ngx_slab_pool_shim_create(65536);

    /* A plain slab chunk, well past the header the free path would read. */
    foreign = ngx_slab_alloc(pool, 64);
    ngx_memset(foreign, 'Z', 64);

    ok(ngx_test_probe_slab_free(pool, foreign + 32, NULL) == 1,
       "a pointer this probe did not allocate is refused");
    ok(ngx_test_probe_canary_violations_get() == 1,
       "and counted -- a mismatched alloc/free pair is a defect, not noise");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 7 -- the live counter is a leak oracle.
 */
static void
test_live_counter_tracks_outstanding(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a, *b;

    ngx_test_probe_canary_reset();

    pool = ngx_slab_pool_shim_create(65536);

    ok(ngx_test_probe_canary_live_get() == 0, "nothing outstanding at rest");

    a = must_alloc(pool, 16);
    b = must_alloc(pool, 16);

    ok(ngx_test_probe_canary_live_get() == 2, "two allocations outstanding");

    ngx_test_probe_slab_free(pool, a, NULL);

    ok(ngx_test_probe_canary_live_get() == 1,
       "freeing one leaves one outstanding -- the leak oracle at rest");

    ngx_test_probe_slab_free(pool, b, NULL);

    ok(ngx_test_probe_canary_live_get() == 0, "and back to zero when balanced");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 8 -- a clean run is distinguishable from a run that never happened.
 */
static void
test_clean_run_is_distinguishable_from_no_run(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a;

    ngx_test_probe_canary_reset();

    ok(ngx_test_probe_canary_checked_get() == 0,
       "a fresh worker has checked nothing");

    pool = ngx_slab_pool_shim_create(65536);
    a = must_alloc(pool, 32);
    ngx_memset(a, 'A', 32);          /* exactly in bounds */
    ngx_test_probe_slab_free(pool, a, NULL);

    ok(ngx_test_probe_canary_violations_get() == 0, "a clean run has no violation");
    ok(ngx_test_probe_canary_checked_get() == 1,
       "...and a nonzero checked count, which is what proves it ran at all");

    ngx_slab_pool_shim_destroy(pool);
}


/*
 * Test 9 -- boundary and rejection cases.
 */
static void
test_bounds_and_rejections(void)
{
    ngx_slab_pool_t  *pool;
    u_char           *a;

    ngx_test_probe_canary_reset();

    pool = ngx_slab_pool_shim_create(65536);

    a = must_alloc(pool, 16);
    a[0] = 'A';
    a[15] = 'A';                     /* last legal byte */

    ok(ngx_test_probe_canary_check(a, NULL) == 0,
       "writing the first and last in-bounds bytes is not a violation");

    a[16] = 'A';                     /* first illegal byte */

    ok(ngx_test_probe_canary_check(a, NULL) == 1,
       "one byte past the request IS a violation, even inside the chunk");

    ok(ngx_test_probe_slab_alloc(pool, (size_t) -1) == NULL,
       "SIZE_MAX is rejected rather than wrapped");
    ok(ngx_test_probe_slab_alloc(NULL, 16) == NULL, "a NULL pool is rejected");

    ngx_slab_pool_shim_destroy(pool);
}


int
main(void)
{
    printf("1..26\n");

    test_sanitizers_are_blind_to_intra_slab_overflow();
    test_power_of_two_slack_hides_an_overflow();
    test_guard_catches_the_slack_overflow();
    test_free_poisons_the_chunk();
    test_double_free_is_refused();
    test_foreign_pointer_is_refused();
    test_live_counter_tracks_outstanding();
    test_clean_run_is_distinguishable_from_no_run();
    test_bounds_and_rejections();

    if (tests_run != 26) {
        printf("# plan said 26, ran %d\n", tests_run);
        return 1;
    }

    return failures > 0 ? 1 : 0;
}
