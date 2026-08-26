/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * probe_redzone_test.c -- TAP tests for ngx_test_probe_redzone.c.
 *
 * The headline test here is not "does the detector fire". It is the VACUITY
 * PROOF: an identical overflow, through a plain pool allocation, is caught by
 * NOTHING -- not by this test binary's own AddressSanitizer, not by valgrind.
 * That control is what establishes the detector is worth its cost. Without it
 * a reader is entitled to assume ASan already covered this and the file is
 * redundant, which is exactly what a reasonable reviewer assumed when the idea
 * was first raised.
 *
 * Build (see t/Makefile.redzone or ci/prober/test.sh):
 *   cc -DNGX_TEST_HARNESS -I t -I src -fsanitize=address,undefined ...
 *
 * Running it under ASan is deliberate and is the whole point of test 1: the
 * suite asserts that ASan stays silent on the unguarded case while this file's
 * own checker catches it. If ASan ever does learn to catch intra-pool
 * overflows, test 1 fails loudly and this file's justification needs revisiting
 * -- which is the correct outcome, not a nuisance.
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
 * A guarded allocation the test cannot continue without.
 *
 * Every case below dereferences what it allocates, and passing NULL to memset
 * is undefined behaviour -- so an unchecked NULL would turn one honest failure
 * into a crash, or into whatever the optimiser decides UB permits. Returning
 * early instead would desynchronise the TAP plan from the assertions actually
 * run, which this repo treats as its own defect class (a suite can exit
 * nonzero with every assertion green and no `not ok` line to grep for).
 *
 * These pools are 4096 bytes from malloc and the requests are tens of bytes,
 * so a failure here is a broken harness rather than a property of the code
 * under test. Bail out! is the honest TAP verdict for that: it says the run
 * did not happen, rather than reporting a pass or a fail that was never
 * measured.
 */
static u_char *
must_alloc(ngx_pool_t *pool, size_t size)
{
    u_char  *p;

    p = ngx_test_probe_palloc(pool, size);

    if (p == NULL) {
        printf("Bail out! the %zu-byte guarded allocation the harness itself "
               "needs failed\n", size);
        exit(1);
    }

    return p;
}


/*
 * Test 1 -- THE VACUITY PROOF.
 *
 * Two adjacent unguarded pool objects; the first is overrun into the second.
 * This is byte-for-byte the corruption test 2 catches, and here nothing
 * notices: the process does not trap, ASan prints nothing, and the only
 * evidence is that the second object's contents changed.
 *
 * If this test ever fails by crashing or by ASan aborting, that is the signal
 * that the gap closed and this whole file should be re-justified.
 */
static void
test_asan_is_blind_to_intra_pool_overflow(void)
{
    ngx_pool_t  *pool;
    u_char      *a, *b;

    pool = ngx_create_pool_shim(4096);

    a = ngx_pnalloc(pool, 16);
    b = ngx_pnalloc(pool, 16);

    ngx_memset(b, 'B', 16);
    ngx_memset(a, 'A', 32);          /* 32 into a 16-byte object */

    ok(b == a + 16, "the two pool objects really are adjacent");
    ok(b[0] == 'A', "VACUITY PROOF: the overflow corrupted the neighbour and "
                    "neither ASan nor the allocator said a word");

    ngx_destroy_pool_shim(pool);
}


/*
 * Test 2 -- the same overflow, guarded, is caught and reported.
 */
static void
test_overflow_is_caught(void)
{
    ngx_pool_t  *pool;
    u_char      *a;

    ngx_test_probe_redzone_reset();
    ngx_shim_log_count = 0;

    pool = ngx_create_pool_shim(4096);

    a = must_alloc(pool, 16);

    /* The guards are real bytes in the pool, not bookkeeping: the object must
     * sit exactly NGX_TEST_PROBE_REDZONE bytes into the padded allocation.
     * Asserting `a != NULL` here would be vacuous -- must_alloc() has already
     * bailed out if it were. */
    ok(a[-1] == (u_char) 0xDB && a[16] == (u_char) 0xDB,
       "the allocation is bracketed by guard bytes on both sides");

    ok(ngx_test_probe_redzone_check(pool) == 0,
       "an untouched guarded allocation reports no violation");

    ngx_memset(a, 'A', 32);          /* the same 16-byte overflow as test 1 */

    ok(ngx_test_probe_redzone_check(pool) == 1,
       "the overflow IS caught once the allocation is guarded");
    ok(ngx_shim_log_count > 0, "the violation is logged, not merely counted");
    ok(strstr(ngx_shim_log_last, "OVERFLOW") != NULL,
       "the log names the direction (OVERFLOW)");

    ngx_destroy_pool_shim(pool);
}


/*
 * Test 3 -- underflow, the other direction.
 *
 * A write BEFORE the object is the rarer half, and the one a single trailing
 * guard would miss entirely. Worth its own case because the natural
 * implementation shortcut -- one guard, after the object -- passes every
 * overflow test while catching none of these.
 */
static void
test_underflow_is_caught(void)
{
    ngx_pool_t  *pool;
    u_char      *a;

    ngx_test_probe_redzone_reset();
    ngx_shim_log_count = 0;

    pool = ngx_create_pool_shim(4096);

    a = must_alloc(pool, 16);

    a[-1] = 'X';
    a[-4] = 'X';

    ok(ngx_test_probe_redzone_check(pool) == 1, "an underflow is caught");
    ok(strstr(ngx_shim_log_last, "UNDERFLOW") != NULL,
       "the log names the direction (UNDERFLOW)");

    ngx_destroy_pool_shim(pool);
}


/*
 * Test 4 -- the pool-destruction path counts the violation.
 *
 * A module that never calls the check explicitly must still be caught, because
 * a check that depends on being remembered is a check that stops running. The
 * cleanup handler is what makes the guarantee unconditional.
 */
static void
test_cleanup_counts_violations(void)
{
    ngx_pool_t  *pool;
    u_char      *a;

    ngx_test_probe_redzone_reset();

    pool = ngx_create_pool_shim(4096);
    a = must_alloc(pool, 16);
    ngx_memset(a, 'A', 24);

    ok(ngx_test_probe_redzone_violations() == 0,
       "nothing is counted before the pool is destroyed");

    ngx_destroy_pool_shim(pool);

    ok(ngx_test_probe_redzone_violations() == 1,
       "pool destruction counts the violation without an explicit check");
    ok(ngx_test_probe_redzone_checked() == 1,
       "and counts the allocation as checked");
}


/*
 * Test 5 -- a clean run counts checked allocations but no violations.
 *
 * This is the pair that makes `redzone.violations == 0` falsifiable. Zero
 * violations out of zero checked is the vacuous pass; the `checked` counter is
 * what lets a rule file tell the two apart.
 */
static void
test_clean_run_is_distinguishable_from_no_run(void)
{
    ngx_pool_t  *pool;
    u_char      *a;

    ngx_test_probe_redzone_reset();

    ok(ngx_test_probe_redzone_checked() == 0,
       "a fresh worker has checked nothing");

    pool = ngx_create_pool_shim(4096);
    a = must_alloc(pool, 32);
    ngx_memset(a, 'A', 32);          /* exactly in bounds */
    ngx_destroy_pool_shim(pool);

    ok(ngx_test_probe_redzone_violations() == 0, "a clean run has no violation");
    ok(ngx_test_probe_redzone_checked() == 1,
       "...and a nonzero checked count, which is what proves it ran at all");
}


/*
 * Test 6 -- writing exactly to the boundary is not a violation.
 *
 * The off-by-one in the DETECTOR is as damaging as the one it hunts: a
 * detector that fires on correct code gets disabled. Both edges are pinned.
 */
static void
test_exact_bounds_are_not_a_violation(void)
{
    ngx_pool_t  *pool;
    u_char      *a;

    ngx_test_probe_redzone_reset();

    pool = ngx_create_pool_shim(4096);

    a = must_alloc(pool, 16);
    a[0] = 'A';
    a[15] = 'A';                     /* last legal byte */

    ok(ngx_test_probe_redzone_check(pool) == 0,
       "writing the first and last in-bounds bytes is not a violation");

    a[16] = 'A';                     /* first illegal byte */

    ok(ngx_test_probe_redzone_check(pool) == 1,
       "one byte past the end IS a violation");

    ngx_destroy_pool_shim(pool);
}


/*
 * Test 7 -- the size-overflow guard.
 *
 * A size within 2*REDZONE of SIZE_MAX would wrap when padded, and the guard
 * memsets would then run off the end of a tiny allocation. That would make
 * this file the memory-safety bug it exists to find, so the rejection is
 * pinned rather than trusted.
 */
static void
test_size_overflow_is_rejected(void)
{
    ngx_pool_t  *pool;

    pool = ngx_create_pool_shim(4096);

    ok(ngx_test_probe_palloc(pool, (size_t) -1) == NULL,
       "SIZE_MAX is rejected rather than wrapped");
    ok(ngx_test_probe_palloc(pool, (size_t) -NGX_TEST_PROBE_REDZONE) == NULL,
       "a size just inside the wrap boundary is rejected too");
    ok(ngx_test_probe_palloc(NULL, 16) == NULL, "a NULL pool is rejected");

    ngx_destroy_pool_shim(pool);
}


/*
 * Test 8 -- allocation failure is reported as failure, not as a violation.
 *
 * A full pool must return NULL. Reporting that as a corrupted guard would send
 * a consumer hunting a memory bug that never happened.
 */
static void
test_allocation_failure_is_not_a_violation(void)
{
    ngx_pool_t  *pool;

    ngx_test_probe_redzone_reset();

    pool = ngx_create_pool_shim(64);

    ok(ngx_test_probe_palloc(pool, 4096) == NULL,
       "an oversized request fails rather than overrunning the pool");
    ok(ngx_test_probe_redzone_violations() == 0,
       "a failed allocation is not counted as a violation");

    ngx_destroy_pool_shim(pool);
}


int
main(void)
{
    printf("1..22\n");

    test_asan_is_blind_to_intra_pool_overflow();
    test_overflow_is_caught();
    test_underflow_is_caught();
    test_cleanup_counts_violations();
    test_clean_run_is_distinguishable_from_no_run();
    test_exact_bounds_are_not_a_violation();
    test_size_overflow_is_rejected();
    test_allocation_failure_is_not_a_violation();

    if (tests_run != 22) {
        printf("# plan said 22, ran %d\n", tests_run);
        return 1;
    }

    return failures > 0 ? 1 : 0;
}
