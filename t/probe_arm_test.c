/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * probe_arm_test.c -- TAP self-test for the fault_*= query parser.
 *
 * ngx_test_probe_arm() is a parser of attacker-shaped text that arms a fault
 * injector at one of several sibling sites (fault_slab=, fault_palloc=,
 * fault_tempfile=, fault_accept=), and it had no tests. Four things about it
 * are easy to get subtly wrong and impossible to notice from a rule file that
 * passes:
 *
 *   1. The key must be a whole query argument. Matched as a substring,
 *      "not_fault_slab=1" arms the injector through a parameter nobody wrote --
 *      and a fault that fires on its own looks like a bug in the module under
 *      test, which is the most expensive kind of false signal a harness can
 *      produce.
 *
 *   2. Malformed input must be NGX_DECLINED, never a best guess. "fault_slab=1x"
 *      silently meaning 1 would arm a fault the rule author did not ask for.
 *
 *   3. The value must be bounded. An unbounded digit accumulate overflows
 *      ngx_int_t -- undefined behaviour, and in practice an arbitrary,
 *      possibly negative fault index.
 *
 *   4. The key must route to the right SITE. A parser that armed every query
 *      as the slab site regardless of key would misroute fault_palloc= and
 *      look correct to any value-only check.
 *
 * The zone pointer is passed straight through to the hook and never
 * dereferenced, so a tagged dummy address is enough to prove it arrives intact.
 */

#include "ngx_test_probe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bumped by hand: a vanished test should show up as a plan mismatch rather
 * than as a smaller green run. */
#define PLANNED  54

static int  tests_run = 0;
static int  failures = 0;

/* What the hook saw on the last call, and how many times it was called. */
static ngx_shm_zone_t         *seen_zone;
static ngx_int_t               seen_value;
static ngx_test_probe_fault_e  seen_fault;
static int                     calls;


static void
ok(int cond, const char *name)
{
    tests_run++;

    printf("%sok %d - %s\n", cond ? "" : "not ", tests_run, name);

    if (!cond) {
        failures++;
    }
}


static ngx_int_t
recording_fault_set(ngx_shm_zone_t *zone, ngx_test_probe_fault_e fault,
    ngx_int_t nth)
{
    calls++;
    seen_zone = zone;
    seen_fault = fault;
    seen_value = nth;

    return NGX_OK;
}


/* A distinct non-NULL address. Never dereferenced -- by the parser or here. */
static ngx_shm_zone_t *const  ZONE = (ngx_shm_zone_t *) 0x5a5a5a5a;


static ngx_int_t
arm(const char *query)
{
    ngx_str_t args;
    u_char    buf[256];
    size_t    len = strlen(query);

    /* ngx_str_t.data is u_char* by nginx ABI and cannot be made const, so the
     * query goes through a writable buffer instead of casting const off a
     * literal. The parser only reads, but the type says it may write, and the
     * test should hand it something it would legally be allowed to. */
    if (len >= sizeof(buf)) {
        printf("Bail out! query too long for the test buffer\n");
        exit(1);
    }

    memcpy(buf, query, len);
    args.data = buf;
    args.len = len;

    calls = 0;
    seen_zone = NULL;
    seen_value = -12345;
    seen_fault = (ngx_test_probe_fault_e) -1;

    return ngx_test_probe_arm(ZONE, &args);
}


/*
 * Declined, AND the hook was not reached.
 *
 * Checking the return value alone would miss the failure that matters: a parser
 * that calls fault_set() with a garbage value and then reports NGX_DECLINED has
 * already armed the injector. The refusal has to be a refusal to act.
 */
static void
declines(const char *query, const char *name)
{
    ngx_int_t rc = arm(query);
    int       good = (rc == NGX_DECLINED && calls == 0);

    if (!good) {
        printf("# %s: rc=%ld calls=%d value=%ld\n", name, (long) rc, calls,
               (long) seen_value);
    }

    ok(good, name);
}


/*
 * Accepted, and the hook received exactly this value, this site and this zone.
 *
 * The site is load-bearing: it proves the key-to-enum mapping in the parser's
 * table, not merely that some key matched. A parser that armed every query as
 * SLAB regardless of the key would pass a value-only check while silently
 * misrouting fault_palloc= to the slab site.
 */
static void
arms_site(const char *query, ngx_test_probe_fault_e site, ngx_int_t want,
    const char *name)
{
    ngx_int_t rc = arm(query);
    int       good = (rc == NGX_OK && calls == 1 && seen_value == want
                      && seen_fault == site && seen_zone == ZONE);

    if (!good) {
        printf("# %s: rc=%ld calls=%d value=%ld (want %ld) fault=%d (want %d) "
               "zone=%s\n", name, (long) rc, calls, (long) seen_value,
               (long) want, (int) seen_fault, (int) site,
               seen_zone == ZONE ? "ok" : "WRONG");
    }

    ok(good, name);
}


/* The slab site: the original tests all name it, so keep them terse. */
static void
arms_with(const char *query, ngx_int_t want, const char *name)
{
    arms_site(query, NGX_TEST_PROBE_FAULT_SLAB, want, name);
}


int
main(void)
{
    ngx_test_probe_hooks_t  hooks;

    printf("1..%d\n", PLANNED);

    /*
     * With no hook registered there is nothing to arm, and the parser must say
     * so before doing anything else -- including before deciding whether the
     * query is well formed. A module that never opted in cannot be armed by a
     * query.
     */
    memset(&hooks, 0, sizeof(hooks));
    ngx_test_probe_register(&hooks);

    declines("fault_slab=1", "a well-formed query declines with no hook");
    declines("garbage", "a malformed query declines with no hook");

    /* Now register for real. */
    hooks.fault_set = recording_fault_set;
    ngx_test_probe_register(&hooks);

    /* ---- the value arrives intact ------------------------------------- */

    arms_with("fault_slab=0", 0, "zero arms");
    arms_with("fault_slab=1", 1, "one arms");
    arms_with("fault_slab=7", 7, "a single digit arms");
    arms_with("fault_slab=42", 42, "two digits arm");
    arms_with("fault_slab=1000", 1000, "the largest allowed digit count arms");
    arms_with("fault_slab=-1", -1, "a negative value keeps its sign");
    arms_with("fault_slab=-0", 0, "negative zero is zero");

    /* ---- the key must be a whole query argument ----------------------- */

    arms_with("a=1&fault_slab=2", 2, "the key after an & is found");
    arms_with("fault_slab=3&b=1", 3, "the key before an & is found");
    arms_with("a=1&fault_slab=4&b=2", 4, "the key between two & is found");

    declines("not_fault_slab=1",
             "a key that is only a suffix does not arm");
    declines("xfault_slab=1",
             "a single junk byte before the key does not arm");
    declines("a=1&xfault_slab=2",
             "a suffix match after an & does not arm");
    declines("afault_slab=1&",
             "a suffix match before a trailing & does not arm");

    /*
     * A real occurrence later in the query must still be found even when an
     * earlier substring match was rejected -- otherwise the boundary check
     * would turn into a denial of the feature.
     */
    arms_with("xfault_slab=9&fault_slab=5", 5,
              "a real key after a rejected substring match is still found");

    /* ---- malformed values decline rather than guess -------------------- */

    declines("fault_slab=", "an empty value does not arm");
    declines("fault_slab=&x=1", "an empty value before an & does not arm");
    declines("fault_slab=-", "a lone minus does not arm");
    declines("fault_slab=-&x=1", "a lone minus before an & does not arm");
    declines("fault_slab=1x", "a trailing letter does not arm");
    declines("fault_slab=1 ", "a trailing space does not arm");
    declines("fault_slab=+1", "a leading plus does not arm");
    declines("fault_slab= 1", "a leading space does not arm");
    declines("fault_slab=1.5", "a fraction does not arm");
    declines("fault_slab=--1", "a doubled minus does not arm");
    declines("fault_slab=1-2", "an embedded minus does not arm");
    declines("fault_slab=abc", "letters do not arm");

    /* ---- the digit bound ---------------------------------------------- */

    /*
     * Unbounded, this accumulate overflows ngx_int_t, which is undefined
     * behaviour and in practice yields an arbitrary -- possibly negative --
     * fault index. Under the UBSan leg of CI an unbounded version aborts here
     * rather than returning anything at all.
     */
    declines("fault_slab=99999", "one digit past the bound does not arm");
    declines("fault_slab=99999999999999999999999",
             "a value that would overflow ngx_int_t does not arm");
    declines("fault_slab=-99999999999999999999999",
             "a negative overflowing value does not arm");
    declines("fault_slab=00000", "leading zeros still count as digits");

    /* ---- degenerate inputs -------------------------------------------- */

    declines("", "an empty query does not arm");
    declines("fault_slab", "the bare key with no '=' does not arm");

    {
        /* args shorter than the key: the length guard must catch this before
         * any comparison reads past the end. */
        ngx_str_t short_args;
        ngx_int_t rc;
        u_char    short_buf[1] = { 'f' };

        short_args.data = short_buf;
        short_args.len = 1;
        calls = 0;

        rc = ngx_test_probe_arm(ZONE, &short_args);
        ok(rc == NGX_DECLINED && calls == 0,
           "a query shorter than the key does not arm");
    }

    /* ---- the sibling fault sites -------------------------------------- */

    /*
     * Each new site gets the same five checks as fault_slab plus a routing
     * check: valid arm (routed to the right enum), disarm via a negative,
     * whole-arg boundary reject, trailing-junk reject, digit-overflow reject.
     * The routing assertion (arms_site's site check) is what proves the key
     * table maps fault_palloc= to PALLOC and not to SLAB.
     */

    arms_site("fault_palloc=1", NGX_TEST_PROBE_FAULT_PALLOC, 1,
              "fault_palloc arms and routes to the palloc site");
    arms_site("fault_palloc=-1", NGX_TEST_PROBE_FAULT_PALLOC, -1,
              "fault_palloc disarms with a negative value");
    declines("not_fault_palloc=1",
             "a suffix of fault_palloc does not arm");
    declines("fault_palloc=1junk",
             "fault_palloc with trailing junk does not arm");
    declines("fault_palloc=99999",
             "fault_palloc one digit past the bound does not arm");

    arms_site("fault_tempfile=2", NGX_TEST_PROBE_FAULT_TEMPFILE, 2,
              "fault_tempfile arms and routes to the tempfile site");
    arms_site("fault_tempfile=-1", NGX_TEST_PROBE_FAULT_TEMPFILE, -1,
              "fault_tempfile disarms with a negative value");
    declines("not_fault_tempfile=1",
             "a suffix of fault_tempfile does not arm");
    declines("fault_tempfile=1junk",
             "fault_tempfile with trailing junk does not arm");
    declines("fault_tempfile=99999",
             "fault_tempfile one digit past the bound does not arm");

    arms_site("fault_accept=3", NGX_TEST_PROBE_FAULT_ACCEPT, 3,
              "fault_accept arms and routes to the accept site");
    arms_site("fault_accept=-1", NGX_TEST_PROBE_FAULT_ACCEPT, -1,
              "fault_accept disarms with a negative value");
    declines("not_fault_accept=1",
             "a suffix of fault_accept does not arm");
    declines("fault_accept=1junk",
             "fault_accept with trailing junk does not arm");
    declines("fault_accept=99999",
             "fault_accept one digit past the bound does not arm");

    /* A sibling key is found after an '&' just like fault_slab, and still
     * routes to its own site -- the boundary logic is shared, the routing is
     * not. */
    arms_site("a=1&fault_accept=4", NGX_TEST_PROBE_FAULT_ACCEPT, 4,
              "a sibling key after an & is found and routes correctly");

    /* fault_palloc is not a prefix of any other key, but guard the reverse:
     * fault_slab must not be matched by fault_palloc's presence, and vice
     * versa -- each key stands alone. */
    arms_site("fault_palloc=5&fault_slab=6", NGX_TEST_PROBE_FAULT_PALLOC, 5,
              "the earliest sibling key wins over a later one");

    /* A malformed value at the earliest matching key declines outright; it does
     * NOT fall through to a well-formed later sibling. Pins the "malformed
     * declines rather than guesses" contract against an accidental fall-through
     * that would silently arm a site the query's first arg did not name. */
    declines("fault_palloc=x&fault_slab=1",
             "a malformed earlier sibling declines despite a well-formed later one");

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
