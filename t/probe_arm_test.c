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
 *
 * It also covers the zone-INDEPENDENT half of the hook contract, added
 * 2026-08-25. Two defects made the probe unusable from a module with no shm
 * zone -- every compression body filter -- and both were silent false greens
 * rather than failures: arm() refused on zone == NULL before reaching any
 * hook, and the renderer's present:false early returns fired before the only
 * render dispatch there was. A module could register hooks, compile, link and
 * never be called once, looking instrumented while asserting nothing. The
 * assertions below therefore check that a hook RAN and what it received, not
 * merely a return code -- a rc-only check passes against both defects.
 *
 * ngx_test_probe_render_module() is reachable here at all because it was
 * placed in ngx_test_probe_arm.c rather than in the renderer: a dispatch
 * exercised only through a configured server fails in exactly the silent way
 * this suite exists to prevent.
 */

#include "ngx_test_probe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bumped by hand: a vanished test should show up as a plan mismatch rather
 * than as a smaller green run. */
#define PLANNED  88

static int  tests_run = 0;
static int  failures = 0;

/* What the hook saw on the last call, and how many times it was called. */
static ngx_shm_zone_t         *seen_zone;
static ngx_int_t               seen_value;
static ngx_test_probe_fault_e  seen_fault;
static int                     calls;

/* The zone-independent fault hook records into its own slots, so a test can
 * tell WHICH family was dispatched -- the whole point of the fallback. */
static ngx_int_t               g_seen_value;
static ngx_test_probe_fault_e  g_seen_fault;
static int                     g_calls;


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


static ngx_int_t
recording_fault_set_global(ngx_test_probe_fault_e fault, ngx_int_t nth)
{
    g_calls++;
    g_seen_fault = fault;
    g_seen_value = nth;

    return NGX_OK;
}


/* Renders a fixed two-member fragment, and records that it ran at all. The
 * "did it run" half is the assertion that matters: a dispatch that is skipped
 * is exactly the F1 defect, and a byte comparison alone could be satisfied by
 * a buffer that was never touched. */
static int  render_calls;

static u_char *
recording_module_render(u_char *buf, u_char *last)
{
    static const char  frag[] = "\"frames\":3";

    render_calls++;

    if ((size_t) (last - buf) < sizeof(frag) - 1) {
        return buf;
    }

    memcpy(buf, frag, sizeof(frag) - 1);

    return buf + sizeof(frag) - 1;
}


/* A misbehaving hook: returns a pointer BEHIND the one it was handed, which
 * means it has scribbled over the opening literal. The probe cannot salvage
 * that and must abandon the whole object rather than close a malformed one. */
static u_char *
rewinding_module_render(u_char *buf, u_char *last)
{
    (void) last;

    render_calls++;

    return buf - 3;
}


/* A registered hook that legitimately has nothing to say this call. */
static u_char *
silent_module_render(u_char *buf, u_char *last)
{
    (void) last;

    return buf;
}


/* A distinct non-NULL address. Never dereferenced -- by the parser or here. */
static ngx_shm_zone_t *const  ZONE = (ngx_shm_zone_t *) 0x5a5a5a5a;


static ngx_int_t
arm_zone(ngx_shm_zone_t *zone, const char *query)
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
    g_calls = 0;
    g_seen_value = -12345;
    g_seen_fault = (ngx_test_probe_fault_e) -1;

    return ngx_test_probe_arm(zone, &args);
}


/* The overwhelming majority of cases arm through a zone; keep them terse. */
static ngx_int_t
arm(const char *query)
{
    return arm_zone(ZONE, query);
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
    ngx_test_probe_hooks_t         hooks;
    ngx_test_probe_module_hooks_t  mhooks;

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

    /* ---- F2: the codec sites ------------------------------------------ */

    /*
     * Same five checks per site as every other sibling, plus the pair that is
     * specific to these two: fault_codec= and fault_codec_end= share a prefix
     * up to the '=', so a table that matched on the bare name rather than on
     * the key-with-'=' would route fault_codec_end= to CODEC. Both directions
     * are asserted, because only one of them is caught by a value check.
     */

    arms_site("fault_codec=1", NGX_TEST_PROBE_FAULT_CODEC, 1,
              "fault_codec arms and routes to the codec site");
    arms_site("fault_codec=-1", NGX_TEST_PROBE_FAULT_CODEC, -1,
              "fault_codec disarms with a negative value");
    declines("not_fault_codec=1",
             "a suffix of fault_codec does not arm");
    declines("fault_codec=1junk",
             "fault_codec with trailing junk does not arm");
    declines("fault_codec=99999",
             "fault_codec one digit past the bound does not arm");

    arms_site("fault_codec_end=2", NGX_TEST_PROBE_FAULT_CODEC_END, 2,
              "fault_codec_end arms and routes to the codec_end site");
    arms_site("fault_codec_end=-1", NGX_TEST_PROBE_FAULT_CODEC_END, -1,
              "fault_codec_end disarms with a negative value");
    declines("not_fault_codec_end=1",
             "a suffix of fault_codec_end does not arm");
    declines("fault_codec_end=1junk",
             "fault_codec_end with trailing junk does not arm");
    declines("fault_codec_end=99999",
             "fault_codec_end one digit past the bound does not arm");

    /*
     * The prefix discrimination, both ways. "fault_codec_end=2" must NOT be
     * seen as fault_codec= (which would route to CODEC and, worse, then find
     * the value "_end=2" malformed and decline the whole query), and
     * "fault_codec=1" must not be seen as fault_codec_end=.
     */
    arms_site("fault_codec_end=7", NGX_TEST_PROBE_FAULT_CODEC_END, 7,
              "fault_codec_end is not matched as fault_codec with junk");
    arms_site("a=1&fault_codec=8", NGX_TEST_PROBE_FAULT_CODEC, 8,
              "fault_codec after an & is found and routes correctly");
    arms_site("fault_codec=9&fault_codec_end=10",
              NGX_TEST_PROBE_FAULT_CODEC, 9,
              "the earliest of the two codec keys wins");
    arms_site("fault_codec_end=11&fault_codec=12",
              NGX_TEST_PROBE_FAULT_CODEC_END, 11,
              "the earliest of the two codec keys wins in the other order");
    declines("fault_codec_=1",
             "fault_codec_ with no site suffix does not arm");

    /* ---- F1: arming a module that has no shm zone ---------------------- */

    /*
     * THE NEGATIVE CONTROL FOR F1's ARM HALF. Before the fix,
     * ngx_test_probe_arm() returned NGX_DECLINED on zone == NULL before it
     * reached any hook, so a module with no shm zone -- every compression
     * body filter -- could register a fault hook that was never once called.
     * That is a silent false green: the module compiles, links, registers,
     * and asserts nothing. Every assertion below therefore checks that the
     * hook RAN (g_calls == 1) and what it received, not merely the rc.
     */

    memset(&hooks, 0, sizeof(hooks));
    ngx_test_probe_register(&hooks);
    memset(&mhooks, 0, sizeof(mhooks));
    mhooks.fault_set_global = recording_fault_set_global;
    ngx_test_probe_register_module(&mhooks);

    {
        ngx_int_t rc = arm_zone(NULL, "fault_codec=3");

        ok(rc == NGX_OK && g_calls == 1 && calls == 0
           && g_seen_fault == NGX_TEST_PROBE_FAULT_CODEC && g_seen_value == 3,
           "a zoneless module arms through fault_set_global");
    }

    {
        ngx_int_t rc = arm_zone(NULL, "fault_slab=-1");

        ok(rc == NGX_OK && g_calls == 1
           && g_seen_fault == NGX_TEST_PROBE_FAULT_SLAB && g_seen_value == -1,
           "a zoneless module disarms through fault_set_global");
    }

    /* The boundary and malformed contract is the SAME parser, so it must hold
     * identically on the zoneless path -- a fallback that skipped validation
     * would be a second, weaker parser reachable by anyone who omits a zone. */
    {
        ngx_int_t rc = arm_zone(NULL, "not_fault_codec=1");

        ok(rc == NGX_DECLINED && g_calls == 0 && calls == 0,
           "a suffix match does not arm on the zoneless path either");
    }

    {
        ngx_int_t rc = arm_zone(NULL, "fault_codec=1junk");

        ok(rc == NGX_DECLINED && g_calls == 0,
           "trailing junk does not arm on the zoneless path either");
    }

    {
        ngx_int_t rc = arm_zone(NULL, "fault_codec=99999");

        ok(rc == NGX_DECLINED && g_calls == 0,
           "the digit bound holds on the zoneless path too");
    }

    {
        ngx_int_t rc = arm_zone(NULL, "");

        ok(rc == NGX_DECLINED && g_calls == 0,
           "an empty query does not arm on the zoneless path");
    }

    /*
     * A zone-carrying probe endpoint on a module that registered ONLY the
     * global hook still reaches it: the fallback keys on which hook exists,
     * not only on whether a zone was handed in.
     */
    {
        ngx_int_t rc = arm_zone(ZONE, "fault_codec_end=4");

        ok(rc == NGX_OK && g_calls == 1 && calls == 0
           && g_seen_fault == NGX_TEST_PROBE_FAULT_CODEC_END
           && g_seen_value == 4,
           "a global-only module arms even when a zone is present");
    }

    /* ---- F1: the dispatch precedence between the two families ---------- */

    /*
     * With BOTH registered, a zone present routes to the zone-addressed hook
     * and NOTHING to the global one. This is the backward-compatibility
     * assertion in test form: an existing consumer that registers only
     * fault_set is the g_calls == 0 half of this, and it must keep receiving
     * every call it received before.
     */
    hooks.fault_set = recording_fault_set;
    ngx_test_probe_register(&hooks);

    {
        ngx_int_t rc = arm_zone(ZONE, "fault_slab=5");

        ok(rc == NGX_OK && calls == 1 && g_calls == 0
           && seen_zone == ZONE && seen_fault == NGX_TEST_PROBE_FAULT_SLAB
           && seen_value == 5,
           "with a zone and both hooks, the zone-addressed hook wins");
    }

    {
        ngx_int_t rc = arm_zone(NULL, "fault_slab=6");

        ok(rc == NGX_OK && g_calls == 1 && calls == 0
           && g_seen_fault == NGX_TEST_PROBE_FAULT_SLAB && g_seen_value == 6,
           "with no zone and both hooks, the global hook takes the call");
    }

    /*
     * fault_set registered, no global hook, no zone: there is nothing that can
     * legally take this call, and the answer must be a refusal rather than a
     * call with a NULL zone the hook would dereference.
     */
    memset(&hooks, 0, sizeof(hooks));
    hooks.fault_set = recording_fault_set;
    ngx_test_probe_register(&hooks);
    ngx_test_probe_register_module(NULL);

    {
        ngx_int_t rc = arm_zone(NULL, "fault_slab=7");

        ok(rc == NGX_DECLINED && calls == 0 && g_calls == 0,
           "a zone-only module with no zone refuses rather than passing NULL");
    }

    /* And with neither hook, the pre-parse refusal still fires. */
    memset(&hooks, 0, sizeof(hooks));
    ngx_test_probe_register(&hooks);
    ngx_test_probe_register_module(NULL);

    {
        ngx_int_t rc = arm_zone(NULL, "fault_codec=1");

        ok(rc == NGX_DECLINED && calls == 0 && g_calls == 0,
           "no hook at all still declines on the zoneless path");
    }

    /* ---- F1: the zone-independent render dispatch ---------------------- */

    /*
     * THE NEGATIVE CONTROL FOR F1's RENDER HALF. ngx_test_probe_json()'s two
     * present:false early returns fire BEFORE the zone_render dispatch, so a
     * zoneless module had no way to put a single member into the document.
     * ngx_test_probe_render_module() is the seam that gives it one, and it
     * lives in this translation unit precisely so the dispatch can be
     * asserted here rather than only through a configured server -- a
     * dispatch exercised only end-to-end fails silently, which is the exact
     * shape of the defect being fixed.
     */
    {
        u_char  buf[64];
        u_char *end;

        memset(&mhooks, 0, sizeof(mhooks));
        ngx_test_probe_register_module(&mhooks);

        memset(buf, 'X', sizeof(buf));
        end = ngx_test_probe_render_module(buf, buf + sizeof(buf));

        ok(end == buf && buf[0] == 'X',
           "no module_render hook renders no \"module\" member at all");
    }

    {
        u_char  buf[64];
        u_char *end;

        memset(&mhooks, 0, sizeof(mhooks));
        mhooks.module_render = recording_module_render;
        ngx_test_probe_register_module(&mhooks);

        render_calls = 0;
        memset(buf, 0, sizeof(buf));
        end = ngx_test_probe_render_module(buf, buf + sizeof(buf));

        ok(render_calls == 1, "the module_render hook is actually called");
        ok(end - buf == (long) strlen(",\"module\":{\"frames\":3}")
           && memcmp(buf, ",\"module\":{\"frames\":3}",
                     strlen(",\"module\":{\"frames\":3}")) == 0,
           "the hook's members land inside a top-level \"module\" object");
    }

    /*
     * A hook that writes nothing must still leave a well-formed empty object.
     * "module":{ with no brace would make the whole document unparseable --
     * which the prober reports as a broken probe rather than as a failed
     * assertion, so it is worth pinning.
     */
    {
        u_char  buf[64];
        u_char *end;

        memset(&mhooks, 0, sizeof(mhooks));
        mhooks.module_render = silent_module_render;
        ngx_test_probe_register_module(&mhooks);

        memset(buf, 0, sizeof(buf));
        end = ngx_test_probe_render_module(buf, buf + sizeof(buf));

        ok(end - buf == (long) strlen(",\"module\":{}")
           && memcmp(buf, ",\"module\":{}", strlen(",\"module\":{}")) == 0,
           "a hook that writes nothing yields an empty \"module\" object");
    }

    /*
     * Truncation is bounded. With no room for even the opening literal,
     * nothing is written and the hook is not called -- a partial `,"modu` in
     * the document would be worse than an absent member.
     */
    {
        u_char  buf[4];
        u_char *end;

        memset(&mhooks, 0, sizeof(mhooks));
        mhooks.module_render = recording_module_render;
        ngx_test_probe_register_module(&mhooks);

        render_calls = 0;
        memset(buf, 'X', sizeof(buf));
        end = ngx_test_probe_render_module(buf, buf + sizeof(buf));

        ok(end == buf && render_calls == 0 && buf[0] == 'X',
           "a buffer too small for the opening literal renders nothing");
    }

    /*
     * A hook that rewinds behind its start abandons the object entirely: the
     * end pointer is back where the render began, so the caller's document
     * simply has no "module" member. Asserting the RETURNED position (not the
     * bytes) is what matters -- the caller keeps writing from there, and a
     * position inside a half-written literal would corrupt the document.
     */
    {
        u_char  buf[64];
        u_char *end;

        memset(&mhooks, 0, sizeof(mhooks));
        mhooks.module_render = rewinding_module_render;
        ngx_test_probe_register_module(&mhooks);

        render_calls = 0;
        memset(buf, 0, sizeof(buf));
        end = ngx_test_probe_render_module(buf, buf + sizeof(buf));

        ok(render_calls == 1 && end == buf,
           "a hook that rewinds behind its start abandons the object");
    }

    /*
     * p already past last -- a caller that overflowed before reaching here.
     * The length guard must reject on the pointer comparison, not on a
     * negative difference cast to a huge size_t, which would wave the write
     * through and scribble past the buffer.
     */
    {
        u_char  buf[32];
        u_char *end;

        memset(&mhooks, 0, sizeof(mhooks));
        mhooks.module_render = recording_module_render;
        ngx_test_probe_register_module(&mhooks);

        render_calls = 0;
        memset(buf, 'X', sizeof(buf));
        end = ngx_test_probe_render_module(buf + 16, buf + 8);

        ok(end == buf + 16 && render_calls == 0 && buf[16] == 'X',
           "p already past last renders nothing rather than wrapping");
    }

    /* A zero-length buffer must not be written to at all. */
    {
        u_char  buf[1];
        u_char *end;

        render_calls = 0;
        buf[0] = 'X';
        end = ngx_test_probe_render_module(buf, buf);

        ok(end == buf && render_calls == 0 && buf[0] == 'X',
           "a zero-length buffer renders nothing");
    }

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
