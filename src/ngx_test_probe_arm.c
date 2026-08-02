/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe_arm.c -- hook registry, and the fault_slab= query parser.
 *
 * Split from the renderer because this half depends on nothing except the
 * query bytes: no ngx_cycle, no slab pool, no /proc. That makes it reachable
 * from a direct-call unit test built against a small shim, which matters
 * because it is a parser of attacker-shaped text -- the boundary rule, the
 * malformed-input contract and the digit bound are all things that are easy to
 * get subtly wrong and impossible to notice from a passing rule file.
 *
 * See ngx_test_probe.h.
 */

#include "ngx_test_probe.h"

#ifdef NGX_TEST_HARNESS


/* Shared with the renderer in ngx_test_probe.c, which reads zone_render from
 * it. Not static for that reason, and not exposed in the header either: it is
 * internal to this pair of files, not part of the consumer-facing API. */
ngx_test_probe_hooks_t  ngx_test_probe_hooks;


void
ngx_test_probe_register(const ngx_test_probe_hooks_t *hooks)
{
    if (hooks == NULL) {
        ngx_memzero(&ngx_test_probe_hooks, sizeof(ngx_test_probe_hooks_t));
        return;
    }

    ngx_test_probe_hooks = *hooks;
}


/*
 * The sibling keys, one per fault site. Whole-query-arg matched, each with the
 * identical boundary/digit-bound/malformed contract -- a query is compared
 * against every key so that the SITE, not the parser, is what varies.
 *
 * The .fault field indexes ngx_test_probe_fault_e; the table order need not
 * match the enum, but every enum value must appear exactly once. A missing key
 * would make that site unreachable from a query; a duplicate would make the
 * later one dead.
 */
typedef struct {
    const char              *key;     /* includes the trailing '=' */
    size_t                   keylen;  /* strlen(key) */
    ngx_test_probe_fault_e   fault;
} ngx_test_probe_fault_key_t;

#define NGX_TEST_PROBE_FAULT_KEY(s, f)  { (s), sizeof(s) - 1, (f) }

static const ngx_test_probe_fault_key_t  ngx_test_probe_fault_keys[] = {
    NGX_TEST_PROBE_FAULT_KEY("fault_slab=",     NGX_TEST_PROBE_FAULT_SLAB),
    NGX_TEST_PROBE_FAULT_KEY("fault_palloc=",   NGX_TEST_PROBE_FAULT_PALLOC),
    NGX_TEST_PROBE_FAULT_KEY("fault_tempfile=", NGX_TEST_PROBE_FAULT_TEMPFILE),
    NGX_TEST_PROBE_FAULT_KEY("fault_accept=",   NGX_TEST_PROBE_FAULT_ACCEPT)
};

#define NGX_TEST_PROBE_FAULT_KEY_N \
    (sizeof(ngx_test_probe_fault_keys) / sizeof(ngx_test_probe_fault_keys[0]))


/*
 * Parse the value that begins at `v` and runs to `end` (the value part of one
 * already-matched key). On a well-formed value -- optional '-', then one to
 * NGX_TEST_PROBE_FAULT_MAX_DIGITS digits, then the arg boundary ('&' or end) --
 * stores the signed result through *out and returns NGX_OK. Anything else
 * (empty, lone minus, trailing junk, digit overflow) returns NGX_DECLINED so
 * the contract for malformed input is a refusal, never a best guess.
 */
static ngx_int_t
ngx_test_probe_parse_nth(u_char *v, u_char *end, ngx_int_t *out)
{
    int         negative;
    ngx_uint_t  digits;
    ngx_int_t   value;

    negative = 0;

    if (v < end && *v == '-') {
        negative = 1;
        v++;
    }

    if (v >= end || *v < '0' || *v > '9') {
        return NGX_DECLINED;
    }

    value = 0;
    digits = 0;

    while (v < end && *v >= '0' && *v <= '9') {
        /*
         * Bounded before the multiply, not after. The nth-event counter this
         * feeds is small by nature -- rules arm the 1st or 2nd event -- so
         * nothing legitimate reaches even four digits, while an unbounded
         * accumulate overflows ngx_int_t on a long enough digit run, which is
         * undefined behaviour and would land as an arbitrary (possibly
         * negative) fault index rather than as the refusal the caller expects
         * for garbage.
         */
        if (++digits > NGX_TEST_PROBE_FAULT_MAX_DIGITS) {
            return NGX_DECLINED;
        }

        value = value * 10 + (*v - '0');
        v++;
    }

    /* The value has to end where the argument ends. "fault_slab=1junk" is
     * malformed, and the contract for malformed input is NGX_DECLINED rather
     * than a best guess at what the caller meant. */
    if (v < end && *v != '&') {
        return NGX_DECLINED;
    }

    *out = negative ? -value : value;

    return NGX_OK;
}


ngx_int_t
ngx_test_probe_arm(ngx_shm_zone_t *zone, ngx_str_t *args)
{
    ngx_uint_t   i;
    u_char      *p, *end;
    ngx_int_t    value;

    if (ngx_test_probe_hooks.fault_set == NULL) {
        return NGX_DECLINED;
    }

    if (zone == NULL || args == NULL || args->len == 0) {
        return NGX_DECLINED;
    }

    end = args->data + args->len;

    /*
     * Walk the query once. At each position that begins a query argument (the
     * start, or just after an '&'), try every sibling key. Matching this way
     * rather than substring-searching is the whole boundary contract: it must
     * start the query or follow an '&', or "not_fault_slab=1" would arm the
     * injector through a parameter nobody wrote. The first key that matches at
     * the earliest argument wins.
     */
    for (p = args->data; p < end; p++) {

        if (p != args->data && p[-1] != '&') {
            continue;
        }

        for (i = 0; i < NGX_TEST_PROBE_FAULT_KEY_N; i++) {
            const ngx_test_probe_fault_key_t  *k = &ngx_test_probe_fault_keys[i];

            if ((size_t) (end - p) < k->keylen) {
                continue;
            }

            if (ngx_strncmp(p, k->key, k->keylen) != 0) {
                continue;
            }

            if (ngx_test_probe_parse_nth(p + k->keylen, end, &value)
                != NGX_OK)
            {
                return NGX_DECLINED;
            }

            return ngx_test_probe_hooks.fault_set(zone, k->fault, value);
        }
    }

    return NGX_DECLINED;
}


/*
 * Emit a JSON-escaped string into a buffer using ngx_slprintf-style semantics.
 * The output is surrounded by quotes; the caller provides opening quote context
 * if needed (e.g. "\"name\":\"" before, and "\"" after for the closing quote).
 *
 * RFC 8259 requires these characters to be escaped in JSON strings:
 * - " (quotation mark)
 * - \ (backslash)
 * - C0 control characters (0x00-0x1F)
 *
 * This implements the short escape sequences for the most common controls
 * (\", \\, \b, \f, \n, \r, \t) and \uXXXX for everything else < 0x20.
 * Characters >= 0x20 are passed through unchanged (supports UTF-8 directly).
 *
 * Returns the new buffer position after the escaping.
 *
 * Lives here rather than in the renderer (ngx_test_probe.c) because it
 * depends on nothing but the input bytes -- no ngx_cycle, no slab pool, no
 * /proc -- the same reachability rationale as ngx_test_probe_arm() above.
 * Not static for that reason: probe_escape_json_string_test.c calls it
 * directly against the t/ shim.
 */
u_char *
ngx_test_probe_escape_json_string(u_char *p, u_char *last, const ngx_str_t *str)
{
    u_char  c;
    size_t  i;

    static const u_char  hex[] = "0123456789abcdef";

    for (i = 0; i < str->len && p < last; i++) {
        c = str->data[i];

        switch (c) {
        case '"':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = '"';
            }
            break;
        case '\\':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = '\\';
            }
            break;
        case '\b':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = 'b';
            }
            break;
        case '\f':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = 'f';
            }
            break;
        case '\n':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = 'n';
            }
            break;
        case '\r':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = 'r';
            }
            break;
        case '\t':
            if (p + 2 <= last) {
                *p++ = '\\';
                *p++ = 't';
            }
            break;
        default:
            if (c < 0x20) {
                /* C0 control characters (other than those above) get
                 * \uXXXX escape. */
                if (p + 6 <= last) {
                    *p++ = '\\';
                    *p++ = 'u';
                    *p++ = '0';
                    *p++ = '0';
                    *p++ = hex[(c >> 4) & 0xf];
                    *p++ = hex[c & 0xf];
                }
            } else {
                /* Printable characters (including UTF-8 continuations)
                 * are passed through unchanged. */
                if (p < last) {
                    *p++ = c;
                }
            }
        }
    }

    return p;
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_test_probe_arm_not_built_t;

#endif /* NGX_TEST_HARNESS */
