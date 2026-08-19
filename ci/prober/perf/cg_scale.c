/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Cachegrind scaling harness for the response-body JSON parser.
 *
 * The point is an ALGORITHMIC-COST claim, not a wall-clock one: parsing an
 * N-element document must cost O(N) instructions, so an 8x larger document
 * costs ~8x, never ~64x. A regression that turns a linear scan quadratic (a
 * per-element loop over all elements seen so far -- a duplicate check, a naive
 * insert, an append that walks to the tail) is invisible to a functional test
 * and to a timing test on small inputs, but it changes the SHAPE of the cost
 * curve, and Cachegrind measures that shape deterministically: the same binary
 * on the same input yields the identical instruction count every run, with no
 * wall-clock flake. That is why this replaces the rejected `expect time<ms`
 * directive (see memory TODO): timing is machine- and load-dependent, an
 * instruction-count ratio is neither.
 *
 * Two modes let the driver cancel everything that is not the parser:
 *
 *   gen    build the fixed-shape input string of `count` elements, free it.
 *   parse  build the SAME input, then json_parse_n() it (and json_free the
 *          tree), then free it.
 *
 * Ir(parse,count) - Ir(gen,count) is the parser's own instruction count at that
 * size: process startup, libc init, and the O(count) input generation appear in
 * BOTH runs and subtract out, leaving only json_parse_n + json_free. The driver
 * takes that marginal at count=N and count=8N and asserts the ratio is linear.
 *
 * The workload is an array of small objects -- {"k":<number>,"s":<string>} --
 * so the scaling exercises parse_array, parse_object, parse_string and
 * parse_number together, and both realloc-grown containers (json.c array items
 * and object keys/items) at once. A quadratic in any of them shows up here.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../json.h"

/* One array element, rendered without the leading comma. Fixed content so the
 * generated document is identical run to run (Cachegrind determinism depends on
 * identical input, and the ratio depends on identical PER-ELEMENT work). */
#define ELEM  "{\"k\":123456789,\"s\":\"abcdefgh\"}"

/* Generous per-element upper bound on the rendered size, including the comma. */
#define ELEM_MAX  (sizeof(ELEM) + 1)

static char *
build(long count, size_t *out_len)
{
    size_t  cap;
    size_t  o = 0;
    char   *s;
    long    i;

    /* [ + count elements each at most ELEM_MAX + ] + NUL. */
    cap = (size_t) count * ELEM_MAX + 3;
    s = malloc(cap);
    if (s == NULL) {
        return NULL;
    }

    s[o++] = '[';
    for (i = 0; i < count; i++) {
        if (i != 0) {
            s[o++] = ',';
        }
        memcpy(s + o, ELEM, sizeof(ELEM) - 1);
        o += sizeof(ELEM) - 1;
    }
    s[o++] = ']';

    *out_len = o;
    return s;
}

int
main(int argc, char **argv)
{
    long         count;
    int          do_parse;
    size_t       len = 0;
    char        *s;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <count> <gen|parse>\n", argv[0]);
        return 2;
    }

    {
        char  *end;
        long   parsed;

        errno = 0;
        parsed = strtol(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || errno != 0 || parsed < 0) {
            fprintf(stderr, "count must be a non-negative integer\n");
            return 2;
        }
        /* Reject a count whose rendered size would overflow size_t in build():
         * a wrapped cap would malloc a tiny buffer that the render loop then
         * overruns (CWE-787). ELEM_MAX bounds the per-element bytes; the +3 is
         * the surrounding [ ] and the NUL. Bytes are driver-controlled today,
         * but this is a standalone binary, so it validates its own argv. */
        if ((size_t) parsed > (SIZE_MAX - 3) / ELEM_MAX) {
            fprintf(stderr, "count too large (would overflow allocation)\n");
            return 2;
        }
        count = parsed;
    }

    if (strcmp(argv[2], "gen") == 0) {
        do_parse = 0;
    } else if (strcmp(argv[2], "parse") == 0) {
        do_parse = 1;
    } else {
        fprintf(stderr, "mode must be gen or parse\n");
        return 2;
    }

    s = build(count, &len);
    if (s == NULL) {
        fprintf(stderr, "out of memory building %ld elements\n", count);
        return 1;
    }

    if (do_parse) {
        const char  *err = NULL;
        json_value  *v;

        v = json_parse_n(s, len, &err);
        if (v == NULL) {
            /* A parse failure would make the marginal meaningless (the parser
             * bailed early instead of doing the O(N) work), so it is a hard
             * error, not a quiet zero. */
            fprintf(stderr, "parse failed at %ld elements: %s\n",
                    count, err ? err : "(no message)");
            free(s);
            return 1;
        }
        json_free(v);
    }

    free(s);
    return 0;
}
