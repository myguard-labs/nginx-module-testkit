/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json_test.c -- TAP self-test for the prober's JSON reader.
 *
 * The reader is the harness ORACLE: every `probe` and `delta` assertion is
 * evaluated against the document it produces. A parser that quietly accepts a
 * malformed document, or that reads a number wrong, turns every rule that
 * depends on it into a test that cannot fail -- which is worse than having no
 * rule at all, because the run still reports green.
 *
 * So the accept cases pin the shapes the probe renderer actually emits, and the
 * reject cases pin the shapes that would mean the renderer is broken (raw
 * control bytes in a string, leading-zero or leading-plus numbers, truncated
 * documents). Run by t/prober/run.sh before any server is booted.
 */

#define _GNU_SOURCE

#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bumped by hand rather than computed, so that a test accidentally deleted or
 * short-circuited shows up as a plan mismatch instead of a smaller green run. */
#define PLANNED  107

static int  tests_run = 0;
static int  failures = 0;


static void
ok(int cond, const char *name)
{
    tests_run++;

    printf("%sok %d - %s\n", cond ? "" : "not ", tests_run, name);

    if (!cond) {
        failures++;
    }
}


static void
accepts(const char *text, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);

    if (v == NULL) {
        printf("# %s: rejected with \"%s\"\n", name, err ? err : "?");
    }

    ok(v != NULL, name);
    json_free(v);
}


static void
rejects(const char *text, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);

    if (v != NULL) {
        printf("# %s: accepted, but must not be\n", name);
    }

    ok(v == NULL, name);
    json_free(v);
}


/*
 * Reject, AND for the stated reason. Several of the rejections below are the
 * only thing standing between a malformed document and a confident wrong
 * verdict, so it matters that the parser refuses them deliberately rather than
 * tripping over some earlier check by luck -- a rejection that moves to a
 * different cause is a rejection that can quietly stop happening.
 */
static void
rejects_because(const char *text, const char *want_err, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);
    int         good;

    good = (v == NULL && err != NULL && strcmp(err, want_err) == 0);

    if (!good) {
        printf("# %s: got %s (\"%s\"), want rejection \"%s\"\n", name,
               v == NULL ? "rejection" : "acceptance", err ? err : "-",
               want_err);
    }

    ok(good, name);
    json_free(v);
}


static void
number_is(const char *text, const char *path, double want, const char *name)
{
    const char       *err = NULL;
    const json_value *field;
    json_value       *doc = json_parse(text, &err);
    int               good;

    if (doc == NULL) {
        printf("# %s: parse failed: %s\n", name, err ? err : "?");
        ok(0, name);
        return;
    }

    field = json_get(doc, path);
    good = (field != NULL && field->type == JSON_NUMBER && field->number == want);

    if (!good) {
        printf("# %s: %s is %s\n", name, path,
               field == NULL ? "absent" : json_type_name(field->type));
    }

    ok(good, name);
    json_free(doc);
}


int
main(void)
{
    /* The document the probe renderer actually emits, in the shape the rule
     * files assert against. If this ever stops parsing, every rule breaks at
     * once, so it is the first thing checked. */
    static const char probe_doc[] =
        "{\"flavor\":\"nginx\",\"flavor_version\":\"1.31.3\",\"pid\":1234,"
        "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
        "\"zone\":{\"present\":true,\"name\":\"demo\",\"size\":1048576,"
        "\"slab_pages_free\":248,\"nodes\":2,\"banned\":1,"
        "\"fault\":{\"slab_nth\":-1,\"slab_seen\":0}}}";

    printf("1..%d\n", PLANNED);

    accepts(probe_doc, "the probe document parses");
    number_is(probe_doc, "zone.nodes", 2, "a nested number reads back");
    number_is(probe_doc, "zone.fault.slab_nth", -1,
              "a negative number keeps its sign");
    number_is(probe_doc, "connections.free", 511, "a two-level path resolves");

    {
        json_value *doc = json_parse(probe_doc, NULL);

        ok(doc != NULL && json_get(doc, "zone.absent") == NULL,
           "an absent path is NULL, not a zero");
        json_free(doc);
    }

    /* Numbers: the JSON grammar, not what strtod() happens to swallow. */
    accepts("{\"n\":0}", "zero");
    accepts("{\"n\":-0}", "negative zero");
    accepts("{\"n\":1234567890}", "a plain integer");
    accepts("{\"n\":1.5}", "a fraction");
    accepts("{\"n\":1e3}", "an exponent");
    rejects("{\"n\":+1}", "a leading plus is not JSON");
    rejects("{\"n\":.5}", "a bare fraction is not JSON");
    rejects("{\"n\":01}", "a leading zero is not JSON");
    rejects("{\"n\":1.}", "a trailing decimal point is not JSON");
    rejects("{\"n\":1e}", "an empty exponent is not JSON");
    rejects("{\"n\":0x10}", "hex is not JSON");
    rejects("{\"n\":"
            "111111111111111111111111111111111111111111111111111111111111"
            "111111111111111111111111}",
            "an over-long number is an error, not a truncation");

    /* Strings. */
    accepts("{\"s\":\"a\\nb\"}", "an escaped newline");
    rejects("{\"s\":\"a\nb\"}", "a raw newline in a string");
    rejects("{\"s\":\"a\tb\"}", "a raw tab in a string");
    rejects("{\"s\":\"unterminated}", "an unterminated string");

    /* Document framing. */
    rejects("{\"a\":1", "a truncated object");
    rejects("{\"a\":1}}", "trailing garbage after the document");
    rejects("", "an empty document");

    /*
     * Duplicate keys.
     *
     * json_get() returns the first match, so a second value for the same key
     * can never be asserted on -- and the way one appears is a module's
     * zone_render hook emitting a member the generic probe already emitted.
     * That is a defect in the code under test, and it has to surface as a
     * broken probe rather than as one value silently shadowing another.
     */
    rejects_because("{\"a\":1,\"a\":2}", "duplicate key in object",
                    "a duplicate key is rejected, not shadowed");
    rejects_because("{\"zone\":{\"n\":1,\"n\":2}}", "duplicate key in object",
                    "a duplicate key nested in an object is rejected");
    accepts("{\"a\":{\"n\":1},\"b\":{\"n\":2}}",
            "the same key in two different objects is fine");

    /*
     * Numbers that do not survive as a finite double. Infinity compares as a
     * number under every operator, so `probe x < 100` against an infinite
     * value would report a clean, confident, wrong verdict.
     */
    rejects_because("{\"n\":1e999}", "number is out of range for a double",
                    "an overflowing exponent is rejected, not read as infinity");
    rejects_because("{\"n\":-1e999}", "number is out of range for a double",
                    "a negative overflowing exponent is rejected too");
    accepts("{\"n\":1e308}", "an exponent that still fits a double");

    /* Nesting. The parser recurses, and the document comes from a worker that
     * may be in the middle of crashing. */
    {
        char deep[4096];
        char shallow[256];
        int  i;

        for (i = 0; i < JSON_MAX_DEPTH + 5; i++) {
            deep[i] = '[';
        }
        deep[JSON_MAX_DEPTH + 5] = '\0';

        rejects_because(deep, "nesting too deep",
                        "nesting past the depth cap is refused");

        /* One below the cap must still parse, or the cap is off by one and
         * quietly rejects documents the probe can legitimately emit. */
        for (i = 0; i < JSON_MAX_DEPTH - 1; i++) {
            shallow[i] = '[';
        }
        shallow[JSON_MAX_DEPTH - 1] = ']';
        for (i = 0; i < JSON_MAX_DEPTH - 2; i++) {
            shallow[JSON_MAX_DEPTH + i] = ']';
        }
        shallow[2 * JSON_MAX_DEPTH - 2] = '\0';

        accepts(shallow, "nesting just under the cap still parses");
    }

    /* Paths. */
    {
        json_value *doc = json_parse(probe_doc, NULL);

        ok(doc != NULL && json_get(doc, "") == NULL,
           "an empty path is not the whole document");
        ok(doc != NULL && json_get(doc, "zone.nodes.deeper") == NULL,
           "descending through a number yields NULL");
        ok(doc != NULL && json_get(doc, "zon") == NULL,
           "a key prefix does not match");
        ok(doc != NULL && json_get(doc, "zone.") == NULL,
           "a trailing dot does not resolve to the parent");
        ok(doc != NULL && json_get(doc, ".zone") == NULL,
           "a leading dot does not resolve");
        ok(doc != NULL && json_get(doc, "zone..nodes") == NULL,
           "a doubled dot does not resolve");

        json_free(doc);
    }

    /* Object and array framing that the probe renderer would only produce if
     * it were emitting a member it had not finished building. */
    rejects("{\"a\":}", "an object member with no value");
    rejects("{\"a\" 1}", "an object member with no colon");
    rejects("{,}", "a bare comma in an object");
    rejects("{\"a\":1,}", "a trailing comma in an object");
    rejects("[1,]", "a trailing comma in an array");
    rejects("[1,,2]", "a doubled comma in an array");
    rejects("{\"a\":1,\"b\"}", "a second member with no value");
    rejects("[", "an unterminated array");
    accepts("{}", "an empty object");
    accepts("[]", "an empty array");
    accepts("{\"a\":[]}", "an empty array as a member");

    /* Whitespace between every token, which ngx_slprintf never emits but a
     * hand-written fixture in a consumer's test might. */
    accepts("  {  \"a\" :  1 ,  \"b\" : [ 1 , 2 ]  }  ",
            "insignificant whitespace everywhere");

    /* ---- AUD-11: json_parse_n is length-delimited, not NUL-delimited ---- */
    {
        const char *err;
        json_value *v;

        /* A valid document, a NUL, then trailing garbage. json_parse (strlen)
         * stops at the NUL and accepts the prefix; json_parse_n sees the whole
         * body and must reject the trailing bytes -- the AUD-11 defect, where a
         * corrupt or smuggled probe reply read as healthy. The literal is sized
         * with sizeof-1 so the embedded NUL is part of the length. */
        static const char nul_doc[] = "{\"pid\":5}\0trailing garbage";
        size_t nul_len = sizeof(nul_doc) - 1;

        err = NULL;
        v = json_parse(nul_doc, &err);
        ok(v != NULL, "json_parse (strlen) stops at the NUL and accepts the "
           "prefix -- the AUD-11 hazard");
        json_free(v);

        err = NULL;
        v = json_parse_n(nul_doc, nul_len, &err);
        ok(v == NULL && err != NULL
           && strcmp(err, "trailing garbage after document") == 0,
           "json_parse_n sees the whole body and rejects trailing garbage "
           "past a NUL (AUD-11)");
        json_free(v);

        /* A raw NUL inside a string is a control byte, which this parser
         * rejects like any other unescaped control char (see the raw-newline
         * and raw-tab cases above). The point here is that json_parse_n SEES it
         * at all: strlen-based parsing would stop at the NUL and accept the
         * truncated prefix `{"k":"a` as... incomplete, masking the real byte.
         * Passing the true length makes the control byte reach the validator. */
        {
            static const char in[] = "{\"k\":\"a\0b\"}";
            size_t inlen = sizeof(in) - 1;

            err = NULL;
            v = json_parse_n(in, inlen, &err);
            ok(v == NULL, "json_parse_n reaches a raw NUL inside a string and "
               "rejects it as a control byte, not truncating at it (AUD-11)");
            json_free(v);
        }

        /*
         * R-11: the number scanner used strchr("-+.eE", *p), and strchr
         * answers for its own terminator -- so a NUL beside a number was
         * consumed into the token, which then ENDED at that NUL and read as a
         * plain number. This is the one hole left in AUD-11: the two cases
         * above cover a NUL after `}` and inside a string, neither of which
         * goes through the number scanner.
         */
        /*
         * The NUL has to be followed by a VALID continuation, or the row is
         * vacuous: `{"n":12\0 34}` is rejected with the bug present too, since
         * the stray `34` fails the next structural check and the NUL never
         * decides anything. The mutation harness caught exactly that draft.
         * With the NUL sitting where the token legitimately ends, the pre-fix
         * scanner swallowed it and the document PARSED.
         */
        {
            static const char in[] = "{\"n\":12\0}";
            size_t inlen = sizeof(in) - 1;

            err = NULL;
            v = json_parse_n(in, inlen, &err);
            ok(v == NULL, "a NUL between a number and the closing brace is "
               "not swallowed into the token (R-11)");
            json_free(v);
        }

        {
            static const char in[] = "{\"n\":12\0,\"m\":1}";
            size_t inlen = sizeof(in) - 1;

            err = NULL;
            v = json_parse_n(in, inlen, &err);
            ok(v == NULL, "a NUL spliced between a number and the next member "
               "is not swallowed into the token (R-11)");
            json_free(v);
        }
    }

    /*
     * R-8: RFC 8259 s.8.1 requires JSON text to be valid UTF-8. The parser
     * rejected C0 controls but copied any byte at or above 0x80 straight
     * through, and json_sort re-emitted it -- so `body_sha256` and every body
     * assertion returned a confident verdict about a document that is not
     * JSON. The reject rows below are one per class the decoder distinguishes,
     * because a validator that catches only the lead byte still admits the
     * overlong and surrogate forms, which are the ones that smuggle an ASCII
     * byte or a non-character past a byte-comparing filter.
     */
    {
        const char *err;
        json_value *v;
        size_t      i;

        static const struct {
            const char *doc;
            const char *what;
        } bad[] = {
            { "{\"k\":\"\xC0\x80\"}", "an overlong two-byte lead (0xC0)" },
            { "{\"k\":\"\xC1\xAF\"}", "an overlong two-byte form of '/'" },
            { "{\"k\":\"\x80\x80\"}", "a bare continuation byte as lead" },
            { "{\"k\":\"\xC2\"}", "a truncated two-byte sequence" },
            { "{\"k\":\"\xE2\x82\"}", "a truncated three-byte sequence" },
            { "{\"k\":\"\xE2\x28\xA1\"}", "a bad continuation byte mid-sequence" },
            { "{\"k\":\"\xE0\x80\xAF\"}", "an overlong three-byte form of '/'" },
            { "{\"k\":\"\xF0\x80\x80\xAF\"}", "an overlong four-byte form of '/'" },
            { "{\"k\":\"\xED\xA0\x80\"}", "a UTF-16 surrogate half (U+D800)" },
            { "{\"k\":\"\xF4\x90\x80\x80\"}", "a code point above U+10FFFF" },
            { "{\"k\":\"\xF5\x80\x80\x80\"}", "a lead byte above 0xF4" },
        };

        static const struct {
            const char *doc;
            const char *what;
        } good[] = {
            { "{\"k\":\"\xC2\xA9\"}", "U+00A9, two bytes" },
            { "{\"k\":\"\xE2\x82\xAC\"}", "U+20AC, three bytes" },
            { "{\"k\":\"\xF0\x9F\x92\xA9\"}", "U+1F4A9, four bytes" },
            { "{\"k\":\"\xEF\xBF\xBD\"}", "U+FFFD, the replacement char" },

            /* The legal ENDPOINTS of each range. Without these the suite stays
             * green through a one-character regression in exactly the code this
             * PR adds: `lead < 0xF5` becoming `< 0xF4`, `cp > 0x10FFFF` becoming
             * `>=`, or an overlong threshold flipping `<` to `<=`. Each of those
             * turns a legal document into NOT_JSON, which fails the case rather
             * than passing it -- a false reject, not a false accept, but still a
             * verdict about a document the probe may legitimately emit. */
            { "{\"k\":\"\xC2\x80\"}", "U+0080, the lowest two-byte scalar" },
            { "{\"k\":\"\xDF\xBF\"}", "U+07FF, the highest two-byte scalar" },
            { "{\"k\":\"\xE0\xA0\x80\"}", "U+0800, the lowest three-byte scalar" },
            { "{\"k\":\"\xED\x9F\xBF\"}", "U+D7FF, just below the surrogates" },
            { "{\"k\":\"\xEE\x80\x80\"}", "U+E000, just above the surrogates" },
            { "{\"k\":\"\xF0\x90\x80\x80\"}", "U+10000, the lowest four-byte scalar" },
            { "{\"k\":\"\xF4\x8F\xBF\xBF\"}", "U+10FFFF, the highest legal scalar" },
        };

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            char name[128];

            err = NULL;
            v = json_parse_n(bad[i].doc, strlen(bad[i].doc), &err);
            snprintf(name, sizeof(name),
                     "a string containing %s is rejected AS BAD UTF-8",
                     bad[i].what);

            /* The reason matters: every one of these documents is also
             * rejectable by accident once the parser stops copying the
             * sequence (the closing quote lands mid-token and the string reads
             * as unterminated). A row that accepts any rejection would then
             * pass against a validator that only truncates. */
            if (v != NULL || err == NULL || strstr(err, "UTF-8") == NULL) {
                printf("# %s: got %s (\"%s\")\n", bad[i].what,
                       v == NULL ? "rejection" : "acceptance", err ? err : "-");
            }

            ok(v == NULL && err != NULL && strstr(err, "UTF-8") != NULL, name);
            json_free(v);
        }

        for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
            char name[128];

            err = NULL;
            v = json_parse_n(good[i].doc, strlen(good[i].doc), &err);
            snprintf(name, sizeof(name), "a string containing %s is accepted",
                     good[i].what);
            ok(v != NULL, name);
            json_free(v);
        }

        /* The multi-byte sequence must survive canonicalization BYTE for byte:
         * a validator that decodes and re-encodes, or one that stops copying
         * after the lead byte, would still pass every reject row above while
         * corrupting the document json_sort hands to body_sha256. */
        {
            static const char in[]  = "{\"b\":\"\xF0\x9F\x92\xA9\",\"a\":1}";
            static const char want[] = "{\"a\":1,\"b\":\"\xF0\x9F\x92\xA9\"}";
            char  *outp = NULL;
            int    rc = -1;

            err = NULL;
            v = json_parse_n(in, sizeof(in) - 1, &err);
            ok(v != NULL, "a document with a four-byte character parses");

            if (v != NULL) {
                rc = json_canonicalize(v, &outp, NULL);
            }

            ok(rc == 0 && outp != NULL && strcmp(outp, want) == 0,
               "canonicalization re-emits the four-byte character unchanged");

            free(outp);
            json_free(v);
        }
    }

    /*
     * json_canonicalize -- the surface json_sort relies on. The property under
     * test is that key ORDER is the only thing normalized away: everything else
     * (array order, values, string bytes) survives, and two documents differing
     * only in key order emit byte-identical canonical forms.
     */
    {
        const char  *err;
        json_value  *v;
        char        *out;
        size_t       out_len;
        int          rc;

        /* keys byte-sorted at the top level */
        v = json_parse("{\"b\":1,\"a\":2,\"c\":3}", &err);
        rc = json_canonicalize(v, &out, &out_len);
        ok(rc == 0 && strcmp(out, "{\"a\":2,\"b\":1,\"c\":3}") == 0,
           "canonicalize sorts object keys in byte order");
        if (rc == 0) { ok(out_len == strlen(out),
            "canonicalize out_len matches the emitted length"); free(out); }
        else { ok(0, "canonicalize out_len matches the emitted length"); }
        json_free(v);

        /* recursive: nested object keys sorted too */
        v = json_parse("{\"z\":{\"y\":1,\"x\":2}}", &err);
        rc = json_canonicalize(v, &out, &out_len);
        ok(rc == 0 && strcmp(out, "{\"z\":{\"x\":2,\"y\":1}}") == 0,
           "canonicalize sorts nested object keys recursively");
        if (rc == 0) free(out);
        json_free(v);

        /* array order is PRESERVED, not sorted (order is semantic in arrays) */
        v = json_parse("[3,1,2]", &err);
        rc = json_canonicalize(v, &out, &out_len);
        ok(rc == 0 && strcmp(out, "[3,1,2]") == 0,
           "canonicalize preserves array element order");
        if (rc == 0) free(out);
        json_free(v);

        /* the headline property: two key orderings, one canonical form */
        {
            char   *a = NULL, *b = NULL;
            json_value *va = json_parse("{\"one\":1,\"two\":2}", &err);
            json_value *vb = json_parse("{\"two\":2,\"one\":1}", &err);
            int rca = json_canonicalize(va, &a, NULL);
            int rcb = json_canonicalize(vb, &b, NULL);
            ok(rca == 0 && rcb == 0 && strcmp(a, b) == 0,
               "two key orderings canonicalize to identical bytes (json_sort core)");
            free(a); free(b);
            json_free(va); json_free(vb);
        }

        /* numbers are emitted from their lexeme, not round-tripped through a
         * double, so 1 and 1.0 stay DISTINCT (they are distinct lexemes) --
         * the flip side of keeping large integers exact below */
        {
            char   *a = NULL, *b = NULL;
            json_value *va = json_parse("{\"n\":1}", &err);
            json_value *vb = json_parse("{\"n\":1.0}", &err);
            int rca = json_canonicalize(va, &a, NULL);
            int rcb = json_canonicalize(vb, &b, NULL);
            ok(rca == 0 && rcb == 0
               && strcmp(a, "{\"n\":1}") == 0 && strcmp(b, "{\"n\":1.0}") == 0,
               "1 and 1.0 canonicalize to distinct verbatim lexemes");
            free(a); free(b);
            json_free(va); json_free(vb);
        }

        /* integers beyond 2^53 stay distinct: round-tripping through a double
         * would collapse ...992 and ...993 to identical %.17g bytes (the
         * CodeRabbit finding). Verbatim emission keeps them apart. */
        {
            char   *a = NULL, *b = NULL;
            json_value *va = json_parse("{\"id\":9007199254740992}", &err);
            json_value *vb = json_parse("{\"id\":9007199254740993}", &err);
            int rca = json_canonicalize(va, &a, NULL);
            int rcb = json_canonicalize(vb, &b, NULL);
            ok(rca == 0 && rcb == 0 && strcmp(a, b) != 0
               && strcmp(a, "{\"id\":9007199254740992}") == 0
               && strcmp(b, "{\"id\":9007199254740993}") == 0,
               "integers beyond 2^53 canonicalize exactly and stay distinct");
            free(a); free(b);
            json_free(va); json_free(vb);
        }

        /* equal numbers with differing exponent spelling collapse: E->e, a '+'
         * exponent sign dropped, exponent leading zeros stripped */
        {
            char   *a = NULL, *b = NULL;
            json_value *va = json_parse("{\"n\":1E+05}", &err);
            json_value *vb = json_parse("{\"n\":1e5}", &err);
            int rca = json_canonicalize(va, &a, NULL);
            int rcb = json_canonicalize(vb, &b, NULL);
            ok(rca == 0 && rcb == 0
               && strcmp(a, "{\"n\":1e5}") == 0 && strcmp(b, "{\"n\":1e5}") == 0,
               "1E+05 and 1e5 normalize to the same exponent lexeme");
            free(a); free(b);
            json_free(va); json_free(vb);
        }

        /* a negative exponent keeps its sign but still strips leading zeros */
        {
            v = json_parse("{\"n\":1E-007}", &err);
            rc = json_canonicalize(v, &out, &out_len);
            ok(rc == 0 && strcmp(out, "{\"n\":1e-7}") == 0,
               "negative exponent keeps sign, strips leading zeros");
            if (rc == 0) free(out);
            json_free(v);
        }

        /* the decimal point is a literal '.' regardless of LC_NUMERIC: no float
         * is formatted on the emit path, so a comma-decimal locale cannot reach
         * it. (The locale-hostility CI leg exercises the process-locale side.) */
        {
            v = json_parse("{\"n\":1.5}", &err);
            rc = json_canonicalize(v, &out, &out_len);
            ok(rc == 0 && strcmp(out, "{\"n\":1.5}") == 0,
               "fractional number emits a literal '.' (locale-independent)");
            if (rc == 0) free(out);
            json_free(v);
        }

        /* string escapes re-emitted: newline and quote and backslash */
        v = json_parse("{\"s\":\"a\\nb\\\"c\\\\d\"}", &err);
        rc = json_canonicalize(v, &out, &out_len);
        ok(rc == 0 && strcmp(out, "{\"s\":\"a\\nb\\\"c\\\\d\"}") == 0,
           "canonicalize re-escapes newline, quote and backslash in strings");
        if (rc == 0) free(out);
        json_free(v);

        /* a bare C0 control () re-emits as , not a raw byte */
        v = json_parse("{\"s\":\"\\u0001\"}", &err);
        if (v != NULL) {
            /* parser rejects \u today, so this document does not parse; the
             * control-escape path is exercised via a decoded \b below instead. */
            rc = json_canonicalize(v, &out, &out_len);
            if (rc == 0) free(out);
        }
        ok(v == NULL,
           "parser rejects \\u so canonicalize never sees an undecoded \\u (guard)");
        json_free(v);

        /* \b decodes to 0x08 then re-emits as \b (short escape, not ) */
        v = json_parse("{\"s\":\"\\b\"}", &err);
        rc = json_canonicalize(v, &out, &out_len);
        ok(rc == 0 && strcmp(out, "{\"s\":\"\\b\"}") == 0,
           "canonicalize re-emits a backspace as the short escape \\b");
        if (rc == 0) free(out);
        json_free(v);

        /* NULL guard */
        ok(json_canonicalize(NULL, &out, &out_len) == -1,
           "canonicalize rejects a NULL value");
    }

    /* ---- json_number_parse: the gate the RULE side shares --------------- */
    {
        double d;

        ok(json_number_parse("2", &d) == 1 && d == 2.0,
           "json_number_parse takes a plain integer");
        ok(json_number_parse("-0.5", &d) == 1 && d == -0.5,
           "json_number_parse takes a negative fraction");
        ok(json_number_parse("2e1", &d) == 1 && d == 20.0,
           "json_number_parse takes an exponent");

        /* Everything strtod() would accept and the document grammar does not.
         * These are the literals that made a rule assertion unable to fail. */
        ok(json_number_parse("nan", &d) == 0, "json_number_parse rejects nan");
        ok(json_number_parse("inf", &d) == 0, "json_number_parse rejects inf");
        ok(json_number_parse("-inf", &d) == 0,
           "json_number_parse rejects -inf");
        ok(json_number_parse("0x7", &d) == 0, "json_number_parse rejects hex");
        ok(json_number_parse("+1", &d) == 0,
           "json_number_parse rejects a leading +");
        ok(json_number_parse(".5", &d) == 0,
           "json_number_parse rejects a bare fraction");
        ok(json_number_parse("01", &d) == 0,
           "json_number_parse rejects a leading zero");
        ok(json_number_parse("1x", &d) == 0,
           "json_number_parse rejects trailing text");
        ok(json_number_parse("", &d) == 0,
           "json_number_parse rejects an empty token");
        ok(json_number_parse("1e999", &d) == 0,
           "json_number_parse rejects a value that overflows to inf");

        /* An accepted token never leaves *out untouched, and a rejected one
         * never writes it: a caller reading a stale double on a 0 return would
         * assert against the PREVIOUS literal. */
        d = 12345.0;
        ok(json_number_parse("nope", &d) == 0 && d == 12345.0,
           "a rejected token leaves the output untouched");
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
