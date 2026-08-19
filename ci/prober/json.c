/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json.c -- see json.h.
 */

/* _GNU_SOURCE for strtod_l(): a JSON number must be read with '.' as the radix
 * character regardless of the process LC_NUMERIC. Plain strtod() honors the
 * locale, so a comma-decimal locale (de_DE, nl_NL) would stop at the '.' in
 * "1.5" and the parser would reject valid JSON as malformed. strtod_l against a
 * pinned C locale reads it correctly in any locale. */
#define _GNU_SOURCE

#include "json.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <locale.h>

typedef struct {
    const char  *p;
    const char  *end;
    const char  *err;
    int          depth;
} jparse;


static json_value *parse_value(jparse *s);


static json_value *
value_new(json_type type)
{
    json_value *v = calloc(1, sizeof(json_value));

    if (v != NULL) {
        v->type = type;
    }

    return v;
}


void
json_free(json_value *v)
{
    size_t i;

    if (v == NULL) {
        return;
    }

    for (i = 0; i < v->count; i++) {
        if (v->keys != NULL) {
            free(v->keys[i]);
        }
        json_free(v->items[i]);
    }

    free(v->keys);
    free(v->items);
    free(v->string);
    free(v->numtext);
    free(v);
}


static void
skip_ws(jparse *s)
{
    while (s->p < s->end
           && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
    {
        s->p++;
    }
}


static int
literal(jparse *s, const char *word)
{
    size_t n = strlen(word);

    if ((size_t) (s->end - s->p) < n || memcmp(s->p, word, n) != 0) {
        return 0;
    }

    s->p += n;
    return 1;
}


/*
 * How many CONTINUATION bytes a UTF-8 lead byte announces, or -1 if the byte
 * cannot start a sequence. 0xC0 and 0xC1 are excluded because the only code
 * points they can encode are overlong forms of ASCII, and 0xF5..0xFF because
 * they encode above U+10FFFF -- both are rejected at the lead byte rather than
 * after decoding, which is the cheaper half of the same check.
 */
static int
utf8_tail_len(unsigned char lead)
{
    if (lead < 0xC2) {
        return -1;              /* a bare continuation byte, or an overlong lead */
    }
    if (lead < 0xE0) {
        return 1;
    }
    if (lead < 0xF0) {
        return 2;
    }
    if (lead < 0xF5) {
        return 3;
    }
    return -1;
}


/*
 * Grow-and-append one byte. parse_string_raw() appends a whole multi-byte
 * sequence at a time, so the growth check cannot stay inlined at a single
 * call site the way it used to be. Returns 0 on allocation failure with the
 * caller's buffer left intact and still owned by the caller.
 */
static int
str_push(char **out, size_t *len, size_t *cap, char c)
{
    if (*len + 1 >= *cap) {
        char *bigger;

        *cap *= 2;
        bigger = realloc(*out, *cap);
        if (bigger == NULL) {
            return 0;
        }
        *out = bigger;
    }

    (*out)[(*len)++] = c;
    return 1;
}


/*
 * Validate one UTF-8 sequence at s->p-1 (its lead byte already consumed and
 * passed in) and append every byte of it to the caller's buffer, advancing
 * s->p past the continuation bytes. Returns NULL on success, or the error
 * string to report -- the caller owns the buffer and frees it.
 *
 * The bytes are copied VERBATIM rather than re-encoded from the decoded code
 * point: json_canonicalize re-emits this buffer and body_sha256 hashes it, so
 * a decode/re-encode round trip would be an opportunity to change the document
 * for no benefit.
 */
static const char *
utf8_copy_sequence(jparse *s, unsigned char lead, char **out, size_t *len,
                   size_t *cap)
{
    int           tail = utf8_tail_len(lead);
    unsigned int  cp;
    int           i;

    if (tail < 0) {
        return "invalid UTF-8 in string";
    }

    cp = (unsigned int) (lead & (0xFF >> (unsigned) (tail + 2)));

    if (!str_push(out, len, cap, (char) lead)) {
        return "out of memory";
    }

    for (i = 0; i < tail; i++) {
        unsigned char t;

        if (s->p >= s->end) {
            return "truncated UTF-8 sequence in string";
        }

        t = (unsigned char) *s->p;

        if ((t & 0xC0) != 0x80) {
            return "invalid UTF-8 in string";
        }

        s->p++;
        cp = (cp << 6) | (unsigned int) (t & 0x3F);

        if (!str_push(out, len, cap, (char) t)) {
            return "out of memory";
        }
    }

    /* The two checks the lead byte cannot make on its own: an overlong three-
     * or four-byte form (the shape that smuggles an ASCII byte past a
     * byte-comparing filter), and the UTF-16 surrogate halves, which are not
     * characters and which RFC 8259 s.8.1 excludes. */
    if ((tail == 2 && cp < 0x800)
        || (tail == 3 && cp < 0x10000)
        || (cp >= 0xD800 && cp <= 0xDFFF)
        || cp > 0x10FFFF)
    {
        return "invalid UTF-8 in string";
    }

    return NULL;
}


/*
 * Strings: the probe emits plain ASCII plus the two-character escapes below.
 * \u is rejected rather than silently mishandled -- a harness that quietly
 * mangles input it does not understand produces wrong verdicts, and the
 * producer is ours, so an unexpected \u means the document changed and the
 * parser should be updated to match.
 *
 * Bytes at or above 0x80 are validated as UTF-8 (RFC 8259 s.8.1) instead of
 * being copied through. json_sort() re-emits whatever the parser accepted, so
 * a parser that passes 0xC0 through canonicalizes a document that is not JSON
 * into another document that is not JSON -- and body_sha256 then certifies it.
 */
static char *
parse_string_raw(jparse *s)
{
    char    *out;
    size_t   len = 0, cap = 32;

    if (s->p >= s->end || *s->p != '"') {
        s->err = "expected string";
        return NULL;
    }

    s->p++;

    out = malloc(cap);
    if (out == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    while (s->p < s->end && *s->p != '"') {
        char c = *s->p++;

        if (c == '\\') {
            if (s->p >= s->end) {
                break;
            }

            switch (*s->p++) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            default:
                s->err = "unsupported string escape";
                free(out);
                return NULL;
            }

        } else if ((unsigned char) c < 0x20) {
            /* RFC 8259 requires C0 controls to be escaped. Accepting a raw one
             * would let a probe document with a stray newline or NUL inside a
             * string still parse, which is the shape a rendering bug takes. */
            s->err = "raw control character in string";
            free(out);
            return NULL;

        } else if ((unsigned char) c >= 0x80) {
            const char *bad = utf8_copy_sequence(s, (unsigned char) c,
                                                 &out, &len, &cap);

            if (bad != NULL) {
                s->err = bad;
                free(out);
                return NULL;
            }

            continue;
        }

        if (!str_push(&out, &len, &cap, c)) {
            s->err = "out of memory";
            free(out);
            return NULL;
        }
    }

    if (s->p >= s->end || *s->p != '"') {
        s->err = "unterminated string";
        free(out);
        return NULL;
    }

    s->p++;
    out[len] = '\0';

    return out;
}


static int
container_push(json_value *v, char *key, json_value *item)
{
    json_value **items;
    char       **keys;

    items = realloc(v->items, (v->count + 1) * sizeof(json_value *));
    if (items == NULL) {
        return -1;
    }
    v->items = items;

    if (key != NULL) {
        keys = realloc(v->keys, (v->count + 1) * sizeof(char *));
        if (keys == NULL) {
            /* v->items was already grown, but count is not bumped, so the slot
             * is not live and the caller still owns `item`. Say so by failing
             * before anything is published rather than half-committing. */
            return -1;
        }
        v->keys = keys;
        v->keys[v->count] = key;
    }

    v->items[v->count] = item;
    v->count++;

    return 0;
}


static json_value *
parse_object(jparse *s)
{
    json_value *v = value_new(JSON_OBJECT);

    if (v == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    s->p++;                                                   /* consume '{' */
    skip_ws(s);

    if (s->p < s->end && *s->p == '}') {
        s->p++;
        return v;
    }

    for ( ;; ) {
        char       *key;
        size_t      i;
        json_value *item;

        skip_ws(s);

        key = parse_string_raw(s);
        if (key == NULL) {
            json_free(v);
            return NULL;
        }

        skip_ws(s);

        if (s->p >= s->end || *s->p != ':') {
            s->err = "expected ':' after object key";
            free(key);
            json_free(v);
            return NULL;
        }
        s->p++;

        item = parse_value(s);
        if (item == NULL) {
            free(key);
            json_free(v);
            return NULL;
        }

        /*
         * A repeated key would be invisible: json_get() returns the first
         * match, so the second value could never be asserted on. The document
         * is produced by the probe, and the way a duplicate gets there is a
         * module's zone_render hook emitting a member the generic side already
         * emitted -- a defect in the thing under test, which should surface as
         * a broken probe rather than as a value silently shadowing another.
         */
        for (i = 0; i < v->count; i++) {
            if (strcmp(v->keys[i], key) == 0) {
                s->err = "duplicate key in object";
                free(key);
                json_free(item);
                json_free(v);
                return NULL;
            }
        }

        if (container_push(v, key, item) != 0) {
            s->err = "out of memory";
            free(key);
            json_free(item);
            json_free(v);
            return NULL;
        }

        skip_ws(s);

        if (s->p < s->end && *s->p == ',') {
            s->p++;
            continue;
        }

        if (s->p < s->end && *s->p == '}') {
            s->p++;
            return v;
        }

        s->err = "expected ',' or '}' in object";
        json_free(v);
        return NULL;
    }
}


static json_value *
parse_array(jparse *s)
{
    json_value *v = value_new(JSON_ARRAY);

    if (v == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    s->p++;                                                   /* consume '[' */
    skip_ws(s);

    if (s->p < s->end && *s->p == ']') {
        s->p++;
        return v;
    }

    for ( ;; ) {
        json_value *item = parse_value(s);

        if (item == NULL) {
            json_free(v);
            return NULL;
        }

        if (container_push(v, NULL, item) != 0) {
            s->err = "out of memory";
            json_free(item);
            json_free(v);
            return NULL;
        }

        skip_ws(s);

        if (s->p < s->end && *s->p == ',') {
            s->p++;
            continue;
        }

        if (s->p < s->end && *s->p == ']') {
            s->p++;
            return v;
        }

        s->err = "expected ',' or ']' in array";
        json_free(v);
        return NULL;
    }
}


/*
 * Validate a collected token against the RFC 8259 number grammar:
 *
 *     -? ( 0 | [1-9][0-9]* ) ( '.' [0-9]+ )? ( [eE] [+-]? [0-9]+ )?
 *
 * strtod() alone is far more permissive -- it takes "+1", ".5", "0x10", "inf",
 * and leading-zero forms JSON forbids. The probe renderer emits plain integers,
 * so anything else in the document means the renderer misformatted a field, and
 * a lenient parser would turn that into a silently passing assertion.
 */
static int
number_token_is_json(const char *t)
{
    const char *p = t;

    if (*p == '-') {
        p++;
    }

    if (*p == '0') {
        p++;                                    /* no leading zeros allowed */

    } else if (*p >= '1' && *p <= '9') {
        while (*p >= '0' && *p <= '9') {
            p++;
        }

    } else {
        return 0;                               /* "+1", ".5", "" */
    }

    if (*p == '.') {
        p++;

        if (*p < '0' || *p > '9') {
            return 0;                           /* "1." */
        }

        while (*p >= '0' && *p <= '9') {
            p++;
        }
    }

    if (*p == 'e' || *p == 'E') {
        p++;

        if (*p == '+' || *p == '-') {
            p++;
        }

        if (*p < '0' || *p > '9') {
            return 0;                           /* "1e", "1e+" */
        }

        while (*p >= '0' && *p <= '9') {
            p++;
        }
    }

    return *p == '\0';
}


/*
 * Copy a validated JSON number token into `out` (size `cap`) in canonical form
 * so that lexemes denoting the same value collapse to identical bytes without
 * ever going through a double. The integer and fraction parts are exact-JSON
 * already (no leading zeros, no leading '+', digits after '.'), so only the
 * exponent varies for an equal value: `E` -> `e`, a '+' sign dropped, and
 * leading zeros in the exponent digits stripped ("1E+05" -> "1e5"). "1" and
 * "1.0" are DIFFERENT lexemes and intentionally stay distinct. Returns the
 * written length, or -1 if `cap` is too small (the caller sized it off the
 * source token, which cannot grow under these edits, so this cannot fire).
 */
static int
number_canon(const char *t, char *out, size_t cap)
{
    size_t o = 0;

    while (*t != '\0' && *t != 'e' && *t != 'E') {
        if (o + 1 >= cap) {
            return -1;
        }
        out[o++] = *t++;
    }

    if (*t == 'e' || *t == 'E') {
        const char *e = t + 1;
        int         neg = 0;

        if (*e == '+' || *e == '-') {
            neg = (*e == '-');
            e++;
        }

        while (*e == '0' && *(e + 1) >= '0' && *(e + 1) <= '9') {
            e++;                                    /* strip leading zeros */
        }

        if (o + 1 >= cap) {
            return -1;
        }
        out[o++] = 'e';

        if (neg) {
            if (o + 1 >= cap) {
                return -1;
            }
            out[o++] = '-';
        }

        while (*e >= '0' && *e <= '9') {
            if (o + 1 >= cap) {
                return -1;
            }
            out[o++] = *e++;
        }
    }

    out[o] = '\0';
    return (int) o;
}


/*
 * strtod() honoring the C locale's '.' radix, whatever the process LC_NUMERIC.
 * The C locale is created once on first use (the harness is single-threaded, so
 * a plain static is safe). newlocale() only fails under memory pressure so
 * extreme the parse is doomed anyway; rather than fall back to plain strtod()
 * -- which would silently reintroduce the LC_NUMERIC dependence this exists to
 * remove, so "1.5" could fail to parse under a comma-decimal locale -- signal
 * the setup failure through *ok and let the caller fail the number explicitly.
 * On success *ok is 1 and the return value is the parsed double; on failure *ok
 * is 0 and the return value is unspecified.
 */
static double
json_strtod(const char *buf, char **stop, int *ok)
{
    static locale_t c_loc = (locale_t) 0;
    static int      tried = 0;

    if (!tried) {
        tried = 1;
        c_loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
    }

    if (c_loc == (locale_t) 0) {
        *ok = 0;
        return 0.0;
    }

    *ok = 1;
    return strtod_l(buf, stop, c_loc);
}


/*
 * The shared number gate -- see json.h. The document parser does not call this
 * because it needs to tell "malformed" apart from "no C locale" in its own
 * error string; it applies the same three checks in the same order, and
 * `parse_number` says so at each one.
 */
int
json_number_parse(const char *token, double *out)
{
    char  *stop;
    double v;
    int    loc_ok;

    if (!number_token_is_json(token)) {
        return 0;
    }

    v = json_strtod(token, &stop, &loc_ok);

    if (!loc_ok || stop == token || *stop != '\0' || !isfinite(v)) {
        return 0;
    }

    *out = v;
    return 1;
}


static json_value *
parse_number(jparse *s)
{
    char        buf[64];
    char       *stop;
    size_t      n = 0;
    json_value *v;

    /*
     * The byte set is spelled out rather than looked up with strchr(), because
     * strchr() answers for the search string's own terminator: strchr("-+.eE",
     * '\0') is non-NULL, so a NUL adjacent to a number was consumed into the
     * token as if it were a digit. The token is then a C string, so the NUL
     * ENDED it and "12\0 34" read as the number 12 -- the document parsed, and
     * json_parse_n's whole purpose is to refuse a body that was truncated or
     * spliced. It is the one byte in the document that must never be part of
     * a token.
     */
    while (s->p < s->end
           && (*s->p == '-' || *s->p == '+' || *s->p == '.'
               || *s->p == 'e' || *s->p == 'E'
               || (*s->p >= '0' && *s->p <= '9')))
    {
        /* Truncating the token and parsing the prefix would turn an absurd
         * number into a plausible one, so overflow is an error, not a clamp. */
        if (n + 1 >= sizeof(buf)) {
            s->err = "number too long";
            return NULL;
        }

        buf[n++] = *s->p++;
    }

    buf[n] = '\0';

    if (!number_token_is_json(buf)) {
        s->err = "malformed number";
        return NULL;
    }

    v = value_new(JSON_NUMBER);
    if (v == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    {
        int loc_ok;
        v->number = json_strtod(buf, &stop, &loc_ok);
        if (!loc_ok) {
            s->err = "could not create a C locale to parse the number";
            json_free(v);
            return NULL;
        }
    }

    if (stop == buf || *stop != '\0') {
        s->err = "malformed number";
        json_free(v);
        return NULL;
    }

    /* "1e999" is grammatical JSON that strtod() turns into infinity. Infinity
     * compares as a number under every operator, so an assertion against it
     * would return a confident verdict about a value this document cannot
     * actually represent. Refuse rather than approximate. */
    if (!isfinite(v->number)) {
        s->err = "number is out of range for a double";
        json_free(v);
        return NULL;
    }

    /* Keep the canonical source lexeme for verbatim emission (see json.h).
     * The canonical form never grows past the source token, so sizeof(buf)
     * always suffices. */
    v->numtext = malloc(n + 1);
    if (v->numtext == NULL) {
        s->err = "out of memory";
        json_free(v);
        return NULL;
    }

    if (number_canon(buf, v->numtext, n + 1) < 0) {
        s->err = "malformed number";                /* unreachable: cannot grow */
        json_free(v);
        return NULL;
    }

    return v;
}


static json_value *
parse_value(jparse *s)
{
    json_value *v;

    skip_ws(s);

    if (s->p >= s->end) {
        s->err = "unexpected end of document";
        return NULL;
    }

    switch (*s->p) {

    case '{':
    case '[': {
        json_value *container;

        /* Bounded because the parser recurses and the document arrives from a
         * worker that may be in the middle of failing. A truncated or garbled
         * body should be a parse error, not a stack overflow in the harness
         * that was supposed to report it. */
        if (s->depth >= JSON_MAX_DEPTH) {
            s->err = "nesting too deep";
            return NULL;
        }

        s->depth++;
        container = (*s->p == '{') ? parse_object(s) : parse_array(s);
        s->depth--;

        return container;
    }

    case '"':
        v = value_new(JSON_STRING);
        if (v == NULL) {
            s->err = "out of memory";
            return NULL;
        }
        v->string = parse_string_raw(s);
        if (v->string == NULL) {
            json_free(v);
            return NULL;
        }
        return v;

    default:
        break;
    }

    if (literal(s, "true") || literal(s, "false")) {
        v = value_new(JSON_BOOL);
        if (v == NULL) {
            s->err = "out of memory";
            return NULL;
        }
        /* literal() already advanced; recover which one from the last char. */
        v->boolean = (s->p[-1] == 'e' && s->p[-2] == 'u') ? 1 : 0;
        return v;
    }

    if (literal(s, "null")) {
        return value_new(JSON_NULL);
    }

    return parse_number(s);
}


json_value *
json_parse(const char *text, const char **err)
{
    /* Length-delimited by strlen for callers that have a NUL-terminated string
     * and no separate length. A body that may carry an embedded NUL must use
     * json_parse_n instead: strlen would stop at the first NUL and this parser
     * would then accept whatever valid prefix preceded it while ignoring the
     * trailing bytes -- exactly the truncation json_parse_n exists to reject. */
    return json_parse_n(text, strlen(text), err);
}


json_value *
json_parse_n(const char *text, size_t len, const char **err)
{
    jparse      s;
    json_value *root;

    s.p = text;
    s.end = text + len;
    s.err = NULL;
    s.depth = 0;

    root = parse_value(&s);
    if (root == NULL) {
        if (err != NULL) {
            *err = s.err ? s.err : "parse failed";
        }
        return NULL;
    }

    skip_ws(&s);

    /* Trailing garbage is an error: it means the document was truncated and
     * re-sent, or two documents were concatenated. Either way the values we
     * would report are not the ones the caller thinks they are. */
    if (s.p != s.end) {
        if (err != NULL) {
            *err = "trailing garbage after document";
        }
        json_free(root);
        return NULL;
    }

    return root;
}


const json_value *
json_get(const json_value *root, const char *path)
{
    const json_value *cur = root;
    const char       *p = path;

    /*
     * Every segment must be non-empty, which rules out "", "zone.", ".zone"
     * and "zone..nodes".
     *
     * Without this, a trailing dot resolves to the PARENT: "zone." walks into
     * the zone object, finds no further segment, and returns it. A rule reading
     * `probe zone. == 1` would then be compared against an object and reported
     * as a type error -- close enough to look like a real failure, far enough
     * from the truth to send someone looking in the wrong place. A malformed
     * path is not a value.
     */
    if (*p == '\0') {
        return NULL;
    }

    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t      len = (dot != NULL) ? (size_t) (dot - p) : strlen(p);
        size_t      i;
        int         found = 0;

        if (len == 0) {
            return NULL;                    /* ".x", "x..y", or a trailing "." */
        }

        if (cur == NULL || cur->type != JSON_OBJECT) {
            return NULL;
        }

        for (i = 0; i < cur->count; i++) {
            if (strlen(cur->keys[i]) == len
                && memcmp(cur->keys[i], p, len) == 0)
            {
                cur = cur->items[i];
                found = 1;
                break;
            }
        }

        if (!found) {
            return NULL;
        }

        if (dot == NULL) {
            break;
        }

        p = dot + 1;

        /* The loop's own condition would end the walk here and hand back the
         * object we just descended into, so a trailing dot has to be caught
         * before the next iteration rather than by the empty-segment check
         * above -- that check only sees segments the loop re-enters for. */
        if (*p == '\0') {
            return NULL;
        }
    }

    return cur;
}


/*
 * Canonical serialization (json_canonicalize).
 *
 * The point of the canonical form is that two documents differing ONLY in
 * object key order serialize to the same bytes, so a body_sha256 assertion on
 * the rendered output is order-independent. Everything else is preserved as
 * faithfully as the parse tree allows: key order is the only thing normalized
 * away. Concretely --
 *
 *   - object keys are emitted in strcmp() (byte, C-locale) order, recursively;
 *   - array order is PRESERVED (array order is semantic in JSON, not incidental
 *     like key order);
 *   - numbers are emitted from their normalized source lexeme (numtext) rather
 *     than round-tripped through a double: integers beyond 2^53 stay exact and
 *     distinct, and no LC_NUMERIC locale can turn '.' into ',' (there is no
 *     printf of a float on this path). 1 and 1.0 are distinct lexemes and stay
 *     distinct -- exactness beats numeric equivalence for an order oracle;
 *   - strings are re-escaped minimally: the RFC 8259 short escapes for
 *     " \ \b \f \n \r \t, and \u00XX for any other C0 control. '/' is left bare
 *     (escaping it is optional and the parser reads it either way). This is the
 *     inverse of parse_string_raw, which decoded those same escapes to bytes.
 *
 * No whitespace is emitted between tokens: canonical form is the most compact
 * one, so there is exactly one representation and nothing to disagree about.
 */

typedef struct {
    char    *buf;
    size_t   len;
    size_t   cap;
    int      err;       /* sticky: set once, never cleared */
} sbuf;


static void
sbuf_ensure(sbuf *b, size_t extra)
{
    if (b->err) {
        return;
    }

    if (b->len + extra + 1 > b->cap) {
        size_t  newcap = (b->cap != 0) ? b->cap : 64;
        char   *bigger;

        while (b->len + extra + 1 > newcap) {
            newcap *= 2;
        }

        bigger = realloc(b->buf, newcap);
        if (bigger == NULL) {
            b->err = 1;
            return;
        }
        b->buf = bigger;
        b->cap = newcap;
    }
}


static void
sbuf_putc(sbuf *b, char c)
{
    sbuf_ensure(b, 1);
    if (b->err) {
        return;
    }
    b->buf[b->len++] = c;
}


/* Append exactly `n` bytes of `s` (which need not be NUL-terminated). */
static void
sbuf_putn(sbuf *b, const char *s, size_t n)
{
    sbuf_ensure(b, n);
    if (b->err) {
        return;
    }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
}


static void
sbuf_puts(sbuf *b, const char *s)
{
    sbuf_putn(b, s, strlen(s));
}


/* Emit `s` as a quoted, canonically-escaped JSON string. */
static void
sbuf_put_jstring(sbuf *b, const char *s)
{
    static const char  hex[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *) s;

    sbuf_putc(b, '"');

    for (; *p != '\0'; p++) {
        unsigned char c = *p;

        switch (c) {
        case '"':  sbuf_puts(b, "\\\""); break;
        case '\\': sbuf_puts(b, "\\\\"); break;
        case '\b': sbuf_puts(b, "\\b");  break;
        case '\f': sbuf_puts(b, "\\f");  break;
        case '\n': sbuf_puts(b, "\\n");  break;
        case '\r': sbuf_puts(b, "\\r");  break;
        case '\t': sbuf_puts(b, "\\t");  break;
        default:
            if (c < 0x20) {
                /* Any other C0 control has no short escape; RFC 8259 requires
                 * it be escaped, so emit the six-character \u00XX form. */
                sbuf_puts(b, "\\u00");
                sbuf_putc(b, hex[(c >> 4) & 0xf]);
                sbuf_putc(b, hex[c & 0xf]);
            } else {
                sbuf_putc(b, (char) c);
            }
        }
    }

    sbuf_putc(b, '"');
}


/*
 * Sort an index array into strcmp() key order via insertion sort.
 *
 * Not qsort_r: its comparator signature differs between glibc and the BSDs and
 * would drag in _GNU_SOURCE for one call. Objects here are the probe document's
 * handful of members (and any JSON a rule feeds), so an O(n^2) sort on tiny n
 * is free and stays portable under the -Werror wall. The parse tree rejects
 * duplicate keys, so strcmp totally orders the members with no tiebreak.
 */
static void
sort_members(size_t *order, const json_value *obj)
{
    size_t  i, j;

    for (i = 1; i < obj->count; i++) {
        size_t  key = order[i];

        j = i;
        while (j > 0
               && strcmp(obj->keys[order[j - 1]], obj->keys[key]) > 0)
        {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = key;
    }
}


static void
canon_emit(sbuf *b, const json_value *v)
{
    size_t  i;

    if (b->err) {
        return;
    }

    switch (v->type) {

    case JSON_NULL:
        sbuf_puts(b, "null");
        break;

    case JSON_BOOL:
        sbuf_puts(b, v->boolean ? "true" : "false");
        break;

    case JSON_NUMBER:
        /* Emit the normalized source lexeme verbatim (json_parse stores it on
         * every JSON_NUMBER). No float is formatted here, so the output is both
         * exact for large integers and immune to LC_NUMERIC. numtext is NULL
         * only if a JSON_NUMBER was hand-built without going through the parser,
         * which the harness never does; guard rather than deref a stray NULL. */
        if (v->numtext == NULL) {
            b->err = 1;
            return;
        }
        sbuf_puts(b, v->numtext);
        break;

    case JSON_STRING:
        sbuf_put_jstring(b, v->string);
        break;

    case JSON_ARRAY:
        sbuf_putc(b, '[');
        for (i = 0; i < v->count; i++) {
            if (i != 0) {
                sbuf_putc(b, ',');
            }
            canon_emit(b, v->items[i]);
        }
        sbuf_putc(b, ']');
        break;

    case JSON_OBJECT: {
        size_t *order = NULL;

        if (v->count != 0) {
            order = malloc(v->count * sizeof(size_t));
            if (order == NULL) {
                b->err = 1;
                return;
            }
            for (i = 0; i < v->count; i++) {
                order[i] = i;
            }
            sort_members(order, v);
        }

        sbuf_putc(b, '{');
        for (i = 0; i < v->count; i++) {
            if (i != 0) {
                sbuf_putc(b, ',');
            }
            sbuf_put_jstring(b, v->keys[order[i]]);
            sbuf_putc(b, ':');
            canon_emit(b, v->items[order[i]]);
        }
        sbuf_putc(b, '}');

        free(order);
        break;
    }

    }
}


int
json_canonicalize(const json_value *v, char **out, size_t *out_len)
{
    sbuf  b = {0};

    if (v == NULL || out == NULL) {
        return -1;
    }

    canon_emit(&b, v);

    if (b.err) {
        free(b.buf);
        return -1;
    }

    /* canon_emit always writes at least one token, so b.buf is allocated; but
     * an empty document is impossible (json_parse rejects it) so len >= 1. The
     * NUL terminator slot was reserved by every sbuf_ensure. */
    b.buf[b.len] = '\0';

    *out = b.buf;
    if (out_len != NULL) {
        *out_len = b.len;
    }
    return 0;
}


const char *
json_type_name(json_type t)
{
    switch (t) {
    case JSON_NULL:   return "null";
    case JSON_BOOL:   return "boolean";
    case JSON_NUMBER: return "number";
    case JSON_STRING: return "string";
    case JSON_OBJECT: return "object";
    case JSON_ARRAY:  return "array";
    }

    return "unknown";
}
