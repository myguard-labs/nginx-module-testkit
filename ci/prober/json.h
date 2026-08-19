/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json.h -- minimal JSON reader for the probe document.
 *
 * Deliberately a real tokenizer rather than substring matching on the response
 * body. A grep for "\"nodes\":1" would pass on a document where nodes lives in
 * a different object, and would silently keep passing if the probe's shape ever
 * changed -- exactly the failure mode a harness must not have, since a test
 * that cannot fail is worse than no test.
 *
 * Scope is the probe document and nothing more: no \u escapes. Inputs come from
 * ngx_test_probe_json(), not from the network, so where there is a choice the
 * parser is strict rather than lenient -- anything it cannot represent exactly
 * is rejected instead of approximated, because an approximated value would be
 * compared by the assertion evaluator and reported as a pass or a fail with no
 * sign that it was a guess.
 *
 * Concretely, beyond RFC 8259 conformance it also rejects:
 *
 *   - duplicate keys in an object. json_get() would return the first, so the
 *     second would be silently invisible -- and the way a duplicate arises is a
 *     module hook rendering a member the generic probe already rendered, which
 *     is a bug in the thing under test.
 *   - numbers that do not survive as a finite double ("1e999"). Infinity
 *     compares as a number under every operator, so a rule asserting on it
 *     would produce a confident verdict about a value the document did not
 *     actually carry.
 *   - nesting deeper than JSON_MAX_DEPTH. The parser is recursive, and the
 *     document is read from a worker that may be in the middle of crashing.
 */

#ifndef PROBER_JSON_H
#define PROBER_JSON_H

#include <stddef.h>

/*
 * Nesting limit. The probe document is three deep (zone.fault.slab_nth), so
 * this is far above anything legitimate; it exists to bound the recursion, not
 * to constrain the shape.
 */
#define JSON_MAX_DEPTH  32

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_OBJECT,
    JSON_ARRAY
} json_type;

typedef struct json_value json_value;

struct json_value {
    json_type    type;
    double       number;    /* JSON_NUMBER: value for numeric comparisons */
    char        *numtext;   /* JSON_NUMBER: normalized source lexeme, emitted
                             * verbatim by json_canonicalize so integers beyond
                             * 2^53 stay exact and no locale can reach it */
    int          boolean;
    char        *string;    /* JSON_STRING only, NUL-terminated */
    char       **keys;      /* JSON_OBJECT only, parallel to items */
    json_value **items;     /* JSON_OBJECT / JSON_ARRAY members */
    size_t       count;
};

/*
 * Parse a complete document. Returns NULL on malformed input or trailing
 * garbage; on failure, and if err is non-NULL, *err points at a static
 * description. The result is owned by the caller: free with json_free().
 */
json_value *json_parse(const char *text, const char **err);

/*
 * Parse a bare number token under the document's own rules: the RFC 8259
 * grammar (no "+1", ".5", "0x10", "inf", "nan", leading zeros or trailing
 * text), a radix point that is '.' whatever LC_NUMERIC says, and a finite
 * result. Returns 1 and stores the value in *out on success, 0 otherwise.
 *
 * Exported so the RULE side can be held to the same grammar as the DOCUMENT
 * side by calling the same code. Two hand-written validators for one grammar
 * drift, and the direction that drifted here accepted `!= nan` -- an assertion
 * true for every finite value, which is the one defect class this harness may
 * not contain.
 */
int json_number_parse(const char *token, double *out);

/*
 * Parse a document of exactly `len` bytes, which MAY contain embedded NULs.
 *
 * json_parse() length-delimits with strlen and so silently truncates at the
 * first NUL: valid JSON followed by a NUL and then garbage would be accepted,
 * because strlen stops before the garbage and the trailing-bytes check never
 * sees it. A caller that already knows the body length (an HTTP response with a
 * Content-Length, a probe reply) must pass it here so the whole body is parsed
 * and trailing garbage after a NUL is rejected like any other. json_parse() is
 * now a thin strlen wrapper over this.
 */
json_value *json_parse_n(const char *text, size_t len, const char **err);

void json_free(json_value *v);

/*
 * Look up a dotted path, e.g. "zone.nodes". Returns NULL if any component is
 * missing or if a non-object is traversed. Array indexing is not supported --
 * the probe document has no arrays, and inventing the syntax before there is a
 * caller for it would be speculative.
 */
const json_value *json_get(const json_value *root, const char *path);

/* Human-readable type name, for assertion failure diagnostics. */
const char *json_type_name(json_type t);

/*
 * Serialize `v` into its canonical form: object keys byte-sorted recursively,
 * arrays preserved, minimal string escaping, numbers emitted from their
 * normalized source lexeme (see numtext), no inter-token whitespace. Two
 * documents differing only in object key order produce byte-identical output,
 * so a hash over it is key-order-independent. Numbers are emitted verbatim
 * rather than round-tripped through a double, so integers beyond 2^53 stay
 * distinct (9007199254740992 != ...993) and no LC_NUMERIC locale can turn the
 * decimal point into a comma; the cost is that 1 and 1.0 canonicalize to
 * distinct bytes (they are distinct lexemes) -- exactness is preferred over
 * numeric equivalence for a key-order oracle.
 *
 * On success returns 0 and stores a malloc'd, NUL-terminated buffer in *out
 * (owned by the caller; free with free()); *out_len, if non-NULL, gets its
 * length excluding the terminator. Returns -1 on allocation failure; *out is
 * untouched on failure.
 */
int json_canonicalize(const json_value *v, char **out, size_t *out_len);

#endif /* PROBER_JSON_H */
