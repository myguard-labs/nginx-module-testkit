/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * schema_test.c -- the probe document keeps the shape ../../probe-schema.json
 * promises.
 *
 * A rule that NAMES a field already fails loudly when the probe stops emitting
 * it: eval_probe reports `probe path "..." not present in document`. This suite
 * covers the half that is otherwise silent -- a field renamed, retyped or
 * dropped while no current rule happens to reference it, which stays invisible
 * until someone writes a rule against it much later and reads the failure as a
 * bug in their rule.
 *
 * Two directions, and both are needed:
 *
 *   FORWARD  every field the schema promises is present, with the promised
 *            type, in a document of the matching variant. Catches a drop or a
 *            retype.
 *
 *   REVERSE  every member the emitter renders at a closed level is named by
 *            the schema. Catches an ADDED field that nobody wrote down --
 *            without this the schema decays into a subset that passes forever
 *            while describing less and less of the document.
 *
 * The schema is read as text rather than linked as a struct on purpose: the
 * point is to check the checked-in file, and a copy compiled into this binary
 * would drift from it exactly as silently as the thing being guarded against.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

/*
 * Both variants of the document, matching what ngx_test_probe_json() renders.
 * The zone-present text is deliberately identical to the fixture in
 * assert_test.c: two fixtures for one emitter that disagree would leave no way
 * to tell which one is stale.
 *
 * `nodes` is here because a module hook may render extra members inside the
 * zone object. It must NOT trip the reverse check -- that is the difference
 * between a closed level and an open one.
 *
 * `module` is the same idea one level up, and it is why "rich" is the right
 * name for this variant rather than "zone-present". A module registering a
 * module_render hook gets a top-level "module" object whose CONTENTS are its
 * own (frames, here), rendered independently of any zone -- that is the whole
 * point of the hook: a module with no shm zone at all reaches the document
 * only through it. So "module" is an open level like "zone", and it is
 * OPTIONAL at the top level, present only when such a hook is registered.
 */
static const char doc_zone_present[] =
    "{\"flavor\":\"nginx\",\"flavor_version\":\"1.29.0\",\"pid\":1234,"
    "\"ppid\":1,\"config_generation\":3,"
    "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
    "\"fds\":9,\"timers\":6,"
    "\"fds_by_kind\":{\"socket\":4,\"file\":3,\"anon\":1,\"other\":1},"
    "\"smaps\":{\"pss\":184,\"private_dirty\":112},"
    "\"pool\":{\"cycle_used\":2048,\"cycle_blocks\":1,"
    "\"cycle_large\":0,\"cycle_cleanup\":2},"
    "\"module\":{\"frames\":7},"
    "\"zone\":{\"present\":true,\"name\":\"demo\",\"size\":1048576,"
    "\"slab_pages_free\":248,\"nodes\":2}}";

/* The zone-absent tail is a literal in the emitter, so it is a literal here. */
static const char doc_zone_absent[] =
    "{\"flavor\":\"nginx\",\"flavor_version\":\"1.29.0\",\"pid\":1234,"
    "\"ppid\":1,\"config_generation\":3,"
    "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
    "\"fds\":9,\"timers\":6,"
    "\"fds_by_kind\":{\"socket\":4,\"file\":3,\"anon\":1,\"other\":1},"
    "\"smaps\":{\"pss\":184,\"private_dirty\":112},"
    "\"pool\":{\"cycle_used\":2048,\"cycle_blocks\":1,"
    "\"cycle_large\":0,\"cycle_cleanup\":2},"
    "\"zone\":{\"present\":false}}";

/*
 * R-10's regression fixture: a zone that is not NULL (a module passed one to
 * ngx_test_probe_json()) but whose shared memory is not mapped yet --
 * zone->shm.addr == NULL, the reload race the emitter's own comment above
 * ngx_test_probe_json() documents as legitimate. The emitter renders the
 * exact same "present":false tail as the zone == NULL case here (both early
 * returns share one ngx_slprintf call), so this fixture is BYTE-IDENTICAL to
 * doc_zone_absent.
 *
 * Be honest about what that means: these fixtures are hand-written literals,
 * not the emitter's output, so this block CANNOT catch R-10 regressing and it
 * is not what caught the R-10 mutation row -- schema_emitter_test.sh is, by
 * checking the emitter source itself carries the present:false tail on both
 * early returns. What this document pins is the CONSUMER side: it states, in
 * the same place the other two variants are stated, that a present:false zone
 * from the shm.addr == NULL path promises no siblings either, so a future
 * edit that starts treating the two present:false cases as different shapes
 * has to change this file and confront the claim.
 */
static const char doc_zone_shm_unmapped[] =
    "{\"flavor\":\"nginx\",\"flavor_version\":\"1.29.0\",\"pid\":1234,"
    "\"ppid\":1,\"config_generation\":3,"
    "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
    "\"fds\":9,\"timers\":6,"
    "\"fds_by_kind\":{\"socket\":4,\"file\":3,\"anon\":1,\"other\":1},"
    "\"smaps\":{\"pss\":184,\"private_dirty\":112},"
    "\"pool\":{\"cycle_used\":2048,\"cycle_blocks\":1,"
    "\"cycle_large\":0,\"cycle_cleanup\":2},"
    "\"zone\":{\"present\":false}}";

/*
 * What the schema promises, transcribed. Keeping this beside the fixtures
 * rather than parsing probe-schema.json into a generic validator is the
 * smaller of two evils: a hand-rolled schema-language interpreter would be a
 * second parser to test, and its bugs would show up as false greens here. The
 * file is instead checked for agreement field-by-field below, so a schema edit
 * that is not mirrored here fails rather than passing unnoticed.
 */
/*
 * `rich_only` marks a field the emitter renders only in the "rich" variant --
 * the fixture with both a mapped zone and a module_render hook. Two unrelated
 * reasons put a field there and the flag deliberately does not distinguish
 * them, because the assertion is the same either way: the field must be
 * ABSENT from the leaner variants, not rendered as a fabricated zero.
 *
 *   zone.name / zone.size / zone.slab_pages_free  -- present:false promises
 *   no siblings (R-10).
 *
 *   module  -- rendered only when a module_render hook is registered; the
 *   reference module in t/module registers none, so its documents carry no
 *   "module" member at all and a required:true here would be a lie.
 */
typedef struct {
    const char *path;
    json_type   type;
    int         rich_only;
} schema_field;

static const schema_field SCHEMA[] = {
    { "flavor",              JSON_STRING, 0 },
    { "flavor_version",      JSON_STRING, 0 },
    { "pid",                 JSON_NUMBER, 0 },
    { "ppid",                JSON_NUMBER, 0 },
    { "config_generation",   JSON_NUMBER, 0 },
    { "page_size",           JSON_NUMBER, 0 },
    { "connections",         JSON_OBJECT, 0 },
    { "connections.total",   JSON_NUMBER, 0 },
    { "connections.free",    JSON_NUMBER, 0 },
    { "fds",                 JSON_NUMBER, 0 },
    { "timers",              JSON_NUMBER, 0 },
    { "fds_by_kind",         JSON_OBJECT, 0 },
    { "fds_by_kind.socket",  JSON_NUMBER, 0 },
    { "fds_by_kind.file",    JSON_NUMBER, 0 },
    { "fds_by_kind.anon",    JSON_NUMBER, 0 },
    { "fds_by_kind.other",   JSON_NUMBER, 0 },
    { "smaps",               JSON_OBJECT, 0 },
    { "smaps.pss",           JSON_NUMBER, 0 },
    { "smaps.private_dirty", JSON_NUMBER, 0 },
    { "pool",                JSON_OBJECT, 0 },
    { "pool.cycle_used",     JSON_NUMBER, 0 },
    { "pool.cycle_blocks",   JSON_NUMBER, 0 },
    { "pool.cycle_large",    JSON_NUMBER, 0 },
    { "pool.cycle_cleanup",  JSON_NUMBER, 0 },
    { "module",              JSON_OBJECT, 1 },
    { "zone",                JSON_OBJECT, 0 },
    { "zone.present",        JSON_BOOL,   0 },
    { "zone.name",           JSON_STRING, 1 },
    { "zone.size",           JSON_NUMBER, 1 },
    { "zone.slab_pages_free",JSON_NUMBER, 1 }
};

#define SCHEMA_N  ((int) (sizeof(SCHEMA) / sizeof(SCHEMA[0])))

/*
 * Levels where the emitter renders a fixed set of members, so an unexpected
 * one means drift. "zone" and "module" are absent from this list by design:
 * zone_render lets a consuming module add its own members to the first, and
 * module_render owns the entire contents of the second.
 *
 * The top level "" stays closed, which is what makes "module" have to be
 * written down here at all -- an unnamed top-level object would fail the
 * reverse check rather than slipping in undocumented.
 */
static const char *CLOSED_LEVELS[] = {
    "", "connections", "fds_by_kind", "smaps", "pool"
};

#define CLOSED_N  ((int) (sizeof(CLOSED_LEVELS) / sizeof(CLOSED_LEVELS[0])))

/*
 * Count of field entries actually found in probe-schema.json's "fields"
 * block, filled in by count_schema_file_fields() before PLANNED is used.
 * The reverse schema-file check below needs one "ok" per line found there,
 * so the plan has to know that count up front -- see main().
 */
static int schema_file_field_n = 0;

/*
 * SCHEMA_N schema fields against the zone-present document, SCHEMA_N against
 * the zone-absent one and SCHEMA_N again against the shm-unmapped one (the
 * three zone-present-only members are asserted ABSENT in the latter two,
 * which is the same count either way), CLOSED_N closed levels, SCHEMA_N
 * schema-file agreement checks (FORWARD: every SCHEMA[] entry is named in
 * the file), schema_file_field_n schema-file agreement checks (REVERSE:
 * every field named in the file is in SCHEMA[]), plus the three parses.
 */
#define PLANNED \
    (SCHEMA_N + SCHEMA_N + SCHEMA_N + CLOSED_N + SCHEMA_N + \
     schema_file_field_n + 3)

static int tests_run = 0;
static int failures  = 0;

static void ok(int cond, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void
ok(int cond, const char *fmt, ...)
{
    va_list ap;

    tests_run++;

    if (!cond) {
        failures++;
        printf("not ok %d - ", tests_run);
    } else {
        printf("ok %d - ", tests_run);
    }

    /* fmt is not attacker-controlled: the __attribute__((format(printf, 2,
     * 3))) above makes the compiler check every call site against a literal
     * format string (this is a self-test binary with no external input in
     * the first place). */
    va_start(ap, fmt);
    vprintf(fmt, ap);  /* flawfinder: ignore */
    va_end(ap);
    printf("\n");
}

/* Read the checked-in schema so its text can be checked, not a copy of it. */
static char *
slurp(const char *path)
{
    FILE   *f = fopen(path, "rb");
    char   *buf;
    long    n;

    if (f == NULL) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
        fclose(f);
        return NULL;
    }

    rewind(f);

    buf = malloc((size_t) n + 1);

    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t) n, f) != (size_t) n) {
        free(buf);
        fclose(f);
        return NULL;
    }

    buf[n] = '\0';
    fclose(f);

    return buf;
}

/*
 * Pull every field name out of probe-schema.json's "fields" object, in file
 * order, into out[] (capacity max). Returns the count found, or -1 if the
 * document does not parse or has no "fields" object.
 *
 * This uses the same json.c the prober itself uses rather than scanning the
 * text. A hand-rolled scanner lived here first and counted raw '{' and '}'
 * bytes inside field values without treating quoted strings as opaque, so a
 * '}' inside any string value -- a "note" or a description, the style this
 * very file already uses -- desynced the depth counter and silently dropped
 * every field after it. Measured: one injected "closes here }" cut the
 * reverse sweep from 26 checks to 1 and the suite still exited 0. A gate that
 * quietly stops checking is worse than no gate, and this repo already links a
 * parser that gets strings, escapes and nesting right.
 */
static int
extract_schema_file_fields(const char *text, char out[][160], int max)
{
    const char       *err = NULL;
    json_value       *root;
    const json_value *fields;
    size_t            i;
    int               n = 0;

    root = json_parse(text, &err);

    if (root == NULL) {
        return -1;
    }

    fields = json_get(root, "fields");

    if (fields == NULL || fields->type != JSON_OBJECT) {
        json_free(root);
        return -1;
    }

    for (i = 0; i < fields->count && n < max; i++) {
        size_t len = strlen(fields->keys[i]);

        /* A key too long for the buffer is skipped rather than truncated:
         * a truncated name could spuriously match a shorter SCHEMA[] entry
         * and turn a real mismatch into a pass. */
        if (len == 0 || len >= sizeof(out[0])) {
            continue;
        }

        memcpy(out[n], fields->keys[i], len);
        out[n][len] = '\0';
        n++;
    }

    json_free(root);

    return n;
}

/* Capacity for the reverse schema-file scan: comfortably above SCHEMA_N so
 * a schema file that grows past the current field count still gets a real
 * count instead of silently truncating. */
#define SCHEMA_FILE_FIELD_MAX  128

int
main(void)
{
    json_value *present;
    json_value *absent;
    json_value *shm_unmapped;
    const char *err = NULL;
    char       *schema_text;
    char        schema_file_fields[SCHEMA_FILE_FIELD_MAX][160];
    int         i;
    int         j;

    /*
     * Read the schema file and extract its field list BEFORE printing the
     * plan line: the reverse check's test count depends on how many fields
     * the file actually names, and TAP requires the plan up front.
     */
    schema_text = slurp("../../probe-schema.json");

    if (schema_text != NULL) {
        schema_file_field_n =
            extract_schema_file_fields(schema_text, schema_file_fields,
                                        SCHEMA_FILE_FIELD_MAX);

        if (schema_file_field_n < 0) {
            schema_file_field_n = 0;
        }
    } else {
        schema_file_field_n = 0;
    }

    /*
     * Zero extracted fields is a FAILURE, not an empty check set. The reverse
     * direction exists to catch drift between probe-schema.json and SCHEMA[],
     * and every way the extraction can come back empty -- file moved or
     * unreadable, "fields" renamed, the object reshaped -- is itself that
     * drift. Degrading to "ran no reverse checks, exit 0" would let the one
     * edit most likely to need this gate be the edit that silently removes it.
     * Measured before this guard existed: renaming "fields" in the schema
     * dropped all 26 reverse checks and still exited 0.
     *
     * Not folded into the loop below: with a count of 0 that loop body never
     * runs, so the failure has to be stated outside it, and it has to be in
     * the plan (hence the +1 in PLANNED) to avoid a ran-vs-planned mismatch.
     */
    if (schema_file_field_n <= 0) {
        printf("1..1\n");
        printf("not ok 1 - probe-schema.json yields at least one field "
               "(read %s, \"fields\" object %s)\n",
               schema_text != NULL ? "ok" : "FAILED",
               schema_text != NULL ? "missing or unparseable" : "not reached");
        free(schema_text);
        return 1;
    }

    printf("1..%d\n", PLANNED);

    present = json_parse(doc_zone_present, &err);
    ok(present != NULL, "the zone-present document parses%s%s",
       err ? ": " : "", err ? err : "");

    err = NULL;
    absent = json_parse(doc_zone_absent, &err);
    ok(absent != NULL, "the zone-absent document parses%s%s",
       err ? ": " : "", err ? err : "");

    err = NULL;
    shm_unmapped = json_parse(doc_zone_shm_unmapped, &err);
    ok(shm_unmapped != NULL, "the shm-unmapped document parses%s%s",
       err ? ": " : "", err ? err : "");

    if (present == NULL || absent == NULL || shm_unmapped == NULL) {
        printf("Bail out! the fixtures do not parse\n");
        return 1;
    }

    /* ---- FORWARD: rich variant (mapped zone + module_render hook) ------ */

    for (i = 0; i < SCHEMA_N; i++) {
        const json_value *v = json_get(present, SCHEMA[i].path);

        ok(v != NULL && v->type == SCHEMA[i].type,
           "rich: \"%s\" is %s", SCHEMA[i].path,
           json_type_name(SCHEMA[i].type));
    }

    /* ---- FORWARD: zone-absent variant --------------------------------- */

    for (i = 0; i < SCHEMA_N; i++) {
        const json_value *v = json_get(absent, SCHEMA[i].path);

        if (SCHEMA[i].rich_only) {
            /*
             * present:false promises nothing about its siblings. Asserting
             * they are ABSENT rather than skipping them is what stops the
             * emitter from quietly rendering a stale name or a zero size on
             * the variant that has no zone to describe. The same assertion
             * covers "module": a document from a module registering no
             * module_render hook must carry no empty "module":{} stub, or a
             * rule asserting on a member inside it would fail with "not
             * present in document" instead of the clearer absent-object.
             */
            ok(v == NULL, "zone-absent: \"%s\" is not rendered",
               SCHEMA[i].path);
        } else {
            ok(v != NULL && v->type == SCHEMA[i].type,
               "zone-absent: \"%s\" is %s", SCHEMA[i].path,
               json_type_name(SCHEMA[i].type));
        }
    }

    /* ---- FORWARD: shm-unmapped variant (R-10 regression) --------------- */

    for (i = 0; i < SCHEMA_N; i++) {
        const json_value *v = json_get(shm_unmapped, SCHEMA[i].path);

        if (SCHEMA[i].rich_only) {
            /* Same reasoning as the zone-absent block above: shm.addr ==
             * NULL is a legitimate present:false case, and none of its
             * siblings may be rendered -- that is R-10 itself. */
            ok(v == NULL, "shm-unmapped: \"%s\" is not rendered",
               SCHEMA[i].path);
        } else {
            ok(v != NULL && v->type == SCHEMA[i].type,
               "shm-unmapped: \"%s\" is %s", SCHEMA[i].path,
               json_type_name(SCHEMA[i].type));
        }
    }

    /* ---- REVERSE: no unnamed member at a closed level ------------------ */

    for (i = 0; i < CLOSED_N; i++) {
        const json_value *level;
        const char       *prefix = CLOSED_LEVELS[i];
        int               unknown = 0;
        const char       *first = NULL;

        level = (prefix[0] == '\0') ? present : json_get(present, prefix);

        if (level == NULL || level->type != JSON_OBJECT) {
            ok(0, "closed level \"%s\" is an object", prefix);
            continue;
        }

        for (j = 0; j < (int) level->count; j++) {
            char  full[128];
            int   found = 0;
            int   k;

            if (prefix[0] == '\0') {
                snprintf(full, sizeof(full), "%s", level->keys[j]);
            } else {
                snprintf(full, sizeof(full), "%s.%s", prefix, level->keys[j]);
            }

            for (k = 0; k < SCHEMA_N; k++) {
                if (strcmp(SCHEMA[k].path, full) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                unknown++;
                if (first == NULL) {
                    first = level->keys[j];
                }
            }
        }

        ok(unknown == 0,
           "closed level \"%s\" renders no member the schema does not name%s%s",
           prefix, first ? ", saw: " : "", first ? first : "");
    }

    /* ---- the checked-in schema names exactly these fields -------------- */

    if (schema_text == NULL) {
        for (i = 0; i < SCHEMA_N; i++) {
            ok(0, "probe-schema.json is readable (\"%s\")", SCHEMA[i].path);
        }
    } else {
        /*
         * FORWARD: every SCHEMA[] entry is named in the file. Substring
         * rather than a parse of the schema's own syntax: the check that
         * matters is that the file and this table name the same fields, and
         * a quoted dotted path is unambiguous enough to test by presence. A
         * field deleted from the schema but still asserted here fails.
         */
        for (i = 0; i < SCHEMA_N; i++) {
            char needle[160];

            snprintf(needle, sizeof(needle), "\"%s\"", SCHEMA[i].path);

            ok(strstr(schema_text, needle) != NULL,
               "probe-schema.json names \"%s\"", SCHEMA[i].path);
        }

        /*
         * REVERSE: every field the file names is in SCHEMA[]. Without this
         * direction a field added to probe-schema.json but never mirrored
         * into SCHEMA[] passes forever -- the FORWARD loop only ever checks
         * the fields SCHEMA[] already knows about.
         */
        for (i = 0; i < schema_file_field_n; i++) {
            int found = 0;

            for (j = 0; j < SCHEMA_N; j++) {
                if (strcmp(SCHEMA[j].path, schema_file_fields[i]) == 0) {
                    found = 1;
                    break;
                }
            }

            ok(found, "SCHEMA[] names \"%s\" from probe-schema.json",
               schema_file_fields[i]);
        }

        free(schema_text);
    }

    json_free(present);
    json_free(absent);
    json_free(shm_unmapped);

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        return 1;
    }

    return failures == 0 ? 0 : 1;
}
