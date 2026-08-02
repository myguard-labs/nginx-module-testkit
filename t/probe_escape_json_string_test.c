/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * probe_escape_json_string_test.c -- TAP self-test for the short-escape
 * buffer boundary in ngx_test_probe_escape_json_string().
 *
 * Seven characters (", \, \b, \f, \n, \r, \t) each expand to a two-byte
 * escape. Each of the seven if-blocks is guarded by `if (p + 2 <= last)`:
 * when exactly one byte remains in the output buffer and the next input
 * character needs one of these escapes, the guard must skip the write
 * entirely rather than emit a lone leading '\\' with no partner byte -- a
 * dangling backslash is invalid JSON and, worse, one that survives to a
 * quote-closing byte written by the caller turns into an escaped quote,
 * silently reopening the string.
 *
 * scenarios/zone-name-escaping never drives the renderer's real output
 * buffer to that exact one-byte-remaining boundary (its buffer has slack by
 * the time a zone name is reached), so a guard removed there was reported
 * SURVIVED against a scenario that exists to catch exactly this class. This
 * test constructs the boundary directly instead of hoping a scenario's
 * buffer sizing happens to land on it.
 */

#include "ngx_test_probe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLANNED  23

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


/*
 * Escape a single input byte `c` into `buf`, a buffer sized so exactly
 * `slack` bytes are available to the writer (last = buf + slack). Returns
 * the number of bytes actually written (p - buf).
 */
static size_t
escape_one(u_char c, size_t slack, u_char *buf, size_t bufsize)
{
    ngx_str_t  str;
    u_char    *p, *last;

    if (slack > bufsize) {
        printf("Bail out! test buffer too small for requested slack\n");
        exit(1);
    }

    memset(buf, 0xAA, bufsize);   /* sentinel: untouched bytes stay 0xAA */

    str.data = &c;
    str.len  = 1;

    last = buf + slack;
    p = ngx_test_probe_escape_json_string(buf, last, &str);

    return (size_t) (p - buf);
}


static const struct {
    u_char       in;
    const char  *label;
} short_escapes[] = {
    { '"',  "quote"      },
    { '\\', "backslash"  },
    { '\b', "backspace"  },
    { '\f', "formfeed"   },
    { '\n', "newline"    },
    { '\r', "carriage-return" },
    { '\t', "tab"        },
};

#define N_SHORT_ESCAPES  (sizeof(short_escapes) / sizeof(short_escapes[0]))


int
main(void)
{
    size_t  i;
    u_char  buf[8];
    size_t  written;
    char    name[128];

    printf("1..%d\n", PLANNED);

    /*
     * Boundary case: exactly one byte remains (last = buf + 1). The guard
     * `if (p + 2 <= last)` must be false (p == buf, last == buf + 1, so
     * p + 2 > last), so the writer must emit NOTHING -- no lone '\\' left
     * dangling in the buffer, and the returned pointer must not have moved
     * past buf. This is the exact condition the removed guard mutation
     * breaks: without it, '\\' would be written unconditionally, running
     * one byte past `last` into the buffer's would-be next field.
     */
    for (i = 0; i < N_SHORT_ESCAPES; i++) {
        written = escape_one(short_escapes[i].in, 1, buf, sizeof(buf));

        snprintf(name, sizeof(name),
                 "%s: one byte remaining writes nothing",
                 short_escapes[i].label);
        ok(written == 0, name);

        snprintf(name, sizeof(name),
                 "%s: one byte remaining leaves buffer untouched (no dangling backslash)",
                 short_escapes[i].label);
        ok(buf[0] == 0xAA, name);
    }

    /*
     * Negative control at the same call sites: with two bytes of slack (the
     * exact amount the escape needs), every short escape DOES fit and DOES
     * write both bytes, starting with the backslash. This is what proves
     * "writes nothing" above is the guard doing its job and not the helper
     * being broken outright -- a helper that never writes would pass the
     * boundary assertions above for the wrong reason.
     */
    for (i = 0; i < N_SHORT_ESCAPES; i++) {
        written = escape_one(short_escapes[i].in, 2, buf, sizeof(buf));

        snprintf(name, sizeof(name),
                 "%s: two bytes remaining writes the full two-byte escape",
                 short_escapes[i].label);
        ok(written == 2 && buf[0] == '\\', name);
    }

    /* One more boundary check, on the C0 \uXXXX path (6-byte escape, guarded
     * by `p + 6 <= last`): 5 bytes of slack must write nothing, matching the
     * short-escape contract, so a guard fix that only touches the 7 short
     * cases and forgets this one is not silently declared out of scope by an
     * absent assertion. */
    written = escape_one('\x01', 5, buf, sizeof(buf));
    ok(written == 0, "C0 control (\\u0001): five bytes remaining writes nothing");
    ok(buf[0] == 0xAA, "C0 control (\\u0001): five bytes remaining leaves buffer untouched");

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
