/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libFuzzer target for json_parse_n() -- the byte-and-length JSON entry the
 * probe drives over a response body (http.c:517, prober.c:250). Chosen because
 * it consumes untrusted server-supplied bytes: an embedded NUL, a deeply nested
 * array, a number that overflows a double, a truncated escape are all inputs a
 * hostile or broken upstream can produce, and none of them are reachable from a
 * live socket on demand.
 *
 * Engine-neutral: the body defines LLVMFuzzerTestOneInput and nothing else, so
 * it links equally under -fsanitize=fuzzer (clang) and under the standalone
 * corpus-replay driver in fuzz_standalone.c (plain gcc, no engine).
 */
#include <stddef.h>
#include <stdint.h>

#include "../json.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char  *err = NULL;
    json_value  *v;

    /* json_parse_n takes (text, len): it does not require a NUL terminator and
     * treats an embedded NUL as data, which is exactly the property under test.
     * A leaked json_value on the accept path would be an ASan/LSan finding, so
     * the free is load-bearing, not decoration. */
    v = json_parse_n((const char *) data, size, &err);
    if (v != NULL) {
        json_free(v);
    }

    return 0;
}
