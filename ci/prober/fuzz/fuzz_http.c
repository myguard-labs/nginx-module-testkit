/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libFuzzer target for http_parse_response() -- the in-place status/header/body
 * splitter (http.h:509). The header itself lists the inputs that matter and
 * that a live server will not emit on demand: no header terminator, a body
 * containing CRLFCRLF, an embedded NUL, a truncated status line. Fuzzing drives
 * exactly those.
 *
 * The function reads resp->raw / resp->raw_len and writes every other field, so
 * the target owns a zeroed http_response, points raw at a NUL-terminated copy of
 * the input (raw is treated as a C string in places), and frees whatever the
 * parse allocated. body points into raw and is not separately owned.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../http.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    http_response  resp;
    unsigned char *raw;

    /* +1 for the trailing NUL the parser's string scans rely on; raw_len stays
     * the true byte count so an embedded NUL inside the response is preserved. */
    raw = malloc(size + 1);
    if (raw == NULL) {
        return 0;
    }
    memcpy(raw, data, size);
    raw[size] = '\0';

    memset(&resp, 0, sizeof(resp));
    resp.raw = raw;
    resp.raw_len = size;

    http_parse_response(&resp);

    /* http_response_free owns resp->raw (it frees it), so we must NOT free raw
     * ourselves -- that would double-free. It also releases headers and any
     * decode buffers the split allocated. */
    http_response_free(&resp);

    return 0;
}
