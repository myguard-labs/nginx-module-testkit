/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libFuzzer target for backend_parse_resp() -- the fake upstream's RESP
 * (Redis wire) command parser (backend.h:253). RESP carries binary-safe bulk
 * strings with declared lengths, so a lying `$` length, a multibulk `*` count
 * that overruns, an embedded NUL inside a bulk value are precisely the
 * length-prefix confusions a fuzzer explores. The parser NUL-terminates each
 * bulk in place, so the input must be a writable copy.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../backend.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    backend_cmd     cmd;
    unsigned char  *buf;

    buf = malloc(size + 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';

    memset(&cmd, 0, sizeof(cmd));
    (void) backend_parse_resp(buf, size, &cmd);

    free(buf);
    return 0;
}
