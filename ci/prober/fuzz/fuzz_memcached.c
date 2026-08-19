/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libFuzzer target for backend_parse_memcached() -- the fake upstream's
 * memcached text-protocol command parser (backend.h:252). It reads
 * attacker-shaped bytes off a client socket: a storage command with a lying
 * data-length, an argument count past BACKEND_MAX_ARGS, a line with no
 * terminator. The parser writes into its buffer (NUL-terminating args in place),
 * so the target hands it a writable copy, never the read-only fuzzer input.
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
    /* cmd.args point into buf; nothing in cmd is separately owned, so there is
     * no free -- the buffer copy is the only allocation. */
    (void) backend_parse_memcached(buf, size, &cmd);

    free(buf);
    return 0;
}
