/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_shim.h -- just enough nginx to compile ngx_test_probe_arm.c on its own.
 *
 * That file parses a query string, and a query-string parser is worth testing
 * exhaustively: the boundary rule ("fault_slab=" must start the query or follow
 * an '&'), the malformed-input contract (NGX_DECLINED, never a best guess), and
 * the digit bound. None of that needs a server, a worker, or shared memory --
 * but reaching it through a real build needs all three, which is why it had no
 * tests at all.
 *
 * Purpose-built for that one translation unit; not a general nginx emulation.
 * That is deliberate. The ten shim headers across labs/ were measured in July
 * 2026 and share almost nothing -- each stubs exactly the surface its own
 * target touches. A merged "common" shim would be a superset nobody needs plus
 * a coupling every consumer pays for.
 */

#ifndef NGX_TEST_HARNESS_SHIM_H
#define NGX_TEST_HARNESS_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define NGX_OK         0
#define NGX_ERROR     -1
#define NGX_DECLINED  -5

/* Real nginx picks this from the server version; the arm path never renders
 * it, and the flavor detection in ngx_test_probe.h needs it to exist. */
#define NGINX_VERSION  "shim"

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/*
 * The arm path never dereferences the zone -- it only passes the pointer
 * through to the module's hook -- so an opaque tag type is enough. Keeping it
 * opaque also means a test cannot accidentally depend on a layout the real
 * server owns.
 */
typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

#define ngx_strncmp(s1, s2, n)  strncmp((const char *) (s1), \
                                        (const char *) (s2), n)
#define ngx_memzero(buf, n)     memset(buf, 0, n)
/* ngx_test_probe_render_module() copies its two fixed literals with this.
 * Real nginx spells it the same way (ngx_string.h). */
#define ngx_memcpy(dst, src, n)  memcpy(dst, src, n)

#endif /* NGX_TEST_HARNESS_SHIM_H */
