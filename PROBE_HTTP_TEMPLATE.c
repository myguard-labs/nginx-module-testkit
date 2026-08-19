/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * nginx-module-testkit HTTP probe template
 *
 * Copy this file to your module's src directory, rename to fit your module
 * (e.g., ngx_mymod_probe_http.c), and fill in the blanks:
 *
 *   0. Put your own copyright on the copy. The BSD-2-Clause line above is the
 *      template's own licence; a consumer's derived probe is their file, and
 *      the module repos that vendor this all run the same SPDX gate.
 *   1. Replace "mymod" with your module name throughout.
 *   2. Replace "mymod_conf_t" with your module's location config struct.
 *   3. Add `#include` for your module's header.
 *   4. Keep or remove the hooks registration at the bottom (optional).
 *
 * The whole file is guarded by #ifdef NGX_TEST_HARNESS, so it compiles out
 * when building for production.
 *
 * This template is the ONLY C you need to write beyond editing nginx.conf to
 * add a "mymod_probe" location. Everything else is copy-paste + #ifdef.
 *
 * Buffer sizing: NGX_TEST_PROBE_JSON_MAX + the zone name + space for your
 * hooks to append (if any). The example uses 128; adjust if your hook renders
 * more than a few integers. Undersizing truncates the JSON in the harness
 * (ngx_slprintf stops at `last`), which surfaces as a parse error on every
 * case -- not wrong assertions on one. When in doubt, oversize.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_TEST_HARNESS

/* Include the harness headers. Paths assume t/harness/ was added as a
 * git submodule named "harness" -- adjust if your layout differs. */
#include "t/harness/src/ngx_test_probe.h"

/* Your module's public header (if needed for the hooks). */
/* #include "ngx_mymod.h" */


/*
 * Optional: Append module-specific fields to the probe JSON.
 *
 * If your module does not need custom introspection, delete this function
 * and the hooks struct below; the generic probe alone covers fd and cycle-pool
 * leaks for any module.
 *
 * Contract (see ngx_test_probe_hooks_t): the generic members are already
 * rendered and the object is still open, so this must:
 *   - Lead with a comma
 *   - NOT close the brace
 *   - Use ngx_slprintf (stops at `last`, never overflows)
 *   - Return the new `last` pointer
 *
 * Example for a zone with custom LRU counting:
 *
 *   return ngx_slprintf(buf, last,
 *                       ",\"custom_count\":%ui",
 *                       my_count_nodes(zone));
 *
 * The function runs WITHOUT holding locks (unless you take them yourself),
 * which is why it is test-only -- holding the slab mutex for the whole
 * probe snapshot would make production deployments' latency unpredictable.
 */
static u_char *
ngx_mymod_probe_zone_render(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    /* Append nothing; the zone's generic members (name, size, slab page
     * usage) are rendered by the harness and sufficient for testing. */
    return buf;
}


/*
 * Optional: Arm or clear a fault-injection counter.
 *
 * If your module does not support fault injection, delete this function
 * and set .fault_set = NULL in the hooks struct below.
 *
 * Contract: the harness has already parsed and validated the query
 * argument (e.g., "fault_slab=5") and identified which fault site it named,
 * passed as `fault`; this function only stores the result for that site.
 * `nth` is negative to disarm, non-negative to arm. Implement only the sites
 * your module actually has injection points for and return NGX_DECLINED for
 * the rest. Return NGX_OK on success, NGX_DECLINED if the zone/module is not
 * ready to accept it or the named site is not one you implement.
 *
 * Counters MUST live in shared memory (not a process global) if the zone
 * can be accessed by multiple workers. The fault counter lives here, not in
 * the prober, because a single worker cannot trip its own injection -- the
 * next request (or a different worker in production) does.
 *
 * Example: store the counter in a field of the zone's shared context:
 *
 *   ngx_mymod_ctx_t  *ctx = zone->data;
 *   if (ctx == NULL) return NGX_DECLINED;
 *   ngx_shmtx_lock(&ctx->shpool->mutex);
 *   ctx->fault_nth = nth;
 *   ctx->fault_seen = 0;  // reset the seen counter when arming
 *   ngx_shmtx_unlock(&ctx->shpool->mutex);
 *   return NGX_OK;
 */
static ngx_int_t
ngx_mymod_probe_fault_set(ngx_shm_zone_t *zone, ngx_test_probe_fault_e fault,
    ngx_int_t nth)
{
    (void) zone;
    (void) fault;
    (void) nth;

    /* Fault injection not supported by this module. Switch on `fault` here to
     * arm only the sites (NGX_TEST_PROBE_FAULT_SLAB, ..._PALLOC, ...) your
     * module actually implements, and return NGX_DECLINED for the others. */
    return NGX_DECLINED;
}


static const ngx_test_probe_hooks_t  ngx_mymod_probe_hooks = {
    .zone_render = ngx_mymod_probe_zone_render,
    .fault_set = ngx_mymod_probe_fault_set,
};


void
ngx_mymod_probe_hooks_register(void)
{
    ngx_test_probe_register(&ngx_mymod_probe_hooks);
}


/*
 * Configuration handler for the "mymod_probe" directive.
 *
 * Declares a shared-memory zone and installs a simple content handler
 * that calls ngx_test_probe_json() and returns the JSON snapshot.
 *
 * nginx.conf usage:
 *
 *   location /__probe {
 *       mymod_probe zone_name;
 *   }
 *
 * The zone_name is any valid nginx shm-zone name. Its lifetime and
 * initialization are the consuming module's responsibility; this only
 * passes it to the harness. The typical pattern:
 *
 *   http {
 *       mymod_zone zone=mymod:10m;  // module directive declares the zone
 *       server {
 *           location /__probe {
 *               mymod_probe mymod;   // probe directive references it
 *           }
 *       }
 *   }
 */
static char *
ngx_mymod_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                   *value;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_mymod_loc_conf_t        *mlcf;  /* Rename to your module's struct. */
    ngx_shm_zone_t              *zone;

    mlcf = (ngx_mymod_loc_conf_t *) conf;
    value = cf->args->elts;

    if (mlcf->probe_zone != NULL) {
        return "is duplicate";
    }

    /* Look up or create the zone. An existing zone is reused; if it does not
     * exist, it will be initialized during the module's postconfiguration
     * hook. */
    zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_mymod_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mlcf->probe_zone = zone;

    /* Install this location's content handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_mymod_probe_handler;

    return NGX_CONF_OK;
}


/*
 * Content handler: render the probe snapshot as JSON and return 200 OK.
 *
 * Called for every request to the probe location (e.g., GET /__probe).
 * Issues a GET, HEAD, or any other method with a body return 405.
 */
static ngx_int_t
ngx_mymod_probe_handler(ngx_http_request_t *r)
{
    size_t                  size;
    u_char                  *buf, *last;
    ngx_int_t               rc;
    ngx_buf_t               *b;
    ngx_chain_t             out;
    ngx_mymod_loc_conf_t    *mlcf;  /* Rename to your module's struct. */

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_mymod_module);

    /* Process any fault-injection directives in the query string before
     * rendering the snapshot. This arm-then-render order means the response
     * reflects the state AFTER arming, which is what the test expects. */
    (void) ngx_test_probe_arm(mlcf->probe_zone, &r->args);

    /*
     * Buffer sizing. NGX_TEST_PROBE_JSON_MAX is the harness's generic
     * document size. Add:
     *
     *   1. The zone name length (shm.name.len)
     *   2. Space for your zone_render hook to append (if any)
     *   3. A small margin for safety
     *
     * Example:
     *   NGX_TEST_PROBE_JSON_MAX + zone_name + ~128 bytes for hook overhead
     *
     * Undersizing truncates the JSON (ngx_slprintf stops at `last`), which
     * surfaces as a parse error in the prober on every case -- not a wrong
     * assertion on one. When in doubt, oversize.
     */
    size = NGX_TEST_PROBE_JSON_MAX + 128;  /* Adjust to your module's needs. */
    if (mlcf->probe_zone != NULL) {
        size += mlcf->probe_zone->shm.name.len;
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Render the snapshot. The harness handles the generic part; your
     * zone_render hook (if registered) appends module-specific fields. */
    last = ngx_test_probe_json(buf, buf + size, mlcf->probe_zone);

    /* Send the JSON as the response body. */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = last - buf;
    ngx_str_set(&r->headers_out.content_type, "application/json");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = buf;
    b->last = last;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


/* Declare the handler and config for the command table. */
static char *ngx_mymod_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_mymod_probe_handler(ngx_http_request_t *r);

/* Add to your module's command table:
 *
 *   { ngx_string("mymod_probe"),
 *     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
 *     ngx_mymod_probe,
 *     NGX_HTTP_LOC_CONF_OFFSET,
 *     0,
 *     NULL },
 *
 * Place this entry inside the #ifdef NGX_TEST_HARNESS block of your
 * ngx_command_t array.
 */

/* At module initialization, register the hooks (if not NULL):
 *
 *   ngx_mymod_probe_hooks_register();
 *
 * Call this in your module's postconfiguration hook or module init handler.
 * If your hooks are NULL, skip this (the generic probe still works).
 */

#else

/* ISO C forbids an empty translation unit, and angie's configure adds
 * -Werror, so the disabled build needs a declaration to stand on. */
typedef int ngx_mymod_probe_not_built_t;

#endif /* NGX_TEST_HARNESS */
