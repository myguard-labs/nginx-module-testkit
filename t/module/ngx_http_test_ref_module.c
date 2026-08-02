/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_test_ref_module -- the reference consumer of the test probe.
 *
 * This module exists so CI can BOOT a server and run the scenario tree. The
 * probe and the prober were both fully built and fully unexercised: every job
 * compiled the probe, none ever linked it into a server and made a request to
 * it, because prober_resolve requires a PROBER_MODULE and this repo shipped
 * none. Layer 3 -- scenarios, drivers, signal choreography -- had no execution
 * anywhere. Shipping the first drivers on top of that is how the s43
 * flaky-fork bug nearly merged.
 *
 * It is deliberately the SMALLEST module that makes the existing scenarios
 * runnable, and it is not a demonstration of the hook API. Both hooks in
 * ngx_test_probe_hooks_t are optional; a module registering neither still gets
 * the whole generic document -- flavor, pid, connections, fds, cycle-pool
 * accounting -- and that generic half is exactly what all 13 checked-in
 * scenarios assert on (`delta fds`, `delta pool.cycle_used`, and the http
 * behaviour around them). Registering a zone_render or a fault_set here would
 * add surface that nothing in the tree reads, and would make this module a
 * second, subtly different reference for consumers to copy from. The hooks are
 * documented in the header and exercised by the direct-call unit harness in
 * t/; that is where they belong.
 *
 * By default it takes no shm zone. `test_ref_probe;` is the whole directive,
 * PROBER_PROBE_ZONE stays empty, and the probe reports
 * "zone": {"present": false} -- which is a legitimate rendering, not a
 * degraded one, and is what every scenario except zone-name-escaping relies
 * on.
 *
 * The one exception is `test_ref_zone <name> <size>;` (optional, http-level).
 * It exists solely so the zone-name-escaping scenario can drive a REAL zone
 * whose name contains characters ngx_test_probe_escape_json_string() has to
 * escape, and assert the probe's JSON round-trips that name exactly -- a
 * `zone.present:false` document never reaches the escape helper at all, so
 * without this directive that scenario could not fail no matter how broken
 * the escaping got. When the directive is absent, ngx_http_test_ref_zone
 * stays NULL and the handler passes NULL to ngx_test_probe_json() exactly as
 * before -- every other scenario's boot is unaffected.
 *
 * A consuming module (shield, and whatever follows) is the real integration
 * test of the hook API. This one only has to prove the harness can drive a
 * live server end to end.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_test_probe.h"

#ifndef NGX_TEST_HARNESS
#error "ngx_http_test_ref_module is a CI-only module and requires NGX_TEST_HARNESS"
#endif

static char *ngx_http_test_ref_probe(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_test_ref_zone_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_test_ref_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_test_ref_handler(ngx_http_request_t *r);

/*
 * The zone this module's probe reports, when `test_ref_zone` configured one.
 * A plain module-global, not a location/main-conf field: the probe handler
 * runs per-worker and only needs to read the pointer nginx already fixed up
 * at postconfiguration time, and every scenario conf that uses this directive
 * declares exactly one zone (see the "is duplicate" guard below), so there is
 * nothing per-location to disambiguate.
 */
static ngx_shm_zone_t  *ngx_http_test_ref_zone = NULL;


static ngx_command_t  ngx_http_test_ref_commands[] = {

    /*
     * NGX_CONF_NOARGS: the directive that the scenario confs put in
     * `location /__probe` is bare. A consumer whose probe needs a zone
     * declares its own directive with its own argument spec -- @PROBE@
     * exists precisely so the scenario tree does not have to know which
     * shape it is.
     */
    { ngx_string("test_ref_probe"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_test_ref_probe,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Optional, http-level: `test_ref_zone <name> <size>;`. Only the
     * zone-name-escaping scenario's conf carries this (via @PROBE_ZONE@);
     * every other scenario conf leaves it out and ngx_http_test_ref_zone
     * stays NULL. NGX_CONF_TAKE2 so the name is its own token and can be a
     * quoted nginx-conf string ("a\"b") -- nginx's own lexer unescapes
     * \", \\ and control-char escapes before this handler ever sees value[1],
     * which is what lets the scenario drive a zone name containing a literal
     * quote, backslash and control character without this module doing any
     * unescaping itself.
     */
    { ngx_string("test_ref_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_test_ref_zone_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_int_t ngx_http_test_ref_preconfiguration(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_test_ref_module_ctx = {
    ngx_http_test_ref_preconfiguration, /* preconfiguration */
    NULL,                          /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_http_test_ref_module = {
    NGX_MODULE_V1,
    &ngx_http_test_ref_module_ctx, /* module context */
    ngx_http_test_ref_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * Runs once per configuration parse (nginx -t, initial boot, or a reload),
 * before any command handler in this file. A reload re-parses configuration
 * in the SAME master process, so the module-global ngx_http_test_ref_zone
 * would otherwise still point at the previous cycle's zone if the new config
 * dropped `test_ref_zone` -- resetting it here is what keeps "directive
 * absent" meaning NULL on every parse, not just the first one.
 */
static ngx_int_t
ngx_http_test_ref_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_test_ref_zone = NULL;

    return NGX_OK;
}


static char *
ngx_http_test_ref_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_test_ref_handler;

    /*
     * This directive handler is the config-load path: nginx runs it once per
     * `test_ref_probe;` while PARSING a configuration, in the master, before
     * any worker of that cycle is forked. That makes it the correct place to
     * count a config load -- the workers a reload creates inherit the bumped
     * value through fork(), which is the whole mechanism config_generation
     * relies on (see ngx_test_probe.h).
     *
     * A consequence worth stating rather than discovering: the count advances
     * once per OCCURRENCE of the directive, not once per reload. A config with
     * the directive in two locations bumps twice per load. The reload gate is
     * specified against "strictly greater after a reload", never against a
     * step of exactly one, precisely so that a scenario conf is free to place
     * the directive wherever it needs it.
     */
    ngx_test_probe_config_loaded();

    return NGX_CONF_OK;
}


/*
 * `test_ref_zone <name> <size>;` -- http-level, optional. Registers a real
 * shm zone under the given name so the probe can report `zone.present: true`
 * with that name, for scenarios (currently only zone-name-escaping) that need
 * to exercise the JSON-escaping path on a name they control. See the file
 * header for why this exists and why every other scenario is unaffected by
 * its absence.
 */
static char *
ngx_http_test_ref_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t        *value;
    ssize_t            size;
    ngx_shm_zone_t    *shm_zone;

    if (ngx_http_test_ref_zone != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid test_ref_zone size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &value[1], (size_t) size,
                                      &ngx_http_test_ref_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "test_ref_zone \"%V\" is already bound",
                            &value[1]);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_test_ref_init_zone;
    /*
     * Nonzero, meaningless data pointer: init_zone below only needs to
     * allocate the slab pool (ngx_init_zone_pool does that unconditionally,
     * before init() ever runs), and the probe reads name/size/pfree straight
     * off shm.addr/shm.size. Duplicate-directive detection above already
     * covers "already bound"; this is just a marker so a SECOND zone with a
     * different tag colliding on the same name (ngx_shared_memory_add's own
     * "already declared for a different use" case) is not this module's
     * problem to re-check.
     */
    shm_zone->data = (void *) 1;

    ngx_http_test_ref_zone = shm_zone;

    return NGX_CONF_OK;
}


/*
 * Nothing to initialize beyond the slab pool nginx already sets up in
 * shm.addr before calling init() -- this module has no per-zone data
 * structure, only the generic zone.name/zone.size/zone.slab_pages_free the
 * harness renders from shm.addr/shm.size directly. See ngx_test_probe_json().
 */
static ngx_int_t
ngx_http_test_ref_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_test_ref_handler(ngx_http_request_t *r)
{
    u_char       *buf, *last;
    size_t        len, size;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /*
     * Discard the request body before answering. Skipping this leaves an
     * unread body in the connection buffer, which the next request on a
     * keepalive connection then parses as its request line -- and
     * keepalive-bleed is one of the checked-in scenarios.
     */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Fault arming happens before rendering, so a request that both arms a
     * fault and reads the document sees the state it just asked for. Return
     * value is deliberately ignored: NGX_DECLINED means "no fault directive in
     * this query, or no fault_set hook" -- this module registers none, so that
     * is the normal answer here and not an error. The probe validates the
     * argument itself; a malformed one arms nothing.
     */
    (void) ngx_test_probe_arm(ngx_http_test_ref_zone, &r->args);

    /*
     * NGX_TEST_PROBE_JSON_MAX covers the generic document. When a zone is
     * configured its name is rendered too (escaped, so up to 6x its raw
     * length -- \u00XX is the longest expansion), plus a small margin; a pool
     * buffer replaces the old fixed stack buffer because that bound is no
     * longer a compile-time constant once test_ref_zone is in play.
     * Undersizing truncates the JSON (ngx_slprintf stops at `last`), which
     * would surface as a parse error, not a wrong escape -- oversize rather
     * than trim this.
     */
    size = NGX_TEST_PROBE_JSON_MAX;
    if (ngx_http_test_ref_zone != NULL) {
        size += ngx_http_test_ref_zone->shm.name.len * 6 + 64;
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_test_probe_json(buf, buf + size, ngx_http_test_ref_zone);
    len = (size_t) (last - buf);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;

    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        return ngx_http_send_header(r);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, buf, len);
    b->last = b->pos + len;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}
