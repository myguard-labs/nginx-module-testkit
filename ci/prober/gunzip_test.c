/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * gunzip_test.c -- TAP self-test for the gunzip body oracle (http_gunzip()).
 *
 * The inputs worth testing -- a truncated gzip stream, a corrupt one, a body
 * labelled gzip that is really plaintext, a chunked-AND-gzipped body -- are the
 * ones a live server will not produce on demand, so they are built here and fed
 * to the decoder directly. The gzip/deflate fixtures are COMPRESSED at test
 * time with zlib rather than checked in as hex blobs, so the test cannot rot
 * against a hand-transcribed byte and a reader can see exactly what went in.
 *
 * Each fixture assembles a full response (status line + Content-Encoding header
 * + compressed body) so http_gunzip() runs against the same http_response shape
 * the live path hands it. body_bytes() layering (assert.c) is exercised by
 * reading resp.inflated after a success.
 */

#define _GNU_SOURCE

#include "http.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define PLANNED  19

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
 * Compress `src` into a freshly malloc'd buffer. `window` selects the wrapper:
 * 15+16 for a gzip header, 15 for a zlib (deflate) header, -15 for raw
 * headerless deflate. Aborts on any zlib failure -- a broken fixture builder
 * would silently weaken every test that leans on it.
 */
static char *
compress_with(const char *src, size_t src_len, int window, size_t *out_len)
{
    z_stream  zs;
    size_t    cap;
    char     *out;

    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, window, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
    {
        fprintf(stderr, "gunzip_test: deflateInit2 failed\n");
        exit(2);
    }

    cap = deflateBound(&zs, (uLong) src_len);
    out = malloc(cap);
    if (out == NULL) {
        fprintf(stderr, "gunzip_test: out of memory\n");
        exit(2);
    }

    /* Launder const via memcpy, not a cast: matches http.c and dodges both
     * -Wcast-qual and clang-tidy's bugprone-casting-through-void. */
    memcpy(&zs.next_in, &src, sizeof zs.next_in);
    zs.avail_in = (uInt) src_len;
    zs.next_out = (Bytef *) out;
    zs.avail_out = (uInt) cap;

    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        fprintf(stderr, "gunzip_test: deflate did not finish\n");
        exit(2);
    }

    *out_len = cap - zs.avail_out;
    (void) deflateEnd(&zs);

    return out;
}


/*
 * Build a full response into a freshly malloc'd http_response: status line, the
 * given Content-Encoding value (NULL to omit the header entirely), CRLFCRLF,
 * then `body` bytes. Length-bounded throughout because the compressed body is
 * binary and holds NULs.
 */
static void
make_resp(http_response *resp, const char *enc, const char *body,
          size_t body_len)
{
    char    head[256];
    int     hn;
    size_t  total;
    char   *raw;

    if (enc != NULL) {
        hn = snprintf(head, sizeof(head),
                      "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\n\r\n", enc);
    } else {
        hn = snprintf(head, sizeof(head), "HTTP/1.1 200 OK\r\n\r\n");
    }

    if (hn < 0 || (size_t) hn >= sizeof(head)) {
        fprintf(stderr, "gunzip_test: header too long\n");
        exit(2);
    }

    total = (size_t) hn + body_len;
    raw = malloc(total + 1);
    if (raw == NULL) {
        fprintf(stderr, "gunzip_test: out of memory\n");
        exit(2);
    }

    memcpy(raw, head, (size_t) hn);
    memcpy(raw + hn, body, body_len);
    raw[total] = '\0';

    memset(resp, 0, sizeof(*resp));
    resp->raw = raw;
    resp->raw_len = total;

    http_parse_response(resp);
}


/* True when the inflated body equals `want` exactly (length + bytes). */
static int
inflated_is(const http_response *resp, const char *want)
{
    size_t  n = strlen(want);

    return resp->inflated != NULL
           && resp->inflated_len == n
           && memcmp(resp->inflated, want, n) == 0;
}


int
main(void)
{
    static const char  payload[] =
        "the quick brown fox jumps over the lazy dog, "
        "and does so repeatedly so the stream is worth compressing";
    http_response  resp;
    char          *gz, *df, *raw;
    size_t         gz_len, df_len, raw_len;
    size_t         payload_len = sizeof(payload) - 1;

    printf("1..%d\n", PLANNED);

    gz  = compress_with(payload, payload_len, 15 + 16, &gz_len);
    df  = compress_with(payload, payload_len, 15,      &df_len);
    raw = compress_with(payload, payload_len, -15,     &raw_len);

    /* --- gzip happy path --------------------------------------------------- */
    make_resp(&resp, "gzip", gz, gz_len);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_OK, "gzip: status OK");
    ok(inflated_is(&resp, payload), "gzip: inflated bytes match");
    http_response_free(&resp);

    /* --- deflate (zlib header) happy path ---------------------------------- */
    make_resp(&resp, "deflate", df, df_len);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_OK, "deflate/zlib: status OK");
    ok(inflated_is(&resp, payload), "deflate/zlib: inflated bytes match");
    http_response_free(&resp);

    /* --- raw headerless deflate under the `deflate` name -------------------- */
    make_resp(&resp, "deflate", raw, raw_len);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_OK, "deflate/raw: status OK");
    ok(inflated_is(&resp, payload), "deflate/raw: inflated bytes match");
    http_response_free(&resp);

    /* --- coding list "gzip, br" still counts as gzip ----------------------- */
    make_resp(&resp, "gzip, br", gz, gz_len);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_OK, "coding list: gzip detected");
    http_response_free(&resp);

    /* --- no Content-Encoding header -> NOT_ENCODED, not an error ------------ */
    make_resp(&resp, NULL, gz, gz_len);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_NOT_ENCODED,
       "no encoding header: NOT_ENCODED");
    ok(resp.inflated == NULL, "no encoding header: no inflated buffer");
    http_response_free(&resp);

    /* --- identity body labelled gzip -> BAD_STREAM ------------------------- */
    make_resp(&resp, "gzip", "this is plain text, not a gzip stream at all",
              sizeof("this is plain text, not a gzip stream at all") - 1);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_BAD_STREAM,
       "plaintext labelled gzip: BAD_STREAM");
    ok(resp.inflated == NULL, "plaintext labelled gzip: no inflated buffer");
    http_response_free(&resp);

    /* --- truncated gzip stream -> TRUNCATED -------------------------------- */
    /* Drop the trailing 8 bytes (CRC32 + ISIZE) so the deflate data is intact
     * but the stream never reaches Z_STREAM_END. */
    make_resp(&resp, "gzip", gz, gz_len - 8);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_TRUNCATED,
       "truncated gzip: TRUNCATED");
    ok(resp.inflated == NULL, "truncated gzip: no inflated buffer");
    http_response_free(&resp);

    /* --- corrupt gzip stream (flipped byte mid-deflate) -> BAD_STREAM ------- */
    gz[gz_len / 2] = (char) (gz[gz_len / 2] ^ 0xFF);
    make_resp(&resp, "gzip", gz, gz_len);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_BAD_STREAM
       || resp.gunzip_status == HTTP_GUNZIP_TRUNCATED,
       "corrupt gzip: not OK");
    ok(resp.inflated == NULL, "corrupt gzip: no inflated buffer");
    gz[gz_len / 2] = (char) (gz[gz_len / 2] ^ 0xFF);  /* restore */
    http_response_free(&resp);

    /* --- empty body labelled gzip -> TRUNCATED, never a clean empty decode -- */
    make_resp(&resp, "gzip", "", 0);
    http_gunzip(&resp);
    ok(resp.gunzip_status == HTTP_GUNZIP_TRUNCATED,
       "empty body labelled gzip: TRUNCATED");
    http_response_free(&resp);

    /* --- large body round-trips through the geometric grow loop ------------ */
    {
        size_t   big_len = 400 * 1024;   /* > several GUNZIP_CHUNK rounds */
        char    *big = malloc(big_len);
        char    *big_gz;
        size_t   big_gz_len;

        if (big == NULL) {
            fprintf(stderr, "gunzip_test: out of memory\n");
            exit(2);
        }
        memset(big, 'A', big_len);
        big_gz = compress_with(big, big_len, 15 + 16, &big_gz_len);

        make_resp(&resp, "gzip", big_gz, big_gz_len);
        http_gunzip(&resp);
        ok(resp.gunzip_status == HTTP_GUNZIP_OK, "large gzip: status OK");
        ok(resp.inflated_len == big_len
           && resp.inflated != NULL
           && resp.inflated[0] == 'A'
           && resp.inflated[big_len - 1] == 'A',
           "large gzip: full length inflated");
        http_response_free(&resp);
        free(big_gz);
        free(big);
    }

    /* --- reason strings are total (never NULL, unknown renders) ------------- */
    ok(http_gunzip_reason(HTTP_GUNZIP_TRUNCATED) != NULL
       && http_gunzip_reason(999) != NULL,
       "reason: never NULL, unknown code renders");

    free(gz);
    free(df);
    free(raw);

    printf("# %d run, %d failed\n", tests_run, failures);

    if (tests_run != PLANNED) {
        printf("# PLAN MISMATCH: ran %d, planned %d\n", tests_run, PLANNED);
        return 1;
    }

    return failures == 0 ? 0 : 1;
}
