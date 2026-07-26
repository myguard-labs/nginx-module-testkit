/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libFuzzer target for backend_load() -- the fake-upstream .backend script
 * parser (backend.c). A .backend file is an untrusted-text grammar distinct
 * from the wire codecs the memcached/resp targets cover: line directives
 * (proto/seed/fault), whitespace tokenising, kv_split, escape decoding for
 * seed values and fault `data=`, numeric bounds via xstrtol, and a
 * data=-carries-spaces special case that reaches into the raw line before the
 * tokeniser sees it. Any of those a malformed script can drive into a bad
 * state a hand-written fixture would not think to try.
 *
 * TWO things make this target work where a naive one would not, the same two
 * that made fuzz_rules.c work:
 *
 *   1. backend_load_buf(): the production entry backend_load() reads a PATH via
 *      fopen/fgets, not a (data, size) buffer. backend_load_buf() fmemopen()s
 *      the fuzzer's bytes into the SAME parser (backend_load_fp), so no
 *      fuzz-only reimplementation exists to drift from what the prober runs.
 *
 *   2. the die() recovery hook: backend_load() die()s (exit(2)s) on ANY
 *      malformed line or a missing proto directive -- correct for production (a
 *      script that does not mean what it says must not run, lest a scenario
 *      exercise the happy path while claiming a fault) but fatal for a fuzzer,
 *      which feeds malformed scripts by the million. Arming prober_die_jmp
 *      makes die() longjmp back here instead, so a rejected script is a handled
 *      non-event and only a CRASH (ASan/UBSan finding, real abort) fails the
 *      run -- exactly the bug class the target exists to find.
 *
 * Engine-neutral: defines LLVMFuzzerTestOneInput and nothing else, so it links
 * under -fsanitize=fuzzer (clang) and under fuzz_standalone.c's corpus replay
 * (plain gcc, no engine), same as the sibling targets.
 */
#define _GNU_SOURCE

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

#include "../backend.h"
#include "../util.h"

/*
 * One static script reused across runs (libFuzzer calls this in a tight loop).
 * backend_free() releases everything backend_load_buf() built AND memsets the
 * struct back to zero, so the next input starts from a clean slate. It is safe
 * on a partially-built or already-zeroed script: every faults[] pointer is
 * either a real allocation or NULL (free(NULL) is a no-op) and the counts are
 * exact, so no over-read of an uninitialised slot occurs.
 */
static backend_script  g_script;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    jmp_buf  env;

    /*
     * Arm the recovery hook around the parse. On a malformed line or missing
     * proto directive backend_load_buf die()s, which longjmps here (setjmp
     * returns 1); on success it returns normally (setjmp's initial 0 already
     * fell through to the call). Either way we land at the cleanup below -- the
     * only difference is whether a full or partial script got built, and
     * backend_free handles both.
     *
     * On the longjmp path *g_script is whatever the parser had built up to the
     * failing line -- memset to zero by backend_load_buf's first act, then
     * populated entry-by-entry -- so backend_free frees exactly those and no
     * more. The store (entries) is a fixed inline array, nothing heap-owned, so
     * the only allocations are the faults' cmd/raw, which backend_free releases.
     */
    prober_die_jmp = &env;

    if (setjmp(env) == 0) {
        backend_load_buf((const char *) data, size, &g_script);
    }

    /*
     * Disarm BEFORE backend_free: backend_free calls free(), not die, but
     * leaving a dangling &env armed past this stack frame would be a
     * use-after-scope the moment anything else called die(). Clear it first.
     */
    prober_die_jmp = NULL;

    backend_free(&g_script);

    return 0;
}
