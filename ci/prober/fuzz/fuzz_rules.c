/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libFuzzer target for load_rules() -- the rule-file parser (rules.c). Chosen
 * because a rule file is the harness's most complex untrusted-text surface: a
 * ~40-directive line grammar with per-directive numeric bounds, escape
 * decoding, regex compilation, pipeline sub-blocks and cross-line budget
 * checks, any of which a malformed file can drive into a bad state a hand-
 * written fixture would not think to try.
 *
 * TWO things make this target work where a naive one would not:
 *
 *   1. load_rules_buf(): the production entry load_rules() reads a PATH via
 *      fopen/fgets, not a (data, size) buffer. load_rules_buf() fmemopen()s the
 *      fuzzer's bytes into the SAME parser (load_rules_fp), so no fuzz-only
 *      reimplementation exists to drift from what the prober actually runs.
 *
 *   2. the die() recovery hook: load_rules() die()s (exit(2)s) on ANY syntax
 *      error -- correct for production (a rule file that does not mean what it
 *      says must not run) but fatal for a fuzzer, which feeds malformed files
 *      by the million and every one would abort the process. Arming
 *      prober_die_jmp makes die() longjmp back here instead, so a rejected file
 *      is a handled non-event, and only a CRASH (ASan/UBSan finding, real
 *      abort) fails the run -- exactly the bug class the target exists to find.
 *
 * Engine-neutral: defines LLVMFuzzerTestOneInput and nothing else, so it links
 * under -fsanitize=fuzzer (clang) and under fuzz_standalone.c's corpus replay
 * (plain gcc, no engine), same as the sibling targets.
 */
#define _GNU_SOURCE

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

#include "../rules.h"
#include "../util.h"

/*
 * One static array reused across runs (libFuzzer calls this in a tight loop).
 * Every slot is case_free()d after each input, which both releases what the
 * parser built AND -- because case_free memsets the slot to zero on its way out
 * -- leaves the array clean for the next input. case_free is safe on a zeroed
 * slot (all pointers NULL -> free(NULL); all counts 0 -> no regfree on an
 * uninitialised regex_t), so freeing all MAX_CASES slots unconditionally,
 * including ones a short run never touched, is correct.
 */
static test_case  g_cases[MAX_CASES];

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    jmp_buf  env;
    size_t   i;

    /*
     * Arm the recovery hook around the parse. On a syntax error load_rules_fp
     * die()s, which longjmps here (setjmp returns 1); on success it returns
     * normally (setjmp's initial 0 already fell through to the call). Either
     * way we land at the cleanup below -- the only difference is whether a full
     * or partial set of slots got built, and case_free handles both.
     */
    prober_die_jmp = &env;

    if (setjmp(env) == 0) {
        (void) load_rules_buf((const char *) data, size, g_cases, MAX_CASES);
    }

    /*
     * Disarm BEFORE case_free: case_free calls regfree/free, not die, but
     * leaving a dangling &env armed past this stack frame would be a
     * use-after-scope the moment anything else called die(). Clear it first.
     */
    prober_die_jmp = NULL;

    for (i = 0; i < MAX_CASES; i++) {
        case_free(&g_cases[i]);
    }

    return 0;
}
