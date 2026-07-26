/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * util.h -- the three helpers shared by the rule parser and the assertion
 * evaluator.
 */

#ifndef NGX_TEST_HARNESS_UTIL_H
#define NGX_TEST_HARNESS_UTIL_H

#include <setjmp.h>
#include <stddef.h>

/*
 * Fatal, with a "prober: " prefix on stderr and exit status 2.
 *
 * _Noreturn is load-bearing rather than decoration: without it clang cannot see
 * that the default arm of the escape switch in the rule parser never falls
 * through, and rejects the function under -Wsometimes-uninitialized.
 *
 * Status 2 and not 1 so a rule-file or usage error is distinguishable from
 * "the tests ran and some failed", which is 1.
 *
 * The GNU noreturn attribute is spelled out ALONGSIDE C11 _Noreturn, which is
 * redundant to a compiler and is not redundant to cppcheck: it does not model
 * _Noreturn, so every `if (x == NULL) { die(...); }` guard in this codebase
 * reads to it as a fall-through into a null dereference. That produced four
 * null-pointer findings, all false, at sites where the guard is correct.
 * Suppressing them by id would have blinded the checker to the genuine class
 * as well, so the declaration is made legible to the tool instead. Verified
 * against cppcheck 2.17.1: with only _Noreturn it warns, with the attribute
 * it does not.
 */
_Noreturn void die(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)))
    __attribute__((noreturn));

/*
 * Recovery hook for die(), NULL in every normal build so die() exit(2)s
 * exactly as before. A test/fuzz harness that must survive a die() (the rules
 * fuzz target, which feeds die-on-syntax-error rule files by the thousand)
 * points this at an armed jmp_buf; die() then longjmp(*prober_die_jmp, 1)s to
 * it instead of exiting, still without returning to its caller (longjmp is
 * _Noreturn), so die()'s noreturn contract holds. Single-threaded use only:
 * the prober and its self-tests never call die() from more than one thread.
 * The value passed to longjmp is 1 (setjmp returns it), never 0.
 */
extern jmp_buf *prober_die_jmp;

/* strdup(), or die trying. */
char *xstrdup(const char *s);

/* Trim leading and trailing whitespace in place; returns the new start. */
char *trim(char *s);

/*
 * strtol() where the WHOLE token has to be the number, or die with `what` in
 * the message.
 *
 * This exists because atoi() cannot report a conversion error: it returns 0 for
 * "junk" exactly as it does for "0". On a command-line flag that is a silent
 * wrong answer -- `-p http` became port 0 and `-t junk` became a 0 ms timeout,
 * which times out every request and reds the entire suite while pointing
 * nowhere near the actual mistake. The rule parser already rejects partial
 * numbers for the same reason (see the "10junk" note in rules.c); this is that
 * check, shared, instead of open-coded a fourth time.
 */
long xstrtol(const char *s, const char *what);

/*
 * Decode this repo's text escapes -- \r \n \t \\ \" \0 \xNN -- into raw bytes
 * appended to *buf, growing it as needed. Byte-exact: no implied CRLF, no
 * length synthesis, no reordering. The bytes in the file are the bytes that go
 * on the wire.
 *
 * Shared rather than duplicated. Two text formats now spell out wire bytes by
 * hand -- a rule file's `send` and a backend script's `raw` reply -- and both
 * must agree on what "\x00" means down to the byte, because a case asserting on
 * an embedded NUL is testing precisely the disagreement a second copy of this
 * lexer would introduce. A forked escape table would not fail a test; it would
 * silently put different bytes on the wire than the file says, which is the one
 * defect class no amount of running the suite reveals.
 *
 * `where` names the construct being decoded ("send line", "raw reply") and
 * appears in the die() message, so a bad escape still points at the syntax the
 * author actually wrote instead of at whichever caller happens to share the
 * code.
 */
void append_escaped(unsigned char **buf, size_t *len, size_t *cap,
                    const char *src, const char *where);

#endif /* NGX_TEST_HARNESS_UTIL_H */
