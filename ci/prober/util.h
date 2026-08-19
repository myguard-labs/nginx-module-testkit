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
#include <stdint.h>
#include <stdio.h>
#include <time.h>

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
 * Milliseconds since an unspecified epoch, as a 64-bit count.
 *
 * The width is the whole point and is why this is int64_t rather than long.
 * `long` is 32 bits on every ILP32 target, and this repo supports one: the
 * arch-32bit workflow builds AND RUNS these suites under -m32. There,
 * tv_sec * 1000 overflows after ~24.9 days of host uptime -- signed overflow,
 * so undefined behaviour, and in practice a NEGATIVE millisecond count. Every
 * consumer of this clock is a deadline: fakesrv's close_after arms
 * `close_at_ms = now + ms` and disarms on the `>= 0` sentinel, so a wrapped
 * clock reads as "no deadline armed" and the fault silently never fires --
 * a fake server that answers a test by not doing the thing the test asked
 * for. CI runs start near zero uptime, so no amount of green CI on either
 * arch exposes it; the width is a contract, pinned by the endpoint rows in
 * util_test.c rather than by a run that reaches the wrap.
 *
 * Returns 0 when the clock is unavailable, matching the caller's pre-existing
 * behaviour: fakesrv treats that as "no time has passed", which stalls its
 * deadlines rather than firing them early.
 */
int64_t prober_monotonic_ms(void);

/*
 * The conversion prober_monotonic_ms() performs, separated from the syscall so
 * a test can hand it a timespec no test host will ever have been up for. Pure:
 * no clock read, no global state.
 */
int64_t prober_timespec_ms(const struct timespec *ts);

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

/*
 * Write `n` bytes of `s` to `fp` as a double-quoted JSON string, escaping
 * whatever JSON forbids. Length-delimited rather than NUL-delimited: `s` is a
 * RESP argument, which is binary-safe and may contain embedded NULs, so
 * iterating to strlen() would silently truncate the record.
 *
 * `s` is a client's wire bytes, so this has to hold for anything a byte can
 * be, not just the ASCII a hand test happens to try. Two classes need
 * escaping: JSON's own syntax (quote, backslash, C0 controls) and the byte
 * values 0x80-0xff. Those are never valid on their own as a single-byte
 * unit under UTF-8 (continuation bytes 0x80-0xbf need a preceding lead byte;
 * 0xf8-0xff are not assigned at all), and JSON text is required to be valid
 * Unicode -- RFC 8259 SS8.1. A RESP command is not itself required to be
 * UTF-8, so a lone high byte (e.g. 0xC0 from an attacker-chosen argument)
 * must not be forwarded as if it already were. `\u00XX` on the raw byte
 * value is the honest, lossless rendering: a decoder gets back the exact
 * byte, and the line stays valid JSON either way, which is the point --
 * the journal is documented as JSONL and every consumer is entitled to
 * `jq` it without a byte in the input breaking that contract.
 *
 * Split out from fakesrv.c's jlog()/jstr() so it is reachable from a test
 * binary: fakesrv.c has a main() and links into no test binary (same
 * reasoning as prober_monotonic_ms() versus fakesrv.c's now_ms() wrapper,
 * above).
 */
void prober_jstrn(FILE *fp, const char *s, size_t n);

#endif /* NGX_TEST_HARNESS_UTIL_H */
