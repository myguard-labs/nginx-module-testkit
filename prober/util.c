/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * util.c -- see util.h.
 */

/* strdup() is POSIX, not C11, and the build asks for -std=c11 strictly. */
#define _GNU_SOURCE

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* NULL in every normal build -- see util.h. The fuzz target arms it so die()
 * longjmps back instead of exiting. */
jmp_buf *prober_die_jmp = NULL;


_Noreturn void
die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "prober: ");

    /* -Wformat=2 implies -Wformat-nonliteral, which fires on every va_list
     * forwarder because the format is a parameter rather than a literal. That
     * is the whole point of this function, so the diagnostic is suppressed for
     * exactly this line -- not the file. The checking is not lost: the
     * format(printf, 1, 2) attribute on the declaration in util.h moves it to
     * die()'s callers, where the literal actually is. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    /*
     * The suppression below is a false positive, and a version-dependent one:
     * the CI runner's clang-tidy reports this va_list as uninitialized at the
     * vfprintf, while 19.1.7 locally does not. va_start() is a few lines up and
     * va_end() a few lines down with no branch between them -- the checker
     * loses the initialization crossing the diagnostic pragma region above.
     *
     * Suppressed at this one line rather than by dropping the checker from the
     * job: valist.Uninitialized catches a real bug class (forwarding a va_list
     * after va_end, or into a second variadic call without va_copy), and this
     * is the only site in the codebase that trips it.
     *
     * The marker has to be the LAST line before the code -- clang-tidy only
     * honours NOLINTNEXTLINE on the line immediately preceding. Putting it at
     * the top of this comment block reads better and silently does nothing,
     * which is how a suppression becomes a permanently red gate nobody can
     * explain.
     */
    /*
     * flawfinder rates any vfprintf level 4 on the assumption the format may
     * be attacker-influenced. It cannot be here: die() is
     * __attribute__((format(printf, 1, 2))) and build.sh compiles with
     * -Wformat=2, whose -Wformat-nonliteral arm makes a non-literal format at
     * any call site a BUILD failure under -Werror. The gate is the compiler,
     * not a convention, so the finding is suppressed rather than carried.
     */
    /* NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized) */
    vfprintf(stderr, fmt, ap);  /* flawfinder: ignore */
#pragma GCC diagnostic pop

    fprintf(stderr, "\n");
    va_end(ap);

    /* A harness that armed the recovery hook (the rules fuzz target) unwinds
     * back to its setjmp instead of exiting, so a die-on-syntax-error rule
     * file returns to the fuzzer as a handled reject rather than aborting the
     * process. longjmp is _Noreturn, so die()'s noreturn contract still holds.
     * NULL in every normal build -- the exit(2) below is the only path then. */
    if (prober_die_jmp != NULL) {
        longjmp(*prober_die_jmp, 1);
    }

    exit(2);
}


char *
xstrdup(const char *s)
{
    char *p = strdup(s);

    if (p == NULL) {
        die("out of memory");
    }

    return p;
}


char *
trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char) *s)) {
        s++;
    }

    end = s + strlen(s);

    while (end > s && isspace((unsigned char) end[-1])) {
        end--;
    }

    *end = '\0';

    return s;
}


long
xstrtol(const char *s, const char *what)
{
    char *stop;
    long  v;

    if (s == NULL || *s == '\0') {
        die("%s: expected a number, got an empty value", what);
    }

    errno = 0;
    v = strtol(s, &stop, 10);

    /*
     * Three distinct failures, all of which atoi() would have reported as 0:
     * trailing garbage ("10junk"), a value outside long (ERANGE), and a token
     * that was not a number at all (stop == s, caught by the same check).
     */
    if (*stop != '\0') {
        die("%s: \"%s\" is not a number", what, s);
    }

    if (errno == ERANGE) {
        die("%s: \"%s\" is out of range", what, s);
    }

    return v;
}


int64_t
prober_timespec_ms(const struct timespec *ts)
{
    /*
     * The cast is on tv_sec, not on the product: tv_sec is time_t, which is
     * 32 bits on an ILP32 target, so multiplying first and widening after
     * would overflow exactly where this function exists to not overflow.
     */
    return (int64_t) ts->tv_sec * 1000 + (int64_t) ts->tv_nsec / 1000000;
}


int64_t
prober_monotonic_ms(void)
{
    struct timespec ts;

    /*
     * CLOCK_MONOTONIC, not the wall clock: one of the scenarios this clock
     * serves drives libfaketime, and a fault deadline measured on a clock the
     * test is deliberately moving would fire at a time nobody asked for.
     */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return prober_timespec_ms(&ts);
}


void
append_escaped(unsigned char **buf, size_t *len, size_t *cap, const char *src,
               const char *where)
{
    while (*src != '\0') {
        unsigned char c;

        if (*src == '\\' && src[1] != '\0') {
            src++;

            switch (*src) {
            case 'r':  c = '\r'; src++; break;
            case 'n':  c = '\n'; src++; break;
            case 't':  c = '\t'; src++; break;
            case '0':  c = '\0'; src++; break;
            case '\\': c = '\\'; src++; break;
            case '"':  c = '"';  src++; break;

            case 'x': {
                char  hex[3];
                int   i = 0;

                src++;

                while (i < 2 && isxdigit((unsigned char) src[i])) {
                    hex[i] = src[i];
                    i++;
                }

                if (i == 0) {
                    die("bad \\x escape in %s", where);
                }

                hex[i] = '\0';
                c = (unsigned char) strtol(hex, NULL, 16);
                src += i;
                break;
            }

            default:
                die("unknown escape \\%c in %s", *src, where);
            }

        } else {
            c = (unsigned char) *src++;
        }

        if (*len + 1 >= *cap) {
            unsigned char *bigger;

            *cap = (*cap == 0) ? 256 : *cap * 2;
            bigger = realloc(*buf, *cap);
            if (bigger == NULL) {
                die("out of memory");
            }
            *buf = bigger;
        }

        (*buf)[(*len)++] = c;
    }
}


void
prober_jstrn(FILE *fp, const char *s, size_t n)
{
    size_t i;

    fputc('"', fp);

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];

        switch (c) {
        case '"':  fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n", fp);  break;
        case '\r': fputs("\\r", fp);  break;
        case '\t': fputs("\\t", fp);  break;
        default:
            /* c >= 0x80 is not valid on its own as a single-byte unit
             * under UTF-8 (see util.h): JSON text must be valid Unicode,
             * so a lone high byte gets the same \u00XX escape as a C0
             * control rather than being forwarded raw and breaking every
             * consumer's JSON parser. Folded into one condition with the
             * C0/DEL case (rather than a separate `else if`) because both
             * arms emit byte-identical output -- clang-tidy's
             * bugprone-branch-clone flags the split as a repeated branch
             * body, and this repo's analyzers job runs -warnings-as-errors. */
            if (c < 0x20 || c == 0x7f || c >= 0x80) {
                fprintf(fp, "\\u%04x", c);
            } else {
                fputc((int) c, fp);
            }
        }
    }

    fputc('"', fp);
}
