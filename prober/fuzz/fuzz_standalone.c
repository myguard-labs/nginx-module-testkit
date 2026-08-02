/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Engine-neutral corpus-replay driver.
 *
 * libFuzzer (and honggfuzz, and AFL's persistent mode) supply their own main()
 * that calls LLVMFuzzerTestOneInput in a mutate loop. That loop needs clang and
 * runs unbounded, so it belongs in a scheduled discovery job, not on the PR
 * path. For the PR path we want the SAME targets replayed once over a fixed,
 * checked-in corpus under plain gcc + ASan/UBSan, with a nonzero exit on the
 * first crash -- deterministic, fast, no external engine.
 *
 * This file provides exactly that main(): each argv is a file (or a directory
 * of files) whose bytes are fed once to LLVMFuzzerTestOneInput. It is the LLVM
 * "StandaloneFuzzTargetMain" pattern. Linked with one fuzz_*.c at a time (each
 * defines LLVMFuzzerTestOneInput), it becomes a replay binary for that target.
 *
 * Exit status: 0 iff every input was processed without the process dying. A
 * sanitizer abort (ASan/UBSan halt_on_error) or a real crash terminates with a
 * nonzero status of the runtime's choosing -- which is the whole point, and is
 * what the ci.yml corpus-replay step asserts. A target that "reports but exits
 * 0" is the vacuous fuzz gate this driver is built to make impossible: there is
 * no reporting path here, only the process living or dying.
 */
/* S_ISLNK and lstat are POSIX, not C11; -std=c11 hides them without this. */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Optional one-time init some targets define; ours do not, so this stays a
 * weak-ish no-op via a local default. Kept for drop-in parity with libFuzzer
 * targets that use it. */
__attribute__((weak)) int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    return 0;
}

/* Both run_file() and run_path() report how many files were actually handed
 * to LLVMFuzzerTestOneInput via *nfiles (added to, never reset), and return
 * 0/-1 for I/O success/failure the same as before. main()'s completion count
 * must reflect files processed, not argv entries -- an argv that is a
 * directory is one entry but zero-to-many files, and an emptied corpus
 * directory must count as zero, not one. */
static int
run_file(const char *path, long *nfiles)
{
    FILE    *f;
    long     len;
    size_t   got;
    uint8_t *buf;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "fuzz-replay: cannot open %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(stderr, "fuzz-replay: cannot seek %s\n", path);
        return -1;
    }
    len = ftell(f);
    if (len < 0) {
        fclose(f);
        fprintf(stderr, "fuzz-replay: cannot tell %s\n", path);
        return -1;
    }
    rewind(f);

    /* An empty corpus file is legitimate (it is the size==0 edge case) and must
     * still reach the target, so a zero-length malloc is replaced with 1 to keep
     * the pointer non-NULL while the reported size stays 0. */
    buf = malloc((size_t) len == 0 ? 1 : (size_t) len);
    if (buf == NULL) {
        fclose(f);
        fprintf(stderr, "fuzz-replay: out of memory for %s\n", path);
        return -1;
    }

    got = fread(buf, 1, (size_t) len, f);
    fclose(f);
    if (got != (size_t) len) {
        free(buf);
        fprintf(stderr, "fuzz-replay: short read on %s\n", path);
        return -1;
    }

    LLVMFuzzerTestOneInput(buf, (size_t) len);
    free(buf);
    (*nfiles)++;
    return 0;
}

static int
run_path(const char *path, long *nfiles)
{
    struct stat  st;

    /* lstat, not stat: a symlink in the corpus (a -> ., or a -> /) would
     * otherwise be followed and, if it points at a directory, recurse forever.
     * A corpus is checked-in test data, so a symlink there is never a real
     * input -- skip it rather than chase it. */
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "fuzz-replay: cannot lstat %s\n", path);
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        fprintf(stderr, "fuzz-replay: skipping symlink %s\n", path);
        return 0;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR           *d;
        struct dirent *e;
        int            rc = 0;

        d = opendir(path);
        if (d == NULL) {
            fprintf(stderr, "fuzz-replay: cannot opendir %s\n", path);
            return -1;
        }
        while ((e = readdir(d)) != NULL) {
            char sub[4096];

            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            if ((size_t) snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name)
                >= sizeof(sub))
            {
                fprintf(stderr, "fuzz-replay: path too long under %s\n", path);
                rc = -1;
                continue;
            }
            if (run_path(sub, nfiles) != 0) {
                rc = -1;
            }
        }
        closedir(d);
        return rc;
    }

    return run_file(path, nfiles);
}

int
main(int argc, char **argv)
{
    int   i;
    int   rc = 0;
    long  nfiles = 0;

    LLVMFuzzerInitialize(&argc, &argv);

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <corpus-file-or-dir> [more ...]\n"
                "replays each input once through the fuzz target; a crash or a\n"
                "sanitizer abort terminates with a nonzero status.\n",
                argv[0]);
        return 2;
    }

    for (i = 1; i < argc; i++) {
        if (run_path(argv[i], &nfiles) != 0) {
            rc = 1;   /* an I/O problem with the corpus, not a target crash */
        }
    }

    /* nfiles counts files actually handed to LLVMFuzzerTestOneInput, not argv
     * entries -- an argv that is a directory recurses to zero-to-many files.
     * A corpus that resolves to zero files (emptied directory, or every path
     * an I/O failure) ran nothing, so it must not report clean: that would
     * make an emptied corpus a silent, permanent pass. */
    if (nfiles == 0) {
        fprintf(stderr,
                "fuzz-replay: 0 files processed -- empty or unreadable corpus, "
                "treating as failure\n");
        return rc != 0 ? rc : 1;
    }

    /* "clean" is a claim about the whole replay, so it may only be printed
     * when rc is 0. A partial corpus -- some files replayed, others
     * unreadable -- exits nonzero either way, but saying "processed clean"
     * next to a nonzero rc sends whoever reads the log looking for a crash
     * that did not happen, when the real fault is the corpus. */
    if (rc == 0) {
        fprintf(stderr, "fuzz-replay: %ld file(s) processed clean, rc=0\n",
                nfiles);
    } else {
        fprintf(stderr,
                "fuzz-replay: %ld file(s) processed, corpus I/O failed on at "
                "least one path, rc=%d\n", nfiles, rc);
    }

    return rc;
}
