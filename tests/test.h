/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A test harness in one header.
 *
 * No external framework: restate is a small C program with no dependencies,
 * and a test runner that needs a package installed before `make test` works
 * would undo that. What is here is what a unit test needs -- a name, checks
 * that keep going after a failure so one run reports every problem, and a
 * count at the end.
 */
#ifndef RESTATE_TEST_H
#define RESTATE_TEST_H

#include <stdio.h>
#include <string.h>

#include "restate.h"

extern int         rs_test_checks;
extern int         rs_test_failures;
extern const char *rs_test_case;

void rs_test_begin(const char *name);
void rs_test_fail(const char *file, int line, const char *fmt, ...)
    RESTATE_PRINTF(3, 4);

/* A fresh scratch directory under $TMPDIR, removed by rs_test_rmtree. The
 * returned string is the caller's to free. */
char *rs_test_tmpdir(void);
void  rs_test_rmtree(const char *path);
/* Writes `text` to `dir`/`name`, creating it with `mode`. */
void  rs_test_write(const char *dir, const char *name, const char *text, unsigned mode);
/* Runs `fn` with stdout and stderr sent to files, and returns what it
 * returned; the captured text lands in `out` and `err` (caller frees). */
int   rs_test_capture(int (*fn)(const void *), const void *arg, char **out, char **err);

#define TEST_CASE(name) rs_test_begin(name)

#define CHECK(cond)                                                            \
    do {                                                                       \
        rs_test_checks++;                                                      \
        if (!(cond))                                                           \
            rs_test_fail(__FILE__, __LINE__, "%s", #cond);                     \
    } while (0)

#define CHECK_STR(actual, expected)                                            \
    do {                                                                       \
        const char *a_ = (actual);                                             \
        const char *e_ = (expected);                                           \
        rs_test_checks++;                                                      \
        if (!a_ || !e_ || strcmp(a_, e_) != 0)                                 \
            rs_test_fail(__FILE__, __LINE__, "expected \"%s\", got \"%s\"",    \
                         e_ ? e_ : "(null)", a_ ? a_ : "(null)");              \
    } while (0)

#define CHECK_INT(actual, expected)                                            \
    do {                                                                       \
        long long a_ = (long long)(actual);                                    \
        long long e_ = (long long)(expected);                                  \
        rs_test_checks++;                                                      \
        if (a_ != e_)                                                          \
            rs_test_fail(__FILE__, __LINE__, "%s: expected %lld, got %lld",    \
                         #actual, e_, a_);                                     \
    } while (0)

#define CHECK_CONTAINS(haystack, needle)                                       \
    do {                                                                       \
        const char *h_ = (haystack);                                           \
        rs_test_checks++;                                                      \
        if (!h_ || !strstr(h_, (needle)))                                      \
            rs_test_fail(__FILE__, __LINE__, "\"%s\" does not contain \"%s\"", \
                         h_ ? h_ : "(null)", (needle));                        \
    } while (0)

/* Every suite, declared here and called from test_main.c. */
void test_util(void);
void test_sha256(void);
void test_glob(void);
void test_rules(void);
void test_json(void);
void test_meta(void);
void test_index(void);
void test_image(void);
void test_machine(void);
void test_packages(void);
void test_installer(void);
void test_rebuild(void);
void test_pgp(void);
void test_bsd(void);
void test_progress(void);
void test_scan(void);
void test_diff(void);
void test_opts(void);
void test_cmd(void);

#endif /* RESTATE_TEST_H */
