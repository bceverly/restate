/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate — reconstruct a machine's state from a known baseline
 *
 * The definitions every module shares: the version and copyright the program
 * prints, the exit statuses it promises, and the printf-format attribute.
 */
#ifndef RESTATE_H
#define RESTATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Set by the build (-DRESTATE_VERSION="..."), from the VERSION file. */
#ifndef RESTATE_VERSION
#define RESTATE_VERSION "0.0.0.0-dev"
#endif

/*
 * The copyright line the program prints.
 *
 * One definition, used by --help and --version. scripts/lint.sh audits every
 * source file for the same name and SPDX identifier, so the notice in the
 * comment headers, the one in the binary and the one in debian/copyright
 * cannot drift apart without something failing.
 */
#define RESTATE_COPYRIGHT "Copyright (c) 2026 Bryan C. Everly"

/*
 * Exit statuses, in the diff(1) tradition, because `diff` and `verify` are
 * the commands most likely to be called from a script that branches on them.
 *
 *   0  success; for diff and verify, no differences
 *   1  differences were found
 *   2  trouble: a usage error, an unreadable manifest, an I/O failure
 *   3  the scan finished, but some files could not be read, so the manifest
 *      is incomplete -- a backup that silently skipped files is the worst
 *      kind, so this is never folded into 0
 *   4  the image is not signed by a key it was to be checked against, and
 *      was not used
 */
#define RESTATE_EXIT_OK          0
#define RESTATE_EXIT_DIFFERENT   1
#define RESTATE_EXIT_TROUBLE     2
#define RESTATE_EXIT_INCOMPLETE  3
#define RESTATE_EXIT_UNVERIFIED  4

/*
 * Mark a function as taking a printf-style format, so the compiler checks the
 * format against the arguments at every call site, and -Wformat-nonliteral
 * can prove no format string here is attacker-controlled.
 */
#if defined(__GNUC__) || defined(__clang__)
/* Flawfinder matches the word "printf" lexically, including here, where it
 * names the attribute rather than calling anything. */
#define RESTATE_PRINTF(fmt, first) \
    __attribute__((format(printf, fmt, first))) /* Flawfinder: ignore */
#define RESTATE_NORETURN __attribute__((noreturn))
#else
#define RESTATE_PRINTF(fmt, first)
#define RESTATE_NORETURN
#endif

#endif /* RESTATE_H */
