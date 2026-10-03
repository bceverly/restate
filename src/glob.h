/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Path patterns for the classification rules.
 *
 *   *     any run of characters except '/'
 *   **    any run of characters including '/'
 *   **\/  zero or more whole directories
 *   ?     one character except '/'
 *   \c    the character c, literally
 *
 * Every other character matches itself. A pattern that does not begin with
 * '/' matches at any depth, exactly as if it had been written with a leading
 * "**\/" -- so "*.pid" matches "/run/sshd.pid" and "/var/run/x/y.pid".
 *
 * Written here rather than taken from fnmatch(3) for two reasons. fnmatch has
 * no "**", and each platform's fnmatch has its own idea of FNM_PATHNAME and
 * FNM_LEADING_DIR, which is exactly the kind of difference that makes one
 * rule set classify a file differently on FreeBSD than on Linux. And the
 * implementation below runs in time proportional to the pattern length times
 * the path length, whatever the pattern -- the usual recursive matcher is
 * exponential on a pattern like "*a*a*a*a*b", and the rules file is input.
 */
#ifndef RESTATE_GLOB_H
#define RESTATE_GLOB_H

#include <stdbool.h>

/* true if the whole of `path` matches `pattern`. */
bool rs_glob_match(const char *pattern, const char *path);

/*
 * true if `pattern` matches `path` itself or any of its ancestor directories.
 * This is what a rule means: "/tmp" covers "/tmp" and everything under it.
 */
bool rs_glob_covers(const char *pattern, const char *path);

#endif /* RESTATE_GLOB_H */
