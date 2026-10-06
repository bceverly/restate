/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Allocation that cannot return NULL, a growable byte buffer, and the
 * diagnostics every module writes.
 */
#ifndef RESTATE_UTIL_H
#define RESTATE_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "restate.h"

/*
 * Out of memory is reported and the program exits with RESTATE_EXIT_TROUBLE.
 * A partial index written after a failed allocation would be worse than no
 * index at all, so there is nothing to recover to.
 *
 * Every size computed from a count is checked for overflow before it reaches
 * the allocator: rs_xcalloc and rs_xreallocarray do the multiplication
 * themselves rather than trusting the caller to.
 */
void *rs_xmalloc(size_t n);
void *rs_xcalloc(size_t count, size_t size);
void *rs_xrealloc(void *p, size_t n);
void *rs_xreallocarray(void *p, size_t count, size_t size);
char *rs_xstrdup(const char *s);
char *rs_xstrndup(const char *s, size_t n);
char *rs_xasprintf(const char *fmt, ...) RESTATE_PRINTF(1, 2);
char *rs_xvasprintf(const char *fmt, va_list ap) RESTATE_PRINTF(1, 0);

/* A growable, always NUL-terminated byte buffer. */
struct rs_buf {
    char  *data;
    size_t len;
    size_t cap;
};

void  rs_buf_init(struct rs_buf *b);
void  rs_buf_free(struct rs_buf *b);
void  rs_buf_reset(struct rs_buf *b);
void  rs_buf_add(struct rs_buf *b, const void *data, size_t n);
void  rs_buf_addc(struct rs_buf *b, char c);
void  rs_buf_addstr(struct rs_buf *b, const char *s);
void  rs_buf_addf(struct rs_buf *b, const char *fmt, ...) RESTATE_PRINTF(2, 3);
/* Hands the contents to the caller (who frees them) and empties the buffer. */
char *rs_buf_detach(struct rs_buf *b);

/*
 * Diagnostics, prefixed with the program name and written to stderr.
 *
 * rs_quiet silences warnings but never errors: an error is the reason the exit
 * status is non-zero, and a script that asked for quiet still deserves to be
 * told why it failed.
 */
extern bool rs_quiet;
void rs_warn(const char *fmt, ...) RESTATE_PRINTF(1, 2);
void rs_error(const char *fmt, ...) RESTATE_PRINTF(1, 2);

/* true if `s` starts with `prefix`. */
bool rs_starts_with(const char *s, const char *prefix);

/*
 * Appends `word` to `b` as one shell word: as it is where it is plainly safe,
 * single-quoted otherwise. For commands written out for a person or an
 * installer to run, from names that came from a captured tree.
 */
void rs_shell_word(struct rs_buf *b, const char *word);

#endif /* RESTATE_UTIL_H */
