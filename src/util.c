/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool rs_quiet = false;

RESTATE_NORETURN static void out_of_memory(size_t n)
{
    (void)fprintf(stderr, "restate: out of memory allocating %zu bytes\n", n);
    exit(RESTATE_EXIT_TROUBLE);
}

void *rs_xmalloc(size_t n)
{
    /* malloc(0) may legitimately return NULL; asking for one byte means a
     * NULL here always means the allocation failed. */
    void *p = malloc(n ? n : 1);

    if (!p)
    {
        out_of_memory(n);
    }
    return p;
}

void *rs_xcalloc(size_t count, size_t size)
{
    void *p;

    if (size != 0 && count > SIZE_MAX / size)
    {
        out_of_memory(SIZE_MAX);
    }
    p = calloc(count ? count : 1, size ? size : 1);
    if (!p)
    {
        out_of_memory(count * size);
    }
    return p;
}

void *rs_xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);

    if (!q)
    {
        out_of_memory(n);
    }
    return q;
}

void *rs_xreallocarray(void *p, size_t count, size_t size)
{
    if (size != 0 && count > SIZE_MAX / size)
    {
        out_of_memory(SIZE_MAX);
    }
    return rs_xrealloc(p, count * size);
}

char *rs_xstrdup(const char *s)
{
    return rs_xstrndup(s, strlen(s));
}

char *rs_xstrndup(const char *s, size_t n)
{
    char  *p;
    size_t len = 0;

    while (len < n && s[len] != '\0')
    {
        len++;
    }
    p = rs_xmalloc(len + 1);
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

char *rs_xvasprintf(const char *fmt, va_list ap)
{
    va_list copy;
    int     need;
    char   *p;

    va_copy(copy, ap);
    /* `fmt` is always a caller's literal: RESTATE_PRINTF on every entry
     * point makes the compiler check it, and -Wformat-nonliteral proves it. */
    need = vsnprintf(NULL, 0, fmt, copy); /* Flawfinder: ignore */
    va_end(copy);
    if (need < 0)
    {
        /* Only an encoding error gets here; an empty string is a safer
         * answer than a crash. */
        return rs_xstrdup("");
    }
    p = rs_xmalloc((size_t)need + 1);
    (void)vsnprintf(p, (size_t)need + 1, fmt, ap); /* Flawfinder: ignore */
    return p;
}

char *rs_xasprintf(const char *fmt, ...)
{
    va_list ap;
    char   *p;

    va_start(ap, fmt);
    p = rs_xvasprintf(fmt, ap);
    va_end(ap);
    return p;
}

/* ------------------------------------------------------------------------- */

void rs_buf_init(struct rs_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void rs_buf_free(struct rs_buf *b)
{
    free(b->data);
    rs_buf_init(b);
}

void rs_buf_reset(struct rs_buf *b)
{
    b->len = 0;
    if (b->data)
    {
        b->data[0] = '\0';
    }
}

static void buf_reserve(struct rs_buf *b, size_t extra)
{
    size_t want;

    if (extra > SIZE_MAX - b->len - 1)
    {
        out_of_memory(SIZE_MAX);
    }
    want = b->len + extra + 1;
    if (want <= b->cap)
    {
        return;
    }
    if (b->cap == 0)
    {
        b->cap = 64;
    }
    while (b->cap < want)
    {
        b->cap = b->cap > SIZE_MAX / 2 ? want : b->cap * 2;
    }
    b->data = rs_xrealloc(b->data, b->cap);
}

void rs_buf_add(struct rs_buf *b, const void *data, size_t n)
{
    buf_reserve(b, n);
    if (n > 0)
    {
        memcpy(b->data + b->len, data, n);
    }
    b->len += n;
    b->data[b->len] = '\0';
}

void rs_buf_addc(struct rs_buf *b, char c)
{
    rs_buf_add(b, &c, 1);
}

void rs_buf_addstr(struct rs_buf *b, const char *s)
{
    rs_buf_add(b, s, strlen(s));
}

void rs_buf_addf(struct rs_buf *b, const char *fmt, ...)
{
    va_list ap;
    char   *s;

    va_start(ap, fmt);
    s = rs_xvasprintf(fmt, ap);
    va_end(ap);
    rs_buf_addstr(b, s);
    free(s);
}

char *rs_buf_detach(struct rs_buf *b)
{
    char *p;

    if (!b->data)
    {
        return rs_xstrdup("");
    }
    p = b->data;
    rs_buf_init(b);
    return p;
}

/* ------------------------------------------------------------------------- */

static void vreport(const char *kind, const char *fmt, va_list ap) RESTATE_PRINTF(2, 0);

static void vreport(const char *kind, const char *fmt, va_list ap)
{
    /* Flushed first so a diagnostic lands after the output that preceded it
     * when both go to the same terminal or log. */
    (void)fflush(stdout);
    (void)fprintf(stderr, "restate: %s", kind);
    (void)vfprintf(stderr, fmt, ap); /* Flawfinder: ignore -- checked, as above */
    (void)fputc('\n', stderr);
}

void rs_warn(const char *fmt, ...)
{
    va_list ap;

    if (rs_quiet)
    {
        return;
    }
    va_start(ap, fmt);
    vreport("warning: ", fmt, ap);
    va_end(ap);
}

void rs_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vreport("", fmt, ap);
    va_end(ap);
}

bool rs_starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}
