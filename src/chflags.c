/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "chflags.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#define RS_CHFLAGS 1
#endif

/* Each flag's name, restate's bit, and this system's, or 0 where it has
 * none. The names are chflags(1)'s. */
#ifndef SF_ARCHIVED
#define SF_ARCHIVED 0
#endif
#ifndef SF_IMMUTABLE
#define SF_IMMUTABLE 0
#endif
#ifndef SF_APPEND
#define SF_APPEND 0
#endif
#ifndef SF_NOUNLINK
#define SF_NOUNLINK 0
#endif
#ifndef UF_NODUMP
#define UF_NODUMP 0
#endif
#ifndef UF_IMMUTABLE
#define UF_IMMUTABLE 0
#endif
#ifndef UF_APPEND
#define UF_APPEND 0
#endif
#ifndef UF_NOUNLINK
#define UF_NOUNLINK 0
#endif
#ifndef UF_OPAQUE
#define UF_OPAQUE 0
#endif
#ifndef UF_HIDDEN
#define UF_HIDDEN 0
#endif
#ifndef UF_ARCHIVE
#define UF_ARCHIVE 0
#endif
#ifndef UF_SYSTEM
#define UF_SYSTEM 0
#endif
#ifndef UF_SPARSE
#define UF_SPARSE 0
#endif
#ifndef UF_OFFLINE
#define UF_OFFLINE 0
#endif
#ifndef UF_REPARSE
#define UF_REPARSE 0
#endif
#ifndef UF_READONLY
#define UF_READONLY 0
#endif

static const struct {
    const char   *name;
    unsigned      bit;
    unsigned long native;
} flags[] = {
    { "arch", RS_CHF_ARCH, SF_ARCHIVED },     { "schg", RS_CHF_SCHG, SF_IMMUTABLE },
    { "sappnd", RS_CHF_SAPPND, SF_APPEND },   { "sunlnk", RS_CHF_SUNLNK, SF_NOUNLINK },
    { "nodump", RS_CHF_NODUMP, UF_NODUMP },   { "uchg", RS_CHF_UCHG, UF_IMMUTABLE },
    { "uappnd", RS_CHF_UAPPND, UF_APPEND },   { "uunlnk", RS_CHF_UUNLNK, UF_NOUNLINK },
    { "opaque", RS_CHF_OPAQUE, UF_OPAQUE },   { "hidden", RS_CHF_HIDDEN, UF_HIDDEN },
    { "uarch", RS_CHF_UARCH, UF_ARCHIVE },    { "system", RS_CHF_SYSTEM, UF_SYSTEM },
    { "sparse", RS_CHF_SPARSE, UF_SPARSE },   { "offline", RS_CHF_OFFLINE, UF_OFFLINE },
    { "reparse", RS_CHF_REPARSE, UF_REPARSE }, { "rdonly", RS_CHF_RDONLY, UF_READONLY },
};

#define NFLAGS (sizeof(flags) / sizeof(flags[0]))

/* The tests' flags, by file, while they pretend. */
struct pretended {
    dev_t    dev;
    ino_t    ino;
    unsigned flags;
};

static bool              pretending;
static struct pretended *pretended;
static size_t            npretended;

void rs_chflags_pretend(bool on)
{
    free(pretended);
    pretended = NULL;
    npretended = 0;
    pretending = on;
}

static struct pretended *pretended_of(const struct stat *st, bool make)
{
    size_t i;

    for (i = 0; i < npretended; i++)
    {
        if (pretended[i].dev == st->st_dev && pretended[i].ino == st->st_ino)
        {
            return &pretended[i];
        }
    }
    if (!make)
    {
        return NULL;
    }
    pretended = rs_xreallocarray(pretended, npretended + 1, sizeof(*pretended));
    pretended[npretended].dev = st->st_dev;
    pretended[npretended].ino = st->st_ino;
    pretended[npretended].flags = 0;
    return &pretended[npretended++];
}

bool rs_chflags_supported(void)
{
#ifdef RS_CHFLAGS
    return true;
#else
    return pretending;
#endif
}

void rs_chflags_text(unsigned bits, struct rs_buf *out)
{
    size_t i;
    bool   first = true;

    for (i = 0; i < NFLAGS; i++)
    {
        if (bits & flags[i].bit)
        {
            if (!first)
            {
                rs_buf_addc(out, ',');
            }
            rs_buf_addstr(out, flags[i].name);
            first = false;
        }
    }
}

unsigned rs_chflags_parse(const char *text, struct rs_buf *unknown)
{
    unsigned    bits = 0;
    const char *p = text;

    while (p && *p)
    {
        const char *end = strchr(p, ',');
        size_t      len = end ? (size_t)(end - p) : strlen(p);
        size_t      i;
        bool        known = false;

        for (i = 0; i < NFLAGS && len > 0; i++)
        {
            if (strlen(flags[i].name) == len && strncmp(flags[i].name, p, len) == 0)
            {
                bits |= flags[i].bit;
                known = true;
            }
        }
        if (!known && len > 0 && unknown)
        {
            if (unknown->len)
            {
                rs_buf_addc(unknown, ',');
            }
            rs_buf_add(unknown, p, len);
        }
        p = end ? end + 1 : NULL;
    }
    return bits;
}

unsigned rs_chflags_settable(void)
{
    unsigned bits = 0;
    size_t   i;

    for (i = 0; i < NFLAGS; i++)
    {
        if (flags[i].native != 0 || pretending)
        {
            bits |= flags[i].bit;
        }
    }
    return bits;
}

unsigned rs_chflags_of(const struct stat *st)
{
    if (pretending)
    {
        const struct pretended *p = pretended_of(st, false);

        return p ? p->flags : 0;
    }
#ifdef RS_CHFLAGS
    {
        unsigned bits = 0;
        size_t   i;

        for (i = 0; i < NFLAGS; i++)
        {
            if (flags[i].native != 0 && ((unsigned long)st->st_flags & flags[i].native) != 0)
            {
                bits |= flags[i].bit;
            }
        }
        return bits;
    }
#else
    return 0;
#endif
}

int rs_chflags_set(int fd, unsigned bits)
{
    struct stat st;

    if (fstat(fd, &st) != 0)
    {
        return -1;
    }
    if (pretending)
    {
        pretended_of(&st, true)->flags = bits & rs_chflags_settable();
        return 0;
    }
#ifdef RS_CHFLAGS
    {
        unsigned long native = 0;
        unsigned long ours = 0;
        size_t        i;

        for (i = 0; i < NFLAGS; i++)
        {
            ours |= flags[i].native;
            if (bits & flags[i].bit)
            {
                native |= flags[i].native;
            }
        }
        /* What restate does not record -- a snapshot, compression -- stays. */
        native |= (unsigned long)st.st_flags & ~ours;
#if defined(__OpenBSD__) || defined(__APPLE__)
        return fchflags(fd, (uint32_t)native);
#else
        return fchflags(fd, native);
#endif
    }
#else
    (void)bits;
    errno = ENOTSUP;
    return -1;
#endif
}

bool rs_chflags_thaw(int fd)
{
    struct stat st;
    unsigned    now;

    /* Where there are none, of() says none. */
    if (fstat(fd, &st) != 0)
    {
        return false;
    }
    now = rs_chflags_of(&st);
    if ((now & RS_CHF_BLOCKING) == 0)
    {
        return false;
    }
    return rs_chflags_set(fd, now & ~(unsigned)RS_CHF_BLOCKING) == 0;
}
