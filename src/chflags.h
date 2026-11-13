/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The BSDs' and macOS's file flags, chflags(1)'s: schg and uchg (immutable),
 * sappnd and uappnd (append-only), sunlnk and uunlnk, nodump, hidden, arch
 * and the rest.
 *
 * FreeBSD marks its own base this way -- libc, the dynamic linker and
 * /var/empty are schg -- and a site marks what it protects, so a restore that
 * left them off would leave the system less protected than it was. They are
 * recorded by name, as chflags and `ls -lo` spell them, comma-separated --
 * "schg,nodump" -- so an index reads the same on every system, and are set
 * again last, after every file's content, owner, mode and times: an
 * immutable or append-only flag set any earlier refuses what follows.
 *
 * Only the flags someone sets on purpose are recorded. The ones a filesystem
 * keeps for itself -- a UFS snapshot, macOS's compression, dataless files
 * and SIP's restricted -- are not: set by hand they mean nothing, or worse.
 *
 * The bits below are restate's own, for every system alike; each is this
 * system's flag where it has it, and nothing where it does not. Linux has
 * none of them (its chattr flags are another thing, fsflags.h).
 */
#ifndef RESTATE_CHFLAGS_H
#define RESTATE_CHFLAGS_H

#include <stdbool.h>
#include <sys/stat.h>

#include "util.h"

enum {
    RS_CHF_ARCH = 1u << 0,      /* SF_ARCHIVED */
    RS_CHF_SCHG = 1u << 1,      /* SF_IMMUTABLE */
    RS_CHF_SAPPND = 1u << 2,    /* SF_APPEND */
    RS_CHF_SUNLNK = 1u << 3,    /* SF_NOUNLINK */
    RS_CHF_NODUMP = 1u << 4,    /* UF_NODUMP */
    RS_CHF_UCHG = 1u << 5,      /* UF_IMMUTABLE */
    RS_CHF_UAPPND = 1u << 6,    /* UF_APPEND */
    RS_CHF_UUNLNK = 1u << 7,    /* UF_NOUNLINK */
    RS_CHF_OPAQUE = 1u << 8,    /* UF_OPAQUE */
    RS_CHF_HIDDEN = 1u << 9,    /* UF_HIDDEN */
    RS_CHF_UARCH = 1u << 10,    /* UF_ARCHIVE */
    RS_CHF_SYSTEM = 1u << 11,   /* UF_SYSTEM */
    RS_CHF_SPARSE = 1u << 12,   /* UF_SPARSE */
    RS_CHF_OFFLINE = 1u << 13,  /* UF_OFFLINE */
    RS_CHF_REPARSE = 1u << 14,  /* UF_REPARSE */
    RS_CHF_RDONLY = 1u << 15    /* UF_READONLY */
};

/* The ones that stop a file being changed, renamed or removed. */
#define RS_CHF_BLOCKING                                                         \
    (RS_CHF_SCHG | RS_CHF_SAPPND | RS_CHF_SUNLNK | RS_CHF_UCHG | RS_CHF_UAPPND | \
     RS_CHF_UUNLNK)

/* Whether this system has file flags: a BSD or macOS, or the tests
 * pretending. */
bool rs_chflags_supported(void);

/* `flags` as their names, comma-separated, added to `out`; nothing for 0. */
void rs_chflags_text(unsigned flags, struct rs_buf *out);

/* The flags `text` names. A name no system has is added to `unknown`
 * (comma-separated, if given). */
unsigned rs_chflags_parse(const char *text, struct rs_buf *unknown);

/* The recorded flags of what `st` describes: 0 where there are none, or no
 * flags here. */
unsigned rs_chflags_of(const struct stat *st);

/* Which flags this system can set at all. */
unsigned rs_chflags_settable(void);

/* Gives what `fd` is open on exactly `flags`, of those this system has; its
 * others are left as they are. 0, or -1 with errno (ENOTSUP where there are
 * none; EPERM for a system flag, unless root at a low enough securelevel). */
int rs_chflags_set(int fd, unsigned flags);

/* Clears what of RS_CHF_BLOCKING `fd` has: true if there was any, and it
 * could be. */
bool rs_chflags_thaw(int fd);

/* For the tests: the flags kept in memory, by file, in place of the
 * filesystem's -- on Linux, which has none, and anywhere setting them needs
 * root. Off again with false. */
void rs_chflags_pretend(bool on);

#endif /* RESTATE_CHFLAGS_H */
