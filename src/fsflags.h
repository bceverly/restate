/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Linux's immutable and append-only flags (chattr +i and +a), which protect
 * sets in place of a sticky bit there.
 *
 * A Linux NFS client refuses to open a file it has just made in a sticky
 * directory when that file is neither its caller's nor the directory owner's
 * (fs.protected_regular=2, the default on Ubuntu and in systemd): a share
 * that squashes every machine to one user makes exactly such files. So on
 * Linux, a repository's directory is 0770 and append-only -- the machines add
 * packs/ and snapshots/ to it, and remove and rename nothing -- packs/ and
 * snapshots/ are 0770 and nothing more, and each finished file and snapshot
 * is immutable: not removed, renamed, replaced or changed by anyone, root
 * included, until root clears the flag. Only root (CAP_LINUX_IMMUTABLE) sets
 * or clears either.
 *
 * So prune and repack, run as root on the storage, clear them where they
 * remove or replace what protect made immutable: rs_fsflags_unlink, _rmdir
 * and _rename do what unlink, rmdir and rename do, and where the answer is
 * EPERM, clear the flags of what they change and of the directories it is in,
 * try again, and put back the directories' flags (and the file's, unless it
 * is gone).
 */
#ifndef RESTATE_FSFLAGS_H
#define RESTATE_FSFLAGS_H

#include <stdbool.h>

#define RS_FSFLAGS_IMMUTABLE 1U
#define RS_FSFLAGS_APPEND    2U

/* Whether this system has them: Linux, or the tests pretending. */
bool rs_fsflags_supported(void);

/* `fd`'s, as the two bits above: 0, or -1 with errno. */
int rs_fsflags_get(int fd, unsigned *flags);

/* Makes `fd`'s two flags `flags`, leaving its others as they are: 0, or -1
 * with errno -- EPERM unless root. */
int rs_fsflags_set(int fd, unsigned flags);

/* Whether an error from either says the filesystem has no such flags (tmpfs
 * before Linux 6.0, NFS from its client), rather than that they failed. */
bool rs_fsflags_none(int err);

/* What rs_fsflags_thaw cleared, for rs_fsflags_refreeze to put back. */
struct rs_fsflags_thawed {
    int      fd;
    unsigned flags;
};

/* Clears the two flags of `path` -- a regular file or a directory, never
 * through a symlink -- where it has them and they could be cleared: true if
 * they were. */
bool rs_fsflags_thaw(const char *path, struct rs_fsflags_thawed *t);
void rs_fsflags_refreeze(struct rs_fsflags_thawed *t);

/* unlink, rmdir and rename, through protect's flags: 0, or -1 with errno. */
int rs_fsflags_unlink(const char *path);
int rs_fsflags_rmdir(const char *path);
int rs_fsflags_rename(const char *from, const char *to);

/* For the tests: the flags are kept in memory in place of the filesystem,
 * which only root may set them on, and what they forbid is refused by the
 * three above as the kernel would. */
enum rs_fsflags_mode {
    RS_FSFLAGS_REAL,
    RS_FSFLAGS_PRETEND,         /* every file has them, and setting them works */
    RS_FSFLAGS_PRETEND_REFUSED, /* setting them is refused, as for any but root */
    RS_FSFLAGS_PRETEND_NONE     /* no file has them, as on a filesystem without */
};
void rs_fsflags_pretend(enum rs_fsflags_mode mode);

#endif
