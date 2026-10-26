/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "fsflags.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#include "util.h"

/* The tests' flags, by file, while they pretend. */
struct pretended {
    dev_t    dev;
    ino_t    ino;
    unsigned flags;
};

static enum rs_fsflags_mode     pretending = RS_FSFLAGS_REAL;
static struct pretended        *pretended;
static size_t                   npretended;

void rs_fsflags_pretend(enum rs_fsflags_mode m)
{
    free(pretended);
    pretended = NULL;
    npretended = 0;
    pretending = m;
}

bool rs_fsflags_supported(void)
{
#if defined(__linux__)
    return true;
#else
    return pretending != RS_FSFLAGS_REAL;
#endif
}

bool rs_fsflags_none(int err)
{
    return err == ENOTTY || err == EOPNOTSUPP || err == EINVAL || err == ENOSYS;
}

/* The tests' entry for the file `fd`, made if `make`. */
static struct pretended *pretended_of(int fd, bool make)
{
    struct stat st;
    size_t      i;

    if (fstat(fd, &st) != 0)
    {
        return NULL;
    }
    for (i = 0; i < npretended; i++)
    {
        if (pretended[i].dev == st.st_dev && pretended[i].ino == st.st_ino)
        {
            return &pretended[i];
        }
    }
    if (!make)
    {
        return NULL;
    }
    pretended = rs_xreallocarray(pretended, npretended + 1, sizeof(*pretended));
    pretended[npretended].dev = st.st_dev;
    pretended[npretended].ino = st.st_ino;
    pretended[npretended].flags = 0;
    return &pretended[npretended++];
}

int rs_fsflags_get(int fd, unsigned *flags)
{
    *flags = 0;
    if (pretending != RS_FSFLAGS_REAL)
    {
        const struct pretended *p = pretended_of(fd, false);

        if (pretending == RS_FSFLAGS_PRETEND_NONE)
        {
            errno = ENOTTY;
            return -1;
        }
        *flags = p ? p->flags : 0;
        return 0;
    }
#if defined(__linux__)
    {
        int attr = 0;

        if (ioctl(fd, FS_IOC_GETFLAGS, &attr) != 0)
        {
            return -1;
        }
        *flags = ((attr & FS_IMMUTABLE_FL) ? RS_FSFLAGS_IMMUTABLE : 0) |
                 ((attr & FS_APPEND_FL) ? RS_FSFLAGS_APPEND : 0);
        return 0;
    }
#else
    (void)fd;
    errno = EOPNOTSUPP;
    return -1;
#endif
}

int rs_fsflags_set(int fd, unsigned flags)
{
    unsigned now;

    if (rs_fsflags_get(fd, &now) != 0)
    {
        return -1;
    }
    if (now == flags)
    {
        return 0;
    }
    if (pretending != RS_FSFLAGS_REAL)
    {
        struct pretended *p = pretending == RS_FSFLAGS_PRETEND ? pretended_of(fd, true) : NULL;

        if (!p)
        {
            errno = EPERM;
            return -1;
        }
        p->flags = flags;
        return 0;
    }
#if defined(__linux__)
    {
        int attr = 0;

        if (ioctl(fd, FS_IOC_GETFLAGS, &attr) != 0)
        {
            return -1;
        }
        attr &= ~(FS_IMMUTABLE_FL | FS_APPEND_FL);
        attr |= ((flags & RS_FSFLAGS_IMMUTABLE) ? FS_IMMUTABLE_FL : 0) |
                ((flags & RS_FSFLAGS_APPEND) ? FS_APPEND_FL : 0);
        return ioctl(fd, FS_IOC_SETFLAGS, &attr);
    }
#else
    errno = EOPNOTSUPP;
    return -1;
#endif
}

/* `path`, a regular file or a directory, opened never through a symlink and
 * never as anything else -- not a device, which an open alone can act on: -1
 * if it is not one of those. */
static int open_plain(const char *path)
{
    struct stat before;
    struct stat st;
    int         fd;

    if (lstat(path, &before) != 0 || !(S_ISREG(before.st_mode) || S_ISDIR(before.st_mode)))
    {
        return -1;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0 && (fstat(fd, &st) != 0 || st.st_dev != before.st_dev ||
                    st.st_ino != before.st_ino))
    {
        (void)close(fd);
        fd = -1;
    }
    return fd;
}

bool rs_fsflags_thaw(const char *path, struct rs_fsflags_thawed *t)
{
    int      fd;
    unsigned flags;

    t->fd = -1;
    t->flags = 0;
    fd = open_plain(path);
    if (fd < 0)
    {
        return false;
    }
    if (rs_fsflags_get(fd, &flags) != 0 || flags == 0 || rs_fsflags_set(fd, 0) != 0)
    {
        (void)close(fd);
        return false;
    }
    t->fd = fd;
    t->flags = flags;
    return true;
}

void rs_fsflags_refreeze(struct rs_fsflags_thawed *t)
{
    if (t->fd >= 0)
    {
        (void)rs_fsflags_set(t->fd, t->flags);
        (void)close(t->fd);
    }
    t->fd = -1;
    t->flags = 0;
}

/* The directory `path` is in. */
static char *dir_of(const char *path)
{
    const char *slash = strrchr(path, '/');

    if (!slash)
    {
        return rs_xstrdup(".");
    }
    return slash == path ? rs_xstrdup("/") : rs_xstrndup(path, (size_t)(slash - path));
}

/* Whether the tests' flags forbid changing the name `path`: its own, or its
 * directory's. */
static bool pretend_forbids(const char *path)
{
    char *dir;
    bool  no = false;
    int   i;

    if (pretending != RS_FSFLAGS_PRETEND || !path)
    {
        return false;
    }
    dir = dir_of(path);
    for (i = 0; i < 2 && !no; i++)
    {
        int                     fd = open_plain(i == 0 ? path : dir);
        const struct pretended *p;

        p = fd >= 0 ? pretended_of(fd, false) : NULL;
        no = p && p->flags != 0;
        if (fd >= 0)
        {
            (void)close(fd);
        }
    }
    free(dir);
    return no;
}

enum change {
    UNLINK,
    RMDIR,
    RENAME
};

static int change_once(enum change how, const char *from, const char *to)
{
    if (pretend_forbids(from) || pretend_forbids(to))
    {
        errno = EPERM;
        return -1;
    }
    switch (how)
    {
    case UNLINK:
        return unlink(from);
    case RMDIR:
        return rmdir(from);
    default:
        return rename(from, to);
    }
}

/* `how`, and where protect's flags refuse it, again with them cleared from
 * what it changes -- `from`, `to` and the directories they are in -- and put
 * back after. */
static int change(enum change how, const char *from, const char *to)
{
    struct rs_fsflags_thawed t[4];
    const char              *paths[4];
    char                    *dirs[2];
    bool                     any = false;
    int                      ret;
    int                      saved;
    size_t                   i;

    if (change_once(how, from, to) == 0)
    {
        return 0;
    }
    if (errno != EPERM)
    {
        return -1;
    }
    dirs[0] = dir_of(from);
    dirs[1] = to ? dir_of(to) : NULL;
    paths[0] = from;
    paths[1] = dirs[0];
    paths[2] = to;
    paths[3] = dirs[1];
    for (i = 0; i < 4; i++)
    {
        t[i].fd = -1;
        any = (paths[i] && rs_fsflags_thaw(paths[i], &t[i])) || any;
    }
    ret = any ? change_once(how, from, to) : -1;
    saved = any ? errno : EPERM;
    /* Each put back as it was, but for what is gone: what was removed, or
     * replaced by the rename. */
    for (i = 0; i < 4; i++)
    {
        if (ret == 0 && t[i].fd >= 0 && (i == 2 || (i == 0 && how != RENAME)))
        {
            (void)close(t[i].fd);
            t[i].fd = -1;
        }
        rs_fsflags_refreeze(&t[i]);
    }
    free(dirs[0]);
    free(dirs[1]);
    errno = saved;
    return ret;
}

int rs_fsflags_unlink(const char *path)
{
    return change(UNLINK, path, NULL);
}

int rs_fsflags_rmdir(const char *path)
{
    return change(RMDIR, path, NULL);
}

int rs_fsflags_rename(const char *from, const char *to)
{
    return change(RENAME, from, to);
}
