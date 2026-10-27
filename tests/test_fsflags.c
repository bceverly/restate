/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fsflags.h"
#include "test.h"
#include "util.h"

/* The flags of `path`, as RS_FSFLAGS_*; ~0U if they cannot be read. */
static unsigned flags_at(const char *path)
{
    int      fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    unsigned flags = ~0U;

    if (fd >= 0)
    {
        if (rs_fsflags_get(fd, &flags) != 0)
        {
            flags = ~0U;
        }
        (void)close(fd);
    }
    return flags;
}

/* Sets the flags of `path`. */
static bool flag(const char *path, unsigned flags)
{
    int  fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    bool ok = fd >= 0 && rs_fsflags_set(fd, flags) == 0;

    if (fd >= 0)
    {
        (void)close(fd);
    }
    return ok;
}

static bool there(const char *path)
{
    struct stat st;

    return lstat(path, &st) == 0;
}

/* As the filesystem has them: read by anyone, set by root alone. */
static void real_flags(const char *dir)
{
    char *file = rs_xasprintf("%s/real", dir);
    char *moved = rs_xasprintf("%s/real-moved", dir);
    char *sub = rs_xasprintf("%s/real-dir", dir);
    int   fd;

    TEST_CASE("fsflags: as the filesystem has them, root's alone to set");
    rs_fsflags_pretend(RS_FSFLAGS_REAL);
    rs_test_write(dir, "real", "x\n", 0600);
    fd = open(file, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        unsigned flags = 0;
        int      got = rs_fsflags_get(fd, &flags);

        if (got == 0)
        {
            CHECK_INT(flags, 0);
            CHECK_INT(rs_fsflags_set(fd, 0), 0);
            if (rs_fsflags_set(fd, RS_FSFLAGS_IMMUTABLE) == 0)
            {
                CHECK_INT(flags_at(file), RS_FSFLAGS_IMMUTABLE);
                CHECK_INT(unlink(file), -1);
                CHECK_INT(rs_fsflags_set(fd, 0), 0);
            } else
            {
                CHECK(errno == EPERM || rs_fsflags_none(errno));
            }
        } else
        {
            CHECK(rs_fsflags_none(errno));
            CHECK(!rs_fsflags_supported() || rs_fsflags_set(fd, RS_FSFLAGS_APPEND) != 0);
        }
        (void)close(fd);
    }
    /* With no flags to clear, each is what it stands for. */
    CHECK_INT(rs_fsflags_rename(file, moved), 0);
    CHECK(there(moved) && !there(file));
    CHECK_INT(rs_fsflags_unlink(moved), 0);
    CHECK(!there(moved));
    CHECK_INT(rs_fsflags_unlink(moved), -1);
    CHECK_INT(errno, ENOENT);
    CHECK(mkdir(sub, 0700) == 0);
    CHECK_INT(rs_fsflags_rmdir(sub), 0);
    CHECK(!there(sub));
    free(file);
    free(moved);
    free(sub);
}

/* With the tests' flags, which refuse what the kernel's would. */
static void pretended_flags(const char *dir)
{
    char                    *frozen = rs_xasprintf("%s/frozen", dir);
    char                    *in = rs_xasprintf("%s/frozen/in", dir);
    char                    *to = rs_xasprintf("%s/frozen/to", dir);
    char                    *file = rs_xasprintf("%s/file", dir);
    char                    *sym = rs_xasprintf("%s/sym", dir);
    char                    *nowhere = rs_xasprintf("%s/no-such-dir/file", dir);
    char                    *fifo = rs_xasprintf("%s/fifo", dir);
    struct rs_fsflags_thawed t;

    TEST_CASE("fsflags: removing and renaming what is immutable, and in an append-only directory");
    rs_fsflags_pretend(RS_FSFLAGS_PRETEND);
    CHECK(rs_fsflags_supported());
    CHECK(mkdir(frozen, 0700) == 0);
    rs_test_write(frozen, "in", "x\n", 0600);
    rs_test_write(dir, "file", "x\n", 0600);
    CHECK(flag(in, RS_FSFLAGS_IMMUTABLE));
    CHECK(flag(frozen, RS_FSFLAGS_APPEND));
    CHECK_INT(flags_at(in), RS_FSFLAGS_IMMUTABLE);
    /* Renamed, it keeps its flag; its directory keeps its own. */
    CHECK_INT(rs_fsflags_rename(in, to), 0);
    CHECK(there(to) && !there(in));
    CHECK_INT(flags_at(to), RS_FSFLAGS_IMMUTABLE);
    CHECK_INT(flags_at(frozen), RS_FSFLAGS_APPEND);
    /* Over what is immutable, from where nothing is. */
    CHECK(flag(file, RS_FSFLAGS_IMMUTABLE));
    CHECK_INT(rs_fsflags_rename(to, file), 0);
    CHECK(!there(to));
    CHECK_INT(flags_at(file), RS_FSFLAGS_IMMUTABLE);
    CHECK_INT(flags_at(frozen), RS_FSFLAGS_APPEND);
    /* A rename that fails all the same puts back what it cleared. */
    CHECK_INT(rs_fsflags_rename(file, nowhere), -1);
    CHECK_INT(errno, ENOENT);
    CHECK_INT(flags_at(file), RS_FSFLAGS_IMMUTABLE);
    CHECK_INT(rs_fsflags_unlink(file), 0);
    CHECK(!there(file));
    CHECK(flag(frozen, RS_FSFLAGS_IMMUTABLE));
    CHECK_INT(rs_fsflags_rmdir(frozen), 0);
    CHECK(!there(frozen));

    TEST_CASE("fsflags: thawed and frozen again, never through a symlink");
    rs_test_write(dir, "file", "x\n", 0600);
    CHECK(!rs_fsflags_thaw(file, &t));
    CHECK(flag(file, RS_FSFLAGS_APPEND | RS_FSFLAGS_IMMUTABLE));
    CHECK(rs_fsflags_thaw(file, &t));
    CHECK_INT(flags_at(file), 0);
    rs_fsflags_refreeze(&t);
    CHECK_INT(flags_at(file), RS_FSFLAGS_APPEND | RS_FSFLAGS_IMMUTABLE);
    rs_fsflags_refreeze(&t);
    CHECK(symlink(file, sym) == 0);
    CHECK(!rs_fsflags_thaw(sym, &t));
    CHECK_INT(flags_at(file), RS_FSFLAGS_APPEND | RS_FSFLAGS_IMMUTABLE);
    CHECK(!rs_fsflags_thaw(nowhere, &t));
    /* Nor anything but a file or a directory, which an open could act on. */
    CHECK(mkfifo(fifo, 0600) == 0);
    CHECK(!rs_fsflags_thaw(fifo, &t));
    CHECK(flag(file, 0));
    CHECK(unlink(sym) == 0 && unlink(file) == 0 && unlink(fifo) == 0);

    TEST_CASE("fsflags: where setting them is refused, and where there are none");
    rs_test_write(dir, "file", "x\n", 0600);
    rs_fsflags_pretend(RS_FSFLAGS_PRETEND_REFUSED);
    CHECK_INT(flags_at(file), 0);
    CHECK(flag(file, 0));
    CHECK(!flag(file, RS_FSFLAGS_IMMUTABLE));
    CHECK_INT(errno, EPERM);
    rs_fsflags_pretend(RS_FSFLAGS_PRETEND_NONE);
    CHECK_INT(flags_at(file), ~0U);
    CHECK(!flag(file, 0));
    CHECK(rs_fsflags_none(errno));
    CHECK(!rs_fsflags_none(EPERM));
    CHECK(!rs_fsflags_thaw(file, &t));
    CHECK_INT(rs_fsflags_unlink(file), 0);
    rs_fsflags_pretend(RS_FSFLAGS_REAL);
    free(frozen);
    free(in);
    free(to);
    free(file);
    free(sym);
    free(nowhere);
    free(fifo);
}

void test_fsflags(void)
{
    char *dir = rs_test_tmpdir();

    real_flags(dir);
    pretended_flags(dir);
    rs_test_rmtree(dir);
    free(dir);
}
