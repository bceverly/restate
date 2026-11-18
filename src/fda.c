/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "fda.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

#ifdef __APPLE__
#define RS_FDA_MACOS true
#else
#define RS_FDA_MACOS false
#endif

static const char system_database[] = "/Library/Application Support/com.apple.TCC/TCC.db";

static char *pretended;

void rs_fda_pretend(const char *database)
{
    free(pretended);
    pretended = database ? rs_xstrdup(database) : NULL;
}

/* Whether `root` is this machine's own: what macOS protects is under it, and
 * not under a tree captured from elsewhere -- a disk mounted, a directory. */
static bool is_system_root(const char *root)
{
    struct stat a;
    struct stat b;

    return stat(root, &a) == 0 && stat("/", &b) == 0 && a.st_dev == b.st_dev &&
           a.st_ino == b.st_ino;
}

enum rs_fda rs_fda_state(const char *root)
{
    const char *database = pretended ? pretended : system_database;
    int         fd;
    int         err;

    if ((!RS_FDA_MACOS && !pretended) || !is_system_root(root))
    {
        return RS_FDA_NONE;
    }
    fd = open(database, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0)
    {
        (void)close(fd);
        return RS_FDA_GRANTED;
    }
    err = errno;
    return err == EPERM ? RS_FDA_DENIED : RS_FDA_UNKNOWN;
}

void rs_fda_warn(void)
{
    rs_warn("macOS has not given restate Full Disk Access, so what it keeps private -- "
            "Mail, Messages, Safari, Time Machine's settings, other apps' data -- cannot "
            "be read, and the capture will be incomplete. Grant it in System Settings, "
            "Privacy & Security, Full Disk Access, to the app restate is run from "
            "(Terminal, iTerm) or, where launchd runs it, to restate itself; then capture "
            "again");
}

void rs_fda_summary(uint64_t refused)
{
    if (refused == 0)
    {
        return;
    }
    rs_warn("%" PRIu64 " paths were refused by macOS, for want of Full Disk Access "
            "(above)", refused);
}
