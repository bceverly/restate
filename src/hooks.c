/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "run.h"

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

/* How long a hook may take, in seconds: a pause can be a large dump. */
#define PAUSE_TIMEOUT  (30u * 60u)
#define RESUME_TIMEOUT (10u * 60u)

static const char *const *test_dirs;
static size_t             ntest_dirs;

void rs_hooks_set_dirs(const char *const *dirs, size_t n)
{
    test_dirs = dirs;
    ntest_dirs = dirs ? n : 0;
}

/* The hooks restate ships: libexec/restate/hooks beside the sbin (or bin)
 * this program runs from, as `make install` lays them out. */
static char *shipped_dir(void)
{
    char    buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1); /* Flawfinder: ignore */
    int     up;

    if (n <= 0 || buf[0] != '/')
    {
        return rs_xstrdup("/usr/local/libexec/restate/hooks");
    }
    buf[n] = '\0';
    /* .../sbin/restate, up two: the program, then its directory. */
    for (up = 0; up < 2; up++)
    {
        char *slash = strrchr(buf, '/');

        if (!slash || slash == buf)
        {
            return rs_xstrdup("/usr/local/libexec/restate/hooks");
        }
        *slash = '\0';
    }
    return rs_xasprintf("%s/libexec/restate/hooks", buf);
}

/* A kind is a hook's file name: a plain word. */
static bool plain(const char *kind)
{
    return kind[0] != '\0' && kind[0] != '.' &&
           strspn(kind, "abcdefghijklmnopqrstuvwxyz0123456789-_") == strlen(kind);
}

char *rs_hook_find(const char *kind)
{
    char *shipped;
    char *path;

    if (!plain(kind))
    {
        return NULL;
    }
    if (test_dirs)
    {
        size_t i;

        for (i = 0; i < ntest_dirs; i++)
        {
            path = rs_xasprintf("%s/%s", test_dirs[i], kind);
            if (rs_hook_usable(path))
            {
                return path;
            }
            free(path);
        }
        return NULL;
    }
    path = rs_xasprintf("%s/%s", RS_HOOKS_SITE_DIR, kind);
    if (rs_hook_usable(path))
    {
        return path;
    }
    free(path);
    shipped = shipped_dir();
    path = rs_xasprintf("%s/%s", shipped, kind);
    free(shipped);
    if (rs_hook_usable(path))
    {
        return path;
    }
    free(path);
    return NULL;
}

/* "postgresql-18-main": the kind and name, as one file name. */
static char *dump_name(const struct rs_live *l)
{
    char  *s = rs_xasprintf("%s-%s", l->kind, l->name);
    size_t i;

    for (i = 0; s[i]; i++)
    {
        unsigned char c = (unsigned char)s[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_'))
        {
            s[i] = '_';
        }
    }
    return s;
}

/* Opens the directory `name` in `dirfd`, making it first if `make`; never
 * through a symlink. */
static int open_dir(int dirfd, const char *name, bool make)
{
    int fd;

    if (make && mkdirat(dirfd, name, 0700) != 0 && errno != EEXIST)
    {
        return -1;
    }
    fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return fd;
}

bool rs_hook_dump_dir(const char *root, const struct rs_live *l, char **tree_path,
                      struct rs_buf *err)
{
    /* var and lib are the system's; restate, dumps and the last are made. */
    static const char *const parts[] = { "var", "lib", "restate", "dumps" };
    char                    *name = dump_name(l);
    struct stat              st;
    size_t                   i;
    int                      fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    for (i = 0; fd >= 0 && i <= sizeof(parts) / sizeof(parts[0]); i++)
    {
        const char *part = i < sizeof(parts) / sizeof(parts[0]) ? parts[i] : name;
        int         next = open_dir(fd, part, i >= 2);

        (void)close(fd);
        fd = next;
    }
    /* Root's alone: a dump of every database is no one else's to read. */
    {
        const char *why = NULL;

        if (fd >= 0 && fstat(fd, &st) == 0 && st.st_uid != geteuid())
        {
            why = "not restate's own";
        } else if (fd < 0 || fstat(fd, &st) != 0 || fchmod(fd, 0700) != 0)
        {
            why = strerror(errno);
        }
        if (why)
        {
            rs_buf_addf(err, "%s%s/%s: %s", strcmp(root, "/") == 0 ? "" : root, RS_HOOKS_DUMPS,
                        name, why);
            if (fd >= 0)
            {
                (void)close(fd);
            }
            free(name);
            return false;
        }
    }
    (void)close(fd);
    *tree_path = rs_xasprintf("%s/%s", RS_HOOKS_DUMPS, name);
    free(name);
    return true;
}

bool rs_hook_run(const char *hook, const char *action, const struct rs_live *l,
                 const char *dump_dir, struct rs_buf *err)
{
    struct rs_buf  paths;
    struct passwd *pw = getpwuid((uid_t)l->uid);
    char          *env[9];
    char          *argv[4];
    size_t         i;
    int            code = -1;
    bool           ok;

    rs_buf_init(&paths);
    for (i = 0; i < l->npaths; i++)
    {
        rs_buf_addf(&paths, "%s%s", i ? "\n" : "", l->paths[i]);
    }
    env[0] = rs_xasprintf("RESTATE_ACTION=%s", action);
    env[1] = rs_xasprintf("RESTATE_KIND=%s", l->kind);
    env[2] = rs_xasprintf("RESTATE_NAME=%s", l->name);
    env[3] = rs_xasprintf("RESTATE_PID=%ld", l->pid);
    env[4] = rs_xasprintf("RESTATE_UID=%lu", l->uid);
    env[5] = rs_xasprintf("RESTATE_USER=%s", pw && pw->pw_name ? pw->pw_name : "");
    env[6] = rs_xasprintf("RESTATE_PATHS=%s", paths.data ? paths.data : "");
    env[7] = rs_xasprintf("RESTATE_DUMP_DIR=%s", dump_dir ? dump_dir : "");
    env[8] = NULL;
    argv[0] = rs_xstrdup(hook);
    argv[1] = rs_xstrdup(action);
    argv[2] = rs_xstrdup(l->name);
    argv[3] = NULL;
    ok = rs_run_hook(hook, argv, env, strcmp(action, "pause") == 0 ? PAUSE_TIMEOUT : RESUME_TIMEOUT,
                     &code, err);
    if (ok && code != 0)
    {
        rs_buf_addf(err, "%s %s %s exited %d", hook, action, l->name, code);
        ok = false;
    }
    for (i = 0; i < 3; i++)
    {
        free(argv[i]);
    }
    for (i = 0; i < 8; i++)
    {
        free(env[i]);
    }
    rs_buf_free(&paths);
    return ok;
}
