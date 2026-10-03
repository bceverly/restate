/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "gzip.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const default_paths[] = { "/usr/bin/gzip", "/bin/gzip" };

static const char *const *paths = default_paths;
static size_t              npaths = sizeof(default_paths) / sizeof(default_paths[0]);

void rs_gzip_set_paths(const char *const *list, size_t n)
{
    if (list)
    {
        paths = list;
        npaths = n;
    } else
    {
        paths = default_paths;
        npaths = sizeof(default_paths) / sizeof(default_paths[0]);
    }
}

/* A regular file someone may execute. */
static bool usable(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111);
}

const char *rs_gzip_path(void)
{
    size_t i;

    for (i = 0; i < npaths; i++)
    {
        if (usable(paths[i]))
        {
            return paths[i];
        }
    }
    return NULL;
}

static void cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags >= 0)
    {
        (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

/*
 * Starts gzip with `child_in` as its standard input and `child_out` as its
 * standard output. Both are ours to close afterwards.
 *
 * posix_spawn rather than fork and exec: there is no code at all running in
 * the child before the exec -- the descriptor plumbing and the signal reset
 * are declared up front and done by the C library.
 *
 * A path that is not an executable file is skipped before it is tried, rather
 * than tried and found wanting, because not every posix_spawn can say an exec
 * failed: OpenBSD's, and glibc's under valgrind, report success and leave the
 * child to exit 127. Between the check and the exec, the file could change --
 * but only in /usr/bin or /bin, which only root can write, so there is no one
 * for that race to help. An exec that fails anyway still shows: as exit 127,
 * which rs_gzip_finish reports.
 */
static bool spawn(char *const argv[], int child_in, int child_out, pid_t *pid,
                  struct rs_buf *err)
{
    /* posix_spawn takes char *const[] and string literals are const, so the
     * environment is writable copies and nothing is cast. */
    static char                env_path[] = "PATH=/usr/bin:/bin";
    static char                env_locale[] = "LC_ALL=C";
    char                      *envp[] = { env_path, env_locale, NULL };
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t          attr;
    sigset_t                   reset;
    size_t                     i;
    int                        rc = ENOENT;

    (void)posix_spawn_file_actions_init(&actions);
    (void)posix_spawnattr_init(&attr);
    (void)posix_spawn_file_actions_adddup2(&actions, child_in, STDIN_FILENO);
    (void)posix_spawn_file_actions_adddup2(&actions, child_out, STDOUT_FILENO);
    /* SIGPIPE may be ignored here while an image is written, and an ignored
     * signal survives exec; gzip should die of it like any other filter. */
    (void)sigemptyset(&reset);
    (void)sigaddset(&reset, SIGPIPE);
    (void)posix_spawnattr_setsigdefault(&attr, &reset);
    (void)posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);

    for (i = 0; i < npaths; i++)
    {
        if (!usable(paths[i]))
        {
            continue;
        }
        rc = posix_spawn(pid, paths[i], &actions, &attr, argv, envp);
        if (rc == 0)
        {
            break;
        }
    }
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)posix_spawnattr_destroy(&attr);
    if (rc != 0)
    {
        rs_buf_addf(err, "could not run gzip (looked for /usr/bin/gzip and /bin/gzip): %s",
                    strerror(rc));
        return false;
    }
    return true;
}

/* A pipe whose ends do not leak into gzip or anything else restate starts. */
static bool make_pipe(int p[2], struct rs_buf *err)
{
    if (pipe(p) < 0)
    {
        rs_buf_addf(err, "pipe: %s", strerror(errno));
        return false;
    }
    cloexec(p[0]);
    cloexec(p[1]);
    return true;
}

bool rs_gzip_compress(int out_fd, struct rs_gzip *gz, struct rs_buf *err)
{
    /* -n leaves out the name and timestamp gzip would otherwise record. */
    static char a0[] = "gzip";
    static char a1[] = "-c";
    static char a2[] = "-n";
    static char a3[] = "-6";
    char       *argv[] = { a0, a1, a2, a3, NULL };
    int         p[2];

    if (!make_pipe(p, err))
    {
        return false;
    }
    if (!spawn(argv, p[0], out_fd, &gz->pid, err))
    {
        (void)close(p[0]);
        (void)close(p[1]);
        return false;
    }
    (void)close(p[0]);
    gz->fd = p[1];
    return true;
}

bool rs_gzip_decompress(int in_fd, struct rs_gzip *gz, struct rs_buf *err)
{
    static char a0[] = "gzip";
    static char a1[] = "-d";
    static char a2[] = "-c";
    char       *argv[] = { a0, a1, a2, NULL };
    int         p[2];

    if (!make_pipe(p, err))
    {
        return false;
    }
    if (!spawn(argv, in_fd, p[1], &gz->pid, err))
    {
        (void)close(p[0]);
        (void)close(p[1]);
        return false;
    }
    (void)close(p[1]);
    gz->fd = p[0];
    return true;
}

bool rs_gzip_finish(struct rs_gzip *gz, bool abandon, struct rs_buf *err)
{
    int status = 0;

    if (gz->fd >= 0)
    {
        (void)close(gz->fd);
        gz->fd = -1;
    }
    if (abandon)
    {
        (void)kill(gz->pid, SIGTERM);
    }
    while (waitpid(gz->pid, &status, 0) < 0)
    {
        if (errno != EINTR)
        {
            rs_buf_addf(err, "waiting for gzip: %s", strerror(errno));
            return false;
        }
    }
    if (abandon)
    {
        return true;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    {
        return true;
    }
    if (WIFEXITED(status))
    {
        rs_buf_addf(err, "gzip failed (exit %d)", WEXITSTATUS(status));
    } else
    {
        rs_buf_addstr(err, "gzip was killed by a signal");
    }
    return false;
}
