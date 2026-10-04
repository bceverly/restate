/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "run.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *const gzip_paths[] = { "/usr/bin/gzip", "/bin/gzip" };
/* /usr/local/bin too, for curl and gpgv: that is where the BSDs' packages put
 * them. Like /usr/bin it is writable only by root. */
static const char *const curl_paths[] = { "/usr/bin/curl", "/usr/local/bin/curl", "/bin/curl" };
static const char *const gpgv_paths[] = { "/usr/bin/gpgv", "/usr/local/bin/gpgv", "/bin/gpgv" };

struct program {
    const char        *name;
    const char *const *defaults;
    size_t             ndefaults;
    const char *const *paths;
    size_t             npaths;
};

#define PROGRAM(n, list) { n, list, sizeof(list) / sizeof((list)[0]), list, sizeof(list) / sizeof((list)[0]) }

static struct program programs[RS_PROG_COUNT] = {
    PROGRAM("gzip", gzip_paths),
    PROGRAM("curl", curl_paths),
    PROGRAM("gpgv", gpgv_paths),
};

#undef PROGRAM

/* The proxy settings curl reads, passed through; nothing else is. */
static const char *const passthrough[] = {
    "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"
};

const char *rs_program_name(enum rs_program p)
{
    return programs[p].name;
}

void rs_program_set_paths(enum rs_program p, const char *const *list, size_t n)
{
    if (list)
    {
        programs[p].paths = list;
        programs[p].npaths = n;
    } else
    {
        programs[p].paths = programs[p].defaults;
        programs[p].npaths = programs[p].ndefaults;
    }
}

/* A regular file someone may execute. */
static bool usable(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111);
}

const char *rs_program_path(enum rs_program p)
{
    size_t i;

    for (i = 0; i < programs[p].npaths; i++)
    {
        if (usable(programs[p].paths[i]))
        {
            return programs[p].paths[i];
        }
    }
    return NULL;
}

bool rs_spawn(enum rs_program p, char *const argv[], int in_fd, int out_fd, int err_fd,
              pid_t *pid, struct rs_buf *err)
{
    /* posix_spawn takes char *const[] and string literals are const, so the
     * environment is built from writable copies and nothing is cast. */
    char                      *envp[2 + sizeof(passthrough) / sizeof(passthrough[0]) + 1];
    size_t                     nenv = 0;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t          attr;
    sigset_t                   reset;
    size_t                     i;
    int                        rc = ENOENT;

    envp[nenv++] = rs_xstrdup("PATH=/usr/bin:/bin:/usr/local/bin");
    envp[nenv++] = rs_xstrdup("LC_ALL=C");
    for (i = 0; i < sizeof(passthrough) / sizeof(passthrough[0]); i++)
    {
        /* Untrusted, and not interpreted here: it goes to curl, which reads
         * these very variables itself, as the caller could have set them. */
        const char *v = getenv(passthrough[i]); /* Flawfinder: ignore */

        if (v && *v)
        {
            envp[nenv++] = rs_xasprintf("%s=%s", passthrough[i], v);
        }
    }
    envp[nenv] = NULL;

    (void)posix_spawn_file_actions_init(&actions);
    (void)posix_spawnattr_init(&attr);
    if (in_fd >= 0)
    {
        (void)posix_spawn_file_actions_adddup2(&actions, in_fd, STDIN_FILENO);
    }
    if (out_fd >= 0)
    {
        (void)posix_spawn_file_actions_adddup2(&actions, out_fd, STDOUT_FILENO);
    }
    if (err_fd >= 0)
    {
        (void)posix_spawn_file_actions_adddup2(&actions, err_fd, STDERR_FILENO);
    }
    /* SIGPIPE may be ignored here while an image is written, and an ignored
     * signal survives exec; the child should die of it like any filter. */
    (void)sigemptyset(&reset);
    (void)sigaddset(&reset, SIGPIPE);
    (void)posix_spawnattr_setsigdefault(&attr, &reset);
    (void)posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);

    for (i = 0; i < programs[p].npaths; i++)
    {
        if (!usable(programs[p].paths[i]))
        {
            continue;
        }
        rc = posix_spawn(pid, programs[p].paths[i], &actions, &attr, argv, envp);
        if (rc == 0)
        {
            break;
        }
    }
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)posix_spawnattr_destroy(&attr);
    for (i = 0; i < nenv; i++)
    {
        free(envp[i]);
    }
    if (rc != 0)
    {
        struct rs_buf where;

        rs_buf_init(&where);
        for (i = 0; i < programs[p].npaths; i++)
        {
            rs_buf_addf(&where, "%s%s", i ? ", " : "", programs[p].paths[i]);
        }
        rs_buf_addf(err, "could not run %s (looked for %s): %s", programs[p].name, where.data,
                    strerror(rc));
        rs_buf_free(&where);
        return false;
    }
    return true;
}

bool rs_wait(pid_t pid, int *code, struct rs_buf *err)
{
    int status = 0;

    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno != EINTR)
        {
            rs_buf_addf(err, "waiting for a child process: %s", strerror(errno));
            return false;
        }
    }
    if (WIFEXITED(status))
    {
        *code = WEXITSTATUS(status);
    } else
    {
        *code = WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255;
    }
    return true;
}

static void cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags >= 0)
    {
        (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

static bool open_pipe(int p[2], struct rs_buf *err)
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

bool rs_run(enum rs_program p, char *const argv[], struct rs_buf *out, struct rs_buf *errtext,
            int *code, struct rs_buf *err)
{
    int           op[2] = { -1, -1 };
    int           ep[2] = { -1, -1 };
    struct pollfd fds[2];
    pid_t         pid;
    bool          ok;

    if ((out && !open_pipe(op, err)) || (errtext && !open_pipe(ep, err)))
    {
        if (op[0] >= 0)
        {
            (void)close(op[0]);
            (void)close(op[1]);
        }
        return false;
    }
    ok = rs_spawn(p, argv, -1, op[1], ep[1], &pid, err);
    if (op[1] >= 0)
    {
        (void)close(op[1]);
    }
    if (ep[1] >= 0)
    {
        (void)close(ep[1]);
    }
    if (!ok)
    {
        if (op[0] >= 0)
        {
            (void)close(op[0]);
        }
        if (ep[0] >= 0)
        {
            (void)close(ep[0]);
        }
        return false;
    }
    /* Both streams at once: reading one to the end first could leave the
     * child blocked writing the other into a full pipe. */
    fds[0].fd = op[0];
    fds[0].events = POLLIN;
    fds[1].fd = ep[0];
    fds[1].events = POLLIN;
    while (fds[0].fd >= 0 || fds[1].fd >= 0)
    {
        int k;

        if (poll(fds, 2, -1) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        for (k = 0; k < 2; k++)
        {
            char    chunk[4096];
            ssize_t n;

            if (fds[k].fd < 0 || !(fds[k].revents & (POLLIN | POLLHUP | POLLERR)))
            {
                continue;
            }
            n = read(fds[k].fd, chunk, sizeof(chunk));
            if (n > 0)
            {
                rs_buf_add(k == 0 ? out : errtext, chunk, (size_t)n);
            } else if (n == 0 || errno != EINTR)
            {
                (void)close(fds[k].fd);
                fds[k].fd = -1;
            }
        }
    }
    if (out && !out->data)
    {
        rs_buf_add(out, "", 0);
    }
    if (errtext && !errtext->data)
    {
        rs_buf_add(errtext, "", 0);
    }
    return rs_wait(pid, code, err);
}
