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
/* /usr/local/bin too, for curl and the GnuPG tools: that is where the BSDs'
 * packages put them. A path is used only if it and its directory belong to
 * root and nobody else can write them -- see usable() -- which is what rules
 * out a Homebrew /usr/local/bin on macOS, owned by whoever installed it. */
static const char *const curl_paths[] = { "/usr/bin/curl", "/usr/local/bin/curl", "/bin/curl" };
static const char *const gpgv_paths[] = { "/usr/bin/gpgv", "/usr/local/bin/gpgv", "/bin/gpgv" };
static const char *const gpg_paths[] = { "/usr/bin/gpg", "/usr/local/bin/gpg", "/bin/gpg" };
static const char *const pigz_paths[] = { "/usr/bin/pigz", "/usr/local/bin/pigz", "/bin/pigz" };

/* The environment each program gets beyond PATH and LC_ALL: curl the proxy
 * settings, gpg what it needs to find the key that decrypts an image and to
 * ask for its passphrase. Nothing else is passed to anything. */
static const char *const no_env[] = { NULL };
static const char *const curl_env[] = {
    "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", NULL
};
static const char *const gpg_env[] = {
    "HOME", "GNUPGHOME", "GPG_TTY", "TERM", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS", NULL
};

#define ENV_MAX 8

struct program {
    const char        *name;
    const char *const *defaults;
    size_t             ndefaults;
    const char *const *paths;
    size_t             npaths;
    const char *const *env;
};

#define PROGRAM(n, list, env) \
    { n, list, sizeof(list) / sizeof((list)[0]), list, sizeof(list) / sizeof((list)[0]), env }

static struct program programs[RS_PROG_COUNT] = {
    PROGRAM("gzip", gzip_paths, no_env),
    PROGRAM("curl", curl_paths, curl_env),
    PROGRAM("gpgv", gpgv_paths, no_env),
    PROGRAM("gpg", gpg_paths, gpg_env),
    PROGRAM("pigz", pigz_paths, no_env),
};

#undef PROGRAM

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

/* Owned by root, and writable by nobody else. */
static bool root_only(const struct stat *st)
{
    return st->st_uid == 0 && (st->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/*
 * A regular file someone may execute, which only root could have put there:
 * the file and its directory both root's and writable by no one else. restate
 * runs as root, and a program anyone else could replace would run as root too.
 */
static bool usable(const char *path)
{
    struct stat st;
    struct stat dir;
    const char *slash = strrchr(path, '/');
    char       *parent;
    bool        ok;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111) || !root_only(&st) ||
        !slash)
    {
        return false;
    }
    parent = slash == path ? rs_xstrdup("/") : rs_xstrndup(path, (size_t)(slash - path));
    ok = stat(parent, &dir) == 0 && root_only(&dir);
    free(parent);
    return ok;
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
    const struct program      *prog;
    char                      *envp[2 + ENV_MAX + 1];
    size_t                     nenv = 0;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t          attr;
    sigset_t                   reset;
    size_t                     i;
    int                        rc = ENOENT;

    /* Every caller passes one of the enum's values; checked anyway, since
     * it indexes the table. */
    if ((size_t)p >= RS_PROG_COUNT)
    {
        rs_buf_addf(err, "no program numbered %d", (int)p);
        return false;
    }
    prog = &programs[(size_t)p];
    envp[nenv++] = rs_xstrdup("PATH=/usr/bin:/bin:/usr/local/bin");
    envp[nenv++] = rs_xstrdup("LC_ALL=C");
    for (i = 0; i < ENV_MAX && prog->env[i]; i++)
    {
        /* Untrusted, and not interpreted here: it goes to the program, which
         * reads these very variables itself, as the caller could have set them. */
        const char *v = getenv(prog->env[i]); /* Flawfinder: ignore */

        if (v && *v)
        {
            envp[nenv++] = rs_xasprintf("%s=%s", prog->env[i], v);
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

    for (i = 0; i < prog->npaths; i++)
    {
        if (!usable(prog->paths[i]))
        {
            continue;
        }
        rc = posix_spawn(pid, prog->paths[i], &actions, &attr, argv, envp);
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
        for (i = 0; i < prog->npaths; i++)
        {
            rs_buf_addf(&where, "%s%s", i ? ", " : "", prog->paths[i]);
        }
        rs_buf_addf(err, "could not run %s (looked for %s): %s", prog->name, where.data,
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
