/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "gzip.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "run.h"

const char *rs_gzip_path(void)
{
    return rs_program_path(RS_PROG_GZIP);
}

void rs_gzip_set_paths(const char *const *list, size_t n)
{
    /* Both: whichever compresses, it is the one the tests mean. */
    rs_program_set_paths(RS_PROG_GZIP, list, n);
    rs_program_set_paths(RS_PROG_PIGZ, list, n);
}

static void cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags >= 0)
    {
        (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
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

bool rs_gzip_parallel(void)
{
    return rs_program_path(RS_PROG_PIGZ) != NULL;
}

bool rs_gzip_compress(int out_fd, struct rs_gzip *gz, struct rs_buf *err)
{
    /* -n leaves out the name and timestamp gzip would otherwise record; pigz
     * takes the same options and writes the same format. */
    static char     gzip_name[] = "gzip";
    static char     pigz_name[] = "pigz";
    static char     a1[] = "-c";
    static char     a2[] = "-n";
    static char     a3[] = "-6";
    bool            parallel = rs_gzip_parallel();
    char           *argv[] = { parallel ? pigz_name : gzip_name, a1, a2, a3, NULL };
    int             p[2];

    if (!make_pipe(p, err))
    {
        return false;
    }
    if (!rs_spawn(parallel ? RS_PROG_PIGZ : RS_PROG_GZIP, argv, p[0], out_fd, -1, &gz->pid, err))
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
    if (!rs_spawn(RS_PROG_GZIP, argv, in_fd, p[1], -1, &gz->pid, err))
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
