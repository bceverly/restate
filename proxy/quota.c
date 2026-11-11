/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "quota.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "json.h"
#include "run.h"
#include "util.h"

void rs_quota_init(struct rs_quota_run *r)
{
    memset(r, 0, sizeof(*r));
    r->fd = -1;
}

bool rs_quota_program_ok(const char *program, struct rs_buf *why)
{
    struct stat st;

    if (program[0] != '/')
    {
        rs_buf_addf(why, "--quota-hook %s: not an absolute path", program);
        return false;
    }
    if (stat(program, &st) != 0)
    {
        rs_buf_addf(why, "--quota-hook %s: %s", program, strerror(errno));
        return false;
    }
    /* The mode, not access(): that would be a check and then a use, and the
     * use, each run, is what says whether it can be run. */
    if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111))
    {
        rs_buf_addf(why, "--quota-hook %s: not an executable file", program);
        return false;
    }
    return true;
}

/* The hook's environment, every string allocated, NULL at its end. */
static char **environment(const struct rs_quota_ask *q)
{
    char **env = rs_xcalloc(8, sizeof(*env));
    size_t n = 0;

    env[n++] = rs_xstrdup("PATH=/usr/bin:/bin:/usr/sbin:/sbin");
    env[n++] = rs_xasprintf("RESTATE_PROXY_EVENT=%s", q->event);
    env[n++] = rs_xasprintf("RESTATE_PROXY_CLIENT=%s", q->client);
    env[n++] = rs_xasprintf("RESTATE_PROXY_REPOSITORY=%s", q->repository);
    env[n++] = rs_xasprintf("RESTATE_PROXY_BYTES=%" PRIu64, q->bytes);
    if (q->label)
    {
        env[n++] = rs_xasprintf("RESTATE_PROXY_LABEL=%s", q->label);
    }
    if (q->name)
    {
        env[n++] = rs_xasprintf("RESTATE_PROXY_NAME=%s", q->name);
    }
    return env;
}

static void free_environment(char **env)
{
    size_t i;

    for (i = 0; env[i]; i++)
    {
        free(env[i]);
    }
    free(env);
}

bool rs_quota_start(struct rs_quota_run *r, const char *program, const struct rs_quota_ask *q,
                    int64_t now, unsigned timeout, struct rs_buf *why)
{
    char **env = environment(q);
    char  *argv[2];
    int    p[2];
    pid_t  pid = 0;
    int    rc;

    rs_quota_init(r);
    if (pipe(p) != 0)
    {
        rs_buf_addf(why, "pipe: %s", strerror(errno));
        free_environment(env);
        return false;
    }
    /* Both ends close-on-exec: the hook's standard output is a copy of the
     * one, which is not. */
    (void)fcntl(p[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(p[1], F_SETFD, FD_CLOEXEC);
    /* Nothing else of the listener's goes with it: every descriptor it has
     * -- its sockets, the children's pairs, the repositories' locks -- is
     * close-on-exec. */
    argv[0] = rs_xstrdup(program);
    argv[1] = NULL;
    rc = rs_spawn_alone(program, argv, env, p[1], &pid);
    free(argv[0]);
    free_environment(env);
    (void)close(p[1]);
    if (rc != 0)
    {
        rs_buf_addf(why, "%s: %s", program, strerror(rc));
        (void)close(p[0]);
        return false;
    }
    (void)fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
    r->pid = pid;
    r->fd = p[0];
    r->deadline = now + (int64_t)timeout;
    r->timeout = timeout;
    return true;
}

void rs_quota_read(struct rs_quota_run *r)
{
    char buf[512];

    while (r->fd >= 0)
    {
        ssize_t n = read(r->fd, buf, sizeof(buf));
        ssize_t i;

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0)
        {
            /* EAGAIN: nothing more yet. */
            return;
        }
        if (n == 0)
        {
            (void)close(r->fd);
            r->fd = -1;
            return;
        }
        /* Its first line, as far as it is kept; the rest read and let go,
         * so that the hook never waits to write. */
        for (i = 0; i < n && !r->said_whole; i++)
        {
            if (buf[i] == '\n' || r->nsaid == RS_QUOTA_SAID_MAX)
            {
                r->said_whole = true;
            } else
            {
                r->said[r->nsaid++] = buf[i];
            }
        }
    }
}

bool rs_quota_reaped(struct rs_quota_run *r, pid_t pid, int status)
{
    if (r->pid == 0 || r->pid != pid || r->exited)
    {
        return false;
    }
    r->exited = true;
    r->status = status;
    return true;
}

void rs_quota_check_time(struct rs_quota_run *r, int64_t now)
{
    if (r->pid != 0 && !r->exited && !r->killed && now >= r->deadline)
    {
        (void)kill(-r->pid, SIGKILL);
        (void)kill(r->pid, SIGKILL);
        r->killed = true;
    }
}

bool rs_quota_running(const struct rs_quota_run *r)
{
    return r->pid != 0;
}

bool rs_quota_done(const struct rs_quota_run *r)
{
    return r->pid != 0 && r->exited;
}

/* What it said, as a person is to read it: its printable bytes, on one
 * line, or nothing if that is not text. */
static void keep_said(const struct rs_quota_run *r, struct rs_buf *message)
{
    size_t start = message->len;
    size_t i;

    for (i = 0; i < r->nsaid; i++)
    {
        unsigned char c = (unsigned char)r->said[i];
        char          ch = r->said[i];

        /* A double quote would end the log's message="..." early. */
        if (ch == '"')
        {
            ch = '\'';
        }
        if (c >= 0x20 && c != 0x7f)
        {
            rs_buf_addc(message, ch);
        }
    }
    while (message->len > start && message->data[message->len - 1] == ' ')
    {
        message->data[--message->len] = '\0';
    }
    if (message->len > start && !rs_utf8_valid(message->data + start, message->len - start))
    {
        message->len = start;
        message->data[start] = '\0';
    }
}

int rs_quota_answer(struct rs_quota_run *r, struct rs_buf *message, struct rs_buf *why)
{
    int answer = 500;

    /* What it wrote before it exited is in the pipe still. */
    rs_quota_read(r);
    if (r->fd >= 0)
    {
        (void)close(r->fd);
    }
    if (r->killed)
    {
        rs_buf_addf(why, "it ran for longer than %u seconds, and was killed", r->timeout);
    } else if (WIFEXITED(r->status) && WEXITSTATUS(r->status) == 0)
    {
        answer = 0;
    } else if (WIFEXITED(r->status) && WEXITSTATUS(r->status) == 1)
    {
        answer = 507;
        keep_said(r, message);
    } else if (WIFEXITED(r->status))
    {
        rs_buf_addf(why, "it exited %d, not 0 (yes) or 1 (no)", WEXITSTATUS(r->status));
    } else if (WIFSIGNALED(r->status))
    {
        rs_buf_addf(why, "it was killed by signal %d", WTERMSIG(r->status));
    } else
    {
        rs_buf_addstr(why, "it ended, and how is not known");
    }
    rs_quota_init(r);
    return answer;
}

void rs_quota_abandon(struct rs_quota_run *r)
{
    if (r->pid != 0 && !r->exited)
    {
        (void)kill(-r->pid, SIGKILL);
        (void)kill(r->pid, SIGKILL);
    }
    if (r->fd >= 0)
    {
        (void)close(r->fd);
    }
    rs_quota_init(r);
}
