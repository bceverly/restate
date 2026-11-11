/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate-proxy's quota hook (--quota-hook PROGRAM): a program of the
 * storage host's, asked before an append session opens and before each
 * upload whether the client may store more, so that a host serving many
 * clients holds each to what it pays for or was given, by whatever it keeps
 * that in -- a filesystem's quotas, a database, a billing system.
 *
 * It is run by the listening process, which is not confined, as the proxy's
 * user: no arguments, standard input /dev/null, standard error the proxy's
 * log, and an environment of its own and nothing of the proxy's --
 *
 *   PATH                        /usr/bin:/bin:/usr/sbin:/sbin
 *   RESTATE_PROXY_EVENT         open, or upload
 *   RESTATE_PROXY_CLIENT        the client's name, web01
 *   RESTATE_PROXY_REPOSITORY    its repository, as its grant names it
 *   RESTATE_PROXY_LABEL         its grant's label, where it has one
 *   RESTATE_PROXY_NAME          an upload's name, packs/NAME.tar.gz
 *   RESTATE_PROXY_BYTES         an upload's size; 0 for open
 *
 * -- and its answer is how it exits: 0, the client may; 1, it may not, which
 * the client is told as 507 quota-exceeded, with the first line the hook
 * wrote, if it wrote one; anything else, killed, or still running after
 * RS_QUOTA_TIMEOUT seconds, is the hook failing, and the request is 500.
 *
 * The listening process serves every connection's questions, so it never
 * waits for the hook: a run is started, its output read as it comes, its
 * exit seen as the process is reaped, and the question answered then. Only
 * the connection that asked waits for it.
 */
#ifndef RESTATE_QUOTA_H
#define RESTATE_QUOTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "util.h"

#define RS_QUOTA_TIMEOUT  30u    /* seconds */
#define RS_QUOTA_SAID_MAX 200    /* bytes of the line a refusal is told with */

/* What the hook is asked. */
struct rs_quota_ask {
    const char *event;          /* "open", "upload" */
    const char *client;
    const char *repository;
    const char *label;          /* NULL where the grant has none */
    const char *name;           /* NULL for open */
    uint64_t    bytes;
};

/* One run of the hook. Zeroed (rs_quota_init) is none. */
struct rs_quota_run {
    pid_t    pid;               /* 0: none */
    int      fd;                /* its standard output; -1 once closed */
    int64_t  deadline;
    unsigned timeout;
    bool     exited;
    int      status;            /* as waitpid gives it */
    bool     killed;            /* past its deadline */
    char     said[RS_QUOTA_SAID_MAX + 1];
    size_t   nsaid;
    bool     said_whole;        /* its first line has ended, or it is past the most kept */
};

void rs_quota_init(struct rs_quota_run *r);

/* Whether `program` is one to run: an absolute path to a regular file this
 * user may run. Why not into `why`. */
bool rs_quota_program_ok(const char *program, struct rs_buf *why);

/* `program` started for `q` at `now`, to be done by `now` + `timeout`
 * seconds: false, and why into `why`, if it could not be. */
bool rs_quota_start(struct rs_quota_run *r, const char *program, const struct rs_quota_ask *q,
                    int64_t now, unsigned timeout, struct rs_buf *why);

/* What it has written, read without waiting: when r->fd polls readable. */
void rs_quota_read(struct rs_quota_run *r);

/* Whether `pid`, reaped with `status`, was this run's process. */
bool rs_quota_reaped(struct rs_quota_run *r, pid_t pid, int status);

/* Killed, if it is past its deadline at `now`. */
void rs_quota_check_time(struct rs_quota_run *r, int64_t now);

bool rs_quota_running(const struct rs_quota_run *r);
/* Whether it has exited, and so has its answer. */
bool rs_quota_done(const struct rs_quota_run *r);

/*
 * The answer of a run that is done: 0 if the client may, 507 if not (and
 * what it said, if anything, into `message`), 500 if the hook failed (and
 * how, into `why`, for the log). The run is none again after.
 */
int rs_quota_answer(struct rs_quota_run *r, struct rs_buf *message, struct rs_buf *why);

/* A run no one waits for any more: killed, and forgotten. */
void rs_quota_abandon(struct rs_quota_run *r);

#endif /* RESTATE_QUOTA_H */
