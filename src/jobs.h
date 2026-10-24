/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Jobs: `restate run JOBFILE`.
 *
 * A job is a run of restate written down: which command, on what, with which
 * options. A program that schedules restate -- or a systemd timer, through
 * restate-job@.service -- then runs one fixed command, `restate run FILE`,
 * and what is run is decided by the file, which only its owner can change.
 * Nothing is ever built into a command line, and nothing in a job can name a
 * program to run: every key is one restate knows, of one type, and allowed
 * only for the commands it means something for.
 *
 *   # /etc/restate/jobs.d/nightly.conf
 *   command      = capture
 *   repository   = /mnt/nas/restate/web01
 *   quiesce      = true
 *   quiesce_with = unifi
 *   encrypt_to   = /etc/restate/keys/backup.asc
 *   result       = /var/lib/restate/nightly.json
 *   report_group = restate-report
 *
 * One `key = value` a line; blank lines and lines starting with '#' are
 * skipped. A value is the rest of the line, without the spaces around it.
 * Booleans are true or false (yes or no); counts are decimal; paths are
 * absolute, with no "." or ".." in them. A key marked repeatable may be given
 * more than once; any other only once. A key restate does not know, a key the
 * command has no use for, or a value of the wrong kind refuses the whole job.
 *
 * The file has to be a regular file, not a symlink, and it and the directory
 * it is in have to belong to root -- or to whoever runs it -- and be writable
 * by no one else: the rule hooks are held to. The command line can add -q,
 * -v, -P, --syslog and where the result and progress go, for what the job
 * does not say itself; nothing else.
 */
#ifndef RESTATE_JOBS_H
#define RESTATE_JOBS_H

#include <stdbool.h>
#include <stddef.h>

#include "opts.h"
#include "util.h"

#define RS_JOB_SCHEMA 1
/* A job is a few lines; anything larger is not one. */
#define RS_JOB_MAX    ((size_t)64 * 1024)

struct rs_job {
    struct rs_options opts;      /* what the job says, as a command line would */
    char            **strings;   /* what opts points into */
    size_t            nstrings;
    char             *ref;       /* restore, copy: REPO::NAME */
    char             *args[2];
};

void rs_job_init(struct rs_job *job);
void rs_job_free(struct rs_job *job);

/*
 * Parses the job `text` (`len` bytes), called `name` in messages, into
 * job->opts. False, with one line saying where and why in `err`, if it is not
 * a job.
 */
bool rs_job_parse(const char *text, size_t len, const char *name, struct rs_job *job,
                  struct rs_buf *err);

/*
 * The job given->args[0] names: checked to be a file only its owner can
 * change, read and parsed, with what the command line adds. An exit status:
 * RESTATE_EXIT_OK, or RESTATE_EXIT_TROUBLE having said why.
 */
int rs_job_load(const struct rs_options *given, struct rs_job *job);

/* The keys a job can have, in the order the manual lists them. */
const char *const *rs_job_keys(size_t *n);
/* The commands a job can be, by name, for restate features. */
const char *const *rs_job_commands(size_t *n);

#endif /* RESTATE_JOBS_H */
