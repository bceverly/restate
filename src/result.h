/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * How a run ended, for a program to read: --result FILE.
 *
 * restate's messages are written for people, and its exit status says only
 * which of six ways a run ended. A run given --result FILE also writes, when
 * it ends, one JSON object into FILE -- written beside it and renamed into
 * place, so whoever reads FILE reads the last run's whole result or the one
 * before -- with what the run did:
 *
 *   {"schema": 1, "command": "capture", "status": "incomplete", "exit": 3,
 *    "started_at": "2026-10-20T03:00:00Z", "seconds": 812,
 *    ... what the command did ...,
 *    "unreadable": {"count": 2, "first": [{"path": ..., "reason": ...}]},
 *    "quiesce": [{"kind": "postgresql", "name": "16-main", "paused_at": ...,
 *                 "resumed_at": ..., "status": "ok", "message": ""}],
 *    "warnings": ["..."], "warnings_count": 7}
 *
 * The status is the exit status as a word: ok (0), different (1), failed
 * (2), incomplete (3), untrusted (4) or busy (5). What each command adds is
 * in the manual, under RESULTS; a later restate adds members, and never
 * changes what one means without a new "schema".
 *
 * Every warning is collected, --quiet or not -- the first RS_RESULT_WARNINGS
 * of them in full -- as are the paths a walk could not read, the first
 * RS_RESULT_UNREADABLE with why.
 *
 * The file is its owner's alone, as everything restate writes is, unless a
 * group is given (--report-group): then it is that group's to read too.
 */
#ifndef RESTATE_RESULT_H
#define RESTATE_RESULT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "json.h"

#define RS_RESULT_SCHEMA     1
#define RS_RESULT_WARNINGS   50
#define RS_RESULT_UNREADABLE 100

/* Starts collecting for `command`; the clock starts now. */
void rs_result_begin(const char *command);
/* The object the command adds its own members to. */
struct rs_jval *rs_result(void);

/* A path a walk could not read, and why. */
void rs_result_unreadable(const char *path, const char *reason);
/* A hook that paused something, and how it went: the times are the
 * clock's, and `resumed` 0 if it never was. */
void rs_result_quiesce(const char *kind, const char *name, time_t paused, time_t resumed,
                       bool ok, const char *message);
/* How many unreadable paths, and how many hooks that failed, so far. */
uint64_t rs_result_unreadable_count(void);
uint64_t rs_result_quiesce_failed(void);

/*
 * Finishes the result with the exit status `status` and, if `path` is not
 * NULL, writes it there: 0640 and that group's if `group` names one, else
 * 0600. False, having said why, if it could not be written. The collection
 * is cleared either way.
 */
bool rs_result_write(int status, const char *path, const char *group);
/* Clears what was collected without writing it. */
void rs_result_end(void);

/* The exit status as the word the result and the system log use. */
const char *rs_result_status_word(int status);

/* "2026-10-20T03:00:00Z": `t` in UTC, to the second. */
void rs_result_time(time_t t, char out[32]);

/*
 * A file only its owner can write, readable by `group` too if it is not
 * NULL: opened for writing as the temporary that becomes `path`, its name
 * into *tmp. -1, having said why, on failure. For the progress file too.
 */
int rs_result_open(const char *path, const char *group, char **tmp);

#endif /* RESTATE_RESULT_H */
