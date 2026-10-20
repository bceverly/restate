/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "result.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "restate.h"
#include "util.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static bool           collecting;
static char          *command;
static time_t         started;
static struct rs_jval root;          /* the command's own members */
static struct rs_jval warnings;      /* the first RS_RESULT_WARNINGS */
static uint64_t       nwarnings;
static struct rs_jval errors;        /* the first RS_RESULT_ERRORS */
static uint64_t       nerrors;
static struct rs_jval unreadable;    /* the first RS_RESULT_UNREADABLE */
static uint64_t       nunreadable;
static struct rs_jval quiesce;
static uint64_t       quiesce_failed;

static void collect_warning(const char *msg)
{
    if (!collecting)
    {
        return;
    }
    if (nwarnings < RS_RESULT_WARNINGS)
    {
        rs_jval_set_string(rs_jarr_add(&warnings), msg);
    }
    nwarnings++;
}

static void collect_error(const char *msg)
{
    if (!collecting)
    {
        return;
    }
    if (nerrors < RS_RESULT_ERRORS)
    {
        rs_jval_set_string(rs_jarr_add(&errors), msg);
    }
    nerrors++;
}

void rs_result_end(void)
{
    rs_jval_free(&root);
    rs_jval_free(&warnings);
    rs_jval_free(&errors);
    rs_jval_free(&unreadable);
    rs_jval_free(&quiesce);
    memset(&root, 0, sizeof(root));
    memset(&warnings, 0, sizeof(warnings));
    memset(&errors, 0, sizeof(errors));
    memset(&unreadable, 0, sizeof(unreadable));
    memset(&quiesce, 0, sizeof(quiesce));
    free(command);
    command = NULL;
    nwarnings = 0;
    nerrors = 0;
    nunreadable = 0;
    quiesce_failed = 0;
    collecting = false;
    if (rs_warn_hook == collect_warning)
    {
        rs_warn_hook = NULL;
    }
    if (rs_error_hook == collect_error)
    {
        rs_error_hook = NULL;
    }
}

void rs_result_begin(const char *cmd)
{
    rs_result_end();
    collecting = true;
    command = rs_xstrdup(cmd);
    started = time(NULL);
    rs_jval_set_object(&root);
    rs_jval_set_array(&warnings);
    rs_jval_set_array(&errors);
    rs_jval_set_array(&unreadable);
    rs_jval_set_array(&quiesce);
    rs_warn_hook = collect_warning;
    rs_error_hook = collect_error;
}

struct rs_jval *rs_result(void)
{
    if (!collecting)
    {
        rs_result_begin("unknown");
    }
    return &root;
}

void rs_result_unreadable(const char *path, const char *reason)
{
    if (!collecting)
    {
        return;
    }
    if (nunreadable < RS_RESULT_UNREADABLE)
    {
        struct rs_jval *e = rs_jarr_add(&unreadable);
        char           *p = rs_utf8_lossy(path, strlen(path));

        rs_jval_set_object(e);
        rs_jobj_str(e, "path", p);
        rs_jobj_str(e, "reason", reason);
        free(p);
    }
    nunreadable++;
}

uint64_t rs_result_unreadable_count(void)
{
    return nunreadable;
}

void rs_result_time(time_t t, char out[32])
{
    struct tm tm;

    if (!gmtime_r(&t, &tm) || strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
    {
        (void)snprintf(out, 32, "%lld", (long long)t);
    }
}

void rs_result_quiesce(const char *kind, const char *name, time_t paused, time_t resumed,
                       bool ok, const char *message)
{
    struct rs_jval *e;
    char            when[32];

    if (!ok)
    {
        quiesce_failed++;
    }
    if (!collecting)
    {
        return;
    }
    e = rs_jarr_add(&quiesce);
    rs_jval_set_object(e);
    rs_jobj_str(e, "kind", kind);
    rs_jobj_str(e, "name", name);
    rs_result_time(paused, when);
    rs_jobj_str(e, "paused_at", when);
    if (resumed != 0)
    {
        rs_result_time(resumed, when);
        rs_jobj_str(e, "resumed_at", when);
    } else
    {
        (void)rs_jobj_add(e, "resumed_at");   /* null: it was not */
    }
    rs_jobj_str(e, "status", ok ? "ok" : "failed");
    rs_jobj_str(e, "message", message ? message : "");
}

uint64_t rs_result_quiesce_failed(void)
{
    return quiesce_failed;
}

const char *rs_result_status_word(int status)
{
    switch (status)
    {
    case RESTATE_EXIT_OK:
        return "ok";
    case RESTATE_EXIT_DIFFERENT:
        return "different";
    case RESTATE_EXIT_INCOMPLETE:
        return "incomplete";
    case RESTATE_EXIT_UNVERIFIED:
        return "untrusted";
    case RESTATE_EXIT_BUSY:
        return "busy";
    default:
        return "failed";
    }
}

int rs_result_open(const char *path, const char *group, char **tmp)
{
    int fd;

    *tmp = rs_xasprintf("%s.XXXXXX", path);
    fd = mkstemp(*tmp);
    if (fd < 0)
    {
        rs_error("%s: %s", path, strerror(errno));
        free(*tmp);
        *tmp = NULL;
        return -1;
    }
    if (group)
    {
        const struct group *g = getgrnam(group);

        if (!g || fchown(fd, (uid_t)-1, g->gr_gid) != 0 || fchmod(fd, 0640) != 0)
        {
            rs_error("%s: it could not be made readable by the group %s: %s", path, group,
                     g ? strerror(errno) : "there is no such group");
            (void)close(fd);
            (void)unlink(*tmp);
            free(*tmp);
            *tmp = NULL;
            return -1;
        }
    }
    return fd;
}

/* Every member of `from`, moved onto the end of `to`. */
static void take_members(struct rs_jval *to, struct rs_jval *from)
{
    size_t i;

    for (i = 0; i < from->n; i++)
    {
        struct rs_jval *v = rs_jobj_add(to, from->keys[i]);

        *v = from->items[i];
        memset(&from->items[i], 0, sizeof(from->items[i]));
    }
}

bool rs_result_write(int status, const char *path, const char *group)
{
    struct rs_jval  out;
    struct rs_jval *v;
    struct rs_buf   text;
    char            when[32];
    char           *tmp = NULL;
    int             fd;
    bool            ok = true;

    if (!collecting)
    {
        rs_result_begin("unknown");
    }
    if (!path)
    {
        rs_result_end();
        return true;
    }
    memset(&out, 0, sizeof(out));
    rs_jval_set_object(&out);
    rs_jobj_u64(&out, "schema", RS_RESULT_SCHEMA);
    rs_jobj_str(&out, "command", command);
    rs_jobj_str(&out, "status", rs_result_status_word(status));
    rs_jobj_u64(&out, "exit", (uint64_t)status);
    rs_result_time(started, when);
    rs_jobj_str(&out, "started_at", when);
    rs_jobj_u64(&out, "seconds", (uint64_t)(time(NULL) > started ? time(NULL) - started : 0));
    take_members(&out, &root);
    v = rs_jobj_add(&out, "unreadable");
    rs_jval_set_object(v);
    rs_jobj_u64(v, "count", nunreadable);
    v = rs_jobj_add(v, "first");
    *v = unreadable;
    memset(&unreadable, 0, sizeof(unreadable));
    v = rs_jobj_add(&out, "quiesce");
    *v = quiesce;
    memset(&quiesce, 0, sizeof(quiesce));
    v = rs_jobj_add(&out, "warnings");
    *v = warnings;
    memset(&warnings, 0, sizeof(warnings));
    rs_jobj_u64(&out, "warnings_count", nwarnings);
    v = rs_jobj_add(&out, "errors");
    *v = errors;
    memset(&errors, 0, sizeof(errors));
    rs_jobj_u64(&out, "errors_count", nerrors);
    rs_buf_init(&text);
    rs_json_write(&text, &out, 2, 0);
    rs_buf_addc(&text, '\n');
    rs_jval_free(&out);
    rs_result_end();

    fd = rs_result_open(path, group, &tmp);
    if (fd < 0)
    {
        rs_buf_free(&text);
        return false;
    }
    {
        const char *p = text.data;
        size_t      left = text.len;

        while (ok && left > 0)
        {
            ssize_t w = write(fd, p, left);

            if (w < 0 && errno == EINTR)
            {
                continue;
            }
            ok = w > 0;
            if (ok)
            {
                p += w;
                left -= (size_t)w;
            }
        }
    }
    ok = ok && fsync(fd) == 0;
    if (close(fd) != 0)
    {
        ok = false;
    }
    if (ok && rename(tmp, path) != 0)
    {
        ok = false;
    }
    if (!ok)
    {
        rs_error("%s: %s", path, strerror(errno));
        (void)unlink(tmp);
    }
    free(tmp);
    rs_buf_free(&text);
    return ok;
}
