/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "sessions.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "repo.h"
#include "store.h"
#include "util.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct session {
    char               id[RS_SESSION_LEN + 1];
    char              *client;
    char              *repository;
    enum rs_proxy_kind kind;
    struct rs_repo    *repo;        /* open, and so holding its locks */
    int64_t            opened;
    int64_t            idle_since;
    unsigned           busy;        /* requests in it, being answered */
    uint64_t           bytes_out;
};

struct rs_sessions {
    struct session *s;
    size_t          n;
    size_t          max;
    unsigned        lease;
    void            (*log)(void *ctx, const char *line);
    void           *log_ctx;
};

static const char *random_path;

void rs_sessions_set_random(const char *path)
{
    random_path = path;
}

struct rs_sessions *rs_sessions_new(unsigned max, unsigned lease,
                                    void (*log)(void *ctx, const char *line), void *log_ctx)
{
    struct rs_sessions *s = rs_xcalloc(1, sizeof(*s));

    s->max = max ? max : RS_PROXY_MAX_SESSIONS;
    s->lease = lease ? lease : RS_PROXY_LEASE;
    s->s = rs_xcalloc(s->max, sizeof(*s->s));
    s->log = log;
    s->log_ctx = log_ctx;
    return s;
}

unsigned rs_sessions_lease(const struct rs_sessions *s)
{
    return s->lease;
}

size_t rs_sessions_count(const struct rs_sessions *s)
{
    return s->n;
}

static struct session *by_id(struct rs_sessions *s, const char *id)
{
    size_t i;

    for (i = 0; i < s->n; i++)
    {
        if (strcmp(s->s[i].id, id) == 0)
        {
            return &s->s[i];
        }
    }
    return NULL;
}

/* A new session id: 16 bytes of the random source, in hex. */
static bool new_id(char id[RS_SESSION_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char     bytes[RS_SESSION_LEN / 2];
    size_t            got = 0;
    size_t            i;
    int               fd = open(random_path ? random_path : "/dev/urandom", O_RDONLY | O_CLOEXEC);

    while (fd >= 0 && got < sizeof(bytes))
    {
        ssize_t n = read(fd, bytes + got, sizeof(bytes) - got);

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            break;
        }
        got += (size_t)n;
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    if (got < sizeof(bytes))
    {
        return false;
    }
    for (i = 0; i < sizeof(bytes); i++)
    {
        id[2 * i] = hex[bytes[i] >> 4];
        id[2 * i + 1] = hex[bytes[i] & 15];
    }
    id[RS_SESSION_LEN] = '\0';
    return true;
}

/* Ends session `i`, as `result` says, and says so in the log. */
static void end_at(struct rs_sessions *s, size_t i, int64_t now, const char *result)
{
    struct session *e = &s->s[i];

    if (s->log)
    {
        char *line = rs_xasprintf("session-end client=%s kind=%s seconds=%" PRId64
                                  " bytes_in=0 bytes_out=%" PRIu64 " packs=0 result=%s",
                                  e->client, rs_proxy_kind_name(e->kind),
                                  now > e->opened ? now - e->opened : 0, e->bytes_out, result);

        s->log(s->log_ctx, line);
        free(line);
    }
    rs_repo_close(e->repo);
    free(e->client);
    free(e->repository);
    s->s[i] = s->s[--s->n];
    memset(&s->s[s->n], 0, sizeof(s->s[s->n]));
}

/* How a session of its kind ends, when its client ends it: an append
 * session that committed no snapshot -- and nothing commits one yet -- has
 * "ended", not finished. */
static const char *ended_as(const struct session *e)
{
    return e->kind == RS_PROXY_APPEND ? "ended" : "ok";
}

void rs_sessions_free(struct rs_sessions *s, int64_t now)
{
    if (!s)
    {
        return;
    }
    while (s->n > 0)
    {
        end_at(s, s->n - 1, now, "ended");
    }
    free(s->s);
    free(s);
}

void rs_sessions_forget(struct rs_sessions *s)
{
    size_t i;

    if (!s)
    {
        return;
    }
    for (i = 0; i < s->n; i++)
    {
        rs_repo_close(s->s[i].repo);
        free(s->s[i].client);
        free(s->s[i].repository);
    }
    free(s->s);
    free(s);
}

/* Whether grant `g` allows a session of `kind`: look with either
 * operation, read with read, append with append. */
static bool allowed(const struct rs_grant *g, enum rs_proxy_kind kind)
{
    switch (kind)
    {
    case RS_PROXY_READ:
        return (g->operations & RS_GRANT_READ) != 0;
    case RS_PROXY_APPEND:
        return (g->operations & RS_GRANT_APPEND) != 0;
    case RS_PROXY_LOOK:
    default:
        return (g->operations & (RS_GRANT_READ | RS_GRANT_APPEND)) != 0;
    }
}

int rs_sessions_open(struct rs_sessions *s, const struct rs_grant *g, enum rs_proxy_kind kind,
                     int64_t now, char id[RS_SESSION_LEN + 1], struct rs_buf *why)
{
    static const enum rs_repo_lock locks[] = { RS_REPO_LOOK, RS_REPO_READ, RS_REPO_APPEND };
    struct rs_store *st;
    struct rs_buf    marker;
    struct rs_buf    err;
    struct session  *e;
    struct rs_repo  *repo;
    bool             encrypted = false;
    bool             newer = false;
    bool             busy = false;
    int              version = 0;

    if (!allowed(g, kind))
    {
        return 403;
    }
    if (s->n >= s->max)
    {
        return 503;
    }
    /* The marker first, for what only it says: a version 1 repository is
     * one an append session would have to change, which nothing through the
     * proxy may. */
    st = rs_store_local(g->repository);
    rs_buf_init(&err);
    if (!rs_store_read(st, RS_REPO_MARKER, 4096, &marker, &err) ||
        !rs_repo_parse_marker(marker.data, &version, &encrypted, &newer))
    {
        rs_buf_addf(why, "%s: %s", g->repository,
                    err.len ? err.data : newer ? "made by a newer restate" : "not a repository");
        rs_buf_free(&marker);
        rs_buf_free(&err);
        rs_store_free(st);
        return 500;
    }
    rs_buf_free(&marker);
    rs_store_free(st);
    if (kind == RS_PROXY_APPEND && version == 1)
    {
        rs_buf_free(&err);
        return 409;
    }
    repo = rs_repo_open(g->repository, locks[kind], &busy, &err);
    if (!repo)
    {
        if (!busy)
        {
            rs_buf_addstr(why, err.data ? err.data : g->repository);
        }
        rs_buf_free(&err);
        return busy ? 423 : 500;
    }
    rs_buf_free(&err);
    e = &s->s[s->n];
    memset(e, 0, sizeof(*e));
    if (!new_id(e->id))
    {
        rs_buf_addstr(why, "the system's random source could not be read");
        rs_repo_close(repo);
        return 500;
    }
    /* Unique, as 128 random bits are; checked all the same. */
    if (by_id(s, e->id))
    {
        rs_buf_addstr(why, "a session id came out twice");
        rs_repo_close(repo);
        return 500;
    }
    e->client = rs_xstrdup(g->client);
    e->repository = rs_xstrdup(g->repository);
    e->kind = kind;
    e->repo = repo;
    e->opened = now;
    e->idle_since = now;
    s->n++;
    memcpy(id, e->id, sizeof(e->id));
    if (s->log)
    {
        char *line = rs_xasprintf("session-open client=%s kind=%s", e->client,
                                  rs_proxy_kind_name(kind));

        s->log(s->log_ctx, line);
        free(line);
    }
    return 201;
}

enum rs_proxy_found rs_sessions_find(struct rs_sessions *s, const char *client, const char *id,
                                     struct rs_proxy_session *out)
{
    struct session *e = by_id(s, id);

    if (!e)
    {
        return RS_PROXY_NO_SESSION;
    }
    if (strcmp(e->client, client) != 0)
    {
        return RS_PROXY_NOT_YOURS;
    }
    e->busy++;
    out->kind = e->kind;
    out->repository = e->repository;
    return RS_PROXY_FOUND;
}

void rs_sessions_release(struct rs_sessions *s, const char *id, uint64_t bytes_out, int64_t now)
{
    struct session *e = by_id(s, id);

    if (e && e->busy > 0)
    {
        e->busy--;
        e->bytes_out += bytes_out;
        e->idle_since = now;
    }
}

int rs_sessions_renew(struct rs_sessions *s, const char *client, const char *id, int64_t now)
{
    struct session *e = by_id(s, id);

    if (!e)
    {
        return 404;
    }
    if (strcmp(e->client, client) != 0)
    {
        return 401;
    }
    e->idle_since = now;
    return 204;
}

int rs_sessions_end(struct rs_sessions *s, const char *client, const char *id, int64_t now)
{
    const struct session *e = by_id(s, id);

    if (!e)
    {
        return 404;
    }
    if (strcmp(e->client, client) != 0)
    {
        return 401;
    }
    end_at(s, (size_t)(e - s->s), now, ended_as(e));
    return 204;
}

size_t rs_sessions_expire(struct rs_sessions *s, int64_t now)
{
    size_t ended = 0;
    size_t i = 0;

    while (i < s->n)
    {
        const struct session *e = &s->s[i];

        if (e->busy == 0 && now - e->idle_since >= (int64_t)s->lease)
        {
            end_at(s, i, now, "expired");
            ended++;
            continue;   /* the last one is in its place now */
        }
        i++;
    }
    return ended;
}
