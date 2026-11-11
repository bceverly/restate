/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * proxy/serve.c: a connection served from memory, its requests given in
 * pieces as a network gives them.
 */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "grant.h"
#include "serve.h"
#include "sha256.h"
#include "util.h"

/* A token that is one: the prefix, and 43 characters of which the last has
 * its two low bits clear. */
#define TOKEN "rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define OTHER "rsp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"

struct mem {
    const char   *in;
    size_t        len;
    size_t        at;
    size_t        piece;    /* the most one read gives */
    struct rs_buf out;
    bool          fail_writes;
    struct rs_buf log;
};

static long mem_read(void *ctx, void *buf, size_t len)
{
    struct mem *m = ctx;
    size_t      n = m->len - m->at;

    if (n > len)
    {
        n = len;
    }
    if (n > m->piece)
    {
        n = m->piece;
    }
    memcpy(buf, m->in + m->at, n);
    m->at += n;
    return (long)n;
}

static bool mem_write(void *ctx, const void *buf, size_t len)
{
    struct mem *m = ctx;

    if (m->fail_writes)
    {
        return false;
    }
    rs_buf_add(&m->out, buf, len);
    return true;
}

static void mem_log(void *ctx, const char *line)
{
    struct mem *m = ctx;

    rs_buf_addf(&m->log, "%s\n", line);
}

/* The sessions there are, for the tests that use them: SID_READ and
 * SID_LOOK are web01's, SID_OTHER another client's, in `fake_repo`. */
#define SID_READ   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SID_LOOK   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SID_OTHER  "cccccccccccccccccccccccccccccccc"
#define SID_APPEND "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#define SID_GONE   "ffffffffffffffffffffffffffffffff"   /* an append session with no staging */

static const char *fake_repo;
static bool        with_sessions;
static uint64_t    fake_rate;      /* what a session found is paced at */

static enum rs_proxy_found fake_session(void *ctx, const char *client, const char *id,
                                        struct rs_proxy_session *s)
{
    (void)ctx;
    s->repository = fake_repo;
    s->rate = fake_rate;
    if (strcmp(id, SID_OTHER) == 0)
    {
        return RS_PROXY_NOT_YOURS;
    }
    if (strcmp(client, "web01") != 0 ||
        (strcmp(id, SID_READ) != 0 && strcmp(id, SID_LOOK) != 0 &&
         strcmp(id, SID_APPEND) != 0 && strcmp(id, SID_GONE) != 0))
    {
        return RS_PROXY_NO_SESSION;
    }
    s->kind = strcmp(id, SID_READ) == 0   ? RS_PROXY_READ
              : strcmp(id, SID_LOOK) == 0 ? RS_PROXY_LOOK
                                          : RS_PROXY_APPEND;
    return RS_PROXY_FOUND;
}

/* What the fake was last asked, and what it answers open with. */
static int         open_answer = 201;
static const char *open_message;
static char        last_kind[16];
static uint64_t    released;

static int fake_open(void *ctx, const char *client, enum rs_proxy_kind kind, char id[33],
                     unsigned *lease, struct rs_buf *message)
{
    (void)ctx;
    (void)client;
    if (open_message)
    {
        rs_buf_addstr(message, open_message);
    }
    (void)snprintf(last_kind, sizeof(last_kind), "%s", rs_proxy_kind_name(kind));
    memcpy(id, SID_READ, sizeof(SID_READ));
    *lease = 300;
    return open_answer;
}

static uint64_t released_in;
static char     last_committed[64];

static void fake_release(void *ctx, const char *id, uint64_t bytes_out, uint64_t bytes_in)
{
    (void)ctx;
    (void)id;
    released += bytes_out;
    released_in += bytes_in;
}

static void fake_committed(void *ctx, const char *id, const char *name)
{
    (void)ctx;
    (void)snprintf(last_committed, sizeof(last_committed), "%s %s", id, name);
}

static int fake_renew(void *ctx, const char *client, const char *id, unsigned *lease)
{
    (void)ctx;
    (void)client;
    *lease = 300;
    return strcmp(id, SID_READ) == 0 ? 204 : strcmp(id, SID_OTHER) == 0 ? 401 : 404;
}

static int fake_end(void *ctx, const char *client, const char *id)
{
    unsigned lease;

    return fake_renew(ctx, client, id, &lease);
}

/* The quota hook, as the fake answers it, and what it was last asked. */
static int         quota_answer;
static const char *quota_message;
static char        quota_asked[128];

static int fake_quota(void *ctx, const char *client, const char *id, const char *name,
                      uint64_t bytes, struct rs_buf *message)
{
    (void)ctx;
    (void)snprintf(quota_asked, sizeof(quota_asked), "%s %s %s %llu", client, id, name,
                   (unsigned long long)bytes);
    if (quota_message)
    {
        rs_buf_addstr(message, quota_message);
    }
    return quota_answer;
}

static const struct rs_proxy_sessions fake_sessions = {
    NULL, fake_open, fake_session, fake_release, fake_committed, fake_renew, fake_end, NULL,
};
static const struct rs_proxy_sessions fake_sessions_quota = {
    NULL, fake_open, fake_session, fake_release, fake_committed, fake_renew, fake_end, fake_quota,
};
static bool with_quota;

/* Where uploads go, and how a commit and a binding are answered, for the
 * tests that set them. */
static const char *fake_staging;
static uint64_t    fake_max_staging;
static bool        fake_commits;
static int         commit_answer = 201;
static bool        bind_answer = true;
static unsigned    binds;

static void fake_commit(void *ctx, const char *repository, const char *staging, const char *name,
                        struct rs_proxy_committed *out)
{
    (void)ctx;
    (void)repository;
    (void)staging;
    out->status = commit_answer;
    out->pack_added = commit_answer == 201 && strncmp(name, "packs/", 6) == 0;
    out->snapshot_added = commit_answer == 201 && strncmp(name, "snapshots/", 10) == 0;
    out->reason = commit_answer == 422 ? "invalid" : commit_answer >= 400 ? "proxy-failed" : NULL;
    rs_buf_addstr(&out->message, commit_answer == 422 ? "packs/P-0.tar.gz: it is not what its .sum "
                                                        "says"
                                                      : "the disk went away");
}

static bool fake_bind(void *ctx, const struct rs_grant *g)
{
    (void)ctx;
    (void)g;
    binds++;
    return bind_answer;
}

/* Serves `in` with `grants`, at `now`: what was answered, and the log, in
 * *log (both the caller's to free). */
static char *serve(const char *in, const struct rs_grant *grants, size_t ngrants, int64_t now,
                   unsigned *served, char **log)
{
    struct mem           m;
    struct rs_proxy_io   io;
    struct rs_proxy_conn c;

    memset(&m, 0, sizeof(m));
    m.in = in;
    m.len = strlen(in);
    m.piece = 7;
    rs_buf_init(&m.out);
    rs_buf_init(&m.log);
    rs_buf_add(&m.out, "", 0);
    rs_buf_add(&m.log, "", 0);
    io.ctx = &m;
    io.read = mem_read;
    io.write = mem_write;
    memset(&c, 0, sizeof(c));
    c.grants = grants;
    c.ngrants = ngrants;
    c.peer = "192.0.2.1:4000";
    c.now = now;
    c.log = mem_log;
    c.log_ctx = &m;
    if (with_sessions)
    {
        c.sessions = with_quota ? &fake_sessions_quota : &fake_sessions;
    }
    c.staging = fake_staging;
    c.max_staging = fake_max_staging;
    c.bind = fake_bind;
    if (fake_commits)
    {
        c.commit = fake_commit;
    }
    *served = rs_proxy_serve(&io, &c);
    *log = rs_buf_detach(&m.log);
    return rs_buf_detach(&m.out);
}

/* How many times `needle` is in `hay`. */
static int count(const char *hay, const char *needle)
{
    int n = 0;

    while ((hay = strstr(hay, needle)) != NULL)
    {
        n++;
        hay += strlen(needle);
    }
    return n;
}

#define GET(target, extra) "GET " target " HTTP/1.1\r\nHost: p\r\n" extra "\r\n"
#define AUTH "Authorization: Bearer " TOKEN "\r\n"
#define IN(sid) AUTH "Restate-Session: " sid "\r\n"

/* `what`, asked in session `sid`, of the fake repository: the answer. */
static size_t ngrants_asked = 1;

static char *ask(const struct rs_grant *grant, const char *what, char **log)
{
    unsigned served;

    return serve(what, grant, ngrants_asked, 0, &served, log);
}

/* The listing in `out`, past its head: "" if it has none. */
static const char *body_of(const char *out)
{
    const char *b = strstr(out, "\r\n\r\n");

    return b ? b + 4 : "";
}

static void test_reading(const struct rs_grant *grant)
{
    char *dir = rs_test_tmpdir();
    char *out;
    char *log;
    char *path;

    /* A repository, with what a listing names and what it does not. */
    rs_test_write(dir, "restate-repository", "restate-repository 2\n", 0644);
    rs_test_write(dir, "chunk-key", "k\n", 0644);
    rs_test_write(dir, "lock", "", 0644);
    rs_test_write(dir, "readers", "", 0644);
    rs_test_write(dir, ".hidden", "", 0644);
    path = rs_xasprintf("%s/packs", dir);
    CHECK(mkdir(path, 0755) == 0);
    free(path);
    path = rs_xasprintf("%s/snapshots", dir);
    CHECK(mkdir(path, 0755) == 0);
    free(path);
    path = rs_xasprintf("%s/snapshots/20261020T030000Z", dir);
    CHECK(mkdir(path, 0755) == 0);
    free(path);
    path = rs_xasprintf("%s/snapshots/.20261020T040000Z.tmp", dir);
    CHECK(mkdir(path, 0755) == 0);
    free(path);
    path = rs_xasprintf("%s/packs/P-1.idx", dir);
    CHECK(mkdir(path, 0755) == 0);   /* a directory where a file is named */
    free(path);
    rs_test_write(dir, "packs/P-0.tar.gz", "0123456789", 0644);
    rs_test_write(dir, "packs/P-0.idx", "index", 0644);
    rs_test_write(dir, "packs/P-0.sum", "sum", 0644);
    rs_test_write(dir, "packs/junk", "", 0644);
    rs_test_write(dir, "snapshots/20261020T030000Z/info", "info", 0644);
    rs_test_write(dir, "snapshots/20261020T030000Z/index.json.gz", "ix", 0644);
    rs_test_write(dir, "snapshots/20261020T030000Z/other", "", 0644);
    fake_repo = dir;
    with_sessions = true;

    TEST_CASE("serve: a listing names what the protocol knows, and nothing else");
    out = ask(grant, GET("/v1/web01/list/", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 200 OK\r\n");
    CHECK(rs_starts_with(body_of(out), "restate-list 1\nf 2 "));
    CHECK_CONTAINS(body_of(out), " chunk-key\nf 21 ");
    CHECK_CONTAINS(body_of(out), " restate-repository\n");
    CHECK(strstr(body_of(out), "lock") == NULL && strstr(body_of(out), "readers") == NULL);
    CHECK(strstr(body_of(out), "hidden") == NULL && strstr(body_of(out), "packs") == NULL);
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/list/packs/", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(body_of(out), " P-0.idx\n");
    CHECK_CONTAINS(body_of(out), "f 3 ");
    CHECK_CONTAINS(body_of(out), "f 10 ");
    CHECK_CONTAINS(body_of(out), "d 0 ");      /* P-1.idx, a directory where a file is named */
    CHECK(strstr(body_of(out), "junk") == NULL);
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/list/snapshots/", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(body_of(out), "d 0 ");
    CHECK_CONTAINS(body_of(out), " 20261020T030000Z\n");
    CHECK(strstr(body_of(out), "tmp") == NULL);
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/list/snapshots/20261020T030000Z/", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(body_of(out), " info\n");
    CHECK_CONTAINS(body_of(out), " index.json.gz\n");
    CHECK(strstr(body_of(out), "other") == NULL);
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/list/snapshots/20261020T050000Z/", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 404 Not Found\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: a file, whole, by HEAD, and a pack's content only to a restore");
    out = ask(grant, GET("/v1/web01/f/packs/P-0.idx", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 200 OK\r\n");
    CHECK_CONTAINS(out, "Content-Type: application/octet-stream\r\n");
    CHECK_CONTAINS(out, "Content-Length: 5\r\n");
    CHECK_CONTAINS(out, "Accept-Ranges: bytes\r\n");
    CHECK_CONTAINS(out, "Last-Modified: ");
    CHECK_CONTAINS(out, " GMT\r\n");
    CHECK_STR(body_of(out), "index");
    CHECK_CONTAINS(log, "status=200 bytes=5");
    free(out);
    free(log);
    out = ask(grant, "HEAD /v1/web01/f/restate-repository HTTP/1.1\r\nHost: p\r\n" IN(SID_LOOK)
                     "\r\n", &log);
    CHECK_CONTAINS(out, "Content-Length: 21\r\n");
    CHECK_STR(body_of(out), "");
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 403 Forbidden\r\n");
    CHECK_CONTAINS(out, "Restate-Reason: forbidden\r\n");
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ)), &log);
    CHECK_STR(body_of(out), "0123456789");
    free(out);
    free(log);
    {
        const char *two = GET("/v1/web01/f/packs/P-9.idx", IN(SID_READ))
            GET("/v1/web01/f/packs/P-1.idx", IN(SID_READ));

        out = ask(grant, two, &log);
    }
    CHECK_INT(count(out, "HTTP/1.1 404 Not Found\r\n"), 2);
    free(out);
    free(log);

    TEST_CASE("serve: a request in a session whose grant has a bandwidth is paced by it");
    {
        char           *big = rs_xmalloc(100 * 1024 + 1);
        struct timespec t0;
        struct timespec t1;
        double          took;

        memset(big, 'k', 100 * 1024);
        big[100 * 1024] = '\0';
        rs_test_write(dir, "snapshots/20261020T030000Z/kit", big, 0644);
        free(big);
        fake_rate = 64 * 1024;
        (void)clock_gettime(CLOCK_MONOTONIC, &t0);
        out = ask(grant, GET("/v1/web01/f/snapshots/20261020T030000Z/kit", IN(SID_LOOK)), &log);
        (void)clock_gettime(CLOCK_MONOTONIC, &t1);
        fake_rate = 0;
        took = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        CHECK_CONTAINS(out, "Content-Length: 102400\r\n");
        CHECK_INT((long long)strlen(body_of(out)), 102400);
        /* 100 KiB at 64 KiB a second: a second and a half, and some. */
        CHECK(took > 1.4 && took < 30);
        free(out);
        free(log);
        /* And one not in a session is not paced, whatever was before it. */
        (void)clock_gettime(CLOCK_MONOTONIC, &t0);
        out = ask(grant, GET("/v1/web01/f/snapshots/20261020T030000Z/kit", IN(SID_LOOK)), &log);
        (void)clock_gettime(CLOCK_MONOTONIC, &t1);
        took = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        CHECK(took < 1.0);
        free(out);
        free(log);
    }

    TEST_CASE("serve: one range of a file, and none that is not one within it");
    {
        const char *three =
            GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ) "Range: bytes=4-\r\n")
            GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ) "Range: bytes=1-3\r\n")
            GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ) "Range: bytes=8-100\r\n");

        out = ask(grant, three, &log);
    }
    CHECK_INT(count(out, "HTTP/1.1 206 Partial Content\r\n"), 3);
    CHECK_CONTAINS(out, "Content-Range: bytes 4-9/10\r\n\r\n456789");
    CHECK_CONTAINS(out, "Content-Range: bytes 1-3/10\r\n\r\n123");
    CHECK_CONTAINS(out, "Content-Range: bytes 8-9/10\r\n\r\n89");
    free(out);
    free(log);
    {
        const char *two =
            GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ) "Range: bytes=10-\r\n")
            GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ) "Range: bytes=-3\r\n");

        out = ask(grant, two, &log);
    }
    CHECK_INT(count(out, "HTTP/1.1 416 Range Not Satisfiable\r\n"), 2);
    CHECK_CONTAINS(out, "Content-Range: bytes */10\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: reading needs the client's own session, not ended");
    out = ask(grant, GET("/v1/web01/list/", AUTH), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/list/", IN(SID_OTHER)), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
    free(out);
    free(log);
    out = ask(grant, GET("/v1/web01/list/", IN("dddddddddddddddddddddddddddddddd")), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 404 Not Found\r\n");
    free(out);
    free(log);
    /* An upload is still to come. */
    out = ask(grant, "PUT /v1/web01/sessions/" SID_READ "/files/packs/P-0.idx HTTP/1.1\r\n"
                     "Host: p\r\n" AUTH "Content-Length: 0\r\n\r\n", &log);
    CHECK_CONTAINS(out, "HTTP/1.1 501 Not Implemented\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: a session opened, its kind read from the body once all else is checked");
    {
        const char *opened = "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH
                             "Expect: 100-continue\r\nContent-Length: 7\r\n\r\nappend\n"
                             GET("/v1/", "");

        out = ask(grant, opened, &log);
    }
    CHECK_STR(last_kind, "append");
    CHECK_CONTAINS(out, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n");
    CHECK_CONTAINS(out, "Restate-Session: " SID_READ "\r\nRestate-Lease: 300\r\n");
    CHECK_CONTAINS(out, "\r\n\r\n" SID_READ "\n");
    /* The body read, the connection goes on to the next request. */
    CHECK_CONTAINS(out, "restate-proxy 1\n");
    free(out);
    free(log);
    {
        static const struct {
            int         answer;
            const char *says;
        } refused[] = {
            { 403, "Restate-Reason: forbidden" },  { 409, "Restate-Reason: repository-version-1" },
            { 423, "Restate-Reason: busy" },       { 503, "Restate-Reason: sessions-full" },
            { 500, "Restate-Reason: proxy-failed" },
            /* A client's own limit is a 503 too, with a reason of its own. */
            { RS_PROXY_CLIENT_FULL, "503 Service Unavailable\r\n" },
            { RS_PROXY_CLIENT_FULL, "Restate-Reason: client-sessions-full" },
            { RS_PROXY_CLIENT_FULL, "as many sessions open as its grant allows" },
            { 507, "Restate-Reason: quota-exceeded" },
            { 507, "over its quota on the storage host" },
        };
        size_t i;

        for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        {
            open_answer = refused[i].answer;
            out = ask(grant, "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH
                             "Content-Length: 4\r\n\r\nread", &log);
            CHECK_CONTAINS(out, refused[i].says);
            free(out);
            free(log);
        }
        /* What the quota hook said is the body, where it said something. */
        open_answer = 507;
        open_message = "web01 is over its 10 GiB";
        out = ask(grant, "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH
                         "Content-Length: 6\r\n\r\nappend", &log);
        CHECK_STR(body_of(out), "web01 is over its 10 GiB\n");
        free(out);
        free(log);
        open_message = NULL;
        open_answer = 201;
    }
    /* A refusal before the body is read sends no 100, and ends the
     * connection rather than read what it would not have asked for. */
    out = ask(grant, "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n"
                     "Expect: 100-continue\r\nContent-Length: 4\r\n\r\nread", &log);
    CHECK(strstr(out, "100 Continue") == NULL);
    CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
    CHECK_CONTAINS(out, "Connection: close\r\n");
    free(out);
    free(log);
    {
        static const char *const bad[] = {
            "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH "\r\n",
            "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH "Content-Length: 0\r\n\r\n",
            "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH
            "Content-Length: 40\r\n\r\nappendappendappendappendappendappendappen",
            "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH
            "Content-Length: 5\r\n\r\nwrite",
            "POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\n" AUTH
            "Content-Length: 6\r\n\r\nap",
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            out = ask(grant, bad[i], &log);
            CHECK(strstr(out, "HTTP/1.1 4") != NULL);
            CHECK_CONTAINS(out, "Restate-Reason: bad-request");
            free(out);
            free(log);
        }
    }

    TEST_CASE("serve: renewed and ended, with no body, and the lease said");
    out = ask(grant, "POST /v1/web01/sessions/" SID_READ "/renew HTTP/1.1\r\nHost: p\r\n" AUTH
                     "Content-Length: 0\r\n\r\n"
                     "POST /v1/web01/sessions/" SID_READ "/end HTTP/1.1\r\nHost: p\r\n" AUTH
                     "\r\n"
                     "POST /v1/web01/sessions/" SID_OTHER "/end HTTP/1.1\r\nHost: p\r\n" AUTH
                     "\r\n"
                     "POST /v1/web01/sessions/dddddddddddddddddddddddddddddddd/renew HTTP/1.1\r\n"
                     "Host: p\r\n" AUTH "\r\n", &log);
    CHECK_INT(count(out, "HTTP/1.1 204 No Content\r\n"), 2);
    CHECK_CONTAINS(out, "HTTP/1.1 204 No Content\r\nRestate-Lease: 300\r\n\r\n");
    CHECK(strstr(out, "204 No Content\r\nContent-Length") == NULL);
    CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
    CHECK_CONTAINS(out, "HTTP/1.1 404 Not Found\r\n");
    /* The log names no session: its id is a secret of its client's. */
    CHECK_CONTAINS(log, "target=/v1/web01/sessions/-/renew status=204");
    CHECK_CONTAINS(log, "target=/v1/web01/sessions/-/end status=204");
    CHECK(strstr(log, SID_READ) == NULL);
    CHECK(strstr(log, "dddddddddddddddddddddddddddddddd") == NULL);
    free(out);
    free(log);

    TEST_CASE("serve: a request in a session is let go once it is answered, with what it sent");
    released = 0;
    out = ask(grant, GET("/v1/web01/f/packs/P-0.tar.gz", IN(SID_READ)), &log);
    CHECK_INT((long long)released, 10);
    free(out);
    free(log);

    TEST_CASE("serve: a repository that is not there is nothing to list");
    fake_repo = "/nonexistent/restate-repo";
    out = ask(grant, GET("/v1/web01/list/", IN(SID_LOOK)), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 404 Not Found\r\n");
    free(out);
    free(log);

    with_sessions = false;
    fake_repo = NULL;
    rs_test_rmtree(dir);
    free(dir);
}

#define PUT(sid, name, extra, body)                                                     \
    "PUT /v1/web01/sessions/" sid "/files/" name " HTTP/1.1\r\nHost: p\r\n" AUTH extra \
    "\r\n" body
#define COMMIT(sid, name, extra)                                                         \
    "POST /v1/web01/sessions/" sid "/commit/" name " HTTP/1.1\r\nHost: p\r\n" AUTH extra \
    "\r\n"

static void test_writing(const struct rs_grant *grants)
{
    char *dir = rs_test_tmpdir();
    char *session = rs_xasprintf("%s/web01/" SID_APPEND, dir);
    char *cmd = rs_xasprintf("mkdir -p '%s'", session);
    char *out;
    char *log;
    char *got;
    char *path;

    CHECK_INT(system(cmd), 0);
    free(cmd);
    fake_repo = dir;
    fake_staging = dir;
    with_sessions = true;

    TEST_CASE("serve: an upload, into the session's staging, whole, once all else is checked");
    released_in = 0;
    out = ask(grants, PUT(SID_APPEND, "packs/P-0.sum", "Expect: 100-continue\r\n"
                          "Content-Length: 3\r\n", "abc") GET("/v1/", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n");
    CHECK_CONTAINS(out, "restate-proxy 1\n");
    CHECK_CONTAINS(log, "status=201 bytes_in=3");
    CHECK_INT((long long)released_in, 3);
    path = rs_xasprintf("%s/packs/P-0.sum", session);
    got = rs_test_slurp(path);
    CHECK_STR(got ? got : "", "abc");
    free(got);
    free(out);
    free(log);
    /* Sent again, it replaces what was there: an upload that failed partway. */
    out = ask(grants, PUT(SID_APPEND, "packs/P-0.sum", "Content-Length: 4\r\n", "abcd"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 201 Created\r\n");
    got = rs_test_slurp(path);
    CHECK_STR(got ? got : "", "abcd");
    free(got);
    free(path);
    free(out);
    free(log);
    out = ask(grants, PUT(SID_APPEND, "snapshots/S1/index.json.gz", "Content-Length: 2\r\n", "ix"),
              &log);
    CHECK_CONTAINS(out, "HTTP/1.1 201 Created\r\n");
    path = rs_xasprintf("%s/snapshots/S1/index.json.gz", session);
    CHECK(access(path, F_OK) == 0);
    free(path);
    free(out);
    free(log);
    out = ask(grants, PUT(SID_APPEND, "chunk-key", "Content-Length: 1\r\n", "k"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 201 Created\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: an upload refused before a byte of it is read, and never told 100");
    {
        static const struct {
            const char *in;
            const char *says;
        } refused[] = {
            { PUT(SID_READ, "packs/P-0.sum", "Expect: 100-continue\r\nContent-Length: 3\r\n",
                  "abc"),
              "403 Forbidden" },
            { PUT(SID_APPEND, "packs/P-0.sum", "Expect: 100-continue\r\nContent-Length: 5000\r\n",
                  "abc"),
              "413 Content Too Large" },
            { PUT(SID_APPEND, "packs/P-0.sum", "Expect: 100-continue\r\n", ""),
              "411 Length Required" },
            { PUT(SID_APPEND, "snapshots/S1/index.json.gz",
                  "Expect: 100-continue\r\nContent-Length: 3000000000\r\n", ""),
              "413 Content Too Large" },
        };
        size_t i;

        for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        {
            out = ask(grants, refused[i].in, &log);
            CHECK_CONTAINS(out, refused[i].says);
            CHECK(strstr(out, "100 Continue") == NULL);
            free(out);
            free(log);
        }
    }
    out = ask(grants, PUT(SID_APPEND, "packs/P-0.sum", "Content-Length: 5000\r\n", "abc"), &log);
    CHECK_CONTAINS(out, "Restate-Reason: too-large\r\n");
    CHECK_CONTAINS(out, "Connection: close\r\n");
    free(out);
    free(log);
    fake_max_staging = 10;
    out = ask(grants, PUT(SID_APPEND, "packs/P-1.idx", "Content-Length: 20\r\n",
                          "01234567890123456789"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 507 Insufficient Storage\r\n");
    CHECK_CONTAINS(out, "Restate-Reason: storage-full\r\n");
    free(out);
    free(log);
    /* What it replaces is not counted against it. */
    out = ask(grants, PUT(SID_APPEND, "packs/P-0.sum", "Content-Length: 4\r\n", "wxyz"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 201 Created\r\n");
    free(out);
    free(log);
    fake_max_staging = 0;

    TEST_CASE("serve: an upload cut short keeps nothing, and ends the connection");
    out = ask(grants, PUT(SID_APPEND, "packs/P-2.idx", "Content-Length: 10\r\n", "0123"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 400 Bad Request\r\n");
    path = rs_xasprintf("%s/packs/P-2.idx", session);
    CHECK(access(path, F_OK) != 0);
    free(path);
    path = rs_xasprintf("%s/packs/.P-2.idx.up", session);
    CHECK(access(path, F_OK) != 0);
    free(path);
    free(out);
    free(log);

    TEST_CASE("serve: the quota hook asked of an upload, refusing it before a byte is read");
    with_quota = true;
    quota_answer = 507;
    quota_message = "over 10 GiB";
    out = ask(grants, PUT(SID_APPEND, "packs/P-3.idx", "Expect: 100-continue\r\n"
                          "Content-Length: 5\r\n", "abcde"), &log);
    CHECK(strstr(out, "100 Continue") == NULL);
    CHECK_CONTAINS(out, "HTTP/1.1 507 Insufficient Storage\r\n");
    CHECK_CONTAINS(out, "Restate-Reason: quota-exceeded\r\n");
    CHECK_STR(body_of(out), "over 10 GiB\n");
    CHECK_STR(quota_asked, "web01 " SID_APPEND " packs/P-3.idx 5");
    path = rs_xasprintf("%s/packs/P-3.idx", session);
    CHECK(access(path, F_OK) != 0);
    free(out);
    free(log);
    quota_message = NULL;
    quota_answer = 500;
    out = ask(grants, PUT(SID_APPEND, "packs/P-3.idx", "Content-Length: 5\r\n", "abcde"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 500 Internal Server Error\r\n");
    CHECK_CONTAINS(out, "Restate-Reason: proxy-failed\r\n");
    free(out);
    free(log);
    quota_answer = 0;
    out = ask(grants, PUT(SID_APPEND, "packs/P-3.idx", "Content-Length: 5\r\n", "abcde"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 201 Created\r\n");
    CHECK(access(path, F_OK) == 0);
    free(path);
    free(out);
    free(log);
    /* A refusal of its own comes first: the hook is not asked. */
    quota_asked[0] = '\0';
    out = ask(grants, PUT(SID_APPEND, "packs/P-0.sum", "Content-Length: 5000\r\n", ""), &log);
    CHECK_CONTAINS(out, "Restate-Reason: too-large");
    CHECK_STR(quota_asked, "");
    free(out);
    free(log);
    with_quota = false;

    TEST_CASE("serve: an upload whose session has no staging is the proxy's failure");
    out = ask(grants, PUT(SID_GONE, "packs/P-0.sum", "Content-Length: 1\r\n", "a"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 500 Internal Server Error\r\n");
    CHECK_CONTAINS(log, "upload-failed client=web01 error=\"the session's staging is not there\"");
    free(out);
    free(log);
    /* A file in the way of a directory an upload needs. */
    rs_test_write(session, "snapshots/S2", "", 0600);
    out = ask(grants, PUT(SID_APPEND, "snapshots/S2/kit", "Content-Length: 1\r\n", "a"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 500 Internal Server Error\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: a commit, its outcome said, and the session told of what it put there");
    fake_commits = true;
    last_committed[0] = '\0';
    out = ask(grants, COMMIT(SID_APPEND, "packs/P-0", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 201 Created\r\n");
    CHECK_STR(last_committed, SID_APPEND " packs/P-0");
    free(out);
    free(log);
    commit_answer = 200;
    last_committed[0] = '\0';
    out = ask(grants, COMMIT(SID_APPEND, "snapshots/S1", "Content-Length: 0\r\n"), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 200 OK\r\n");
    CHECK_STR(last_committed, "");
    free(out);
    free(log);
    commit_answer = 422;
    out = ask(grants, COMMIT(SID_APPEND, "packs/P-0", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 422 Unprocessable Content\r\n");
    CHECK_CONTAINS(out, "Restate-Reason: invalid\r\n");
    CHECK_CONTAINS(out, "\r\n\r\npacks/P-0.tar.gz: it is not what its .sum says\n");
    free(out);
    free(log);
    commit_answer = 500;
    out = ask(grants, COMMIT(SID_APPEND, "packs/P-0", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 500 Internal Server Error\r\n");
    CHECK_CONTAINS(out, "the proxy failed; its log says why\n");
    CHECK_CONTAINS(log, "commit-failed client=web01 name=packs/P-0 error=\"the disk went away\"");
    free(out);
    free(log);
    commit_answer = 201;
    out = ask(grants, COMMIT(SID_READ, "packs/P-0", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 403 Forbidden\r\n");
    free(out);
    free(log);
    out = ask(grants, COMMIT(SID_APPEND, "packs/P-0", "Content-Length: 2\r\n") "ab", &log);
    CHECK_CONTAINS(out, "HTTP/1.1 400 Bad Request\r\n");
    free(out);
    free(log);
    fake_commits = false;
    /* The real one, which finds nothing uploaded by that name. */
    out = ask(grants, COMMIT(SID_APPEND, "packs/P-9", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 422 Unprocessable Content\r\n");
    CHECK_CONTAINS(out, "packs/P-9.tar.gz: not uploaded in this session\n");
    free(out);
    free(log);

    TEST_CASE("serve: a connection is bound to its first good client, and no other's");
    binds = 0;
    out = ask(grants,
              GET("/v1/web01/list/", IN(SID_LOOK)) GET("/v1/web01/list/", IN(SID_LOOK))
                  GET("/v1/db01/list/", "Authorization: Bearer " OTHER "\r\n"),
              &log);
    CHECK_INT(binds, 1);
    CHECK_INT(count(out, "HTTP/1.1 200 OK\r\n"), 2);
    CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
    free(out);
    free(log);
    bind_answer = false;
    out = ask(grants, GET("/v1/web01/list/", IN(SID_LOOK)) GET("/v1/", ""), &log);
    CHECK_CONTAINS(out, "HTTP/1.1 500 Internal Server Error\r\n");
    CHECK_CONTAINS(out, "Connection: close\r\n");
    CHECK(strstr(out, "restate-proxy 1") == NULL);
    free(out);
    free(log);
    bind_answer = true;

    with_sessions = false;
    fake_staging = NULL;
    fake_repo = NULL;
    rs_test_rmtree(dir);
    free(session);
    free(dir);
}

void test_serve(void)
{
    struct rs_grant grant;
    struct rs_buf   err;
    char            hex[RS_SHA256_HEX_SIZE];
    char           *text;
    char           *out;
    char           *log;
    unsigned        served;

    rs_buf_init(&err);
    rs_sha256_hex(TOKEN, strlen(TOKEN), hex);
    text = rs_xasprintf("repository = /srv/r\noperations = read\ntoken_sha256 = %s\n"
                        "expires = 2030-01-01T00:00:00Z\n", hex);
    memset(&grant, 0, sizeof(grant));
    CHECK(rs_grant_parse("web01", text, strlen(text), &grant, &err));
    free(text);

    TEST_CASE("serve: /v1/ says what it is, to anyone, and HEAD the same without it");
    out = serve(GET("/v1/", "") "HEAD /v1/ HTTP/1.1\r\nHost: p\r\n\r\n", &grant, 1, 0, &served,
                &log);
    CHECK_INT(served, 2);
    CHECK_INT(count(out, "HTTP/1.1 200 OK\r\n"), 2);
    CHECK_INT(count(out, "Content-Length: 16\r\n"), 2);
    CHECK_INT(count(out, "restate-proxy 1\n"), 1);
    CHECK_INT(count(log, "status=200"), 2);
    free(out);
    free(log);
    out = serve("POST /v1/ HTTP/1.1\r\nHost: p\r\n\r\n", &grant, 1, 0, &served, &log);
    CHECK_CONTAINS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: without the client's good token, every request is the same 401");
    {
        static const char *const asks[] = {
            GET("/v1/web01/list/", ""),
            GET("/v1/web01/list/", "Authorization: Bearer " OTHER "\r\n"),
            GET("/v1/web01/list/", "Authorization: Basic YTpi\r\n"),
            GET("/v1/db01/list/", "Authorization: Bearer " TOKEN "\r\n"),
            GET("/v1/web01/lock", ""),
            "DELETE /v1/web01/f/restate-repository HTTP/1.1\r\nHost: p\r\n\r\n",
        };
        size_t i;

        for (i = 0; i < sizeof(asks) / sizeof(asks[0]); i++)
        {
            out = serve(asks[i], &grant, 1, 0, &served, &log);
            CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
            CHECK_CONTAINS(out, "Restate-Reason: unauthorized\r\n");
            CHECK_CONTAINS(out, "WWW-Authenticate: Bearer\r\n");
            CHECK_CONTAINS(out, "no good token or session for this client\n");
            CHECK(strstr(log, "rsp_") == NULL);
            free(out);
            free(log);
        }
    }
    /* The grant's expiry passed: the same 401. */
    out = serve(GET("/v1/web01/list/", "Authorization: Bearer " TOKEN "\r\n"), &grant, 1,
                (int64_t)4102444800, &served, &log);
    CHECK_CONTAINS(out, "HTTP/1.1 401 Unauthorized\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: with it, the name and the method are checked, and sessions are to come");
    out = serve(GET("/v1/web01/list/", "Authorization: Bearer " TOKEN "\r\n")
                GET("/v1/web01/lock", "Authorization: Bearer " TOKEN "\r\n")
                "DELETE /v1/web01/f/restate-repository HTTP/1.1\r\nHost: p\r\n"
                "Authorization: Bearer " TOKEN "\r\n\r\n",
                &grant, 1, 0, &served, &log);
    CHECK_INT(served, 3);
    CHECK_CONTAINS(out, "HTTP/1.1 501 Not Implemented\r\n");
    CHECK_CONTAINS(out, "Restate-Reason: not-implemented\r\n");
    CHECK_CONTAINS(out, "HTTP/1.1 404 Not Found\r\n");
    CHECK_CONTAINS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
    CHECK_CONTAINS(log, "request peer=192.0.2.1:4000 client=web01 method=GET "
                        "target=/v1/web01/list/ status=501 reason=not-implemented");
    CHECK(strstr(log, TOKEN) == NULL);
    free(out);
    free(log);

    TEST_CASE("serve: a body it does not read ends the connection, never answered 100");
    out = serve("POST /v1/web01/sessions HTTP/1.1\r\nHost: p\r\nAuthorization: Bearer " TOKEN
                "\r\nExpect: 100-continue\r\nContent-Length: 6\r\n\r\nappend" GET("/v1/", ""),
                &grant, 1, 0, &served, &log);
    CHECK_INT(served, 1);
    CHECK(strstr(out, "100 Continue") == NULL);
    CHECK_CONTAINS(out, "Connection: close\r\n");
    CHECK(strstr(out, "restate-proxy 1") == NULL);
    free(out);
    free(log);
    out = serve(GET("/v1/", "Connection: close\r\n") GET("/v1/", ""), &grant, 1, 0, &served,
                &log);
    CHECK_INT(served, 1);
    CHECK_CONTAINS(out, "Connection: close\r\n");
    free(out);
    free(log);

    TEST_CASE("serve: a head it cannot read is answered, and the connection ended");
    {
        static const struct {
            const char *in;
            const char *says;
        } bad[] = {
            { "GET /v1/ HTTP/1.0\r\nHost: p\r\n\r\n" GET("/v1/", ""), "505 HTTP Version" },
            { "GET /v1/ HTTP/1.1\nHost: p\r\n\r\n", "400 Bad Request" },
            { "POST /v1/ HTTP/1.1\r\nHost: p\r\nTransfer-Encoding: chunked\r\n\r\n",
              "411 Length Required" },
            { "GET /v1/ HTTP/1.1\r\nHost: p\r\nExpect: other\r\n\r\n", "417 Expectation" },
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            out = serve(bad[i].in, &grant, 1, 0, &served, &log);
            CHECK_INT(served, 1);
            CHECK_CONTAINS(out, bad[i].says);
            CHECK_CONTAINS(out, "Restate-Reason: bad-request\r\n");
            CHECK_CONTAINS(out, "Connection: close\r\n");
            CHECK_CONTAINS(log, "why=\"");
            free(out);
            free(log);
        }
    }
    {
        char *big = rs_xcalloc(1, 10000);

        memcpy(big, "GET /v1/ HTTP/1.1\r\nHost: p\r\nX: ", 31);
        memset(big + 31, 'a', 9000);
        out = serve(big, &grant, 1, 0, &served, &log);
        CHECK_CONTAINS(out, "431 Request Header Fields Too Large");
        free(out);
        free(log);
        free(big);
    }

    TEST_CASE("serve: nothing under /v1/CLIENT/ is a 404, and a cut request no answer");
    out = serve(GET("/nothing", ""), &grant, 1, 0, &served, &log);
    CHECK_CONTAINS(out, "HTTP/1.1 404 Not Found\r\n");
    free(out);
    free(log);
    out = serve("GET /v1/ HTTP/1.1\r\nHo", &grant, 1, 0, &served, &log);
    CHECK_INT(served, 0);
    CHECK_STR(out, "");
    free(out);
    free(log);

    TEST_CASE("serve: an answer that cannot be written ends the connection");
    {
        struct mem           m;
        struct rs_proxy_io   io;
        struct rs_proxy_conn c;
        const char          *in = GET("/v1/", "") GET("/v1/", "");

        memset(&m, 0, sizeof(m));
        m.in = in;
        m.len = strlen(in);
        m.piece = 4096;
        m.fail_writes = true;
        rs_buf_init(&m.out);
        io.ctx = &m;
        io.read = mem_read;
        io.write = mem_write;
        memset(&c, 0, sizeof(c));
        CHECK_INT(rs_proxy_serve(&io, &c), 1);
        rs_buf_free(&m.out);
    }

    test_reading(&grant);
    {
        struct rs_grant both[2];

        both[0] = grant;
        memset(&both[1], 0, sizeof(both[1]));
        rs_sha256_hex(OTHER, strlen(OTHER), hex);
        text = rs_xasprintf("repository = /srv/d\noperations = read\ntoken_sha256 = %s\n", hex);
        CHECK(rs_grant_parse("db01", text, strlen(text), &both[1], &err));
        free(text);
        ngrants_asked = 2;
        test_writing(both);
        ngrants_asked = 1;
        rs_grant_free(&both[1]);
    }
    rs_grant_free(&grant);
    rs_buf_free(&err);
}
