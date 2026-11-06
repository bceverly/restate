/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * proxy/sessions.c: the table of sessions, against repositories made here,
 * at times the tests choose.
 */
#include "test.h"

#include <stdlib.h>
#include <sys/stat.h>

#include "grant.h"
#include "sessions.h"
#include "sha256.h"
#include "util.h"

#define TOKEN "rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static struct rs_buf logged;

static void keep_line(void *ctx, const char *line)
{
    (void)ctx;
    rs_buf_addf(&logged, "%s\n", line);
}

/* A repository of `version` at DIR/NAME, with its lock files. */
static char *make_repo(const char *dir, const char *name, int version)
{
    char *repo = rs_xasprintf("%s/%s", dir, name);

    CHECK(mkdir(repo, 0755) == 0);
    rs_test_write(repo, "restate-repository",
                  version == 1 ? "restate-repository 1\n"
                               : "restate-repository 2\nid 0123456789abcdef0123456789abcdef\n",
                  0644);
    rs_test_write(repo, "lock", "", 0644);
    rs_test_write(repo, "readers", "", 0644);
    return repo;
}

/* `client`'s grant of `ops` to `repo`. */
static void grant_of(const char *client, const char *repo, const char *ops, struct rs_grant *g)
{
    char          hex[RS_SHA256_HEX_SIZE];
    char         *text;
    struct rs_buf err;

    rs_sha256_hex(TOKEN, strlen(TOKEN), hex);
    text = rs_xasprintf("repository = %s\noperations = %s\ntoken_sha256 = %s\n", repo, ops, hex);
    rs_buf_init(&err);
    memset(g, 0, sizeof(*g));
    CHECK(rs_grant_parse(client, text, strlen(text), g, &err));
    rs_buf_free(&err);
    free(text);
}

void test_sessions(void)
{
    char                   *dir = rs_test_tmpdir();
    char                   *repo = make_repo(dir, "r", 2);
    char                   *old = make_repo(dir, "old", 1);
    char                   *none = rs_xasprintf("%s/none", dir);
    struct rs_grant         rw;
    struct rs_grant         ro;
    struct rs_grant         other;
    struct rs_grant         v1;
    struct rs_grant         missing;
    struct rs_sessions     *s;
    struct rs_proxy_session found;
    struct rs_buf           why;
    char                    a[RS_SESSION_LEN + 1];
    char                    b[RS_SESSION_LEN + 1];
    char                    c[RS_SESSION_LEN + 1];

    grant_of("web01", repo, "read, append", &rw);
    grant_of("ro", repo, "read", &ro);
    grant_of("db01", repo, "append", &other);
    grant_of("web02", old, "read, append", &v1);
    grant_of("web03", none, "read", &missing);
    rs_buf_init(&logged);
    rs_buf_init(&why);
    s = rs_sessions_new(3, 10, keep_line, NULL);

    TEST_CASE("sessions: the kinds there are, by their words");
    {
        enum rs_proxy_kind k = RS_PROXY_LOOK;

        CHECK(rs_proxy_kind_of("append\n", 7, &k) && k == RS_PROXY_APPEND);
        CHECK(rs_proxy_kind_of("read", 4, &k) && k == RS_PROXY_READ);
        CHECK(rs_proxy_kind_of("look", 4, &k) && k == RS_PROXY_LOOK);
        CHECK(!rs_proxy_kind_of("write", 5, &k) && !rs_proxy_kind_of("", 0, &k));
        CHECK(!rs_proxy_kind_of("read\n\n", 6, &k));
        CHECK_STR(rs_proxy_kind_name(RS_PROXY_APPEND), "append");
    }

    TEST_CASE("sessions: opened as each grant allows, each with its locks");
    CHECK_INT(rs_sessions_open(s, &rw, RS_PROXY_APPEND, 1000, a, &why), 201);
    CHECK_INT((long long)strlen(a), RS_SESSION_LEN);
    CHECK_INT((long long)strspn(a, "0123456789abcdef"), RS_SESSION_LEN);
    CHECK_CONTAINS(logged.data, "session-open client=web01 kind=append");
    /* The lock is the repository's: a second capture is busy. */
    CHECK_INT(rs_sessions_open(s, &other, RS_PROXY_APPEND, 1000, b, &why), 423);
    CHECK_INT(rs_sessions_open(s, &ro, RS_PROXY_APPEND, 1000, b, &why), 403);
    CHECK_INT(rs_sessions_open(s, &other, RS_PROXY_READ, 1000, b, &why), 403);
    CHECK_INT(rs_sessions_open(s, &ro, RS_PROXY_READ, 1000, b, &why), 201);
    CHECK_INT(rs_sessions_open(s, &other, RS_PROXY_LOOK, 1000, c, &why), 201);
    CHECK(strcmp(a, b) != 0 && strcmp(b, c) != 0);
    CHECK_INT((long long)rs_sessions_count(s), 3);
    /* Full. */
    CHECK_INT(rs_sessions_open(s, &ro, RS_PROXY_LOOK, 1000, c, &why), 503);
    CHECK_INT(rs_sessions_end(s, "db01", c, 1001), 204);

    TEST_CASE("sessions: a version 1 repository, and one that is not there");
    CHECK_INT(rs_sessions_open(s, &v1, RS_PROXY_APPEND, 1000, c, &why), 409);
    CHECK_INT(rs_sessions_open(s, &v1, RS_PROXY_READ, 1000, c, &why), 201);
    CHECK_INT(rs_sessions_end(s, "web02", c, 1000), 204);
    rs_buf_reset(&why);
    CHECK_INT(rs_sessions_open(s, &missing, RS_PROXY_READ, 1000, c, &why), 500);
    CHECK_CONTAINS(why.data, none);
    rs_buf_reset(&why);
    rs_sessions_set_random("/nonexistent/random");
    CHECK_INT(rs_sessions_open(s, &ro, RS_PROXY_LOOK, 1000, c, &why), 500);
    CHECK_CONTAINS(why.data, "random source");
    rs_sessions_set_random(NULL);

    TEST_CASE("sessions: found by their own client, held while a request is in them");
    CHECK_INT(rs_sessions_find(s, "web01", a, &found), RS_PROXY_FOUND);
    CHECK(found.kind == RS_PROXY_APPEND);
    CHECK_STR(found.repository, repo);
    CHECK_INT(rs_sessions_find(s, "ro", a, &found), RS_PROXY_NOT_YOURS);
    CHECK_INT(rs_sessions_find(s, "web01", "dddddddddddddddddddddddddddddddd", &found),
              RS_PROXY_NO_SESSION);
    /* Held: long past the lease, it is not ended. */
    CHECK_INT((long long)rs_sessions_expire(s, 5000), 1);   /* b, the idle one */
    CHECK_CONTAINS(logged.data, "session-end client=ro kind=read seconds=4000");
    CHECK_CONTAINS(logged.data, "result=expired");
    CHECK_INT(rs_sessions_find(s, "ro", b, &found), RS_PROXY_NO_SESSION);
    rs_sessions_release(s, a, 1234, 5000);
    rs_sessions_release(s, "dddddddddddddddddddddddddddddddd", 1, 5000);
    /* Let go, its lease starts again from then. */
    CHECK_INT((long long)rs_sessions_expire(s, 5009), 0);
    CHECK_INT(rs_sessions_renew(s, "web01", a, 5008), 204);
    CHECK_INT((long long)rs_sessions_expire(s, 5017), 0);
    CHECK_INT(rs_sessions_renew(s, "ro", a, 5008), 401);
    CHECK_INT(rs_sessions_renew(s, "web01", b, 5008), 404);

    TEST_CASE("sessions: ended by their client, an append one as ended, not finished");
    CHECK_INT(rs_sessions_end(s, "ro", a, 5010), 401);
    CHECK_INT(rs_sessions_end(s, "web01", a, 5010), 204);
    CHECK_CONTAINS(logged.data, "session-end client=web01 kind=append seconds=4010 bytes_in=0 "
                                "bytes_out=1234 packs=0 result=ended");
    CHECK_INT(rs_sessions_end(s, "web01", a, 5010), 404);
    /* With its lock gone, the next capture is not busy. */
    CHECK_INT(rs_sessions_open(s, &other, RS_PROXY_APPEND, 6000, a, &why), 201);
    CHECK_INT(rs_sessions_open(s, &rw, RS_PROXY_READ, 6000, b, &why), 201);
    CHECK_INT(rs_sessions_end(s, "web01", b, 6001), 204);
    CHECK_CONTAINS(logged.data, "kind=read seconds=1 bytes_in=0 bytes_out=0 packs=0 result=ok");
    CHECK_INT((long long)rs_sessions_lease(s), 10);

    TEST_CASE("sessions: ended as the proxy stops; forgotten by a process forked from it");
    {
        struct rs_sessions *t = rs_sessions_new(0, 0, NULL, NULL);

        CHECK_INT((long long)rs_sessions_lease(t), RS_PROXY_LEASE);
        CHECK_INT(rs_sessions_open(t, &ro, RS_PROXY_READ, 1, b, &why), 201);
        rs_sessions_forget(t);
        rs_sessions_forget(NULL);
    }
    rs_buf_reset(&logged);
    rs_sessions_free(s, 7000);
    CHECK_CONTAINS(logged.data, "session-end client=db01 kind=append");
    CHECK_CONTAINS(logged.data, "result=ended");
    rs_sessions_free(NULL, 0);

    rs_grant_free(&rw);
    rs_grant_free(&ro);
    rs_grant_free(&other);
    rs_grant_free(&v1);
    rs_grant_free(&missing);
    rs_buf_free(&why);
    rs_buf_free(&logged);
    rs_test_rmtree(dir);
    free(repo);
    free(old);
    free(none);
    free(dir);
}
