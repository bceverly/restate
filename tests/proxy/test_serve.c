/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * proxy/serve.c: a connection served from memory, its requests given in
 * pieces as a network gives them.
 */
#include "test.h"

#include <stdlib.h>

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
            CHECK_CONTAINS(out, "no good token for this client\n");
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

    rs_grant_free(&grant);
    rs_buf_free(&err);
}
