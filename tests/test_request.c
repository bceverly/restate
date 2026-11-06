/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <string.h>

#include "request.h"
#include "test.h"
#include "util.h"

#define SID "6f1c0a9d2e7b4c35a8f0e1d2c3b4a596"

/* What rs_request_parse says of `text`, `req` freed after. */
static long parse_says(const char *text, const char **why)
{
    struct rs_request req;
    long              rc = rs_request_parse(text, strlen(text), &req, why);

    rs_request_free(&req);
    return rc;
}

static void test_heads(void)
{
    const char *head = "PUT /v1/web01/sessions/" SID "/files/packs/P.tar.gz HTTP/1.1\r\n"
                       "Host: proxy.example\r\n"
                       "authorization: Bearer rsp_AAAA\r\n"
                       "Content-Length:   1024 \r\n"
                       "Restate-Session: " SID "\r\n"
                       "Expect: 100-Continue\r\n"
                       "Connection: keep-alive, Close\r\n"
                       "X-Other: anything at all \x80\r\n"
                       "\r\n"
                       "BODY";
    struct rs_request req;
    const char       *why;
    long              rc;
    size_t            i;

    TEST_CASE("request: a whole head");
    rc = rs_request_parse(head, strlen(head), &req, &why);
    CHECK_INT(rc, (long long)(strlen(head) - 4));
    CHECK_INT(req.method, RS_METHOD_PUT);
    CHECK_STR(req.target, "/v1/web01/sessions/" SID "/files/packs/P.tar.gz");
    CHECK(req.has_length);
    CHECK_INT((long long)req.length, 1024);
    CHECK_STR(req.token, "rsp_AAAA");
    CHECK(!req.token_malformed);
    CHECK_STR(req.session, SID);
    CHECK(req.expect_continue);
    CHECK(req.close);
    CHECK(!req.has_range);
    rs_request_free(&req);

    TEST_CASE("request: not whole yet, a byte at a time");
    for (i = 0; i < strlen(head) - 4; i++)
    {
        rc = rs_request_parse(head, i, &req, &why);
        rs_request_free(&req);
        if (rc != 0)
        {
            break;
        }
    }
    CHECK_INT((long long)i, (long long)(strlen(head) - 4));

    TEST_CASE("request: the least a head can be");
    rc = rs_request_parse("GET /v1/ HTTP/1.1\r\nHost: x\r\n\r\n", 30, &req, &why);
    CHECK_INT(rc, 30);
    CHECK_INT(req.method, RS_METHOD_GET);
    CHECK(req.token == NULL);
    CHECK_STR(req.session, "");
    CHECK(!req.close);
    rs_request_free(&req);

    TEST_CASE("request: methods");
    {
        static const struct {
            const char    *line;
            enum rs_method m;
        } methods[] = { { "HEAD /x HTTP/1.1", RS_METHOD_HEAD },
                        { "POST /x HTTP/1.1", RS_METHOD_POST },
                        { "DELETE /x HTTP/1.1", RS_METHOD_DELETE },
                        { "PATCH /x HTTP/1.1", RS_METHOD_OTHER },
                        { "get /x HTTP/1.1", RS_METHOD_OTHER } };

        for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
        {
            char *text = rs_xasprintf("%s\r\nHost: x\r\n\r\n", methods[i].line);

            CHECK(rs_request_parse(text, strlen(text), &req, &why) > 0);
            CHECK_INT(req.method, methods[i].m);
            rs_request_free(&req);
            free(text);
        }
    }

    TEST_CASE("request: ranges");
    {
        static const struct {
            const char *range;
            bool        bad;
            bool        open;
            uint64_t    first;
            uint64_t    last;
        } ranges[] = {
            { "bytes=0-", false, true, 0, 0 },
            { "bytes=1048576-", false, true, 1048576, 0 },
            { "bytes=10-20", false, false, 10, 20 },
            { "bytes=7-7", false, false, 7, 7 },
            { "bytes=20-10", true, false, 0, 0 },
            { "bytes=-500", true, false, 0, 0 },
            { "bytes=0-1,5-6", true, false, 0, 0 },
            { "bytes=", true, false, 0, 0 },
            { "items=0-", true, false, 0, 0 },
            { "bytes=a-", true, false, 0, 0 },
            { "bytes=99999999999999999999-", true, false, 0, 0 },
        };

        for (i = 0; i < sizeof(ranges) / sizeof(ranges[0]); i++)
        {
            char *text = rs_xasprintf("GET /x HTTP/1.1\r\nHost: x\r\nRange: %s\r\n\r\n",
                                      ranges[i].range);

            CHECK(rs_request_parse(text, strlen(text), &req, &why) > 0);
            CHECK(req.has_range);
            CHECK(req.range_bad == ranges[i].bad);
            if (!ranges[i].bad)
            {
                CHECK(req.range_open == ranges[i].open);
                CHECK_INT((long long)req.range_first, (long long)ranges[i].first);
                CHECK_INT((long long)req.range_last, (long long)ranges[i].last);
            }
            rs_request_free(&req);
            free(text);
        }
    }

    TEST_CASE("request: authorization that is not a bearer token");
    {
        static const char *const auths[] = { "Basic dXNlcjpwYXNz", "Bearer", "Bearer ",
                                             "Bearer a b", "Bearer\trsp_x", "Bearerrsp_x" };

        for (i = 0; i < sizeof(auths) / sizeof(auths[0]); i++)
        {
            char *text = rs_xasprintf("GET /x HTTP/1.1\r\nHost: x\r\nAuthorization: %s\r\n\r\n",
                                      auths[i]);

            CHECK(rs_request_parse(text, strlen(text), &req, &why) > 0);
            CHECK(req.token_malformed);
            CHECK(req.token == NULL);
            rs_request_free(&req);
            free(text);
        }
    }
    {
        char  token[300];
        char *text;

        memset(token, 'a', sizeof(token) - 1);
        token[sizeof(token) - 1] = '\0';
        text = rs_xasprintf("GET /x HTTP/1.1\r\nHost: x\r\nAuthorization: BEARER %s\r\n\r\n",
                            token);
        CHECK(rs_request_parse(text, strlen(text), &req, &why) > 0);
        CHECK(req.token_malformed);
        rs_request_free(&req);
        free(text);
    }

    TEST_CASE("request: every way a head is refused");
    {
        static const struct {
            const char *text;
            long        rc;
            const char *why;
        } bad[] = {
            { "GET /x HTTP/1.1\r\n\r\n", -400, "no Host" },
            { "GET /x HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", -400, "given twice" },
            { "GET /x HTTP/1.0\r\nHost: x\r\n\r\n", -505, "not HTTP/1.1" },
            { "GET /x HTTP/2.0\r\nHost: x\r\n\r\n", -505, "not HTTP/1.1" },
            { "GET /x HTTPS/1.1\r\nHost: x\r\n\r\n", -400, "not HTTP" },
            { "GET /x HTTP/1.1 \r\nHost: x\r\n\r\n", -400, "not HTTP" },
            { "GET  /x HTTP/1.1\r\nHost: x\r\n\r\n", -400, "not a request line" },
            { "GET /x\r\nHost: x\r\n\r\n", -400, "not a request line" },
            { "G(T /x HTTP/1.1\r\nHost: x\r\n\r\n", -400, "not a method" },
            { "GET x HTTP/1.1\r\nHost: x\r\n\r\n", -400, "origin-form" },
            { "GET http://a/x HTTP/1.1\r\nHost: x\r\n\r\n", -400, "origin-form" },
            { "GET /\x7f HTTP/1.1\r\nHost: x\r\n\r\n", -400, "not a target" },
            { "GET /x HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n", -400, "folded" },
            { "GET /x HTTP/1.1\r\nHost: x\r\nNo colon\r\n\r\n", -400, "not a header" },
            { "GET /x HTTP/1.1\r\nHost: x\r\n: empty\r\n\r\n", -400, "not a header" },
            { "GET /x HTTP/1.1\r\nHost: x\r\nBad Name: v\r\n\r\n", -400, "header's name" },
            { "GET /x HTTP/1.1\r\nHost: x\r\nX: a\x01" "b\r\n\r\n", -400, "control" },
            { "GET /x HTTP/1.1\r\nHost: x\r\nX: a\rb\r\n\r\n", -400, "bare CR" },
            { "GET /x HTTP/1.1\r\nHost: x\nX: y\r\n\r\n", -400, "bare LF" },
            { "GET /x HTTP/1.1\nHost: x\r\n\r\n", -400, "bare" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1e3\r\n\r\n", -400, "number" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", -400, "number" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: \r\n\r\n", -400, "number" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: 9223372036854775808\r\n\r\n",
              -400, "number" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n",
              -400, "given twice" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n", -411,
              "Transfer-Encoding" },
            { "GET /x HTTP/1.1\r\nHost: x\r\nRestate-Session: abc\r\n\r\n", -400,
              "Restate-Session" },
            { "GET /x HTTP/1.1\r\nHost: x\r\nRestate-Session: 6F1C0A9D2E7B4C35A8F0E1D2C3B4A596"
              "\r\n\r\n", -400, "Restate-Session" },
            { "PUT /x HTTP/1.1\r\nHost: x\r\nExpect: something\r\n\r\n", -417, "Expect" },
        };

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            rc = parse_says(bad[i].text, &why);
            CHECK_INT(rc, bad[i].rc);
            CHECK_CONTAINS(why, bad[i].why);
        }
        rc = rs_request_parse("GET /x HTTP/1.1\r\nHost: x\0\r\n\r\n", 29, &req, &why);
        CHECK_INT(rc, -400);
        CHECK_CONTAINS(why, "NUL");
        rs_request_free(&req);
    }

    TEST_CASE("request: 8 KiB and no more");
    {
        char *big = rs_xmalloc(RS_REQUEST_HEAD_MAX + 64);
        char *p = big;

        p += sprintf(p, "GET /x HTTP/1.1\r\nHost: x\r\nX: ");
        while (p < big + RS_REQUEST_HEAD_MAX - 4)
        {
            *p++ = 'a';
        }
        memcpy(p, "\r\n\r\n", 4);
        /* Exactly 8 KiB: taken. */
        rc = rs_request_parse(big, RS_REQUEST_HEAD_MAX, &req, &why);
        CHECK_INT(rc, RS_REQUEST_HEAD_MAX);
        rs_request_free(&req);
        /* A byte more, the end not yet seen: refused before the end comes. */
        p[0] = 'a';
        memcpy(p + 1, "\r\n\r\n", 4);
        rc = rs_request_parse(big, RS_REQUEST_HEAD_MAX, &req, &why);
        CHECK_INT(rc, -431);
        rs_request_free(&req);
        rc = rs_request_parse(big, RS_REQUEST_HEAD_MAX + 5, &req, &why);
        CHECK_INT(rc, -431);
        rs_request_free(&req);
        /* Short of 8 KiB, no end yet: more to come. */
        rc = rs_request_parse(big, RS_REQUEST_HEAD_MAX - 1, &req, &why);
        CHECK_INT(rc, 0);
        rs_request_free(&req);
        free(big);
    }
}

/* What rs_route_parse makes of `target`. */
static void route_of(const char *target, struct rs_route *route)
{
    rs_route_free(route);
    rs_route_parse(target, route);
}

static void test_routes(void)
{
    struct rs_route route;
    size_t          i;

    memset(&route, 0, sizeof(route));

    TEST_CASE("route: every endpoint");
    route_of("/v1/", &route);
    CHECK_INT(route.endpoint, RS_EP_HELLO);
    CHECK(route.client == NULL);
    route_of("/v1/web01/sessions", &route);
    CHECK_INT(route.endpoint, RS_EP_SESSION_OPEN);
    CHECK_STR(route.client, "web01");
    route_of("/v1/web01/sessions/" SID "/renew", &route);
    CHECK_INT(route.endpoint, RS_EP_SESSION_RENEW);
    CHECK_STR(route.session, SID);
    route_of("/v1/web01/sessions/" SID "/end", &route);
    CHECK_INT(route.endpoint, RS_EP_SESSION_END);
    route_of("/v1/web01/list/", &route);
    CHECK_INT(route.endpoint, RS_EP_LIST);
    CHECK_STR(route.name, "");
    route_of("/v1/web01/list/packs/", &route);
    CHECK_STR(route.name, "packs");
    route_of("/v1/web01/list/snapshots/", &route);
    CHECK_STR(route.name, "snapshots");
    route_of("/v1/web01/list/snapshots/20261020T030000Z/", &route);
    CHECK_INT(route.endpoint, RS_EP_LIST);
    CHECK_STR(route.name, "snapshots/20261020T030000Z");
    route_of("/v1/web01/f/packs/P-1.idx", &route);
    CHECK_INT(route.endpoint, RS_EP_FILE);
    CHECK_STR(route.name, "packs/P-1.idx");
    CHECK_INT(route.kind, RS_FK_PACK_IDX);
    route_of("/v1/web01/f/restate-repository", &route);
    CHECK_INT(route.kind, RS_FK_MARKER);
    route_of("/v1/web01/sessions/" SID "/files/snapshots/S/index.json.gz", &route);
    CHECK_INT(route.endpoint, RS_EP_UPLOAD);
    CHECK_INT(route.kind, RS_FK_INDEX);
    CHECK_STR(route.name, "snapshots/S/index.json.gz");
    CHECK_STR(route.session, SID);
    route_of("/v1/web01/sessions/" SID "/commit/packs/P-1", &route);
    CHECK_INT(route.endpoint, RS_EP_COMMIT);
    CHECK_STR(route.name, "packs/P-1");
    route_of("/v1/web01/sessions/" SID "/commit/snapshots/S", &route);
    CHECK_STR(route.name, "snapshots/S");
    route_of("/v1/web01/sessions/" SID "/commit/chunk-key", &route);
    CHECK_INT(route.endpoint, RS_EP_COMMIT);
    route_of("/v1/web01/sessions/" SID "/commit/chunk-key.20261020T030000Z-000", &route);
    CHECK_INT(route.endpoint, RS_EP_COMMIT);

    TEST_CASE("route: nothing this protocol has, its client still found");
    {
        static const char *const none[] = {
            "/v1/web01/", "/v1/web01/sessions/", "/v1/web01/f/lock", "/v1/web01/f/readers",
            "/v1/web01/f/packs/.P.idx.tmp", "/v1/web01/f/packs/P.idx/x",
            "/v1/web01/f/packs/../lock", "/v1/web01/f/packs//P.idx", "/v1/web01/f/packs/%2e.idx",
            "/v1/web01/f/packs/P.idx?x=1", "/v1/web01/f/snapshots/S/other",
            "/v1/web01/f/snapshots/.S/kit", "/v1/web01/f/snapshots/S", "/v1/web01/f/",
            "/v1/web01/f/packs/.idx", "/v1/web01/f/chunk-key.", "/v1/web01/f/chunk-key.a/b",
            "/v1/web01/list/lock/", "/v1/web01/list/packs", "/v1/web01/list/snapshots/.S/",
            "/v1/web01/list/snapshots/S/x/", "/v1/web01/list//",
            "/v1/web01/sessions/" SID, "/v1/web01/sessions/" SID "/",
            "/v1/web01/sessions/" SID "/renew/", "/v1/web01/sessions/" SID "/other",
            "/v1/web01/sessions/" SID "/files/restate-repository",
            "/v1/web01/sessions/" SID "/files/lock",
            "/v1/web01/sessions/" SID "/commit/packs/P.idx/x",
            "/v1/web01/sessions/" SID "/commit/packs/.P",
            "/v1/web01/sessions/" SID "/commit/snapshots/S/kit",
            "/v1/web01/sessions/" SID "/commit/lock",
            "/v1/web01/sessions/6F1C0A9D2E7B4C35A8F0E1D2C3B4A596/end",
            "/v1/web01/sessions/abc/end", "/v1/web01/DELETE",
        };

        for (i = 0; i < sizeof(none) / sizeof(none[0]); i++)
        {
            route_of(none[i], &route);
            CHECK_INT(route.endpoint, RS_EP_NONE);
            CHECK_STR(route.client, "web01");
            CHECK_STR(route.session, "");
            CHECK(route.name == NULL);
            CHECK_INT(route.kind, RS_FK_NONE);
        }
    }

    TEST_CASE("route: no client");
    {
        static const char *const none[] = { "/", "/v1", "/v2/web01/sessions", "/v1/web01",
                                            "/v1//sessions", "/v1/.web01/sessions",
                                            "/v1/-web01/sessions", "/V1/web01/sessions",
                                            "/v1/we%62/sessions" };

        for (i = 0; i < sizeof(none) / sizeof(none[0]); i++)
        {
            route_of(none[i], &route);
            CHECK_INT(route.endpoint, RS_EP_NONE);
            CHECK(route.client == NULL);
        }
    }
    rs_route_free(&route);

    TEST_CASE("route: methods");
    CHECK(rs_route_method_ok(RS_EP_HELLO, RS_METHOD_GET));
    CHECK(rs_route_method_ok(RS_EP_FILE, RS_METHOD_HEAD));
    CHECK(!rs_route_method_ok(RS_EP_FILE, RS_METHOD_PUT));
    CHECK(!rs_route_method_ok(RS_EP_LIST, RS_METHOD_DELETE));
    CHECK(rs_route_method_ok(RS_EP_SESSION_OPEN, RS_METHOD_POST));
    CHECK(!rs_route_method_ok(RS_EP_SESSION_END, RS_METHOD_DELETE));
    CHECK(!rs_route_method_ok(RS_EP_COMMIT, RS_METHOD_GET));
    CHECK(rs_route_method_ok(RS_EP_UPLOAD, RS_METHOD_PUT));
    CHECK(!rs_route_method_ok(RS_EP_UPLOAD, RS_METHOD_POST));
    CHECK(!rs_route_method_ok(RS_EP_UPLOAD, RS_METHOD_OTHER));
    CHECK(rs_route_method_ok(RS_EP_NONE, RS_METHOD_DELETE));
}

static void test_kinds(void)
{
    TEST_CASE("route: what a file is, and the most it may be");
    CHECK_INT(rs_file_kind_of("packs/P.tar.gz"), RS_FK_PACK);
    CHECK_INT(rs_file_kind_of("packs/P.sum"), RS_FK_PACK_SUM);
    CHECK_INT(rs_file_kind_of("packs/P.seek"), RS_FK_PACK_SEEK);
    CHECK_INT(rs_file_kind_of("packs/a.b.idx"), RS_FK_PACK_IDX);
    CHECK_INT(rs_file_kind_of("snapshots/S/index.sig"), RS_FK_INDEX_SIG);
    CHECK_INT(rs_file_kind_of("snapshots/S/kit"), RS_FK_KIT);
    CHECK_INT(rs_file_kind_of("snapshots/S/info"), RS_FK_INFO);
    CHECK_INT(rs_file_kind_of("snapshots/S/packs"), RS_FK_PACK_LIST);
    CHECK_INT(rs_file_kind_of("packs/P.tar"), RS_FK_NONE);
    CHECK_INT(rs_file_kind_of("packs"), RS_FK_NONE);
    CHECK_INT(rs_file_kind_of("lock"), RS_FK_NONE);
    CHECK_INT(rs_file_kind_of(""), RS_FK_NONE);
    CHECK_INT((long long)rs_upload_max(RS_FK_PACK), 64LL * 1024 * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_PACK_IDX), 256LL * 1024 * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_KIT), 256LL * 1024 * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_INFO), 256LL * 1024 * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_PACK_SUM), 4096);
    CHECK_INT((long long)rs_upload_max(RS_FK_CHUNK_KEY), 4096);
    CHECK_INT((long long)rs_upload_max(RS_FK_PACK_SEEK), 16LL * 1024 * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_PACK_LIST), 16LL * 1024 * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_INDEX), 2LL * 1024 * 1024 * 1024 - 1);
    CHECK_INT((long long)rs_upload_max(RS_FK_INDEX_SIG), 64LL * 1024);
    CHECK_INT((long long)rs_upload_max(RS_FK_MARKER), 0);
    CHECK_INT((long long)rs_upload_max(RS_FK_NONE), 0);
}

void test_request(void)
{
    test_heads();
    test_routes();
    test_kinds();
}
