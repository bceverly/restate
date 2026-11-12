/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "grant.h"
#include "sha256.h"
#include "test.h"
#include "token.h"

/* Two tokens and their digests in hex, as sha256sum gives them. */
#define TOKEN_A "rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define TOKEN_B "rsp_abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

static char hex_a[RS_SHA256_HEX_SIZE];
static char hex_b[RS_SHA256_HEX_SIZE];

/* A grant's text with `extra` after the keys every grant has. */
static char *grant_text(const char *extra)
{
    return rs_xasprintf("# a grant\n"
                        "repository   = /srv/restate/web01\n"
                        "operations   = append, read\n"
                        "token_sha256 = %s\n"
                        "%s",
                        hex_a, extra);
}

/* Whether `text` parses for client "web01"; why into `why`, reset first. */
static bool parses(const char *text, struct rs_buf *why)
{
    struct rs_grant g;
    bool            ok;

    rs_buf_reset(why);
    ok = rs_grant_parse("web01", text, strlen(text), &g, why);
    rs_grant_free(&g);
    return ok;
}

static void test_tokens(void)
{
    char             tok[RS_TOKEN_SIZE];
    char             other[RS_TOKEN_SIZE];
    unsigned char    d[RS_SHA256_SIZE];
    unsigned char    e[RS_SHA256_SIZE];
    char             hex[RS_SHA256_HEX_SIZE];
    char            *dir;
    char            *empty;
    struct rs_sha256 sha;

    TEST_CASE("token: what one is");
    CHECK(rs_token_valid(TOKEN_A, strlen(TOKEN_A)));
    CHECK(rs_token_valid(TOKEN_B, strlen(TOKEN_B)));
    /* The last character's two low bits are 0: "B" (1) is not one. */
    CHECK(!rs_token_valid("rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", 47));
    CHECK(!rs_token_valid("rsq_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 47));
    CHECK(!rs_token_valid("rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 46));
    CHECK(!rs_token_valid("rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 48));
    CHECK(!rs_token_valid("rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+A", 47));
    CHECK(!rs_token_valid("rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=A", 47));
    CHECK(!rs_token_valid("", 0));

    TEST_CASE("token: a new one is one, and another is another");
    CHECK(rs_token_new(tok));
    CHECK_INT((long long)strlen(tok), RS_TOKEN_LEN);
    CHECK(rs_token_valid(tok, strlen(tok)));
    CHECK(rs_token_new(other));
    CHECK(strcmp(tok, other) != 0);

    TEST_CASE("token: none without a random source");
    dir = rs_test_tmpdir();
    rs_test_write(dir, "empty", "", 0600);
    empty = rs_xasprintf("%s/empty", dir);
    rs_token_set_random(empty);
    CHECK(!rs_token_new(tok));
    rs_token_set_random("/nonexistent/random");
    CHECK(!rs_token_new(tok));
    rs_token_set_random(NULL);
    free(empty);
    rs_test_rmtree(dir);
    free(dir);

    TEST_CASE("token: its digest is the SHA-256 of it as written");
    rs_token_digest(TOKEN_A, strlen(TOKEN_A), d);
    rs_sha256_init(&sha);
    rs_sha256_update(&sha, TOKEN_A, strlen(TOKEN_A));
    rs_sha256_final_raw(&sha, e);
    CHECK(memcmp(d, e, sizeof(d)) == 0);
    rs_sha256_hex(TOKEN_A, strlen(TOKEN_A), hex);
    CHECK_STR(hex, hex_a);
    CHECK(rs_digest_equal(d, e));
    e[31] ^= 1;
    CHECK(!rs_digest_equal(d, e));
    e[31] ^= 1;
    e[0] ^= 0x80;
    CHECK(!rs_digest_equal(d, e));
}

static void test_times(void)
{
    int64_t t = 0;

    TEST_CASE("grant: times");
    CHECK(rs_grant_parse_time("1970-01-01T00:00:00Z", 20, &t));
    CHECK_INT(t, 0);
    CHECK(rs_grant_parse_time("2026-12-31T00:00:00Z", 20, &t));
    CHECK_INT(t, 1798675200);
    CHECK(rs_grant_parse_time("2028-02-29T23:59:59Z", 20, &t));
    CHECK_INT(t, 1835481599);
    CHECK(rs_grant_parse_time("2000-02-29T12:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2027-02-29T00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("1900-02-29T00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-13-01T00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-00-01T00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-31T00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-00T00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-01T24:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-01T00:60:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-01T00:00:60Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-01 00:00:00Z", 20, &t));
    CHECK(!rs_grant_parse_time("2026-04-01T00:00:00+", 20, &t));
    CHECK(!rs_grant_parse_time("2026-4-01T00:00:00Z", 19, &t));
    CHECK(!rs_grant_parse_time("1969-12-31T23:59:59Z", 20, &t));
    CHECK(!rs_grant_parse_time("2O26-04-01T00:00:00Z", 20, &t));
}

static void test_names(void)
{
    char *client = NULL;

    TEST_CASE("grant: the keys a grant may use");
    {
        size_t             n = 0;
        const char *const *keys = rs_grant_keys(&n);

        CHECK(n == 7);
        CHECK_STR(keys[0], "repository");
        CHECK_STR(keys[5], "max_sessions");
        CHECK_STR(keys[6], "bandwidth");
    }

    TEST_CASE("grant: client names and grant file names");
    CHECK(rs_grant_client_valid("web01"));
    CHECK(rs_grant_client_valid("4b1f0c7e-2d6a-4e8f-9a3b-1c2d3e4f5a6b.previous"));
    CHECK(rs_grant_client_valid("A_b-c.d"));
    CHECK(!rs_grant_client_valid(""));
    CHECK(!rs_grant_client_valid(".web01"));
    CHECK(!rs_grant_client_valid("-web01"));
    CHECK(!rs_grant_client_valid("web 01"));
    CHECK(!rs_grant_client_valid("web/01"));
    CHECK(!rs_grant_client_valid("web01\xc3\xa9"));
    {
        char name[66];

        memset(name, 'a', 64);
        name[64] = '\0';
        CHECK(rs_grant_client_valid(name));
        name[64] = 'a';
        name[65] = '\0';
        CHECK(!rs_grant_client_valid(name));
    }

    CHECK(rs_grant_file_client("web01.conf", &client));
    CHECK_STR(client, "web01");
    free(client);
    CHECK(!rs_grant_file_client(".web01.conf.tmp", &client));
    CHECK(client == NULL);
    CHECK(!rs_grant_file_client(".web01.conf", &client));
    CHECK(!rs_grant_file_client("web01.conf.tmp", &client));
    CHECK(!rs_grant_file_client("web01", &client));
    CHECK(!rs_grant_file_client(".conf", &client));
    CHECK(!rs_grant_file_client("-web01.conf", &client));
    CHECK(client == NULL);
}

static void test_parsing(void)
{
    struct rs_grant g;
    struct rs_buf   why;
    char           *text;
    char           *extra;

    rs_buf_init(&why);

    TEST_CASE("grant: a whole one");
    extra = rs_xasprintf("token_sha256 = %s\n"
                         "expires      = 2026-12-31T00:00:00Z\n"
                         "\n"
                         "   # an indented comment\n"
                         "label = managed by sysmanage-agent: a=b #1\r\n",
                         hex_b);
    text = grant_text(extra);
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_STR(g.client, "web01");
    CHECK_STR(g.repository, "/srv/restate/web01");
    CHECK_INT(g.operations, RS_GRANT_APPEND | RS_GRANT_READ);
    CHECK_INT((long long)g.ntokens, 2);
    CHECK(g.expires_set);
    CHECK_INT(g.expires, 1798675200);
    CHECK_STR(g.label, "managed by sysmanage-agent: a=b #1");
    CHECK(rs_grant_admits(&g, TOKEN_A, strlen(TOKEN_A), 1798675199));
    CHECK(rs_grant_admits(&g, TOKEN_B, strlen(TOKEN_B), 0));
    CHECK(!rs_grant_admits(&g, TOKEN_A, strlen(TOKEN_A), 1798675200));
    CHECK(!rs_grant_admits(&g, "rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", 47, 0));
    CHECK(!rs_grant_admits(&g, TOKEN_A, strlen(TOKEN_A) - 1, 0));
    CHECK(!rs_grant_admits(&g, hex_a, strlen(hex_a), 0));
    rs_grant_free(&g);
    free(text);
    free(extra);

    TEST_CASE("grant: the least one can be, and its values");
    text = grant_text("");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK(!g.expires_set);
    CHECK(g.label == NULL);
    CHECK(rs_grant_admits(&g, TOKEN_A, strlen(TOKEN_A), 4000000000LL));
    CHECK(!rs_grant_admits(&g, TOKEN_B, strlen(TOKEN_B), 0));
    rs_grant_free(&g);
    free(text);
    CHECK(parses("repository=/a\noperations=read\ntoken_sha256="
                 "C2C8B8D44E4C2C6A9F3A2BCF5D8B1A0F6E9D4C3B2A1F0E9D8C7B6A5F4E3D2C1B",
                 &why));
    CHECK(parses("repository = /srv/r\noperations = read ,append\ntoken_sha256 = "
                 "c2c8b8d44e4c2c6a9f3a2bcf5d8b1a0f6e9d4c3b2a1f0e9d8c7b6a5f4e3d2c1b\n",
                 &why));

    TEST_CASE("grant: every way one is refused");
    {
        static const struct {
            const char *extra;
            const char *says;
        } bad[] = {
            { "nonsense\n", "line 5: not \"key = value\"" },
            { "shade = red\n", "line 5: \"shade\" is not a key a grant has" },
            { "repository = /srv/other\n", "line 5: repository is given twice" },
            { "operations = read\n", "line 5: operations is given twice" },
            { "expires = \n", "line 5: expires has no value" },
            { "expires = tomorrow\n", "expires: not a time in UTC" },
            { "expires = 2026-12-31T00:00:00Z\nexpires = 2026-12-31T00:00:00Z\n",
              "line 6: expires is given twice" },
            { "label = a\nlabel = b\n", "line 6: label is given twice" },
            { "label = \x01\n", "label: more than 256 bytes, or not text" },
            { "label = \xff\xfe\n", "label: more than 256 bytes, or not text" },
            { "token_sha256 = abc\n", "token_sha256: not a SHA-256" },
            { "token_sha256 = "
              "zzc8b8d44e4c2c6a9f3a2bcf5d8b1a0f6e9d4c3b2a1f0e9d8c7b6a5f4e3d2c1b\n",
              "token_sha256: not a SHA-256" },
            { "= value\n", "line 5: \"\" is not a key a grant has" },
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            text = grant_text(bad[i].extra);
            CHECK(!parses(text, &why));
            CHECK_CONTAINS(why.data, bad[i].says);
            free(text);
        }
    }
    text = grant_text("");
    extra = rs_xasprintf("%stoken_sha256 = %s\n", text, hex_a);
    CHECK(!parses(extra, &why));
    CHECK_CONTAINS(why.data, "the same token is given twice");
    free(extra);
    extra = rs_xasprintf("%stoken_sha256 = %s\ntoken_sha256 = "
                         "c2c8b8d44e4c2c6a9f3a2bcf5d8b1a0f6e9d4c3b2a1f0e9d8c7b6a5f4e3d2c1b\n",
                         text, hex_b);
    CHECK(!parses(extra, &why));
    CHECK_CONTAINS(why.data, "line 6: token_sha256: given more than 2 times");
    free(extra);
    free(text);

    {
        char label[300];

        memset(label, 'x', sizeof(label) - 1);
        label[sizeof(label) - 1] = '\0';
        extra = rs_xasprintf("label = %s\n", label);
        text = grant_text(extra);
        CHECK(!parses(text, &why));
        CHECK_CONTAINS(why.data, "label: more than 256 bytes");
        free(text);
        free(extra);
        label[256] = '\0';
        extra = rs_xasprintf("label = %s\n", label);
        text = grant_text(extra);
        CHECK(parses(text, &why));
        free(text);
        free(extra);
    }

    TEST_CASE("grant: max_sessions");
    text = grant_text("");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_INT(g.max_sessions, 0);
    CHECK_INT((long long)rs_grant_rate(&g, 12), 0);
    rs_grant_free(&g);
    free(text);
    text = grant_text("max_sessions = 2\n");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_INT(g.max_sessions, 2);
    rs_grant_free(&g);
    free(text);
    text = grant_text("max_sessions = 1024\n");
    CHECK(parses(text, &why));
    free(text);
    {
        static const char *const bad[] = { "max_sessions = 0\n", "max_sessions = 1025\n",
                                           "max_sessions = 02\n", "max_sessions = two\n",
                                           "max_sessions = 99999\n",
                                           "max_sessions = 1\nmax_sessions = 2\n" };
        size_t                   i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            text = grant_text(bad[i]);
            CHECK(!parses(text, &why));
            CHECK_CONTAINS(why.data, "max_sessions");
            free(text);
        }
    }

    TEST_CASE("grant: rates");
    {
        uint64_t r = 1;

        CHECK(rs_grant_parse_rate("unlimited", 9, &r) && r == 0);
        CHECK(rs_grant_parse_rate("64KiB/s", 7, &r) && r == 65536);
        CHECK(rs_grant_parse_rate("2MiB/s", 6, &r) && r == 2097152);
        CHECK(rs_grant_parse_rate("1GiB/s", 6, &r) && r == 1073741824);
        CHECK(rs_grant_parse_rate("9999999GiB/s", 12, &r) && r == 9999999ULL << 30);
        CHECK(!rs_grant_parse_rate("63KiB/s", 7, &r));
        CHECK(!rs_grant_parse_rate("10000000GiB/s", 13, &r));
        CHECK(!rs_grant_parse_rate("2MiB", 4, &r));
        CHECK(!rs_grant_parse_rate("2MB/s", 5, &r));
        CHECK(!rs_grant_parse_rate("02MiB/s", 7, &r));
        CHECK(!rs_grant_parse_rate("MiB/s", 5, &r));
        CHECK(!rs_grant_parse_rate("", 0, &r));
        CHECK(!rs_grant_parse_rate("unlimited!", 10, &r));
    }

    TEST_CASE("grant: bandwidth by hour of the day");
    text = grant_text("bandwidth = 08-18 2MiB/s\nbandwidth = 20MiB/s\n"
                      "bandwidth = 22-02\tunlimited\n");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_INT((long long)rs_grant_rate(&g, 7), 20 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, 8), 2 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, 17), 2 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, 18), 20 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, 21), 20 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, 22), 0);
    CHECK_INT((long long)rs_grant_rate(&g, 23), 0);
    CHECK_INT((long long)rs_grant_rate(&g, 0), 0);
    CHECK_INT((long long)rs_grant_rate(&g, 1), 0);
    CHECK_INT((long long)rs_grant_rate(&g, 2), 20 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, -1), 0);
    CHECK_INT((long long)rs_grant_rate(&g, 24), 0);
    rs_grant_free(&g);
    free(text);
    /* The rate for every other hour first, the range after: the same. */
    text = grant_text("bandwidth = 1MiB/s\nbandwidth = 00-12 512KiB/s\n");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_INT((long long)rs_grant_rate(&g, 11), 512 << 10);
    CHECK_INT((long long)rs_grant_rate(&g, 12), 1 << 20);
    rs_grant_free(&g);
    free(text);
    /* A range alone: no limit outside it; and the whole day as one. */
    text = grant_text("bandwidth = 09-10 64KiB/s\n");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_INT((long long)rs_grant_rate(&g, 9), 65536);
    CHECK_INT((long long)rs_grant_rate(&g, 10), 0);
    rs_grant_free(&g);
    free(text);
    text = grant_text("bandwidth = 00-24 1MiB/s\n");
    CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
    CHECK_INT((long long)rs_grant_rate(&g, 0), 1 << 20);
    CHECK_INT((long long)rs_grant_rate(&g, 23), 1 << 20);
    rs_grant_free(&g);
    free(text);
    {
        static const struct {
            const char *extra;
            const char *says;
        } bad[] = {
            { "bandwidth = 1MiB/s\nbandwidth = 2MiB/s\n", "every other hour is given twice" },
            { "bandwidth = 08-18 1MiB/s\nbandwidth = 17-20 2MiB/s\n",
              "the hour from 17:00 is in two of its ranges" },
            { "bandwidth = 22-06 1MiB/s\nbandwidth = 05-07 2MiB/s\n",
              "the hour from 05:00 is in two of its ranges" },
            { "bandwidth = 08-08 1MiB/s\n", "not hours as HH-HH" },
            { "bandwidth = 24-02 1MiB/s\n", "not hours as HH-HH" },
            { "bandwidth = 08-25 1MiB/s\n", "not hours as HH-HH" },
            { "bandwidth = a8-18 1MiB/s\n", "not hours as HH-HH" },
            { "bandwidth = 08-1x 1MiB/s\n", "not hours as HH-HH" },
            { "bandwidth = 08-18 fast\n", "bandwidth: not a rate" },
            { "bandwidth = 8-18 1MiB/s\n", "bandwidth: not a rate" },
            { "bandwidth = 1KiB/s\n", "64KiB/s at the least" },
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            text = grant_text(bad[i].extra);
            CHECK(!parses(text, &why));
            CHECK_CONTAINS(why.data, bad[i].says);
            free(text);
        }
    }

    TEST_CASE("grant: operations");
    {
        static const struct {
            const char *ops;
            const char *says;
        } bad[] = {
            { "write", "\"write\" is not one; they are append and read" },
            { "append,", "\"\" is not one" },
            { ",read", "\"\" is not one" },
            { "read, read", "operations: read is given twice" },
            { "Append", "\"Append\" is not one" },
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            text = rs_xasprintf("repository = /r\noperations = %s\ntoken_sha256 = %s\n",
                                bad[i].ops, hex_a);
            CHECK(!parses(text, &why));
            CHECK_CONTAINS(why.data, bad[i].says);
            free(text);
        }
        text = rs_xasprintf("repository = /r\noperations = append\ntoken_sha256 = %s\n", hex_a);
        CHECK(rs_grant_parse("web01", text, strlen(text), &g, &why));
        CHECK_INT(g.operations, RS_GRANT_APPEND);
        rs_grant_free(&g);
        free(text);
    }

    TEST_CASE("grant: repositories");
    {
        static const char *const bad[] = { "srv/restate", "/", "/srv/restate/", "//srv",
                                           "/srv//restate", "/srv/./restate", "/srv/../etc",
                                           "/srv/restate/..", "/srv/\x01" };
        static const char *const good[] = { "/srv", "/srv/restate/web01", "/a/.b/..c/c..",
                                            "/srv/rest ate" };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            text = rs_xasprintf("repository = %s\noperations = read\ntoken_sha256 = %s\n",
                                bad[i], hex_a);
            CHECK(!parses(text, &why));
            CHECK_CONTAINS(why.data, "line 1: repository: not an absolute path");
            free(text);
        }
        for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        {
            text = rs_xasprintf("repository = %s\noperations = read\ntoken_sha256 = %s\n",
                                good[i], hex_a);
            CHECK(parses(text, &why));
            free(text);
        }
    }

    TEST_CASE("grant: what every grant has");
    CHECK(!parses("operations = read\n", &why));
    CHECK_CONTAINS(why.data, "it has no repository");
    CHECK(!parses("repository = /r\n", &why));
    CHECK_CONTAINS(why.data, "it has no operations");
    CHECK(!parses("repository = /r\noperations = read\n", &why));
    CHECK_CONTAINS(why.data, "it has no token_sha256");
    CHECK(!parses("", &why));
    CHECK(!parses("# nothing but a comment\n\n", &why));
    CHECK(!rs_grant_parse("web01", "repository = /r\0", 16, &g, &why));
    CHECK_CONTAINS(why.data, "NUL byte");
    text = grant_text("");
    CHECK(!rs_grant_parse(".web01", text, strlen(text), &g, &why));
    CHECK_CONTAINS(why.data, "not a client's name");
    free(text);

    rs_buf_free(&why);
}

static void test_files(void)
{
    char                    *dir = rs_test_tmpdir();
    char                    *grants = rs_xasprintf("%s/proxy.d", dir);
    char                    *text = grant_text("");
    char                    *path;
    struct rs_grant          g;
    struct rs_buf            why;
    struct rs_buf            out;
    struct rs_grant_checked *c = NULL;
    size_t                   n = 0;

    rs_buf_init(&why);
    rs_buf_init(&out);
    CHECK(mkdir(grants, 0755) == 0);
    rs_test_write(grants, "web01.conf", text, 0644);
    rs_test_write(grants, ".web02.conf.tmp", "half written", 0644);
    rs_test_write(grants, "README", "not a grant", 0644);
    rs_test_write(grants, "web03.conf", "repository = relative\n", 0644);
    rs_test_write(grants, "web04.conf", text, 0666);
    rs_test_write(grants, "bad name.conf", text, 0644);

    TEST_CASE("grant: a file");
    CHECK(rs_grant_load(grants, "web01.conf", &g, &why));
    CHECK_STR(g.client, "web01");
    rs_grant_free(&g);

    TEST_CASE("grant: a file refused");
    rs_buf_reset(&why);
    CHECK(!rs_grant_load(grants, "web03.conf", &g, &why));
    CHECK_CONTAINS(why.data, "/proxy.d/web03.conf: line 1: repository: not an absolute path");
    rs_buf_reset(&why);
    CHECK(!rs_grant_load(grants, "web04.conf", &g, &why));
    CHECK_CONTAINS(why.data, "writable by no one else");
    rs_buf_reset(&why);
    CHECK(!rs_grant_load(grants, "bad name.conf", &g, &why));
    CHECK_CONTAINS(why.data, "not a grant's name");
    rs_buf_reset(&why);
    CHECK(!rs_grant_load(grants, "web09.conf", &g, &why));
    CHECK_CONTAINS(why.data, "No such file");
    {
        char *target = rs_xasprintf("%s/web01.conf", grants);
        char *link = rs_xasprintf("%s/web05.conf", grants);

        CHECK(symlink(target, link) == 0);
        rs_buf_reset(&why);
        CHECK(!rs_grant_load(grants, "web05.conf", &g, &why));
        CHECK_CONTAINS(why.data, "a symlink; a grant has to be the file itself");
        free(target);
        free(link);
    }
    {
        char *big = rs_xmalloc(RS_GRANT_FILE_MAX + 2);

        memset(big, '#', RS_GRANT_FILE_MAX + 1);
        big[RS_GRANT_FILE_MAX + 1] = '\0';
        rs_test_write(grants, "web06.conf", big, 0644);
        rs_buf_reset(&why);
        CHECK(!rs_grant_load(grants, "web06.conf", &g, &why));
        CHECK_CONTAINS(why.data, "larger than a grant can be");
        free(big);
    }
    {
        char *sub = rs_xasprintf("%s/web07.conf", grants);

        CHECK(mkdir(sub, 0755) == 0);
        rs_buf_reset(&why);
        CHECK(!rs_grant_load(grants, "web07.conf", &g, &why));
        CHECK_CONTAINS(why.data, "has to be a regular file");
        free(sub);
    }
    CHECK(chmod(grants, 0777) == 0);
    rs_buf_reset(&why);
    CHECK(!rs_grant_load(grants, "web01.conf", &g, &why));
    CHECK_CONTAINS(why.data, "writable by no one else");
    CHECK(chmod(grants, 0755) == 0);

    TEST_CASE("grant: --check-grants");
    CHECK(rs_grants_check(grants, &c, &n, &why));
    /* web01 and web03 to web07, and "bad name": the dot file and README
     * passed over. */
    CHECK_INT((long long)n, 7);
    CHECK_STR(c[0].file, "bad name.conf");
    CHECK(c[0].client == NULL);
    CHECK(!c[0].ok);
    CHECK_STR(c[1].file, "web01.conf");
    CHECK_STR(c[1].client, "web01");
    CHECK(c[1].ok);
    CHECK(c[1].error == NULL);
    CHECK(!c[2].ok);
    rs_grants_report(c, n, false, &out);
    CHECK_CONTAINS(out.data, "web01.conf: ok\n");
    CHECK_CONTAINS(out.data, "web03.conf: line 1: repository: not an absolute path");
    CHECK(strstr(out.data, "README") == NULL);
    CHECK(strstr(out.data, "web02") == NULL);
    rs_buf_reset(&out);
    rs_grants_report(c, n, true, &out);
    CHECK_CONTAINS(out.data, "\"schema\": 1");
    CHECK_CONTAINS(out.data, "\"file\": \"web01.conf\"");
    CHECK_CONTAINS(out.data, "\"client\": \"web01\"");
    CHECK_CONTAINS(out.data, "\"ok\": true");
    CHECK_CONTAINS(out.data, "\"client\": null");
    CHECK_CONTAINS(out.data, "\"error\": null");
    rs_grants_checked_free(c, n);

    TEST_CASE("grant: the proxy's grants, good and not");
    {
        struct rs_grant *gs = NULL;
        size_t           ngs = 0;

        CHECK(rs_grants_load(grants, &gs, &ngs, &c, &n, &why));
        CHECK_INT((long long)ngs, 1);
        CHECK_INT((long long)n, 6);
        CHECK(rs_grants_find(gs, ngs, "web01") == &gs[0]);
        CHECK(rs_grants_find(gs, ngs, "web03") == NULL);
        CHECK(rs_grants_find(gs, ngs, NULL) == NULL);
        CHECK_STR(n == 6 ? c[0].file : NULL, "bad name.conf");
        CHECK(n == 6 && c[1].client && c[1].error && strcmp(c[1].client, "web03") == 0);
        rs_grants_free(gs, ngs);
        rs_grants_checked_free(c, n);
        path = rs_xasprintf("%s/missing", dir);
        rs_buf_reset(&why);
        CHECK(!rs_grants_load(path, &gs, &ngs, &c, &n, &why));
        CHECK_CONTAINS(why.data, "No such file");
        CHECK(gs == NULL && c == NULL && ngs == 0 && n == 0);
        free(path);
    }

    TEST_CASE("grant: --check-grants on an empty or missing directory");
    {
        char *none = rs_xasprintf("%s/empty", dir);

        CHECK(mkdir(none, 0755) == 0);
        CHECK(rs_grants_check(none, &c, &n, &why));
        CHECK_INT((long long)n, 0);
        rs_buf_reset(&out);
        rs_grants_report(c, n, true, &out);
        CHECK_CONTAINS(out.data, "\"grants\": []");
        rs_grants_checked_free(c, n);
        free(none);
    }
    rs_buf_reset(&why);
    path = rs_xasprintf("%s/missing", dir);
    CHECK(!rs_grants_check(path, &c, &n, &why));
    CHECK_CONTAINS(why.data, "No such file");
    CHECK(c == NULL);
    free(path);

    rs_buf_free(&why);
    rs_buf_free(&out);
    free(text);
    free(grants);
    rs_test_rmtree(dir);
    free(dir);
}

void test_grant(void)
{
    rs_sha256_hex(TOKEN_A, strlen(TOKEN_A), hex_a);
    rs_sha256_hex(TOKEN_B, strlen(TOKEN_B), hex_b);
    test_tokens();
    test_times();
    test_names();
    test_parsing();
    test_files();
}
