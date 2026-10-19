/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <sys/stat.h>

#include "clones.h"
#include "test.h"

/* Parses `text`; on failure, what was said, in `why` (freed by the caller). */
static bool parse(struct rs_clones *c, const char *text, char **why)
{
    struct rs_buf err;
    bool          ok;

    rs_buf_init(&err);
    ok = rs_clones_parse(c, text, strlen(text), "c.csv", &err);
    *why = err.data ? rs_buf_detach(&err) : rs_xstrdup("");
    return ok;
}

/* Whether `text` is refused, saying `needle`. */
static void refused(const char *text, const char *needle)
{
    struct rs_clones c;
    char            *why;

    CHECK(!parse(&c, text, &why));
    CHECK_CONTAINS(why, needle);
    CHECK_INT(c.count, 0);
    free(why);
    rs_clones_free(&c);
}

static void good(void)
{
    struct rs_clones c;
    char            *why;

    TEST_CASE("clones: a list of copies, every column");
    CHECK(parse(&c,
                "# the lab\n"
                "\n"
                "name, mac ,serial,address,gateway,dns\r\n"
                "web1,52:54:00:AB:cd:01,,10.0.0.11/24,10.0.0.1,10.0.0.2 10.0.0.3;10.0.0.4\n"
                "  # a copy left for later\n"
                "web2,52-54-00-00-00-02,S4EW-2.x_y,fd00::12/64,fd00::1,\n"
                "web3,,SER3,,,\n",
                &why));
    CHECK_STR(why, "");
    free(why);
    CHECK_INT(c.count, 3);
    if (c.count == 3)
    {
        CHECK_STR(c.items[0].name, "web1");
        CHECK_STR(c.items[0].mac, "52:54:00:ab:cd:01");
        CHECK(c.items[0].serial == NULL);
        CHECK_STR(c.items[0].address, "10.0.0.11/24");
        CHECK_STR(c.items[0].gateway, "10.0.0.1");
        CHECK_INT(c.items[0].ndns, 3);
        CHECK_STR(c.items[0].dns[2], "10.0.0.4");
        CHECK_STR(c.items[1].mac, "52:54:00:00:00:02");
        CHECK_STR(c.items[1].serial, "S4EW-2.x_y");
        CHECK_STR(c.items[1].address, "fd00::12/64");
        CHECK(c.items[2].mac == NULL && c.items[2].address == NULL && c.items[2].ndns == 0);
    }
    rs_clones_free(&c);

    TEST_CASE("clones: only the columns needed, hostname for name");
    CHECK(parse(&c, "serial,hostname\nA1,a\nB2,b", &why));
    CHECK_INT(c.count, 2);
    CHECK_STR(c.count == 2 ? c.items[1].name : NULL, "b");
    free(why);
    rs_clones_free(&c);
}

static void bad(void)
{
    TEST_CASE("clones: what is refused, and where");
    refused("", "c.csv: no header, and no copies");
    refused("# only a comment\n", "no header");
    refused("name,mac\n", "c.csv: no copies, only the header");
    refused("name,mac,shade\nweb1,52:54:00:00:00:01,red\n", "c.csv:1: a column that is not");
    refused("name,mac,name\n", "a column named twice");
    refused("name,address\nweb1,10.0.0.1/24\n", "a mac or serial column");
    refused("mac,serial\n52:54:00:00:00:01,x\n", "a name column");
    refused("name,mac,serial,address,gateway,dns,x\n", "more columns than");
    refused("name,mac\nweb1\n", "c.csv:2: a different number of fields");
    refused("name,mac\n\"web1\",52:54:00:00:00:01\n", "a quote");
    refused("name,mac\nweb1,52:54:00:00:00:01\n'x',y\n", "c.csv:3: a quote");
    {
        static const char nul[] = "name,mac\nweb\0,52:54:00:00:00:01\n";
        struct rs_clones  c;
        struct rs_buf     err;

        rs_buf_init(&err);
        CHECK(!rs_clones_parse(&c, nul, sizeof(nul) - 1, "c.csv", &err));
        CHECK_CONTAINS(err.data, "a NUL byte");
        rs_buf_free(&err);
    }
    refused("name,mac\nweb_1,52:54:00:00:00:01\n", "not a host name");
    refused("name,mac\n,52:54:00:00:00:01\n", "a copy with no name");
    refused("name,mac\nweb1,52:54:00:00:00\n", "six pairs of hex digits");
    refused("name,mac\nweb1,52:54:00:00:00:0g\n", "six pairs of hex digits");
    refused("name,mac\nweb1,52:54:00.00:00:01\n", "six pairs of hex digits");
    refused("name,serial\nweb1,has space\n", "a disk serial of other than");
    refused("name,serial\nweb1,"
            "12345678901234567890123456789012345678901234567890123456789012345\n",
            "a disk serial of other than");
    refused("name,mac,serial\nweb1,,\n", "neither a MAC address nor a disk serial");
    refused("name,serial,address\nweb1,A,10.0.0.1\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,10.0.0.1/33\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,10.0.0.1/0\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,10.0.0.1/024\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,10.0.0.1/2x\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,10.0.0.1/\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,fd00::1/129\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,10.0.0.256/24\n", "ADDRESS/PREFIX");
    refused("name,serial,address\nweb1,A,"
            "1111:2222:3333:4444:5555:6666:7777:8888:9999:aaaa/64\n",
            "ADDRESS/PREFIX");
    refused("name,serial,address,gateway\nweb1,A,10.0.0.2/24,10.0.0\n", "a gateway that is not");
    refused("name,serial,gateway\nweb1,A,10.0.0.1\n", "a gateway with no address");
    refused("name,serial,dns\nweb1,A,10.0.0.1 nameserver\n", "a name server that is not");
    refused("name,serial,dns\nweb1,A,1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 "
            "1.1.1.8 1.1.1.9\n",
            "more name servers");
    refused("name,mac\nweb1,52:54:00:00:00:01\nweb1,52:54:00:00:00:02\n",
            "c.csv:3: a name given to another copy");
    refused("name,mac\nweb1,52:54:00:00:00:01\nweb2,52:54:00:00:00:01\n", "a MAC address given");
    refused("name,serial\nweb1,A\nweb2,A\n", "a disk serial given");
    refused("name,serial,address\nweb1,A,10.0.0.1/24\nweb2,B,10.0.0.1/16\n", "an address given");
}

static void files(void)
{
    char            *dir = rs_test_tmpdir();
    char            *path = rs_xasprintf("%s/c.csv", dir);
    struct rs_clones c;
    struct rs_buf    err;

    TEST_CASE("clones: read from a file");
    rs_test_write(dir, "c.csv", "name,serial\nweb1,A\n", 0644);
    rs_buf_init(&err);
    CHECK(rs_clones_load_file(&c, path, &err));
    CHECK_INT(c.count, 1);
    rs_clones_free(&c);
    rs_buf_free(&err);

    TEST_CASE("clones: a file that is not there, a directory, one too large");
    rs_buf_init(&err);
    CHECK(!rs_clones_load_file(&c, "/nonexistent/c.csv", &err));
    CHECK_CONTAINS(err.data, "/nonexistent/c.csv");
    rs_buf_reset(&err);
    CHECK(!rs_clones_load_file(&c, dir, &err));
    CHECK_CONTAINS(err.data, "not a regular file");
    rs_buf_reset(&err);
    {
        size_t n = 1100 * 1024;
        char  *big = rs_xmalloc(n + 1);

        memset(big, '#', n);
        big[n] = '\0';
        rs_test_write(dir, "big.csv", big, 0644);
        free(big);
        free(path);
        path = rs_xasprintf("%s/big.csv", dir);
        CHECK(!rs_clones_load_file(&c, path, &err));
        CHECK_CONTAINS(err.data, "larger than");
    }
    rs_buf_free(&err);
    free(path);
    rs_test_rmtree(dir);
    free(dir);
}

void test_clones(void)
{
    good();
    bad();
    files();
}
