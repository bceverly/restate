/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "meta.h"
#include "test.h"

static void round_trip(int64_t sec, int32_t nsec, const char *want)
{
    struct rs_time t = { sec, nsec, true };
    struct rs_time back;
    char           s[RS_TIME_STR_MAX];

    rs_time_format(&t, s);
    CHECK_STR(s, want);
    CHECK(rs_time_parse(s, &back));
    CHECK(rs_time_equal(&t, &back));
}

void test_meta(void)
{
    struct rs_time t;
    struct rs_time u;

    TEST_CASE("meta: timestamps format and parse back exactly");
    round_trip(0, 0, "1970-01-01T00:00:00.000000000Z");
    round_trip(1700000000, 123456789, "2023-11-14T22:13:20.123456789Z");
    round_trip(951782400, 0, "2000-02-29T00:00:00.000000000Z");
    round_trip(-1, 999999999, "1969-12-31T23:59:59.999999999Z");
    round_trip(-62167219200LL, 0, "0000-01-01T00:00:00.000000000Z");
    round_trip(253402300799LL, 5, "9999-12-31T23:59:59.000000005Z");
    round_trip(253402300800LL, 7, "@253402300800.000000007");
    round_trip(-62167219201LL, 0, "@-62167219201.000000000");

    TEST_CASE("meta: malformed timestamps are refused");
    CHECK(!rs_time_parse("", &t));
    CHECK(!rs_time_parse("2023-11-14T22:13:20Z", &t));
    CHECK(!rs_time_parse("2023-13-14T22:13:20.000000000Z", &t));
    CHECK(!rs_time_parse("2023-02-30T22:13:20.000000000Z", &t));
    CHECK(!rs_time_parse("2023-02-29T22:13:20.000000000Z", &t));
    CHECK(!rs_time_parse("1900-02-29T00:00:00.000000000Z", &t));
    CHECK(rs_time_parse("2024-02-29T00:00:00.000000000Z", &t));
    CHECK(!rs_time_parse("2023-11-14T24:13:20.000000000Z", &t));
    CHECK(!rs_time_parse("2023-11-14T22:60:20.000000000Z", &t));
    CHECK(!rs_time_parse("2023-11-14T22:13:60.000000000Z", &t));
    CHECK(!rs_time_parse("2023-11-14 22:13:20.000000000Z", &t));
    CHECK(!rs_time_parse("2023-11-14T22:13:20.00000000xZ", &t));
    CHECK(!rs_time_parse("@", &t));
    CHECK(!rs_time_parse("@12", &t));
    CHECK(!rs_time_parse("@12.1", &t));
    CHECK(!rs_time_parse("@12.0000000001", &t));
    CHECK(!rs_time_parse("@1234567890123456789.000000000", &t));
    CHECK(rs_time_parse("@-5.000000001", &t) && t.sec == -5 && t.nsec == 1);

    TEST_CASE("meta: time equality respects 'unknown'");
    memset(&t, 0, sizeof(t));
    memset(&u, 0, sizeof(u));
    CHECK(rs_time_equal(&t, &u));
    u.set = true;
    CHECK(!rs_time_equal(&t, &u));
    t.set = true;
    t.nsec = 1;
    CHECK(!rs_time_equal(&t, &u));

    TEST_CASE("meta: a real file's times, birth time included where kept");
    {
        char          *dir = rs_test_tmpdir();
        struct stat    st;
        struct rs_time a;
        struct rs_time m;
        struct rs_time c;
        struct rs_time b;
        int            dirfd;

        rs_test_write(dir, "f", "x", 0644);
        dirfd = open(dir, O_RDONLY);
        CHECK(dirfd >= 0);
        CHECK(fstatat(dirfd, "f", &st, AT_SYMLINK_NOFOLLOW) == 0);
        rs_stat_times(&st, &a, &m, &c);
        CHECK(a.set && m.set && c.set);
        CHECK(m.sec == (int64_t)st.st_mtime);
        CHECK(m.nsec >= 0 && m.nsec < 1000000000);
        rs_birth_time_at(dirfd, "f", &st, &b);
        /* Whether the filesystem keeps one is its business; if it does, the
         * file cannot have been born after it was last changed. */
        if (b.set)
        {
            CHECK(b.sec <= c.sec);
        }
        rs_birth_time_at(dirfd, "missing", &st, &b);
        (void)close(dirfd);
        rs_test_rmtree(dir);
        free(dir);
    }

    TEST_CASE("meta: names behind ids, cached");
    {
        const char *root = rs_user_name(0);
        const char *again = rs_user_name(0);
        const char *group = rs_group_name(0);

        CHECK(root != NULL);
        CHECK(root == again);
        CHECK(group != NULL);
        CHECK(rs_user_name(4000000000u) == NULL);
        CHECK(rs_user_name(4000000000u) == NULL);
        CHECK(rs_group_name(4000000000u) == NULL);
        rs_name_cache_free();
        CHECK(rs_user_name(0) != NULL);
        rs_name_cache_free();
    }
}
