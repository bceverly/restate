/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <unistd.h>

#include "image.h"
#include "index.h"
#include "test.h"

#define HASH_A "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define HEAD   "{\"format\": \"restate-index\", \"version\": 1, \"entries\": ["
#define TAIL   "]}"
/* A minimal valid entry, with one field substituted by the rejection table. */
#define ENTRY(path, type, mode, extra)                                          \
    "{\"path\": " path ", \"type\": " type ", \"class\": \"state\", \"mode\": " \
    mode ", \"uid\": 0, \"gid\": 0, \"size\": 0, "                              \
    "\"mtime\": \"2026-10-03T00:00:00.000000000Z\"" extra "}"

static bool parse(struct rs_index *ix, const char *text, struct rs_buf *err)
{
    rs_index_free(ix);
    rs_buf_reset(err);
    return rs_index_parse(ix, text, strlen(text), "ix", err);
}

static const char *const bad_entries[][2] = {
    { ENTRY("\"a\"", "\"file\"", "\"0644\"", ""), "not a clean absolute path" },
    { ENTRY("\"/a/../b\"", "\"file\"", "\"0644\"", ""), "not a clean absolute path" },
    { ENTRY("1", "\"file\"", "\"0644\"", ""), "bad \"path\"" },
    { ENTRY("\"/a\"", "\"socket\"", "\"0644\"", ""), "unknown \"type\"" },
    { ENTRY("\"/a\"", "\"file\"", "\"0648\"", ""), "bad \"mode\"" },
    { ENTRY("\"/a\"", "\"file\"", "\"17777\"", ""), "bad \"mode\"" },
    { ENTRY("\"/a\"", "\"file\"", "420", ""), "bad \"mode\"" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"uid\": -1"), "duplicate key" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"nlink\": -1"), "a bad number" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"atime\": \"yesterday\""), "a bad timestamp" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"sha256\": \"abc\""), "a bad \"sha256\"" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"sha256\": 5"), "a bad \"sha256\"" },
    { ENTRY("\"/a\"", "\"directory\"", "\"0755\"", ", \"sha256\": \"" HASH_A "\""),
      "a digest on something" },
    { ENTRY("\"/a\"", "\"symlink\"", "\"0777\"", ""), "a symlink without" },
    { ENTRY("\"/a\"", "\"symlink\"", "\"0777\"", ", \"target\": \"\""), "a symlink without" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"path_base64\": \"!!!!\""), "bad \"path\"" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"path_base64\": \"AA==\""), "bad \"path\"" },
    { ENTRY("\"/a\"", "\"file\"", "\"0644\"", ", \"user\": 7"), "a bad \"user\"" },
    { "7", "an entry is not an object" },
};

void test_index(void)
{
    struct rs_index ix;
    struct rs_buf   err;
    size_t          i;

    rs_index_init(&ix);
    rs_buf_init(&err);

    TEST_CASE("index: what counts as a clean path");
    CHECK(rs_path_is_clean("/"));
    CHECK(rs_path_is_clean("/etc/ssh/sshd_config"));
    CHECK(rs_path_is_clean("/a/.hidden/..x/x.."));
    CHECK(!rs_path_is_clean(""));
    CHECK(!rs_path_is_clean("etc"));
    CHECK(!rs_path_is_clean("//etc"));
    CHECK(!rs_path_is_clean("/etc/"));
    CHECK(!rs_path_is_clean("/./etc"));
    CHECK(!rs_path_is_clean("/etc/.."));

    TEST_CASE("index: type names");
    {
        char t = 0;

        CHECK_STR(rs_type_name('d'), "directory");
        CHECK_STR(rs_type_name('?'), "?");
        CHECK(rs_type_parse("fifo", &t) && t == 'p');
        CHECK(!rs_type_parse("door", &t));
    }

    TEST_CASE("index: escaping for display");
    {
        struct rs_buf b;

        rs_buf_init(&b);
        rs_escape(&b, "a\tb\nc\\d\re\x01\x7f" "f \xc3\xa9");
        CHECK_STR(b.data, "a\\tb\\nc\\\\d\\re\\x01\\x7ff \xc3\xa9");
        rs_buf_free(&b);
        rs_escape(&b, "");
        CHECK_STR(b.data, "");
        rs_buf_free(&b);
    }

    TEST_CASE("index: a full index parses, sorted, with every field");
    CHECK(parse(&ix, "{\"format\": \"restate-index\", \"version\": 1, \"restate\": \"9.9\", "
                     "\"root\": \"/mnt/old\", \"os\": \"linux\", \"host\": \"web\", "
                     "\"created\": \"2026-10-03T00:00:00.000000000Z\", \"hash\": \"sha256\", "
                     "\"hashed\": true, \"content\": \"state\", \"count\": 3, \"future\": [1, {}], "
                     "\"entries\": ["
                     ENTRY("\"/etc/b\"", "\"file\"", "\"0644\"",
                           ", \"sha256\": \"" HASH_A "\", \"user\": \"root\", \"group\": null, "
                           "\"nlink\": 2, \"device\": 9, \"inode\": 99, "
                           "\"atime\": \"@-1.000000000\", \"btime\": null, "
                           "\"stored\": \"restate/files/etc/b\"")
                     ", " ENTRY("\"/\"", "\"directory\"", "\"0755\"", "")
                     ", " ENTRY("\"x\"", "\"symlink\"", "\"0777\"",
                                ", \"path_base64\": \"L2V0Yy9h/w==\", \"target\": \"t\"")
                     ", " ENTRY("\"/dev/null\"", "\"char\"", "\"0666\"", ", \"rdev\": 259")
                     ", " ENTRY("\"/etc/c\"", "\"file\"", "\"0600\"",
                                ", \"sha256\": null, \"unreadable\": true")
                     "]}", &err));
    CHECK_STR(err.data ? err.data : "", "");
    CHECK_INT(ix.count, 5);
    CHECK_STR(ix.root, "/mnt/old");
    CHECK_STR(ix.version, "9.9");
    CHECK_STR(ix.content, "state");
    CHECK(ix.hashed);
    CHECK_STR(ix.entries[0].path, "/");
    CHECK_STR(ix.entries[2].path, "/etc/a\xff");
    CHECK_STR(ix.entries[2].target, "t");
    CHECK_INT(ix.entries[3].hash_state, RS_HASH_PRESENT);
    CHECK_STR(ix.entries[3].user, "root");
    CHECK(ix.entries[3].group == NULL);
    CHECK_INT(ix.entries[3].nlink, 2);
    CHECK_INT(ix.entries[3].atime.sec, -1);
    CHECK(!ix.entries[3].btime.set);
    CHECK_STR(ix.entries[3].stored, "restate/files/etc/b");
    CHECK_INT(ix.entries[4].hash_state, RS_HASH_UNREADABLE);
    CHECK_INT(ix.entries[1].rdev, 259);
    CHECK(rs_index_find(&ix, "/etc/c") == &ix.entries[4]);
    CHECK(rs_index_find(&ix, "/zzz") == NULL);

    TEST_CASE("index: writing and reading back is lossless, odd bytes and all");
    {
        char           *dir = rs_test_tmpdir();
        char           *path = rs_xasprintf("%s/ix.json", dir);
        FILE           *fp = fopen(path, "w");
        struct rs_index back;

        free(ix.host);
        ix.host = rs_xstrdup("h\x01\xff");
        CHECK(fp != NULL);
        if (fp)
        {
            CHECK(rs_index_write(&ix, fp));
            (void)fclose(fp);
        }
        rs_index_init(&back);
        rs_buf_reset(&err);
        CHECK(rs_index_load(&back, path, &err));
        CHECK_STR(err.data ? err.data : "", "");
        CHECK_INT(back.count, ix.count);
        for (i = 0; i < ix.count && i < back.count; i++)
        {
            const struct rs_entry *a = &ix.entries[i];
            const struct rs_entry *b = &back.entries[i];

            CHECK_STR(b->path, a->path);
            CHECK_INT(b->type, a->type);
            CHECK_INT(b->mode, a->mode);
            CHECK(rs_time_equal(&b->mtime, &a->mtime));
            CHECK(rs_time_equal(&b->atime, &a->atime));
            CHECK_INT(b->hash_state, a->hash_state);
            CHECK_INT(b->rdev, a->rdev);
        }
        /* The host is not a path, so it goes through lossily. */
        CHECK_STR(back.host, "h\x01\xef\xbf\xbd");
        rs_index_free(&back);
        rs_buf_reset(&err);
        CHECK(!rs_index_load(&back, "/nonexistent/ix.json", &err));
        CHECK_CONTAINS(err.data, "/nonexistent/ix.json");
        rs_index_free(&back);
        rs_test_rmtree(dir);
        free(path);
        free(dir);
    }

    TEST_CASE("index: an empty index");
    CHECK(parse(&ix, HEAD TAIL, &err));
    CHECK_INT(ix.count, 0);
    CHECK(!ix.hashed);

    TEST_CASE("index: refusing what is not one");
    CHECK(!parse(&ix, "", &err));
    CHECK_CONTAINS(err.data, "not a restate index");
    CHECK(!parse(&ix, "[]", &err));
    CHECK_CONTAINS(err.data, "not a restate index");
    CHECK(!parse(&ix, "{}", &err));
    CHECK_CONTAINS(err.data, "not a restate index");
    CHECK(!parse(&ix, "{\"format\": \"restate-index\"}", &err));
    CHECK_CONTAINS(err.data, "no \"entries\"");
    CHECK(!parse(&ix, "{\"format\": \"other\", \"entries\": []}", &err));
    CHECK_CONTAINS(err.data, "not a restate index");
    CHECK(!parse(&ix, "{\"format\": \"restate-index\", \"version\": 2, \"entries\": []}", &err));
    CHECK_CONTAINS(err.data, "index version 2");
    CHECK(!parse(&ix, "{\"format\": \"restate-index\", \"root\": 5, \"entries\": []}", &err));
    CHECK_CONTAINS(err.data, "\"root\" is not a string");
    CHECK(!parse(&ix, HEAD TAIL " x", &err));
    CHECK_CONTAINS(err.data, "data after the index");
    CHECK(!parse(&ix, "{\"format\": \"restate-index\", \"entries\": [], \"entries\": []}", &err));
    CHECK_CONTAINS(err.data, "duplicate key");
    CHECK(!parse(&ix, HEAD "1," TAIL, &err));
    CHECK(!parse(&ix, "{\"format\": \"restate-index\", \"entries\": [}", &err));
    CHECK(!parse(&ix, HEAD ENTRY("\"/a\"", "\"file\"", "\"0644\"", "") ", " ENTRY("\"/a\"", "\"file\"", "\"0644\"", "") TAIL, &err));
    CHECK_CONTAINS(err.data, "/a appears more than once");
    for (i = 0; i < sizeof(bad_entries) / sizeof(bad_entries[0]); i++)
    {
        char *text = rs_xasprintf("%s%s%s", HEAD, bad_entries[i][0], TAIL);

        rs_test_case = bad_entries[i][1];
        CHECK(!parse(&ix, text, &err));
        CHECK_CONTAINS(err.data, bad_entries[i][1]);
        free(text);
    }

    rs_index_free(&ix);
    rs_buf_free(&err);
}
