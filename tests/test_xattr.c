/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "diff.h"
#include "index.h"
#include "test.h"
#include "xattr.h"

static unsigned long plus_one(const void *ctx, unsigned long id)
{
    (void)ctx;
    return id + 1;
}

static unsigned long times_ten(const void *ctx, unsigned long id)
{
    (void)ctx;
    return id * 10;
}

/* An index of one entry, written out and parsed back. */
static bool round_trip(const struct rs_entry *e, struct rs_index *back, struct rs_buf *text)
{
    struct rs_index ix;
    struct rs_entry copy = *e;
    struct rs_buf   err;
    FILE           *fp = tmpfile();
    bool            ok;

    rs_index_init(&ix);
    rs_index_add(&ix, &copy);
    rs_buf_init(text);
    if (fp)
    {
        char   chunk[4096];
        size_t n;

        (void)rs_index_write(&ix, fp);
        rewind(fp);
        while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
        {
            rs_buf_add(text, chunk, n);
        }
        (void)fclose(fp);
    }
    rs_buf_add(text, "", 0);
    /* The strings belong to the caller's entry. */
    ix.count = 0;
    rs_index_free(&ix);
    rs_buf_init(&err);
    rs_index_init(back);
    ok = rs_index_parse(back, text->data, text->len, "test", &err);
    rs_buf_free(&err);
    return ok;
}

void test_xattr(void)
{
    char            *dir = rs_test_tmpdir();
    struct rs_xattr *got = NULL;
    size_t           n = 0;

    TEST_CASE("xattr: what is kept, and what describes the machine instead");
    CHECK(rs_xattr_kept("user.color"));
    CHECK(rs_xattr_kept("security.capability"));
    CHECK(rs_xattr_kept("system.posix_acl_access"));
    CHECK(rs_xattr_kept("com.apple.quarantine"));
    CHECK(!rs_xattr_kept("security.selinux"));
    CHECK(!rs_xattr_kept("security.SMACK64EXEC"));
    CHECK(!rs_xattr_kept("security.ima"));
    CHECK(!rs_xattr_kept(""));
    CHECK(rs_xattr_is_acl("system.posix_acl_default"));
    CHECK(!rs_xattr_is_acl("user.x"));

    TEST_CASE("xattr: an ACL's named users and groups mapped, nobody else");
    {
        /* version 2; USER_OBJ, USER 1000, GROUP_OBJ, GROUP 50, MASK, OTHER */
        unsigned char acl[] = {
            2, 0, 0, 0,
            0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
            0x02, 0, 4, 0, 0xe8, 0x03, 0, 0,
            0x04, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
            0x08, 0, 5, 0, 50, 0, 0, 0,
            0x10, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
            0x20, 0, 4, 0, 0xff, 0xff, 0xff, 0xff,
        };
        unsigned char bad[] = { 1, 0, 0, 0, 0x02, 0, 4, 0, 1, 0, 0, 0 };

        CHECK(rs_xattr_map_acl(acl, sizeof(acl), plus_one, times_ten, NULL));
        CHECK_INT(acl[12 + 4] | (acl[12 + 5] << 8), 1001);
        CHECK_INT(acl[28 + 4], 244);   /* 500, little-endian: 0x01f4 */
        CHECK_INT(acl[28 + 5], 1);
        CHECK_INT(acl[4 + 4], 0xff);   /* USER_OBJ's id is not an id */
        CHECK(!rs_xattr_map_acl(bad, sizeof(bad), plus_one, times_ten, NULL));
        CHECK(!rs_xattr_map_acl(acl, 7, plus_one, times_ten, NULL));
        CHECK(!rs_xattr_map_acl(acl, 2, plus_one, times_ten, NULL));
    }

    TEST_CASE("xattr: set, read back, sorted, and the machine's own left alone");
    rs_test_write(dir, "f", "x", 0644);
    {
        char           *path = rs_xasprintf("%s/f", dir);
        struct rs_xattr set[3];
        size_t          failed;
        int             fd = open(path, O_RDONLY);

        CHECK(fd >= 0);
        set[0].name = (char *)(uintptr_t)"user.zebra";
        set[0].value = (unsigned char *)(uintptr_t)"z\0z";
        set[0].len = 3;
        set[1].name = (char *)(uintptr_t)"user.apple";
        set[1].value = (unsigned char *)(uintptr_t)"";
        set[1].len = 0;
        set[2].name = (char *)(uintptr_t)"security.selinux";
        set[2].value = (unsigned char *)(uintptr_t)"label";
        set[2].len = 5;
        failed = rs_xattr_write(fd, set, 3);
        /* The label is never set; the others where this filesystem allows. */
        CHECK(failed >= 1);
        CHECK(rs_xattr_read(fd, &got, &n));
        if (failed == 1)
        {
            CHECK_INT(n, 2);
            CHECK_STR(n == 2 ? got[0].name : "", "user.apple");
            CHECK(n == 2 && got[1].len == 3 && memcmp(got[1].value, "z\0z", 3) == 0);
        }
        rs_xattr_free(got, n);
        (void)close(fd);
        free(path);
        CHECK(!rs_xattr_read(-1, &got, &n) || n == 0);
    }

    TEST_CASE("index: xattrs written and read back, and diffed");
    {
        struct rs_entry  e;
        struct rs_index  back;
        struct rs_buf    text;
        struct rs_xattr *x = rs_xcalloc(2, sizeof(*x));

        memset(&e, 0, sizeof(e));
        e.path = rs_xstrdup("/etc/f");
        e.type = 'f';
        e.mode = 0644;
        e.mtime.set = true;
        x[0].name = rs_xstrdup("user.a\xff");
        x[0].value = rs_xmalloc(3);
        memcpy(x[0].value, "\0\1\2", 3);
        x[0].len = 3;
        x[1].name = rs_xstrdup("user.b");
        x[1].value = rs_xmalloc(1);
        x[1].len = 0;
        e.xattrs = x;
        e.nxattrs = 2;
        CHECK(round_trip(&e, &back, &text));
        CHECK_CONTAINS(text.data, "\"xattrs\": [{\"name\": ");
        CHECK_CONTAINS(text.data, "\"name_base64\": \"dXNlci5h/w==\", \"value\": \"AAEC\"}");
        CHECK_INT(back.count, 1);
        if (back.count == 1)
        {
            const struct rs_entry *b = &back.entries[0];

            CHECK_INT(b->nxattrs, 2);
            CHECK(b->nxattrs == 2 && strcmp(b->xattrs[0].name, "user.a\xff") == 0 &&
                  b->xattrs[0].len == 3 && memcmp(b->xattrs[0].value, "\0\1\2", 3) == 0);
            CHECK(b->nxattrs == 2 && b->xattrs[1].len == 0);
            CHECK_INT(rs_diff_entries(&e, b), 0);
            e.xattrs[0].value[2] = 9;
            CHECK(rs_diff_entries(&e, b) & RS_DIFF_XATTRS);
            e.nxattrs = 1;
            CHECK(rs_diff_entries(&e, b) & RS_DIFF_XATTRS);
            e.nxattrs = 2;
            free(e.xattrs[1].name);
            e.xattrs[1].name = rs_xstrdup("user.c");
            CHECK(rs_diff_entries(&e, b) & RS_DIFF_XATTRS);
        }
        {
            struct rs_buf described;

            rs_buf_init(&described);
            rs_diff_describe(RS_DIFF_XATTRS | RS_DIFF_MODE, &described);
            CHECK_STR(described.data, "mode,xattrs");
            rs_buf_free(&described);
        }
        rs_index_free(&back);
        rs_buf_free(&text);
        rs_entry_free(&e);
    }

    TEST_CASE("index: xattrs that are not what restate writes");
    {
        static const char *const bad[] = {
            "\"xattrs\": {}",
            "\"xattrs\": [1]",
            "\"xattrs\": [{\"name\": \"user.a\"}]",
            "\"xattrs\": [{\"value\": \"AA==\"}]",
            "\"xattrs\": [{\"name\": \"user.a\", \"value\": \"!!\"}]",
            "\"xattrs\": [{\"name\": 7, \"value\": \"AA==\"}]",
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            struct rs_index ix;
            struct rs_buf   err;
            char           *text = rs_xasprintf(
                "{\"format\": \"restate-index\", \"version\": 1, \"entries\": [\n"
                "{\"path\": \"/\", \"type\": \"directory\", \"class\": \"state\", \"mode\": "
                "\"0755\", \"uid\": 0, \"gid\": 0, \"size\": 0, \"mtime\": "
                "\"2026-01-01T00:00:00.000000000Z\", %s}\n]}",
                bad[i]);

            rs_index_init(&ix);
            rs_buf_init(&err);
            CHECK(!rs_index_parse(&ix, text, strlen(text), "test", &err));
            CHECK_CONTAINS(err.data ? err.data : "", "xattrs");
            rs_index_free(&ix);
            rs_buf_free(&err);
            free(text);
        }
    }
    {
        /* On a symlink: refused. */
        struct rs_index ix;
        struct rs_buf   err;
        const char     *text =
            "{\"format\": \"restate-index\", \"version\": 1, \"entries\": [\n"
            "{\"path\": \"/l\", \"type\": \"symlink\", \"target\": \"x\", \"class\": \"state\", "
            "\"mode\": \"0777\", \"uid\": 0, \"gid\": 0, \"size\": 1, \"mtime\": "
            "\"2026-01-01T00:00:00.000000000Z\", \"xattrs\": []}\n]}";

        rs_index_init(&ix);
        rs_buf_init(&err);
        CHECK(!rs_index_parse(&ix, text, strlen(text), "test", &err));
        rs_index_free(&ix);
        rs_buf_free(&err);
    }

    rs_test_rmtree(dir);
    free(dir);
}
