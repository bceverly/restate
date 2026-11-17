/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "acl.h"
#include "test.h"

/* `text` parsed and written again. */
static char *again(const char *text)
{
    struct rs_ace *aces;
    size_t         n;
    struct rs_buf  b;

    if (!rs_acl_parse(text, &aces, &n))
    {
        return NULL;
    }
    rs_buf_init(&b);
    rs_acl_format(aces, n, &b);
    rs_acl_free(aces, n);
    return rs_buf_detach(&b);
}

static bool parses(const char *text)
{
    struct rs_ace *aces;
    size_t         n;
    bool           ok = rs_acl_parse(text, &aces, &n);

    rs_acl_free(aces, n);
    return ok;
}

/* Every user and group given the number 7000 more than it had, and the
 * group "staff" 20, as merged accounts would. */
static void shift(const void *ctx, bool group, const char *name, uint64_t *id)
{
    (void)ctx;
    if (group && name && strcmp(name, "staff") == 0)
    {
        *id = 20;
        return;
    }
    *id += 7000;
}

void test_acl(void)
{
    static const char full[] =
        "owner@::read_data/write_data/append_data/read_xattr/write_xattr/execute/"
        "delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/"
        "write_owner/synchronize:file_inherit/dir_inherit/inherit_only/no_propagate/"
        "successful_access/failed_access/inherited:allow";
    struct rs_ace *aces;
    size_t         n;
    char          *text;
    char          *dir = rs_test_tmpdir();
    char          *path = rs_xasprintf("%s/f", dir);
    int            fd;

    TEST_CASE("acl: text, as it is written and read back");
    text = again("user:alice=1001:read_data/execute::allow,everyone@::write_data::deny");
    CHECK_STR(text ? text : "", "user:alice=1001:read_data/execute::allow,"
                                "everyone@::write_data::deny");
    free(text);
    text = again(full);
    CHECK_STR(text ? text : "", full);
    free(text);
    /* In restate's order, whatever order they were written in. */
    text = again("group@::execute/read_data:dir_inherit/file_inherit:audit");
    CHECK_STR(text ? text : "", "group@::read_data/execute:file_inherit/dir_inherit:audit");
    free(text);
    text = again("group:=42::inherited:alarm,"
                 "uuid:0F0E0D0C-0B0A-0908-0706-050403020100:delete::deny");
    CHECK_STR(text ? text : "",
              "group:=42::inherited:alarm,uuid:0F0E0D0C-0B0A-0908-0706-050403020100:delete::deny");
    free(text);

    CHECK(rs_acl_parse("user:bob=7:read_acl::deny,owner@::::allow", &aces, &n));
    CHECK_INT(n, 2);
    if (n != 2)
    {
        return;
    }
    CHECK_INT(aces[0].tag, RS_ACE_USER);
    CHECK_STR(aces[0].name, "bob");
    CHECK_INT(aces[0].id, 7);
    CHECK_INT(aces[0].perms, RS_ACE_READ_ACL);
    CHECK_INT(aces[0].type, RS_ACE_DENY);
    CHECK_INT(aces[1].tag, RS_ACE_OWNER);
    CHECK_INT(aces[1].perms, 0);
    rs_acl_free(aces, n);

    TEST_CASE("acl: a name that would not read back is left to its number");
    {
        static const char *const names[] = { "a:b", "a,b", "a=b", "a/b", "a b", "", "\xff" };
        struct rs_ace             one;
        struct rs_buf             b;
        size_t                    i;

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        {
            memset(&one, 0, sizeof(one));
            one.tag = RS_ACE_USER;
            one.name = (char *)(uintptr_t)names[i];
            one.id = 55;
            one.perms = RS_ACE_READ_DATA;
            rs_buf_init(&b);
            rs_acl_format(&one, 1, &b);
            CHECK_STR(b.data, "user:=55:read_data::allow");
            CHECK(parses(b.data));
            rs_buf_free(&b);
        }
        memset(&one, 0, sizeof(one));
        one.tag = RS_ACE_UUID;
        rs_buf_init(&b);
        rs_acl_format(&one, 1, &b);
        CHECK_STR(b.data, "uuid::::allow");
        CHECK(!parses(b.data));   /* an identity of nothing is not one */
        rs_buf_free(&b);
    }

    TEST_CASE("acl: text that is not an ACL");
    {
        static const char *const bad[] = {
            "",
            "owner@",
            "owner@::read_data:",
            "owner@::read_data::allow:",
            "owner@::read_data::permit",
            "owner@:alice:read_data::allow",
            "user:alice:read_data::allow",
            "user:alice=:read_data::allow",
            "user:alice=12x:read_data::allow",
            "user:=99999999999999999999999:read_data::allow",
            "user:=-1:read_data::allow",
            "uuid::read_data::allow",
            "wheel:=0:read_data::allow",
            "owner@::read_data/fly::allow",
            "owner@::read_data//execute::allow",
            "owner@::read_data:sideways:allow",
            "owner@::read_data::allow,",
            ",owner@::read_data::allow",
            "owner@::read_data::allow,,everyone@:::deny",
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            if (parses(bad[i]))
            {
                CHECK_STR(bad[i], "(not an ACL)");
            }
        }
        CHECK(!rs_acl_parse(NULL, &aces, &n));
        CHECK(aces == NULL && n == 0);
    }

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0);

    TEST_CASE("acl: this system's, or none");
    text = path;   /* anything but NULL: read says none with NULL */
    CHECK(rs_acl_read(fd, &text));
    /* A file just made, in the tests' own directory, has none beyond its
     * mode -- unless the filesystem passes one on. */
    if (text == NULL)
    {
        CHECK(rs_acl_set(fd, NULL, NULL, NULL) == 0);
    }
    free(text);
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    CHECK(rs_acl_supported());
#else
    CHECK(!rs_acl_supported());
    errno = 0;
    CHECK(rs_acl_set(fd, "owner@::read_data::allow", NULL, NULL) != 0);
    CHECK_INT(errno, ENOTSUP);
#endif
    errno = 0;
    CHECK(rs_acl_set(fd, "not one", NULL, NULL) != 0);
    CHECK_INT(errno, EINVAL);

    TEST_CASE("acl: pretending, as the tests do where there are none");
    rs_acl_pretend(true);
    CHECK(rs_acl_supported());
    CHECK(rs_acl_read(fd, &text));
    CHECK(text == NULL);
    CHECK(rs_acl_set(fd, "user:alice=1001:read_data::allow,group:staff=50:execute::deny,"
                         "group:=3:delete::allow",
                     shift, NULL) == 0);
    CHECK(rs_acl_read(fd, &text));
    CHECK_STR(text ? text : "", "user:alice=8001:read_data::allow,group:staff=20:execute::deny,"
                                "group:=7003:delete::allow");
    free(text);
    CHECK(rs_acl_set(fd, "everyone@::read_data::allow", NULL, NULL) == 0);
    CHECK(rs_acl_read(fd, &text));
    CHECK_STR(text ? text : "", "everyone@::read_data::allow");
    free(text);
    CHECK(rs_acl_set(fd, NULL, NULL, NULL) == 0);
    CHECK(rs_acl_read(fd, &text));
    CHECK(text == NULL);
    CHECK(rs_acl_set(-1, "everyone@::read_data::allow", NULL, NULL) != 0);
    rs_acl_pretend(false);

    (void)close(fd);
    rs_test_rmtree(dir);
    free(path);
    free(dir);
}
