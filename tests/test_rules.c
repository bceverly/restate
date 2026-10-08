/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rules.h"
#include "test.h"

static bool parse(struct rs_rules *rs, const char *text, struct rs_buf *err)
{
    rs_buf_reset(err);
    return rs_rules_parse(rs, text, strlen(text), "t.rules", err);
}

static enum rs_class classify(const struct rs_rules *rs, const char *path)
{
    return rs_rules_classify(rs, path, NULL);
}

void test_rules(void)
{
    struct rs_rules rs;
    struct rs_buf   err;
    enum rs_class   cls;
    long            which;
    const char     *oses[] = { "linux", "freebsd", "openbsd", "netbsd", "darwin" };
    size_t          i;

    rs_buf_init(&err);

    TEST_CASE("rules: class names");
    CHECK_STR(rs_class_name(RS_CLASS_EPHEMERAL), "ephemeral");
    CHECK_STR(rs_class_name(RS_CLASS_STATE), "state");
    CHECK_STR(rs_class_name((enum rs_class)99), "?");
    CHECK(rs_class_parse("baseline", 8, &cls) && cls == RS_CLASS_BASELINE);
    CHECK(!rs_class_parse("base", 4, &cls));
    CHECK(!rs_class_parse("baselinex", 9, &cls));

    TEST_CASE("rules: no rules means everything is state");
    rs_rules_init(&rs);
    CHECK_INT(classify(&rs, "/anything"), RS_CLASS_STATE);
    cls = rs_rules_classify(&rs, "/x", &which);
    CHECK_INT(cls, RS_CLASS_STATE);
    CHECK_INT(which, -1);
    rs_rules_free(&rs);

    TEST_CASE("rules: the built-in linux rules");
    rs_rules_init(&rs);
    CHECK(rs_rules_add_builtin(&rs, "linux"));
    CHECK_INT(classify(&rs, "/proc/1/status"), RS_CLASS_EPHEMERAL);
    CHECK_INT(classify(&rs, "/tmp"), RS_CLASS_EPHEMERAL);
    CHECK_INT(classify(&rs, "/etc/ssh/sshd_config"), RS_CLASS_STATE);
    CHECK_INT(classify(&rs, "/usr/bin/bash"), RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/usr/local/bin/tool"), RS_CLASS_STATE);
    CHECK_INT(classify(&rs, "/var/lib/postgresql/18/main"), RS_CLASS_STATE);
    CHECK_INT(classify(&rs, "/var/lib/dpkg/status"), RS_CLASS_EXPENDABLE);
    /* What packages' scripts generate beneath the baseline trees. */
    CHECK_INT(classify(&rs, "/boot/initrd.img-7.0.0-38-generic"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/boot/vmlinuz-7.0.0-38-generic"), RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/usr/lib/modules/7.0.0-38-generic/modules.dep"),
              RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/usr/lib/modules/7.0.0-38-generic/kernel/fs/x.ko"),
              RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/usr/share/mime/globs2"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/usr/share/mime/packages/freedesktop.org.xml"),
              RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/usr/share/fonts/X11/misc/fonts.dir"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/usr/share/icons/Yaru/icon-theme.cache"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/var/lib/apt/lists/x"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/var/cache/apt/archives/x.deb"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/snap/core/1"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/home/u/.cache/x"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/var/lib/app/server.pid"), RS_CLASS_EPHEMERAL);
    CHECK_INT(classify(&rs, "/home/u/documents"), RS_CLASS_STATE);
    cls = rs_rules_classify(&rs, "/usr/local/x", &which);
    CHECK(which >= 0);
    CHECK_STR(rs.rules[which].pattern, "/usr/local");
    CHECK_STR(rs.rules[which].source, "built-in (linux)");
    rs_rules_free(&rs);

    TEST_CASE("rules: every system has built-ins, and they differ");
    for (i = 0; i < sizeof(oses) / sizeof(oses[0]); i++)
    {
        rs_rules_init(&rs);
        CHECK(rs_rules_known_os(oses[i]));
        CHECK(rs_rules_add_builtin(&rs, oses[i]));
        CHECK(rs.count > 10);
        CHECK_INT(classify(&rs, "/etc/rc.conf"), RS_CLASS_STATE);
        CHECK_INT(classify(&rs, "/tmp/x"), RS_CLASS_EPHEMERAL);
        rs_rules_free(&rs);
    }
    rs_rules_init(&rs);
    CHECK(!rs_rules_known_os("plan9"));
    CHECK(!rs_rules_add_builtin(&rs, "plan9"));
    CHECK(rs_rules_add_builtin(&rs, "freebsd"));
    CHECK_INT(classify(&rs, "/usr/local/bin/nginx"), RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/usr/local/etc/nginx/nginx.conf"), RS_CLASS_STATE);
    rs_rules_free(&rs);
    rs_rules_init(&rs);
    CHECK(rs_rules_add_builtin(&rs, "netbsd"));
    CHECK_INT(classify(&rs, "/usr/pkg/bin/bash"), RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/usr/pkg/etc/x"), RS_CLASS_STATE);
    rs_rules_free(&rs);

    TEST_CASE("rules: the host system is recognized");
    {
        const char *host = rs_rules_host_os();

        /* Every system CI runs on is one with built-ins. */
        CHECK(host != NULL);
        if (host)
        {
            CHECK(rs_rules_known_os(host));
        }
    }

    TEST_CASE("rules: parsing, and the last match winning");
    rs_rules_init(&rs);
    CHECK(parse(&rs, "# a comment\n"
                     "\n"
                     "   state      /data   \n"
                     "expendable /data/cache\t# why\r\n"
                     "ephemeral\t/data/cache/hot#not-a-comment\n"
                     "baseline /with space/x\n"
                     "state /trailing/slash/\n", &err));
    CHECK_INT(rs.count, 5);
    CHECK_STR(rs.rules[1].pattern, "/data/cache");
    CHECK_STR(rs.rules[1].source, "t.rules:4");
    CHECK_STR(rs.rules[2].pattern, "/data/cache/hot#not-a-comment");
    CHECK_STR(rs.rules[3].pattern, "/with space/x");
    CHECK_STR(rs.rules[4].pattern, "/trailing/slash");
    CHECK_INT(classify(&rs, "/data/x"), RS_CLASS_STATE);
    CHECK_INT(classify(&rs, "/data/cache/y"), RS_CLASS_EXPENDABLE);
    CHECK_INT(classify(&rs, "/with space/x"), RS_CLASS_BASELINE);
    CHECK_INT(classify(&rs, "/trailing/slash/z"), RS_CLASS_STATE);
    /* No trailing newline on the last line. */
    CHECK(parse(&rs, "state /last", &err));
    CHECK_STR(rs.rules[rs.count - 1].pattern, "/last");

    TEST_CASE("rules: what a bad rules file is told");
    CHECK(!parse(&rs, "keep /x\n", &err));
    CHECK_CONTAINS(err.data, "t.rules:1: unknown class \"keep\"");
    CHECK(!parse(&rs, "\n\nstate\n", &err));
    CHECK_CONTAINS(err.data, "t.rules:3: \"state\" needs a pattern");
    CHECK(!parse(&rs, "state   # only a comment\n", &err));
    CHECK_CONTAINS(err.data, "needs a pattern");
    rs_buf_reset(&err);
    CHECK(!rs_rules_parse(&rs, "state /a\0b\n", 11, "nul", &err));
    CHECK_CONTAINS(err.data, "nul:1: a NUL byte");
    rs_rules_free(&rs);

    TEST_CASE("rules: loading from a file");
    {
        char *dir = rs_test_tmpdir();
        char *path = rs_xasprintf("%s/site.rules", dir);
        char *big = rs_xasprintf("%s/big.rules", dir);
        char *subdir = rs_xasprintf("%s/sub", dir);

        rs_test_write(dir, "site.rules", "state /srv\nephemeral /srv/tmp\n", 0644);
        rs_rules_init(&rs);
        rs_buf_reset(&err);
        CHECK(rs_rules_load_file(&rs, path, &err));
        CHECK_INT(rs.count, 2);
        CHECK_INT(classify(&rs, "/srv/tmp/x"), RS_CLASS_EPHEMERAL);
        rs_buf_reset(&err);
        CHECK(!rs_rules_load_file(&rs, "/nonexistent/restate.rules", &err));
        CHECK_CONTAINS(err.data, "/nonexistent/restate.rules");
        CHECK(mkdir(subdir, 0700) == 0);
        rs_buf_reset(&err);
        CHECK(!rs_rules_load_file(&rs, subdir, &err));
        CHECK_CONTAINS(err.data, "not a regular file");
        {
            /* Over the size limit: a wrong file named by mistake. */
            struct rs_buf text;
            int           n;

            rs_buf_init(&text);
            for (n = 0; n < 100000; n++)
            {
                rs_buf_addstr(&text, "state /x/yy\n");
            }
            rs_test_write(dir, "big.rules", text.data, 0644);
            rs_buf_free(&text);
        }
        rs_buf_reset(&err);
        CHECK(!rs_rules_load_file(&rs, big, &err));
        CHECK_CONTAINS(err.data, "larger than");
        rs_rules_free(&rs);
        rs_test_rmtree(dir);
        free(path);
        free(big);
        free(subdir);
        free(dir);
    }

    TEST_CASE("rules: what `restate rules` writes reads back the same");
    {
        struct rs_rules back;
        char           *dir = rs_test_tmpdir();
        char           *path = rs_xasprintf("%s/out.rules", dir);
        FILE           *fp = fopen(path, "w");
        size_t          k;

        rs_rules_init(&rs);
        CHECK(rs_rules_add_builtin(&rs, "linux"));
        CHECK(parse(&rs, "state /site/a\nstate /site/b\n", &err));
        CHECK(fp != NULL);
        if (fp)
        {
            rs_rules_write(&rs, fp);
            (void)fclose(fp);
        }
        rs_rules_init(&back);
        rs_buf_reset(&err);
        CHECK(rs_rules_load_file(&back, path, &err));
        CHECK_INT(back.count, rs.count);
        for (k = 0; k < rs.count && k < back.count; k++)
        {
            CHECK_STR(back.rules[k].pattern, rs.rules[k].pattern);
            CHECK_INT(back.rules[k].cls, rs.rules[k].cls);
        }
        rs_rules_free(&back);
        rs_rules_free(&rs);
        rs_test_rmtree(dir);
        free(path);
        free(dir);
    }

    rs_buf_free(&err);
}
