/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "diff.h"
#include "json.h"
#include "test.h"

#define H1 "1111111111111111111111111111111111111111111111111111111111111111"
#define H2 "2222222222222222222222222222222222222222222222222222222222222222"

static struct rs_entry entry(const char *path, char type)
{
    struct rs_entry e;

    memset(&e, 0, sizeof(e));
    e.path = (char *)path;
    e.type = type;
    e.mode = 0644;
    e.cls = RS_CLASS_STATE;
    return e;
}

static char *diff_text_by(const struct rs_index *a, const struct rs_index *b,
                          struct rs_diff_stats *st, bool by_package)
{
    char  *dir = rs_test_tmpdir();
    char  *path = rs_xasprintf("%s/d", dir);
    FILE  *fp = fopen(path, "w+");
    char   buf[4096];
    size_t n = 0;

    if (fp)
    {
        CHECK(by_package ? rs_diff_write_packages(a, b, fp, st) : rs_diff_write(a, b, fp, st));
        rewind(fp);
        n = fread(buf, 1, sizeof(buf) - 1, fp);
        (void)fclose(fp);
    }
    buf[n] = '\0';
    rs_test_rmtree(dir);
    free(path);
    free(dir);
    return rs_xstrdup(buf);
}

static char *diff_text(const struct rs_index *a, const struct rs_index *b,
                       struct rs_diff_stats *st)
{
    return diff_text_by(a, b, st, false);
}

static void inventory(struct rs_index *m, const char *json)
{
    struct rs_json_parser jp;
    struct rs_buf         err;

    rs_buf_init(&err);
    rs_json_init(&jp, json, strlen(json), &err);
    CHECK(rs_json_value(&jp, &m->packages));
    rs_buf_free(&err);
}

/* Adds an entry whose strings the index then owns. */
static void add(struct rs_index *m, struct rs_entry e)
{
    e.path = rs_xstrdup(e.path);
    e.target = e.target ? rs_xstrdup(e.target) : NULL;
    e.package = e.package ? rs_xstrdup(e.package) : NULL;
    rs_index_add(m, &e);
}

void test_diff(void)
{
    struct rs_entry      a;
    struct rs_entry      b;
    struct rs_buf        desc;
    struct rs_index      m1;
    struct rs_index      m2;
    struct rs_diff_stats st;
    struct rs_buf        err;
    char                *text;

    TEST_CASE("diff: comparing two entries");
    a = entry("/f", 'f');
    b = entry("/f", 'f');
    CHECK_INT(rs_diff_entries(&a, &b), 0);
    b.mode = 0600;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_MODE);
    b.uid = 5;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_MODE | RS_DIFF_OWNER);
    b = entry("/f", 'f');
    b.gid = 5;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_OWNER);
    b = entry("/f", 'd');
    b.mode = 0700;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_TYPE);

    TEST_CASE("diff: content is judged by digest when both have one");
    a = entry("/f", 'f');
    b = entry("/f", 'f');
    a.hash_state = b.hash_state = RS_HASH_PRESENT;
    memcpy(a.hash, H1, sizeof(H1));
    memcpy(b.hash, H1, sizeof(H1));
    b.mtime.sec = 99;   /* touched, not changed */
    b.mtime.set = true;
    CHECK_INT(rs_diff_entries(&a, &b), 0);
    memcpy(b.hash, H2, sizeof(H2));
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_CONTENT);

    TEST_CASE("diff: and by size and mtime when either does not");
    b.hash_state = RS_HASH_UNREADABLE;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_CONTENT);
    b.mtime = a.mtime;
    CHECK_INT(rs_diff_entries(&a, &b), 0);
    b.size = 1;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_CONTENT);

    TEST_CASE("diff: symlink targets");
    a = entry("/l", 'l');
    b = entry("/l", 'l');
    a.target = (char *)"x";
    b.target = (char *)"x";
    CHECK_INT(rs_diff_entries(&a, &b), 0);
    b.target = (char *)"y";
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_TARGET);
    b.target = NULL;
    CHECK_INT(rs_diff_entries(&a, &b), RS_DIFF_TARGET);

    TEST_CASE("diff: describing a change");
    rs_buf_init(&desc);
    rs_diff_describe(RS_DIFF_OWNER | RS_DIFF_CONTENT | RS_DIFF_MODE, &desc);
    CHECK_STR(desc.data, "content,mode,owner");
    rs_buf_reset(&desc);
    rs_diff_describe(RS_DIFF_TYPE, &desc);
    CHECK_STR(desc.data, "type");
    rs_buf_reset(&desc);
    rs_diff_describe(RS_DIFF_TARGET, &desc);
    CHECK_STR(desc.data, "target");
    rs_buf_free(&desc);

    TEST_CASE("diff: two indexes, merged");
    rs_index_init(&m1);
    rs_index_init(&m2);
    rs_buf_init(&err);
    add(&m1, entry("/", 'd'));
    add(&m1, entry("/a", 'f'));
    add(&m1, entry("/gone", 'f'));
    add(&m1, entry("/same", 'f'));
    add(&m1, entry("/z", 'f'));
    add(&m2, entry("/", 'd'));
    a = entry("/a", 'f');
    a.mode = 0755;
    add(&m2, a);
    add(&m2, entry("/new\tname", 'f'));
    add(&m2, entry("/same", 'f'));
    add(&m2, entry("/z", 'f'));
    add(&m2, entry("/zz", 'f'));
    CHECK(rs_index_sort(&m1, &err));
    CHECK(rs_index_sort(&m2, &err));
    text = diff_text(&m1, &m2, &st);
    CHECK_STR(text, "M\t/a\tmode\nD\t/gone\nA\t/new\\tname\nA\t/zz\n");
    CHECK_INT(st.added, 2);
    CHECK_INT(st.deleted, 1);
    CHECK_INT(st.modified, 1);
    free(text);
    text = diff_text(&m1, &m1, &st);
    CHECK_STR(text, "");
    CHECK_INT(st.added + st.deleted + st.modified, 0);
    free(text);
    rs_index_free(&m2);
    rs_index_init(&m2);
    text = diff_text(&m1, &m2, &st);
    CHECK_INT(st.deleted, m1.count);
    free(text);
    rs_index_free(&m1);
    rs_index_free(&m2);

    TEST_CASE("diff --packages: what changed by package, and the files that accounts for");
    rs_index_init(&m1);
    rs_index_init(&m2);
    inventory(&m1, "{\"apt\": {\"architectures\": [\"amd64\"], \"packages\": ["
                   "{\"name\": \"nginx\", \"architecture\": \"amd64\", \"version\": \"1.0\"},"
                   "{\"name\": \"old\", \"architecture\": \"all\", \"version\": \"2\"},"
                   "{\"name\": \"libc6\", \"architecture\": \"i386\", \"version\": \"2.4\"},"
                   "{\"name\": \"same\", \"architecture\": \"amd64\", \"version\": \"1\"}]},"
                   "\"snap\": [{\"name\": \"hello\", \"revision\": \"29\"}]}");
    inventory(&m2, "{\"apt\": {\"architectures\": [\"amd64\"], \"packages\": ["
                   "{\"name\": \"htop\", \"architecture\": \"amd64\", \"version\": \"3\"},"
                   "{\"name\": \"libc6\", \"architecture\": \"i386\", \"version\": \"2.5\"},"
                   "{\"name\": \"nginx\", \"architecture\": \"amd64\", \"version\": \"1.1\"},"
                   "{\"name\": \"same\", \"architecture\": \"amd64\", \"version\": \"1\"},"
                   "{\"name\": 7}]},"
                   "\"snap\": [{\"name\": \"hello\", \"revision\": \"30\"}]}");
    add(&m1, entry("/", 'd'));
    a = entry("/etc/nginx/nginx.conf", 'f');
    a.package = (char *)"nginx";
    add(&m1, a);
    a = entry("/usr/bin/nginx", 'f');
    a.package = (char *)"nginx";
    add(&m1, a);
    a = entry("/usr/share/old/x", 'f');
    a.package = (char *)"old";
    add(&m1, a);
    a = entry("/usr/share/same/x", 'f');
    a.package = (char *)"same";
    add(&m1, a);
    add(&m2, entry("/", 'd'));
    a = entry("/etc/nginx/nginx.conf", 'f');
    a.package = (char *)"nginx";
    a.modified = true;      /* edited by hand: listed whatever its package did */
    a.mode = 0600;
    add(&m2, a);
    a = entry("/usr/bin/htop", 'f');
    a.package = (char *)"htop";
    add(&m2, a);
    a = entry("/usr/bin/nginx", 'f');
    a.package = (char *)"nginx";
    a.mode = 0755;
    add(&m2, a);
    a = entry("/usr/share/same/x", 'f');
    a.package = (char *)"same";
    a.mode = 0600;          /* its package did not change: listed */
    add(&m2, a);
    add(&m2, entry("/var/new", 'f'));
    CHECK(rs_index_sort(&m1, &err));
    CHECK(rs_index_sort(&m2, &err));
    text = diff_text_by(&m1, &m2, &st, true);
    CHECK_STR(text, "I\tapt:htop\t3, 1 file\n"
                    "U\tapt:libc6:i386\t2.4 -> 2.5\n"
                    "U\tapt:nginx\t1.0 -> 1.1, 1 file\n"
                    "R\tapt:old\t2, 1 file\n"
                    "U\tsnap:hello\t29 -> 30\n"
                    "M\t/etc/nginx/nginx.conf\tmode\n"
                    "M\t/usr/share/same/x\tmode\n"
                    "A\t/var/new\n");
    CHECK_INT(st.packages, 5);
    CHECK_INT(st.explained, 3);
    CHECK_INT(st.added, 1);
    CHECK_INT(st.modified, 2);
    CHECK_INT(st.deleted, 0);
    free(text);

    TEST_CASE("diff --packages --json: the same, as objects");
    {
        struct rs_jval changes;
        struct rs_jval packages;
        struct rs_buf  json;

        rs_diff_json(&changes, &packages);
        text = diff_text_by(&m1, &m2, &st, true);
        rs_diff_json(NULL, NULL);
        CHECK_STR(text, "");
        free(text);
        CHECK_INT(packages.n, 5);
        CHECK_INT(changes.n, 3);
        rs_buf_init(&json);
        rs_json_write(&json, &packages, 0, 0);
        CHECK_CONTAINS(json.data, "{\"change\": \"I\", \"manager\": \"apt\", \"name\": \"htop\", "
                                  "\"to\": \"3\", \"files\": 1}");
        CHECK_CONTAINS(json.data, "\"name\": \"libc6\", \"arch\": \"i386\", \"from\": \"2.4\", "
                                  "\"to\": \"2.5\"");
        CHECK_CONTAINS(json.data, "{\"change\": \"R\", \"manager\": \"apt\", \"name\": \"old\", "
                                  "\"from\": \"2\", \"files\": 1}");
        rs_buf_reset(&json);
        rs_json_write(&json, &changes, 0, 0);
        CHECK_CONTAINS(json.data, "{\"change\": \"M\", \"path\": \"/etc/nginx/nginx.conf\", "
                                  "\"what\": \"mode\"}");
        CHECK_CONTAINS(json.data, "{\"change\": \"A\", \"path\": \"/var/new\"}");
        rs_buf_free(&json);
        rs_jval_free(&changes);
        rs_jval_free(&packages);
    }

    TEST_CASE("diff --packages: without an inventory on both sides, the files alone");
    rs_jval_free(&m1.packages);
    memset(&m1.packages, 0, sizeof(m1.packages));
    text = diff_text_by(&m1, &m2, &st, true);
    CHECK_INT(st.packages, 0);
    CHECK_INT(st.explained, 0);
    CHECK_CONTAINS(text, "A\t/usr/bin/htop\n");
    CHECK_CONTAINS(text, "D\t/usr/share/old/x\n");
    free(text);
    rs_index_free(&m1);
    rs_index_free(&m2);
    rs_buf_free(&err);
}
