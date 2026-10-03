/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <unistd.h>

#include "diff.h"
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

static char *diff_text(const struct rs_index *a, const struct rs_index *b,
                       struct rs_diff_stats *st)
{
    char  *dir = rs_test_tmpdir();
    char  *path = rs_xasprintf("%s/d", dir);
    FILE  *fp = fopen(path, "w+");
    char   buf[4096];
    size_t n = 0;

    if (fp)
    {
        CHECK(rs_diff_write(a, b, fp, st));
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

/* Adds an entry whose strings the index then owns. */
static void add(struct rs_index *m, struct rs_entry e)
{
    e.path = rs_xstrdup(e.path);
    e.target = e.target ? rs_xstrdup(e.target) : NULL;
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
    rs_buf_free(&err);
}
