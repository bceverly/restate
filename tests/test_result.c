/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <grp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "json.h"
#include "result.h"
#include "test.h"

/* The JSON object in `path`, parsed; false if it is not one. */
static bool read_json(const char *path, struct rs_jval *v)
{
    FILE                 *fp = fopen(path, "r");
    char                  buf[65536];
    size_t                n;
    struct rs_json_parser jp;
    struct rs_buf         err;
    bool                  ok;

    memset(v, 0, sizeof(*v));
    if (!fp)
    {
        return false;
    }
    n = fread(buf, 1, sizeof(buf), fp);
    (void)fclose(fp);
    rs_buf_init(&err);
    rs_json_init(&jp, buf, n, &err);
    ok = rs_json_value(&jp, v) && rs_json_at_end(&jp) && v->type == RS_JOBJECT;
    rs_buf_free(&err);
    return ok;
}

static uint64_t u64_of(const struct rs_jval *obj, const char *key)
{
    uint64_t v = 0;

    (void)rs_jval_u64(rs_jobject_get(obj, key), &v);
    return v;
}

static int warn_twice(const void *arg)
{
    (void)arg;
    rs_warn("first %d", 1);
    rs_warn("second");
    return 0;
}

static int error_many(const void *arg)
{
    size_t i;

    (void)arg;
    rs_error("--append-only: %s is not a repository; an image is written whole", "/r");
    for (i = 1; i < RS_RESULT_ERRORS + 3; i++)
    {
        rs_error("error %zu", i);
    }
    return 0;
}

/* A result written to `arg`, for a group there is not unless the path
 * cannot be written at all: 0 if it was refused. */
static int write_to_group(const void *arg)
{
    const char *path = arg;

    rs_result_begin("du");
    return rs_result_write(RESTATE_EXIT_OK, path,
                           strncmp(path, "/nonexistent", 12) == 0 ? NULL
                                                                  : "no-such-group-restate")
               ? 1
               : 0;
}

static void collecting(const char *dir)
{
    char          *path = rs_xasprintf("%s/r.json", dir);
    struct rs_jval v;
    char          *out = NULL;
    char          *errs = NULL;
    size_t         i;
    bool           quiet = rs_quiet;

    TEST_CASE("result: what a run did, written whole when it ends");
    rs_result_begin("capture");
    rs_jobj_str(rs_result(), "repository", "/r");
    rs_jobj_u64(rs_result(), "paths", 42);
    rs_quiet = true;   /* collected, quiet or not */
    (void)rs_test_capture(warn_twice, NULL, &out, &errs);
    rs_quiet = quiet;
    free(out);
    free(errs);
    for (i = 0; i < RS_RESULT_UNREADABLE + 5; i++)
    {
        rs_result_unreadable("/srv/a\xff", "Input/output error");
    }
    CHECK_INT(rs_result_unreadable_count(), RS_RESULT_UNREADABLE + 5);
    rs_result_quiesce("postgresql", "16-main", 1000, 1010, true, NULL);
    rs_result_quiesce("unifi", "unifi", 1000, 0, false, "exited 1");
    CHECK_INT(rs_result_quiesce_failed(), 1);
    CHECK(rs_result_write(RESTATE_EXIT_INCOMPLETE, path, NULL));
    CHECK(read_json(path, &v));
    CHECK_INT(u64_of(&v, "schema"), RS_RESULT_SCHEMA);
    CHECK_STR(rs_jobject_str(&v, "command"), "capture");
    CHECK_STR(rs_jobject_str(&v, "status"), "incomplete");
    CHECK_INT(u64_of(&v, "exit"), 3);
    CHECK(rs_jobject_str(&v, "started_at") && strlen(rs_jobject_str(&v, "started_at")) == 20);
    CHECK_STR(rs_jobject_str(&v, "repository"), "/r");
    CHECK_INT(u64_of(&v, "paths"), 42);
    CHECK_INT(u64_of(&v, "warnings_count"), 2);
    {
        const struct rs_jval *w = rs_jobject_get(&v, "warnings");
        const struct rs_jval *u = rs_jobject_get(&v, "unreadable");
        const struct rs_jval *q = rs_jobject_get(&v, "quiesce");

        CHECK(w && w->type == RS_JARRAY && w->n == 2);
        CHECK_STR(w && w->n == 2 ? w->items[0].s : NULL, "first 1");
        CHECK_INT(u64_of(u, "count"), RS_RESULT_UNREADABLE + 5);
        CHECK(rs_jobject_get(u, "first") && rs_jobject_get(u, "first")->n == RS_RESULT_UNREADABLE);
        CHECK_CONTAINS(rs_jobject_str(&rs_jobject_get(u, "first")->items[0], "path"), "/srv/a");
        CHECK(q && q->n == 2);
        if (q && q->n == 2)
        {
            CHECK_STR(rs_jobject_str(&q->items[0], "status"), "ok");
            CHECK_STR(rs_jobject_str(&q->items[0], "resumed_at"), "1970-01-01T00:16:50Z");
            CHECK_STR(rs_jobject_str(&q->items[1], "status"), "failed");
            CHECK(rs_jobject_get(&q->items[1], "resumed_at") &&
                  rs_jobject_get(&q->items[1], "resumed_at")->type == RS_JNULL);
            CHECK_STR(rs_jobject_str(&q->items[1], "message"), "exited 1");
        }
    }
    rs_jval_free(&v);
    {
        struct stat st;

        CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    }

    TEST_CASE("result: many warnings, the first in full and all counted");
    rs_result_begin("check");
    rs_quiet = true;
    for (i = 0; i < RS_RESULT_WARNINGS + 10; i++)
    {
        rs_warn("warning %zu", i);
    }
    rs_quiet = quiet;
    CHECK(rs_result_write(RESTATE_EXIT_OK, path, NULL));
    CHECK(read_json(path, &v));
    CHECK_INT(u64_of(&v, "warnings_count"), RS_RESULT_WARNINGS + 10);
    CHECK_INT(rs_jobject_get(&v, "warnings")->n, RS_RESULT_WARNINGS);
    CHECK_STR(rs_jobject_str(&v, "status"), "ok");
    rs_jval_free(&v);

    TEST_CASE("result: a run that failed says why, the first errors in full and all counted");
    rs_result_begin("capture");
    rs_quiet = true;   /* errors are said all the same */
    (void)rs_test_capture(error_many, NULL, &out, &errs);
    rs_quiet = quiet;
    CHECK_CONTAINS(errs, "restate: --append-only: /r is not a repository");
    free(out);
    free(errs);
    CHECK(rs_result_write(RESTATE_EXIT_TROUBLE, path, NULL));
    CHECK(read_json(path, &v));
    CHECK_STR(rs_jobject_str(&v, "status"), "failed");
    CHECK_INT(u64_of(&v, "errors_count"), RS_RESULT_ERRORS + 3);
    {
        const struct rs_jval *e = rs_jobject_get(&v, "errors");

        CHECK(e && e->type == RS_JARRAY && e->n == RS_RESULT_ERRORS);
        CHECK_STR(e && e->n > 0 ? e->items[0].s : NULL,
                  "--append-only: /r is not a repository; an image is written whole");
    }
    rs_jval_free(&v);
    /* Once the result is written, errors are no longer collected. */
    (void)rs_test_capture(error_many, NULL, &out, &errs);
    free(out);
    free(errs);
    rs_result_begin("du");
    CHECK(rs_result_write(RESTATE_EXIT_OK, path, NULL));
    CHECK(read_json(path, &v));
    CHECK_INT(u64_of(&v, "errors_count"), 0);
    CHECK(rs_jobject_get(&v, "errors") && rs_jobject_get(&v, "errors")->n == 0);
    rs_jval_free(&v);

    TEST_CASE("result: readable by a group too, where one is given");
    {
        const struct group *g = getgrgid(getgid());
        /* A copy: getgrnam may parse into the buffer this points into, as
         * OpenBSD's and NetBSD's do, and then it looks up some other name. */
        char *name = g && g->gr_name ? rs_xstrdup(g->gr_name) : NULL;

        if (name)
        {
            struct stat st;

            rs_result_begin("du");
            CHECK(rs_result_write(RESTATE_EXIT_OK, path, name));
            CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0640 && st.st_gid == getgid());
        }
        free(name);
    }

    TEST_CASE("result: a group there is not, and a file that cannot be written");
    free(path);
    path = rs_xasprintf("%s/r2.json", dir);
    CHECK_INT(rs_test_capture(write_to_group, path, &out, &errs), 0);
    CHECK_CONTAINS(errs, "there is no such group");
    CHECK(access(path, F_OK) != 0);
    free(out);
    free(errs);
    CHECK_INT(rs_test_capture(write_to_group, "/nonexistent/dir/r.json", &out, &errs), 0);
    CHECK_CONTAINS(errs, "/nonexistent/dir/r.json");
    free(out);
    free(errs);

    TEST_CASE("result: none asked for, nothing written, and the collection cleared");
    rs_result_begin("prune");
    rs_result_unreadable("/x", "gone");
    CHECK(rs_result_write(RESTATE_EXIT_BUSY, NULL, NULL));
    CHECK_INT(rs_result_unreadable_count(), 0);
    rs_result_end();
    rs_result_unreadable("/x", "not collecting");
    CHECK_INT(rs_result_unreadable_count(), 0);
    CHECK(rs_result() != NULL);
    rs_result_end();
    free(path);
}

static void words(void)
{
    char when[32];

    TEST_CASE("result: the status words, and times");
    CHECK_STR(rs_result_status_word(RESTATE_EXIT_OK), "ok");
    CHECK_STR(rs_result_status_word(RESTATE_EXIT_DIFFERENT), "different");
    CHECK_STR(rs_result_status_word(RESTATE_EXIT_TROUBLE), "failed");
    CHECK_STR(rs_result_status_word(RESTATE_EXIT_INCOMPLETE), "incomplete");
    CHECK_STR(rs_result_status_word(RESTATE_EXIT_UNVERIFIED), "untrusted");
    CHECK_STR(rs_result_status_word(RESTATE_EXIT_BUSY), "busy");
    CHECK_STR(rs_result_status_word(99), "failed");
    rs_result_time(1792454400, when);
    CHECK_STR(when, "2026-10-20T00:00:00Z");
}

void test_result(void)
{
    char *dir = rs_test_tmpdir();

    collecting(dir);
    words();
    rs_test_rmtree(dir);
    free(dir);
}
