/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cmd.h"
#include "image.h"
#include "index.h"
#include "test.h"

static int run(const void *arg)
{
    return rs_cmd_run(arg);
}

/* Runs a command with its output captured; `out` and `err` are freed by the
 * next call, or by run_done. */
static char *out_text;
static char *err_text;

static int run_cmd(const struct rs_options *o)
{
    free(out_text);
    free(err_text);
    return rs_test_capture(run, o, &out_text, &err_text);
}

static void run_done(void)
{
    free(out_text);
    free(err_text);
    out_text = NULL;
    err_text = NULL;
}

void test_cmd(void)
{
    char             *root = rs_test_tmpdir();
    char             *work = rs_test_tmpdir();
    char             *m1 = rs_xasprintf("%s/m1", work);
    char             *m2 = rs_xasprintf("%s/m2", work);
    char             *rules = rs_xasprintf("%s/site.rules", work);
    char             *etc = rs_xasprintf("%s/etc", root);
    char             *args[4];
    const char       *rules_files[1];
    struct rs_options o;
    struct stat       st;

    (void)mkdir(etc, 0755);
    rs_test_write(root, "etc/conf", "one\n", 0644);
    rs_test_write(work, "site.rules", "ephemeral /etc/skip\n", 0644);
    rs_test_write(root, "etc/skip", "x", 0644);
    (void)setenv("SOURCE_DATE_EPOCH", "1700000000", 1);

    TEST_CASE("cmd: scan writes a private index");
    memset(&o, 0, sizeof(o));
    o.command = CMD_SCAN;
    o.root = root;
    o.output = m1;
    o.os = "linux";
    rules_files[0] = rules;
    o.rules_files = rules_files;
    o.nrules_files = 1;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK_CONTAINS(err_text, "recorded 3 paths");
    CHECK(stat(m1, &st) == 0 && (st.st_mode & 0777) == 0600);
    {
        struct rs_index m;
        struct rs_buf   err;

        rs_index_init(&m);
        rs_buf_init(&err);
        CHECK(rs_index_load(&m, m1, &err));
        CHECK_STR(m.created, "2023-11-14T22:13:20.000000000Z");
        CHECK_STR(m.os, "linux");
        CHECK(m.root && m.root[0] == '/');
        CHECK(rs_index_find(&m, "/etc/conf") != NULL);
        CHECK(rs_index_find(&m, "/etc/skip") == NULL);
        rs_index_free(&m);
        rs_buf_free(&err);
    }

    TEST_CASE("cmd: scan to standard output, quietly");
    o.output = NULL;
    o.quiet = true;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK_CONTAINS(out_text, "\"format\": \"restate-index\"");
    CHECK_STR(err_text, "");
    o.quiet = false;

    TEST_CASE("cmd: scan reports a bad root and a bad output path");
    o.root = "/nonexistent/restate";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    o.root = root;
    o.output = "/nonexistent/dir/m";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(err_text, "/nonexistent/dir/m");

    TEST_CASE("cmd: a missing rules file is trouble, not a silent default");
    rules_files[0] = "/nonexistent/site.rules";
    o.output = NULL;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(err_text, "/nonexistent/site.rules");
    rules_files[0] = rules;

    TEST_CASE("cmd: verify an unchanged tree, then a changed one");
    memset(&o, 0, sizeof(o));
    o.command = CMD_VERIFY;
    o.os = "linux";
    o.rules_files = rules_files;
    o.nrules_files = 1;
    args[0] = m1;
    o.args = args;
    o.nargs = 1;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK_STR(out_text, "");
    CHECK_CONTAINS(err_text, "0 added, 0 deleted, 0 modified");
    rs_test_write(root, "etc/conf", "two\n", 0644);
    rs_test_write(root, "etc/new", "n", 0644);
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_DIFFERENT);
    CHECK_CONTAINS(out_text, "M\t/etc/conf\tcontent\n");
    CHECK_CONTAINS(out_text, "A\t/etc/new\n");
    args[0] = (char *)"/nonexistent/m";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    args[0] = m1;
    o.root = "/nonexistent/restate";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    o.root = NULL;

    TEST_CASE("cmd: diff two indexes");
    memset(&o, 0, sizeof(o));
    o.command = CMD_SCAN;
    o.root = root;
    o.output = m2;
    o.os = "linux";
    o.quiet = true;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    memset(&o, 0, sizeof(o));
    o.command = CMD_DIFF;
    args[0] = m1;
    args[1] = m2;
    o.args = args;
    o.nargs = 2;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_DIFFERENT);
    CHECK_CONTAINS(out_text, "M\t/etc/conf\tcontent");
    CHECK_CONTAINS(out_text, "A\t/etc/skip");
    args[1] = m1;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    args[0] = (char *)"-";
    args[1] = (char *)"-";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(err_text, "only one of the two");
    args[0] = m1;
    args[1] = rules;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(err_text, "not a restate index");

    TEST_CASE("cmd: capture writes an image that verify and diff read");
    {
        char *img = rs_xasprintf("%s/img.tgz", work);

        memset(&o, 0, sizeof(o));
        o.command = CMD_CAPTURE;
        o.root = root;
        o.os = "linux";
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
        CHECK_CONTAINS(err_text, "give one with -o");
        o.output = img;
        o.no_hash = true;
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
        CHECK_CONTAINS(err_text, "--no-hash is ignored");
        CHECK_CONTAINS(err_text, "kept the content of");
        CHECK(stat(img, &st) == 0 && (st.st_mode & 0777) == 0600);
        o.no_hash = false;
        o.baseline_content = true;
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
        o.output = "/nonexistent/dir/img.tgz";
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
        o.output = img;
        o.root = "/nonexistent/restate";
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);

        memset(&o, 0, sizeof(o));
        o.command = CMD_VERIFY;
        o.os = "linux";
        args[0] = img;
        o.args = args;
        o.nargs = 1;
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
        o.command = CMD_DIFF;
        args[1] = m2;
        o.nargs = 2;
        CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
        free(img);
    }

    TEST_CASE("cmd: classify explains each answer");
    memset(&o, 0, sizeof(o));
    o.command = CMD_CLASSIFY;
    o.os = "linux";
    args[0] = (char *)"/etc/passwd";
    args[1] = (char *)"/srv/x";
    args[2] = (char *)"/nowhere";
    o.args = args;
    o.nargs = 3;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK_CONTAINS(out_text, "state\t/etc/passwd\tstate /etc (built-in (linux))\n");
    CHECK_CONTAINS(out_text, "state\t/nowhere\t(no rule matched; state by default)\n");
    args[1] = (char *)"relative/path";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(err_text, "not a clean absolute path");
    o.nargs = 1;
    o.no_default_rules = true;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK_CONTAINS(out_text, "no rule matched");

    TEST_CASE("cmd: rules prints the rule set, to a file if asked");
    memset(&o, 0, sizeof(o));
    o.command = CMD_RULES;
    o.os = "openbsd";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK_CONTAINS(out_text, "# from built-in (openbsd)");
    CHECK_CONTAINS(out_text, "/var/db/pkg");
    o.output = m2;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_OK);
    CHECK(stat(m2, &st) == 0 && st.st_size > 0);
    rules_files[0] = "/nonexistent/x.rules";
    o.rules_files = rules_files;
    o.nrules_files = 1;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    o.nrules_files = 0;
    o.output = "/nonexistent/dir/r";
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);

    TEST_CASE("cmd: classify cannot write to a missing directory");
    o.command = CMD_CLASSIFY;
    args[0] = (char *)"/etc";
    o.args = args;
    o.nargs = 1;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    o.output = NULL;
    o.rules_files = rules_files;
    o.nrules_files = 1;
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);

    TEST_CASE("cmd: no command is trouble");
    memset(&o, 0, sizeof(o));
    CHECK_INT(run_cmd(&o), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(err_text, "no command given");

    run_done();
    (void)unsetenv("SOURCE_DATE_EPOCH");
    rs_test_rmtree(root);
    rs_test_rmtree(work);
    free(root);
    free(work);
    free(m1);
    free(m2);
    free(rules);
    free(etc);
}
