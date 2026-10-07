/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>

#include "opts.h"
#include "test.h"

/* Parses a NULL-terminated argument list; argv[0] is supplied. The vector is
 * static because the parsed options point into it, as they point into the
 * real argv. */
static bool parse_args(struct rs_options *o, struct rs_buf *err, const char *const *args)
{
    static char *argv[32];
    int    argc = 0;

    argv[argc++] = (char *)"restate";
    while (*args && argc < 31)
    {
        argv[argc++] = (char *)*args++;
    }
    argv[argc] = NULL;
    rs_options_free(o);
    rs_buf_reset(err);
    return rs_options_parse(argc, argv, o, err);
}

#define ARGS(...) ((const char *const[]){ __VA_ARGS__, NULL })

static int print_help(const void *arg)
{
    (void)arg;
    rs_print_help(stdout);
    rs_print_version(stdout);
    rs_print_usage_hint(stdout);
    return 0;
}

void test_opts(void)
{
    struct rs_options o;
    struct rs_buf     err;
    char             *out;
    char             *errtext;

    memset(&o, 0, sizeof(o));
    rs_buf_init(&err);

    TEST_CASE("opts: a command and its options, in either order");
    CHECK(parse_args(&o, &err, ARGS("scan", "-r", "/mnt", "-o", "m", "-n", "-a", "-x", "-v")));
    CHECK_INT(o.command, CMD_SCAN);
    CHECK_STR(o.root, "/mnt");
    CHECK_STR(o.output, "m");
    CHECK(o.no_hash && o.all && o.one_fs && o.verbose);
    CHECK_INT(o.nargs, 0);
    CHECK(parse_args(&o, &err, ARGS("--root=/mnt", "--quiet", "diff", "a", "b")));
    CHECK_INT(o.command, CMD_DIFF);
    CHECK_INT(o.nargs, 2);
    CHECK_STR(o.args[0], "a");
    CHECK_STR(o.args[1], "b");
    CHECK(o.quiet);

    TEST_CASE("opts: rules files accumulate");
    CHECK(parse_args(&o, &err, ARGS("-N", "-R", "a.rules", "--rules=b.rules", "--os=freebsd",
                                    "rules")));
    CHECK(o.no_default_rules);
    CHECK_INT(o.nrules_files, 2);
    CHECK_STR(o.rules_files[1], "b.rules");
    CHECK_STR(o.os, "freebsd");
    CHECK_INT(o.command, CMD_RULES);

    TEST_CASE("opts: help and version need no command");
    CHECK(parse_args(&o, &err, ARGS("--help")));
    CHECK(o.help);
    CHECK(parse_args(&o, &err, ARGS("-V")));
    CHECK(o.version);

    TEST_CASE("opts: usage errors say what is wrong");
    CHECK(!parse_args(&o, &err, ARGS("-r")));
    CHECK_CONTAINS(err.data, "option -r needs an argument");
    CHECK(!parse_args(&o, &err, ARGS("scan", "--root")));
    CHECK_CONTAINS(err.data, "--root needs an argument");
    CHECK(!parse_args(&o, &err, ARGS("-Z", "scan")));
    CHECK_CONTAINS(err.data, "unknown option -Z");
    CHECK(!parse_args(&o, &err, ARGS("--bogus", "scan")));
    CHECK_CONTAINS(err.data, "unknown option --bogus");
    CHECK(!parse_args(&o, &err, ARGS("--os=plan9", "scan")));
    CHECK_CONTAINS(err.data, "plan9");
    CHECK(!parse_args(&o, &err, ARGS("-q", "-v", "scan")));
    CHECK_CONTAINS(err.data, "contradict");
    CHECK(!parse_args(&o, &err, ARGS("-n")));
    CHECK_CONTAINS(err.data, "no command given");
    CHECK(!parse_args(&o, &err, ARGS("frobnicate")));
    CHECK_CONTAINS(err.data, "unknown command \"frobnicate\"");
    CHECK(!parse_args(&o, &err, ARGS("restore")));
    CHECK_CONTAINS(err.data, "usage: restate restore IMAGE");
    CHECK(!parse_args(&o, &err, ARGS("scan", "extra")));
    CHECK_CONTAINS(err.data, "scan takes no arguments");
    CHECK(!parse_args(&o, &err, ARGS("diff", "one")));
    CHECK_CONTAINS(err.data, "usage: restate diff OLD NEW");
    CHECK(!parse_args(&o, &err, ARGS("classify")));
    CHECK_CONTAINS(err.data, "usage: restate classify PATH...");
    CHECK(parse_args(&o, &err, ARGS("classify", "/a", "/b", "/c")));
    CHECK_INT(o.nargs, 3);

    TEST_CASE("opts: command names");
    CHECK_STR(rs_command_name(CMD_VERIFY), "verify");
    CHECK_STR(rs_command_name(CMD_NONE), "(none)");

    TEST_CASE("opts: the help lists every command and option");
    CHECK_INT(rs_test_capture(print_help, NULL, &out, &errtext), 0);
    CHECK_CONTAINS(out, "Usage: restate [OPTION]... COMMAND");
    CHECK_CONTAINS(out, "  scan ");
    CHECK_CONTAINS(out, "  diff OLD NEW");
    CHECK_CONTAINS(out, "      --os=NAME");
    CHECK_CONTAINS(out, "  -x, --one-file-system");
    CHECK_CONTAINS(out, "Exit status:");
    CHECK_CONTAINS(out, RESTATE_COPYRIGHT);
    CHECK_CONTAINS(out, "Try 'restate --help'");
    {
        /* Nothing in the help is wider than a terminal. */
        const char *line = out;

        while (line && *line)
        {
            const char *nl = strchr(line, '\n');
            size_t      len = nl ? (size_t)(nl - line) : strlen(line);

            CHECK(len <= 80);
            line = nl ? nl + 1 : NULL;
        }
    }
    free(out);
    free(errtext);

    rs_options_free(&o);
    rs_buf_free(&err);
}
