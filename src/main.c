/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate -- back up what a fresh OS install would not put back, to rebuild the machine.
 *
 * Everything of substance is in the other files; this one parses the command
 * line and hands over, so that the unit tests, which link everything except
 * this file, can exercise all of it.
 */
#include <stdio.h>
#include <sys/stat.h>

#include "cmd.h"
#include "meta.h"
#include "opts.h"
#include "util.h"

int main(int argc, char **argv)
{
    struct rs_options o;
    struct rs_buf     err;
    int               status;

    /* Nothing restate creates should be readable by anybody else: images
     * describe the whole machine. mkstemp already creates 0600, and this
     * covers anything opened any other way. */
    (void)umask(077);

    rs_buf_init(&err);
    if (!rs_options_parse(argc, argv, &o, &err))
    {
        rs_error("%s", err.data);
        rs_print_usage_hint(stderr);
        rs_buf_free(&err);
        rs_options_free(&o);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);

    if (o.help)
    {
        rs_print_help(stdout);
        rs_options_free(&o);
        return fflush(stdout) == 0 ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
    }
    if (o.version)
    {
        rs_print_version(stdout);
        rs_options_free(&o);
        return fflush(stdout) == 0 ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
    }

    rs_quiet = o.quiet;
    status = rs_cmd_run(&o);
    rs_options_free(&o);
    /* Freed rather than left to exit, so valgrind's leak check -- which this
     * project runs with every kind of leak counted -- reads as clean. */
    rs_name_cache_free();
    return status;
}
