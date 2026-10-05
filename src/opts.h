/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The command line: `restate [OPTION]... COMMAND [ARGUMENT]...`
 *
 * Options may come before or after the command, so `restate scan -o m` and
 * `restate -o m scan` mean the same thing.
 */
#ifndef RESTATE_OPTS_H
#define RESTATE_OPTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "util.h"

/* Long-only options, numbered above any character. */
enum {
    OPT_OS = 256,
    OPT_CACHE,
    OPT_MIRROR,
    OPT_TARGET,
    OPT_ENCRYPT_TO
};

enum rs_command {
    CMD_NONE = 0,
#define RS_CMD(id, name, args, min, max, help) id,
#include "commands.def"
#undef RS_CMD
    CMD_COUNT
};

struct rs_options {
    enum rs_command command;
    char          **args;         /* the command's arguments, into argv */
    size_t          nargs;
    const char     *root;         /* NULL: "/", or the index's for verify */
    const char     *output;       /* NULL: standard output */
    const char    **rules_files;
    size_t          nrules_files;
    bool            no_default_rules;
    const char     *os;
    const char     *cache;
    const char     *mirror;
    const char     *target;       /* "vm" or "metal", or NULL: the same machine */
    const char    **recipients;   /* --encrypt-to: public key files */
    size_t          nrecipients;
    bool            all;
    bool            baseline_content;
    bool            one_fs;
    bool            no_hash;
    bool            quiet;
    bool            progress;
    bool            verbose;
    bool            help;
    bool            version;
};

/*
 * Fills `o` from the command line. Returns false with a one-line reason in
 * `err` on a usage error. `o` must be released with rs_options_free whatever
 * the result.
 */
bool rs_options_parse(int argc, char **argv, struct rs_options *o, struct rs_buf *err);
void rs_options_free(struct rs_options *o);

const char *rs_command_name(enum rs_command cmd);

void rs_print_help(FILE *out);
void rs_print_version(FILE *out);
void rs_print_usage_hint(FILE *out);

#endif /* RESTATE_OPTS_H */
