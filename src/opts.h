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
    OPT_ENCRYPT_TO,
    OPT_KEEP_LOCAL,
    OPT_IMAGE_AT,
    OPT_DEB,
    OPT_EXCLUDE,
    OPT_DRY_RUN,
    OPT_CHECK_FIRST,
    OPT_PLAN,
    OPT_NUMERIC_OWNER,
    OPT_RULES_ONLY,
    OPT_QUIESCE,
    OPT_SIGN_WITH,
    OPT_TRUSTED_KEY,
    OPT_ALLOW_UNVERIFIED,
    OPT_KEEP_LAST,
    OPT_KEEP_DAILY,
    OPT_KEEP_WEEKLY,
    OPT_KEEP_MONTHLY,
    OPT_SYSLOG,
    OPT_EXACT_VERSIONS,
    OPT_FETCH_SOURCES,
    OPT_PACKAGES,
    OPT_FIRMWARE,
    OPT_IMAGE_FSTAB,
    OPT_OFFLINE,
    OPT_AS,
    OPT_CLONES,
    OPT_READ_ALL,
    OPT_QUIESCE_WITH,
    OPT_APPEND_ONLY,
    OPT_CREATE,
    OPT_RESULT,
    OPT_GROUP,
    OPT_REPORT_GROUP,
    OPT_JSON,
    OPT_INCLUDE,
    OPT_METADATA_ONLY,
    OPT_RECORD,
    OPT_WHOLE_PACKS,
    OPT_PROGRESS_FILE,
    OPT_TMPDIR,
    OPT_PASSPHRASE_FD
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
    const char     *firmware;     /* "uefi" or "bios", or NULL: the machine's own */
    const char    **recipients;   /* --encrypt-to: public key files */
    size_t          nrecipients;
    const char     *sign_with;    /* --sign-with: a secret key file */
    const char    **trusted;      /* --trusted-key: public key files */
    size_t          ntrusted;
    bool            allow_unverified;
    bool            all;
    bool            rules_only;     /* --rules-only */
    bool            baseline_content;
    bool            keep_local;     /* --keep-local-packages */
    bool            quiesce;        /* --quiesce */
    unsigned        keep_last;      /* prune --keep-last N, and the rest */
    unsigned        keep_daily;
    unsigned        keep_weekly;
    unsigned        keep_monthly;
    bool            log_outcome;    /* --syslog */
    bool            exact_versions; /* --exact-versions */
    bool            fetch_sources;  /* --fetch-sources */
    const char    **debs;           /* --deb NAME=FILE, each */
    size_t          ndebs;
    const char    **excludes;       /* --exclude PATTERN, each */
    size_t          nexcludes;
    bool            dry_run;
    bool            check_first;    /* restore: read it all first */
    bool            plan_only;      /* restore --plan: dry, from the index alone */
    bool            packages;       /* --packages: diff by package, restore them */
    bool            numeric_owner;
    bool            image_fstab;    /* restore: the image's, whatever disks
                                     * they name */
    bool            offline;        /* restore --packages: no network */
    const char     *image_at;       /* --image-at */
    const char     *as;             /* restore --as: the copy's host name */
    const char     *clones;         /* autoinstall --clones: the CSV of copies */
    bool            read_all;       /* check: every snapshot read, as restore would */
    bool            metadata_only;  /* check: no index read, no key needed */
    const char     *record;         /* check, prune: what was there at the last check */
    bool            whole_packs;    /* prune: no index read, whole packs only */
    const char    **quiesce_with;   /* --quiesce-with NAME, each */
    size_t          nquiesce_with;
    bool            append_only;    /* capture: add files only */
    bool            create;         /* capture: init the repository if need be */
    const char     *result;         /* --result FILE */
    const char     *report_group;   /* --report-group GROUP */
    const char     *group;          /* --group GROUP, for protect */
    bool            json;           /* --json */
    const char    **includes;       /* restore --include PATTERN, each */
    size_t          nincludes;
    bool            progress_json;  /* --progress=json */
    const char     *progress_file;  /* --progress-file FILE */
    const char     *tmpdir;         /* --tmpdir DIR */
    int             passphrase_fd;  /* --passphrase-fd N, where passphrase_given */
    bool            passphrase_given;
    bool            one_fs;
    /* verify, status: the index's classification (index.h), classified by
     * instead of the rules options. Set by them, never by an option. */
    const struct rs_jval *classified;
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
/* The i'th option's long name, and the i'th command's name, in the order
 * --help lists them; NULL past the last. */
const char *rs_option_name(size_t i);
const char *rs_command_name_at(size_t i);
/* Whether `name` can be a hook's (--quiesce-with): lowercase letters, digits,
 * '-' and '_', not starting with '-'. */
bool rs_hook_name_ok(const char *name);

void rs_print_help(FILE *out);
void rs_print_version(FILE *out);
void rs_print_usage_hint(FILE *out);

#endif /* RESTATE_OPTS_H */
