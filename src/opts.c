/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "opts.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rules.h"

/* Descriptions start at this column in --help, and wrap to fit 80. */
#define HELP_COLUMN 26
#define HELP_WIDTH  79

static const struct option long_options[] = {
#define RS_OPT(code, name, arg, argname, help) { name, arg, NULL, code },
#include "options.def"
#undef RS_OPT
    { NULL, 0, NULL, 0 }
};

struct option_help {
    int         code;
    const char *name;
    const char *argname;
    const char *help;
};

static const struct option_help option_help[] = {
#define RS_OPT(code, name, arg, argname, help) { code, name, argname, help },
#include "options.def"
#undef RS_OPT
};

struct command_info {
    enum rs_command id;
    const char     *name;
    const char     *args;
    int             min;
    int             max;
    const char     *help;
};

static const struct command_info commands[] = {
#define RS_CMD(id, name, args, min, max, help) { id, name, args, min, max, help },
#include "commands.def"
#undef RS_CMD
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* "r:o:R:Na..." built from the table, so it cannot disagree with it. */
static void short_options(char *out, size_t size)
{
    size_t n = 0;
    size_t i;

    /* The leading ':' makes getopt report a missing argument as ':' rather
     * than '?', so the two errors can be told apart. */
    out[n++] = ':';
    for (i = 0; i < COUNT(option_help) && n + 3 < size; i++)
    {
        int code = option_help[i].code;

        if (code > 0 && code < 256)
        {
            out[n++] = (char)code;
            if (option_help[i].argname)
            {
                out[n++] = ':';
            }
        }
    }
    out[n] = '\0';
}

/*
 * Rewinds getopt so the parser can run more than once in one process, which
 * the unit tests do. glibc and musl reset on optind = 0; the BSDs and macOS
 * have optreset for it instead.
 */
static void reset_getopt(void)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
    optreset = 1;
    optind = 1;
#else
    optind = 0;
#endif
}

const char *rs_command_name(enum rs_command cmd)
{
    size_t i;

    for (i = 0; i < COUNT(commands); i++)
    {
        if (commands[i].id == cmd)
        {
            return commands[i].name;
        }
    }
    return "(none)";
}

/*
 * The option getopt just rejected, spelled the way the user typed it.
 *
 * optopt alone cannot do this: for a long option glibc sets it to the short
 * letter the option maps to, so "--root" with no argument came out as "-r".
 * The argument getopt last looked at is argv[optind - 1], and when that is a
 * "--" option it is the right thing to show -- minus any "=value", which may
 * be long or private.
 */
static const char *offending(char **argv, int code)
{
    static char shown[64];
    const char *arg = optind > 0 ? argv[optind - 1] : NULL;

    if (arg && arg[0] == '-' && arg[1] == '-')
    {
        size_t n = strcspn(arg, "=");

        if (n >= sizeof(shown))
        {
            n = sizeof(shown) - 1;
        }
        memcpy(shown, arg, n);
        shown[n] = '\0';
        return shown;
    }
    if (code > 0 && code < 256)
    {
        shown[0] = '-';
        shown[1] = (char)code;
        shown[2] = '\0';
        return shown;
    }
    return arg ? arg : "?";
}

void rs_options_free(struct rs_options *o)
{
    free(o->rules_files);
    o->rules_files = NULL;
    o->nrules_files = 0;
    free(o->recipients);
    o->recipients = NULL;
    o->nrecipients = 0;
}

bool rs_options_parse(int argc, char **argv, struct rs_options *o, struct rs_buf *err)
{
    char                       shortopts[2 * COUNT(option_help) + 2];
    int                        c;
    size_t                     i;
    const struct command_info *cmd = NULL;

    memset(o, 0, sizeof(*o));
    short_options(shortopts, sizeof(shortopts));
    reset_getopt();
    opterr = 0;   /* the errors below say it better */

    /* flawfinder recalls getopt implementations that overflowed on long
     * arguments decades ago; this is the system libc's, and the arguments are
     * only ever pointed at, never copied. */
    while ((c = getopt_long(argc, argv, shortopts, long_options, NULL)) != -1) /* Flawfinder: ignore */
    {
        switch (c)
        {
        case 'r':
            o->root = optarg;
            break;
        case 'o':
            o->output = optarg;
            break;
        case 'R':
            o->rules_files = rs_xreallocarray(o->rules_files, o->nrules_files + 1,
                                              sizeof(*o->rules_files));
            o->rules_files[o->nrules_files++] = optarg;
            break;
        case 'N':
            o->no_default_rules = true;
            break;
        case OPT_OS:
            if (!rs_rules_known_os(optarg))
            {
                rs_buf_addf(err, "--os: no built-in rules for \"%s\" (linux, freebsd, "
                            "openbsd, netbsd or darwin)", optarg);
                return false;
            }
            o->os = optarg;
            break;
        case OPT_CACHE:
            o->cache = optarg;
            break;
        case OPT_MIRROR:
            if (!rs_starts_with(optarg, "https://") && !rs_starts_with(optarg, "file://"))
            {
                rs_buf_addf(err, "--mirror: \"%s\" is not an https:// or file:// URL", optarg);
                return false;
            }
            o->mirror = optarg;
            break;
        case OPT_ENCRYPT_TO:
            o->recipients = rs_xreallocarray(o->recipients, o->nrecipients + 1,
                                             sizeof(*o->recipients));
            o->recipients[o->nrecipients++] = optarg;
            break;
        case OPT_TARGET:
            if (strcmp(optarg, "vm") != 0 && strcmp(optarg, "metal") != 0)
            {
                rs_buf_addf(err, "--target: \"%s\" is not vm or metal", optarg);
                return false;
            }
            o->target = optarg;
            break;
        case 'a':
            o->all = true;
            break;
        case 'B':
            o->baseline_content = true;
            break;
        case 'x':
            o->one_fs = true;
            break;
        case 'n':
            o->no_hash = true;
            break;
        case 'q':
            o->quiet = true;
            break;
        case 'v':
            o->verbose = true;
            break;
        case 'h':
            o->help = true;
            break;
        case 'V':
            o->version = true;
            break;
        case ':':
            rs_buf_addf(err, "option %s needs an argument", offending(argv, optopt));
            return false;
        case '?':
        default:
            rs_buf_addf(err, "unknown option %s", offending(argv, optopt));
            return false;
        }
    }

    if (o->quiet && o->verbose)
    {
        rs_buf_addstr(err, "--quiet and --verbose contradict each other");
        return false;
    }
    if (o->help || o->version)
    {
        return true;
    }
    if (optind >= argc)
    {
        rs_buf_addstr(err, "no command given");
        return false;
    }
    for (i = 0; i < COUNT(commands); i++)
    {
        if (strcmp(commands[i].name, argv[optind]) == 0)
        {
            cmd = &commands[i];
            break;
        }
    }
    if (!cmd)
    {
        rs_buf_addf(err, "unknown command \"%s\"", argv[optind]);
        return false;
    }
    o->command = cmd->id;
    o->args = argv + optind + 1;
    o->nargs = (size_t)(argc - optind - 1);
    if (o->nargs < (size_t)cmd->min ||
        (cmd->max >= 0 && o->nargs > (size_t)cmd->max))
    {
        if (cmd->args[0] == '\0')
        {
            rs_buf_addf(err, "%s takes no arguments", cmd->name);
        } else
        {
            rs_buf_addf(err, "usage: restate %s %s", cmd->name, cmd->args);
        }
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------------- */

/* Prints `text` from the current column `col`, wrapping at HELP_WIDTH with a
 * hanging indent of HELP_COLUMN. */
static void wrap(FILE *out, size_t col, const char *text)
{
    const char *p = text;

    if (col >= HELP_COLUMN - 1)
    {
        (void)fputc('\n', out);
        col = 0;
    }
    (void)fprintf(out, "%*s", (int)(HELP_COLUMN - col), "");
    col = HELP_COLUMN;
    while (*p != '\0')
    {
        const char *word = p;
        size_t      len;

        while (*p != '\0' && *p != ' ')
        {
            p++;
        }
        len = (size_t)(p - word);
        if (col > HELP_COLUMN && col + 1 + len > HELP_WIDTH)
        {
            (void)fprintf(out, "\n%*s", HELP_COLUMN, "");
            col = HELP_COLUMN;
        } else if (col > HELP_COLUMN)
        {
            (void)fputc(' ', out);
            col++;
        }
        (void)fwrite(word, 1, len, out);
        col += len;
        while (*p == ' ')
        {
            p++;
        }
    }
    (void)fputc('\n', out);
}

void rs_print_help(FILE *out)
{
    size_t i;

    (void)fprintf(out, "Usage: restate [OPTION]... COMMAND [ARGUMENT]...\n"
                       "\n"
                       "Records what makes this machine different from a fresh install of its\n"
                       "operating system, so that after a reinstall the difference can be put\n"
                       "back. Every path is classified by a set of rules as ephemeral (never\n"
                       "kept), expendable (kept only with --all), baseline (supplied by the\n"
                       "operating system or its packages) or state (always kept). An image is a\n"
                       ".tgz holding index.json -- every recorded path with its owner, mode,\n"
                       "times and SHA-256 -- and the content of everything kept.\n"
                       "\n"
                       "Commands:\n");
    for (i = 0; i < COUNT(commands); i++)
    {
        int n = fprintf(out, "  %s%s%s", commands[i].name,
                        commands[i].args[0] ? " " : "", commands[i].args);

        wrap(out, n > 0 ? (size_t)n : 0, commands[i].help);
    }
    (void)fprintf(out, "\nOptions:\n");
    for (i = 0; i < COUNT(option_help); i++)
    {
        const struct option_help *h = &option_help[i];
        int                       n;

        if (h->code > 0 && h->code < 256)
        {
            n = fprintf(out, "  -%c, --%s%s%s", h->code, h->name,
                        h->argname ? "=" : "", h->argname ? h->argname : "");
        } else
        {
            n = fprintf(out, "      --%s%s%s", h->name,
                        h->argname ? "=" : "", h->argname ? h->argname : "");
        }
        wrap(out, n > 0 ? (size_t)n : 0, h->help);
    }
    (void)fprintf(out, "\n"
                       "Exit status:\n"
                       "  0  success; for diff and verify, no differences\n"
                       "  1  differences were found\n"
                       "  2  trouble: a usage error, a bad image, index or rules file, an I/O error\n"
                       "  3  the scan finished, but some files could not be read\n"
                       "\n"
                       "Examples:\n"
                       "  restate capture -o /var/backups/web01.tgz\n"
                       "  restate scan -o web01.json\n"
                       "  restate diff monday.tgz tuesday.tgz\n"
                       "  restate verify /var/backups/web01.tgz\n"
                       "  restate classify /etc/passwd /var/cache/apt /usr/bin/ls\n"
                       "  restate rules > site.rules && restate -N -R site.rules scan\n"
                       "\n"
                       "Report bugs at https://github.com/bceverly/restate/issues\n");
}

void rs_print_version(FILE *out)
{
    (void)fprintf(out, "restate %s\n"
                       "%s\n"
                       "License: BSD 2-Clause <https://opensource.org/license/bsd-2-clause>\n",
                  RESTATE_VERSION, RESTATE_COPYRIGHT);
}

void rs_print_usage_hint(FILE *out)
{
    (void)fprintf(out, "Try 'restate --help' for more information.\n");
}
