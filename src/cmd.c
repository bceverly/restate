/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "cmd.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "diff.h"
#include "image.h"
#include "index.h"
#include "meta.h"
#include "rules.h"
#include "scan.h"

/* ------------------------------------------------------------------------- */
/* Rules                                                                     */
/* ------------------------------------------------------------------------- */

/* The built-in rules for the chosen system, then every --rules file in the
 * order given. `os_used` is set to the system whose built-ins were taken. */
static bool load_rules(const struct rs_options *o, struct rs_rules *rules,
                       const char **os_used)
{
    struct rs_buf err;
    size_t        i;

    rs_rules_init(rules);
    *os_used = o->os ? o->os : rs_rules_host_os();
    if (!o->no_default_rules)
    {
        if (!*os_used)
        {
            rs_warn("no built-in rules for this system; pass --os=NAME or --rules=FILE");
        } else
        {
            (void)rs_rules_add_builtin(rules, *os_used);
        }
    }
    rs_buf_init(&err);
    for (i = 0; i < o->nrules_files; i++)
    {
        if (!rs_rules_load_file(rules, o->rules_files[i], &err))
        {
            rs_error("%s", err.data);
            rs_buf_free(&err);
            rs_rules_free(rules);
            return false;
        }
    }
    rs_buf_free(&err);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Output                                                                    */
/* ------------------------------------------------------------------------- */

/*
 * Where a command writes. Standard output, or a file -- and a file is written
 * beside its final name and renamed into place only once it is complete, so
 * an interrupted scan never leaves half an index where the last good one used
 * to be. The temporary is created 0600 by mkstemp and stays that way: an
 * index is a map of everything on the machine and who owns it, which is
 * nobody else's business.
 */
struct output {
    FILE       *fp;
    char       *tmp;
    const char *final;
};

static bool output_open(const struct rs_options *o, struct output *out)
{
    int fd;

    out->tmp = NULL;
    out->final = o->output;
    if (!o->output || strcmp(o->output, "-") == 0)
    {
        out->fp = stdout;
        out->final = NULL;
        return true;
    }
    out->tmp = rs_xasprintf("%s.XXXXXX", o->output);
    fd = mkstemp(out->tmp);
    if (fd < 0)
    {
        rs_error("%s: %s", o->output, strerror(errno));
        free(out->tmp);
        out->tmp = NULL;
        return false;
    }
    out->fp = fdopen(fd, "w");
    if (!out->fp)
    {
        rs_error("%s: %s", out->tmp, strerror(errno));
        (void)close(fd);
        (void)unlink(out->tmp);
        free(out->tmp);
        out->tmp = NULL;
        return false;
    }
    return true;
}

/* Finishes the output: renames it into place if `ok`, discards it if not.
 * Returns whether the output is now complete and where it should be. */
static bool output_close(struct output *out, bool ok)
{
    if (!out->tmp)
    {
        if (fflush(stdout) != 0 || ferror(stdout))
        {
            rs_error("standard output: %s", strerror(errno));
            return false;
        }
        return ok;
    }
    if (ok && (fflush(out->fp) != 0 || fsync(fileno(out->fp)) != 0))
    {
        rs_error("%s: %s", out->tmp, strerror(errno));
        ok = false;
    }
    if (fclose(out->fp) != 0 && ok)
    {
        rs_error("%s: %s", out->tmp, strerror(errno));
        ok = false;
    }
    if (ok && rename(out->tmp, out->final) != 0)
    {
        rs_error("%s: %s", out->final, strerror(errno));
        ok = false;
    }
    if (!ok)
    {
        (void)unlink(out->tmp);
    }
    free(out->tmp);
    out->tmp = NULL;
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Scanning                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * The creation time, in the index's own time format. SOURCE_DATE_EPOCH, when set,
 * replaces the clock -- the reproducible-builds convention -- which is what
 * lets the end-to-end tests compare two images byte for byte.
 */
static char *created_now(void)
{
    /* Read once, and accepted only as a plain non-negative number below;
     * anything else is ignored rather than trusted. */
    const char     *sde = getenv("SOURCE_DATE_EPOCH"); /* Flawfinder: ignore */
    struct rs_time  now;
    struct timespec ts;
    char            buf[RS_TIME_STR_MAX];

    memset(&now, 0, sizeof(now));
    now.set = true;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    {
        now.sec = (int64_t)ts.tv_sec;
        now.nsec = (int32_t)ts.tv_nsec;
    } else
    {
        now.sec = (int64_t)time(NULL);
    }
    if (sde && *sde)
    {
        char     *end = NULL;
        long long v;

        errno = 0;
        v = strtoll(sde, &end, 10);
        if (errno == 0 && end && *end == '\0' && v >= 0)
        {
            now.sec = (int64_t)v;
            now.nsec = 0;
        }
    }
    rs_time_format(&now, buf);
    return rs_xstrdup(buf);
}

static char *host_name(void)
{
    char buf[256];

    if (gethostname(buf, sizeof(buf)) != 0)
    {
        return rs_xstrdup("unknown");
    }
    buf[sizeof(buf) - 1] = '\0';
    return rs_xstrdup(buf);
}

static void scan_summary(const struct rs_options *o, const struct rs_scan_stats *st)
{
    if (o->quiet)
    {
        return;
    }
    (void)fflush(stdout);
    (void)fprintf(stderr, "restate: recorded %" PRIu64 " paths (%" PRIu64 " state, %" PRIu64
                          " baseline, %" PRIu64 " expendable); kept the content of %" PRIu64 "\n",
                  st->recorded, st->by_class[RS_CLASS_STATE], st->by_class[RS_CLASS_BASELINE],
                  st->by_class[RS_CLASS_EXPENDABLE], st->stored);
    (void)fprintf(stderr, "restate: skipped %" PRIu64 " ephemeral, %" PRIu64 " expendable, %"
                          PRIu64 " sockets, %" PRIu64 " mount points\n",
                  st->skipped_ephemeral, st->skipped_expendable, st->skipped_sockets,
                  st->skipped_mounts);
    if (st->bytes_hashed > 0)
    {
        (void)fprintf(stderr, "restate: hashed %" PRIu64 " bytes\n", st->bytes_hashed);
    }
    if (st->unreadable > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " paths could not be read; "
                      "the index is incomplete\n", st->unreadable);
    }
}

static bool run_scan(const struct rs_options *o, const char *root, bool hash,
                     struct rs_image_writer *image, struct rs_index *m,
                     struct rs_scan_stats *st)
{
    struct rs_rules     rules;
    struct rs_scan_opts so;
    struct rs_buf       err;
    const char         *os_used = NULL;
    bool                ok;

    /* Initialized before anything can fail, because every caller frees the
     * index and the stats are read whatever happened. */
    rs_index_init(m);
    memset(st, 0, sizeof(*st));
    if (!load_rules(o, &rules, &os_used))
    {
        return false;
    }
    memset(&so, 0, sizeof(so));
    so.root = root;
    so.rules = &rules;
    so.hash = hash;
    so.all = o->all;
    so.one_fs = o->one_fs;
    so.verbose = o->verbose;
    if (image)
    {
        so.store = rs_image_store;
        so.store_ctx = image;
        so.store_baseline = o->baseline_content;
    }

    /* Recorded absolute, so `verify` run from another directory -- or another
     * day -- finds the same tree. Kept as given if it cannot be resolved; the
     * scan below will then say why. */
    {
        /* With NULL, realpath allocates a buffer of the size it needs: none of
         * the PATH_MAX overflow flawfinder warns of is possible. */
        char *resolved = realpath(root, NULL); /* Flawfinder: ignore */

        m->root = resolved ? resolved : rs_xstrdup(root);
    }
    m->os = rs_xstrdup(os_used ? os_used : "unknown");
    m->host = host_name();
    m->created = created_now();
    m->hashed = hash || image != NULL;
    m->version = rs_xstrdup(RESTATE_VERSION);
    m->content = rs_xstrdup(!image ? "none" : o->baseline_content ? "state+baseline" : "state");

    rs_buf_init(&err);
    ok = rs_scan(&so, m, st, &err);
    if (!ok)
    {
        rs_error("%s", err.data);
    }
    rs_buf_free(&err);
    rs_rules_free(&rules);
    return ok;
}

int rs_cmd_scan(const struct rs_options *o)
{
    struct rs_index      m;
    struct rs_scan_stats st;
    struct output        out;
    bool                 ok;

    if (!run_scan(o, o->root ? o->root : "/", !o->no_hash, NULL, &m, &st))
    {
        rs_index_free(&m);
        return RESTATE_EXIT_TROUBLE;
    }
    if (!output_open(o, &out))
    {
        rs_index_free(&m);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = rs_index_write(&m, out.fp);
    if (!ok)
    {
        rs_error("%s: %s", out.tmp ? out.tmp : "standard output", strerror(errno));
    }
    ok = output_close(&out, ok);
    rs_index_free(&m);
    if (!ok)
    {
        return RESTATE_EXIT_TROUBLE;
    }
    scan_summary(o, &st);
    return st.unreadable > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

int rs_cmd_capture(const struct rs_options *o)
{
    struct rs_index        m;
    struct rs_scan_stats   st;
    struct rs_image_writer image;
    struct rs_buf          err;
    bool                   ok;

    if (!o->output || strcmp(o->output, "-") == 0)
    {
        rs_error("capture writes an image to a file: give one with -o FILE.tgz");
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->no_hash)
    {
        /* Every kept file is read to store it, so its digest costs nothing
         * more, and an image whose content cannot be checked is worse. */
        rs_warn("--no-hash is ignored by capture: kept files are always hashed");
    }
    rs_buf_init(&err);
    if (!rs_image_begin(&image, o->output, &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    if (!run_scan(o, o->root ? o->root : "/", true, &image, &m, &st))
    {
        rs_image_abort(&image);
        rs_index_free(&m);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = rs_image_finish(&image, &m, &err);
    if (!ok)
    {
        rs_error("%s", err.data);
    }
    rs_buf_free(&err);
    rs_index_free(&m);
    if (!ok)
    {
        return RESTATE_EXIT_TROUBLE;
    }
    scan_summary(o, &st);
    return st.unreadable > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Comparing                                                                 */
/* ------------------------------------------------------------------------- */

static void diff_summary(const struct rs_options *o, const struct rs_diff_stats *d)
{
    if (o->quiet)
    {
        return;
    }
    (void)fflush(stdout);
    (void)fprintf(stderr, "restate: %zu added, %zu deleted, %zu modified\n",
                  d->added, d->deleted, d->modified);
}

static int write_diff(const struct rs_options *o, const struct rs_index *a,
                      const struct rs_index *b, struct rs_diff_stats *d)
{
    struct output out;
    bool          ok;

    if (!output_open(o, &out))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    ok = rs_diff_write(a, b, out.fp, d);
    if (!ok)
    {
        rs_error("%s: %s", out.tmp ? out.tmp : "standard output", strerror(errno));
    }
    if (!output_close(&out, ok))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    diff_summary(o, d);
    return (d->added || d->deleted || d->modified) ? RESTATE_EXIT_DIFFERENT
                                                   : RESTATE_EXIT_OK;
}

int rs_cmd_diff(const struct rs_options *o)
{
    struct rs_index      a;
    struct rs_index      b;
    struct rs_diff_stats d;
    struct rs_buf        err;
    int                  status;

    if (strcmp(o->args[0], "-") == 0 && strcmp(o->args[1], "-") == 0)
    {
        rs_error("diff: only one of the two can be standard input");
        return RESTATE_EXIT_TROUBLE;
    }
    rs_index_init(&a);
    rs_index_init(&b);
    rs_buf_init(&err);
    if (!rs_index_load(&a, o->args[0], &err) || !rs_index_load(&b, o->args[1], &err))
    {
        rs_error("%s", err.data);
        status = RESTATE_EXIT_TROUBLE;
    } else
    {
        status = write_diff(o, &a, &b, &d);
    }
    rs_buf_free(&err);
    rs_index_free(&a);
    rs_index_free(&b);
    return status;
}

int rs_cmd_verify(const struct rs_options *o)
{
    struct rs_index      recorded;
    struct rs_index      live;
    struct rs_scan_stats st;
    struct rs_diff_stats d;
    struct rs_buf        err;
    const char          *root;
    int                  status;

    rs_index_init(&recorded);
    rs_buf_init(&err);
    if (!rs_index_load(&recorded, o->args[0], &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_index_free(&recorded);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);

    /* The root the index was taken from, unless told otherwise: verifying an
     * index of /mnt/old against / would report every file as changed. */
    root = o->root ? o->root : (recorded.root ? recorded.root : "/");
    if (!run_scan(o, root, recorded.hashed && !o->no_hash, NULL, &live, &st))
    {
        rs_index_free(&live);
        rs_index_free(&recorded);
        return RESTATE_EXIT_TROUBLE;
    }
    status = write_diff(o, &recorded, &live, &d);
    if (status == RESTATE_EXIT_OK && st.unreadable > 0)
    {
        status = RESTATE_EXIT_INCOMPLETE;
    }
    rs_index_free(&live);
    rs_index_free(&recorded);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Explaining                                                                */
/* ------------------------------------------------------------------------- */

int rs_cmd_classify(const struct rs_options *o)
{
    struct rs_rules rules;
    struct output   out;
    struct rs_buf   shown;
    const char     *os_used;
    size_t          i;
    int             status = RESTATE_EXIT_OK;

    if (!load_rules(o, &rules, &os_used))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    if (!output_open(o, &out))
    {
        rs_rules_free(&rules);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&shown);
    for (i = 0; i < o->nargs; i++)
    {
        const char   *path = o->args[i];
        long          which;
        enum rs_class cls;

        rs_buf_reset(&shown);
        rs_escape(&shown, path);
        if (!rs_path_is_clean(path))
        {
            rs_error("%s: not a clean absolute path (no \".\", \"..\" or \"//\")",
                     shown.data);
            status = RESTATE_EXIT_TROUBLE;
            continue;
        }
        cls = rs_rules_classify(&rules, path, &which);
        if (which < 0)
        {
            (void)fprintf(out.fp, "%s\t%s\t(no rule matched; state by default)\n",
                          rs_class_name(cls), shown.data);
        } else
        {
            const struct rs_rule *r = &rules.rules[which];

            (void)fprintf(out.fp, "%s\t%s\t%s %s (%s)\n", rs_class_name(cls),
                          shown.data, rs_class_name(r->cls), r->pattern, r->source);
        }
    }
    rs_buf_free(&shown);
    rs_rules_free(&rules);
    if (!output_close(&out, true))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    return status;
}

int rs_cmd_rules(const struct rs_options *o)
{
    struct rs_rules rules;
    struct output   out;
    const char     *os_used;
    bool            ok;

    if (!load_rules(o, &rules, &os_used))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    if (!output_open(o, &out))
    {
        rs_rules_free(&rules);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_rules_write(&rules, out.fp);
    ok = output_close(&out, !ferror(out.fp));
    rs_rules_free(&rules);
    return ok ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
}

int rs_cmd_run(const struct rs_options *o)
{
    switch (o->command)
    {
    case CMD_CAPTURE:
        return rs_cmd_capture(o);
    case CMD_SCAN:
        return rs_cmd_scan(o);
    case CMD_DIFF:
        return rs_cmd_diff(o);
    case CMD_VERIFY:
        return rs_cmd_verify(o);
    case CMD_CLASSIFY:
        return rs_cmd_classify(o);
    case CMD_RULES:
        return rs_cmd_rules(o);
    case CMD_NONE:
    case CMD_COUNT:
    default:
        rs_error("no command given");
        return RESTATE_EXIT_TROUBLE;
    }
}
