/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "cmd.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "autoinstall.h"
#include "buildsheet.h"
#include "diff.h"
#include "hooks.h"
#include "image.h"
#include "index.h"
#include "installer.h"
#include "live.h"
#include "machine.h"
#include "meta.h"
#include "packages.h"
#include "pgp.h"
#include "progress.h"
#include "restore.h"
#include "rules.h"
#include "run.h"
#include "scan.h"
#include "sources.h"

/* A machine description read on its own is refused beyond this size. */
#define MACHINE_MAX ((size_t)16 * 1024 * 1024)

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
    if (st->pkg_unmodified + st->pkg_modified + st->unpackaged > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " files as their packages installed them; "
                      "%" PRIu64 " changed since, and %" PRIu64 " where only packages put "
                      "files that no package did, kept\n",
                      st->pkg_unmodified, st->pkg_modified, st->unpackaged);
    }
    if (st->grew > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " files were written to while they were "
                      "copied (logs, usually), and are kept as they were when the copy "
                      "began\n", st->grew);
    }
    if (st->unreadable > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " paths could not be read; "
                      "the index is incomplete\n", st->unreadable);
    }
}

/*
 * Whether `root` is the running system's own root. The machine description --
 * disks, firmware, mounts -- is of the running machine, so it belongs only in
 * an index of that machine's root, not in one of a tree mounted from some
 * other disk.
 */
static bool is_live_root(const char *root)
{
    struct stat a;
    struct stat b;

    return stat(root, &a) == 0 && stat("/", &b) == 0 && a.st_dev == b.st_dev &&
           a.st_ino == b.st_ino;
}

/* This program's own path, where the system says (Linux's /proc), if it is a
 * clean absolute path to a regular file; else NULL. */
static char *self_path(void)
{
    char        buf[4096];
    struct stat st;
    ssize_t     n = readlink("/proc/self/exe", buf, sizeof(buf) - 1); /* Flawfinder: ignore */

    if (n <= 0)
    {
        return NULL;
    }
    buf[n] = '\0';
    if (!rs_path_is_clean(buf) || lstat(buf, &st) != 0 || !S_ISREG(st.st_mode))
    {
        return NULL;
    }
    return rs_xstrdup(buf);
}

/*
 * apt's sources checked, each one apt cannot use recorded in the inventory
 * with why; and with `warn`, named, since a rebuild will not install from it
 * either. The time is the real one, not SOURCE_DATE_EPOCH: an index expires
 * by the clock.
 */
static void check_sources(const char *root, struct rs_jval *packages, bool warn)
{
    const struct rs_jval *apt;
    const struct rs_jval *sources;
    bool                  checked = false;
    size_t                i;

    if (rs_sources_check(root, packages, (int64_t)time(NULL), &checked) == 0 || !warn)
    {
        if (!checked && warn && rs_jobject_get(packages, "apt"))
        {
            rs_warn("gpgv is not installed: apt's sources were not checked");
        }
        return;
    }
    apt = rs_jobject_get(packages, "apt");
    sources = apt ? rs_jobject_get(apt, "sources") : NULL;
    for (i = 0; sources && i < sources->n; i++)
    {
        const char *problem = rs_jobject_str(&sources->items[i], "problem");
        const char *file = rs_jobject_str(&sources->items[i], "file");

        if (problem)
        {
            rs_warn("apt cannot use a source in %s -- %s; a rebuild will not install from it "
                    "until that is put right", file ? file : "its sources", problem);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* What is running: warned about, or paused while its files are copied        */
/* ------------------------------------------------------------------------- */

struct quiesce {
    struct rs_live       *live;     /* what was found, and matters */
    size_t                nlive;
    char                **hooks;    /* each one's hook, NULL for none */
    char                **dumps;    /* each one's dump directory, or NULL */
    struct rs_scan_group *groups;   /* one per thing with a hook */
    size_t               *of;       /* the thing each group is */
    size_t                ngroups;
    const char         ***paths;    /* each group's paths */
    bool                  paused;   /* signals are held while it is */
    sigset_t              held;
    sigset_t              saved;
};

/* Whether the walk would record anything of `path`. */
static bool matters(const struct rs_rules *rules, const struct rs_options *o, const char *path)
{
    enum rs_class cls = rs_rules_classify(rules, path, NULL);

    return cls != RS_CLASS_EPHEMERAL && (cls != RS_CLASS_EXPENDABLE || o->all);
}

/* Each live thing's name and files, as messages give them. */
static void describe_live(const struct rs_live *l, struct rs_buf *b)
{
    size_t i;

    rs_buf_addf(b, "%s %s (", rs_live_what(l), l->name);
    for (i = 0; i < l->npaths; i++)
    {
        if (i > 0)
        {
            rs_buf_addstr(b, ", ");
        }
        rs_escape(b, l->paths[i]);
    }
    rs_buf_addc(b, ')');
}

/* A line for the terminal and the system log alike: a capture run from cron
 * leaves its record of what it paused and resumed there. */
static void tell(const struct rs_options *o, int priority, const char *fmt, ...)
    RESTATE_PRINTF(3, 4);

static void tell(const struct rs_options *o, int priority, const char *fmt, ...)
{
    va_list ap;
    char   *msg;

    va_start(ap, fmt);
    msg = rs_xvasprintf(fmt, ap);
    va_end(ap);
    syslog(priority, "%s", msg);
    rs_progress_clear();
    if (priority <= LOG_WARNING)
    {
        rs_warn("%s", msg);
    } else if (!o->quiet)
    {
        (void)fflush(stdout);
        (void)fprintf(stderr, "restate: %s\n", msg);
    }
    free(msg);
}

/*
 * The live things whose files the walk would copy: named, with the command
 * that would stop each, when not quiescing; given a hook and a dump
 * directory, and left to the end of the walk, when quiescing.
 */
static void quiesce_plan(const struct rs_options *o, const struct rs_rules *rules,
                         const char *root, struct quiesce *q)
{
    struct rs_live *all = NULL;
    size_t          n = 0;
    size_t          i;
    size_t          k;

    memset(q, 0, sizeof(*q));
    rs_live_detect("/proc", &all, &n);
    q->live = rs_xcalloc(n + 1, sizeof(*q->live));
    for (i = 0; i < n; i++)
    {
        bool keep = false;

        for (k = 0; k < all[i].npaths; k++)
        {
            keep = keep || matters(rules, o, all[i].paths[k]);
        }
        if (keep)
        {
            q->live[q->nlive++] = all[i];
        } else
        {
            for (k = 0; k < all[i].npaths; k++)
            {
                free(all[i].paths[k]);
            }
            free(all[i].paths);
            free(all[i].name);
        }
    }
    free(all);
    q->hooks = rs_xcalloc(q->nlive + 1, sizeof(*q->hooks));
    q->dumps = rs_xcalloc(q->nlive + 1, sizeof(*q->dumps));
    q->groups = rs_xcalloc(q->nlive + 1, sizeof(*q->groups));
    q->of = rs_xcalloc(q->nlive + 1, sizeof(*q->of));
    q->paths = rs_xcalloc(q->nlive + 1, sizeof(*q->paths));
    for (i = 0; i < q->nlive; i++)
    {
        const struct rs_live *l = &q->live[i];
        struct rs_buf         what;
        struct rs_buf         hint;
        struct rs_buf         err;
        size_t                np = 0;

        rs_buf_init(&what);
        rs_buf_init(&hint);
        rs_buf_init(&err);
        describe_live(l, &what);
        rs_live_hint(l, &hint);
        if (o->quiesce)
        {
            q->hooks[i] = rs_hook_find(l->kind);
        }
        if (!o->quiesce)
        {
            rs_warn("%s is running, and its files will be copied as they change: stop it "
                    "first (%s), or capture with --quiesce", what.data, hint.data);
        } else if (!q->hooks[i])
        {
            rs_warn("%s is running, and no hook pauses %s (%s/%s): its files will be copied as "
                    "they change; stop it first (%s)", what.data, l->kind, RS_HOOKS_SITE_DIR,
                    l->kind, hint.data);
        } else
        {
            if (!rs_hook_dump_dir(root, l, &q->dumps[i], &err))
            {
                rs_warn("no dump directory for %s: %s", what.data, err.data);
            }
            q->paths[q->ngroups] = rs_xcalloc(l->npaths + 2, sizeof(char *));
            for (k = 0; k < l->npaths; k++)
            {
                q->paths[q->ngroups][np++] = l->paths[k];
            }
            if (q->dumps[i])
            {
                q->paths[q->ngroups][np++] = q->dumps[i];
            }
            q->groups[q->ngroups].paths = q->paths[q->ngroups];
            q->groups[q->ngroups].npaths = np;
            q->of[q->ngroups++] = i;
        }
        rs_buf_free(&what);
        rs_buf_free(&hint);
        rs_buf_free(&err);
    }
}

static void quiesce_free(struct quiesce *q)
{
    size_t i;

    for (i = 0; i < q->nlive; i++)
    {
        free(q->hooks[i]);
        free(q->dumps[i]);
    }
    for (i = 0; i < q->ngroups; i++)
    {
        free(q->paths[i]);
    }
    rs_live_free(q->live, q->nlive);
    free(q->hooks);
    free(q->dumps);
    free(q->groups);
    free(q->of);
    free(q->paths);
}

struct around_ctx {
    const struct rs_options *o;
    struct quiesce          *q;
};

/*
 * The scan's call on each side of a group: pause before, resume after.
 * While the thing is paused the signals that would end restate are held, so
 * nothing can stop it between the two; a Ctrl-C reaches the hook itself, and
 * once the thing is resumed restate goes the way the signal says.
 */
static bool around(const void *ctx, size_t group, bool before)
{
    const struct around_ctx *a = ctx;
    struct quiesce          *q = a->q;
    size_t                   i = q->of[group];
    const struct rs_live    *l = &q->live[i];
    const char              *what = rs_live_what(l);
    struct rs_buf            err;
    bool                     go = true;

    rs_buf_init(&err);
    if (before)
    {
        sigset_t pending;

        (void)sigemptyset(&q->held);
        (void)sigaddset(&q->held, SIGINT);
        (void)sigaddset(&q->held, SIGTERM);
        (void)sigaddset(&q->held, SIGHUP);
        (void)sigaddset(&q->held, SIGQUIT);
        (void)sigprocmask(SIG_BLOCK, &q->held, &q->saved);
        q->paused = true;
        tell(a->o, LOG_NOTICE, "pausing %s %s", what, l->name);
        if (!rs_hook_run(q->hooks[i], "pause", l, q->dumps[i], &err))
        {
            tell(a->o, LOG_WARNING, "%s %s was not paused (%s): its files are copied as they "
                 "are", what, l->name, err.data);
        }
        /* Interrupted while it paused: nothing more is copied. */
        go = sigpending(&pending) != 0 ||
             !(sigismember(&pending, SIGINT) == 1 || sigismember(&pending, SIGTERM) == 1 ||
               sigismember(&pending, SIGHUP) == 1 || sigismember(&pending, SIGQUIT) == 1);
    } else
    {
        if (!rs_hook_run(q->hooks[i], "resume", l, q->dumps[i], &err))
        {
            tell(a->o, LOG_ERR, "%s %s was not resumed, and may still be stopped: %s", what,
                 l->name, err.data);
        } else
        {
            tell(a->o, LOG_NOTICE, "resumed %s %s", what, l->name);
        }
        q->paused = false;
        (void)sigprocmask(SIG_SETMASK, &q->saved, NULL);
    }
    rs_buf_free(&err);
    return go;
}

/*
 * `kept_from`, where given, is the inventory of an image this walk is being
 * compared with: the files it kept outside the rules (capture
 * --keep-local-packages) are walked again, so they are not reported deleted.
 */
static bool run_scan(const struct rs_options *o, const char *root, bool hash,
                     struct rs_image_writer *image, struct rs_index *m,
                     struct rs_scan_stats *st, const struct rs_jval *kept_from)
{
    struct rs_rules     rules;
    struct rs_pkgdb     db;
    struct rs_scan_opts so;
    struct quiesce      q;
    struct around_ctx   actx;
    bool                live = false;
    struct rs_buf       err;
    const char         *os_used = NULL;
    char              **keep = NULL;
    size_t              nkeep = 0;
    const char        **kit = NULL;
    size_t              i;
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
    rs_pkgdb_init(&db);
    if (!o->rules_only && rs_pkgdb_load(&db, root))
    {
        so.pkgdb = &db;
    }
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
    if (is_live_root(root))
    {
        rs_machine_describe("/", root, &m->machine);
    }
    /* What is installed is in the tree's own files, wherever it is mounted. */
    rs_packages_describe(root, &m->packages);
    check_sources(root, &m->packages, image != NULL);
    if (o->keep_local)
    {
        struct rs_buf missing;
        const char   *p;

        rs_buf_init(&missing);
        keep = rs_packages_keep(root, &m->packages, o->debs, o->ndebs, &nkeep, &missing);
        so.keep = (const char *const *)keep;
        so.nkeep = nkeep;
        for (p = missing.data; p && *p; )
        {
            size_t len = strcspn(p, "\n");

            rs_warn("%.*s", (int)len, p);
            p += len + (p[len] == '\n' ? 1 : 0);
        }
        rs_buf_free(&missing);
    } else if (kept_from && kept_from->type == RS_JOBJECT)
    {
        keep = rs_packages_kept(kept_from, &nkeep);
        so.keep = (const char *const *)keep;
        so.nkeep = nkeep;
    }
    if (image && is_live_root(root))
    {
        /* The restate making the image, kept in its kit: a new system can
         * run `restate restore` before restate is installed on it. */
        char *self = self_path();

        if (self)
        {
            keep = rs_xreallocarray(keep, nkeep + 1, sizeof(*keep));
            keep[nkeep++] = self;
            so.keep = (const char *const *)keep;
            so.nkeep = nkeep;
        }
    }
    m->content = rs_xstrdup(!image ? "none" : o->baseline_content ? "state+baseline" : "state");
    /* What is running and writing to files the image keeps: named, or with
     * --quiesce left to the end and paused while it is copied. */
    if (image && is_live_root(root))
    {
        live = true;
        quiesce_plan(o, &rules, root, &q);
        actx.o = o;
        actx.q = &q;
        if (q.ngroups > 0)
        {
            so.defer = q.groups;
            so.ndefer = q.ngroups;
            so.around = around;
            so.around_ctx = &actx;
        }
    }
    if (image)
    {
        /* The kit, the part of the image a reinstall reads first: apt's
         * sources and keys, the packages no repository has, and the accounts
         * restore merges before it puts any file back. */
        static const char *const fixed[] = { "/etc/apt", "/etc/apt/", "/etc/passwd",
                                             "/etc/group", "/etc/shadow", "/etc/gshadow" };
        const size_t             nfixed = sizeof(fixed) / sizeof(fixed[0]);

        kit = rs_xreallocarray(NULL, nkeep + nfixed, sizeof(*kit));
        for (i = 0; i < nfixed; i++)
        {
            kit[i] = fixed[i];
        }
        for (i = 0; i < nkeep; i++)
        {
            kit[i + nfixed] = keep[i];
        }
        image->kit = kit;
        image->nkit = nkeep + nfixed;
    }

    rs_buf_init(&err);
    {
        uint64_t total = 0;

        /* A walk that reads files is counted first -- metadata only -- so its
         * progress has a total to show a percentage against. */
        if (rs_progress_enabled() && (so.hash || so.store))
        {
            struct rs_scan_opts  count = so;
            struct rs_scan_stats cst;
            struct rs_index      none;

            count.count_only = true;
            count.verbose = false;
            rs_index_init(&none);
            rs_progress_phase("counting", 0);
            if (rs_scan(&count, &none, &cst, &err))
            {
                total = cst.bytes_hashed;
            }
            rs_progress_done();
            rs_index_free(&none);
            rs_buf_reset(&err);
        }
        rs_progress_phase("walking", total);
    }
    ok = rs_scan(&so, m, st, &err);
    rs_progress_done();
    if (!ok)
    {
        rs_error("%s", err.data);
    }
    rs_buf_free(&err);
    if (live)
    {
        quiesce_free(&q);
    }
    rs_rules_free(&rules);
    rs_pkgdb_free(&db);
    if (image)
    {
        image->kit = NULL;
        image->nkit = 0;
    }
    free(kit);
    for (i = 0; i < nkeep; i++)
    {
        free(keep[i]);
    }
    free(keep);
    return ok;
}

int rs_cmd_scan(const struct rs_options *o)
{
    struct rs_index      m;
    struct rs_scan_stats st;
    struct output        out;
    bool                 ok;

    if (!run_scan(o, o->root ? o->root : "/", !o->no_hash, NULL, &m, &st, NULL))
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

/* ------------------------------------------------------------------------- */
/* Signatures                                                                */
/* ------------------------------------------------------------------------- */

/* Whether an image can be signed with `keyfile` here: gpg and gpgv there,
 * and the file readable. Says why not. Asked before a capture's walk, which
 * is a long time to wait to find out. */
static bool signing_possible(const char *keyfile)
{
    int fd;

    if (!rs_program_path(RS_PROG_GPG) || !rs_program_path(RS_PROG_GPGV))
    {
        rs_error("--sign-with needs gpg and gpgv, and %s is not installed (or not owned by root)",
                 !rs_program_path(RS_PROG_GPG) ? "gpg" : "gpgv");
        return false;
    }
    /* Opened, not access()ed: whether this process can read it. */
    fd = open(keyfile, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        rs_error("--sign-with %s: %s", keyfile, strerror(errno));
        return false;
    }
    (void)close(fd);
    return true;
}

static void say_signer(const char *what, const struct rs_pgp_signer *s)
{
    (void)fflush(stdout);
    (void)fprintf(stderr, "restate: %s %s (%.4s %.4s %.4s %.4s %.4s  %.4s %.4s %.4s %.4s %.4s)%s%s\n",
                  what, s->who[0] ? s->who : "a key with no user ID", s->fpr, s->fpr + 4,
                  s->fpr + 8, s->fpr + 12, s->fpr + 16, s->fpr + 20, s->fpr + 24, s->fpr + 28,
                  s->fpr + 32, s->fpr + 36, s->when[0] ? " on " : "", s->when);
}

/* What a check of an image's signature found, for the index read after it. */
struct trust {
    bool                 checked;   /* and signed by a trusted key */
    struct rs_pgp_signer signer;
    char                 digest[RS_SHA256_HEX_SIZE];
};

/*
 * Whether the image at `path` may be used, checked before its index is even
 * read: signed by one of the --trusted-key keys, or, where `required` is
 * false, not checked at all. Returns RESTATE_EXIT_OK, or
 * RESTATE_EXIT_UNVERIFIED having said why not -- unless --allow-unverified
 * lets a restore through, with a warning.
 */
static int trust_check(const struct rs_options *o, const char *path, bool required,
                       struct trust *tr)
{
    struct rs_buf why;
    size_t        i;
    bool          good;

    memset(tr, 0, sizeof(*tr));
    if (!required)
    {
        return RESTATE_EXIT_OK;
    }
    rs_buf_init(&why);
    /* A key file that is not one is a mistake in the command, not a verdict
     * on the image. */
    for (i = 0; i < o->ntrusted; i++)
    {
        struct rs_buf key;

        rs_buf_init(&key);
        good = rs_pgp_key_bytes(o->trusted[i], &key, &why);
        rs_buf_free(&key);
        if (!good)
        {
            rs_error("--trusted-key %s", why.data);
            rs_buf_free(&why);
            return RESTATE_EXIT_TROUBLE;
        }
    }
    if (!rs_program_path(RS_PROG_GPGV))
    {
        rs_buf_addstr(&why, "gpgv, which checks signatures, is not installed (or not owned by "
                            "root)");
        good = false;
    } else
    {
        good = rs_image_trusted(path, o->trusted, o->ntrusted, &tr->signer, tr->digest, &why);
    }
    if (good)
    {
        tr->checked = true;
        rs_buf_free(&why);
        return RESTATE_EXIT_OK;
    }
    if (o->allow_unverified && o->command == CMD_RESTORE)
    {
        rs_warn("%s: %s; restoring it anyway, as --allow-unverified says", path, why.data);
        rs_buf_free(&why);
        return RESTATE_EXIT_OK;
    }
    if (o->ntrusted == 0)
    {
        rs_error("%s: %s, and no --trusted-key was given to check it against: not restoring it. "
                 "Give the public key of whoever signed it (capture --sign-with) with "
                 "--trusted-key KEYFILE, or restore it unchecked with --allow-unverified",
                 path, why.data);
    } else
    {
        rs_error("%s: %s: not %s it%s", path, why.data,
                 o->command == CMD_RESTORE ? "restoring" : "using",
                 o->command == CMD_RESTORE ? " (--allow-unverified would)" : "");
    }
    rs_buf_free(&why);
    return RESTATE_EXIT_UNVERIFIED;
}

/*
 * The index then read, matched with what was checked: the same bytes, not
 * merely the same file, which could have been changed in between. Says who
 * signed it, and when and where it was captured.
 */
static int trust_matches(const struct rs_options *o, const char *path, const struct trust *tr,
                         const struct rs_index *ix)
{
    struct rs_buf what;

    if (!tr->checked)
    {
        return RESTATE_EXIT_OK;
    }
    if (strcmp(tr->digest, ix->part_sha256) != 0)
    {
        rs_error("%s: it changed while it was being read: not using it", path);
        return RESTATE_EXIT_UNVERIFIED;
    }
    if (!o->quiet)
    {
        rs_buf_init(&what);
        rs_buf_addf(&what, "%s is signed by", path);
        say_signer(what.data, &tr->signer);
        (void)fprintf(stderr, "restate: captured on %s at %s, by restate %s\n",
                      ix->host ? ix->host : "an unknown host",
                      ix->created ? ix->created : "an unknown time",
                      ix->version ? ix->version : "(unknown)");
        rs_buf_free(&what);
    }
    return RESTATE_EXIT_OK;
}

int rs_cmd_sign(const struct rs_options *o)
{
    const char          *path = o->args[0];
    struct rs_buf        index_part;
    struct rs_buf        sig;
    struct rs_buf        err;
    struct rs_pgp_signer signer;
    char                *dir;
    char                *data = NULL;
    bool                 ok;

    if (!o->sign_with)
    {
        rs_error("sign: give the secret key to sign with, --sign-with KEYFILE");
        return RESTATE_EXIT_TROUBLE;
    }
    if (!signing_possible(o->sign_with))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&index_part);
    rs_buf_init(&sig);
    rs_buf_init(&err);
    ok = rs_image_signed_bytes(path, &index_part, &sig, &err);
    if (ok && sig.len > 0)
    {
        rs_buf_addf(&err, "%s: it is signed already", path);
        ok = false;
    }
    rs_buf_reset(&sig);
    dir = ok ? rs_pgp_home(&err) : NULL;
    ok = ok && dir;
    if (ok)
    {
        int fd;

        data = rs_xasprintf("%s/index", dir);
        fd = open(data, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        ok = fd >= 0 && write(fd, index_part.data, index_part.len) == (ssize_t)index_part.len;
        if (fd >= 0 && close(fd) != 0)
        {
            ok = false;
        }
        if (!ok)
        {
            rs_buf_addf(&err, "%s: %s", data, strerror(errno));
        }
    }
    ok = ok && rs_pgp_sign(o->sign_with, data, &sig, &signer, &err) &&
         rs_image_add_signature(path, sig.data, sig.len, &err);
    free(data);
    rs_pgp_home_remove(dir);
    rs_buf_free(&index_part);
    rs_buf_free(&sig);
    if (!ok)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    if (!o->quiet)
    {
        say_signer("signed by", &signer);
    }
    return RESTATE_EXIT_OK;
}

int rs_cmd_capture(const struct rs_options *o)
{
    struct rs_index        m;
    struct rs_scan_stats   st;
    struct rs_image_writer image;
    struct rs_buf          err;
    size_t                 k;
    bool                   ok;

    if (!o->output || strcmp(o->output, "-") == 0)
    {
        rs_error("capture writes an image to a file: give one with -o FILE.tar");
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->no_hash)
    {
        /* Every kept file is read to store it, so its digest costs nothing
         * more, and an image whose content cannot be checked is worse. */
        rs_warn("--no-hash is ignored by capture: kept files are always hashed");
    }
    rs_buf_init(&err);
    /* Before the scan, which can take a long time to find out at the end. */
    if (o->nrecipients > 0 && !rs_program_path(RS_PROG_GPG))
    {
        rs_error("--encrypt-to needs gpg, which is not installed (or not owned by root)");
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->sign_with && !signing_possible(o->sign_with))
    {
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    for (k = 0; k < o->nrecipients; k++)
    {
        /* Opened, not access()ed: the question is whether this process can
         * read it, which only opening it answers. gpg opens it again later. */
        int fd = open(o->recipients[k], O_RDONLY | O_CLOEXEC);

        if (fd < 0)
        {
            rs_error("--encrypt-to %s: %s", o->recipients[k], strerror(errno));
            rs_buf_free(&err);
            return RESTATE_EXIT_TROUBLE;
        }
        (void)close(fd);
    }
    if (!rs_image_begin(&image, o->output, &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    image.recipients = o->recipients;
    image.nrecipients = o->nrecipients;
    image.sign_with = o->sign_with;
    if (!run_scan(o, o->root ? o->root : "/", true, &image, &m, &st, NULL))
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
    } else if (o->sign_with && !o->quiet)
    {
        say_signer("signed by", &image.signer);
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
    struct trust         ta;
    struct trust         tb;
    int                  status;

    if (strcmp(o->args[0], "-") == 0 && strcmp(o->args[1], "-") == 0)
    {
        rs_error("diff: only one of the two can be standard input");
        return RESTATE_EXIT_TROUBLE;
    }
    status = trust_check(o, o->args[0], o->ntrusted > 0, &ta);
    if (status == RESTATE_EXIT_OK)
    {
        status = trust_check(o, o->args[1], o->ntrusted > 0, &tb);
    }
    if (status != RESTATE_EXIT_OK)
    {
        return status;
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
        status = trust_matches(o, o->args[0], &ta, &a);
        if (status == RESTATE_EXIT_OK)
        {
            status = trust_matches(o, o->args[1], &tb, &b);
        }
        if (status == RESTATE_EXIT_OK)
        {
            status = write_diff(o, &a, &b, &d);
        }
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
    struct trust         tr;
    const char          *root;
    int                  status;

    status = trust_check(o, o->args[0], o->ntrusted > 0, &tr);
    if (status != RESTATE_EXIT_OK)
    {
        return status;
    }
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
    status = trust_matches(o, o->args[0], &tr, &recorded);
    if (status != RESTATE_EXIT_OK)
    {
        rs_index_free(&recorded);
        return status;
    }

    /* The root the index was taken from, unless told otherwise: verifying an
     * index of /mnt/old against / would report every file as changed. */
    root = o->root ? o->root : (recorded.root ? recorded.root : "/");
    if (!run_scan(o, root, recorded.hashed && !o->no_hash, NULL, &live, &st,
                  &recorded.packages))
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

int rs_cmd_restore(const struct rs_options *o)
{
    struct rs_index         ix;
    struct rs_restore_opts  ro;
    struct rs_restore_stats st;
    struct rs_buf           err;
    struct trust            tr;
    int                     status;
    bool                    ok;

    /* Before anything is written -- before the index is even read: whose
     * image it is. */
    status = trust_check(o, o->args[0], true, &tr);
    if (status != RESTATE_EXIT_OK)
    {
        return status;
    }
    rs_index_init(&ix);
    rs_buf_init(&err);
    if (!rs_index_load(&ix, o->args[0], &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_index_free(&ix);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_reset(&err);
    status = trust_matches(o, o->args[0], &tr, &ix);
    if (status != RESTATE_EXIT_OK)
    {
        rs_buf_free(&err);
        rs_index_free(&ix);
        return status;
    }
    memset(&ro, 0, sizeof(ro));
    ro.root = o->root ? o->root : "/";
    ro.exclude = o->excludes;
    ro.nexclude = o->nexcludes;
    ro.dry_run = o->dry_run;
    ro.verbose = o->verbose;
    ro.numeric_owner = o->numeric_owner;
    ok = rs_restore(o->args[0], &ix, &ro, &st, &err);
    rs_index_free(&ix);
    if (!ok)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    if (!o->quiet)
    {
        (void)fprintf(stderr, "restate: %s %" PRIu64 " files (%" PRIu64 " bytes), %" PRIu64
                      " directories, %" PRIu64 " symlinks, %" PRIu64 " hard links, %" PRIu64
                      " others under %s\n", o->dry_run ? "would put back" : "put back",
                      st.files, st.bytes, st.directories, st.symlinks, st.links, st.other,
                      ro.root);
        if (st.merged)
        {
            (void)fprintf(stderr, "restate: owners mapped by name, through the image's accounts "
                          "merged with %s's own\n", ro.root);
        }
        if (st.excluded > 0)
        {
            (void)fprintf(stderr, "restate: left out %" PRIu64 " paths (--exclude)\n",
                          st.excluded);
        }
        if (st.owners > 0)
        {
            (void)fprintf(stderr, "restate: %" PRIu64 " owners could not be set: restoring "
                          "owners needs root\n", st.owners);
        }
        if (st.xattrs > 0)
        {
            (void)fprintf(stderr, "restate: %" PRIu64 " extended attributes could not be set: "
                          "some need root, and some filesystems have none\n", st.xattrs);
        }
    }
    if (st.refused + st.failed + st.missing > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " refused, %" PRIu64 " not written, %" PRIu64
                      " missing from the image; the restore is incomplete\n",
                      st.refused, st.failed, st.missing);
        return RESTATE_EXIT_INCOMPLETE;
    }
    return RESTATE_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Explaining                                                                */
/* ------------------------------------------------------------------------- */

int rs_cmd_machine(const struct rs_options *o)
{
    struct rs_jval machine;
    struct rs_buf  text;
    struct output  out;
    bool           ok;

    memset(&machine, 0, sizeof(machine));
    rs_machine_describe("/", o->root ? o->root : "/", &machine);
    rs_buf_init(&text);
    rs_json_write(&text, &machine, 2, 0);
    rs_buf_addc(&text, '\n');
    rs_jval_free(&machine);
    if (!output_open(o, &out))
    {
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = fwrite(text.data, 1, text.len, out.fp) == text.len;
    rs_buf_free(&text);
    return output_close(&out, ok) ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
}

/*
 * What the index records on each mounted filesystem: the bytes of every file
 * under its mount point (and under no deeper one), as "captured" on the
 * description's mounts. A rebuilt machine holds that much -- the files the
 * image keeps and the system files a reinstall puts back -- not the old
 * disk's whole use, which counted downloads and caches the image left out.
 */
static void note_captured(const struct rs_index *ix, struct rs_jval *machine)
{
    struct rs_jval *mounts = NULL;
    uint64_t       *sums;
    size_t          i;
    size_t          k;

    for (i = 0; machine->type == RS_JOBJECT && i < machine->n; i++)
    {
        if (strcmp(machine->keys[i], "mounts") == 0 && machine->items[i].type == RS_JARRAY)
        {
            mounts = &machine->items[i];
        }
    }
    if (!mounts || mounts->n == 0)
    {
        return;
    }
    sums = rs_xcalloc(mounts->n, sizeof(*sums));
    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];
        size_t                 best = SIZE_MAX;
        size_t                 best_len = 0;

        if (e->type != 'f' || !e->path)
        {
            continue;
        }
        for (k = 0; k < mounts->n; k++)
        {
            const char *mp = rs_jobject_str(&mounts->items[k], "mountpoint");
            size_t      len = mp ? strlen(mp) : 0;
            bool        under;

            if (!mp)
            {
                continue;
            }
            under = strcmp(mp, "/") == 0 ||
                    (strncmp(e->path, mp, len) == 0 && (e->path[len] == '/' || e->path[len] == '\0'));
            if (under && (best == SIZE_MAX || len > best_len))
            {
                best = k;
                best_len = len;
            }
        }
        if (best != SIZE_MAX)
        {
            sums[best] += e->size;
        }
    }
    for (k = 0; k < mounts->n; k++)
    {
        if (mounts->items[k].type == RS_JOBJECT && !rs_jobject_get(&mounts->items[k], "captured"))
        {
            rs_jobj_u64(&mounts->items[k], "captured", sums[k]);
        }
    }
    free(sums);
}

/*
 * The machine description in `path`: an image or index with a "machine"
 * section, or what `restate machine -o` writes.
 */
static bool load_machine(const char *path, struct rs_jval *machine, struct rs_jval *packages,
                         bool *old_image, bool *knows_trust)
{
    struct rs_index ix;
    struct rs_buf   err;
    bool            ok = false;

    rs_index_init(&ix);
    rs_buf_init(&err);
    if (rs_index_load(&ix, path, &err))
    {
        if (ix.machine.type == RS_JOBJECT)
        {
            rs_jval_copy(machine, &ix.machine);
            note_captured(&ix, machine);
            if (packages && ix.packages.type == RS_JOBJECT)
            {
                rs_jval_copy(packages, &ix.packages);
            }
            if (old_image)
            {
                *old_image = !ix.in_parts;
            }
            if (knows_trust)
            {
                *knows_trust = rs_image_knows_trust(ix.version);
            }
            ok = true;
        } else
        {
            rs_error("%s has no machine description: only a capture or scan of a machine's "
                     "own root has one", path);
        }
    } else
    {
        /* Not an index: perhaps a description on its own. */
        int           fd = open(path, O_RDONLY | O_CLOEXEC);
        struct rs_buf text;
        char          chunk[8192];
        ssize_t       n = 0;

        rs_buf_init(&text);
        rs_buf_add(&text, "", 0);
        /* A description is a few kilobytes; a file far bigger is not one. */
        while (fd >= 0 && text.len < MACHINE_MAX && (n = read(fd, chunk, sizeof(chunk))) > 0)
        {
            rs_buf_add(&text, chunk, (size_t)n);
        }
        if (fd >= 0)
        {
            (void)close(fd);
        }
        if (fd >= 0 && n >= 0 && text.len < MACHINE_MAX)
        {
            struct rs_json_parser jp;
            struct rs_buf         jerr;

            rs_buf_init(&jerr);
            rs_json_init(&jp, text.data, text.len, &jerr);
            ok = rs_json_value(&jp, machine) && rs_json_at_end(&jp) &&
                 machine->type == RS_JOBJECT && rs_jobject_get(machine, "system");
            rs_buf_free(&jerr);
        }
        if (!ok)
        {
            rs_error("%s", err.data);
        }
        rs_buf_free(&text);
    }
    rs_buf_free(&err);
    rs_index_free(&ix);
    return ok;
}

/* "843938DF228D..." as "8439 38DF 228D ..." -- the way fingerprints are read. */
static void print_fingerprint(FILE *fp, const char *fpr)
{
    size_t i;

    for (i = 0; fpr[i] != '\0'; i++)
    {
        if (i > 0 && i % 4 == 0)
        {
            (void)fputc(' ', fp);
        }
        if (i == 20)
        {
            (void)fputc(' ', fp);
        }
        (void)fputc(fpr[i], fp);
    }
}

int rs_cmd_installer(const struct rs_options *o)
{
    bool                fetch = o->nargs > 0 && strcmp(o->args[0], "fetch") == 0;
    const char         *image = o->nargs > (fetch ? 1u : 0u) ? o->args[fetch ? 1 : 0] : NULL;
    struct rs_jval      machine;
    struct rs_installer in;
    struct rs_buf       err;
    const char         *host;
    int                 status = RESTATE_EXIT_OK;

    if (o->nargs == 2 && !fetch)
    {
        rs_error("usage: restate installer [fetch] [IMAGE]");
        return RESTATE_EXIT_TROUBLE;
    }
    memset(&machine, 0, sizeof(machine));
    if (image)
    {
        if (!load_machine(image, &machine, NULL, NULL, NULL))
        {
            rs_jval_free(&machine);
            return RESTATE_EXIT_TROUBLE;
        }
    } else
    {
        rs_machine_describe("/", o->root ? o->root : "/", &machine);
    }
    rs_buf_init(&err);
    if (!rs_installer_resolve(&machine, &in, &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_jval_free(&machine);
        return RESTATE_EXIT_TROUBLE;
    }
    host = rs_jobject_str(rs_jobject_get(&machine, "system"), "hostname");
    if (!fetch)
    {
        (void)printf("installer   %s\n", in.description);
        (void)printf("for         %s (%s)\n", host ? host : "this machine",
                     rs_jobject_str(rs_jobject_get(&machine, "system"), "pretty_name")
                         ? rs_jobject_str(rs_jobject_get(&machine, "system"), "pretty_name")
                         : in.release);
        (void)printf("because     %s\n", in.reason);
        (void)printf("from        %s\n", in.url);
        if (in.fallback_url)
        {
            (void)printf("            or, after end of life, %s\n", in.fallback_url);
        }
        (void)printf("file        %s -- %s, or the newest listed\n", in.pattern,
                     in.point ? in.point : "the release");
        (void)printf("checked by  SHA256SUMS, signed by %s\n", in.key ? in.key->name : "(no key)");
        if (in.key)
        {
            (void)printf("            ");
            print_fingerprint(stdout, in.key->fingerprint);
            (void)printf("\n");
        }
        (void)printf("fetch it    restate installer fetch%s%s\n", image ? " " : "",
                     image ? image : "");
    } else
    {
        struct rs_fetch_opts fo;
        char                *path = NULL;

        memset(&fo, 0, sizeof(fo));
        fo.cache = o->cache;
        fo.mirror = o->mirror;
        fo.quiet = o->quiet;
        fo.progress = o->progress;
        if (rs_installer_fetch(&in, &fo, &path, &err))
        {
            (void)printf("%s\n", path);
            if (!o->quiet)
            {
                (void)fflush(stdout);
                (void)fprintf(stderr, "restate: %s is verified. To write it to a USB stick -- "
                                      "which erases the stick --\n", in.description);
#if defined(__APPLE__)
                (void)fprintf(stderr, "restate: find the stick with `diskutil list`, then\n"
                                      "restate:   diskutil unmountDisk /dev/diskN\n"
                                      "restate:   sudo dd if=%s of=/dev/rdiskN bs=4m\n", path);
#else
                (void)fprintf(stderr, "restate: find the stick with `lsblk`, then\n"
                                      "restate:   sudo dd if=%s of=/dev/sdX bs=4M "
                                      "status=progress conv=fsync\n", path);
#endif
            }
            free(path);
        } else
        {
            rs_error("%s", err.data);
            status = RESTATE_EXIT_TROUBLE;
        }
    }
    rs_installer_free(&in);
    rs_buf_free(&err);
    rs_jval_free(&machine);
    return status;
}

/* The --target option as the layout spells it. */
static enum rs_target target_of(const struct rs_options *o)
{
    if (o->target && strcmp(o->target, "vm") == 0)
    {
        return RS_TARGET_VM;
    }
    if (o->target && strcmp(o->target, "metal") == 0)
    {
        return RS_TARGET_METAL;
    }
    return RS_TARGET_SAME;
}

/* The machine to describe: the one in IMAGE, or this one -- and, with
 * `packages`, what is installed on it, which an image may not record. */
static bool machine_for(const struct rs_options *o, const char *image, struct rs_jval *machine,
                        struct rs_jval *packages, bool *old_image, bool *knows_trust)
{
    *old_image = false;
    /* This machine's restate, which the restore would be: it knows. */
    *knows_trust = true;
    memset(machine, 0, sizeof(*machine));
    if (packages)
    {
        memset(packages, 0, sizeof(*packages));
    }
    if (image)
    {
        return load_machine(image, machine, packages, old_image, knows_trust);
    }
    rs_machine_describe("/", o->root ? o->root : "/", machine);
    if (packages)
    {
        rs_packages_describe(o->root ? o->root : "/", packages);
    }
    return true;
}

/* Writes `text` where --output says, and frees it. */
static int emit(const struct rs_options *o, struct rs_buf *text)
{
    struct output out;
    bool          ok;

    if (!output_open(o, &out))
    {
        rs_buf_free(text);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = fwrite(text->data, 1, text->len, out.fp) == text->len;
    rs_buf_free(text);
    return output_close(&out, ok) ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
}

/*
 * What is installed: in this tree, or in the one IMAGE was taken from. An
 * image made before the inventory has none, and says so.
 */
int rs_cmd_packages(const struct rs_options *o)
{
    struct rs_jval packages;
    struct rs_buf  text;

    memset(&packages, 0, sizeof(packages));
    if (o->nargs > 0)
    {
        struct rs_index ix;
        struct rs_buf   err;

        rs_index_init(&ix);
        rs_buf_init(&err);
        if (!rs_index_load(&ix, o->args[0], &err))
        {
            rs_error("%s", err.data);
            rs_buf_free(&err);
            rs_index_free(&ix);
            return RESTATE_EXIT_TROUBLE;
        }
        rs_buf_free(&err);
        if (ix.packages.type != RS_JOBJECT)
        {
            rs_error("%s has no package inventory: it was made by a restate older than 1.1",
                     o->args[0]);
            rs_index_free(&ix);
            return RESTATE_EXIT_TROUBLE;
        }
        rs_jval_copy(&packages, &ix.packages);
        rs_index_free(&ix);
    } else
    {
        rs_packages_describe(o->root ? o->root : "/", &packages);
        check_sources(o->root ? o->root : "/", &packages, false);
    }
    rs_buf_init(&text);
    rs_json_write(&text, &packages, 2, 0);
    rs_buf_addc(&text, '\n');
    rs_jval_free(&packages);
    return emit(o, &text);
}

/*
 * What a build sheet or autoinstall file has restore told about whom to
 * trust: nothing, for an image whose own restate is too old to know; with
 * --trusted-key, those keys -- for an installer, put in the file itself, in
 * `keyring`, base64, since the key files are not there -- and otherwise
 * --allow-unverified, which the file then says.
 */
static bool trust_for(const struct rs_options *o, bool knows, bool installer, char **trust,
                      char **keyring)
{
    struct rs_buf b;
    size_t        i;

    *trust = NULL;
    *keyring = NULL;
    if (!knows)
    {
        return true;
    }
    if (o->ntrusted == 0)
    {
        *trust = rs_xstrdup("--allow-unverified");
        return true;
    }
    rs_buf_init(&b);
    if (installer)
    {
        struct rs_buf keys;
        struct rs_buf err;

        rs_buf_init(&keys);
        rs_buf_init(&err);
        for (i = 0; i < o->ntrusted; i++)
        {
            if (!rs_pgp_key_bytes(o->trusted[i], &keys, &err))
            {
                rs_error("--trusted-key %s", err.data);
                rs_buf_free(&err);
                rs_buf_free(&keys);
                return false;
            }
        }
        rs_base64_encode(&b, keys.data, keys.len);
        *keyring = rs_buf_detach(&b);
        *trust = rs_xstrdup("--trusted-key " RS_AUTO_TRUSTED_KEYRING);
        rs_buf_free(&err);
        rs_buf_free(&keys);
        return true;
    }
    for (i = 0; i < o->ntrusted; i++)
    {
        rs_buf_addf(&b, "%s--trusted-key ", i ? " " : "");
        rs_shell_word(&b, o->trusted[i]);
    }
    *trust = rs_buf_detach(&b);
    return true;
}

int rs_cmd_buildsheet(const struct rs_options *o)
{
    const char          *image = o->nargs > 0 ? o->args[0] : NULL;
    struct rs_jval       machine;
    struct rs_buf        text;
    struct rs_buf        err;
    struct rs_sheet_opts so;
    struct rs_jval       packages;
    bool                 old_image;
    bool                 knows;
    char                *trust = NULL;
    char                *keyring = NULL;
    bool                 ok;

    if (!machine_for(o, image, &machine, &packages, &old_image, &knows) ||
        !trust_for(o, knows, false, &trust, &keyring))
    {
        rs_jval_free(&machine);
        rs_jval_free(&packages);
        return RESTATE_EXIT_TROUBLE;
    }
    memset(&so, 0, sizeof(so));
    so.trust = trust;
    so.old_image = old_image;
    so.target = target_of(o);
    so.image = image;
    so.version = RESTATE_VERSION;
    so.packages = packages.type == RS_JOBJECT ? &packages : NULL;
    rs_buf_init(&text);
    rs_buf_init(&err);
    ok = rs_buildsheet(&machine, &so, &text, &err);
    rs_jval_free(&machine);
    rs_jval_free(&packages);
    free(trust);
    free(keyring);
    if (!ok)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    return emit(o, &text);
}

int rs_cmd_autoinstall(const struct rs_options *o)
{
    const char         *image = o->nargs > 0 ? o->args[0] : NULL;
    struct rs_jval      machine;
    struct rs_buf       text;
    struct rs_buf       err;
    struct rs_auto_opts ao;
    struct rs_jval      packages;
    bool                old_image;
    bool                knows;
    char               *trust = NULL;
    char               *keyring = NULL;
    bool                ok;

    if (!machine_for(o, image, &machine, &packages, &old_image, &knows) ||
        !trust_for(o, knows, true, &trust, &keyring))
    {
        rs_jval_free(&machine);
        rs_jval_free(&packages);
        return RESTATE_EXIT_TROUBLE;
    }
    memset(&ao, 0, sizeof(ao));
    ao.trust = trust;
    ao.trust_keyring = keyring;
    ao.old_image = old_image;
    ao.target = target_of(o);
    ao.image = image;
    ao.version = RESTATE_VERSION;
    ao.packages = packages.type == RS_JOBJECT ? &packages : NULL;
    ao.image_at = o->image_at;
    rs_buf_init(&text);
    rs_buf_init(&err);
    ok = rs_autoinstall(&machine, &ao, &text, &err);
    rs_jval_free(&machine);
    rs_jval_free(&packages);
    free(trust);
    free(keyring);
    if (!ok)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    return emit(o, &text);
}

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
    rs_progress_enable(o->progress);
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
    case CMD_SIGN:
        return rs_cmd_sign(o);
    case CMD_RESTORE:
        return rs_cmd_restore(o);
    case CMD_MACHINE:
        return rs_cmd_machine(o);
    case CMD_PACKAGES:
        return rs_cmd_packages(o);
    case CMD_INSTALLER:
        return rs_cmd_installer(o);
    case CMD_BUILDSHEET:
        return rs_cmd_buildsheet(o);
    case CMD_AUTOINSTALL:
        return rs_cmd_autoinstall(o);
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
