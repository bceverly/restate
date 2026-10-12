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
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "autoinstall.h"
#include "baseline.h"
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
#include "reinstall.h"
#include "repo.h"
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
static void check_sources(const struct rs_options *o, const char *root, struct rs_jval *packages,
                          bool warn)
{
    const struct rs_jval *apt;
    const struct rs_jval *sources;
    bool                  checked = false;
    bool                  online = o->fetch_sources;
    size_t                i;

    if (online && !rs_program_path(RS_PROG_CURL))
    {
        rs_warn("--fetch-sources needs curl, which is not installed (or not owned by root): "
                "apt's sources are checked as apt last fetched them only");
        online = false;
    }
    if (rs_sources_check(root, packages, (int64_t)time(NULL), online, &checked) == 0 || !warn)
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

/* Where a walk's kept content goes: an image, or a new snapshot in a
 * repository; and, for an incremental run, the index of the last one. */
struct sink {
    struct rs_image_writer *image;
    struct rs_repo_writer  *repo;
    const struct rs_index  *prev;
};

/*
 * `sink` NULL, or with neither an image nor a repository, makes an index
 * alone. `kept_from`, where given, is the inventory of an image this walk is
 * being compared with: the files it kept outside the rules (capture
 * --keep-local-packages) are walked again, so they are not reported deleted.
 */
static bool run_scan(const struct rs_options *o, const char *root, bool hash,
                     const struct sink *sink, struct rs_index *m,
                     struct rs_scan_stats *st, const struct rs_jval *kept_from)
{
    struct rs_image_writer *image = sink ? sink->image : NULL;
    struct rs_repo_writer  *repo = sink ? sink->repo : NULL;
    bool                    storing = image || repo;
    struct rs_rules         rules;
    struct rs_pkgdb         db;
    struct rs_scan_opts     so;
    struct quiesce          q;
    struct around_ctx       actx;
    bool                    live = false;
    struct rs_buf           err;
    const char             *os_used = NULL;
    char                  **keep = NULL;
    size_t                  nkeep = 0;
    const char            **kit = NULL;
    size_t                  i;
    bool                    ok;

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
    } else if (repo)
    {
        so.store = rs_repo_store;
        so.store_ctx = repo;
        so.have = rs_repo_have;
    }
    so.store_baseline = storing && o->baseline_content;
    so.prev = sink ? sink->prev : NULL;

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
    m->hashed = hash || storing;
    m->version = rs_xstrdup(RESTATE_VERSION);
    if (is_live_root(root))
    {
        rs_machine_describe("/", root, &m->machine);
    }
    /* What is installed is in the tree's own files, wherever it is mounted. */
    rs_packages_describe(root, &m->packages);
    check_sources(o, root, &m->packages, storing);
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
    if (storing && is_live_root(root))
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
    m->content = rs_xstrdup(!storing ? "none" : o->baseline_content ? "state+baseline" : "state");
    /* What is running and writing to files the image keeps: named, or with
     * --quiesce left to the end and paused while it is copied. */
    if (storing && is_live_root(root))
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
    if (storing)
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
        if (image)
        {
            image->kit = kit;
            image->nkit = nkeep + nfixed;
        } else
        {
            rs_repo_writer_kit(repo, kit, nkeep + nfixed);
        }
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
    if (o->allow_unverified && (o->command == CMD_RESTORE || o->command == CMD_BASELINE))
    {
        rs_warn("%s: %s; %s anyway, as --allow-unverified says", path, why.data,
                o->command == CMD_RESTORE ? "restoring it" : "fetching its packages");
        rs_buf_free(&why);
        return RESTATE_EXIT_OK;
    }
    if (o->ntrusted == 0)
    {
        rs_error("%s: %s, and no --trusted-key was given to check it against: not %s. "
                 "Give the public key of whoever signed it (capture --sign-with) with "
                 "--trusted-key KEYFILE, or %s unchecked with --allow-unverified",
                 path, why.data,
                 o->command == CMD_RESTORE ? "restoring it" : "fetching its packages",
                 o->command == CMD_RESTORE ? "restore it" : "fetch them");
    } else
    {
        rs_error("%s: %s: not %s%s", path, why.data,
                 o->command == CMD_RESTORE    ? "restoring it"
                 : o->command == CMD_BASELINE ? "fetching its packages"
                                              : "using it",
                 o->command == CMD_RESTORE || o->command == CMD_BASELINE
                     ? " (--allow-unverified would)"
                     : "");
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

/* ------------------------------------------------------------------------- */
/* Running unattended                                                        */
/* ------------------------------------------------------------------------- */

/* Where --quiesce's lock is: one capture at a time on a machine, since two
 * would pause and resume the same databases under each other. */
#define QUIESCE_LOCK_DIR  "/run/restate"
#define QUIESCE_LOCK_FILE QUIESCE_LOCK_DIR "/capture.lock"

/*
 * Takes the machine's capture lock, without waiting: the descriptor, which
 * holds it until it is closed; -1 with *busy set if another capture has it;
 * -1 without, if there is nowhere to keep one (no /run, or not root), in
 * which case the capture goes ahead -- the lock guards the hooks, and they
 * need root to run anyway.
 */
static int quiesce_lock(bool *busy)
{
    int fd;

    *busy = false;
    if (mkdir(QUIESCE_LOCK_DIR, 0700) != 0 && errno != EEXIST)
    {
        return -1;
    }
    fd = open(QUIESCE_LOCK_FILE, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0)
    {
        *busy = errno == EWOULDBLOCK;
        (void)close(fd);
        return -1;
    }
    return fd;
}

static const char *status_word(int status)
{
    switch (status)
    {
    case RESTATE_EXIT_OK:
        return "ok";
    case RESTATE_EXIT_DIFFERENT:
        return "different";
    case RESTATE_EXIT_INCOMPLETE:
        return "incomplete";
    case RESTATE_EXIT_UNVERIFIED:
        return "unverified";
    case RESTATE_EXIT_BUSY:
        return "busy";
    default:
        return "failed";
    }
}

/*
 * With --syslog, how the run ended, as one line in the system log a
 * monitoring system can match on: "restate capture: status=ok exit=0 ...",
 * then `fmt`'s counts as more key=value pairs. A warning for an incomplete
 * run, an error for one that failed.
 */
static void log_outcome(const struct rs_options *o, int status, time_t began, const char *fmt,
                        ...) RESTATE_PRINTF(4, 5);

static void log_outcome(const struct rs_options *o, int status, time_t began, const char *fmt,
                        ...)
{
    va_list ap;
    char   *rest;
    int     priority = LOG_ERR;

    if (!o->log_outcome)
    {
        return;
    }
    va_start(ap, fmt);
    rest = rs_xvasprintf(fmt, ap);
    va_end(ap);
    if (status == RESTATE_EXIT_OK || status == RESTATE_EXIT_DIFFERENT)
    {
        priority = LOG_INFO;
    } else if (status == RESTATE_EXIT_INCOMPLETE || status == RESTATE_EXIT_BUSY)
    {
        priority = LOG_WARNING;
    }
    syslog(priority, "restate %s: status=%s exit=%d seconds=%lld%s%s",
           rs_command_name(o->command), status_word(status), status,
           (long long)(time(NULL) - began), rest[0] ? " " : "", rest);
    free(rest);
}

/* A size as people read it: "1.4 GiB". */
static void human_size(struct rs_buf *b, uint64_t bytes)
{
    static const char *const units[] = { "bytes", "KiB", "MiB", "GiB", "TiB", "PiB" };
    double                   v = (double)bytes;
    size_t                   u = 0;

    while (v >= 1024.0 && u + 1 < sizeof(units) / sizeof(units[0]))
    {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
    {
        rs_buf_addf(b, "%" PRIu64 " bytes", bytes);
    } else
    {
        rs_buf_addf(b, "%.1f %s", v, units[u]);
    }
}

/* ------------------------------------------------------------------------- */
/* Capturing                                                                 */
/* ------------------------------------------------------------------------- */

/* A capture into an image file. */
static int capture_image(const struct rs_options *o, struct rs_scan_stats *st)
{
    struct rs_index        m;
    struct rs_image_writer image;
    struct sink            sink;
    struct rs_buf          err;
    bool                   ok;

    rs_buf_init(&err);
    if (!rs_image_begin(&image, o->output, &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    image.recipients = o->recipients;
    image.nrecipients = o->nrecipients;
    image.sign_with = o->sign_with;
    memset(&sink, 0, sizeof(sink));
    sink.image = &image;
    if (!run_scan(o, o->root ? o->root : "/", true, &sink, &m, st, NULL))
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
    scan_summary(o, st);
    return st->unreadable > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

/*
 * The newest snapshot's index, for an incremental run, if it is of the same
 * tree: a file at the same path under another root is another file, however
 * alike its size and times.
 */
static bool last_capture(const struct rs_options *o, struct rs_repo *r, const char *root,
                         struct rs_index *prev)
{
    struct rs_buf err;
    char         *last;
    char         *here = realpath(root, NULL); /* Flawfinder: ignore */
    bool          ok;

    rs_index_init(prev);
    rs_buf_init(&err);
    last = rs_repo_resolve(r, NULL, &err);
    rs_buf_reset(&err);
    ok = last && rs_repo_load_index_cached(r, last, prev, &err);
    if (last && !ok)
    {
        rs_warn("%s; every file is read again", err.data);
    }
    ok = ok && here && prev->root && strcmp(prev->root, here) == 0;
    if (ok && o->verbose)
    {
        rs_warn("files unchanged since %s" RS_REPO_SEP "%s are not read again",
                rs_repo_dir(r), last);
    }
    if (!ok)
    {
        rs_index_free(prev);
        rs_index_init(prev);
    }
    free(last);
    free(here);
    rs_buf_free(&err);
    return ok;
}

/* A capture into a repository: a new snapshot, with only what is new
 * stored, and what has not changed since the last one not read at all. */
static int capture_repo(const struct rs_options *o, struct rs_scan_stats *st, char **where)
{
    const char            *root = o->root ? o->root : "/";
    struct rs_repo        *r;
    struct rs_repo_writer *w;
    struct rs_repo_written done;
    struct rs_index        m;
    struct rs_index        prev;
    struct sink            sink;
    struct rs_buf          err;
    bool                   busy;
    bool                   ok;

    rs_buf_init(&err);
    r = rs_repo_open(o->output, RS_REPO_WRITE, &busy, &err);
    if (!r)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return busy ? RESTATE_EXIT_BUSY : RESTATE_EXIT_TROUBLE;
    }
    rs_repo_set_recipients(r, o->recipients, o->nrecipients);
    w = rs_repo_writer_begin(r, &err);
    if (!w)
    {
        rs_error("%s", err.data);
        rs_repo_close(r);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    memset(&sink, 0, sizeof(sink));
    sink.prev = last_capture(o, r, root, &prev) ? &prev : NULL;
    sink.repo = w;
    ok = run_scan(o, root, true, &sink, &m, st, NULL);
    if (!ok)
    {
        rs_repo_writer_abort(w);
    } else
    {
        ok = rs_repo_writer_finish(w, &m, o->sign_with, &done, &err);
        if (!ok)
        {
            rs_error("%s", err.data);
        }
    }
    rs_index_free(&prev);
    rs_index_free(&m);
    if (ok)
    {
        *where = rs_xasprintf("%s" RS_REPO_SEP "%s", o->output, done.name);
        if (!o->quiet)
        {
            struct rs_buf size;

            rs_buf_init(&size);
            human_size(&size, done.bytes);
            (void)fflush(stdout);
            (void)fprintf(stderr, "restate: snapshot %s: %s new to the repository, from %"
                          PRIu64 " files; %" PRIu64 " files unchanged since the last snapshot "
                          "were not read\n", *where, size.data, done.objects, st->reused);
            rs_buf_free(&size);
            if (o->sign_with)
            {
                say_signer("signed by", &done.signer);
            }
        }
        free(done.name);
    }
    rs_repo_close(r);
    rs_buf_free(&err);
    if (!ok)
    {
        return RESTATE_EXIT_TROUBLE;
    }
    scan_summary(o, st);
    return st->unreadable > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

int rs_cmd_capture(const struct rs_options *o)
{
    struct rs_scan_stats st;
    time_t               began = time(NULL);
    char                *where = NULL;
    size_t               k;
    int                  lock = -1;
    int                  status;
    bool                 busy = false;

    memset(&st, 0, sizeof(st));
    if (!o->output || strcmp(o->output, "-") == 0)
    {
        rs_error("capture writes an image to a file, or a snapshot to a repository: give one "
                 "with -o FILE.tar or -o REPOSITORY");
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "%s", "");
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->no_hash)
    {
        /* Every kept file is read to store it, so its digest costs nothing
         * more, and an image whose content cannot be checked is worse. */
        rs_warn("--no-hash is ignored by capture: kept files are always hashed");
    }
    /* Before the scan, which can take a long time to find out at the end. */
    status = RESTATE_EXIT_OK;
    if (o->nrecipients == 0 && rs_repo_is(o->output) && rs_repo_dir_encrypted(o->output))
    {
        rs_error("%s is an encrypted repository: give the public keys to encrypt to with "
                 "--encrypt-to", o->output);
        status = RESTATE_EXIT_TROUBLE;
    } else if (o->nrecipients > 0 && rs_repo_is(o->output) && !rs_repo_dir_encrypted(o->output))
    {
        rs_error("--encrypt-to: %s is a repository that is not encrypted; make an encrypted one "
                 "with restate init --encrypt-to KEYFILE DIR", o->output);
        status = RESTATE_EXIT_TROUBLE;
    } else if (o->nrecipients > 0 && !rs_program_path(RS_PROG_GPG))
    {
        rs_error("--encrypt-to needs gpg, which is not installed (or not owned by root)");
        status = RESTATE_EXIT_TROUBLE;
    }
    if (status == RESTATE_EXIT_OK && o->sign_with && !signing_possible(o->sign_with))
    {
        status = RESTATE_EXIT_TROUBLE;
    }
    for (k = 0; status == RESTATE_EXIT_OK && k < o->nrecipients; k++)
    {
        /* Opened, not access()ed: the question is whether this process can
         * read it, which only opening it answers. gpg opens it again later. */
        int fd = open(o->recipients[k], O_RDONLY | O_CLOEXEC);

        if (fd < 0)
        {
            rs_error("--encrypt-to %s: %s", o->recipients[k], strerror(errno));
            status = RESTATE_EXIT_TROUBLE;
        } else
        {
            (void)close(fd);
        }
    }
    if (status == RESTATE_EXIT_OK && o->quiesce)
    {
        lock = quiesce_lock(&busy);
        if (busy)
        {
            rs_error("another capture with --quiesce is running on this machine (%s); try again "
                     "when it is done", QUIESCE_LOCK_FILE);
            status = RESTATE_EXIT_BUSY;
        }
    }
    if (status == RESTATE_EXIT_OK)
    {
        status = rs_repo_is(o->output) ? capture_repo(o, &st, &where) : capture_image(o, &st);
    }
    if (lock >= 0)
    {
        (void)close(lock);
    }
    log_outcome(o, status, began, "output=%s paths=%" PRIu64 " kept=%" PRIu64 " read=%" PRIu64
                " reused=%" PRIu64 " unreadable=%" PRIu64, where ? where : o->output,
                st.recorded, st.stored, st.bytes_hashed, st.reused, st.unreadable);
    free(where);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Repositories                                                              */
/* ------------------------------------------------------------------------- */

/* The keys to encrypt to can be read, and gpg is there to use them. */
static bool recipients_usable(const struct rs_options *o)
{
    size_t k;

    if (o->nrecipients > 0 && !rs_program_path(RS_PROG_GPG))
    {
        rs_error("--encrypt-to needs gpg, which is not installed (or not owned by root)");
        return false;
    }
    for (k = 0; k < o->nrecipients; k++)
    {
        int fd = open(o->recipients[k], O_RDONLY | O_CLOEXEC);

        if (fd < 0)
        {
            rs_error("--encrypt-to %s: %s", o->recipients[k], strerror(errno));
            return false;
        }
        (void)close(fd);
    }
    return true;
}

int rs_cmd_init(const struct rs_options *o)
{
    struct rs_buf err;

    if (!recipients_usable(o))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&err);
    if (!rs_repo_init(o->args[0], o->nrecipients > 0, &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    if (!o->quiet && o->nrecipients > 0)
    {
        (void)fprintf(stderr, "restate: made the encrypted repository %s; capture into it with "
                      "restate capture -o %s --encrypt-to KEYFILE, giving the keys each time\n",
                      o->args[0], o->args[0]);
    } else if (!o->quiet)
    {
        (void)fprintf(stderr, "restate: made the repository %s; capture into it with "
                      "restate capture -o %s\n", o->args[0], o->args[0]);
    }
    return RESTATE_EXIT_OK;
}

int rs_cmd_snapshots(const struct rs_options *o)
{
    struct rs_repo *r;
    struct rs_buf   err;
    struct rs_buf   text;
    struct output   out;
    char          **names;
    size_t          n;
    size_t          i;
    bool            busy;
    bool            ok;

    rs_buf_init(&err);
    r = rs_repo_open(o->args[0], RS_REPO_LOOK, &busy, &err);
    if (!r)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    names = rs_repo_snapshots(r, &n);
    rs_buf_init(&text);
    for (i = 0; i < n; i++)
    {
        struct rs_jval        info;
        struct rs_buf         sig;
        struct rs_buf         gz;
        uint64_t              files = 0;
        uint64_t              bytes = 0;
        uint64_t              fresh = 0;

        rs_buf_reset(&err);
        rs_buf_init(&sig);
        rs_buf_init(&gz);
        (void)rs_repo_index_bytes(r, names[i], &gz, &sig, &err);
        rs_buf_reset(&err);
        if (rs_repo_info(r, names[i], &info, &err))
        {
            const struct rs_jval *v;

            (void)((v = rs_jobject_get(&info, "files")) && rs_jval_u64(v, &files));
            (void)((v = rs_jobject_get(&info, "bytes")) && rs_jval_u64(v, &bytes));
            (void)((v = rs_jobject_get(&info, "new_bytes")) && rs_jval_u64(v, &fresh));
            rs_buf_addf(&text, "%s  %s  %" PRIu64 " files, ", names[i],
                        rs_jobject_str(&info, "host") ? rs_jobject_str(&info, "host") : "?",
                        files);
            human_size(&text, bytes);
            rs_buf_addstr(&text, "; ");
            human_size(&text, fresh);
            rs_buf_addf(&text, " new%s\n", sig.len > 0 ? "; signed" : "");
            rs_jval_free(&info);
        } else
        {
            rs_buf_addf(&text, "%s  (no summary: %s)\n", names[i], err.data);
        }
        rs_buf_free(&sig);
        rs_buf_free(&gz);
    }
    rs_repo_free_names(names, n);
    rs_repo_close(r);
    rs_buf_free(&err);
    if (!output_open(o, &out))
    {
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = text.len == 0 || fwrite(text.data, 1, text.len, out.fp) == text.len;
    if (!ok)
    {
        rs_error("%s: %s", out.tmp ? out.tmp : "standard output", strerror(errno));
    }
    ok = output_close(&out, ok);
    rs_buf_free(&text);
    return ok ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
}

int rs_cmd_prune(const struct rs_options *o)
{
    struct rs_repo_keep   keep;
    struct rs_repo_pruned pruned;
    struct rs_repo       *r;
    struct rs_buf         err;
    time_t                began = time(NULL);
    size_t                i;
    bool                  busy;
    bool                  ok;

    keep.last = o->keep_last;
    keep.daily = o->keep_daily;
    keep.weekly = o->keep_weekly;
    keep.monthly = o->keep_monthly;
    if (keep.last + keep.daily + keep.weekly + keep.monthly == 0)
    {
        rs_error("prune: say what to keep, with --keep-last, --keep-daily, --keep-weekly or "
                 "--keep-monthly");
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "repository=%s", o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->nrecipients > 0 && rs_repo_is(o->args[0]) && !rs_repo_dir_encrypted(o->args[0]))
    {
        rs_error("--encrypt-to: %s is a repository that is not encrypted", o->args[0]);
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "repository=%s", o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    if (!recipients_usable(o))
    {
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "repository=%s", o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&err);
    r = rs_repo_open(o->args[0], o->dry_run ? RS_REPO_LOOK : RS_REPO_PRUNE, &busy, &err);
    if (!r)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        log_outcome(o, busy ? RESTATE_EXIT_BUSY : RESTATE_EXIT_TROUBLE, began, "repository=%s",
                    o->args[0]);
        return busy ? RESTATE_EXIT_BUSY : RESTATE_EXIT_TROUBLE;
    }
    rs_repo_set_recipients(r, o->recipients, o->nrecipients);
    ok = rs_repo_prune(r, &keep, o->dry_run, &pruned, &err);
    rs_repo_close(r);
    for (i = 0; !o->quiet && i < pruned.ndropped; i++)
    {
        (void)printf("%s %s\n", o->dry_run ? "would drop" : "dropped", pruned.dropped[i]);
    }
    if (!ok)
    {
        rs_error("%s", err.data);
    } else if (!o->quiet && !o->dry_run)
    {
        struct rs_buf size;

        rs_buf_init(&size);
        human_size(&size, pruned.bytes_freed);
        (void)fflush(stdout);
        (void)fprintf(stderr, "restate: dropped %zu snapshots; removed %zu packs and rewrote %zu, "
                      "freeing %s\n", pruned.ndropped, pruned.packs_removed,
                      pruned.packs_rewritten, size.data);
        if (pruned.packs_left > 0)
        {
            (void)fprintf(stderr, "restate: %zu packs that are mostly content nothing needs were "
                          "left as they are: rewriting them needs the keys to encrypt to "
                          "(--encrypt-to)\n", pruned.packs_left);
        }
        rs_buf_free(&size);
    }
    log_outcome(o, ok ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE, began,
                "repository=%s dropped=%zu packs_removed=%zu packs_rewritten=%zu "
                "bytes_freed=%" PRIu64, o->args[0], pruned.ndropped, pruned.packs_removed,
                pruned.packs_rewritten, pruned.bytes_freed);
    rs_repo_pruned_free(&pruned);
    rs_buf_free(&err);
    return ok ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
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
    if (o->packages && o->command == CMD_DIFF)
    {
        (void)fprintf(stderr, "restate: %zu packages changed, accounting for %zu files; "
                      "otherwise ", d->packages, d->explained);
    } else
    {
        (void)fprintf(stderr, "restate: ");
    }
    (void)fprintf(stderr, "%zu added, %zu deleted, %zu modified\n", d->added, d->deleted,
                  d->modified);
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
    ok = o->packages && o->command == CMD_DIFF ? rs_diff_write_packages(a, b, out.fp, d) : rs_diff_write(a, b, out.fp, d);
    if (!ok)
    {
        rs_error("%s: %s", out.tmp ? out.tmp : "standard output", strerror(errno));
    }
    if (!output_close(&out, ok))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    diff_summary(o, d);
    return (d->added || d->deleted || d->modified || d->packages) ? RESTATE_EXIT_DIFFERENT
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

/*
 * What has changed since a capture, quickly: the walk verify makes, but
 * incremental -- a file whose size, times and inode are what the capture
 * recorded is taken to be unchanged and not read -- so it takes as long as
 * reading what did change.
 */
int rs_cmd_status(const struct rs_options *o)
{
    struct rs_index      recorded;
    struct rs_index      live;
    struct rs_scan_stats st;
    struct rs_diff_stats d;
    struct rs_buf        err;
    struct trust         tr;
    struct sink          sink;
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
    root = o->root ? o->root : (recorded.root ? recorded.root : "/");
    memset(&sink, 0, sizeof(sink));
    sink.prev = &recorded;
    if (!run_scan(o, root, recorded.hashed && !o->no_hash, &sink, &live, &st,
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

int rs_cmd_export(const struct rs_options *o)
{
    struct rs_index        ix;
    struct rs_image_writer iw;
    struct rs_buf          err;
    struct trust           tr;
    size_t                 k;
    int                    status;
    bool                   ok;

    if (!o->output || strcmp(o->output, "-") == 0)
    {
        rs_error("export writes an image to a file: give one with -o FILE.tar");
        return RESTATE_EXIT_TROUBLE;
    }
    if ((o->nrecipients > 0 && !rs_program_path(RS_PROG_GPG)) ||
        (o->sign_with && !signing_possible(o->sign_with)))
    {
        if (o->nrecipients > 0 && !rs_program_path(RS_PROG_GPG))
        {
            rs_error("--encrypt-to needs gpg, which is not installed (or not owned by root)");
        }
        return RESTATE_EXIT_TROUBLE;
    }
    for (k = 0; k < o->nrecipients; k++)
    {
        int fd = open(o->recipients[k], O_RDONLY | O_CLOEXEC);

        if (fd < 0)
        {
            rs_error("--encrypt-to %s: %s", o->recipients[k], strerror(errno));
            return RESTATE_EXIT_TROUBLE;
        }
        (void)close(fd);
    }
    status = trust_check(o, o->args[0], o->ntrusted > 0, &tr);
    if (status != RESTATE_EXIT_OK)
    {
        return status;
    }
    rs_index_init(&ix);
    rs_buf_init(&err);
    ok = rs_index_load(&ix, o->args[0], &err);
    if (!ok)
    {
        rs_error("%s", err.data);
        status = RESTATE_EXIT_TROUBLE;
    } else
    {
        status = trust_matches(o, o->args[0], &tr, &ix);
    }
    if (status == RESTATE_EXIT_OK)
    {
        rs_buf_reset(&err);
        ok = rs_image_begin(&iw, o->output, &err);
        if (ok)
        {
            iw.recipients = o->recipients;
            iw.nrecipients = o->nrecipients;
            iw.sign_with = o->sign_with;
            ok = rs_image_export(o->args[0], &ix, &iw, &err);
        }
        if (!ok)
        {
            rs_error("%s", err.data);
            status = RESTATE_EXIT_TROUBLE;
        } else if (o->sign_with && !o->quiet)
        {
            say_signer("signed by", &iw.signer);
        }
    }
    rs_buf_free(&err);
    rs_index_free(&ix);
    return status;
}

/*
 * The baseline cache restore --packages installs from: the one given, or the
 * default, if it is there -- and only if it is root's and no one else can
 * write it, since what is in it is installed as root.
 */
static const char *baseline_cache(const struct rs_options *o)
{
    const char *cache = o->cache ? o->cache : rs_baseline_default_cache();
    struct stat st;

    if (stat(cache, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        if (o->cache)
        {
            rs_warn("--cache %s: not a directory; the packages are fetched instead", cache);
        }
        return NULL;
    }
    if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    {
        rs_warn("%s: not root's alone, so nothing is installed from it; the packages are "
                "fetched instead", cache);
        return NULL;
    }
    return cache;
}

/* Runs the package script `script`, from a file only root can reach. */
static int run_script(const char *script)
{
    char          dir[] = "/tmp/restate.XXXXXX";
    char         *path;
    struct rs_buf err;
    int           fd;
    int           code = -1;
    bool          ok;

    if (!mkdtemp(dir))
    {
        rs_error("%s: %s", dir, strerror(errno));
        return RESTATE_EXIT_TROUBLE;
    }
    path = rs_xasprintf("%s/packages.sh", dir);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0700);
    ok = fd >= 0 && write(fd, script, strlen(script)) == (ssize_t)strlen(script);
    ok = fd >= 0 && close(fd) == 0 && ok;
    rs_buf_init(&err);
    if (ok)
    {
        char  a0[] = "sh";
        char *argv[3];

        argv[0] = a0;
        argv[1] = path;
        argv[2] = NULL;
        ok = rs_run(RS_PROG_SH, argv, NULL, NULL, &code, &err);
        if (!ok)
        {
            rs_error("the package script could not be run: %s", err.data);
        }
    } else
    {
        rs_error("%s: %s", path, strerror(errno));
    }
    (void)unlink(path);
    (void)rmdir(dir);
    free(path);
    rs_buf_free(&err);
    if (!ok)
    {
        return RESTATE_EXIT_TROUBLE;
    }
    if (code != 0)
    {
        rs_warn("the package script ended with status %d; restoring the files anyway", code);
        return RESTATE_EXIT_INCOMPLETE;
    }
    return RESTATE_EXIT_OK;
}

/*
 * restore --packages, before the files: the kit -- /etc/apt and the kept
 * packages -- then the script that installs the packages (reinstall.h).
 * Dry, the script is written out instead, for reading.
 */
static int restore_packages(const struct rs_options *o, const struct rs_index *ix,
                            struct rs_restore_opts *ro)
{
    struct rs_reinstall_opts io;
    struct rs_restore_stats  st;
    struct rs_buf            script;
    struct rs_buf            err;
    char                    *snapshot;
    int                      status;

    if (ix->packages.type != RS_JOBJECT)
    {
        rs_error("%s has no package inventory: it was made by a restate older than 1.1",
                 o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    if (!o->dry_run && strcmp(ro->root, "/") != 0)
    {
        rs_error("--packages installs onto the running system, and --root is %s: restore the "
                 "packages there from a shell inside it (chroot), or leave --packages out",
                 ro->root);
        return RESTATE_EXIT_TROUBLE;
    }
    if (!o->dry_run && geteuid() != 0)
    {
        rs_error("--packages installs packages, which needs root");
        return RESTATE_EXIT_TROUBLE;
    }
    snapshot = o->exact_versions ? rs_repo_snapshot_name(ix->created) : NULL;
    memset(&io, 0, sizeof(io));
    io.snapshot = snapshot;
    io.cache = baseline_cache(o);
    rs_buf_init(&script);
    rs_reinstall_script(&ix->packages, &io, &script);
    free(snapshot);
    if (o->dry_run)
    {
        /* What would be run, to read: on standard output, or -o. */
        return emit(o, &script);
    }
    rs_buf_init(&err);
    ro->kit = true;
    ro->dry_run = false;
    if (!rs_restore(o->args[0], ix, ro, &st, &err))
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_buf_free(&script);
        return RESTATE_EXIT_TROUBLE;
    }
    ro->kit = false;
    rs_buf_free(&err);
    if (!o->quiet)
    {
        (void)fprintf(stderr, "restate: put back the image's apt configuration and kept "
                      "packages (%" PRIu64 " files); now its packages\n", st.files);
    }
    status = run_script(script.data ? script.data : "");
    rs_buf_free(&script);
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
    int                     packages = RESTATE_EXIT_OK;
    const char            **excludes = NULL;
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
    ro.verbose = o->verbose;
    ro.numeric_owner = o->numeric_owner;
    if (o->check_first && !o->dry_run)
    {
        /* Read through once, checking everything and writing nothing, so a
         * damaged image is refused whole rather than put back as far as it
         * is whole. */
        ro.dry_run = true;
        ro.quiet = true;
        ok = rs_restore(o->args[0], &ix, &ro, &st, &err);
        if (ok && st.refused + st.missing > 0)
        {
            rs_buf_addf(&err, "%s: %" PRIu64 " files are not what its index says and %" PRIu64
                        " are missing from it", o->args[0], st.refused, st.missing);
            ok = false;
        }
        if (!ok)
        {
            rs_error("%s; nothing was written (--check-first)", err.data);
            rs_buf_free(&err);
            rs_index_free(&ix);
            return RESTATE_EXIT_TROUBLE;
        }
        if (!o->quiet)
        {
            (void)fprintf(stderr, "restate: %s checked: every file is what its index says; "
                          "putting it back\n", o->args[0]);
        }
        ro.quiet = false;
    }
    if (o->packages)
    {
        packages = restore_packages(o, &ix, &ro);
        if (packages != RESTATE_EXIT_OK && packages != RESTATE_EXIT_INCOMPLETE)
        {
            rs_buf_free(&err);
            rs_index_free(&ix);
            return packages;
        }
    }
    ro.dry_run = o->dry_run;
    ro.kit = false;
    if (o->packages)
    {
        /* Which packages were installed by hand: the script has just made
         * that what the old machine had, for the packages there are now. */
        excludes = rs_xcalloc(o->nexcludes + 1, sizeof(*excludes));
        if (o->nexcludes > 0)
        {
            memcpy(excludes, o->excludes, o->nexcludes * sizeof(*excludes));
        }
        excludes[o->nexcludes] = "/var/lib/apt/extended_states";
        ro.exclude = excludes;
        ro.nexclude = o->nexcludes + 1;
    }
    ok = rs_restore(o->args[0], &ix, &ro, &st, &err);
    free(excludes);
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
            (void)fprintf(stderr, "restate: left out %" PRIu64 " paths (%s)\n", st.excluded,
                          o->packages ? "--exclude, and apt's record of what was installed by "
                                        "hand, which --packages set"
                                      : "--exclude");
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
    return packages;
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
                         bool *old_image, bool *knows_trust, char **created)
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
            if (created && ix.created)
            {
                *created = rs_xstrdup(ix.created);
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
        if (!load_machine(image, &machine, NULL, NULL, NULL, NULL))
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

/*
 * The package baseline: what `baseline fetch` would fetch, or fetching it.
 * From an image, its inventory -- whose packages and keys restore installs as
 * root, so it is held to restore's rule: signed by a --trusted-key, or
 * --allow-unverified -- and otherwise this system's own.
 */
int rs_cmd_baseline(const struct rs_options *o)
{
    bool                     fetch = o->nargs > 0 && strcmp(o->args[0], "fetch") == 0;
    const char              *image = o->nargs > (fetch ? 1u : 0u) ? o->args[fetch ? 1 : 0] : NULL;
    struct rs_jval           packages;
    struct rs_baseline_stats st;
    struct rs_baseline_opts  bo;
    struct rs_buf            err;
    struct trust             tr;
    char                    *snapshot;
    int                      status;

    if (o->nargs == 2 && !fetch)
    {
        rs_error("usage: restate baseline [fetch] [IMAGE]");
        return RESTATE_EXIT_TROUBLE;
    }
    memset(&packages, 0, sizeof(packages));
    rs_buf_init(&err);
    if (image)
    {
        struct rs_index ix;

        status = trust_check(o, image, fetch || o->ntrusted > 0, &tr);
        if (status != RESTATE_EXIT_OK)
        {
            rs_buf_free(&err);
            return status;
        }
        rs_index_init(&ix);
        if (!rs_index_load(&ix, image, &err))
        {
            rs_error("%s", err.data);
            rs_buf_free(&err);
            rs_index_free(&ix);
            return RESTATE_EXIT_TROUBLE;
        }
        status = trust_matches(o, image, &tr, &ix);
        if (status == RESTATE_EXIT_OK && ix.packages.type != RS_JOBJECT)
        {
            rs_error("%s has no package inventory: it was made by a restate older than 1.1",
                     image);
            status = RESTATE_EXIT_TROUBLE;
        }
        if (status != RESTATE_EXIT_OK)
        {
            rs_buf_free(&err);
            rs_index_free(&ix);
            return status;
        }
        rs_jval_copy(&packages, &ix.packages);
        snapshot = rs_repo_snapshot_name(ix.created);
        rs_index_free(&ix);
    } else
    {
        rs_packages_describe(o->root ? o->root : "/", &packages);
        snapshot = rs_repo_snapshot_name(NULL);
    }
    if (!rs_jobject_get(&packages, "apt"))
    {
        rs_error("%s has no apt packages to fetch", image ? image : "this system");
        rs_jval_free(&packages);
        rs_buf_free(&err);
        free(snapshot);
        return RESTATE_EXIT_TROUBLE;
    }
    if (!fetch)
    {
        struct rs_buf text;

        rs_buf_init(&text);
        rs_baseline_list(&packages, o->cache, &text, &st);
        rs_jval_free(&packages);
        rs_buf_free(&err);
        free(snapshot);
        status = emit(o, &text);
        if (status == RESTATE_EXIT_OK && !o->quiet)
        {
            (void)fprintf(stderr, "restate: %zu packages in the baseline, %zu of them cached in "
                          "%s; %zu installed from .deb files no repository has\n", st.wanted,
                          st.cached, o->cache ? o->cache : rs_baseline_default_cache(), st.local);
        }
        return status;
    }
    memset(&bo, 0, sizeof(bo));
    bo.cache = o->cache;
    bo.snapshot = snapshot;
    bo.quiet = o->quiet;
    if (!rs_baseline_fetch(&packages, &bo, &st, &err))
    {
        rs_error("%s", err.data);
        status = RESTATE_EXIT_TROUBLE;
    } else
    {
        if (!o->quiet)
        {
            (void)fprintf(stderr, "restate: %zu packages in the baseline: %zu fetched (%" PRIu64
                          " bytes, %zu of them from an archive's snapshot), %zu already in %s; %zu "
                          "could not be had\n", st.wanted, st.fetched, st.bytes, st.snapshot,
                          st.cached, o->cache ? o->cache : rs_baseline_default_cache(),
                          st.missing);
            if (st.local > 0)
            {
                (void)fprintf(stderr, "restate: %zu were installed from .deb files no repository "
                              "has: only an image can keep those (capture "
                              "--keep-local-packages)\n", st.local);
            }
        }
        status = st.missing > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
    }
    rs_jval_free(&packages);
    rs_buf_free(&err);
    free(snapshot);
    return status;
}

/*
 * Whether the build files can be made from `image`: not from a snapshot in a
 * repository, which is no file their commands could unpack -- it is exported
 * as an image first, and they are made from that.
 */
static bool from_a_file(const char *image)
{
    char *dir;
    char *name;

    if (!image || !rs_repo_ref(image, &dir, &name))
    {
        return true;
    }
    rs_error("%s is a snapshot in a repository, and the commands a build sheet or autoinstall "
             "file writes unpack an image's file: export it first (restate export %s -o "
             "FILE.tar), and make them from that", image, image);
    free(dir);
    free(name);
    return false;
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
                        struct rs_jval *packages, bool *old_image, bool *knows_trust,
                        char **created)
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
        return load_machine(image, machine, packages, old_image, knows_trust, created);
    }
    rs_machine_describe("/", o->root ? o->root : "/", machine);
    if (packages)
    {
        rs_packages_describe(o->root ? o->root : "/", packages);
    }
    return true;
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
        check_sources(o, o->root ? o->root : "/", &packages, false);
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

/* --firmware changes the partitions, which only a rebuild elsewhere renumbers. */
static bool firmware_ok(const struct rs_options *o)
{
    if (o->firmware && !o->target)
    {
        rs_error("--firmware needs --target vm or --target metal: rebuilt as the same "
                 "machine, it boots as that machine did");
        return false;
    }
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
    char                *created = NULL;
    char                *snapshot;
    bool                 ok;

    if (!from_a_file(image) || !firmware_ok(o))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    if (!machine_for(o, image, &machine, &packages, &old_image, &knows, &created) ||
        !trust_for(o, knows, false, &trust, &keyring))
    {
        rs_jval_free(&machine);
        rs_jval_free(&packages);
        free(created);
        return RESTATE_EXIT_TROUBLE;
    }
    snapshot = o->exact_versions ? rs_repo_snapshot_name(created) : NULL;
    memset(&so, 0, sizeof(so));
    so.snapshot = snapshot;
    so.trust = trust;
    so.old_image = old_image;
    so.target = target_of(o);
    so.firmware = o->firmware;
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
    free(created);
    free(snapshot);
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
    char               *created = NULL;
    char               *snapshot;
    bool                ok;

    if (!from_a_file(image) || !firmware_ok(o))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    if (!machine_for(o, image, &machine, &packages, &old_image, &knows, &created) ||
        !trust_for(o, knows, true, &trust, &keyring))
    {
        rs_jval_free(&machine);
        rs_jval_free(&packages);
        free(created);
        return RESTATE_EXIT_TROUBLE;
    }
    snapshot = o->exact_versions ? rs_repo_snapshot_name(created) : NULL;
    memset(&ao, 0, sizeof(ao));
    ao.snapshot = snapshot;
    ao.trust = trust;
    ao.trust_keyring = keyring;
    ao.old_image = old_image;
    ao.target = target_of(o);
    ao.firmware = o->firmware;
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
    free(created);
    free(snapshot);
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
    case CMD_BASELINE:
        return rs_cmd_baseline(o);
    case CMD_BUILDSHEET:
        return rs_cmd_buildsheet(o);
    case CMD_AUTOINSTALL:
        return rs_cmd_autoinstall(o);
    case CMD_CLASSIFY:
        return rs_cmd_classify(o);
    case CMD_RULES:
        return rs_cmd_rules(o);
    case CMD_INIT:
        return rs_cmd_init(o);
    case CMD_SNAPSHOTS:
        return rs_cmd_snapshots(o);
    case CMD_PRUNE:
        return rs_cmd_prune(o);
    case CMD_EXPORT:
        return rs_cmd_export(o);
    case CMD_STATUS:
        return rs_cmd_status(o);
    case CMD_NONE:
    case CMD_COUNT:
    default:
        rs_error("no command given");
        return RESTATE_EXIT_TROUBLE;
    }
}
