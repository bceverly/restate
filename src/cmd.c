/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "cmd.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "autoinstall.h"
#include "baseline.h"
#include "buildsheet.h"
#include "clones.h"
#include "diff.h"
#include "fsflags.h"
#include "fstab.h"
#include "hooks.h"
#include "identity.h"
#include "image.h"
#include "index.h"
#include "installer.h"
#include "jobs.h"
#include "live.h"
#include "machine.h"
#include "meta.h"
#include "packages.h"
#include "pgp.h"
#include "progress.h"
#include "reinstall.h"
#include "repo.h"
#include "restore.h"
#include "result.h"
#include "rules.h"
#include "run.h"
#include "scan.h"
#include "sources.h"

/* The paths a restore's result names, of all it puts back. */
#define RESTORE_PLAN_MAX 1000

/* A machine description read on its own is refused beyond this size. */
#define MACHINE_MAX ((size_t)16 * 1024 * 1024)

/* ------------------------------------------------------------------------- */
/* Rules                                                                     */
/* ------------------------------------------------------------------------- */

/* The rules the capture recorded, `o->classified`, if verify or status has
 * them; otherwise the built-in rules for the chosen system, then every
 * --rules file in the order given. `os_used` is set to the system whose
 * built-ins were taken. */
static bool load_rules(const struct rs_options *o, struct rs_rules *rules,
                       const char **os_used)
{
    struct rs_buf err;
    size_t        i;

    rs_rules_init(rules);
    *os_used = o->os ? o->os : rs_rules_host_os();
    if (o->classified)
    {
        if (!rs_rules_from_json(rules, o->classified, "the capture's rules"))
        {
            rs_error("the index's classification is not a list of rules; give --rules (or "
                     "--no-default-rules) to classify by instead");
            rs_rules_free(rules);
            return false;
        }
        return true;
    }
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

/* How a scan classifies, as the index records it (index.h): every rule in
 * effect, built-in or read, so that verify and status classify by exactly
 * these whatever restate later runs them. Left out (null) if a pattern is
 * not UTF-8, which the index's JSON cannot hold as a string. */
static void record_classification(const struct rs_options *o, const struct rs_rules *rules,
                                  struct rs_jval *out)
{
    struct rs_jval *list;
    size_t          i;

    for (i = 0; i < rules->count; i++)
    {
        if (!rs_utf8_valid(rules->rules[i].pattern, strlen(rules->rules[i].pattern)))
        {
            return;
        }
    }
    rs_jval_set_object(out);
    list = rs_jobj_add(out, "rules");
    rs_jval_set_array(list);
    for (i = 0; i < rules->count; i++)
    {
        struct rs_jval *pair = rs_jarr_add(list);

        rs_jval_set_array(pair);
        rs_jval_set_string(rs_jarr_add(pair), rs_class_name(rules->rules[i].cls));
        rs_jval_set_string(rs_jarr_add(pair), rules->rules[i].pattern);
    }
    rs_jobj_bool(out, "all", o->all);
    rs_jobj_bool(out, "one_file_system", o->one_fs);
    rs_jobj_bool(out, "rules_only", o->rules_only);
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
/*
 * gcc's analyzer loses track of a FILE held in a struct output across the
 * call that closes it, and reports a leak at the end of each function that
 * holds one -- a leak that is not there. Said around those functions alone;
 * a real leak there is still found at run time, by ASan, LeakSanitizer and
 * valgrind, which the tests all run under.
 */
#if defined(__GNUC__) && !defined(__clang__)
#define OUTPUT_HELD_BEGIN \
    _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wanalyzer-malloc-leak\"")
#define OUTPUT_HELD_END _Pragma("GCC diagnostic pop")
#else
#define OUTPUT_HELD_BEGIN
#define OUTPUT_HELD_END
#endif

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
OUTPUT_HELD_BEGIN
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

OUTPUT_HELD_END

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
                          " identity, %" PRIu64 " baseline, %" PRIu64 " expendable); kept the "
                          "content of %" PRIu64 "\n",
                  st->recorded, st->by_class[RS_CLASS_STATE], st->by_class[RS_CLASS_IDENTITY],
                  st->by_class[RS_CLASS_BASELINE], st->by_class[RS_CLASS_EXPENDABLE], st->stored);
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
    if (st->pause_failed > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " of the %" PRIu64 " things paused were not "
                      "paused or not resumed (see above); the capture is incomplete\n",
                      st->pause_failed, st->paused);
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
    struct rs_live       *live;     /* what was found, and matters, then what was named */
    size_t                nlive;
    bool                 *declared; /* named by --quiesce-with, not found */
    size_t               *covered;  /* 1 + the named one whose paths hold all of its */
    char                **hooks;    /* each one's hook, NULL for none */
    char                **dumps;    /* each one's dump directory, or NULL */
    struct rs_scan_group *groups;   /* one per thing with a hook and paths */
    size_t               *of;       /* the thing each group is */
    size_t                ngroups;
    const char         ***paths;    /* each group's paths */
    size_t               *whole;    /* the things paused for the whole walk */
    size_t                nwhole;
    time_t               *paused_at;
    bool                 *pause_ok;
    char                **said;     /* why a pause or a resume failed */
    uint64_t              paused;
    uint64_t              failed;
    unsigned              depth;    /* signals are held while anything is paused */
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

/* Whether something of the kind `kind` was found running, and has a hook. */
static bool found_kind(const struct quiesce *q, size_t n, const char *kind)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        if (strcmp(q->live[i].kind, kind) == 0 && q->hooks[i])
        {
            return true;
        }
    }
    return false;
}

/*
 * The named thing whose paths hold every one of the found thing `l`'s, as
 * 1 + its index; 0 for none (rs_live_within).
 */
static size_t covered_by(const struct quiesce *q, size_t found, const struct rs_live *l)
{
    size_t j;

    for (j = found; j < q->nlive; j++)
    {
        if (rs_live_within(l, &q->live[j]))
        {
            return j + 1;
        }
    }
    return 0;
}

/*
 * The live things whose files the walk would copy: named, with the command
 * that would stop each, when not quiescing; given a hook and a dump
 * directory, and left to the end of the walk, when quiescing. Then each hook
 * --quiesce-with names, with the paths it says it covers, or for the whole
 * walk if it names none; and the same, when quiescing, for each program
 * running that has a hook of its name in RS_HOOKS_SITE_DIR. False, having
 * said why, if a named hook is not there to run.
 */
static bool quiesce_plan(const struct rs_options *o, const struct rs_rules *rules,
                         const char *root, struct quiesce *q)
{
    struct rs_live *all = NULL;
    struct rs_live *progs = NULL;
    size_t          n = 0;
    size_t          nprogs = 0;
    size_t          found;
    size_t          i;
    size_t          k;
    bool            ok = true;

    memset(q, 0, sizeof(*q));
    rs_live_detect("/proc", &all, &n);
    if (o->quiesce)
    {
        rs_live_programs("/proc", &progs, &nprogs);
    }
    q->live = rs_xcalloc(n + o->nquiesce_with + nprogs + 1, sizeof(*q->live));
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
    found = q->nlive;
    n = found + o->nquiesce_with + nprogs + 1;
    q->declared = rs_xcalloc(n, sizeof(*q->declared));
    q->covered = rs_xcalloc(n, sizeof(*q->covered));
    q->hooks = rs_xcalloc(n, sizeof(*q->hooks));
    q->dumps = rs_xcalloc(n, sizeof(*q->dumps));
    q->groups = rs_xcalloc(n, sizeof(*q->groups));
    q->of = rs_xcalloc(n, sizeof(*q->of));
    q->paths = rs_xcalloc(n, sizeof(*q->paths));
    q->whole = rs_xcalloc(n, sizeof(*q->whole));
    q->paused_at = rs_xcalloc(n, sizeof(*q->paused_at));
    q->pause_ok = rs_xcalloc(n, sizeof(*q->pause_ok));
    q->said = rs_xcalloc(n, sizeof(*q->said));
    for (i = 0; i < found; i++)
    {
        if (o->quiesce)
        {
            q->hooks[i] = rs_hook_find(q->live[i].kind);
        }
    }
    /* What --quiesce-with names, unless --quiesce pauses it already. */
    for (k = 0; k < o->nquiesce_with; k++)
    {
        const char     *name = o->quiesce_with[k];
        struct rs_live *l;
        struct rs_buf   err;
        char           *hook;

        if (found_kind(q, found, name))
        {
            continue;
        }
        hook = rs_hook_find(name);
        if (!hook)
        {
            rs_error("--quiesce-with %s: there is no hook by that name that restate would run "
                     "(%s/%s, root's and writable by no one else, or one restate ships)", name,
                     RS_HOOKS_SITE_DIR, name);
            ok = false;
            continue;
        }
        /* Named by a policy that every host shares, it may have nothing to
         * pause here: so it says, and is not run. */
        if (rs_hook_present(hook, name) == RS_HOOK_ABSENT)
        {
            tell(o, LOG_NOTICE, "--quiesce-with %s: %s says there is none on this host to pause",
                 name, hook);
            free(hook);
            continue;
        }
        l = &q->live[q->nlive];
        memset(l, 0, sizeof(*l));
        l->kind = name;
        l->name = rs_xstrdup(name);
        rs_buf_init(&err);
        if (!rs_hook_paths(hook, name, &l->paths, &l->npaths, &err))
        {
            rs_warn("%s paths: %s; it is paused for the whole walk", hook, err.data);
        }
        rs_buf_free(&err);
        q->hooks[q->nlive] = hook;
        q->declared[q->nlive] = true;
        q->nlive++;
    }
    /* A program no kind covers, with a hook of its name in the site's own
     * directory: paused as one --quiesce-with names, unless it is named. */
    for (k = 0; k < nprogs; k++)
    {
        struct rs_live *l;
        struct rs_buf   err;
        char           *hook = found_kind(q, q->nlive, progs[k].name)
                                   ? NULL
                                   : rs_hook_for_program(progs[k].name);

        if (!hook)
        {
            free(progs[k].name);
            continue;
        }
        l = &q->live[q->nlive];
        *l = progs[k];
        rs_buf_init(&err);
        if (!rs_hook_paths(hook, l->name, &l->paths, &l->npaths, &err))
        {
            rs_warn("%s paths: %s; it is paused for the whole walk", hook, err.data);
        }
        rs_buf_free(&err);
        q->hooks[q->nlive] = hook;
        q->declared[q->nlive] = true;
        q->nlive++;
    }
    free(progs);
    for (i = 0; i < found; i++)
    {
        q->covered[i] = covered_by(q, found, &q->live[i]);
        if (q->covered[i])
        {
            free(q->hooks[i]);
            q->hooks[i] = NULL;
        }
    }
    for (i = 0; i < q->nlive; i++)
    {
        const struct rs_live *l = &q->live[i];
        struct rs_buf         what;
        struct rs_buf         hint;
        struct rs_buf         err;

        if (q->covered[i])
        {
            tell(o, LOG_NOTICE, "%s %s is %s's own, and paused with it", rs_live_what(l), l->name,
                 q->live[q->covered[i] - 1].name);
            continue;
        }
        rs_buf_init(&what);
        rs_buf_init(&hint);
        rs_buf_init(&err);
        describe_live(l, &what);
        if (!q->declared[i])
        {
            rs_live_hint(l, &hint);
        }
        if (!q->declared[i] && !o->quiesce)
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
            if (l->npaths == 0)
            {
                /* A hook that names no paths: paused for all of it. */
                q->whole[q->nwhole++] = i;
            } else
            {
                size_t np = 0;

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
        }
        rs_buf_free(&what);
        rs_buf_free(&hint);
        rs_buf_free(&err);
    }
    return ok;
}

static void quiesce_free(struct quiesce *q)
{
    size_t i;

    for (i = 0; i < q->nlive; i++)
    {
        free(q->hooks[i]);
        free(q->dumps[i]);
        free(q->said[i]);
    }
    for (i = 0; i < q->ngroups; i++)
    {
        free(q->paths[i]);
    }
    rs_live_free(q->live, q->nlive);
    free(q->declared);
    free(q->covered);
    free(q->hooks);
    free(q->dumps);
    free(q->groups);
    free(q->of);
    free(q->paths);
    free(q->whole);
    free(q->paused_at);
    free(q->pause_ok);
    free(q->said);
}

struct around_ctx {
    const struct rs_options *o;
    struct quiesce          *q;
};

/* Whether a signal that ends restate came while something was paused. */
static bool interrupted(void)
{
    sigset_t pending;

    return sigpending(&pending) == 0 &&
           (sigismember(&pending, SIGINT) == 1 || sigismember(&pending, SIGTERM) == 1 ||
            sigismember(&pending, SIGHUP) == 1 || sigismember(&pending, SIGQUIT) == 1);
}

/* The signals that end restate, while held through a prune that removes. */
static sigset_t stops_saved;
static bool     stops_held;

/*
 * Holds the signals that would end restate, so that one stops a prune
 * between one removal and the next and its record still follows what went;
 * let_stops lets it through once the result is written.
 */
static void hold_stops(void)
{
    sigset_t held;

    (void)sigemptyset(&held);
    (void)sigaddset(&held, SIGINT);
    (void)sigaddset(&held, SIGTERM);
    (void)sigaddset(&held, SIGHUP);
    (void)sigaddset(&held, SIGQUIT);
    (void)sigprocmask(SIG_BLOCK, &held, &stops_saved);
    stops_held = true;
}

/* The held signal that would end restate, by name. */
static const char *stop_signal(void)
{
    static const int         sigs[] = { SIGTERM, SIGINT, SIGHUP, SIGQUIT };
    static const char *const names[] = { "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT" };
    sigset_t                 pending;
    size_t                   i;

    for (i = 0; sigpending(&pending) == 0 && i < sizeof(sigs) / sizeof(sigs[0]); i++)
    {
        if (sigismember(&pending, sigs[i]) == 1)
        {
            return names[i];
        }
    }
    return "a signal";
}

/* Lets a signal hold_stops held end restate, the way it says. */
static void let_stops(void)
{
    if (stops_held)
    {
        stops_held = false;
        (void)fflush(NULL);
        (void)sigprocmask(SIG_SETMASK, &stops_saved, NULL);
    }
}

/*
 * Pauses the live thing `i`. While anything is paused the signals that would
 * end restate are held, so nothing can stop it between the pause and the
 * resume; a Ctrl-C reaches the hook itself, and once everything is resumed
 * restate goes the way the signal says. False if a signal came meanwhile.
 */
static bool pause_one(const struct around_ctx *a, size_t i)
{
    struct quiesce       *q = a->q;
    const struct rs_live *l = &q->live[i];
    struct rs_buf         err;

    if (q->depth++ == 0)
    {
        (void)sigemptyset(&q->held);
        (void)sigaddset(&q->held, SIGINT);
        (void)sigaddset(&q->held, SIGTERM);
        (void)sigaddset(&q->held, SIGHUP);
        (void)sigaddset(&q->held, SIGQUIT);
        (void)sigprocmask(SIG_BLOCK, &q->held, &q->saved);
    }
    rs_buf_init(&err);
    tell(a->o, LOG_NOTICE, "pausing %s %s", rs_live_what(l), l->name);
    rs_progress_hook(l->name);
    q->paused++;
    q->paused_at[i] = time(NULL);
    q->pause_ok[i] = rs_hook_run(q->hooks[i], "pause", l, q->dumps[i], a->o->quiesce, &err);
    if (!q->pause_ok[i])
    {
        tell(a->o, LOG_WARNING, "%s %s was not paused (%s): its files are copied as they are",
             rs_live_what(l), l->name, err.data);
        q->said[i] = rs_xstrdup(err.data ? err.data : "");
    }
    rs_buf_free(&err);
    return !interrupted();
}

static void resume_one(const struct around_ctx *a, size_t i)
{
    struct quiesce       *q = a->q;
    const struct rs_live *l = &q->live[i];
    struct rs_buf         err;
    bool                  ok;

    rs_buf_init(&err);
    ok = rs_hook_run(q->hooks[i], "resume", l, q->dumps[i], a->o->quiesce, &err);
    if (!ok)
    {
        tell(a->o, LOG_ERR, "%s %s was not resumed, and may still be stopped: %s",
             rs_live_what(l), l->name, err.data);
        free(q->said[i]);
        q->said[i] = rs_xstrdup(err.data ? err.data : "");
    } else
    {
        tell(a->o, LOG_NOTICE, "resumed %s %s", rs_live_what(l), l->name);
    }
    if (!ok || !q->pause_ok[i])
    {
        q->failed++;
    }
    rs_result_quiesce(l->kind, l->name, q->paused_at[i], ok ? time(NULL) : 0,
                      ok && q->pause_ok[i], q->said[i]);
    rs_progress_hook(NULL);
    rs_buf_free(&err);
    if (--q->depth == 0)
    {
        (void)sigprocmask(SIG_SETMASK, &q->saved, NULL);
    }
}

/* The scan's call on each side of a group: pause before, resume after. */
static bool around(const void *ctx, size_t group, bool before)
{
    const struct around_ctx *a = ctx;

    if (before)
    {
        return pause_one(a, a->q->of[group]);
    }
    resume_one(a, a->q->of[group]);
    return true;
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
    struct around_ctx       actx = { o, &q };
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
    memset(&q, 0, sizeof(q));
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
    record_classification(o, &rules, &m->classification);
    /* What is running and writing to files the image keeps: named, or with
     * --quiesce left to the end and paused while it is copied. */
    if (storing && is_live_root(root))
    {
        live = true;
        if (!quiesce_plan(o, &rules, root, &q))
        {
            quiesce_free(&q);
            rs_rules_free(&rules);
            rs_pkgdb_free(&db);
            for (i = 0; i < nkeep; i++)
            {
                free(keep[i]);
            }
            free(keep);
            return false;
        }
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
    /* What is paused for the whole walk, around all of it. */
    ok = true;
    for (i = 0; live && i < q.nwhole; i++)
    {
        ok = pause_one(&actx, q.whole[i]) && ok;
    }
    if (ok)
    {
        ok = rs_scan(&so, m, st, &err);
    } else
    {
        rs_buf_addstr(&err, "interrupted while it paused what it captures");
    }
    for (i = live ? q.nwhole : 0; i-- > 0;)
    {
        resume_one(&actx, q.whole[i]);
    }
    rs_progress_done();
    if (live)
    {
        st->paused = q.paused;
        st->pause_failed = q.failed;
    }
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
    (void)fprintf(stderr,
                  "restate: %s %s (%.4s %.4s %.4s %.4s %.4s  %.4s %.4s %.4s %.4s %.4s)%s%s\n",
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

/* A repository named alone as its newest snapshot, REPO::NAME: what is
 * signed, and said to be, is that one, whatever a capture adds meanwhile.
 * Anything else as it is. */
static char *sign_ref(const char *ref)
{
    char           *dir;
    char           *name;
    char           *found = NULL;
    struct rs_repo *r;
    struct rs_buf   err;
    bool            busy;

    if (!rs_repo_ref(ref, &dir, &name) || name)
    {
        free(dir);
        free(name);
        return rs_xstrdup(ref);
    }
    rs_buf_init(&err);
    r = rs_repo_open(dir, RS_REPO_LOOK, &busy, &err);
    if (r)
    {
        found = rs_repo_resolve(r, NULL, &err);
        rs_repo_close(r);
    }
    rs_buf_free(&err);
    {
        char *full = found ? rs_xasprintf("%s" RS_REPO_SEP "%s", dir, found) : rs_xstrdup(ref);

        free(found);
        free(dir);
        return full;
    }
}

int rs_cmd_sign(const struct rs_options *o)
{
    char                *path;
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
    path = sign_ref(o->args[0]);
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
        free(path);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    rs_jobj_str(rs_result(), "signed", path);
    rs_jobj_str(rs_result(), "signer", signer.fpr);
    if (!o->quiet)
    {
        say_signer("signed by", &signer);
    }
    free(path);
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
    return st->unreadable + st->pause_failed > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
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
static int capture_repo(const struct rs_options *o, struct rs_scan_stats *st, char **where,
                        uint64_t *new_bytes)
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
    r = rs_repo_open(o->output, o->append_only ? RS_REPO_APPEND : RS_REPO_WRITE, &busy, &err);
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
        *new_bytes = done.bytes;
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
    return st->unreadable + st->pause_failed > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

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

/* What a capture did, in its result. */
static void capture_result(const struct rs_options *o, const struct rs_scan_stats *st,
                           const char *where, uint64_t new_bytes, bool created)
{
    struct rs_jval *res = rs_result();
    struct rs_jval *by;
    bool            repo = o->output && rs_repo_is(o->output);

    if (!o->output)
    {
        return;
    }
    rs_jobj_str(res, repo ? "repository" : "image", o->output);
    rs_jobj_bool(res, "created_repository", created);
    rs_jobj_str(res, "snapshot", where);
    rs_jobj_u64(res, "paths", st->recorded);
    rs_jobj_u64(res, "kept", st->stored);
    rs_jobj_u64(res, "read_bytes", st->bytes_hashed);
    rs_jobj_u64(res, "reused", st->reused);
    rs_jobj_u64(res, "reused_bytes", st->bytes_reused);
    if (repo)
    {
        struct rs_repo      *r;
        struct rs_repo_usage u;
        struct rs_buf        err;
        bool                 busy;

        rs_jobj_u64(res, "new_bytes", new_bytes);
        rs_buf_init(&err);
        r = rs_repo_open(o->output, RS_REPO_LOOK, &busy, &err);
        if (r)
        {
            struct rs_jval *cache;

            rs_repo_du(r, &u);
            rs_jobj_u64(res, "repository_bytes", u.bytes);
            rs_repo_usage_free(&u);
            cache = rs_jobj_add(res, "cache");
            if (rs_repo_cache_path(r))
            {
                rs_jval_set_object(cache);
                rs_jobj_str(cache, "path", rs_repo_cache_path(r));
                rs_jobj_u64(cache, "bytes", rs_repo_cache_bytes(r));
            }
            rs_repo_close(r);
        }
        rs_buf_free(&err);
    } else
    {
        struct stat sb;

        rs_jobj_u64(res, "new_bytes", stat(o->output, &sb) == 0 ? (uint64_t)sb.st_size : 0);
    }
    by = rs_jobj_add(res, "classes");
    rs_jval_set_object(by);
    rs_jobj_u64(by, "state", st->by_class[RS_CLASS_STATE]);
    rs_jobj_u64(by, "identity", st->by_class[RS_CLASS_IDENTITY]);
    rs_jobj_u64(by, "baseline", st->by_class[RS_CLASS_BASELINE]);
    rs_jobj_u64(by, "expendable", st->by_class[RS_CLASS_EXPENDABLE]);
    rs_jobj_u64(res, "grew", st->grew);
    rs_jobj_u64(res, "paused", st->paused);
    rs_jobj_u64(res, "pause_failed", st->pause_failed);
}

int rs_cmd_capture(const struct rs_options *o)
{
    struct rs_scan_stats st;
    time_t               began = time(NULL);
    uint64_t             new_bytes = 0;
    char                *where = NULL;
    size_t               k;
    int                  lock = -1;
    int                  status;
    bool                 busy = false;
    bool                 created = false;

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
    if (o->create && !rs_repo_is(o->output))
    {
        struct rs_buf err;

        /* Only new files, in a directory with nothing else in it: an
         * --append-only capture can make its repository too. */
        rs_buf_init(&err);
        if (!recipients_usable(o))
        {
            status = RESTATE_EXIT_TROUBLE;
        } else if (!rs_repo_init(o->output, o->nrecipients > 0, &err))
        {
            rs_error("--create: %s", err.data);
            status = RESTATE_EXIT_TROUBLE;
        } else
        {
            created = true;
            if (!o->quiet)
            {
                (void)fprintf(stderr, "restate: made the %srepository %s\n",
                              o->nrecipients > 0 ? "encrypted " : "", o->output);
            }
        }
        rs_buf_free(&err);
    }
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
    if (status == RESTATE_EXIT_OK && o->append_only && !rs_repo_is(o->output))
    {
        rs_error("--append-only: %s is not a repository; an image is written whole", o->output);
        status = RESTATE_EXIT_TROUBLE;
    }
    if (status == RESTATE_EXIT_OK)
    {
        status = rs_repo_is(o->output) ? capture_repo(o, &st, &where, &new_bytes)
                                       : capture_image(o, &st);
    }
    if (lock >= 0)
    {
        (void)close(lock);
    }
    capture_result(o, &st, where, new_bytes, created);
    log_outcome(o, status, began, "output=%s paths=%" PRIu64 " kept=%" PRIu64 " read=%" PRIu64
                " reused=%" PRIu64 " unreadable=%" PRIu64, where ? where : o->output,
                st.recorded, st.stored, st.bytes_hashed, st.reused, st.unreadable);
    free(where);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Repositories                                                              */
/* ------------------------------------------------------------------------- */

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

OUTPUT_HELD_BEGIN
/* Who a snapshot's signature says made it, and, with --trusted-key, whether
 * it is good by one of those keys and whose. */
struct said_signer {
    char                 issuer[65];   /* "" if unsigned, or naming none */
    bool                 checked;      /* --trusted-key was given */
    bool                 trusted;
    struct rs_pgp_signer signer;       /* when trusted */
};

static void said_signer(const struct rs_options *o, const struct rs_repo *r, const char *name,
                        const struct rs_buf *sig, struct said_signer *s)
{
    memset(s, 0, sizeof(*s));
    if (sig->len > 0)
    {
        (void)rs_pgp_sig_issuer((const unsigned char *)sig->data, sig->len, s->issuer);
    }
    if (o->ntrusted > 0)
    {
        char         *ref = rs_xasprintf("%s" RS_REPO_SEP "%s", rs_repo_dir(r), name);
        char          digest[RS_SHA256_HEX_SIZE];
        struct rs_buf why;

        rs_buf_init(&why);
        s->checked = true;
        s->trusted = sig->len > 0 &&
                     rs_image_trusted(ref, o->trusted, o->ntrusted, &s->signer, digest, &why);
        rs_buf_free(&why);
        free(ref);
    }
}

static void signature_text(struct rs_buf *text, bool is_signed, const struct said_signer *s)
{
    if (!is_signed)
    {
        rs_buf_addstr(text, s->checked ? "; not signed" : "");
    } else if (s->trusted)
    {
        rs_buf_addf(text, "; signed by %s (%s)", s->signer.who[0] ? s->signer.who : "?",
                    s->signer.fpr);
    } else if (s->checked)
    {
        rs_buf_addf(text, "; signed%s%s, by no key trusted here", s->issuer[0] ? " by " : "",
                    s->issuer);
    } else
    {
        rs_buf_addf(text, "; signed%s%s", s->issuer[0] ? " by " : "", s->issuer);
    }
}

/* "issuer": the key the signature names, unchecked; with --trusted-key,
 * "trusted", and the "signer" and "signer_name" it was checked to be. */
static void signature_json(struct rs_jval *j, const struct said_signer *s)
{
    if (s->issuer[0])
    {
        rs_jobj_str(j, "issuer", s->issuer);
    }
    if (s->checked)
    {
        rs_jobj_bool(j, "trusted", s->trusted);
    }
    if (s->trusted)
    {
        rs_jobj_str(j, "signer", s->signer.fpr);
        rs_jobj_str(j, "signer_name", s->signer.who[0] ? s->signer.who : NULL);
    }
}

int rs_cmd_snapshots(const struct rs_options *o)
{
    struct rs_repo *r;
    struct rs_jval  list;
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
    memset(&list, 0, sizeof(list));
    rs_jval_set_array(&list);
    for (i = 0; i < n; i++)
    {
        struct rs_jval        info;
        struct rs_jval       *j = rs_jarr_add(&list);
        struct rs_buf         sig;
        struct rs_buf         gz;
        struct said_signer    said;
        uint64_t              files = 0;
        uint64_t              bytes = 0;
        uint64_t              fresh = 0;

        rs_jval_set_object(j);
        rs_jobj_str(j, "name", names[i]);
        rs_buf_reset(&err);
        rs_buf_init(&sig);
        rs_buf_init(&gz);
        (void)rs_repo_index_bytes(r, names[i], &gz, &sig, &err);
        said_signer(o, r, names[i], &sig, &said);
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
            rs_buf_addstr(&text, " new");
            signature_text(&text, sig.len > 0, &said);
            rs_buf_addc(&text, '\n');
            rs_jobj_str(j, "host", rs_jobject_str(&info, "host"));
            rs_jobj_str(j, "created", rs_jobject_str(&info, "created"));
            rs_jobj_u64(j, "files", files);
            rs_jobj_u64(j, "bytes", bytes);
            rs_jobj_u64(j, "new_bytes", fresh);
            rs_jval_free(&info);
        } else
        {
            rs_buf_addf(&text, "%s  (no summary: %s)\n", names[i], err.data);
            rs_jobj_str(j, "error", err.data);
        }
        rs_jobj_bool(j, "signed", sig.len > 0);
        signature_json(j, &said);
        rs_buf_free(&sig);
        rs_buf_free(&gz);
    }
    rs_repo_free_names(names, n);
    rs_repo_close(r);
    rs_buf_free(&err);
    rs_jobj_str(rs_result(), "repository", o->args[0]);
    if (o->json)
    {
        struct rs_jval doc;

        memset(&doc, 0, sizeof(doc));
        rs_jval_set_object(&doc);
        rs_jobj_str(&doc, "repository", o->args[0]);
        rs_jval_copy(rs_jobj_add(&doc, "snapshots"), &list);
        rs_buf_reset(&text);
        rs_json_write(&text, &doc, 2, 0);
        rs_buf_addc(&text, '\n');
        rs_jval_free(&doc);
    }
    *rs_jobj_add(rs_result(), "snapshots") = list;
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

OUTPUT_HELD_END

/* What prune dropped and kept, in its result. */
static void prune_result(const struct rs_options *o, struct rs_repo *r,
                         const struct rs_repo_pruned *p)
{
    struct rs_jval *res = rs_result();
    struct rs_jval *dropped;
    struct rs_jval *kept;
    char          **names;
    size_t          n;
    size_t          i;

    rs_jobj_str(res, "repository", o->args[0]);
    rs_jobj_bool(res, "dry_run", o->dry_run);
    rs_jobj_bool(res, "whole_packs", o->whole_packs);
    dropped = rs_jobj_add(res, "pruned");
    rs_jval_set_array(dropped);
    for (i = 0; i < p->ndropped; i++)
    {
        rs_jval_set_string(rs_jarr_add(dropped), p->dropped[i]);
    }
    kept = rs_jobj_add(res, "kept_snapshots");
    rs_jval_set_array(kept);
    names = rs_repo_snapshots(r, &n);
    for (i = 0; i < n; i++)
    {
        size_t k;
        bool   going = false;

        for (k = 0; o->dry_run && k < p->ndropped; k++)
        {
            going = going || strcmp(p->dropped[k], names[i]) == 0;
        }
        if (!going)
        {
            rs_jval_set_string(rs_jarr_add(kept), names[i]);
        }
    }
    rs_repo_free_names(names, n);
    rs_jobj_u64(res, "packs_removed", p->packs_removed);
    rs_jobj_u64(res, "packs_rewritten", p->packs_rewritten);
    rs_jobj_u64(res, "packs_left", p->packs_left);
    rs_jobj_u64(res, "bytes_freed", p->bytes_freed);
}

int rs_cmd_prune(const struct rs_options *o)
{
    struct rs_repo_keep   keep;
    struct rs_repo_pruned pruned;
    struct rs_repo       *r;
    struct rs_buf         err;
    time_t                began = time(NULL);
    size_t                i;
    int                   status;
    bool                  busy;
    bool                  ok;

    keep.last = o->keep_last;
    keep.daily = o->keep_daily;
    keep.weekly = o->keep_weekly;
    keep.monthly = o->keep_monthly;
    keep.yearly = o->keep_yearly;
    if (keep.last + keep.daily + keep.weekly + keep.monthly + keep.yearly == 0)
    {
        rs_error("prune: say what to keep, with --keep-last, --keep-daily, --keep-weekly, "
                 "--keep-monthly or --keep-yearly");
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
    if (!o->dry_run)
    {
        hold_stops();
        rs_repo_set_stop(r, interrupted);
    }
    ok = o->whole_packs ? rs_repo_prune_whole(r, &keep, o->dry_run, &pruned, &err)
                        : rs_repo_prune(r, &keep, o->dry_run, &pruned, &err);
    /* Stopped, it still records what went, which a check would take for
     * files removed behind its back. */
    if (ok && o->record && !o->dry_run && !rs_repo_record_update(r, o->record, &err))
    {
        rs_warn("--record: %s", err.data);
        rs_buf_reset(&err);
    }
    if (ok && pruned.stopped)
    {
        rs_error("prune: stopped by %s; the record follows what was removed, and the next "
                 "prune finishes it", stop_signal());
    }
    prune_result(o, r, &pruned);
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
    status = !ok             ? RESTATE_EXIT_TROUBLE
             : pruned.stopped ? RESTATE_EXIT_INCOMPLETE
                              : RESTATE_EXIT_OK;
    log_outcome(o, status, began,
                "repository=%s dropped=%zu packs_removed=%zu packs_rewritten=%zu "
                "bytes_freed=%" PRIu64, o->args[0], pruned.ndropped, pruned.packs_removed,
                pruned.packs_rewritten, pruned.bytes_freed);
    rs_repo_pruned_free(&pruned);
    rs_buf_free(&err);
    return status;
}

int rs_cmd_repack(const struct rs_options *o)
{
    struct rs_repo_pruned packed;
    struct rs_repo       *r;
    struct rs_buf         err;
    struct rs_jval       *res = rs_result();
    time_t                began = time(NULL);
    int                   status;
    bool                  busy;
    bool                  ok;

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
    if (!o->dry_run)
    {
        hold_stops();
        rs_repo_set_stop(r, interrupted);
    }
    ok = rs_repo_repack(r, o->dry_run, &packed, &err);
    if (ok && o->record && !o->dry_run && !rs_repo_record_update(r, o->record, &err))
    {
        rs_warn("--record: %s", err.data);
        rs_buf_reset(&err);
    }
    rs_repo_close(r);
    rs_jobj_str(res, "repository", o->args[0]);
    rs_jobj_bool(res, "dry_run", o->dry_run);
    rs_jobj_u64(res, "packs_removed", packed.packs_removed);
    rs_jobj_u64(res, "packs_rewritten", packed.packs_rewritten);
    rs_jobj_u64(res, "bytes_freed", packed.bytes_freed);
    if (!ok)
    {
        rs_error("%s", err.data);
    } else if (packed.stopped)
    {
        rs_error("repack: stopped by %s; the packs written so far are kept, and the next "
                 "repack goes on from there", stop_signal());
    } else if (!o->quiet && o->dry_run)
    {
        (void)printf("would write again %zu packs\n", packed.packs_rewritten);
    } else if (!o->quiet)
    {
        struct rs_buf size;

        rs_buf_init(&size);
        human_size(&size, packed.bytes_freed);
        (void)fprintf(stderr, "restate: wrote again %zu packs, and removed %zu that nothing "
                      "needed, freeing %s\n", packed.packs_rewritten, packed.packs_removed,
                      size.data);
        rs_buf_free(&size);
    }
    status = !ok             ? RESTATE_EXIT_TROUBLE
             : packed.stopped ? RESTATE_EXIT_INCOMPLETE
                              : RESTATE_EXIT_OK;
    log_outcome(o, status, began,
                "repository=%s packs_removed=%zu packs_rewritten=%zu bytes_freed=%" PRIu64,
                o->args[0], packed.packs_removed, packed.packs_rewritten, packed.bytes_freed);
    rs_repo_pruned_free(&packed);
    rs_buf_free(&err);
    return status;
}

/*
 * The group protect makes a repository's: --group, or else its directory's.
 * False, having said why, for one that is not there, and for root's: the
 * machines a share maps are never in it, and would be locked out.
 */
static bool protect_group(const struct rs_options *o, const char *dir, gid_t *gid,
                          const char **name)
{
    static char         number[32];
    struct stat         st;
    const struct group *g;

    if (o->group)
    {
        g = getgrnam(o->group);
        if (!g)
        {
            rs_error("--group %s: there is no such group here", o->group);
            return false;
        }
        *gid = g->gr_gid;
    } else if (stat(dir, &st) != 0)
    {
        rs_error("%s: %s", dir, strerror(errno));
        return false;
    } else
    {
        *gid = st.st_gid;
    }
    if (*gid == 0)
    {
        rs_error("protect %s: its group would be root's, which no machine writing to it is in; "
                 "name theirs with --group", dir);
        return false;
    }
    g = getgrgid(*gid);
    if (g && g->gr_name)
    {
        *name = g->gr_name;
    } else
    {
        (void)snprintf(number, sizeof(number), "%lu", (unsigned long)*gid);
        *name = number;
    }
    return true;
}

int rs_cmd_protect(const struct rs_options *o)
{
    struct rs_repo_protected done;
    struct rs_buf            err;
    struct rs_jval          *res = rs_result();
    const char              *dir = o->args[0];
    const char              *name = NULL;
    time_t                   began = time(NULL);
    gid_t                    gid = 0;
    size_t                   i;
    int                      status;
    bool                     ok;

    rs_jobj_str(res, "repository", dir);
    if (!protect_group(o, dir, &gid, &name))
    {
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "repository=%s", dir);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&err);
    ok = rs_repo_protect(dir, geteuid(), gid, &done, &err);
    rs_jobj_str(res, "group", name);
    rs_jobj_u64(res, "files_protected", done.files);
    rs_jobj_u64(res, "snapshots_protected", done.snapshots);
    rs_jobj_u64(res, "directories_protected", done.dirs);
    rs_jobj_u64(res, "unchanged", done.unchanged);
    rs_jobj_u64(res, "not_protected", done.nfailed);
    rs_jobj_u64(res, "waited_for", done.waited_for);
    if (!ok)
    {
        rs_error("%s", err.data);
    }
    for (i = 0; i < done.nfailed; i++)
    {
        rs_error("not protected: %s", done.failed[i]);
    }
    if (ok && geteuid() != 0 && !o->quiet)
    {
        rs_warn("protect %s: run as other than root, what it protects is still yours to change: "
                "safe from the machines only if a share maps them to another user", dir);
    }
    if (ok && !o->quiet)
    {
        (void)fprintf(stderr, "restate: protected %zu files, %zu snapshots and %zu directories "
                      "for the group %s; %zu were already\n", done.files, done.snapshots,
                      done.dirs, name, done.unchanged);
        if (done.waited_for > 0)
        {
            (void)fprintf(stderr, "restate: waited for %zu the file server had lent out to the "
                          "machine that wrote them (an NFS delegation)\n", done.waited_for);
        }
    }
    status = !ok             ? RESTATE_EXIT_TROUBLE
             : done.nfailed ? RESTATE_EXIT_INCOMPLETE
                            : RESTATE_EXIT_OK;
    log_outcome(o, status, began,
                "repository=%s group=%s files_protected=%zu snapshots_protected=%zu "
                "not_protected=%zu", dir, name, done.files, done.snapshots, done.nfailed);
    rs_repo_protected_free(&done);
    rs_buf_free(&err);
    return status;
}

/*
 * check --read-all: the snapshot `ref` read in full, as restore reads it, into
 * `empty`, a directory that stays empty: every file checked against its
 * index, nothing written. Signed by a --trusted-key key too, where any are
 * given. How many files were not what the index says, or not there, into
 * *bad; false if it could not be read at all.
 */
static bool read_snapshot(const struct rs_options *o, const char *ref, const char *empty,
                          uint64_t *files, uint64_t *bad)
{
    struct rs_index         ix;
    struct rs_restore_opts  ro;
    struct rs_restore_stats st;
    struct rs_buf           err;
    struct trust            tr;
    bool                    ok;

    memset(&tr, 0, sizeof(tr));
    if (o->ntrusted > 0 && trust_check(o, ref, true, &tr) != RESTATE_EXIT_OK)
    {
        return false;
    }
    rs_index_init(&ix);
    rs_buf_init(&err);
    ok = rs_index_load(&ix, ref, &err) &&
         (o->ntrusted == 0 || trust_matches(o, ref, &tr, &ix) == RESTATE_EXIT_OK);
    if (ok)
    {
        memset(&ro, 0, sizeof(ro));
        ro.root = empty;
        ro.dry_run = true;
        ro.quiet = true;
        ro.numeric_owner = true;
        ok = rs_restore(ref, &ix, &ro, &st, &err);
        *files += st.files;
        *bad += st.refused + st.missing;
    }
    if (!ok && err.len > 0)
    {
        rs_warn("%s", err.data);
    }
    rs_index_free(&ix);
    rs_buf_free(&err);
    return ok;
}

/* What check found, in its result. */
static void check_result(const struct rs_options *o, const struct rs_repo_checked *c, size_t n,
                         uint64_t read_files, uint64_t read_bad, size_t unread, int status)
{
    struct rs_jval *res = rs_result();
    struct rs_jval *k;
    struct rs_jval *changed;
    size_t          i;

    rs_jobj_str(res, "repository", o->args[0]);
    k = rs_jobj_add(res, "check");
    rs_jval_set_object(k);
    rs_jobj_bool(k, "ok", status == RESTATE_EXIT_OK);
    rs_jobj_bool(k, "read_all", o->read_all);
    rs_jobj_bool(k, "metadata_only", o->metadata_only);
    rs_jobj_u64(k, "packs", c->packs);
    rs_jobj_u64(k, "packs_bad", c->packs_bad);
    rs_jobj_u64(k, "chunks", c->chunks);
    rs_jobj_u64(k, "bytes", c->bytes);
    rs_jobj_u64(k, "snapshots", c->snapshots);
    rs_jobj_u64(k, "snapshots_bad", c->snapshots_bad + unread);
    rs_jobj_u64(k, "files", c->files);
    rs_jobj_u64(k, "files_missing", c->missing);
    rs_jobj_u64(k, "leftovers", c->leftovers);
    rs_jobj_u64(k, "packs_without_sum", c->unsummed);
    rs_jobj_u64(k, "snapshots_without_pack_list", c->unlisted);
    if (o->read_all)
    {
        rs_jobj_u64(k, "snapshots_read", n);
        rs_jobj_u64(k, "files_read", read_files);
        rs_jobj_u64(k, "files_read_bad", read_bad);
    }
    changed = rs_jobj_add(k, "changed");
    rs_jval_set_array(changed);
    for (i = 0; i < c->nchanged; i++)
    {
        rs_jval_set_string(rs_jarr_add(changed), c->changed[i]);
    }
    rs_jobj_bool(k, "recorded", o->record != NULL);
}

int rs_cmd_check(const struct rs_options *o)
{
    struct rs_repo_check_opts copts;
    struct rs_repo_checked    c;
    struct rs_repo           *r;
    struct rs_buf             err;
    struct rs_buf             size;
    time_t                    began = time(NULL);
    uint64_t                  read_files = 0;
    uint64_t                  read_bad = 0;
    size_t                    unread = 0;
    size_t                    n = 0;
    bool                      busy;
    bool                      ok;
    int                       status;

    if (o->metadata_only && o->read_all)
    {
        rs_error("check: --metadata-only reads no index, and --read-all reads every one; give "
                 "one of them");
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "repository=%s", o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&err);
    r = rs_repo_open(o->args[0], RS_REPO_READ, &busy, &err);
    if (!r)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        status = busy ? RESTATE_EXIT_BUSY : RESTATE_EXIT_TROUBLE;
        log_outcome(o, status, began, "repository=%s", o->args[0]);
        return status;
    }
    memset(&copts, 0, sizeof(copts));
    copts.metadata_only = o->metadata_only;
    copts.record = o->record;
    rs_progress_phase("checking", 0);
    ok = rs_repo_check(r, &copts, &c, &err);
    rs_progress_done();
    if (ok && o->read_all)
    {
        /* Where the snapshots are restored to, in a dry run: an empty
         * directory only this run knows, under /tmp as restate's others are,
         * never where the environment says. */
        char   empty[] = "/tmp/restate-check.XXXXXX";
        char **names = rs_repo_snapshots(r, &n);
        size_t i;

        if (!mkdtemp(empty))
        {
            rs_error("%s: %s", empty, strerror(errno));
            ok = false;
        }
        for (i = 0; ok && i < n; i++)
        {
            char    *ref = rs_xasprintf("%s" RS_REPO_SEP "%s", o->args[0], names[i]);
            uint64_t before = read_bad;

            if (!read_snapshot(o, ref, empty, &read_files, &read_bad) || read_bad > before)
            {
                unread++;
            }
            free(ref);
        }
        if (ok)
        {
            (void)rmdir(empty);
        }
        rs_repo_free_names(names, n);
    }
    rs_repo_close(r);
    if (!ok)
    {
        if (err.len > 0)
        {
            rs_error("%s", err.data);
        }
        rs_buf_free(&err);
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "repository=%s", o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    status = c.packs_bad + c.snapshots_bad + unread + c.nchanged > 0 ? RESTATE_EXIT_INCOMPLETE
                                                                      : RESTATE_EXIT_OK;
    check_result(o, &c, n, read_files, read_bad, unread, status);
    if (!o->quiet)
    {
        rs_buf_init(&size);
        human_size(&size, c.bytes);
        (void)fflush(stdout);
        if (o->metadata_only)
        {
            (void)fprintf(stderr, "restate: read %zu packs (%s), each against the digest written "
                          "beside it: %zu damaged; no index was read, so no chunk was checked\n",
                          c.packs, size.data, c.packs_bad);
            (void)fprintf(stderr, "restate: %zu snapshots: %zu with a pack or file missing\n",
                          c.snapshots, c.snapshots_bad);
        } else
        {
            (void)fprintf(stderr, "restate: read %zu packs (%s, %" PRIu64 " chunks checked "
                          "against their digests): %zu damaged\n", c.packs, size.data, c.chunks,
                          c.packs_bad);
            (void)fprintf(stderr, "restate: %zu snapshots, %" PRIu64 " files with content: %zu "
                          "snapshots with something missing, %" PRIu64 " files not whole\n",
                          c.snapshots, c.files, c.snapshots_bad, c.missing);
        }
        if (c.unsummed + c.unlisted > 0)
        {
            (void)fprintf(stderr, "restate: %zu packs have no digest beside them and %zu snapshots "
                          "no list of their packs: written before restate 2.0; a prune adds "
                          "them\n", c.unsummed, c.unlisted);
        }
        if (o->record)
        {
            (void)fprintf(stderr, "restate: %zu files removed or changed since the last check "
                          "(%s)\n", c.nchanged, o->record);
        }
        if (o->read_all)
        {
            (void)fprintf(stderr, "restate: read %zu snapshots in full, as restore would: %"
                          PRIu64 " files, %" PRIu64 " not as their indexes say\n", n, read_files,
                          read_bad);
        }
        if (c.leftovers > 0)
        {
            (void)fprintf(stderr, "restate: %zu packs have no index: an interrupted capture's, "
                          "which nothing refers to and prune removes\n", c.leftovers);
        }
        (void)fprintf(stderr, "restate: %s\n",
                      status != RESTATE_EXIT_OK ? "the repository is damaged; see above"
                      : o->metadata_only        ? "the repository is whole, as far as can be "
                                                  "told without reading its indexes"
                                                : "the repository is whole");
        rs_buf_free(&size);
    }
    log_outcome(o, status, began,
                "repository=%s packs=%zu packs_damaged=%zu snapshots=%zu snapshots_damaged=%zu "
                "files_missing=%" PRIu64 " read_all=%s metadata_only=%s changed=%zu",
                o->args[0], c.packs, c.packs_bad, c.snapshots, c.snapshots_bad + unread,
                c.missing, o->read_all ? "yes" : "no", o->metadata_only ? "yes" : "no",
                c.nchanged);
    rs_repo_checked_free(&c);
    return status;
}

int rs_cmd_copy(const struct rs_options *o)
{
    struct rs_repo_copied copied;
    struct rs_repo       *r;
    struct rs_buf         err;
    struct rs_jval       *res;
    time_t                began = time(NULL);
    char                 *dir = NULL;
    char                 *name = NULL;
    bool                  busy = false;
    bool                  ok;
    int                   status;

    if (!rs_repo_ref(o->args[0], &dir, &name))
    {
        rs_error("copy: %s is not a repository, or a snapshot in one (REPO::NAME)", o->args[0]);
        log_outcome(o, RESTATE_EXIT_TROUBLE, began, "snapshot=%s", o->args[0]);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_init(&err);
    r = rs_repo_open(dir, RS_REPO_READ, &busy, &err);
    ok = r != NULL;
    memset(&copied, 0, sizeof(copied));
    if (ok)
    {
        rs_progress_phase("copying", 0);
        ok = rs_repo_copy(r, name, o->args[1], &copied, &busy, &err);
        rs_progress_done();
    }
    status = ok ? RESTATE_EXIT_OK : busy ? RESTATE_EXIT_BUSY : RESTATE_EXIT_TROUBLE;
    if (!ok)
    {
        rs_error("%s", err.data);
    } else if (!o->quiet)
    {
        struct rs_buf size;

        rs_buf_init(&size);
        human_size(&size, copied.bytes);
        (void)fflush(stdout);
        if (copied.already)
        {
            (void)fprintf(stderr, "restate: %s" RS_REPO_SEP "%s is in %s already\n", dir,
                          copied.name, o->args[1]);
        } else
        {
            (void)fprintf(stderr, "restate: copied %s" RS_REPO_SEP "%s to %s%s: %zu packs (%s); "
                          "%zu it needs were there already\n", dir, copied.name, o->args[1],
                          copied.made ? ", made for it" : "", copied.packs_copied, size.data,
                          copied.packs_there);
        }
        rs_buf_free(&size);
    }
    res = rs_jobj_add(rs_result(), "copy");
    rs_jval_set_object(res);
    rs_jobj_str(res, "from", dir);
    rs_jobj_str(res, "to", o->args[1]);
    rs_jobj_str(res, "snapshot", copied.name);
    rs_jobj_bool(res, "already", copied.already);
    rs_jobj_bool(res, "made", copied.made);
    rs_jobj_u64(res, "packs_copied", copied.packs_copied);
    rs_jobj_u64(res, "packs_there", copied.packs_there);
    rs_jobj_u64(res, "bytes", copied.bytes);
    log_outcome(o, status, began, "from=%s to=%s snapshot=%s packs_copied=%zu bytes=%" PRIu64,
                dir, o->args[1], copied.name ? copied.name : "-", copied.packs_copied,
                copied.bytes);
    rs_repo_copied_free(&copied);
    rs_repo_close(r);
    rs_buf_free(&err);
    free(dir);
    free(name);
    return status;
}

/* The keys du's repository is encrypted to, and what of it each is needed
 * for: in `doc` and, a line a key, in `text`. */
static void du_keys(struct rs_jval *doc, struct rs_buf *text, const struct rs_repo_keys *keys)
{
    struct rs_jval *obj = rs_jobj_add(doc, "keys");
    size_t          i;
    size_t          k;

    rs_jval_set_object(obj);
    rs_jobj_u64(doc, "encrypted_files", keys->files);
    rs_jobj_u64(doc, "unreadable_files", keys->unreadable);
    for (i = 0; i < keys->nkeys; i++)
    {
        const struct rs_repo_key_use *u = &keys->keys[i];
        struct rs_jval               *j = rs_jobj_add(obj, u->id);
        struct rs_jval               *snaps;
        char                          size[32];

        rs_jval_set_object(j);
        rs_jobj_u64(j, "packs", u->packs);
        rs_jobj_u64(j, "bytes", u->bytes);
        snaps = rs_jobj_add(j, "snapshots");
        rs_jval_set_array(snaps);
        for (k = 0; k < u->nsnapshots; k++)
        {
            rs_jval_set_string(rs_jarr_add(snaps), u->snapshots[k]);
        }
        rs_jobj_bool(j, "chunk_key", u->chunk_key);
        rs_human_size(u->bytes, size, sizeof(size));
        rs_buf_addf(text, "encrypted to %s: %zu packs %s, %zu snapshots%s\n", u->id, u->packs,
                    size, u->nsnapshots, u->chunk_key ? ", the chunking key" : "");
    }
    if (keys->unreadable > 0)
    {
        rs_buf_addf(text, "%zu encrypted files whose keys could not be read\n", keys->unreadable);
    }
}

OUTPUT_HELD_BEGIN
int rs_cmd_du(const struct rs_options *o)
{
    struct rs_repo_usage u;
    struct rs_repo_keys  keys;
    struct rs_repo      *r;
    struct rs_jval       doc;
    struct rs_jval      *list;
    struct rs_buf        err;
    struct rs_buf        text;
    struct output        out;
    size_t               i;
    bool                 busy;
    bool                 ok;

    rs_buf_init(&err);
    r = rs_repo_open(o->args[0], RS_REPO_LOOK, &busy, &err);
    if (!r)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    rs_repo_du(r, &u);
    rs_repo_keys(r, &keys);
    rs_repo_close(r);
    memset(&doc, 0, sizeof(doc));
    rs_jval_set_object(&doc);
    rs_jobj_str(&doc, "repository", o->args[0]);
    rs_jobj_u64(&doc, "bytes", u.bytes);
    rs_jobj_u64(&doc, "pack_bytes", u.pack_bytes);
    rs_jobj_u64(&doc, "packs", u.packs);
    list = rs_jobj_add(&doc, "snapshots");
    rs_jval_set_array(list);
    rs_buf_init(&text);
    rs_buf_addstr(&text, "snapshot            needs      alone      added\n");
    for (i = 0; i < u.nsnapshots; i++)
    {
        const struct rs_repo_snapshot_usage *s = &u.snapshots[i];
        struct rs_jval                      *j = rs_jarr_add(list);

        rs_jval_set_object(j);
        rs_jobj_str(j, "name", s->name);
        rs_jobj_bool(j, "listed", s->listed);
        if (s->listed)
        {
            char need[32];
            char alone[32];
            char added[32];

            rs_jobj_u64(j, "bytes", s->bytes);
            rs_jobj_u64(j, "unique_bytes", s->unique_bytes);
            rs_jobj_u64(j, "new_bytes", s->new_bytes);
            rs_human_size(s->bytes, need, sizeof(need));
            rs_human_size(s->unique_bytes, alone, sizeof(alone));
            rs_human_size(s->new_bytes, added, sizeof(added));
            rs_buf_addf(&text, "%-18s %10s %10s %10s\n", s->name, need, alone, added);
        } else
        {
            rs_buf_addf(&text, "%-18s (written before restate 2.0: no pack list)\n", s->name);
        }
    }
    {
        char total[32];
        char packs[32];

        rs_human_size(u.bytes, total, sizeof(total));
        rs_human_size(u.pack_bytes, packs, sizeof(packs));
        rs_buf_addf(&text, "total %s, of which %zu packs %s\n", total, u.packs, packs);
    }
    du_keys(&doc, &text, &keys);
    rs_repo_keys_free(&keys);
    rs_jval_copy(rs_jobj_add(rs_result(), "du"), &doc);
    if (o->json)
    {
        rs_buf_reset(&text);
        rs_json_write(&text, &doc, 2, 0);
        rs_buf_addc(&text, '\n');
    }
    rs_jval_free(&doc);
    rs_repo_usage_free(&u);
    if (!output_open(o, &out))
    {
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = fwrite(text.data, 1, text.len, out.fp) == text.len;
    rs_buf_free(&text);
    return output_close(&out, ok) ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
}

OUTPUT_HELD_END

/* "/var/lib" for "/var/lib/mysql/ibdata1", "/etc" for "/etc/passwd": the
 * directory two levels down that a path is in, or the one level for a file
 * one level down. */
static char *estimate_dir(const char *path)
{
    const char *second = strchr(path + 1, '/');
    const char *third = second ? strchr(second + 1, '/') : NULL;

    if (!second)
    {
        return rs_xstrdup("/");
    }
    return rs_xstrndup(path, (size_t)((third ? third : second) - path));
}

struct dir_total {
    char    *dir;
    uint64_t bytes;
};

static int by_bytes(const void *a, const void *b)
{
    const struct dir_total *x = a;
    const struct dir_total *y = b;

    if (x->bytes != y->bytes)
    {
        return x->bytes < y->bytes ? 1 : -1;
    }
    return strcmp(x->dir, y->dir);
}

OUTPUT_HELD_BEGIN
int rs_cmd_estimate(const struct rs_options *o)
{
    struct rs_index      m;
    struct rs_scan_stats st;
    struct dir_total    *dirs = NULL;
    struct rs_jval       doc;
    struct rs_jval      *by;
    struct rs_buf        text;
    struct output        out;
    uint64_t             bytes = 0;
    uint64_t             files = 0;
    size_t               ndirs = 0;
    size_t               i;
    bool                 ok;

    if (!run_scan(o, o->root ? o->root : "/", false, NULL, &m, &st, NULL))
    {
        rs_index_free(&m);
        return RESTATE_EXIT_TROUBLE;
    }
    for (i = 0; i < m.count; i++)
    {
        const struct rs_entry *e = &m.entries[i];
        char                  *dir;
        size_t                 k;

        if (e->type != 'f' || (e->cls == RS_CLASS_BASELINE && !o->baseline_content))
        {
            continue;
        }
        files++;
        bytes += e->size;
        dir = estimate_dir(e->path);
        for (k = 0; k < ndirs && strcmp(dirs[k].dir, dir) != 0; k++)
        {
        }
        if (k == ndirs)
        {
            dirs = rs_xreallocarray(dirs, ndirs + 1, sizeof(*dirs));
            dirs[ndirs].dir = dir;
            dirs[ndirs++].bytes = 0;
        } else
        {
            free(dir);
        }
        dirs[k].bytes += e->size;
    }
    rs_index_free(&m);
    if (ndirs > 1)
    {
        qsort(dirs, ndirs, sizeof(*dirs), by_bytes);
    }
    memset(&doc, 0, sizeof(doc));
    rs_jval_set_object(&doc);
    rs_jobj_u64(&doc, "bytes", bytes);
    rs_jobj_u64(&doc, "files", files);
    by = rs_jobj_add(&doc, "by_dir");
    rs_jval_set_object(by);
    rs_buf_init(&text);
    for (i = 0; i < ndirs; i++)
    {
        char          size[32];
        char         *shown = rs_utf8_lossy(dirs[i].dir, strlen(dirs[i].dir));
        struct rs_buf b;

        rs_jobj_u64(by, shown, dirs[i].bytes);
        rs_human_size(dirs[i].bytes, size, sizeof(size));
        rs_buf_init(&b);
        rs_escape(&b, dirs[i].dir);
        rs_buf_addf(&text, "%10s  %s\n", size, b.data);
        rs_buf_free(&b);
        free(shown);
        free(dirs[i].dir);
    }
    free(dirs);
    {
        char size[32];

        rs_human_size(bytes, size, sizeof(size));
        rs_buf_addf(&text, "%10s  in all, in %" PRIu64 " files a first capture would keep the "
                    "content of\n", size, files);
    }
    rs_jval_copy(rs_jobj_add(rs_result(), "estimate"), &doc);
    if (o->json)
    {
        rs_buf_reset(&text);
        rs_json_write(&text, &doc, 2, 0);
        rs_buf_addc(&text, '\n');
    }
    rs_jval_free(&doc);
    if (!output_open(o, &out))
    {
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = fwrite(text.data, 1, text.len, out.fp) == text.len;
    rs_buf_free(&text);
    if (!output_close(&out, ok))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    return st.unreadable > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

/* What this restate can do, for a program to ask before it asks for it. */
int rs_cmd_features(const struct rs_options *o)
{
    static const enum rs_program programs[] = { RS_PROG_GZIP, RS_PROG_PIGZ, RS_PROG_GPG,
                                                RS_PROG_GPGV, RS_PROG_CURL, RS_PROG_SSH_KEYGEN };
    static const char *const members[] = { "capture.cache", "diff.changes", "list",
                                           "snapshot", "status.capture_rules",
                                           "verify.capture_rules" };
    struct rs_jval     doc;
    struct rs_jval    *list;
    struct rs_buf      text;
    struct output      out;
    const char *const *keys;
    const char        *name;
    char             **hooks;
    size_t             nkeys;
    size_t             nhooks;
    size_t             i;
    bool               ok;

    memset(&doc, 0, sizeof(doc));
    rs_jval_set_object(&doc);
    rs_jobj_str(&doc, "version", RESTATE_VERSION);
    rs_jobj_u64(&doc, "job_schema", RS_JOB_SCHEMA);
    rs_jobj_u64(&doc, "result_schema", RS_RESULT_SCHEMA);
    list = rs_jobj_add(&doc, "commands");
    rs_jval_set_array(list);
    for (i = 0; (name = rs_command_name_at(i)) != NULL; i++)
    {
        rs_jval_set_string(rs_jarr_add(list), name);
    }
    list = rs_jobj_add(&doc, "options");
    rs_jval_set_array(list);
    for (i = 0; (name = rs_option_name(i)) != NULL; i++)
    {
        char  *under = rs_xstrdup(name);
        size_t k;

        /* As a job's keys are spelled. */
        for (k = 0; under[k]; k++)
        {
            if (under[k] == '-')
            {
                under[k] = '_';
            }
        }
        rs_jval_set_string(rs_jarr_add(list), under);
        free(under);
    }
    list = rs_jobj_add(&doc, "job_keys");
    rs_jval_set_array(list);
    keys = rs_job_keys(&nkeys);
    for (i = 0; i < nkeys; i++)
    {
        rs_jval_set_string(rs_jarr_add(list), keys[i]);
    }
    list = rs_jobj_add(&doc, "job_commands");
    rs_jval_set_array(list);
    keys = rs_job_commands(&nkeys);
    for (i = 0; i < nkeys; i++)
    {
        rs_jval_set_string(rs_jarr_add(list), keys[i]);
    }
    /* Which of those keys each command takes: a key sent to a job only
     * when its command is listed with it. */
    list = rs_jobj_add(&doc, "job_command_keys");
    rs_jval_set_object(list);
    {
        const char *const *cmds = rs_job_commands(&nkeys);
        size_t             c;

        for (c = 0; c < nkeys; c++)
        {
            struct rs_jval    *of = rs_jobj_add(list, cmds[c]);
            size_t             nof;
            const char *const *ks = rs_job_command_keys(c, &nof);

            rs_jval_set_array(of);
            for (i = 0; i < nof; i++)
            {
                rs_jval_set_string(rs_jarr_add(of), ks[i]);
            }
        }
    }
    /* What results have gained since schema 1 began, for a program to ask
     * of a restate before it reads them. */
    list = rs_jobj_add(&doc, "result_members");
    rs_jval_set_array(list);
    for (i = 0; i < sizeof(members) / sizeof(members[0]); i++)
    {
        rs_jval_set_string(rs_jarr_add(list), members[i]);
    }
    list = rs_jobj_add(&doc, "hooks");
    rs_jval_set_array(list);
    hooks = rs_hooks_list(&nhooks);
    for (i = 0; i < nhooks; i++)
    {
        rs_jval_set_string(rs_jarr_add(list), hooks[i]);
    }
    /* Whether protect makes what is finished immutable and the repository
     * append-only (chattr +i and +a) in place of a sticky bit: Linux's. */
    rs_jobj_bool(&doc, "protect_flags", rs_fsflags_supported());
    rs_jobj_bool(&doc, "du_keys", true);
    rs_jobj_bool(&doc, "chunk_key_reseal", true);
    rs_jobj_bool(&doc, "keep_yearly", true);
    /* --arch, and what it rebuilds for: this restate's own processor, and
     * that an image records the processor of each program it keeps. */
    rs_jobj_bool(&doc, "rebuild_arch", true);
    rs_jobj_str(&doc, "arch", rs_arch_built() ? rs_arch_built()->name : NULL);
    rs_jobj_bool(&doc, "program_arch", true);
    /* snapshots names each signature's issuer, and with --trusted-key its
     * checked signer; a job can be a sign. */
    rs_jobj_bool(&doc, "snapshot_signer", true);
    /* protect waits for files an NFS server has lent out to the machine that
     * wrote them, up to 180 seconds; capture --create finishes a create that
     * failed partway, and makes files a Linux client refuses in a sticky
     * directory. */
    rs_jobj_bool(&doc, "protect_waits", true);
    rs_jobj_bool(&doc, "create_resumes", true);
    list = rs_jobj_add(&doc, "programs");
    rs_jval_set_object(list);
    for (i = 0; i < sizeof(programs) / sizeof(programs[0]); i++)
    {
        rs_jobj_bool(list, rs_program_name(programs[i]), rs_program_path(programs[i]) != NULL);
    }
    rs_buf_init(&text);
    if (o->json)
    {
        rs_json_write(&text, &doc, 2, 0);
        rs_buf_addc(&text, '\n');
    } else
    {
        rs_buf_addf(&text, "restate %s (job schema %d, result schema %d)\n", RESTATE_VERSION,
                    RS_JOB_SCHEMA, RS_RESULT_SCHEMA);
        rs_buf_addstr(&text, "hooks:");
        for (i = 0; i < nhooks; i++)
        {
            rs_buf_addf(&text, " %s", hooks[i]);
        }
        rs_buf_addstr(&text, nhooks ? "\n" : " none\n");
        rs_buf_addstr(&text, "programs:");
        for (i = 0; i < sizeof(programs) / sizeof(programs[0]); i++)
        {
            rs_buf_addf(&text, " %s%s", rs_program_name(programs[i]),
                        rs_program_path(programs[i]) ? "" : " (not installed)");
        }
        rs_buf_addc(&text, '\n');
    }
    for (i = 0; i < nhooks; i++)
    {
        free(hooks[i]);
    }
    free(hooks);
    rs_jval_free(&doc);
    if (!output_open(o, &out))
    {
        rs_buf_free(&text);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = fwrite(text.data, 1, text.len, out.fp) == text.len;
    rs_buf_free(&text);
    return output_close(&out, ok) ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
}

OUTPUT_HELD_END

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

/* How many changes of each kind -- added, deleted, modified -- a result
 * names, of all a diff, verify or status finds. */
#define RESULT_CHANGES 1000

static int write_diff(const struct rs_options *o, const struct rs_index *a,
                      const struct rs_index *b, struct rs_diff_stats *d)
{
    struct output   out;
    struct rs_jval  changes;
    struct rs_jval  packages;
    struct rs_jval  first;
    struct rs_jval *res;
    bool            by_package = o->packages && o->command == CMD_DIFF;
    bool            truncated;
    bool            ok;

    if (!output_open(o, &out))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    memset(&changes, 0, sizeof(changes));
    memset(&packages, 0, sizeof(packages));
    if (o->json)
    {
        rs_diff_json(&changes, &packages);
    }
    (void)rs_diff_collect(&first, RESULT_CHANGES);
    ok = by_package ? rs_diff_write_packages(a, b, out.fp, d) : rs_diff_write(a, b, out.fp, d);
    truncated = rs_diff_collect(NULL, 0);
    if (o->json)
    {
        struct rs_jval doc;
        struct rs_buf  text;

        rs_diff_json(NULL, NULL);
        memset(&doc, 0, sizeof(doc));
        rs_jval_set_object(&doc);
        rs_jobj_u64(&doc, "added", d->added);
        rs_jobj_u64(&doc, "deleted", d->deleted);
        rs_jobj_u64(&doc, "modified", d->modified);
        if (by_package)
        {
            rs_jobj_u64(&doc, "packages_changed", d->packages);
            rs_jobj_u64(&doc, "explained", d->explained);
            *rs_jobj_add(&doc, "packages") = packages;
            memset(&packages, 0, sizeof(packages));
        }
        *rs_jobj_add(&doc, "changes") = changes;
        memset(&changes, 0, sizeof(changes));
        rs_buf_init(&text);
        rs_json_write(&text, &doc, 2, 0);
        rs_buf_addc(&text, '\n');
        ok = ok && fwrite(text.data, 1, text.len, out.fp) == text.len;
        rs_buf_free(&text);
        rs_jval_free(&doc);
    }
    rs_jval_free(&changes);
    rs_jval_free(&packages);
    if (!ok)
    {
        rs_error("%s: %s", out.tmp ? out.tmp : "standard output", strerror(errno));
    }
    if (!output_close(&out, ok))
    {
        rs_jval_free(&first);
        return RESTATE_EXIT_TROUBLE;
    }
    res = rs_jobj_add(rs_result(), "diff");
    rs_jval_set_object(res);
    rs_jobj_u64(res, "added", d->added);
    rs_jobj_u64(res, "deleted", d->deleted);
    rs_jobj_u64(res, "modified", d->modified);
    if (by_package)
    {
        rs_jobj_u64(res, "packages_changed", d->packages);
    }
    *rs_jobj_add(res, "changes") = first;
    rs_jobj_bool(res, "truncated", truncated);
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

/* `path` as what it names now: a repository's newest snapshot as REPO::NAME,
 * so that what is read and what the result names are the same snapshot,
 * however many are added meanwhile. Anything else as it is, and so is a
 * reference that does not resolve, for what reads it to say why. */
static char *pinned(const char *path)
{
    struct rs_repo *r;
    struct rs_buf   err;
    char           *dir;
    char           *name;
    char           *found = NULL;
    char           *out;
    bool            busy;

    if (!rs_repo_ref(path, &dir, &name))
    {
        return rs_xstrdup(path);
    }
    rs_buf_init(&err);
    r = rs_repo_open(dir, RS_REPO_LOOK, &busy, &err);
    if (r)
    {
        found = rs_repo_resolve(r, name, &err);
        rs_repo_close(r);
    }
    out = found ? rs_xasprintf("%s::%s", dir, found) : rs_xstrdup(path);
    free(found);
    free(dir);
    free(name);
    rs_buf_free(&err);
    return out;
}

/* Names what was read in the result: a snapshot, or an image or index. */
static void result_source(const char *ref)
{
    char *dir;
    char *name;

    if (rs_repo_ref(ref, &dir, &name))
    {
        rs_jobj_str(rs_result(), "snapshot", ref);
        free(dir);
        free(name);
    } else
    {
        rs_jobj_str(rs_result(), "image", ref);
    }
}

/*
 * The index of the image or snapshot `path` names, pinned (see pinned) and
 * named in the result, and checked against --trusted-key if any is given:
 * RESTATE_EXIT_OK with it in `ix`, which the caller frees, or what went wrong,
 * said, with nothing to free.
 */
static int load_trusted(const struct rs_options *o, const char *path, struct rs_index *ix)
{
    struct rs_buf err;
    struct trust  tr;
    char         *ref = pinned(path);
    int           status;

    rs_index_init(ix);
    result_source(ref);
    status = trust_check(o, ref, o->ntrusted > 0, &tr);
    if (status == RESTATE_EXIT_OK)
    {
        rs_buf_init(&err);
        if (!rs_index_load(ix, ref, &err))
        {
            rs_error("%s", err.data);
            status = RESTATE_EXIT_TROUBLE;
        } else
        {
            status = trust_matches(o, ref, &tr, ix);
        }
        rs_buf_free(&err);
    }
    if (status != RESTATE_EXIT_OK)
    {
        rs_index_free(ix);
    }
    free(ref);
    return status;
}

/* Whether the object `obj` has `key` true. */
static bool true_in(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return v && v->type == RS_JBOOL && v->b;
}

/*
 * verify and status: an image or snapshot compared against the tree as it is
 * now. `incremental` is status's walk: a file whose size, times and inode are
 * what the capture recorded is taken to be unchanged and not read, so it
 * takes as long as reading what did change.
 */
static int compare_live(const struct rs_options *o, bool incremental)
{
    struct rs_index      recorded;
    struct rs_index      live;
    struct rs_scan_stats st;
    struct rs_diff_stats d;
    struct sink          sink;
    struct rs_options    by;
    const char          *root;
    int                  status = load_trusted(o, o->args[0], &recorded);

    if (status != RESTATE_EXIT_OK)
    {
        return status;
    }
    /* Classified by the rules the capture was, unless given others:
     * otherwise everything they left out would be "added". --all,
     * --one-file-system and --rules-only add to what it recorded. */
    by = *o;
    if (recorded.classification.type == RS_JOBJECT && !o->nrules_files &&
        !o->no_default_rules && !o->os)
    {
        const struct rs_jval *cl = &recorded.classification;

        by.classified = cl;
        by.all = o->all || true_in(cl, "all");
        by.one_fs = o->one_fs || true_in(cl, "one_file_system");
        by.rules_only = o->rules_only || true_in(cl, "rules_only");
        o = &by;
    }
    rs_jobj_bool(rs_result(), "capture_rules", o->classified != NULL);
    /* The root the index was taken from, unless told otherwise: verifying an
     * index of /mnt/old against / would report every file as changed. */
    root = o->root ? o->root : (recorded.root ? recorded.root : "/");
    memset(&sink, 0, sizeof(sink));
    sink.prev = &recorded;
    if (!run_scan(o, root, recorded.hashed && !o->no_hash, incremental ? &sink : NULL, &live,
                  &st, &recorded.packages))
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

int rs_cmd_verify(const struct rs_options *o)
{
    return compare_live(o, false);
}

/* What has changed since a capture, quickly: the walk verify makes, but
 * incremental (see compare_live). */
int rs_cmd_status(const struct rs_options *o)
{
    return compare_live(o, true);
}

/* How many of a directory's names a list's result gives; its output gives
 * them all. */
#define LIST_RESULT_MAX 5000

/* `value` as the index writes a name: as it is, if it is UTF-8; otherwise
 * made so, and exactly as it is, base64, in KEY_base64. */
static void json_bytes(struct rs_jval *obj, const char *key, const char *value)
{
    size_t len = strlen(value);

    if (rs_utf8_valid(value, len))
    {
        rs_jobj_str(obj, key, value);
    } else
    {
        char         *lossy = rs_utf8_lossy(value, len);
        char         *key64 = rs_xasprintf("%s_base64", key);
        struct rs_buf b64;

        rs_buf_init(&b64);
        rs_base64_encode(&b64, value, len);
        rs_jobj_str(obj, key, lossy);
        rs_jobj_str(obj, key64, b64.data);
        rs_buf_free(&b64);
        free(key64);
        free(lossy);
    }
}

/* A directory's names into `doc`, at most `max` of them, as list's output and
 * result give them. */
static void list_json(struct rs_jval *doc, const char *dir, const struct rs_child *kids, size_t n,
                      size_t max)
{
    struct rs_jval *list;
    size_t          i;

    memset(doc, 0, sizeof(*doc));
    rs_jval_set_object(doc);
    json_bytes(doc, "path", dir);
    list = rs_jobj_add(doc, "entries");
    rs_jval_set_array(list);
    for (i = 0; i < n && i < max; i++)
    {
        const struct rs_entry *e = kids[i].entry;
        struct rs_jval        *j = rs_jarr_add(list);
        char                   t = 'd';

        if (e)
        {
            t = e->type;
        }
        rs_jval_set_object(j);
        json_bytes(j, "name", kids[i].name);
        rs_jobj_str(j, "type", t == 'f' ? "file" : t == 'd' ? "dir" : t == 'l' ? "link" : "other");
        if (e)
        {
            char mode[8];
            char when[RS_TIME_STR_MAX];

            (void)snprintf(mode, sizeof(mode), "%04o", (unsigned)e->mode);
            rs_time_format(&e->mtime, when);
            rs_jobj_u64(j, "size", e->size);
            rs_jobj_str(j, "mode", mode);
            rs_jobj_str(j, "mtime", when);
            rs_jobj_str(j, "user", e->user);
            rs_jobj_str(j, "group", e->group);
            if (e->target)
            {
                json_bytes(j, "target", e->target);
            }
        }
    }
    rs_jobj_bool(doc, "truncated", n > max);
}

/* A directory's names as lines, much as ls -l writes them. */
static void list_text(struct rs_buf *text, const struct rs_child *kids, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        const struct rs_entry *e = kids[i].entry;

        if (e)
        {
            char when[RS_TIME_STR_MAX];
            char uid[24];
            char gid[24];

            rs_time_format(&e->mtime, when);
            (void)snprintf(uid, sizeof(uid), "%" PRIu64, e->uid); /* Flawfinder: ignore */
            (void)snprintf(gid, sizeof(gid), "%" PRIu64, e->gid); /* Flawfinder: ignore */
            rs_buf_addf(text, "%c %04o %-8s %-8s %12" PRIu64 " %s  ", e->type, (unsigned)e->mode,
                        e->user ? e->user : uid, e->group ? e->group : gid, e->size, when);
        } else
        {
            /* Paths beneath it, but no entry of its own: rules left it out. */
            rs_buf_addf(text, "d %4s %-8s %-8s %12s %s  ", "-", "-", "-", "-", "-");
        }
        rs_escape(text, kids[i].name);
        if (e && e->target)
        {
            rs_buf_addstr(text, " -> ");
            rs_escape(text, e->target);
        }
        rs_buf_addc(text, '\n');
    }
}

/* What is in one directory of an image or snapshot, from its index alone:
 * no pack, and no content, is read. */
int rs_cmd_list(const struct rs_options *o)
{
    const struct rs_entry *self;
    struct rs_child       *kids = NULL;
    struct rs_index        ix;
    struct rs_jval         doc;
    struct rs_buf          text;
    struct output          out;
    char                  *dir = rs_xstrdup(o->nargs > 1 ? o->args[1] : "/");
    size_t                 len = strlen(dir);
    size_t                 n = 0;
    int                    status;

    while (len > 1 && dir[len - 1] == '/')
    {
        dir[--len] = '\0';
    }
    if (!rs_path_is_clean(dir))
    {
        rs_error("list: %s is not an absolute path with no \".\" or \"..\" in it", dir);
        free(dir);
        return RESTATE_EXIT_TROUBLE;
    }
    status = load_trusted(o, o->args[0], &ix);
    if (status != RESTATE_EXIT_OK)
    {
        free(dir);
        return status;
    }
    self = rs_index_find(&ix, dir);
    kids = rs_index_children(&ix, dir, &n);
    if (self && self->type != 'd')
    {
        rs_error("list: %s is a %s in %s, not a directory", dir, rs_type_name(self->type),
                 o->args[0]);
        status = RESTATE_EXIT_TROUBLE;
    } else if (!self && n == 0 && strcmp(dir, "/") != 0)
    {
        rs_error("list: %s has no %s", o->args[0], dir);
        status = RESTATE_EXIT_TROUBLE;
    }
    if (status == RESTATE_EXIT_OK)
    {
        bool ok;

        list_json(&doc, dir, kids, n, LIST_RESULT_MAX);
        *rs_jobj_add(rs_result(), "list") = doc;
        rs_buf_init(&text);
        if (o->json)
        {
            list_json(&doc, dir, kids, n, SIZE_MAX);
            rs_json_write(&text, &doc, 2, 0);
            rs_buf_addc(&text, '\n');
            rs_jval_free(&doc);
        } else
        {
            list_text(&text, kids, n);
        }
        ok = output_open(o, &out);
        if (ok)
        {
            ok = text.len == 0 || fwrite(text.data, 1, text.len, out.fp) == text.len;
            if (!ok)
            {
                rs_error("%s: %s", out.tmp ? out.tmp : "standard output", strerror(errno));
            }
            ok = output_close(&out, ok);
        }
        rs_buf_free(&text);
        status = ok ? RESTATE_EXIT_OK : RESTATE_EXIT_TROUBLE;
    }
    rs_index_children_free(kids, n);
    rs_index_free(&ix);
    free(dir);
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
 * restore --packages --offline: what there is to install from, said, or why
 * there is nothing -- the baseline cache is everything apt will be given.
 */
static bool offline_ready(const struct rs_options *o, const struct rs_index *ix,
                          const char *cache)
{
    struct rs_baseline_stats st;
    struct rs_buf            list;

    if (!cache)
    {
        rs_error("--offline installs from the baseline cache, and there is none at %s: run "
                 "restate baseline fetch on the image while there is a network",
                 o->cache ? o->cache : rs_baseline_default_cache());
        return false;
    }
    rs_buf_init(&list);
    rs_baseline_list(&ix->packages, cache, &list, &st);
    rs_buf_free(&list);
    if (!o->quiet)
    {
        (void)fprintf(stderr, "restate: offline: %zu of the image's %zu packages from "
                      "repositories are in %s; the %zu installed from .deb files come from the "
                      "image where it keeps them%s\n", st.cached, st.wanted, cache, st.local,
                      st.cached < st.wanted ? "; apt cannot install the rest, or what needs them"
                                            : "");
    }
    return true;
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
    io.offline = o->offline;
    if (o->offline && !offline_ready(o, ix, io.cache))
    {
        free(snapshot);
        return RESTATE_EXIT_TROUBLE;
    }
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

/*
 * Whether to leave the image's /etc/fstab and /etc/crypttab out, and keep
 * the root's own: when the image's name disks this machine does not have,
 * and the root has its own to keep (see fstab.h). Says which, either way.
 */
static bool keep_own_fstab(const struct rs_options *o, const struct rs_index *ix,
                           const char *root)
{
    static const char *const files[] = { "etc/fstab", "etc/crypttab" };
    struct rs_buf            why;
    bool                     own = false;
    bool                     keep = false;
    size_t                   i;

    if (ix->machine.type != RS_JOBJECT)
    {
        return false;
    }
    rs_buf_init(&why);
    if (!rs_fstab_foreign(&ix->machine, "/dev", &why))
    {
        rs_buf_free(&why);
        return false;
    }
    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++)
    {
        char       *p = rs_xasprintf("%s/%s", strcmp(root, "/") == 0 ? "" : root, files[i]);
        struct stat st;

        own = own || lstat(p, &st) == 0;
        free(p);
    }
    if (o->image_fstab)
    {
        rs_warn("the image's /etc/fstab and /etc/crypttab name disks this machine does not "
                "have: %s; put back all the same, as --image-fstab says: correct them before "
                "it next boots", why.data);
    } else if (own)
    {
        keep = true;
        if (!o->quiet)
        {
            (void)fprintf(stderr, "restate: %s %s's own /etc/fstab and /etc/crypttab, not the "
                          "image's, which name disks this machine does not have: %s "
                          "(--image-fstab puts the image's back all the same)\n",
                          o->dry_run ? "would keep" : "keeping", root, why.data);
        }
    }
    rs_buf_free(&why);
    return keep;
}

/*
 * restore --as: which of the image's entries are its identity, by what the
 * index records and by the rules for the system it was taken from, so an
 * image from before the class is read as the class would have it. NULL,
 * with the error said, if the rules cannot be read.
 */
static bool *identity_of(const struct rs_options *o, const struct rs_index *ix)
{
    struct rs_options with = *o;
    struct rs_rules   rules;
    const char       *os_used;
    bool             *leave;

    if (!with.os && ix->os && rs_rules_known_os(ix->os))
    {
        with.os = ix->os;
    }
    if (!load_rules(&with, &rules, &os_used))
    {
        return NULL;
    }
    leave = rs_xcalloc(ix->count + 1, sizeof(*leave));
    (void)rs_identity_mark(ix, &rules, leave);
    rs_rules_free(&rules);
    return leave;
}

/* The host name the image's machine had, which its /etc/hosts gives: as
 * its description records it, or, for a capture of the running system, as
 * the capture found it. NULL for a tree captured from elsewhere. */
static const char *image_host(const struct rs_index *ix)
{
    const char *name = rs_jobject_str(rs_jobject_get(&ix->machine, "system"), "hostname");

    if (!name && ix->root && strcmp(ix->root, "/") == 0)
    {
        name = ix->host;
    }
    return name;
}

/* What restore --as did, after the files. Exit status as restore's. */
/*
 * The PostgreSQL clusters the image keeps: each data directory, by the
 * global/pg_control in it, that a restore would put back. A cluster's
 * system identifier is in that file, set by initdb and by nothing after:
 * every copy restored from the image has the original's, and replication
 * takes two clusters with one identifier for one -- a standby of the other,
 * or the same primary twice. restate cannot give a copy its own; it says so.
 */
static char **pg_clusters(const struct rs_index *ix, size_t *n)
{
    static const char tail[] = "/global/pg_control";
    char            **dirs = NULL;
    size_t            i;

    *n = 0;
    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];
        size_t                 len = e->path ? strlen(e->path) : 0;

        if (e->type == 'f' && (e->cls == RS_CLASS_STATE || e->cls == RS_CLASS_IDENTITY) &&
            len > sizeof(tail) - 1 && strcmp(e->path + len - (sizeof(tail) - 1), tail) == 0)
        {
            dirs = rs_xreallocarray(dirs, *n + 1, sizeof(*dirs));
            dirs[(*n)++] = rs_xstrndup(e->path, len - (sizeof(tail) - 1));
        }
    }
    return dirs;
}

/* Says, for a copy made with --as, that each cluster is the original's. */
static void pg_same_cluster(const struct rs_options *o, const struct rs_index *ix)
{
    size_t n;
    char **dirs = pg_clusters(ix, &n);
    size_t i;

    for (i = 0; i < n; i++)
    {
        struct rs_buf b;

        rs_buf_init(&b);
        rs_escape(&b, dirs[i]);
        if (!o->quiet)
        {
            (void)fprintf(stderr, "restate: as %s: the PostgreSQL cluster in %s keeps the "
                          "image's system identifier, which only initdb sets: to replication "
                          "it is the original's cluster. A copy that is to replicate is made a "
                          "standby with pg_basebackup from its primary, not restored from an "
                          "image\n", o->as, b.data ? b.data : "");
        }
        rs_buf_free(&b);
        free(dirs[i]);
    }
    free(dirs);
}

static int renew_identity(const struct rs_options *o, const struct rs_index *ix, const bool *leave,
                          const char *root, uint64_t left)
{
    struct rs_identity_stats is;
    struct rs_buf            err;

    rs_buf_init(&err);
    if (!rs_identity_renew(root, ix, leave, o->as, image_host(ix), o->dry_run, o->verbose, &is,
                           &err))
    {
        rs_error("--as: %s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    {
        struct rs_jval *as = rs_jobj_add(rs_result(), "as");

        rs_jval_set_object(as);
        rs_jobj_str(as, "name", o->as);
        rs_jobj_u64(as, "left_out", left);
        rs_jobj_u64(as, "kept", is.kept);
        rs_jobj_u64(as, "made", is.made);
        rs_jobj_u64(as, "removed", is.removed);
        rs_jobj_u64(as, "failed", is.failed);
        rs_jobj_bool(as, "host_keys", is.host_keys);
        rs_jobj_u64(as, "hosts", is.hosts);
    }
    if (!o->quiet)
    {
        (void)fprintf(stderr, "restate: as %s: %s the image's identity (%" PRIu64 " paths); %"
                      PRIu64 " of this machine's own kept, %" PRIu64 " made new%s, %" PRIu64
                      " of the image's own removed for their services to make anew\n",
                      o->as, o->dry_run ? "would leave out" : "left out", left, is.kept, is.made,
                      is.host_keys ? " and new SSH host keys" : "", is.removed);
        (void)fprintf(stderr, "restate: as %s: the host name %s %s%s\n", o->as,
                      o->dry_run ? "would be" : "is now", o->as,
                      is.hosts > 0 ? ", in /etc/hosts too" : "");
        if (!o->dry_run && strcmp(root, "/") == 0)
        {
            (void)fprintf(stderr, "restate: as %s: reboot, for every service to take up the "
                          "new identity\n", o->as);
        }
    }
    pg_same_cluster(o, ix);
    return is.failed > 0 ? RESTATE_EXIT_INCOMPLETE : RESTATE_EXIT_OK;
}

/* What restore put back, or would, in its result: the counts, and the
 * first paths, which a dry run shows before anything is written. */
static void restore_result(const struct rs_options *o, const struct rs_restore_stats *st,
                           struct rs_jval *plan, const char *root)
{
    struct rs_jval *res = rs_jobj_add(rs_result(), "restore");

    rs_jval_set_object(res);
    rs_jobj_str(res, "from", o->args[0]);
    rs_jobj_str(res, "root", root);
    rs_jobj_bool(res, "dry_run", o->dry_run);
    /* False for a plan: the files were counted from the index, and none was
     * read to see that it is what the index says. */
    rs_jobj_bool(res, "content_read", !o->plan_only);
    rs_jobj_u64(res, "files", st->files);
    rs_jobj_u64(res, "bytes", st->bytes);
    rs_jobj_u64(res, "directories", st->directories);
    rs_jobj_u64(res, "symlinks", st->symlinks);
    rs_jobj_u64(res, "unchanged", st->unchanged);
    rs_jobj_u64(res, "excluded", st->excluded);
    rs_jobj_u64(res, "identity", st->identity);
    rs_jobj_u64(res, "refused", st->refused);
    rs_jobj_u64(res, "failed", st->failed);
    rs_jobj_u64(res, "missing", st->missing);
    rs_jobj_u64(res, "plan_count", st->planned);
    rs_jobj_u64(res, "other_arch", st->other_arch);
    rs_jobj_u64(res, "other_arch_left", st->other_arch_left);
    *rs_jobj_add(res, "plan") = *plan;
    memset(plan, 0, sizeof(*plan));
}

int rs_cmd_restore(const struct rs_options *o)
{
    struct rs_jval          plan;
    struct rs_index         ix;
    struct rs_restore_opts  ro;
    struct rs_restore_stats st;
    struct rs_buf           err;
    struct trust            tr;
    int                     status;
    int                     packages = RESTATE_EXIT_OK;
    int                     renewed = RESTATE_EXIT_OK;
    const char            **excludes = NULL;
    const char             *left_out = "--exclude";
    bool                   *leave = NULL;
    bool                    keep_fstab;
    bool                    ok;

    if (o->offline && !o->packages)
    {
        rs_error("--offline is how restore --packages installs them: give --packages too");
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->plan_only && (o->packages || o->check_first))
    {
        rs_error("--plan reads only the index, and %s reads the image: give --dry-run instead",
                 o->packages ? "--packages" : "--check-first");
        return RESTATE_EXIT_TROUBLE;
    }
    if (o->offline && o->exact_versions)
    {
        rs_error("--offline and --exact-versions: the archive's snapshot is on the network, and "
                 "offline every package is already at the version the baseline fetched");
        return RESTATE_EXIT_TROUBLE;
    }
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
    ro.include = o->includes;
    ro.ninclude = o->nincludes;
    ro.verbose = o->verbose;
    ro.numeric_owner = o->numeric_owner;
    if (o->as)
    {
        leave = identity_of(o, &ix);
        if (!leave)
        {
            rs_buf_free(&err);
            rs_index_free(&ix);
            return RESTATE_EXIT_TROUBLE;
        }
    }
    ro.leave = leave;
    keep_fstab = keep_own_fstab(o, &ix, ro.root);
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
            free(leave);
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
            free(leave);
            return packages;
        }
    }
    ro.dry_run = o->dry_run;
    ro.index_only = o->plan_only;
    ro.kit = false;
    if (o->packages || keep_fstab)
    {
        size_t n = o->nexcludes;

        excludes = rs_xcalloc(o->nexcludes + 3, sizeof(*excludes));
        if (o->nexcludes > 0)
        {
            memcpy(excludes, o->excludes, o->nexcludes * sizeof(*excludes));
        }
        /* Which packages were installed by hand: the script has just made
         * that what the old machine had, for the packages there are now. */
        if (o->packages)
        {
            excludes[n++] = "/var/lib/apt/extended_states";
            left_out = "--exclude, and apt's record of what was installed by hand, which "
                       "--packages set";
        }
        if (keep_fstab)
        {
            excludes[n++] = "/etc/fstab";
            excludes[n++] = "/etc/crypttab";
            left_out = o->packages ? "--exclude, apt's record of what was installed by hand, "
                                     "which --packages set, and the image's fstab and crypttab"
                                   : "--exclude, and the image's fstab and crypttab";
        }
        ro.exclude = excludes;
        ro.nexclude = n;
    }
    memset(&plan, 0, sizeof(plan));
    rs_jval_set_array(&plan);
    ro.plan = &plan;
    ro.plan_max = RESTORE_PLAN_MAX;
    {
        struct utsname        u;
        const struct rs_arch *a = o->arch ? rs_arch_find(o->arch)
                                          : rs_arch_here(uname(&u) == 0 ? u.machine : NULL);

        ro.arch = a ? a->name : NULL;
    }
    ok = rs_restore(o->args[0], &ix, &ro, &st, &err);
    free(excludes);
    restore_result(o, &st, &plan, ro.root);
    if (!ok)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_index_free(&ix);
        free(leave);
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
        if (o->plan_only)
        {
            (void)fprintf(stderr, "restate: planned from the index alone: no file's content was "
                          "read or checked (--dry-run checks it)\n");
        }
        if (st.unchanged > 0)
        {
            (void)fprintf(stderr, "restate: %" PRIu64 " of those files were in place already, "
                          "as the image has them: left as they were, but for their owners, "
                          "modes and times\n", st.unchanged);
        }
        if (st.merged)
        {
            (void)fprintf(stderr, "restate: owners mapped by name, through the image's accounts "
                          "merged with %s's own\n", ro.root);
        }
        if (st.excluded > 0)
        {
            (void)fprintf(stderr, "restate: left out %" PRIu64 " paths (%s)\n", st.excluded,
                          left_out);
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
        if (st.other_arch_left > 0)
        {
            (void)fprintf(stderr, "restate: %" PRIu64 " program%s a package installed %s the "
                          "image's for another processor: left as this %s machine's package "
                          "has %s\n", st.other_arch_left, st.other_arch_left == 1 ? "" : "s",
                          st.other_arch_left == 1 ? "is" : "are", ro.arch,
                          st.other_arch_left == 1 ? "it" : "them");
        }
        if (st.other_arch > 0)
        {
            (void)fprintf(stderr, "restate: warning: %" PRIu64 " program%s put back, which no "
                          "package installed, %s built for another processor and will not run "
                          "on this %s machine: build %s again (restate buildsheet --arch "
                          "names %s)\n", st.other_arch, st.other_arch == 1 ? "" : "s",
                          st.other_arch == 1 ? "is" : "are", ro.arch,
                          st.other_arch == 1 ? "it" : "them", st.other_arch == 1 ? "it" : "them");
        }
    }
    if (leave)
    {
        renewed = renew_identity(o, &ix, leave, ro.root, st.identity);
        free(leave);
    }
    rs_index_free(&ix);
    if (renewed == RESTATE_EXIT_TROUBLE)
    {
        return renewed;
    }
    if (st.refused + st.failed + st.missing > 0)
    {
        (void)fprintf(stderr, "restate: %" PRIu64 " refused, %" PRIu64 " not written, %" PRIu64
                      " missing from the image; the restore is incomplete\n",
                      st.refused, st.failed, st.missing);
        return RESTATE_EXIT_INCOMPLETE;
    }
    return packages != RESTATE_EXIT_OK ? packages : renewed;
}

/* ------------------------------------------------------------------------- */
/* Explaining                                                                */
/* ------------------------------------------------------------------------- */

OUTPUT_HELD_BEGIN
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

OUTPUT_HELD_END

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
                    (strncmp(e->path, mp, len) == 0 &&
                     (e->path[len] == '/' || e->path[len] == '\0'));
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

/* The programs the image keeps -- ELF files it would put back, not those a
 * package reinstalls -- into the description's "programs", for a rebuild on
 * another processor to say which of them will not run there. */
#define PROGRAMS_MAX 1000
static void note_programs(const struct rs_index *ix, struct rs_jval *machine)
{
    struct rs_jval *list = NULL;
    size_t          i;

    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];
        struct rs_jval        *p;

        if (e->type != 'f' || !e->arch ||
            (e->cls != RS_CLASS_STATE && e->cls != RS_CLASS_IDENTITY))
        {
            continue;
        }
        if (!list)
        {
            list = rs_jobj_add(machine, "programs");
            rs_jval_set_array(list);
        }
        if (list->n == PROGRAMS_MAX)
        {
            break;
        }
        p = rs_jarr_add(list);
        rs_jval_set_object(p);
        rs_jobj_str(p, "path", e->path);
        rs_jobj_str(p, "arch", e->arch);
        rs_jobj_str(p, "package", e->package);
    }
}

/* The PostgreSQL clusters the image keeps, into the description's
 * "postgresql_clusters": for an autoinstall file of copies to say that each
 * copy's is the original's (pg_clusters). */
static void note_clusters(const struct rs_index *ix, struct rs_jval *machine)
{
    size_t          n;
    char          **dirs = pg_clusters(ix, &n);
    struct rs_jval *list;
    size_t          i;

    if (n == 0)
    {
        return;
    }
    list = rs_jobj_add(machine, "postgresql_clusters");
    rs_jval_set_array(list);
    for (i = 0; i < n; i++)
    {
        rs_jval_set_string(rs_jarr_add(list), dirs[i]);
        free(dirs[i]);
    }
    free(dirs);
}

/* Sets `key` in `obj` to `value`, in place of what it was. */
static void set_str(struct rs_jval *obj, const char *key, const char *value)
{
    size_t i;

    for (i = 0; obj->type == RS_JOBJECT && i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            rs_jval_free(&obj->items[i]);
            rs_jval_set_string(&obj->items[i], value);
            return;
        }
    }
    rs_jobj_str(obj, key, value);
}

/* The mutable member `key` of `obj`, or NULL. */
static struct rs_jval *member(struct rs_jval *obj, const char *key)
{
    size_t i;

    for (i = 0; obj->type == RS_JOBJECT && i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    return NULL;
}

/* How a machine of `a` boots, rebuilt as one: ARM and RISC-V by UEFI, as
 * Ubuntu's installers for them do; POWER from a PReP partition, as a virtual
 * machine under KVM or PowerVM does; IBM Z by its IPL, of what zipl writes.
 * NULL for x86, which boots either way: as the old machine did, if that
 * was one of the two. */
static const char *arch_firmware(const struct rs_arch *a, const char *was)
{
    if (strcmp(a->name, "s390x") == 0)
    {
        return "zipl";
    }
    if (strncmp(a->name, "ppc64", 5) == 0)
    {
        return "ieee1275";
    }
    if (strcmp(a->name, "x86_64") == 0 || strcmp(a->name, "i686") == 0)
    {
        return was && (strcmp(was, "uefi") == 0 || strcmp(was, "bios") == 0) ? NULL : "uefi";
    }
    return "uefi";
}

/*
 * --arch: the machine rebuilt for another processor. Its description then
 * says the new one -- "arch" and "architecture" -- and "rebuilt_from" the
 * old; and *firmware, unless --firmware chose, how the new one boots. A
 * --firmware the new one cannot boot by is refused.
 */
static bool retarget(const struct rs_options *o, struct rs_jval *machine, const char **firmware)
{
    const struct rs_arch *to = o->arch ? rs_arch_find(o->arch) : NULL;
    const struct rs_arch *from = rs_arch_of_machine(machine);
    struct rs_jval       *sys = member(machine, "system");
    const char           *was = rs_jobject_str(rs_jobject_get(machine, "firmware"), "mode");
    bool                  x86;

    *firmware = o->firmware;
    if (!to || !sys || to == from)
    {
        return true;
    }
    x86 = strcmp(to->name, "x86_64") == 0 || strcmp(to->name, "i686") == 0;
    if (o->firmware && !x86 && strcmp(o->firmware, arch_firmware(to, NULL)) != 0)
    {
        rs_error("--firmware %s: %s machines boot only by %s", o->firmware, to->name,
                 arch_firmware(to, NULL));
        return false;
    }
    if (!o->firmware)
    {
        *firmware = arch_firmware(to, was);
    }
    rs_jobj_str(sys, "rebuilt_from", from ? from->name : rs_jobject_str(sys, "architecture"));
    set_str(sys, "arch", to->name);
    set_str(sys, "architecture", to->name);
    return true;
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
            note_programs(&ix, machine);
            note_clusters(&ix, machine);
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
    {
        const char *firmware;

        if (!retarget(o, &machine, &firmware))
        {
            rs_jval_free(&machine);
            return RESTATE_EXIT_TROUBLE;
        }
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
    bo.arch = o->arch ? rs_arch_find(o->arch)->debian : NULL;
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
            if (st.foreign > 0)
            {
                (void)fprintf(stderr, "restate: %zu of a third processor's, as multiarch "
                              "installed them, left out: they have no place on a %s machine\n",
                              st.foreign, bo.arch);
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

/* --firmware changes the partitions, which only a rebuild elsewhere renumbers;
 * and a machine of another processor is other hardware. */
static bool firmware_ok(const struct rs_options *o)
{
    if (o->firmware && !o->target)
    {
        rs_error("--firmware needs --target vm or --target metal: rebuilt as the same "
                 "machine, it boots as that machine did");
        return false;
    }
    if (o->arch && !o->target)
    {
        rs_error("--arch needs --target vm or --target metal: a machine of another "
                 "processor is other hardware");
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
    const char          *firmware = NULL;
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
        !retarget(o, &machine, &firmware) || !trust_for(o, knows, false, &trust, &keyring))
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
    so.firmware = firmware;
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
    const char         *firmware = NULL;
    bool                old_image;
    bool                knows;
    char               *trust = NULL;
    char               *keyring = NULL;
    char               *created = NULL;
    char               *snapshot;
    struct rs_clones    clones;
    struct rs_buf       from;
    bool                ok;

    if (!from_a_file(image) || !firmware_ok(o))
    {
        return RESTATE_EXIT_TROUBLE;
    }
    rs_clones_init(&clones);
    rs_buf_init(&from);
    if (o->clones)
    {
        rs_buf_init(&err);
        if (!rs_clones_load_file(&clones, o->clones, &err))
        {
            rs_error("--clones: %s", err.data);
            rs_buf_free(&err);
            return RESTATE_EXIT_TROUBLE;
        }
        rs_buf_free(&err);
        rs_escape(&from, o->clones);
    }
    if (!machine_for(o, image, &machine, &packages, &old_image, &knows, &created) ||
        !retarget(o, &machine, &firmware) || !trust_for(o, knows, true, &trust, &keyring))
    {
        rs_jval_free(&machine);
        rs_jval_free(&packages);
        free(created);
        rs_clones_free(&clones);
        rs_buf_free(&from);
        return RESTATE_EXIT_TROUBLE;
    }
    snapshot = o->exact_versions ? rs_repo_snapshot_name(created) : NULL;
    memset(&ao, 0, sizeof(ao));
    ao.snapshot = snapshot;
    ao.trust = trust;
    ao.trust_keyring = keyring;
    ao.old_image = old_image;
    ao.target = target_of(o);
    ao.firmware = firmware;
    ao.image = image;
    ao.version = RESTATE_VERSION;
    ao.packages = packages.type == RS_JOBJECT ? &packages : NULL;
    ao.image_at = o->image_at;
    ao.clones = o->clones ? &clones : NULL;
    ao.clones_from = from.data;
    rs_buf_init(&text);
    rs_buf_init(&err);
    ok = rs_autoinstall(&machine, &ao, &text, &err);
    rs_clones_free(&clones);
    rs_buf_free(&from);
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

OUTPUT_HELD_BEGIN
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

OUTPUT_HELD_END

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

/* The command `o` names, run. */
static int dispatch(const struct rs_options *o)
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
    case CMD_REPACK:
        return rs_cmd_repack(o);
    case CMD_PROTECT:
        return rs_cmd_protect(o);
    case CMD_CHECK:
        return rs_cmd_check(o);
    case CMD_EXPORT:
        return rs_cmd_export(o);
    case CMD_STATUS:
        return rs_cmd_status(o);
    case CMD_LIST:
        return rs_cmd_list(o);
    case CMD_COPY:
        return rs_cmd_copy(o);
    case CMD_DU:
        return rs_cmd_du(o);
    case CMD_ESTIMATE:
        return rs_cmd_estimate(o);
    case CMD_FEATURES:
        return rs_cmd_features(o);
    case CMD_RUN:
        rs_error("run: a job cannot run another job");
        return RESTATE_EXIT_TROUBLE;
    case CMD_NONE:
    case CMD_COUNT:
    default:
        rs_error("no command given");
        return RESTATE_EXIT_TROUBLE;
    }
}

/* The passphrase, read once from `fd` -- to its end, or its first line --
 * and held for every gpg the run starts; `from` says where, in a message. */
static bool read_passphrase(int fd, const char *from)
{
    char    buf[1024];
    size_t  len = 0;
    ssize_t n;

    while (len < sizeof(buf) - 1 && (n = read(fd, buf + len, sizeof(buf) - 1 - len)) != 0)
    {
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0)
        {
            rs_error("%s: %s", from, strerror(errno));
            return false;
        }
        len += (size_t)n;
        if (memchr(buf, '\n', len))
        {
            break;
        }
    }
    buf[len] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';
    rs_pgp_set_passphrase(buf);
    {
        volatile char *v = buf;
        size_t         i;

        for (i = 0; i < sizeof(buf); i++)
        {
            v[i] = '\0';
        }
    }
    return true;
}

/*
 * The secrets the run is given, taken before it starts: the passphrase, from
 * --passphrase-fd or a job's passphrase_file, and the key --decrypt-with
 * names, imported. False, having said why, if one cannot be.
 */
static bool take_secrets(const struct rs_options *o)
{
    struct rs_buf err;
    bool          ok = true;

    if (o->passphrase_given)
    {
        char *from = rs_xasprintf("--passphrase-fd %d", o->passphrase_fd);

        ok = read_passphrase(o->passphrase_fd, from);
        free(from);
    } else if (o->passphrase_file)
    {
        int fd = open(o->passphrase_file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

        if (fd < 0)
        {
            rs_error("passphrase_file %s: %s", o->passphrase_file, strerror(errno));
            return false;
        }
        ok = read_passphrase(fd, o->passphrase_file);
        (void)close(fd);
    }
    if (ok && o->ndecrypt_with > 0)
    {
        rs_buf_init(&err);
        ok = rs_pgp_use_secret_key(o->decrypt_with, o->ndecrypt_with, &err);
        if (!ok)
        {
            rs_error("--decrypt-with: %s", err.data);
        }
        rs_buf_free(&err);
    }
    return ok;
}

/*
 * Opens --progress-file: made at once, with nothing in it, and readable as
 * --result is; NULL, having said why, if it cannot be.
 */
static FILE *progress_open(const struct rs_options *o)
{
    char *tmp = NULL;
    int   fd = rs_result_open(o->progress_file, o->report_group, &tmp);
    FILE *fp = NULL;

    if (fd < 0)
    {
        return NULL;
    }
    if (rename(tmp, o->progress_file) == 0)
    {
        fp = fdopen(fd, "w");
    }
    if (!fp)
    {
        rs_error("%s: %s", o->progress_file, strerror(errno));
        (void)unlink(tmp);
        (void)close(fd);
    }
    free(tmp);
    return fp;
}

int rs_cmd_run(const struct rs_options *given)
{
    struct rs_job            job;
    const struct rs_options *o = given;
    FILE                    *progress = NULL;
    int                      status;

    rs_job_init(&job);
    if (given->command == CMD_RUN)
    {
        status = rs_job_load(given, &job);
        if (status != RESTATE_EXIT_OK)
        {
            rs_job_free(&job);
            return status;
        }
        o = &job.opts;
    }
    rs_image_set_stage_dir(o->tmpdir);
    rs_result_begin(rs_command_name(o->command));
    rs_progress_enable(o->progress);
    if (o->progress_file)
    {
        progress = progress_open(o);
        if (!progress)
        {
            rs_result_end();
            rs_job_free(&job);
            return RESTATE_EXIT_TROUBLE;
        }
        rs_progress_json(progress);
    } else if (o->progress_json)
    {
        rs_progress_json(stderr);
    }
    if (given->command == CMD_RUN)
    {
        rs_jobj_str(rs_result(), "job", given->args[0]);
    }
    /* Taken once the result is begun, so that whoever reads it learns why
     * the run did not start. */
    status = take_secrets(o) ? dispatch(o) : RESTATE_EXIT_TROUBLE;
    rs_progress_finish();
    rs_progress_json(NULL);
    if (progress && fclose(progress) != 0)
    {
        rs_warn("%s: %s", o->progress_file, strerror(errno));
    }
    if (!rs_result_write(status, o->result, o->report_group) && status == RESTATE_EXIT_OK)
    {
        status = RESTATE_EXIT_TROUBLE;
    }
    /* The key goes before a held signal ends restate, which would leave it. */
    rs_pgp_forget_secret_key();
    let_stops();
    rs_pgp_set_passphrase(NULL);
    rs_image_set_stage_dir(NULL);
    rs_job_free(&job);
    return status;
}
