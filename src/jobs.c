/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "jobs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "restate.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* The commands a job can be. */
enum {
    J_CAPTURE   = 1u << 0,
    J_PRUNE     = 1u << 1,
    J_CHECK     = 1u << 2,
    J_COPY      = 1u << 3,
    J_SNAPSHOTS = 1u << 4,
    J_RESTORE   = 1u << 5,
    J_ESTIMATE  = 1u << 6,
    J_DU        = 1u << 7,
    J_REPACK    = 1u << 8,
    J_PROTECT   = 1u << 9,
    J_STATUS    = 1u << 10,
    J_LIST      = 1u << 11,
    J_ANY       = 0xfffu
};

static const struct {
    const char     *name;
    enum rs_command cmd;
    unsigned        bit;
} job_commands[] = {
    { "capture", CMD_CAPTURE, J_CAPTURE },       { "prune", CMD_PRUNE, J_PRUNE },
    { "check", CMD_CHECK, J_CHECK },             { "copy", CMD_COPY, J_COPY },
    { "snapshots", CMD_SNAPSHOTS, J_SNAPSHOTS }, { "restore", CMD_RESTORE, J_RESTORE },
    { "estimate", CMD_ESTIMATE, J_ESTIMATE },    { "du", CMD_DU, J_DU },
    { "repack", CMD_REPACK, J_REPACK },          { "protect", CMD_PROTECT, J_PROTECT },
    { "status", CMD_STATUS, J_STATUS },          { "list", CMD_LIST, J_LIST },
};

enum kind {
    K_COMMAND = 0,
    K_BOOL,
    K_COUNT,
    K_PATH,       /* absolute, with no "." or ".." in it */
    K_PATTERN,    /* as a rules file writes one */
    K_NAME,       /* a hook's or a group's */
    K_SNAPSHOT    /* NAME, or REPO::NAME */
};

enum key_id {
    KEY_COMMAND = 0,
    KEY_REPOSITORY,
    KEY_SNAPSHOT,
    KEY_PATH,
    KEY_ROOT,
    KEY_RESTORE_ROOT,
    KEY_RULES,
    KEY_ALL,
    KEY_BASELINE_CONTENT,
    KEY_ONE_FILE_SYSTEM,
    KEY_QUIESCE,
    KEY_QUIESCE_WITH,
    KEY_ENCRYPT_TO,
    KEY_SIGN_WITH,
    KEY_TRUSTED_KEY,
    KEY_ALLOW_UNVERIFIED,
    KEY_APPEND_ONLY,
    KEY_CREATE,
    KEY_KEEP_LAST,
    KEY_KEEP_DAILY,
    KEY_KEEP_WEEKLY,
    KEY_KEEP_MONTHLY,
    KEY_WHOLE_PACKS,
    KEY_READ_ALL,
    KEY_METADATA_ONLY,
    KEY_RECORD,
    KEY_COPY_TO,
    KEY_INCLUDE,
    KEY_EXCLUDE,
    KEY_DRY_RUN,
    KEY_CHECK_FIRST,
    KEY_PLAN,
    KEY_TMPDIR,
    KEY_SYSLOG,
    KEY_RESULT,
    KEY_PROGRESS,
    KEY_REPORT_GROUP,
    KEY_GROUP,
    KEY_COUNT
};

static const struct key {
    const char *name;
    enum kind   kind;
    bool        repeat;
    unsigned    commands;
} keys[KEY_COUNT] = {
    [KEY_COMMAND] = { "command", K_COMMAND, false, J_ANY },
    [KEY_REPOSITORY] = { "repository", K_PATH, false, J_ANY & ~J_ESTIMATE },
    [KEY_SNAPSHOT] = { "snapshot", K_SNAPSHOT, false, J_RESTORE | J_COPY | J_STATUS | J_LIST },
    [KEY_PATH] = { "path", K_PATH, false, J_LIST },
    [KEY_ROOT] = { "root", K_PATH, false, J_CAPTURE | J_ESTIMATE | J_STATUS },
    [KEY_RESTORE_ROOT] = { "restore_root", K_PATH, false, J_RESTORE },
    [KEY_RULES] = { "rules", K_PATH, true, J_CAPTURE | J_ESTIMATE | J_RESTORE },
    [KEY_ALL] = { "all", K_BOOL, false, J_CAPTURE | J_ESTIMATE },
    [KEY_BASELINE_CONTENT] = { "baseline_content", K_BOOL, false, J_CAPTURE | J_ESTIMATE },
    [KEY_ONE_FILE_SYSTEM] = { "one_file_system", K_BOOL, false, J_CAPTURE | J_ESTIMATE },
    [KEY_QUIESCE] = { "quiesce", K_BOOL, false, J_CAPTURE },
    [KEY_QUIESCE_WITH] = { "quiesce_with", K_NAME, true, J_CAPTURE },
    [KEY_ENCRYPT_TO] = { "encrypt_to", K_PATH, true, J_CAPTURE | J_PRUNE },
    [KEY_SIGN_WITH] = { "sign_with", K_PATH, false, J_CAPTURE },
    [KEY_TRUSTED_KEY] = { "trusted_key", K_PATH, true, J_RESTORE | J_CHECK | J_STATUS | J_LIST },
    [KEY_ALLOW_UNVERIFIED] = { "allow_unverified", K_BOOL, false, J_RESTORE },
    [KEY_APPEND_ONLY] = { "append_only", K_BOOL, false, J_CAPTURE },
    [KEY_CREATE] = { "create", K_BOOL, false, J_CAPTURE },
    [KEY_KEEP_LAST] = { "keep_last", K_COUNT, false, J_PRUNE },
    [KEY_KEEP_DAILY] = { "keep_daily", K_COUNT, false, J_PRUNE },
    [KEY_KEEP_WEEKLY] = { "keep_weekly", K_COUNT, false, J_PRUNE },
    [KEY_KEEP_MONTHLY] = { "keep_monthly", K_COUNT, false, J_PRUNE },
    [KEY_WHOLE_PACKS] = { "whole_packs", K_BOOL, false, J_PRUNE },
    [KEY_READ_ALL] = { "read_all", K_BOOL, false, J_CHECK },
    [KEY_METADATA_ONLY] = { "metadata_only", K_BOOL, false, J_CHECK },
    [KEY_RECORD] = { "record", K_PATH, false, J_CHECK | J_PRUNE | J_REPACK },
    [KEY_COPY_TO] = { "copy_to", K_PATH, false, J_COPY },
    [KEY_INCLUDE] = { "include", K_PATTERN, true, J_RESTORE },
    [KEY_EXCLUDE] = { "exclude", K_PATTERN, true, J_RESTORE },
    [KEY_DRY_RUN] = { "dry_run", K_BOOL, false, J_RESTORE | J_PRUNE | J_REPACK },
    [KEY_CHECK_FIRST] = { "check_first", K_BOOL, false, J_RESTORE },
    [KEY_PLAN] = { "plan", K_BOOL, false, J_RESTORE },
    [KEY_TMPDIR] = { "tmpdir", K_PATH, false, J_CAPTURE },
    [KEY_SYSLOG] = { "syslog", K_BOOL, false,
                     J_CAPTURE | J_PRUNE | J_CHECK | J_COPY | J_REPACK | J_PROTECT },
    [KEY_RESULT] = { "result", K_PATH, false, J_ANY },
    [KEY_PROGRESS] = { "progress", K_PATH, false, J_ANY },
    [KEY_REPORT_GROUP] = { "report_group", K_NAME, false, J_ANY },
    [KEY_GROUP] = { "group", K_NAME, false, J_PROTECT },
};

const char *const *rs_job_keys(size_t *n)
{
    static const char *names[KEY_COUNT];
    size_t             i;

    for (i = 0; i < KEY_COUNT; i++)
    {
        names[i] = keys[i].name;
    }
    *n = KEY_COUNT;
    return names;
}

const char *const *rs_job_commands(size_t *n)
{
    static const char *names[sizeof(job_commands) / sizeof(job_commands[0])];
    size_t             i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        names[i] = job_commands[i].name;
    }
    *n = sizeof(names) / sizeof(names[0]);
    return names;
}

void rs_job_init(struct rs_job *job)
{
    memset(job, 0, sizeof(*job));
    job->opts.passphrase_fd = -1;
}

void rs_job_free(struct rs_job *job)
{
    size_t i;

    rs_options_free(&job->opts);
    for (i = 0; i < job->nstrings; i++)
    {
        free(job->strings[i]);
    }
    free(job->strings);
    free(job->ref);
    rs_job_init(job);
}

/* A copy of `s` that lives as long as the job. */
static char *keep(struct rs_job *job, const char *s, size_t len)
{
    char *copy = rs_xstrndup(s, len);

    job->strings = rs_xreallocarray(job->strings, job->nstrings + 1, sizeof(*job->strings));
    job->strings[job->nstrings++] = copy;
    return copy;
}

/* Appends `v` to a list of options. */
static void add(const char ***list, size_t *n, const char *v)
{
    *list = rs_xreallocarray(*list, *n + 1, sizeof(**list));
    (*list)[(*n)++] = v;
}

/* A path a job can give: absolute, printable, with no "." or ".." in it,
 * and no "//". */
static bool path_ok(const char *v)
{
    size_t i;

    if (v[0] != '/' || strlen(v) >= 4096)
    {
        return false;
    }
    for (i = 0; v[i]; i++)
    {
        if ((unsigned char)v[i] < 0x20 || v[i] == 0x7f)
        {
            return false;
        }
        if (v[i] == '/' &&
            (v[i + 1] == '/' ||
             (v[i + 1] == '.' && (v[i + 2] == '/' || v[i + 2] == '\0' ||
                                  (v[i + 2] == '.' && (v[i + 3] == '/' || v[i + 3] == '\0'))))))
        {
            return false;
        }
    }
    return true;
}

/* A group's or a hook's name: letters, digits, '.', '-' and '_'. */
static bool name_ok(const char *v)
{
    size_t i;

    if (v[0] == '\0' || v[0] == '-' || v[0] == '.' || strlen(v) > 64)
    {
        return false;
    }
    for (i = 0; v[i]; i++)
    {
        char c = v[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_'))
        {
            return false;
        }
    }
    return true;
}

static bool printable(const char *v)
{
    size_t i;

    for (i = 0; v[i]; i++)
    {
        if ((unsigned char)v[i] < 0x20 || v[i] == 0x7f)
        {
            return false;
        }
    }
    return v[0] != '\0';
}

/* A snapshot's name alone, or REPO::NAME with REPO a path. */
static bool snapshot_ok(const char *v)
{
    const char *sep = strstr(v, "::");
    size_t      i;

    if (sep)
    {
        char *repo = rs_xstrndup(v, (size_t)(sep - v));
        bool  ok = path_ok(repo) && !strstr(sep + 2, "::");

        free(repo);
        v = sep + 2;
        if (!ok)
        {
            return false;
        }
    }
    if (v[0] == '\0' || v[0] == '.' || strlen(v) > 64)
    {
        return false;
    }
    for (i = 0; v[i]; i++)
    {
        char c = v[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_'))
        {
            return false;
        }
    }
    return true;
}

static bool bool_value(const char *v, bool *out)
{
    if (strcmp(v, "true") == 0 || strcmp(v, "yes") == 0)
    {
        *out = true;
        return true;
    }
    if (strcmp(v, "false") == 0 || strcmp(v, "no") == 0)
    {
        *out = false;
        return true;
    }
    return false;
}

static bool count_value(const char *v, unsigned *out)
{
    unsigned long n = 0;
    size_t        i;

    if (v[0] == '\0' || strlen(v) > 6 || (v[0] == '0' && v[1] != '\0'))
    {
        return false;
    }
    for (i = 0; v[i]; i++)
    {
        if (v[i] < '0' || v[i] > '9')
        {
            return false;
        }
        n = n * 10 + (unsigned long)(v[i] - '0');
    }
    if (n > 100000)
    {
        return false;
    }
    *out = (unsigned)n;
    return true;
}

/* The value `v` checked as `kind` says. */
static bool value_ok(enum kind kind, const char *v)
{
    bool     b;
    unsigned u;

    switch (kind)
    {
    case K_BOOL:
        return bool_value(v, &b);
    case K_COUNT:
        return count_value(v, &u);
    case K_PATH:
        return path_ok(v);
    case K_PATTERN:
        return printable(v);
    case K_NAME:
        return name_ok(v);
    case K_SNAPSHOT:
        return snapshot_ok(v);
    case K_COMMAND:
    default:
        return true;
    }
}

static const char *kind_words(enum kind kind)
{
    switch (kind)
    {
    case K_BOOL:
        return "true or false";
    case K_COUNT:
        return "a number from 0 to 100000";
    case K_PATH:
        return "an absolute path, with no \".\" or \"..\" in it";
    case K_PATTERN:
        return "a pattern";
    case K_NAME:
        return "a name of letters, digits, '.', '-' and '_'";
    case K_SNAPSHOT:
        return "a snapshot's name, or REPO::NAME";
    case K_COMMAND:
    default:
        return "a command";
    }
}

/* Sets what key `k` says in the job's options. The value is checked. */
static void apply(struct rs_job *job, enum key_id k, const char *v)
{
    struct rs_options *o = &job->opts;
    bool               b = false;
    unsigned           u = 0;

    (void)bool_value(v, &b);
    (void)count_value(v, &u);
    switch (k)
    {
    case KEY_REPOSITORY:
    case KEY_SNAPSHOT:
    case KEY_PATH:
    case KEY_COPY_TO:
    case KEY_COMMAND:
        break;   /* made into arguments once the whole job is read */
    case KEY_ROOT:
    case KEY_RESTORE_ROOT:
        o->root = v;
        break;
    case KEY_RULES:
        add(&o->rules_files, &o->nrules_files, v);
        break;
    case KEY_ALL:
        o->all = b;
        break;
    case KEY_BASELINE_CONTENT:
        o->baseline_content = b;
        break;
    case KEY_ONE_FILE_SYSTEM:
        o->one_fs = b;
        break;
    case KEY_QUIESCE:
        o->quiesce = b;
        break;
    case KEY_QUIESCE_WITH:
        add(&o->quiesce_with, &o->nquiesce_with, v);
        break;
    case KEY_ENCRYPT_TO:
        add(&o->recipients, &o->nrecipients, v);
        break;
    case KEY_SIGN_WITH:
        o->sign_with = v;
        break;
    case KEY_TRUSTED_KEY:
        add(&o->trusted, &o->ntrusted, v);
        break;
    case KEY_ALLOW_UNVERIFIED:
        o->allow_unverified = b;
        break;
    case KEY_APPEND_ONLY:
        o->append_only = b;
        break;
    case KEY_CREATE:
        o->create = b;
        break;
    case KEY_KEEP_LAST:
        o->keep_last = u;
        break;
    case KEY_KEEP_DAILY:
        o->keep_daily = u;
        break;
    case KEY_KEEP_WEEKLY:
        o->keep_weekly = u;
        break;
    case KEY_KEEP_MONTHLY:
        o->keep_monthly = u;
        break;
    case KEY_WHOLE_PACKS:
        o->whole_packs = b;
        break;
    case KEY_READ_ALL:
        o->read_all = b;
        break;
    case KEY_METADATA_ONLY:
        o->metadata_only = b;
        break;
    case KEY_RECORD:
        o->record = v;
        break;
    case KEY_INCLUDE:
        add(&o->includes, &o->nincludes, v);
        break;
    case KEY_EXCLUDE:
        add(&o->excludes, &o->nexcludes, v);
        break;
    case KEY_DRY_RUN:
        o->dry_run = b;
        break;
    case KEY_CHECK_FIRST:
        o->check_first = b;
        break;
    case KEY_PLAN:
        /* A plan is a dry run; "plan = false" leaves dry_run as it was. */
        o->plan_only = b;
        o->dry_run = o->dry_run || b;
        break;
    case KEY_TMPDIR:
        o->tmpdir = v;
        break;
    case KEY_SYSLOG:
        o->log_outcome = b;
        break;
    case KEY_RESULT:
        o->result = v;
        break;
    case KEY_PROGRESS:
        o->progress_file = v;
        break;
    case KEY_REPORT_GROUP:
        o->report_group = v;
        break;
    case KEY_GROUP:
        o->group = v;
        break;
    case KEY_COUNT:
    default:
        break;
    }
}

/* The arguments the command takes, from the keys that make them. */
static bool make_args(struct rs_job *job, const char *const *vals, const char *name,
                      struct rs_buf *err)
{
    struct rs_options *o = &job->opts;
    const char        *repo = vals[KEY_REPOSITORY];
    const char        *snap = vals[KEY_SNAPSHOT];

    switch (o->command)
    {
    case CMD_CAPTURE:
        o->output = repo;
        break;
    case CMD_PRUNE:
    case CMD_REPACK:
    case CMD_PROTECT:
    case CMD_CHECK:
    case CMD_SNAPSHOTS:
    case CMD_DU:
        job->args[0] = repo ? keep(job, repo, strlen(repo)) : NULL;
        o->nargs = 1;
        break;
    case CMD_COPY:
    case CMD_RESTORE:
    case CMD_STATUS:
    case CMD_LIST:
        if (snap && strstr(snap, "::"))
        {
            if (repo)
            {
                rs_buf_addf(err, "%s: snapshot names its repository (REPO::NAME), and "
                            "repository is given as well; give one of them", name);
                return false;
            }
            job->ref = rs_xstrdup(snap);
        } else if (repo)
        {
            job->ref = snap ? rs_xasprintf("%s::%s", repo, snap) : rs_xstrdup(repo);
        }
        job->args[0] = job->ref;
        job->args[1] = vals[KEY_COPY_TO] ? keep(job, vals[KEY_COPY_TO], strlen(vals[KEY_COPY_TO]))
                                         : NULL;
        o->nargs = o->command == CMD_COPY ? 2 : 1;
        if (o->command == CMD_LIST)
        {
            job->args[1] = vals[KEY_PATH] ? keep(job, vals[KEY_PATH], strlen(vals[KEY_PATH]))
                                          : NULL;
            o->nargs = vals[KEY_PATH] ? 2 : 1;
        }
        if (o->command == CMD_COPY && !vals[KEY_COPY_TO])
        {
            rs_buf_addf(err, "%s: a copy job needs copy_to, the repository to copy to", name);
            return false;
        }
        break;
    case CMD_ESTIMATE:
    default:
        break;
    }
    if (o->command != CMD_ESTIMATE && !repo && !job->ref)
    {
        rs_buf_addf(err, "%s: a %s job needs repository%s", name, rs_command_name(o->command),
                    o->command == CMD_RESTORE || o->command == CMD_COPY ||
                            o->command == CMD_STATUS || o->command == CMD_LIST
                        ? ", or snapshot as REPO::NAME"
                        : "");
        return false;
    }
    o->args = job->args;
    return true;
}

bool rs_job_parse(const char *text, size_t len, const char *name, struct rs_job *job,
                  struct rs_buf *err)
{
    const char *vals[KEY_COUNT];
    unsigned    lines[KEY_COUNT];
    unsigned    cmd = 0;
    const char *p = text;
    const char *end = text + len;
    unsigned    lineno = 0;
    size_t      i;
    size_t      k;

    rs_job_free(job);
    memset(vals, 0, sizeof(vals));
    memset(lines, 0, sizeof(lines));
    if (len > RS_JOB_MAX)
    {
        rs_buf_addf(err, "%s: larger than a job can be", name);
        return false;
    }
    if (memchr(text, '\0', len))
    {
        rs_buf_addf(err, "%s: it has a NUL byte in it: not a job", name);
        return false;
    }
    while (p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *stop = nl ? nl : end;
        const char *eq;
        const char *ks;
        const char *ke;
        const char *vs;
        const char *ve;
        char       *key;
        char       *value;

        lineno++;
        ks = p;
        while (ks < stop && (*ks == ' ' || *ks == '\t'))
        {
            ks++;
        }
        ve = stop;
        while (ve > ks && (ve[-1] == ' ' || ve[-1] == '\t' || ve[-1] == '\r'))
        {
            ve--;
        }
        p = nl ? nl + 1 : end;
        if (ks == ve || *ks == '#')
        {
            continue;
        }
        eq = memchr(ks, '=', (size_t)(ve - ks));
        if (!eq)
        {
            rs_buf_addf(err, "%s:%u: not \"key = value\"", name, lineno);
            return false;
        }
        ke = eq;
        while (ke > ks && (ke[-1] == ' ' || ke[-1] == '\t'))
        {
            ke--;
        }
        vs = eq + 1;
        while (vs < ve && (*vs == ' ' || *vs == '\t'))
        {
            vs++;
        }
        key = rs_xstrndup(ks, (size_t)(ke - ks));
        for (k = 0; k < KEY_COUNT && strcmp(keys[k].name, key) != 0; k++)
        {
        }
        if (k == KEY_COUNT)
        {
            rs_buf_addf(err, "%s:%u: \"%.40s\" is not a key a job can have", name, lineno, key);
            free(key);
            return false;
        }
        free(key);
        if (lines[k] && !keys[k].repeat)
        {
            rs_buf_addf(err, "%s:%u: %s is given already, on line %u", name, lineno, keys[k].name,
                        lines[k]);
            return false;
        }
        value = keep(job, vs, (size_t)(ve - vs));
        if (k == KEY_COMMAND)
        {
            for (i = 0; i < sizeof(job_commands) / sizeof(job_commands[0]); i++)
            {
                if (strcmp(job_commands[i].name, value) == 0)
                {
                    cmd = job_commands[i].bit;
                    job->opts.command = job_commands[i].cmd;
                }
            }
            if (!cmd)
            {
                rs_buf_addf(err, "%s:%u: command: \"%.40s\" is not one a job can run (capture, "
                            "prune, check, copy, snapshots, restore, estimate, du, repack, "
                            "protect, status, list)", name, lineno, value);
                return false;
            }
        } else if (!value_ok(keys[k].kind, value))
        {
            rs_buf_addf(err, "%s:%u: %s: not %s", name, lineno, keys[k].name,
                        kind_words(keys[k].kind));
            return false;
        }
        if (keys[k].repeat)
        {
            apply(job, (enum key_id)k, value);
        }
        vals[k] = value;
        lines[k] = lineno;
    }
    if (!cmd)
    {
        rs_buf_addf(err, "%s: no command: say which, with \"command = capture\" or another", name);
        return false;
    }
    /* Every key is checked against the command once it is known, wherever in
     * the file it came. */
    for (k = 0; k < KEY_COUNT; k++)
    {
        if (!lines[k])
        {
            continue;
        }
        if (!(keys[k].commands & cmd))
        {
            rs_buf_addf(err, "%s:%u: %s means nothing to a %s job", name, lines[k], keys[k].name,
                        rs_command_name(job->opts.command));
            return false;
        }
        if (!keys[k].repeat)
        {
            apply(job, (enum key_id)k, vals[k]);
        }
    }
    return make_args(job, vals, name, err);
}

/* Whether `st` is what only its owner can change: root's, or the user's
 * running it, and writable by no one else. */
static bool owned_safely(const struct stat *st)
{
    return (st->st_uid == 0 || st->st_uid == geteuid()) && (st->st_mode & 022) == 0;
}

/* Whether the command line says nothing but how much to say and where:
 * all a job takes from it. Every other option is here, so that a new one is
 * refused until it is thought about; test_jobs.c tries every option in the
 * table to hold it to that. It is a boundary: a sudoers rule can admit
 * `restate run FILE` for root-owned jobs and rely on nothing more getting in. */
static bool only_reporting(const struct rs_options *o)
{
    bool said = o->root || o->output || o->nrules_files || o->no_default_rules || o->os ||
                o->cache || o->mirror || o->target || o->firmware || o->nrecipients ||
                o->sign_with || o->ntrusted || o->allow_unverified || o->all || o->rules_only ||
                o->baseline_content || o->keep_local || o->quiesce || o->keep_last ||
                o->keep_daily || o->keep_weekly || o->keep_monthly || o->exact_versions ||
                o->fetch_sources || o->ndebs || o->nexcludes || o->dry_run || o->check_first ||
                o->plan_only ||
                o->packages || o->numeric_owner || o->image_fstab || o->offline || o->image_at ||
                o->as || o->clones || o->read_all || o->metadata_only || o->record ||
                o->whole_packs || o->nquiesce_with || o->append_only || o->create || o->json ||
                o->nincludes || o->tmpdir || o->one_fs || o->no_hash || o->group;

    return !said;
}

int rs_job_load(const struct rs_options *given, struct rs_job *job)
{
    const char   *path = given->args[0];
    char         *dir;
    const char   *slash = strrchr(path, '/');
    struct stat   st;
    struct stat   dst;
    struct rs_buf text;
    struct rs_buf err;
    char          chunk[4096];
    ssize_t       n;
    int           fd;
    bool          ok;

    rs_job_init(job);
    if (!only_reporting(given))
    {
        rs_error("run %s: what to do is the job's to say; the command line can add only -q, -v, "
                 "-P, --syslog, --result, --progress-file, --report-group and --passphrase-fd",
                 path);
        return RESTATE_EXIT_TROUBLE;
    }
    dir = slash ? (slash == path ? rs_xstrdup("/") : rs_xstrndup(path, (size_t)(slash - path)))
                : rs_xstrdup(".");
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
        int saved = errno;

        /* Asked by lstat, not by errno: O_NOFOLLOW's is ELOOP on Linux and
         * OpenBSD, EMLINK on FreeBSD and EFTYPE on NetBSD. */
        rs_error("run %s: %s", path,
                 lstat(path, &st) == 0 && S_ISLNK(st.st_mode)
                     ? "a symlink; a job has to be the file itself"
                     : strerror(saved));
        free(dir);
        return RESTATE_EXIT_TROUBLE;
    }
    ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && owned_safely(&st) &&
         lstat(dir, &dst) == 0 && S_ISDIR(dst.st_mode) && owned_safely(&dst);
    if (!ok)
    {
        rs_error("run %s: not run: it has to be a regular file, and it and %s have to be root's "
                 "(or yours) and writable by no one else", path, dir);
        (void)close(fd);
        free(dir);
        return RESTATE_EXIT_TROUBLE;
    }
    free(dir);
    rs_buf_init(&text);
    rs_buf_add(&text, "", 0);
    while ((n = read(fd, chunk, sizeof(chunk))) != 0)
    {
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0 || text.len + (size_t)n > RS_JOB_MAX)
        {
            rs_error("run %s: %s", path, n < 0 ? strerror(errno) : "larger than a job can be");
            (void)close(fd);
            rs_buf_free(&text);
            return RESTATE_EXIT_TROUBLE;
        }
        rs_buf_add(&text, chunk, (size_t)n);
    }
    (void)close(fd);
    rs_buf_init(&err);
    ok = rs_job_parse(text.data, text.len, path, job, &err);
    rs_buf_free(&text);
    if (!ok)
    {
        rs_error("%s", err.data);
        rs_buf_free(&err);
        rs_job_free(job);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    /* What the command line adds: how much to say, and where to say it. */
    job->opts.quiet = given->quiet;
    job->opts.verbose = given->verbose;
    job->opts.progress = given->progress;
    job->opts.progress_json = given->progress_json;
    job->opts.log_outcome = job->opts.log_outcome || given->log_outcome;
    job->opts.passphrase_fd = given->passphrase_fd;
    job->opts.passphrase_given = given->passphrase_given;
    if (!job->opts.result)
    {
        job->opts.result = given->result;
    }
    if (!job->opts.progress_file)
    {
        job->opts.progress_file = given->progress_file;
    }
    if (!job->opts.report_group)
    {
        job->opts.report_group = given->report_group;
    }
    return RESTATE_EXIT_OK;
}
