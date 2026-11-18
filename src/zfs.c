/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "zfs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "run.h"

/* What destroying a snapshot is tried, a second apart: Linux unmounts the
 * one the walk had mounted first, and may find it busy a moment longer. */
#define DESTROY_TRIES 3

static char *pretend_base;

void rs_zfs_pretend(const char *base)
{
    free(pretend_base);
    pretend_base = base ? rs_xstrdup(base) : NULL;
}

char *rs_zfs_snapshot_name(time_t when, pid_t pid)
{
    struct tm tm;
    char      stamp[32];

    if (!gmtime_r(&when, &tm) || strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &tm) == 0)
    {
        (void)snprintf(stamp, sizeof(stamp), "%lld", (long long)when);
    }
    return rs_xasprintf("restate-%s-%ld", stamp, (long)pid);
}

/* Whether `path` is `dir` or beneath it, by whole components. */
static bool beneath(const char *dir, const char *path)
{
    size_t len = strlen(dir);

    if (strcmp(dir, "/") == 0)
    {
        return path[0] == '/';
    }
    return strncmp(dir, path, len) == 0 && (path[len] == '\0' || path[len] == '/');
}

/* `path` (beneath `root`) as the walk names it: "/" for the root. */
static char *tree_of(const char *root, const char *path)
{
    if (strcmp(root, "/") == 0)
    {
        return rs_xstrdup(path);
    }
    return rs_xstrdup(path[strlen(root)] == '\0' ? "/" : path + strlen(root));
}

/* A dataset's name as restate will pass it to zfs: the letters ZFS allows,
 * and nothing zfs could take for an option or a snapshot's. */
static bool dataset_name_ok(const char *name)
{
    size_t i;

    if (name[0] == '\0' || name[0] == '-' || name[0] == '/' ||
        name[strlen(name) - 1] == '/' || strstr(name, "//"))
    {
        return false;
    }
    for (i = 0; name[i]; i++)
    {
        char c = name[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == ':' || c == '/'))
        {
            return false;
        }
    }
    return true;
}

/* A dataset's own mount: ZFS, of the dataset's root, not of a snapshot. */
static bool is_dataset(const struct rs_mount *m)
{
    return strcmp(m->type, "zfs") == 0 && !m->part && !strchr(m->source, '@');
}

/* The dataset `name` in z, added if it is not there, with its snapshot read
 * through `mountpoint`. Its index. */
static size_t dataset(struct rs_zfs *z, const char *name, const char *mountpoint)
{
    size_t i;

    for (i = 0; i < z->ndatasets; i++)
    {
        if (strcmp(z->datasets[i].name, name) == 0)
        {
            return i;
        }
    }
    z->datasets = rs_xreallocarray(z->datasets, z->ndatasets + 1, sizeof(*z->datasets));
    z->datasets[i].name = rs_xstrdup(name);
    if (pretend_base)
    {
        char  *flat = rs_xstrdup(name);
        char  *p;

        for (p = flat; *p; p++)
        {
            if (*p == '/')
            {
                *p = '_';
            }
        }
        z->datasets[i].snapdir = rs_xasprintf("%s/%s", pretend_base, flat);
        free(flat);
    } else
    {
        z->datasets[i].snapdir = rs_xasprintf("%s%s.zfs/snapshot/%s", mountpoint,
                                              strcmp(mountpoint, "/") == 0 ? "" : "/",
                                              z->snapshot);
    }
    z->datasets[i].fd = -1;
    z->datasets[i].taken = false;
    z->ndatasets++;
    return i;
}

/* A directory the walk reads in place of `tree`: `dir`, or dataset `of`'s
 * snapshot where `of` is not SIZE_MAX. Both z's from now on. */
static void source(struct rs_zfs *z, char *tree, char *dir, size_t of)
{
    z->owned = rs_xreallocarray(z->owned, z->nowned + 2, sizeof(*z->owned));
    z->owned[z->nowned++] = tree;
    z->owned[z->nowned++] = dir;
    z->sources = rs_xreallocarray(z->sources, z->nsources + 1, sizeof(*z->sources));
    z->of = rs_xreallocarray(z->of, z->nsources + 1, sizeof(*z->of));
    z->sources[z->nsources].tree = tree;
    z->sources[z->nsources].dir = dir;
    z->sources[z->nsources].fd = -1;
    z->of[z->nsources] = of;
    z->nsources++;
}

static int by_tree(const void *a, const void *b)
{
    return strcmp(((const struct rs_scan_source *)a)->tree,
                  ((const struct rs_scan_source *)b)->tree);
}

bool rs_zfs_plan(const char *root, const struct rs_mount *m, size_t n, bool one_fs,
                 const char *snapshot, struct rs_zfs *z, struct rs_buf *err)
{
    const struct rs_mount *cover = NULL;
    size_t                 i;

    memset(z, 0, sizeof(*z));
    z->snapshot = rs_xstrdup(snapshot);
    /* The mount the root itself is on: the longest at or above it. */
    for (i = 0; i < n; i++)
    {
        if (beneath(m[i].path, root) && (!cover || strlen(m[i].path) > strlen(cover->path)))
        {
            cover = &m[i];
        }
    }
    for (i = 0; i < n; i++)
    {
        const struct rs_mount *at = &m[i];
        bool                   is_root = at == cover;

        if (!is_root && (one_fs || !beneath(root, at->path) || strcmp(at->path, root) == 0 ||
                         rs_mount_remote_type(at->type)))
        {
            continue;
        }
        if (is_dataset(at))
        {
            size_t d;

            if (!dataset_name_ok(at->source))
            {
                rs_buf_addf(err, "--from-snapshot: %s is mounted from \"%s\", which is not a ZFS "
                                 "dataset's name restate will pass to zfs", at->path, at->source);
                rs_zfs_free(z);
                return false;
            }
            d = dataset(z, at->source, at->path);
            if (is_root)
            {
                /* The root may be a directory inside the dataset. */
                const char *rest = strcmp(at->path, "/") == 0 ? root : root + strlen(at->path);

                source(z, rs_xstrdup("/"),
                       rs_xasprintf("%s%s", z->datasets[d].snapdir,
                                    strcmp(rest, "/") == 0 ? "" : rest),
                       rest[0] == '\0' || strcmp(rest, "/") == 0 ? d : SIZE_MAX);
            } else
            {
                source(z, tree_of(root, at->path), rs_xstrdup(z->datasets[d].snapdir), d);
            }
        } else
        {
            z->live = rs_xreallocarray(z->live, z->nlive + 1, sizeof(*z->live));
            z->live[z->nlive++] = rs_xstrdup(is_root ? root : at->path);
            if (!is_root)
            {
                source(z, tree_of(root, at->path), rs_xstrdup(at->path), SIZE_MAX);
            }
        }
    }
    if (z->ndatasets == 0)
    {
        rs_buf_addf(err, "--from-snapshot: nothing at or under %s is on ZFS%s", root,
                    one_fs ? " (--one-file-system: only its own filesystem)" : "");
        rs_zfs_free(z);
        return false;
    }
    /* Sorted for the walk's search, with each one's dataset moved too. */
    {
        struct rs_scan_source *sorted = rs_xreallocarray(NULL, z->nsources, sizeof(*sorted));
        size_t                *of = rs_xreallocarray(NULL, z->nsources, sizeof(*of));
        size_t                 k;

        memcpy(sorted, z->sources, z->nsources * sizeof(*sorted));
        qsort(sorted, z->nsources, sizeof(*sorted), by_tree);
        for (k = 0; k < z->nsources; k++)
        {
            size_t j;

            for (j = 0; j < z->nsources; j++)
            {
                if (z->sources[j].tree == sorted[k].tree)
                {
                    of[k] = z->of[j];
                }
            }
        }
        free(z->sources);
        free(z->of);
        z->sources = sorted;
        z->of = of;
    }
    return true;
}

/* zfs, with `argv` after its name; its standard error, where it fails, in
 * `why`. */
static bool zfs(char *const argv[], struct rs_buf *out, struct rs_buf *why)
{
    struct rs_buf errtext;
    int           code = 0;
    bool          ok;

    rs_buf_init(&errtext);
    ok = rs_run(RS_PROG_ZFS, argv, out, &errtext, &code, why);
    if (ok && code != 0)
    {
        size_t len = errtext.len;

        while (len > 0 && (errtext.data[len - 1] == '\n' || errtext.data[len - 1] == ' '))
        {
            len--;
        }
        if (len > 0)
        {
            rs_buf_add(why, errtext.data, len);
        } else
        {
            rs_buf_addf(why, "exit status %d", code);
        }
        ok = false;
    }
    rs_buf_free(&errtext);
    return ok;
}

/* The pool a dataset is in: its name up to the first '/'. */
static size_t pool_len(const char *name)
{
    return strcspn(name, "/");
}

static void free_argv(char **argv)
{
    size_t i;

    for (i = 0; argv[i]; i++)
    {
        free(argv[i]);
    }
    free(argv);
}

bool rs_zfs_take(struct rs_zfs *z, struct rs_buf *err)
{
    size_t i;
    size_t k;

    if (!rs_program_path(RS_PROG_ZFS))
    {
        rs_buf_addstr(err, "--from-snapshot: there is no zfs that restate would run (/sbin/zfs, "
                           "/usr/sbin/zfs, /usr/local/sbin/zfs: root's, and writable by no one "
                           "else)");
        return false;
    }
    /* One zfs snapshot for each pool, atomic across its datasets. */
    for (i = 0; i < z->ndatasets; i++)
    {
        const char    *pool = z->datasets[i].name;
        size_t         plen = pool_len(pool);
        size_t         argc = 0;
        char         **argv;
        struct rs_buf  why;
        bool           ok;

        if (z->datasets[i].taken)
        {
            continue;
        }
        argv = rs_xreallocarray(NULL, z->ndatasets + 6, sizeof(*argv));
        argv[argc++] = rs_xstrdup("zfs");
        argv[argc++] = rs_xstrdup("snapshot");
        argv[argc++] = rs_xstrdup("-o");
        argv[argc++] = rs_xasprintf("restate:capture=%s", z->snapshot);
        for (k = i; k < z->ndatasets; k++)
        {
            const char *name = z->datasets[k].name;

            if (pool_len(name) == plen && strncmp(name, pool, plen) == 0)
            {
                argv[argc++] = rs_xasprintf("%s@%s", name, z->snapshot);
            }
        }
        argv[argc] = NULL;
        rs_buf_init(&why);
        ok = zfs(argv, NULL, &why);
        free_argv(argv);
        if (!ok)
        {
            rs_buf_addf(err, "zfs snapshot of %.*s: %s", (int)plen, pool, why.data ? why.data : "");
            rs_buf_free(&why);
            (void)rs_zfs_release(z, err);
            return false;
        }
        rs_buf_free(&why);
        for (k = i; k < z->ndatasets; k++)
        {
            const char *name = z->datasets[k].name;

            if (pool_len(name) == plen && strncmp(name, pool, plen) == 0)
            {
                z->datasets[k].taken = true;
            }
        }
    }
    /* Each opened now, which on Linux mounts it, and held open until the
     * walk is done, so that it stays mounted. */
    for (i = 0; i < z->ndatasets; i++)
    {
        z->datasets[i].fd = open(z->datasets[i].snapdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (z->datasets[i].fd < 0)
        {
            rs_buf_addf(err, "%s: %s", z->datasets[i].snapdir, strerror(errno));
            (void)rs_zfs_release(z, err);
            return false;
        }
    }
    for (i = 0; i < z->nsources; i++)
    {
        if (z->of[i] != SIZE_MAX)
        {
            z->sources[i].fd = z->datasets[z->of[i]].fd;
        }
    }
    return true;
}

bool rs_zfs_release(struct rs_zfs *z, struct rs_buf *err)
{
    bool   ok = true;
    size_t i;

    for (i = 0; i < z->nsources; i++)
    {
        z->sources[i].fd = -1;
    }
    for (i = 0; i < z->ndatasets; i++)
    {
        if (z->datasets[i].fd >= 0)
        {
            (void)close(z->datasets[i].fd);
            z->datasets[i].fd = -1;
        }
    }
    for (i = 0; i < z->ndatasets; i++)
    {
        static char    cmd[] = "zfs";
        static char    destroy[] = "destroy";
        char          *name;
        char          *argv[4];
        struct rs_buf  why;
        int            tries;
        bool           gone = false;

        if (!z->datasets[i].taken)
        {
            continue;
        }
        /* This capture's own, by its whole name, and nothing else. */
        name = rs_xasprintf("%s@%s", z->datasets[i].name, z->snapshot);
        argv[0] = cmd;
        argv[1] = destroy;
        argv[2] = name;
        argv[3] = NULL;
        rs_buf_init(&why);
        for (tries = 0; tries < DESTROY_TRIES && !gone; tries++)
        {
            if (tries > 0)
            {
                (void)sleep(1);
            }
            rs_buf_reset(&why);
            gone = zfs(argv, NULL, &why);
        }
        if (gone)
        {
            z->datasets[i].taken = false;
        } else
        {
            if (err->len > 0)
            {
                rs_buf_addstr(err, "; ");
            }
            rs_buf_addf(err, "the snapshot %s was not destroyed (%s): zfs destroy %s removes it",
                        name, why.data ? why.data : "", name);
            ok = false;
        }
        rs_buf_free(&why);
        free(name);
    }
    return ok;
}

void rs_zfs_parse_leftovers(const char *text, const char *snapshot, char ***out, size_t *n)
{
    const char *p;

    *out = NULL;
    *n = 0;
    for (p = text; p && *p;)
    {
        size_t      len = strcspn(p, "\n");
        const char *tab = memchr(p, '\t', len);

        /* NAME TAB VALUE, "-" where the property is not set. */
        if (tab && tab + 1 < p + len && !(tab + 2 == p + len && tab[1] == '-'))
        {
            char       *name = rs_xstrndup(p, (size_t)(tab - p));
            const char *at = strchr(name, '@');

            if (at && strcmp(at + 1, snapshot) != 0)
            {
                *out = rs_xreallocarray(*out, *n + 1, sizeof(**out));
                (*out)[(*n)++] = name;
            } else
            {
                free(name);
            }
        }
        p += len + (p[len] == '\n' ? 1 : 0);
    }
}

void rs_zfs_leftovers(const struct rs_zfs *z, char ***out, size_t *n)
{
    char        **argv;
    size_t        argc = 0;
    size_t        i;
    struct rs_buf text;
    struct rs_buf why;

    *out = NULL;
    *n = 0;
    if (z->ndatasets == 0 || !rs_program_path(RS_PROG_ZFS))
    {
        return;
    }
    argv = rs_xreallocarray(NULL, z->ndatasets + 12, sizeof(*argv));
    argv[argc++] = rs_xstrdup("zfs");
    argv[argc++] = rs_xstrdup("list");
    argv[argc++] = rs_xstrdup("-H");
    argv[argc++] = rs_xstrdup("-t");
    argv[argc++] = rs_xstrdup("snapshot");
    argv[argc++] = rs_xstrdup("-o");
    argv[argc++] = rs_xstrdup("name,restate:capture");
    argv[argc++] = rs_xstrdup("-d");
    argv[argc++] = rs_xstrdup("1");
    for (i = 0; i < z->ndatasets; i++)
    {
        argv[argc++] = rs_xstrdup(z->datasets[i].name);
    }
    argv[argc] = NULL;
    rs_buf_init(&text);
    rs_buf_init(&why);
    if (zfs(argv, &text, &why))
    {
        rs_zfs_parse_leftovers(text.data, z->snapshot, out, n);
    }
    rs_buf_free(&text);
    rs_buf_free(&why);
    free_argv(argv);
}

void rs_zfs_free(struct rs_zfs *z)
{
    size_t i;

    for (i = 0; i < z->ndatasets; i++)
    {
        if (z->datasets[i].fd >= 0)
        {
            (void)close(z->datasets[i].fd);
        }
        free(z->datasets[i].name);
        free(z->datasets[i].snapdir);
    }
    for (i = 0; i < z->nowned; i++)
    {
        free(z->owned[i]);
    }
    free(z->owned);
    for (i = 0; i < z->nlive; i++)
    {
        free(z->live[i]);
    }
    free(z->datasets);
    free(z->sources);
    free(z->of);
    free(z->live);
    free(z->snapshot);
    memset(z, 0, sizeof(*z));
}
