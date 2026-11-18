/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "snap.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "run.h"

#ifdef __FreeBSD__
#define RS_SNAP_UFS_HERE true
#else
#define RS_SNAP_UFS_HERE false
#endif

/* What removing a snapshot, or unmounting one, is tried, a second apart:
 * Linux unmounts the one the walk had mounted first, and may find it busy a
 * moment longer; so may FreeBSD a UFS snapshot's mount. */
#define TRIES 3

/* Where UFS snapshots are mounted, a directory to each capture. */
#define UFS_MOUNTS "/var/run"

static char *pretend_base;
static bool  pretend_devices;

void rs_snap_pretend(const char *base)
{
    free(pretend_base);
    pretend_base = base ? rs_xstrdup(base) : NULL;
    pretend_devices = false;
}

void rs_snap_pretend_devices(bool on)
{
    pretend_devices = on;
}

char *rs_snap_name(time_t when, pid_t pid)
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

/* `dir` + "/" + `name`, with no "//" where `dir` is "/". */
static char *join(const char *dir, const char *name)
{
    return rs_xasprintf("%s%s%s", dir, strcmp(dir, "/") == 0 ? "" : "/", name);
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

/* A UFS filesystem's own mount, on FreeBSD, where mksnap_ffs is. */
static bool is_ufs(const struct rs_mount *m)
{
    return strcmp(m->type, "ufs") == 0 && !m->part && (RS_SNAP_UFS_HERE || pretend_base);
}

/* The filesystem `name` of `kind` in z, added if it is not there, with its
 * snapshot read through `mountpoint`. Its index. */
static size_t filesystem(struct rs_snap *z, enum rs_snap_kind kind, const char *name,
                         const char *mountpoint)
{
    struct rs_snap_fs *f;
    size_t             i;

    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].kind == kind && strcmp(z->fs[i].name, name) == 0)
        {
            return i;
        }
    }
    z->fs = rs_xreallocarray(z->fs, z->nfs + 1, sizeof(*z->fs));
    f = &z->fs[i];
    memset(f, 0, sizeof(*f));
    f->kind = kind;
    f->name = rs_xstrdup(name);
    f->fd = -1;
    if (pretend_base)
    {
        char *flat = rs_xstrdup(name);
        char *p;

        for (p = flat; *p; p++)
        {
            if (*p == '/')
            {
                *p = '_';
            }
        }
        f->snapdir = rs_xasprintf("%s/%s", pretend_base, flat);
        free(flat);
    } else if (kind == RS_SNAP_ZFS)
    {
        char *dot = join(mountpoint, ".zfs/snapshot");

        f->snapdir = join(dot, z->snapshot);
        free(dot);
    } else
    {
        f->snapdir = rs_xasprintf("%s/%zu", z->mounts, i);
    }
    if (kind == RS_SNAP_UFS)
    {
        char *dir = join(mountpoint, ".snap");

        f->file = join(dir, z->snapshot);
        free(dir);
    }
    z->nfs++;
    return i;
}

/* A directory the walk reads in place of `tree`: `dir`, or filesystem
 * `of`'s snapshot where `of` is not SIZE_MAX. Both z's from now on. */
static void source(struct rs_snap *z, char *tree, char *dir, size_t of)
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

/* Sorted for the walk's search, with each one's filesystem moved too. */
static void sort_sources(struct rs_snap *z)
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

bool rs_snap_plan(const char *root, const struct rs_mount *m, size_t n, bool one_fs,
                  const char *snapshot, struct rs_snap *z, struct rs_buf *err)
{
    const struct rs_mount *cover = NULL;
    size_t                 i;

    memset(z, 0, sizeof(*z));
    z->snapshot = rs_xstrdup(snapshot);
    z->mounts = join(UFS_MOUNTS, snapshot);
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
        size_t                 d;

        if (!is_root && (one_fs || !beneath(root, at->path) || strcmp(at->path, root) == 0 ||
                         rs_mount_remote_type(at->type)))
        {
            continue;
        }
        if (is_dataset(at) && !dataset_name_ok(at->source))
        {
            rs_buf_addf(err, "--from-snapshot: %s is mounted from \"%s\", which is not a ZFS "
                             "dataset's name restate will pass to zfs", at->path, at->source);
            rs_snap_free(z);
            return false;
        }
        if (!is_dataset(at) && !is_ufs(at))
        {
            z->live = rs_xreallocarray(z->live, z->nlive + 1, sizeof(*z->live));
            z->live[z->nlive++] = rs_xstrdup(is_root ? root : at->path);
            if (!is_root)
            {
                source(z, tree_of(root, at->path), rs_xstrdup(at->path), SIZE_MAX);
            }
            continue;
        }
        d = is_dataset(at) ? filesystem(z, RS_SNAP_ZFS, at->source, at->path)
                           : filesystem(z, RS_SNAP_UFS, at->path, at->path);
        if (is_root)
        {
            /* The root may be a directory inside the filesystem. */
            const char *rest = strcmp(at->path, "/") == 0 ? root : root + strlen(at->path);
            bool        whole = rest[0] == '\0' || strcmp(rest, "/") == 0;

            source(z, rs_xstrdup("/"),
                   rs_xasprintf("%s%s", z->fs[d].snapdir, whole ? "" : rest),
                   whole ? d : SIZE_MAX);
        } else
        {
            source(z, tree_of(root, at->path), rs_xstrdup(z->fs[d].snapdir), d);
        }
    }
    if (z->nfs == 0)
    {
        rs_buf_addf(err, "--from-snapshot: nothing at or under %s is on ZFS%s%s", root,
                    RS_SNAP_UFS_HERE ? " or UFS" : "",
                    one_fs ? " (--one-file-system: only its own filesystem)" : "");
        rs_snap_free(z);
        return false;
    }
    sort_sources(z);
    return true;
}

void rs_snap_describe(const struct rs_snap *z, struct rs_buf *out)
{
    size_t zfs = 0;
    size_t ufs = 0;
    size_t i;

    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].kind == RS_SNAP_ZFS)
        {
            zfs++;
        } else
        {
            ufs++;
        }
    }
    if (zfs > 0)
    {
        rs_buf_addf(out, "%zu ZFS dataset%s", zfs, zfs == 1 ? "" : "s");
    }
    if (ufs > 0)
    {
        rs_buf_addf(out, "%s%zu UFS filesystem%s", zfs > 0 ? " and " : "", ufs,
                    ufs == 1 ? "" : "s");
    }
}

/* Program `p`, with `argv`; its standard output in `out` if that is not
 * NULL, and where it fails, its standard error (or its exit status) in
 * `why`. */
static bool tool(enum rs_program p, char *const argv[], struct rs_buf *out, struct rs_buf *why)
{
    struct rs_buf errtext;
    int           code = 0;
    bool          ok;

    rs_buf_init(&errtext);
    ok = rs_run(p, argv, out, &errtext, &code, why);
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

/* Whether restate has program `p` to run; says where it looked if not. */
static bool have(enum rs_program p, const char *where, struct rs_buf *err)
{
    if (rs_program_path(p))
    {
        return true;
    }
    rs_buf_addf(err, "--from-snapshot: there is no %s that restate would run (%s: root's, and "
                     "writable by no one else)", rs_program_name(p), where);
    return false;
}

/* The pool a dataset is in: its name up to the first '/'. */
static size_t pool_len(const char *name)
{
    return strcspn(name, "/");
}

static bool same_pool(const char *a, const char *b)
{
    return pool_len(a) == pool_len(b) && strncmp(a, b, pool_len(a)) == 0;
}

/* The strings of a NULL-terminated `argv`, not argv itself. */
static void free_args(char **argv)
{
    size_t i;

    for (i = 0; argv[i]; i++)
    {
        free(argv[i]);
    }
}

static void free_argv(char **argv)
{
    free_args(argv);
    free(argv);
}

/* One zfs snapshot for each pool, atomic across its datasets. */
static bool zfs_take(struct rs_snap *z, struct rs_buf *err)
{
    size_t i;
    size_t k;

    for (i = 0; i < z->nfs; i++)
    {
        const char   *pool = z->fs[i].name;
        size_t        argc = 0;
        char        **argv;
        struct rs_buf why;
        bool          ok;

        if (z->fs[i].kind != RS_SNAP_ZFS || z->fs[i].taken)
        {
            continue;
        }
        argv = rs_xreallocarray(NULL, z->nfs + 6, sizeof(*argv));
        argv[argc++] = rs_xstrdup("zfs");
        argv[argc++] = rs_xstrdup("snapshot");
        argv[argc++] = rs_xstrdup("-o");
        argv[argc++] = rs_xasprintf("restate:capture=%s", z->snapshot);
        for (k = i; k < z->nfs; k++)
        {
            if (z->fs[k].kind == RS_SNAP_ZFS && same_pool(z->fs[k].name, pool))
            {
                argv[argc++] = rs_xasprintf("%s@%s", z->fs[k].name, z->snapshot);
            }
        }
        argv[argc] = NULL;
        rs_buf_init(&why);
        ok = tool(RS_PROG_ZFS, argv, NULL, &why);
        free_argv(argv);
        if (!ok)
        {
            rs_buf_addf(err, "zfs snapshot of %.*s: %s", (int)pool_len(pool), pool,
                        why.data ? why.data : "");
            rs_buf_free(&why);
            return false;
        }
        rs_buf_free(&why);
        for (k = i; k < z->nfs; k++)
        {
            if (z->fs[k].kind == RS_SNAP_ZFS && same_pool(z->fs[k].name, pool))
            {
                z->fs[k].taken = true;
            }
        }
    }
    return true;
}

/* A filesystem's .snap, where mksnap_ffs puts a snapshot: made as newfs
 * makes it -- root's, group operator, 0775 -- where it is not there. One
 * there already has to be a directory of restate's own user, which is
 * root. Reached from the filesystem's root, a mount point, and never
 * through a symlink; what is made is changed through a descriptor on it,
 * so nothing put in its place meanwhile is. */
static bool snap_dir(const struct rs_snap_fs *f, struct rs_buf *err)
{
    char       *dir = join(f->name, ".snap");
    int         top = open(f->name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int         fd = -1;
    bool        made = false;
    bool        ok = false;
    struct stat st;

    if (top < 0)
    {
        rs_buf_addf(err, "%s: %s", f->name, strerror(errno));
        free(dir);
        return false;
    }
    if (mkdirat(top, ".snap", 0775) == 0)
    {
        made = true;
    } else if (errno != EEXIST)
    {
        rs_buf_addf(err, "%s: %s", dir, strerror(errno));
        (void)close(top);
        free(dir);
        return false;
    }
    fd = openat(top, ".snap", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_uid != geteuid())
    {
        rs_buf_addf(err, "%s: not root's directory, where UFS keeps its snapshots", dir);
    } else if (made && geteuid() == 0)
    {
        const struct group *g = getgrnam("operator");

        ok = fchown(fd, 0, g ? g->gr_gid : 0) == 0 && (g || fchmod(fd, 0700) == 0);
        if (!ok)
        {
            rs_buf_addf(err, "%s: %s", dir, strerror(errno));
        }
    } else
    {
        ok = true;
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    (void)close(top);
    free(dir);
    return ok;
}

/* Whether `s` is a memory disk's name, as mdconfig prints it: "md" and its
 * unit. */
static bool md_name(const char *s)
{
    size_t i;

    if (strncmp(s, "md", 2) != 0 || s[2] == '\0')
    {
        return false;
    }
    for (i = 2; s[i]; i++)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
    }
    return true;
}

/* One UFS filesystem's snapshot: made with mksnap_ffs, attached read-only
 * and mounted read-only, for the walk -- or, pretending, made alone. */
static bool ufs_take(struct rs_snap_fs *f, struct rs_buf *err)
{
    char         *argv[10];
    struct rs_buf why;
    struct rs_buf out;
    bool          ok;

    if (!snap_dir(f, err))
    {
        return false;
    }
    rs_buf_init(&why);
    argv[0] = rs_xstrdup("mksnap_ffs");
    argv[1] = rs_xstrdup(f->file);
    argv[2] = NULL;
    ok = tool(RS_PROG_MKSNAP_FFS, argv, NULL, &why);
    free(argv[0]);
    free(argv[1]);
    if (!ok)
    {
        rs_buf_addf(err, "mksnap_ffs %s: %s", f->file, why.data ? why.data : "");
        rs_buf_free(&why);
        return false;
    }
    f->taken = true;
    if (pretend_base && !pretend_devices)
    {
        rs_buf_free(&why);
        return true;
    }
    /* Attached read-only, so nothing can write to it. */
    rs_buf_init(&out);
    argv[0] = rs_xstrdup("mdconfig");
    argv[1] = rs_xstrdup("-a");
    argv[2] = rs_xstrdup("-t");
    argv[3] = rs_xstrdup("vnode");
    argv[4] = rs_xstrdup("-o");
    argv[5] = rs_xstrdup("readonly");
    argv[6] = rs_xstrdup("-f");
    argv[7] = rs_xstrdup(f->file);
    argv[8] = NULL;
    ok = tool(RS_PROG_MDCONFIG, argv, &out, &why);
    free_args(argv);
    if (ok)
    {
        size_t len = out.len;

        while (len > 0 && (out.data[len - 1] == '\n' || out.data[len - 1] == ' '))
        {
            len--;
        }
        f->md = rs_xstrndup(out.data ? out.data : "", len);
        if (!md_name(f->md))
        {
            rs_buf_addf(&why, "it said \"%s\", not a memory disk's name", f->md);
            free(f->md);
            f->md = NULL;
            ok = false;
        }
    }
    rs_buf_free(&out);
    if (!ok)
    {
        rs_buf_addf(err, "mdconfig -a -f %s: %s", f->file, why.data ? why.data : "");
        rs_buf_free(&why);
        return false;
    }
    if (mkdir(f->snapdir, 0700) != 0)
    {
        rs_buf_addf(err, "%s: %s", f->snapdir, strerror(errno));
        rs_buf_free(&why);
        return false;
    }
    argv[0] = rs_xstrdup("mount");
    argv[1] = rs_xstrdup("-t");
    argv[2] = rs_xstrdup("ufs");
    argv[3] = rs_xstrdup("-o");
    argv[4] = rs_xstrdup("ro");
    argv[5] = rs_xasprintf("/dev/%s", f->md);
    argv[6] = rs_xstrdup(f->snapdir);
    argv[7] = NULL;
    rs_buf_reset(&why);
    ok = tool(RS_PROG_MOUNT, argv, NULL, &why);
    free_args(argv);
    if (!ok)
    {
        rs_buf_addf(err, "mount /dev/%s %s: %s", f->md, f->snapdir, why.data ? why.data : "");
        rs_buf_free(&why);
        return false;
    }
    f->mounted = true;
    rs_buf_free(&why);
    return true;
}

bool rs_snap_take(struct rs_snap *z, struct rs_buf *err)
{
    bool   zfs = false;
    bool   ufs = false;
    size_t i;

    for (i = 0; i < z->nfs; i++)
    {
        zfs = zfs || z->fs[i].kind == RS_SNAP_ZFS;
        ufs = ufs || z->fs[i].kind == RS_SNAP_UFS;
    }
    if ((zfs && !have(RS_PROG_ZFS, "/sbin/zfs, /usr/sbin/zfs, /usr/local/sbin/zfs", err)) ||
        (ufs && !have(RS_PROG_MKSNAP_FFS, "/sbin/mksnap_ffs", err)) ||
        (ufs && (!pretend_base || pretend_devices) &&
         (!have(RS_PROG_MDCONFIG, "/sbin/mdconfig", err) ||
          !have(RS_PROG_MOUNT, "/sbin/mount", err) || !have(RS_PROG_UMOUNT, "/sbin/umount", err))))
    {
        return false;
    }
    if (ufs && !pretend_base && mkdir(z->mounts, 0700) != 0)
    {
        rs_buf_addf(err, "%s: %s", z->mounts, strerror(errno));
        return false;
    }
    if (!zfs_take(z, err))
    {
        (void)rs_snap_release(z, err);
        return false;
    }
    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].kind == RS_SNAP_UFS && !ufs_take(&z->fs[i], err))
        {
            (void)rs_snap_release(z, err);
            return false;
        }
    }
    /* Each opened now, which on Linux mounts a ZFS snapshot, and held open
     * until the walk is done, so that it stays mounted. */
    for (i = 0; i < z->nfs; i++)
    {
        z->fs[i].fd = open(z->fs[i].snapdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (z->fs[i].fd < 0)
        {
            rs_buf_addf(err, "%s: %s", z->fs[i].snapdir, strerror(errno));
            (void)rs_snap_release(z, err);
            return false;
        }
    }
    for (i = 0; i < z->nsources; i++)
    {
        if (z->of[i] != SIZE_MAX)
        {
            z->sources[i].fd = z->fs[z->of[i]].fd;
        }
    }
    return true;
}

/* Runs `argv` up to TRIES times, a second apart, until it works. */
static bool tries(enum rs_program p, char *const argv[], struct rs_buf *why)
{
    int  n;
    bool ok = false;

    for (n = 0; n < TRIES && !ok; n++)
    {
        if (n > 0)
        {
            (void)sleep(1);
        }
        rs_buf_reset(why);
        ok = tool(p, argv, NULL, why);
    }
    return ok;
}

/* A thing release could not undo, said with the command that would. */
static void undone(struct rs_buf *err, const char *what, const struct rs_buf *why,
                   const char *command)
{
    if (err->len > 0)
    {
        rs_buf_addstr(err, "; ");
    }
    rs_buf_addf(err, "%s (%s): %s", what, why->data ? why->data : "", command);
}

static bool zfs_release(struct rs_snap *z, struct rs_snap_fs *f, struct rs_buf *err)
{
    static char   cmd[] = "zfs";
    static char   destroy[] = "destroy";
    char         *name = rs_xasprintf("%s@%s", f->name, z->snapshot);
    char         *argv[4];
    struct rs_buf why;
    bool          ok;

    /* This capture's own, by its whole name, and nothing else. */
    argv[0] = cmd;
    argv[1] = destroy;
    argv[2] = name;
    argv[3] = NULL;
    rs_buf_init(&why);
    ok = tries(RS_PROG_ZFS, argv, &why);
    if (ok)
    {
        f->taken = false;
    } else
    {
        char *what = rs_xasprintf("the snapshot %s was not destroyed", name);
        char *command = rs_xasprintf("zfs destroy %s removes it", name);

        undone(err, what, &why, command);
        free(what);
        free(command);
    }
    rs_buf_free(&why);
    free(name);
    return ok;
}

/* Unmounted, detached and removed, in that order: each only once what it
 * stands on is undone. */
static bool ufs_release(struct rs_snap_fs *f, struct rs_buf *err)
{
    struct rs_buf why;
    char         *argv[6];
    bool          ok = true;

    rs_buf_init(&why);
    if (f->mounted)
    {
        argv[0] = rs_xstrdup("umount");
        argv[1] = rs_xstrdup(f->snapdir);
        argv[2] = NULL;
        if (tries(RS_PROG_UMOUNT, argv, &why))
        {
            f->mounted = false;
            (void)rmdir(f->snapdir);
        } else
        {
            char *what = rs_xasprintf("the snapshot of %s mounted on %s was not unmounted",
                                      f->name, f->snapdir);
            char *command = rs_xasprintf("umount %s, then mdconfig -d -u %s and rm %s remove it",
                                         f->snapdir, f->md ? f->md + 2 : "?", f->file);

            undone(err, what, &why, command);
            free(what);
            free(command);
            ok = false;
        }
        free(argv[0]);
        free(argv[1]);
    } else if (!pretend_base)
    {
        /* Made for a mount that did not happen, or never made. */
        (void)rmdir(f->snapdir);
    }
    if (ok && f->md)
    {
        argv[0] = rs_xstrdup("mdconfig");
        argv[1] = rs_xstrdup("-d");
        argv[2] = rs_xstrdup("-u");
        argv[3] = rs_xstrdup(f->md + 2);
        argv[4] = NULL;
        if (tries(RS_PROG_MDCONFIG, argv, &why))
        {
            free(f->md);
            f->md = NULL;
        } else
        {
            char *what = rs_xasprintf("%s, the snapshot of %s, was not detached", f->md,
                                      f->name);
            char *command = rs_xasprintf("mdconfig -d -u %s, then rm %s remove it", f->md + 2,
                                         f->file);

            undone(err, what, &why, command);
            free(what);
            free(command);
            ok = false;
        }
        free_args(argv);
    }
    if (ok && f->taken)
    {
        if (unlink(f->file) == 0 || errno == ENOENT)
        {
            f->taken = false;
        } else
        {
            char *what = rs_xasprintf("the snapshot %s was not removed", f->file);
            char *command = rs_xasprintf("rm %s removes it", f->file);

            rs_buf_reset(&why);
            rs_buf_addstr(&why, strerror(errno));
            undone(err, what, &why, command);
            free(what);
            free(command);
            ok = false;
        }
    }
    rs_buf_free(&why);
    return ok;
}

bool rs_snap_release(struct rs_snap *z, struct rs_buf *err)
{
    bool   ok = true;
    size_t i;

    for (i = 0; i < z->nsources; i++)
    {
        z->sources[i].fd = -1;
    }
    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].fd >= 0)
        {
            (void)close(z->fs[i].fd);
            z->fs[i].fd = -1;
        }
    }
    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].kind == RS_SNAP_ZFS && z->fs[i].taken)
        {
            ok = zfs_release(z, &z->fs[i], err) && ok;
        } else if (z->fs[i].kind == RS_SNAP_UFS)
        {
            ok = ufs_release(&z->fs[i], err) && ok;
        }
    }
    if (!pretend_base && z->mounts)
    {
        (void)rmdir(z->mounts);
    }
    return ok;
}

void rs_snap_parse_zfs_leftovers(const char *text, const char *snapshot, char ***out,
                                 size_t *n)
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

static void leftover(struct rs_snap_leftover **out, size_t *n, char *name, char *remove)
{
    *out = rs_xreallocarray(*out, *n + 1, sizeof(**out));
    (*out)[*n].name = name;
    (*out)[*n].remove = remove;
    (*n)++;
}

static void zfs_leftovers(const struct rs_snap *z, struct rs_snap_leftover **out, size_t *n)
{
    char        **argv;
    char        **names;
    size_t        nnames;
    size_t        argc = 0;
    size_t        i;
    struct rs_buf text;
    struct rs_buf why;

    if (!rs_program_path(RS_PROG_ZFS))
    {
        return;
    }
    argv = rs_xreallocarray(NULL, z->nfs + 12, sizeof(*argv));
    argv[argc++] = rs_xstrdup("zfs");
    argv[argc++] = rs_xstrdup("list");
    argv[argc++] = rs_xstrdup("-H");
    argv[argc++] = rs_xstrdup("-t");
    argv[argc++] = rs_xstrdup("snapshot");
    argv[argc++] = rs_xstrdup("-o");
    argv[argc++] = rs_xstrdup("name,restate:capture");
    argv[argc++] = rs_xstrdup("-d");
    argv[argc++] = rs_xstrdup("1");
    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].kind == RS_SNAP_ZFS)
        {
            argv[argc++] = rs_xstrdup(z->fs[i].name);
        }
    }
    argv[argc] = NULL;
    rs_buf_init(&text);
    rs_buf_init(&why);
    if (argc > 9 && tool(RS_PROG_ZFS, argv, &text, &why))
    {
        rs_snap_parse_zfs_leftovers(text.data, z->snapshot, &names, &nnames);
        for (i = 0; i < nnames; i++)
        {
            leftover(out, n, names[i], rs_xasprintf("zfs destroy %s", names[i]));
        }
        free(names);
    }
    rs_buf_free(&text);
    rs_buf_free(&why);
    free_argv(argv);
}

/* What is in a UFS filesystem's .snap by restate's name and is not this
 * capture's. */
static void ufs_leftovers(const struct rs_snap *z, const struct rs_snap_fs *f,
                          struct rs_snap_leftover **out, size_t *n)
{
    char                *dir = join(f->name, ".snap");
    DIR                 *d = opendir(dir);
    const struct dirent *e;

    while (d && (e = readdir(d)) != NULL)
    {
        if (strncmp(e->d_name, "restate-", 8) == 0 && strcmp(e->d_name, z->snapshot) != 0)
        {
            char *path = join(dir, e->d_name);

            leftover(out, n, path,
                     rs_xasprintf("rm %s (after mdconfig -d of any memory disk mdconfig -l -v "
                                  "shows it attached as)", path));
        }
    }
    if (d)
    {
        (void)closedir(d);
    }
    free(dir);
}

void rs_snap_leftovers(const struct rs_snap *z, struct rs_snap_leftover **out, size_t *n)
{
    size_t i;

    *out = NULL;
    *n = 0;
    zfs_leftovers(z, out, n);
    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].kind == RS_SNAP_UFS)
        {
            ufs_leftovers(z, &z->fs[i], out, n);
        }
    }
}

void rs_snap_leftovers_free(struct rs_snap_leftover *l, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(l[i].name);
        free(l[i].remove);
    }
    free(l);
}

void rs_snap_free(struct rs_snap *z)
{
    size_t i;

    for (i = 0; i < z->nfs; i++)
    {
        if (z->fs[i].fd >= 0)
        {
            (void)close(z->fs[i].fd);
        }
        free(z->fs[i].name);
        free(z->fs[i].snapdir);
        free(z->fs[i].file);
        free(z->fs[i].md);
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
    free(z->fs);
    free(z->sources);
    free(z->of);
    free(z->live);
    free(z->snapshot);
    free(z->mounts);
    memset(z, 0, sizeof(*z));
}
