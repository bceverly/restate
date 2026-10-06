/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "scan.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "meta.h"
#include "progress.h"

/* O_DIRECTORY and O_NOFOLLOW are POSIX.1-2008, but be tolerant of a libc that
 * only exposes them under a feature macro this build did not ask for. */
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
/* Linux only. Elsewhere reading a file may move its atime, which the index
 * records before reading it, so the index is right either way. Reading a
 * symlink's target moves the link's atime on Linux whatever is done here --
 * readlink has no O_NOATIME -- so a second scan can see that one change. */
#ifndef O_NOATIME
#define O_NOATIME 0
#endif

struct walk {
    const struct rs_scan_opts *opts;
    struct rs_index           *out;
    struct rs_scan_stats      *stats;
    struct rs_buf             *err;
    dev_t                      root_dev;
    unsigned                   max_depth;
    bool                       failed;    /* the store callback gave up */
    bool                       forced;    /* visiting a kept path: state, whatever the rules */
};

static char type_of(mode_t mode)
{
    if (S_ISREG(mode))
    {
        return 'f';
    }
    if (S_ISDIR(mode))
    {
        return 'd';
    }
    if (S_ISLNK(mode))
    {
        return 'l';
    }
    if (S_ISCHR(mode))
    {
        return 'c';
    }
    if (S_ISBLK(mode))
    {
        return 'b';
    }
    if (S_ISFIFO(mode))
    {
        return 'p';
    }
    return 's';   /* a socket, or something stranger; never recorded */
}

/*
 * openat with O_NOATIME, falling back without it: Linux refuses the flag with
 * EPERM to anyone but the file's owner or root, and an unprivileged scan of
 * somebody else's readable file should still read it.
 */
static int open_at(int dirfd, const char *name, int flags)
{
    int fd = openat(dirfd, name, flags | O_NOATIME);

    if (fd < 0 && errno == EPERM && O_NOATIME != 0)
    {
        fd = openat(dirfd, name, flags);
    }
    return fd;
}

int rs_open_regular_at(int dirfd, const char *name, const struct stat *expect)
{
    struct stat st;
    /* O_NONBLOCK so that if a FIFO is swapped in after the fstatat, the open
     * returns rather than waiting for a writer forever. The fstat below then
     * rejects it. */
    int         fd = open_at(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

    if (fd < 0)
    {
        return -1;
    }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
        (expect && (st.st_dev != expect->st_dev || st.st_ino != expect->st_ino)))
    {
        (void)close(fd);
        errno = ESTALE;
        return -1;
    }
    return fd;
}

bool rs_hash_fd(int fd, char hex[RS_SHA256_HEX_SIZE], uint64_t *bytes)
{
    struct rs_sha256 ctx;
    unsigned char    chunk[65536];

    rs_sha256_init(&ctx);
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (n == 0)
        {
            break;
        }
        rs_sha256_update(&ctx, chunk, (size_t)n);
        rs_progress_bytes((uint64_t)n);
        if (bytes)
        {
            *bytes += (uint64_t)n;
        }
    }
    rs_sha256_final(&ctx, hex);
    return true;
}

bool rs_hash_file_at(int dirfd, const char *name, const struct stat *expect,
                     char hex[RS_SHA256_HEX_SIZE], uint64_t *bytes)
{
    int  fd = rs_open_regular_at(dirfd, name, expect);
    bool ok;
    int  saved;

    if (fd < 0)
    {
        return false;
    }
    ok = rs_hash_fd(fd, hex, bytes);
    saved = errno;
    (void)close(fd);
    errno = saved;
    return ok;
}

/* The tree path of `name` inside `parent`: "/" + "etc" is "/etc". */
static char *child_path(const char *parent, const char *name)
{
    if (parent[0] == '/' && parent[1] == '\0')
    {
        return rs_xasprintf("/%s", name);
    }
    return rs_xasprintf("%s/%s", parent, name);
}

static void unreadable_because(struct walk *w, const char *path, const char *why)
{
    struct rs_buf shown;

    if (w->opts->count_only)
    {
        return;
    }
    w->stats->unreadable++;
    rs_buf_init(&shown);
    rs_escape(&shown, path);
    rs_warn("%s: %s", shown.data, why);
    rs_buf_free(&shown);
}

static void unreadable(struct walk *w, const char *path, int err)
{
    struct rs_buf shown;

    /* A counting pass says nothing: the walk after it will, once. */
    if (w->opts->count_only)
    {
        return;
    }
    w->stats->unreadable++;
    rs_buf_init(&shown);
    rs_escape(&shown, path);
    rs_warn("%s: %s", shown.data, strerror(err));
    rs_buf_free(&shown);
}

/* A file written to while it was copied: kept as it was when the copy began,
 * which for a log -- the usual case -- is all of it but the last few lines. */
static void grew(struct walk *w, const char *path)
{
    struct rs_buf shown;

    w->stats->grew++;
    rs_buf_init(&shown);
    rs_escape(&shown, path);
    rs_warn("%s: written to while it was being copied; kept as it was when the copy began",
            shown.data);
    rs_buf_free(&shown);
}

static void verbose_skip(const struct walk *w, const char *path, const char *why)
{
    if (w->opts->verbose)
    {
        struct rs_buf shown;

        rs_buf_init(&shown);
        rs_escape(&shown, path);
        rs_warn("skipped %s (%s)", shown.data, why);
        rs_buf_free(&shown);
    }
}

static char *read_link_at(int dirfd, const char *name)
{
    size_t size = 256;

    for (;;)
    {
        char   *buf = rs_xmalloc(size);
        ssize_t n = readlinkat(dirfd, name, buf, size);

        if (n < 0)
        {
            free(buf);
            return NULL;
        }
        if ((size_t)n < size)
        {
            /* readlinkat does not terminate what it writes; copy exactly the
             * n bytes it reported rather than writing past them. */
            char *target = rs_xstrndup(buf, (size_t)n);

            free(buf);
            return target;
        }
        free(buf);
        if (size > (size_t)1024 * 1024)
        {
            errno = ENAMETOOLONG;
            return NULL;
        }
        size *= 2;
    }
}

/* Everything the stat says, plus the birth time and the owner's names. */
static void fill_entry(struct rs_entry *e, int dirfd, const char *name,
                       const struct stat *st, char type, enum rs_class cls)
{
    const char *user = rs_user_name((uint64_t)st->st_uid);
    const char *group = rs_group_name((uint64_t)st->st_gid);

    memset(e, 0, sizeof(*e));
    e->type = type;
    e->mode = (uint32_t)(st->st_mode & 07777);
    e->uid = (uint64_t)st->st_uid;
    e->gid = (uint64_t)st->st_gid;
    e->user = user ? rs_xstrdup(user) : NULL;
    e->group = group ? rs_xstrdup(group) : NULL;
    /* Size is meaningful for files and symlinks. A directory's size is a
     * property of the filesystem that holds it, and would make every restore
     * onto a different filesystem look like a change. */
    e->size = (type == 'f' || type == 'l') ? (uint64_t)st->st_size : 0;
    e->nlink = (uint64_t)st->st_nlink;
    e->dev = (uint64_t)st->st_dev;
    e->ino = (uint64_t)st->st_ino;
    e->rdev = (type == 'c' || type == 'b') ? (uint64_t)st->st_rdev : 0;
    rs_stat_times(st, &e->atime, &e->mtime, &e->ctime);
    rs_birth_time_at(dirfd, name, st, &e->btime);
    e->cls = cls;
    e->hash_state = RS_HASH_NONE;
}

/* Hands the entry, and the strings in it, to the index. */
static void record(struct walk *w, const struct rs_entry *e)
{
    rs_index_add(w->out, e);
    rs_progress_path(e->path);
    w->stats->recorded++;
    w->stats->by_class[e->cls]++;
}

/* Whether this entry's content goes into the image. */
static bool storing(const struct walk *w, const struct rs_entry *e)
{
    if (!w->opts->store)
    {
        return false;
    }
    return e->cls != RS_CLASS_BASELINE || w->opts->store_baseline;
}

/* Reads every name in the directory, then closes the stream; the caller keeps
 * only the descriptor while it recurses, so a deep tree costs one descriptor
 * per level rather than one stream per level. */
static char **list_names(int dirfd, size_t *count, int *err)
{
    int                  fd = dup(dirfd);
    DIR                 *d;
    const struct dirent *de;
    char               **names = NULL;
    size_t               n = 0;
    size_t               cap = 0;

    *count = 0;
    if (fd < 0)
    {
        *err = errno;
        return NULL;
    }
    d = fdopendir(fd);
    if (!d)
    {
        *err = errno;
        (void)close(fd);
        return NULL;
    }
    errno = 0;
    while ((de = readdir(d)) != NULL)
    {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
        {
            continue;
        }
        if (n == cap)
        {
            cap = cap ? cap * 2 : 32;
            names = rs_xreallocarray(names, cap, sizeof(*names));
        }
        names[n++] = rs_xstrdup(de->d_name);
    }
    *err = errno;
    (void)closedir(d);
    *count = n;
    return names;
}

/* A regular file's content: hashed, and handed to the store if it is kept.
 * Returns false only when the store failed and the scan must stop. */
static bool file_content(struct walk *w, int dirfd, const char *name,
                         const struct stat *st, struct rs_entry *e)
{
    bool keep = storing(w, e);
    int  fd;

    if (!keep && !w->opts->hash)
    {
        return true;
    }
    fd = rs_open_regular_at(dirfd, name, st);
    if (fd < 0)
    {
        unreadable(w, e->path, errno);
        e->hash_state = RS_HASH_UNREADABLE;
        return true;
    }
    if (keep)
    {
        bool ok = w->opts->store(w->opts->store_ctx, e, fd, st, w->err);

        (void)close(fd);
        if (!ok)
        {
            return false;
        }
        w->stats->stored++;
        if (e->hash_state == RS_HASH_PRESENT)
        {
            w->stats->bytes_hashed += e->size;
            if (e->copy == RS_COPY_GREW)
            {
                grew(w, e->path);
            }
        } else if (e->copy == RS_COPY_SHRANK)
        {
            /* Truncated while read: ESTALE's "stale file" is the nearest
             * the system's own messages come, so say it plainly instead. */
            unreadable_because(w, e->path, "cut short while it was being copied");
        } else
        {
            unreadable(w, e->path, e->copy_errno ? e->copy_errno : EIO);
        }
        return true;
    }
    if (rs_hash_fd(fd, e->hash, &w->stats->bytes_hashed))
    {
        e->hash_state = RS_HASH_PRESENT;
    } else
    {
        unreadable(w, e->path, errno);
        e->hash_state = RS_HASH_UNREADABLE;
    }
    (void)close(fd);
    return true;
}

static void walk_dir(struct walk *w, int dirfd, const char *tree_path, unsigned depth);

/*
 * visit and walk_dir recurse into each other once per directory level. The
 * recursion is bounded: past max_depth a directory is recorded but not
 * entered, and counted as unreadable so the scan exits "incomplete" rather
 * than pretending. Without the bound, anyone who can create directories --
 * every user, in their home -- could nest a million of them and crash a scan
 * running as root by exhausting its stack.
 */
static void visit(struct walk *w, int dirfd, const char *name, /* NOLINT(misc-no-recursion) */
                  const char *tree_path, unsigned depth)
{
    struct stat     st;
    struct rs_entry e;
    enum rs_class   cls;
    char            type;

    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
    {
        unreadable(w, tree_path, errno);
        return;
    }
    cls = w->forced ? RS_CLASS_STATE : rs_rules_classify(w->opts->rules, tree_path, NULL);
    if (cls == RS_CLASS_EPHEMERAL)
    {
        w->stats->skipped_ephemeral++;
        verbose_skip(w, tree_path, "ephemeral");
        return;
    }
    if (cls == RS_CLASS_EXPENDABLE && !w->opts->all)
    {
        w->stats->skipped_expendable++;
        verbose_skip(w, tree_path, "expendable");
        return;
    }
    type = type_of(st.st_mode);
    if (type == 's')
    {
        w->stats->skipped_sockets++;
        verbose_skip(w, tree_path, "a socket");
        return;
    }
    if (w->opts->count_only)
    {
        /* What the real walk will read: every regular file it hashes, or,
         * without hashing, every one it keeps. */
        bool kept = w->opts->store && (cls != RS_CLASS_BASELINE || w->opts->store_baseline);

        if (type == 'f' && (w->opts->hash || kept))
        {
            w->stats->bytes_hashed += (uint64_t)st.st_size;
            rs_progress_found((uint64_t)st.st_size);
        }
        w->stats->recorded++;
        rs_progress_path(tree_path);
    } else
    {
        fill_entry(&e, dirfd, name, &st, type, cls);
        e.path = rs_xstrdup(tree_path);

        if (type == 'l')
        {
            e.target = read_link_at(dirfd, name);
            if (!e.target)
            {
                unreadable(w, tree_path, errno);
                rs_entry_free(&e);
                return;
            }
        }
        if (type == 'f')
        {
            if (!file_content(w, dirfd, name, &st, &e))
            {
                w->failed = true;
                rs_entry_free(&e);
                return;
            }
        } else if (storing(w, &e))
        {
            if (!w->opts->store(w->opts->store_ctx, &e, -1, &st, w->err))
            {
                w->failed = true;
                rs_entry_free(&e);
                return;
            }
            w->stats->stored++;
        }
        record(w, &e);
    }

    if (type != 'd')
    {
        return;
    }
    if (depth >= w->max_depth)
    {
        unreadable(w, tree_path, ELOOP);
        return;
    }
    if (w->opts->one_fs && st.st_dev != w->root_dev)
    {
        w->stats->skipped_mounts++;
        verbose_skip(w, tree_path, "another filesystem");
        return;
    }
    {
        struct stat check;
        int         fd = open_at(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

        if (fd < 0)
        {
            unreadable(w, tree_path, errno);
            return;
        }
        if (fstat(fd, &check) < 0 || check.st_dev != st.st_dev ||
            check.st_ino != st.st_ino)
        {
            /* It changed between the stat and the open. Recording what is
             * there now under the old metadata would be wrong either way. */
            (void)close(fd);
            unreadable(w, tree_path, ESTALE);
            return;
        }
        walk_dir(w, fd, tree_path, depth + 1);
        (void)close(fd);
    }
}

static void walk_dir(struct walk *w, int dirfd, /* NOLINT(misc-no-recursion) */
                     const char *tree_path, unsigned depth)
{
    size_t count;
    size_t i;
    int    err = 0;
    char **names = list_names(dirfd, &count, &err);

    if (err != 0)
    {
        unreadable(w, tree_path, err);
    }
    for (i = 0; i < count; i++)
    {
        if (!w->failed)
        {
            char *path = child_path(tree_path, names[i]);

            visit(w, dirfd, names[i], path, depth);
            free(path);
        }
        free(names[i]);
    }
    free(names);
}

/* Whether the walk recorded `path` already: a rule may keep it anyway. */
static bool recorded(const struct rs_index *ix, const char *path)
{
    size_t i;

    for (i = 0; i < ix->count; i++)
    {
        if (strcmp(ix->entries[i].path, path) == 0)
        {
            return true;
        }
    }
    return false;
}

/* The paths in opts->keep, visited as state. One that is not there is not
 * recorded, and the caller, which knows what it was, says so. */
static void visit_kept(struct walk *w, int rootfd)
{
    size_t k;

    for (k = 0; k < w->opts->nkeep; k++)
    {
        const char *path = w->opts->keep[k];
        struct stat st;
        char       *copy;
        char       *p;
        char       *slash;
        int         dirfd;
        unsigned    depth = 0;

        if (!rs_path_is_clean(path) || strcmp(path, "/") == 0 ||
            (!w->opts->count_only && recorded(w->out, path)))
        {
            continue;
        }
        dirfd = dup(rootfd);
        copy = rs_xstrdup(path + 1);
        p = copy;
        while (dirfd >= 0 && (slash = strchr(p, '/')) != NULL)
        {
            int next;

            *slash = '\0';
            next = open_at(dirfd, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            (void)close(dirfd);
            dirfd = next;
            p = slash + 1;
            depth++;
        }
        if (dirfd >= 0 && fstatat(dirfd, p, &st, AT_SYMLINK_NOFOLLOW) == 0)
        {
            w->forced = true;
            visit(w, dirfd, p, path, depth);
            w->forced = false;
        }
        if (dirfd >= 0)
        {
            (void)close(dirfd);
        }
        free(copy);
    }
}

bool rs_scan(const struct rs_scan_opts *opts, struct rs_index *out,
             struct rs_scan_stats *stats, struct rs_buf *err)
{
    struct walk     w;
    struct stat     st;
    struct rs_entry e;
    struct rs_buf   dup;
    int             fd;
    bool            ok;

    memset(stats, 0, sizeof(*stats));
    /* The root itself may be reached through a symlink -- "/mnt/old" may well
     * be one -- so this is the one open that follows. */
    fd = open(opts->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM && O_NOATIME != 0)
    {
        fd = open(opts->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", opts->root, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode))
    {
        rs_buf_addf(err, "%s: not a directory", opts->root);
        (void)close(fd);
        return false;
    }
    memset(&w, 0, sizeof(w));
    w.opts = opts;
    w.out = out;
    w.stats = stats;
    w.err = err;
    w.root_dev = st.st_dev;
    w.max_depth = opts->max_depth ? opts->max_depth : RS_SCAN_MAX_DEPTH;

    if (opts->count_only)
    {
        stats->recorded = 1;
        walk_dir(&w, fd, "/", 0);
        visit_kept(&w, fd);
        (void)close(fd);
        return true;
    }
    fill_entry(&e, fd, ".", &st, 'd', rs_rules_classify(opts->rules, "/", NULL));
    e.path = rs_xstrdup("/");
    if (storing(&w, &e))
    {
        if (!opts->store(opts->store_ctx, &e, -1, &st, err))
        {
            rs_entry_free(&e);
            (void)close(fd);
            return false;
        }
        stats->stored++;
    }
    record(&w, &e);
    walk_dir(&w, fd, "/", 0);
    if (!w.failed)
    {
        visit_kept(&w, fd);
    }
    (void)close(fd);
    if (w.failed)
    {
        return false;
    }

    rs_buf_init(&dup);
    ok = rs_index_sort(out, &dup);
    if (!ok)
    {
        rs_buf_addf(err, "internal error: %s", dup.data);
    }
    rs_buf_free(&dup);
    return ok;
}
