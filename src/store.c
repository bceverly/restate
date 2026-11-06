/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/vfs.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#endif

#include "fsflags.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

struct rs_store {
    char *dir;
};

struct rs_store *rs_store_local(const char *dir)
{
    struct rs_store *st = rs_xcalloc(1, sizeof(*st));

    st->dir = rs_xstrdup(dir);
    return st;
}

struct rs_store *rs_store_at(const char *where)
{
    return rs_store_local(where);
}

void rs_store_free(struct rs_store *st)
{
    if (st)
    {
        free(st->dir);
        free(st);
    }
}

const char *rs_store_where(const struct rs_store *st)
{
    return st->dir;
}

char *rs_store_path(const struct rs_store *st, const char *name)
{
    if (!*st->dir)
    {
        return rs_xstrdup(*name ? name : ".");
    }
    return *name ? rs_xasprintf("%s/%s", st->dir, name) : rs_xstrdup(st->dir);
}

const char *rs_store_local_dir(const struct rs_store *st)
{
    return st->dir;
}

/* ------------------------------------------------------------------------- */
/* Reading                                                                   */
/* ------------------------------------------------------------------------- */

int rs_store_stat(const struct rs_store *st, const char *name, struct rs_store_stat *out)
{
    char       *path = rs_store_path(st, name);
    struct stat s;
    int         rc = lstat(path, &s);
    int         saved = errno;

    free(path);
    if (rc != 0)
    {
        errno = saved;
        return -1;
    }
    out->kind = S_ISREG(s.st_mode) ? RS_STORE_FILE : S_ISDIR(s.st_mode) ? RS_STORE_DIR
                                                                          : RS_STORE_OTHER;
    out->size = s.st_size > 0 ? (uint64_t)s.st_size : 0;
    out->mtime = (int64_t)s.st_mtime;
    return 0;
}

bool rs_store_is_file(const struct rs_store *st, const char *name)
{
    struct rs_store_stat s;

    return rs_store_stat(st, name, &s) == 0 && s.kind == RS_STORE_FILE;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

char **rs_store_list(const struct rs_store *st, const char *name, rs_store_keep keep, void *ctx,
                     size_t *n)
{
    char                *path = rs_store_path(st, name);
    DIR                 *d = opendir(path);
    int                  saved = errno;
    const struct dirent *de;
    char               **names = NULL;

    free(path);
    *n = 0;
    if (!d)
    {
        errno = saved;
        return NULL;
    }
    errno = 0;
    while ((de = readdir(d)) != NULL)
    {
        char *out = NULL;

        if (keep(st, name, de->d_name, ctx, &out))
        {
            names = rs_xreallocarray(names, *n + 1, sizeof(*names));
            names[(*n)++] = out;
        }
    }
    (void)closedir(d);
    if (names && *n > 1)
    {
        qsort(names, *n, sizeof(*names), by_name);
    }
    errno = 0;
    return names;
}

bool rs_store_keep_all(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                       char **out)
{
    (void)st;
    (void)dir;
    (void)ctx;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    {
        return false;
    }
    *out = rs_xstrdup(name);
    return true;
}

int rs_store_open(const struct rs_store *st, const char *name)
{
    char *path = rs_store_path(st, name);
    int   fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int   saved = errno;

    free(path);
    errno = saved;
    return fd;
}

int rs_store_open_at(const struct rs_store *st, const char *name, uint64_t offset)
{
    int fd = rs_store_open(st, name);

    if (fd >= 0 && offset > 0 && lseek(fd, (off_t)offset, SEEK_SET) < 0)
    {
        int saved = errno;

        (void)close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

ssize_t rs_store_peek(const struct rs_store *st, const char *name, void *buf, size_t max)
{
    char   *path = rs_store_path(st, name);
    int     fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    ssize_t got = -1;
    int     saved;

    if (fd >= 0)
    {
        got = pread(fd, buf, max, 0);
    }
    saved = errno;
    if (fd >= 0)
    {
        (void)close(fd);
    }
    free(path);
    errno = saved;
    return got;
}

bool rs_store_read(const struct rs_store *st, const char *name, size_t max, struct rs_buf *out,
                   struct rs_buf *err)
{
    char *path = rs_store_path(st, name);
    int   fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char  chunk[65536];
    bool  ok = true;

    rs_buf_init(out);
    rs_buf_add(out, "", 0);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    for (;;)
    {
        ssize_t got = read(fd, chunk, sizeof(chunk));

        if (got < 0 && errno == EINTR)
        {
            continue;
        }
        if (got < 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            ok = false;
            break;
        }
        if (got == 0)
        {
            break;
        }
        if (out->len + (size_t)got > max)
        {
            rs_buf_addf(err, "%s: larger than restate writes", path);
            ok = false;
            break;
        }
        rs_buf_add(out, chunk, (size_t)got);
    }
    (void)close(fd);
    free(path);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Writing                                                                   */
/* ------------------------------------------------------------------------- */

static bool write_all(int fd, const void *data, size_t n)
{
    const char *p = data;

    while (n > 0)
    {
        ssize_t w = write(fd, p, n);

        if (w < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/* Whether to act as root does in adopt(): root's alone, but for the tests. */
static bool adopting_always;

void rs_store_set_adopting(bool always)
{
    adopting_always = always;
}

/*
 * What restate makes in a repository is the repository's. Run as root -- as
 * prune, repack and check are on the storage itself -- what it makes would
 * otherwise be root's, and 0600: a share that maps every machine to the
 * repository's owner would then refuse them the packs they wrote. So a file or
 * directory root makes, `fd`, open, is given the owner and group of the
 * directory it is made in, and that group's read if the directory has it.
 * Through the descriptor, never the name: a name in a directory others can
 * write could be swapped for a link to anything.
 * False where the share will not have it, and it stays as it was made -- as
 * on a share that maps root to nobody, whose files are not root's anyway.
 */
static bool adopt(int fd, const char *path)
{
    const char *slash = strrchr(path, '/');
    char       *dir;
    struct stat parent;
    struct stat st;
    bool        ok = true;

    if (fd < 0 || (geteuid() != 0 && !adopting_always))
    {
        return true;
    }
    dir = !slash ? rs_xstrdup(".") : slash == path ? rs_xstrdup("/")
                                                    : rs_xstrndup(path, (size_t)(slash - path));
    if (stat(dir, &parent) == 0 && fstat(fd, &st) == 0)
    {
        mode_t mode = st.st_mode & 07777;

        if (st.st_uid != parent.st_uid || st.st_gid != parent.st_gid)
        {
            ok = fchown(fd, parent.st_uid, parent.st_gid) == 0;
        }
        /* Made where its group reads -- a protected repository
         * (rs_repo_protect) -- its group reads it too: what a prune or a
         * repack writes there, the machines read before protect runs again.
         * Only once it is the directory's, though: a machine root on a share
         * that maps it to a user cannot make it so, and where the directory
         * has an ACL (ZFS's), a chmod would drop the right to rename and
         * remove its own file that the ACL gave it. */
        if (ok && (parent.st_mode & S_IRGRP))
        {
            mode |= S_IRGRP | (S_ISDIR(st.st_mode) ? S_IXGRP : 0);
        }
        if (mode != (st.st_mode & 07777) && fchmod(fd, mode) != 0)
        {
            ok = false;
        }
    }
    free(dir);
    return ok;
}

/* The same for a directory just made, `path`. */
static void adopt_dir(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

    (void)adopt(fd, path);
    if (fd >= 0)
    {
        (void)close(fd);
    }
}

/* Whether create_new() acts as an older Linux does on a prepared share. */
static bool refusing_creates;

void rs_store_set_refusing_creates(bool refuse)
{
    refusing_creates = refuse;
}

/*
 * A new file `path`, 0600, open for writing; -1 with errno if not. Linux
 * before 6.x, with fs.protected_regular=2 (Ubuntu's), refuses with EACCES an
 * O_CREAT open in a sticky directory its group writes, of a file neither the
 * directory's owner nor the caller owns -- even the file that open has just
 * made. That is every file root makes on a share that maps it to another user,
 * in a directory prepared root's for that user's group to add to (as
 * SysManage prepares one): made, and then refused. So where it is refused, the
 * name is opened again without O_CREAT, which that check leaves alone, and
 * kept if it is the empty file just made. With O_EXCL it cannot be a file that
 * was there before: that is EEXIST.
 */
static int create_new(const char *path)
{
    int         fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat st;

    if (fd >= 0 && refusing_creates)
    {
        (void)close(fd);
        fd = -1;
        errno = EACCES;
    }
    if (fd >= 0 || errno != EACCES)
    {
        return fd;
    }
    fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 &&
        (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 0 || st.st_nlink != 1))
    {
        (void)close(fd);
        fd = -1;
    }
    if (fd < 0)
    {
        errno = EACCES;
    }
    return fd;
}

int rs_store_create(const struct rs_store *st, const char *name)
{
    char *path = rs_store_path(st, name);
    int   fd = create_new(path);
    int   saved = errno;

    if (fd >= 0)
    {
        (void)adopt(fd, path);
    }
    free(path);
    errno = saved;
    return fd;
}

bool rs_store_write_new(const struct rs_store *st, const char *name, const void *data, size_t len,
                        struct rs_buf *err)
{
    char *path = rs_store_path(st, name);
    int   fd = create_new(path);
    bool  ok;

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    (void)adopt(fd, path);
    ok = write_all(fd, data, len) && fsync(fd) == 0;
    if (close(fd) != 0)
    {
        ok = false;
    }
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        (void)unlink(path);
    }
    free(path);
    return ok;
}

/* The directory `name` is in, as a path. */
static char *parent_of(const struct rs_store *st, const char *name)
{
    const char *slash = strrchr(name, '/');
    char       *dir = slash ? rs_xstrndup(name, (size_t)(slash - name)) : rs_xstrdup("");
    char       *path = rs_store_path(st, dir);

    free(dir);
    return path;
}

bool rs_store_write_new_thawed(const struct rs_store *st, const char *name, const void *data,
                               size_t len, struct rs_buf *err)
{
    char                    *dir = parent_of(st, name);
    struct rs_fsflags_thawed thawed;
    bool                     ok;

    (void)rs_fsflags_thaw(dir, &thawed);
    ok = rs_store_write_new(st, name, data, len, err);
    rs_fsflags_refreeze(&thawed);
    free(dir);
    return ok;
}

bool rs_store_replace(const struct rs_store *st, const char *name, const void *data, size_t len,
                      struct rs_buf *err)
{
    const char              *slash = strrchr(name, '/');
    char                    *tmp = slash ? rs_xasprintf("%.*s/.%s.%ld.tmp", (int)(slash - name),
                                                        name, slash + 1, (long)getpid())
                                         : rs_xasprintf(".%s.%ld.tmp", name, (long)getpid());
    char                    *dir = parent_of(st, name);
    char                    *tmp_path = rs_store_path(st, tmp);
    char                    *path = rs_store_path(st, name);
    bool                     ok;
    struct rs_fsflags_thawed thawed;

    /* Where protect made it and its directory immutable, root replaces it
     * all the same: a snapshot's list of packs, a pack's .sum. */
    (void)rs_fsflags_thaw(dir, &thawed);
    (void)unlink(tmp_path);
    ok = rs_store_write_new(st, tmp, data, len, err);
    if (ok && rs_fsflags_rename(tmp_path, path) != 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        (void)unlink(tmp_path);
        ok = false;
    }
    rs_fsflags_refreeze(&thawed);
    free(path);
    free(tmp_path);
    free(dir);
    free(tmp);
    return ok;
}

int rs_store_rename(const struct rs_store *st, const char *from, const char *to, bool thawed)
{
    char *a = rs_store_path(st, from);
    char *b = rs_store_path(st, to);
    int   rc = thawed ? rs_fsflags_rename(a, b) : rename(a, b);
    int   saved = errno;

    free(a);
    free(b);
    errno = saved;
    return rc;
}

/* With link(2), which never replaces; where the filesystem has no hard links
 * (exFAT, FAT, many SMB shares), by taking the name with O_EXCL, which only
 * one machine can, and renaming over what it took. Until the rename, the name
 * is an empty file, which a reader takes for a key it cannot read. */
int rs_store_place_new(const struct rs_store *st, const char *from, const char *to)
{
    char *tmp = rs_store_path(st, from);
    char *path = rs_store_path(st, to);
    int   rc = 1;

    if (link(tmp, path) != 0)
    {
        rc = errno == EEXIST ? 0 : -1;
        if (rc < 0 && (errno == EPERM || errno == EOPNOTSUPP || errno == ENOSYS ||
                       errno == EMLINK))
        {
            int fd = create_new(path);

            if (fd < 0)
            {
                rc = errno == EEXIST ? 0 : -1;
            } else
            {
                (void)close(fd);
                rc = 1;
                if (rename(tmp, path) != 0)
                {
                    int saved = errno;

                    (void)unlink(path);
                    errno = saved;
                    rc = -1;
                }
            }
        }
    }
    {
        int saved = errno;

        free(tmp);
        free(path);
        errno = saved;
    }
    return rc;
}

int rs_store_remove(const struct rs_store *st, const char *name, bool thawed)
{
    char *path = rs_store_path(st, name);
    int   rc = thawed ? rs_fsflags_unlink(path) : unlink(path);
    int   saved = errno;

    free(path);
    errno = saved;
    return rc;
}

int rs_store_remove_dir(const struct rs_store *st, const char *name, bool thawed)
{
    char *path = rs_store_path(st, name);
    int   rc = thawed ? rs_fsflags_rmdir(path) : rmdir(path);
    int   saved = errno;

    free(path);
    errno = saved;
    return rc;
}

int rs_store_make_dir(const struct rs_store *st, const char *name, unsigned mode, bool there_ok)
{
    char *path = rs_store_path(st, name);
    int   rc = mkdir(path, (mode_t)mode);
    int   saved = errno;

    if (rc != 0 && saved == EEXIST && there_ok)
    {
        rc = 0;
    }
    if (rc == 0)
    {
        adopt_dir(path);
    }
    free(path);
    errno = saved;
    return rc;
}

char *rs_store_make_temp_dir(const struct rs_store *st, const char *prefix)
{
    char  *at = rs_store_path(st, prefix);
    char  *path = rs_xasprintf("%sXXXXXX", at);
    size_t skip = strlen(at) - strlen(prefix);
    char  *name = NULL;

    free(at);
    if (mkdtemp(path))
    {
        adopt_dir(path);
        name = rs_xstrdup(path + skip);
    }
    {
        int saved = errno;

        free(path);
        errno = saved;
    }
    return name;
}

void rs_store_sync_dir(const struct rs_store *st, const char *name)
{
    char *path = rs_store_path(st, name);
    int   fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    if (fd >= 0)
    {
        (void)fsync(fd);
        (void)close(fd);
    }
    free(path);
}

/* ------------------------------------------------------------------------- */
/* Locks                                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Locks the whole of `fd`, shared or not, without waiting: 0, or -1 with
 * errno EWOULDBLOCK if something else holds it.
 *
 * Two locks, where there are open file description locks (Linux's
 * F_OFD_SETLK). An OFD lock is a POSIX record lock, which an NFS client takes
 * on the server, so a prune run on the file server itself sees a capture's
 * lock taken over NFS, and the capture sees the prune's; flock(2) on the
 * server does not conflict with those. Like flock, and unlike F_SETLK, it
 * belongs to the open file, so two opens in one process conflict, and closing
 * some other descriptor on the file does not drop it. And flock(2) as well,
 * which is what everything else on a machine -- flock(1) in a script, restate
 * 1 -- takes. Over NFS the two are one lock: the client takes both on the
 * server for the same open file. Elsewhere flock(2) alone, which the BSDs and
 * macOS implement as the same locks as fcntl's -- and Linux only, because
 * macOS has F_OFD_SETLK too, and there the two locks on one open file
 * conflict with each other, so every capture would find itself busy.
 */
#if defined(F_OFD_SETLK) && defined(__linux__)
/* Whether `fd` is a file on an SMB share, as Linux's cifs client mounts one. */
static bool on_smb(int fd)
{
    struct statfs st;

    return fstatfs(fd, &st) == 0 && ((unsigned long)st.f_type == 0xFF534D42UL      /* CIFS */
                                     || (unsigned long)st.f_type == 0xFE534D42UL); /* SMB2 */
}
#endif

static int lock_whole(int fd, bool shared)
{
#if defined(F_OFD_SETLK) && defined(__linux__)
    struct flock fl;

    memset(&fl, 0, sizeof(fl));
    fl.l_type = shared ? F_RDLCK : F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_OFD_SETLK, &fl) != 0)
    {
        if (errno == EAGAIN || errno == EACCES)
        {
            errno = EWOULDBLOCK;
            return -1;
        }
        /* A filesystem with no record locks at all -- a FUSE one, as sshfs
         * and rclone's are -- has flock(2), which the kernel keeps itself:
         * that alone, then, as on the BSDs. */
        if (errno != ENOLCK && errno != EOPNOTSUPP && errno != EINVAL)
        {
            return -1;
        }
    } else if (on_smb(fd))
    {
        /* The kernel's SMB client takes flock(2) as a byte-range lock on the
         * server too, the same as the OFD lock, and the second one on a file
         * refuses the first with EACCES: the one lock, then, which every
         * other client of the share sees. */
        return 0;
    }
#endif
    return flock(fd, (shared ? LOCK_SH : LOCK_EX) | LOCK_NB);
}

/* Whether `fd` is a file on an NFS mount. */
static bool on_nfs(int fd)
{
#if defined(__linux__)
    struct statfs st;

    return fstatfs(fd, &st) == 0 && st.f_type == 0x6969;   /* NFS_SUPER_MAGIC */
#elif defined(__NetBSD__)
    struct statvfs st;

    return fstatvfs(fd, &st) == 0 && strncmp(st.f_fstypename, "nfs", 3) == 0;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
    struct statfs st;

    return fstatfs(fd, &st) == 0 && strncmp(st.f_fstypename, "nfs", 3) == 0;
#else
    (void)fd;
    return false;
#endif
}

static int (*lock_fn)(int fd, bool shared) = lock_whole;
static bool (*nfs_fn)(int fd) = on_nfs;
static long lock_nap_ms = 1000;

void rs_store_set_locking(int (*lock)(int fd, bool shared), bool (*nfs)(int fd), long nap_ms)
{
    lock_fn = lock ? lock : lock_whole;
    nfs_fn = nfs ? nfs : on_nfs;
    lock_nap_ms = nap_ms >= 0 ? nap_ms : 1000;
}

/*
 * lock_whole, asked again where NFS says EIO. A Linux NFS client is told EIO,
 * not EWOULDBLOCK, when the lock it asks for is held by a program on a FreeBSD
 * server itself: the lock is taken, not the disk broken. So EIO from a lock on
 * NFS is asked again, LOCK_TRIES times in all, and *refused set if it lasts. A
 * connection that is really failing fails the reads and writes after it too.
 */
#define LOCK_TRIES 3
static int lock_asking(int fd, bool shared, bool *refused)
{
    int tries;

    *refused = false;
    for (tries = 1;; tries++)
    {
        struct timespec nap;

        if (lock_fn(fd, shared) == 0)
        {
            return 0;
        }
        if (errno != EIO || !nfs_fn(fd))
        {
            return -1;
        }
        if (tries == LOCK_TRIES)
        {
            *refused = true;
            errno = EIO;
            return -1;
        }
        nap.tv_sec = lock_nap_ms / 1000;
        nap.tv_nsec = (lock_nap_ms % 1000) * 1000000L;
        (void)nanosleep(&nap, NULL);
    }
}

int rs_store_lock(const struct rs_store *st, const char *name, bool shared, bool *busy,
                  bool *refused, struct rs_buf *err)
{
    char *path = rs_store_path(st, name);
    int   fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);

    *refused = false;
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return -1;
    }
    if (lock_asking(fd, shared, refused) != 0)
    {
        if (errno == EWOULDBLOCK || *refused)
        {
            *busy = true;
        } else
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
        }
        (void)close(fd);
        fd = -1;
    }
    free(path);
    return fd;
}

void rs_store_unlock(const struct rs_store *st, int lock)
{
    (void)st;
    if (lock >= 0)
    {
        (void)close(lock);
    }
}
