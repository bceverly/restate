/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "restore.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "accounts.h"
#include "glob.h"
#include "image.h"
#include "progress.h"
#include "sha256.h"

struct ctx {
    const struct rs_index        *ix;
    const struct rs_restore_opts *o;
    struct rs_restore_stats      *st;
    int                           root;
    bool                         *done;      /* per index entry: put back */
    bool                         *seen;      /* per index entry: in the image */
    unsigned long                 counter;   /* for temporary names */
    struct rs_accounts            accounts;  /* merged, when c->st->merged */
};

/* The account files, merged rather than laid down as the image has them. */
static const char *const account_files[] = { "/etc/passwd", "/etc/group", "/etc/shadow",
                                             "/etc/gshadow" };

static ssize_t read_stream(void *ctx, void *data, size_t n)
{
    return rs_image_read_files(ctx, data, n);
}

static bool excluded(const struct ctx *c, const char *path)
{
    size_t i;

    for (i = 0; i < c->o->nexclude; i++)
    {
        if (rs_glob_covers(c->o->exclude[i], path))
        {
            return true;
        }
    }
    return false;
}

static void said(const struct ctx *c, const char *what, const char *path)
{
    if (c->o->verbose || c->o->dry_run)
    {
        struct rs_buf b;

        rs_buf_init(&b);
        rs_escape(&b, path);
        (void)printf("%s%s %s\n", c->o->dry_run ? "would " : "", what, b.data ? b.data : "");
        rs_buf_free(&b);
    }
}

static void failed(struct ctx *c, const char *path, const char *why)
{
    struct rs_buf b;

    rs_buf_init(&b);
    rs_escape(&b, path);
    rs_warn("%s: %s", b.data ? b.data : "", why);
    rs_buf_free(&b);
    c->st->failed++;
}

/*
 * The directory that holds `path`, opened beneath the root one component at
 * a time, never through a symlink: what is missing on the way is made (0700,
 * until its own entry sets it), and anything that is not a directory where
 * one has to be -- a symlink above all -- is replaced, not followed. `*name`
 * points into `path` at its last component. -1 on failure, with errno set;
 * in a dry run, -2 where the way does not exist yet (it would be made).
 */
static int open_parent(struct ctx *c, const char *path, const char **name)
{
    const char *p = path + 1;
    const char *slash;
    int         fd = dup(c->root);

    while (fd >= 0 && (slash = strchr(p, '/')) != NULL)
    {
        char *comp = rs_xstrndup(p, (size_t)(slash - p));
        int   next = openat(fd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

        if (next < 0 && (errno == ENOENT || errno == ENOTDIR || errno == ELOOP))
        {
            if (c->o->dry_run)
            {
                free(comp);
                (void)close(fd);
                return -2;
            }
            if (errno != ENOENT)
            {
                (void)unlinkat(fd, comp, 0);
            }
            if (mkdirat(fd, comp, 0700) == 0 || errno == EEXIST)
            {
                next = openat(fd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            }
        }
        free(comp);
        (void)close(fd);
        fd = next;
        p = slash + 1;
    }
    *name = p;
    return fd;
}

/* A name to create beside the destination, then rename over it. */
static char *temp_name(struct ctx *c)
{
    return rs_xasprintf(".restate-%ld-%lu", (long)getpid(), ++c->counter);
}

static struct timespec ts_of(const struct rs_time *t)
{
    struct timespec ts;

    ts.tv_sec = (time_t)t->sec;
    ts.tv_nsec = t->set ? (long)t->nsec : UTIME_OMIT;
    if (!t->set)
    {
        ts.tv_sec = 0;
    }
    return ts;
}

/* Whether `err` says the system cannot do this at all. */
static bool unsupported(int err)
{
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    if (err == EOPNOTSUPP)
    {
        return true;
    }
#endif
    return err == ENOTSUP || err == ENOSYS || err == EINVAL;
}

/* The name the image's accounts gave an id, as the index records it beside
 * the files that id owned; NULL if no file it recorded had that owner. */
static const char *old_name(const struct ctx *c, unsigned long id, bool group)
{
    size_t i;

    for (i = 0; i < c->ix->count; i++)
    {
        const struct rs_entry *e = &c->ix->entries[i];

        if (!group && e->user && e->uid == id)
        {
            return e->user;
        }
        if (group && e->group && e->gid == id)
        {
            return e->group;
        }
    }
    return NULL;
}

static unsigned long acl_uid(const void *ctx, unsigned long id)
{
    const struct ctx *c = ctx;
    const char       *name = old_name(c, id, false);
    uint64_t          now;

    return name && rs_accounts_uid(&c->accounts, name, &now) ? (unsigned long)now : id;
}

static unsigned long acl_gid(const void *ctx, unsigned long id)
{
    const struct ctx *c = ctx;
    const char       *name = old_name(c, id, true);
    uint64_t          now;

    return name && rs_accounts_gid(&c->accounts, name, &now) ? (unsigned long)now : id;
}

/* The entry's extended attributes on the open `fd`, after its owner. An
 * ACL's users and groups are mapped by name, as owners are. */
static void set_xattrs(struct ctx *c, int fd, const struct rs_entry *e)
{
    size_t i;

    for (i = 0; i < e->nxattrs; i++)
    {
        struct rs_xattr one = e->xattrs[i];

        one.value = rs_xmalloc(one.len ? one.len : 1);
        if (one.len)
        {
            memcpy(one.value, e->xattrs[i].value, one.len);
        }
        if (c->st->merged && rs_xattr_is_acl(one.name))
        {
            (void)rs_xattr_map_acl(one.value, one.len, acl_uid, acl_gid, c);
        }
        c->st->xattrs += rs_xattr_write(fd, &one, 1);
        free(one.value);
    }
}

/* Owner, extended attributes, mode and times on `name` in `dir` (a
 * temporary, not yet renamed); the attributes through `xfd`, open on it, or
 * none if it is -1. Owner first: chown clears set-id bits and capabilities,
 * which the attributes and chmod then put back; mode after the attributes,
 * since setting an ACL sets the group bits from it. */
static bool set_meta(struct ctx *c, int dir, const char *name, const struct rs_entry *e,
                     bool symlink, int xfd)
{
    struct timespec ts[2];
    int             flags = symlink ? AT_SYMLINK_NOFOLLOW : 0;

    uint64_t        uid = e->uid;
    uint64_t        gid = e->gid;

    /* By name, through the merged accounts, where the index has a name. */
    if (c->st->merged)
    {
        (void)rs_accounts_uid(&c->accounts, e->user, &uid);
        (void)rs_accounts_gid(&c->accounts, e->group, &gid);
    }
    if (fchownat(dir, name, (uid_t)uid, (gid_t)gid, AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (errno != EPERM)
        {
            return false;
        }
        c->st->owners++;
    }
    if (xfd >= 0)
    {
        set_xattrs(c, xfd, e);
    }
    if (!symlink && fchmodat(dir, name, (mode_t)e->mode, 0) != 0)
    {
        return false;
    }
    /* A symlink's own mode: real on macOS and the BSDs, where a link takes
     * its mode from the umask it was made under (restate's is tight); on
     * Linux always 0777, and not to be changed, so "not supported" is fine. */
    if (symlink && fchmodat(dir, name, (mode_t)e->mode, AT_SYMLINK_NOFOLLOW) != 0 &&
        !unsupported(errno))
    {
        return false;
    }
    ts[0] = ts_of(&e->atime);
    ts[1] = ts_of(&e->mtime);
    return utimensat(dir, name, ts, flags) == 0;
}

/* Renames `tmp` over `name`; a directory in the way is not replaced. */
static bool put_in_place(struct ctx *c, int dir, const char *tmp, const char *name,
                         const char *path)
{
    if (renameat(dir, tmp, dir, name) == 0)
    {
        return true;
    }
    {
        bool in_way = errno == EISDIR || errno == ENOTEMPTY || errno == EEXIST;

        failed(c, path, in_way ? "a directory is in the way; left as it is" : strerror(errno));
    }
    (void)unlinkat(dir, tmp, 0);
    return false;
}

/* The merged text for `path`, if it is an account file and the accounts
 * were merged; else NULL. */
static const char *merged_text(const struct ctx *c, const char *path)
{
    if (!c->st->merged)
    {
        return NULL;
    }
    if (strcmp(path, account_files[0]) == 0)
    {
        return c->accounts.passwd;
    }
    if (strcmp(path, account_files[1]) == 0)
    {
        return c->accounts.group;
    }
    if (strcmp(path, account_files[2]) == 0)
    {
        return c->accounts.shadow;
    }
    if (strcmp(path, account_files[3]) == 0)
    {
        return c->accounts.gshadow;
    }
    return NULL;
}

static bool write_text(int fd, const char *text)
{
    size_t left = strlen(text);

    while (left > 0)
    {
        ssize_t w = write(fd, text, left);

        if (w < 0 && errno == EINTR)
        {
            continue;
        }
        if (w <= 0)
        {
            return false;
        }
        text += w;
        left -= (size_t)w;
    }
    return true;
}

/* A regular file: written beside its place, hashed as it is written, and
 * put in place only if the digest is the index's. */
static bool restore_file(struct ctx *c, struct rs_tar_reader *r, const struct rs_entry *e,
                         struct rs_buf *err)
{
    unsigned char    chunk[65536];
    struct rs_sha256 sha;
    char             hex[RS_SHA256_HEX_SIZE];
    const char      *name;
    const char      *merged = merged_text(c, e->path);
    int              dir = open_parent(c, e->path, &name);
    char            *tmp = NULL;
    int              out = -1;
    bool             ok = true;
    bool             wrote = true;
    ssize_t          n;

    if (dir == -1)
    {
        failed(c, e->path, strerror(errno));
        wrote = false;
    } else if (dir >= 0 && !c->o->dry_run)
    {
        tmp = temp_name(c);
        out = openat(dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (out < 0)
        {
            failed(c, e->path, strerror(errno));
            wrote = false;
        }
    }
    rs_sha256_init(&sha);
    while ((n = rs_tar_read(r, chunk, sizeof(chunk), err)) > 0)
    {
        rs_sha256_update(&sha, chunk, (size_t)n);
        rs_progress_bytes((uint64_t)n);
        c->st->bytes += (uint64_t)n;
        if (out >= 0 && !merged)
        {
            const unsigned char *p = chunk;
            size_t               left = (size_t)n;

            while (left > 0 && wrote)
            {
                ssize_t w = write(out, p, left);

                if (w < 0 && errno == EINTR)
                {
                    continue;
                }
                if (w <= 0)
                {
                    failed(c, e->path, strerror(errno));
                    wrote = false;
                    break;
                }
                p += w;
                left -= (size_t)w;
            }
        }
    }
    if (n < 0)
    {
        ok = false;   /* the stream itself: nothing more can be read */
    }
    rs_sha256_final(&sha, hex);
    /* An account file: the image's copy checked, as every file is, and the
     * merged one written in its place. */
    if (merged && out >= 0 && ok && !write_text(out, merged))
    {
        failed(c, e->path, strerror(errno));
        wrote = false;
    }
    if (ok && (e->hash_state != RS_HASH_PRESENT || strcmp(hex, e->hash) != 0))
    {
        struct rs_buf b;

        rs_buf_init(&b);
        rs_escape(&b, e->path);
        rs_warn("%s: %s; not put back", b.data ? b.data : "",
                e->hash_state == RS_HASH_PRESENT
                    ? "its content is not what the index says it is"
                    : "it could not be read when it was captured");
        rs_buf_free(&b);
        c->st->refused++;
        wrote = false;
    }
    if (out >= 0)
    {
        if (wrote && ok && !set_meta(c, dir, tmp, e, false, out))
        {
            failed(c, e->path, strerror(errno));
            wrote = false;
        }
        (void)close(out);
        if (wrote && ok)
        {
            wrote = put_in_place(c, dir, tmp, name, e->path);
        } else
        {
            (void)unlinkat(dir, tmp, 0);
        }
    }
    if (ok && wrote)
    {
        c->st->files++;
        c->done[e - c->ix->entries] = true;
        said(c, "restore", e->path);
    }
    free(tmp);
    if (dir >= 0)
    {
        (void)close(dir);
    }
    return ok;
}

/* A symlink, a FIFO or a device node: made beside its place, then renamed. */
static void restore_special(struct ctx *c, const struct rs_entry *e)
{
    const char *name;
    int         dir = open_parent(c, e->path, &name);
    char       *tmp;
    int         made;

    if (dir == -2)
    {
        said(c, "restore", e->path);
        return;
    }
    if (dir < 0)
    {
        failed(c, e->path, strerror(errno));
        return;
    }
    if (c->o->dry_run)
    {
        said(c, "restore", e->path);
        (void)close(dir);
        return;
    }
    tmp = temp_name(c);
    switch (e->type)
    {
    case 'l':
        made = symlinkat(e->target, dir, tmp);
        break;
    case 'p':
        made = mkfifoat(dir, tmp, 0600);
        break;
    default:
        made = mknodat(dir, tmp, (mode_t)((e->type == 'c' ? S_IFCHR : S_IFBLK) | 0600),
                       (dev_t)e->rdev);
        break;
    }
    if (made != 0)
    {
        failed(c, e->path, strerror(errno));
    } else if (!set_meta(c, dir, tmp, e, e->type == 'l', -1))
    {
        failed(c, e->path, strerror(errno));
        (void)unlinkat(dir, tmp, 0);
    } else if (put_in_place(c, dir, tmp, name, e->path))
    {
        if (e->type == 'l')
        {
            c->st->symlinks++;
        } else
        {
            c->st->other++;
        }
        c->done[e - c->ix->entries] = true;
        said(c, "restore", e->path);
    }
    free(tmp);
    (void)close(dir);
}

/* A directory: there, and a directory, now; its owner, mode and times once
 * everything in it is in (finish_dirs). */
static void restore_dir(struct ctx *c, const struct rs_entry *e)
{
    const char *name;
    int         dir = open_parent(c, e->path, &name);
    struct stat st;

    if (dir == -2 || (dir >= 0 && c->o->dry_run))
    {
        c->done[e - c->ix->entries] = true;
        if (dir >= 0)
        {
            (void)close(dir);
        }
        return;
    }
    if (dir < 0)
    {
        failed(c, e->path, strerror(errno));
        return;
    }
    if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && !S_ISDIR(st.st_mode))
    {
        /* A file or a symlink where the image has a directory: the image's. */
        (void)unlinkat(dir, name, 0);
    }
    if (mkdirat(dir, name, 0700) != 0 && errno != EEXIST)
    {
        failed(c, e->path, strerror(errno));
    } else
    {
        c->done[e - c->ix->entries] = true;
    }
    (void)close(dir);
}

/* Each directory's owner, mode and times, deepest first. */
static void finish_dirs(struct ctx *c)
{
    size_t i = c->ix->count;

    while (i > 0)
    {
        const struct rs_entry *e = &c->ix->entries[--i];
        const char            *name;
        int                    dir;
        int                    fd;

        if (e->type != 'd' || !c->done[i] || strcmp(e->path, "/") == 0)
        {
            continue;
        }
        c->st->directories++;
        said(c, "restore", e->path);
        if (c->o->dry_run)
        {
            continue;
        }
        dir = open_parent(c, e->path, &name);
        fd = dir >= 0 ? openat(dir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
        if (fd < 0 || !set_meta(c, fd, ".", e, false, fd))
        {
            failed(c, e->path, strerror(errno));
        }
        if (fd >= 0)
        {
            (void)close(fd);
        }
        if (dir >= 0)
        {
            (void)close(dir);
        }
    }
}

/* Hard links: every path of one file, made a link to the first put back. */
static void link_files(struct ctx *c)
{
    size_t i;
    size_t j;

    for (i = 0; i < c->ix->count; i++)
    {
        const struct rs_entry *a = &c->ix->entries[i];

        if (a->type != 'f' || a->nlink < 2 || !c->done[i])
        {
            continue;
        }
        for (j = i + 1; j < c->ix->count; j++)
        {
            const struct rs_entry *b = &c->ix->entries[j];
            const char            *an;
            const char            *bn;
            int                    ad;
            int                    bd;
            char                  *tmp;

            if (b->type != 'f' || b->dev != a->dev || b->ino != a->ino || excluded(c, b->path))
            {
                continue;
            }
            /* Linked to this one, whether it was put back on its own or not. */
            c->done[j] = false;
            c->st->links++;
            said(c, "link", b->path);
            if (c->o->dry_run)
            {
                continue;
            }
            ad = open_parent(c, a->path, &an);
            bd = open_parent(c, b->path, &bn);
            tmp = temp_name(c);
            if (ad < 0 || bd < 0 || linkat(ad, an, bd, tmp, 0) != 0)
            {
                failed(c, b->path, strerror(errno));
            } else
            {
                (void)put_in_place(c, bd, tmp, bn, b->path);
            }
            free(tmp);
            if (ad >= 0)
            {
                (void)close(ad);
            }
            if (bd >= 0)
            {
                (void)close(bd);
            }
        }
    }
}

/* One member of the image: it has to be an entry the index lists, and the
 * thing the index says. */
static bool member(struct ctx *c, struct rs_tar_reader *r, struct rs_tar_entry *m,
                   struct rs_buf *err)
{
    static const char      prefix[] = RS_IMAGE_FILES_DIR "/";
    const char            *path;
    const struct rs_entry *e;
    char                   want;

    /* A directory's name may end in a slash, as other tars write it. */
    while (m->name.len > 1 && m->name.data[m->name.len - 1] == '/')
    {
        m->name.data[--m->name.len] = '\0';
    }
    rs_progress_path(m->name.data);
    if (strcmp(m->name.data, RS_IMAGE_INDEX_NAME) == 0 ||
        strcmp(m->name.data, RS_IMAGE_FILES_DIR) == 0)
    {
        return true;   /* the index of an image from before 1.1; the root */
    }
    if (strncmp(m->name.data, prefix, sizeof(prefix) - 1) != 0)
    {
        c->st->refused++;
        rs_warn("%s: not part of an image's files; refused", m->name.data);
        return true;
    }
    path = m->name.data + sizeof(prefix) - 2;   /* from its leading slash */
    e = rs_path_is_clean(path) ? rs_index_find(c->ix, path) : NULL;
    switch (m->typeflag)
    {
    case '0':
        want = 'f';
        break;
    case '5':
        want = 'd';
        break;
    case '2':
        want = 'l';
        break;
    case '6':
        want = 'p';
        break;
    default:
        want = '?';
        break;
    }
    if (!e || e->type != want || !e->stored || strcmp(e->stored, m->name.data) != 0 ||
        (want == 'l' && (!e->target || strcmp(e->target, m->linkname.data) != 0)) ||
        (want == 'f' && e->size != m->size))
    {
        struct rs_buf b;

        rs_buf_init(&b);
        rs_escape(&b, path);
        rs_warn("%s: in the image, but not as the index records it; refused",
                b.data ? b.data : "");
        rs_buf_free(&b);
        c->st->refused++;
        return true;
    }
    c->seen[e - c->ix->entries] = true;
    if (excluded(c, e->path))
    {
        c->st->excluded++;
        return true;
    }
    switch (want)
    {
    case 'f':
        return restore_file(c, r, e, err);
    case 'd':
        restore_dir(c, e);
        return true;
    default:
        restore_special(c, e);
        return true;
    }
}

/* A small file beneath the root, read without making anything on the way
 * or following a symlink; NULL if it is not there. */
static char *read_beneath(const struct ctx *c, const char *path)
{
    const char   *p = path + 1;
    const char   *slash;
    int           fd = dup(c->root);
    struct rs_buf text;
    char          chunk[8192];
    ssize_t       n;

    while (fd >= 0 && (slash = strchr(p, '/')) != NULL)
    {
        char *comp = rs_xstrndup(p, (size_t)(slash - p));
        int   next = openat(fd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

        free(comp);
        (void)close(fd);
        fd = next;
        p = slash + 1;
    }
    if (fd >= 0)
    {
        int file = openat(fd, p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

        (void)close(fd);
        fd = file;
    }
    if (fd < 0)
    {
        return NULL;
    }
    rs_buf_init(&text);
    rs_buf_add(&text, "", 0);
    while ((n = read(fd, chunk, sizeof(chunk))) > 0 && text.len < (size_t)16 * 1024 * 1024)
    {
        rs_buf_add(&text, chunk, (size_t)n);
    }
    (void)close(fd);
    return rs_buf_detach(&text);
}

/*
 * The image's account files, from its kit -- each checked against its
 * digest in the index, as any file is -- merged with the system's own. False
 * if they cannot be: an image from before 1.1, with no kit, or a kit
 * without them; owners are then restored by number.
 */
static bool merge_accounts(struct ctx *c, const char *path)
{
    struct rs_image_stream  s;
    struct rs_tar_reader    r;
    struct rs_tar_entry     m;
    struct rs_buf           err;
    struct rs_buf           texts[4];
    struct rs_account_files now;
    struct rs_account_files old;
    char                   *mine[4];
    size_t                  k;
    bool                    ok;

    rs_buf_init(&err);
    for (k = 0; k < 4; k++)
    {
        rs_buf_init(&texts[k]);
        mine[k] = NULL;
    }
    if (!rs_image_open_kit(path, &s, &err))
    {
        rs_buf_free(&err);
        return false;
    }
    rs_tar_reader_init(&r, read_stream, &s);
    rs_tar_entry_init(&m);
    while (rs_tar_next(&r, &m, &err) == 1)
    {
        for (k = 0; k < 4; k++)
        {
            char                  *want = rs_xasprintf(RS_IMAGE_FILES_DIR "%s", account_files[k]);
            const struct rs_entry *e = rs_index_find(c->ix, account_files[k]);

            if (strcmp(m.name.data, want) == 0 && e && e->hash_state == RS_HASH_PRESENT &&
                m.typeflag == '0')
            {
                unsigned char    chunk[8192];
                struct rs_sha256 sha;
                char             hex[RS_SHA256_HEX_SIZE];
                ssize_t          n;

                rs_sha256_init(&sha);
                rs_buf_reset(&texts[k]);
                while ((n = rs_tar_read(&r, chunk, sizeof(chunk), &err)) > 0)
                {
                    rs_sha256_update(&sha, chunk, (size_t)n);
                    rs_buf_add(&texts[k], chunk, (size_t)n);
                }
                rs_buf_add(&texts[k], "", 0);
                rs_sha256_final(&sha, hex);
                if (strcmp(hex, e->hash) != 0)
                {
                    rs_warn("%s: its content is not what the index says it is; the accounts are "
                            "not merged", account_files[k]);
                    rs_buf_free(&texts[k]);
                    rs_buf_init(&texts[k]);
                }
            }
            free(want);
        }
    }
    rs_tar_entry_free(&m);
    (void)rs_image_close_files(&s, true, &err);
    rs_buf_reset(&err);

    old.passwd = texts[0].data;
    old.group = texts[1].data;
    old.shadow = texts[2].data;
    old.gshadow = texts[3].data;
    for (k = 0; k < 4; k++)
    {
        mine[k] = read_beneath(c, account_files[k]);
    }
    now.passwd = mine[0];
    now.group = mine[1];
    now.shadow = mine[2];
    now.gshadow = mine[3];
    ok = rs_accounts_merge(&now, &old, &c->accounts, &err);
    for (k = 0; k < 4; k++)
    {
        free(mine[k]);
        rs_buf_free(&texts[k]);
    }
    rs_buf_free(&err);
    return ok;
}

bool rs_restore(const char *path, const struct rs_index *ix, const struct rs_restore_opts *o,
                struct rs_restore_stats *st, struct rs_buf *err)
{
    struct rs_image_stream s;
    struct rs_tar_reader   r;
    struct rs_tar_entry    m;
    struct ctx             c;
    struct sigaction       ignore;
    struct sigaction       saved;
    uint64_t               total = 0;
    size_t                 i;
    int                    more;
    bool                   ok;

    memset(st, 0, sizeof(*st));
    memset(&c, 0, sizeof(c));
    c.ix = ix;
    c.o = o;
    c.st = st;
    c.root = open(o->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (c.root < 0)
    {
        rs_buf_addf(err, "%s: %s", o->root, strerror(errno));
        return false;
    }
    /* gzip or gpg giving up would otherwise kill restate with SIGPIPE on the
     * next write into it, before it could say why. */
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &ignore, &saved);
    /* The accounts first: every owner is mapped through them. */
    if (!o->numeric_owner)
    {
        st->merged = merge_accounts(&c, path);
    }
    if (!rs_image_open_files(path, &s, err))
    {
        (void)sigaction(SIGPIPE, &saved, NULL);
        rs_accounts_free(&c.accounts);
        (void)close(c.root);
        return false;
    }
    c.done = rs_xcalloc(ix->count + 1, sizeof(*c.done));
    c.seen = rs_xcalloc(ix->count + 1, sizeof(*c.seen));
    for (i = 0; i < ix->count; i++)
    {
        if (ix->entries[i].type == 'f' && ix->entries[i].stored)
        {
            total += ix->entries[i].size;
        }
    }
    rs_progress_phase("restoring", total);
    rs_tar_reader_init(&r, read_stream, &s);
    rs_tar_entry_init(&m);
    while ((more = rs_tar_next(&r, &m, err)) == 1)
    {
        if (!member(&c, &r, &m, err))
        {
            more = -1;
            break;
        }
    }
    rs_tar_entry_free(&m);
    rs_progress_done();
    ok = more == 0;
    if (!ok && err->len == 0)
    {
        rs_buf_addstr(err, "the image ends early");
    }
    if (!rs_image_close_files(&s, !ok, err))
    {
        ok = false;
    }
    (void)sigaction(SIGPIPE, &saved, NULL);
    if (ok)
    {
        /* What the archive does not carry: device nodes, from the index. */
        for (i = 0; i < ix->count; i++)
        {
            const struct rs_entry *e = &ix->entries[i];

            if ((e->type == 'c' || e->type == 'b') && !excluded(&c, e->path))
            {
                restore_special(&c, e);
            } else if (e->stored && !c.seen[i] && strcmp(e->path, "/") != 0 &&
                       !excluded(&c, e->path))
            {
                struct rs_buf b;

                rs_buf_init(&b);
                rs_escape(&b, e->path);
                rs_warn("%s: the index says the image holds it, and it does not", b.data);
                rs_buf_free(&b);
                c.st->missing++;
            }
        }
        link_files(&c);
        finish_dirs(&c);
    }
    free(c.done);
    free(c.seen);
    rs_accounts_free(&c.accounts);
    (void)close(c.root);
    return ok;
}
