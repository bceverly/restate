/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "image.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "gzip.h"
#include "pgp.h"
#include "progress.h"
#include "repo.h"
#include "sha256.h"

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

static bool tar_to_fd(void *ctx, const void *data, size_t n)
{
    return write_all(*(int *)ctx, data, n);
}

/* A temporary file beside `dest`, so the final rename never crosses a
 * filesystem. */
static int temp_beside(const char *dest, char **path_out, struct rs_buf *err)
{
    char *path = rs_xasprintf("%s.XXXXXX", dest);
    int   fd = mkstemp(path);

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", dest, strerror(errno));
        free(path);
        return -1;
    }
    *path_out = path;
    return fd;
}

/* Where the content is staged instead of beside the image (--tmpdir). */
static char *stage_dir;

void rs_image_set_stage_dir(const char *dir)
{
    free(stage_dir);
    stage_dir = dir ? rs_xstrdup(dir) : NULL;
}

bool rs_image_begin(struct rs_image_writer *iw, const char *dest, struct rs_buf *err)
{
    char *tmp = NULL;

    memset(iw, 0, sizeof(*iw));
    if (stage_dir)
    {
        char *beside = rs_xasprintf("%s/restate-image", stage_dir);

        iw->content_fd = temp_beside(beside, &tmp, err);
        free(beside);
    } else
    {
        iw->content_fd = temp_beside(dest, &tmp, err);
    }
    if (iw->content_fd < 0)
    {
        return false;
    }
    /* Unlinked at once: nothing to clean up after a crash, and nothing for
     * anyone else to open in the meantime. */
    (void)unlink(tmp);
    free(tmp);
    iw->dest = rs_xstrdup(dest);
    rs_tar_writer_init(&iw->tar, tar_to_fd, &iw->content_fd);
    return true;
}

void rs_image_abort(struct rs_image_writer *iw)
{
    if (iw->content_fd >= 0)
    {
        (void)close(iw->content_fd);
    }
    iw->content_fd = -1;
    free(iw->dest);
    iw->dest = NULL;
    free(iw->spans);
    iw->spans = NULL;
    iw->nspans = 0;
}

bool rs_image_in_list(const char *path, const char *const *list, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        const char *k = list[i];
        size_t      len = strlen(k);

        if (len > 0 && k[len - 1] == '/' ? strncmp(path, k, len) == 0 : strcmp(path, k) == 0)
        {
            return true;
        }
    }
    return false;
}

char *rs_image_member_name(const char *path)
{
    if (path[0] == '/' && path[1] == '\0')
    {
        return rs_xstrdup(RS_IMAGE_FILES_DIR);
    }
    return rs_xasprintf("%s%s", RS_IMAGE_FILES_DIR, path);
}

/*
 * Copies exactly `size` bytes of `fd` into the archive -- the tar header has
 * already promised that many -- hashing exactly what is stored.
 *
 * A file that grows while it is read (a log being written to) is kept as it
 * was when the copy began: its first `size` bytes, a consistent prefix, with
 * a digest of those bytes; e->copy says it grew, so it can be reported, and
 * the rest is left for the next capture rather than chased to an end that
 * keeps moving. A file that shrinks, or whose read fails, is padded with
 * zeros to the promised size and its digest marked unreadable, because what
 * is stored then is not the file.
 */
/* What rs_image_copy_file also hands what it copies to, while one is set. */
static void (*copy_tap)(void *ctx, const void *data, size_t n);
static void *copy_tap_ctx;

void rs_image_copy_tap(void (*tap)(void *ctx, const void *data, size_t n), void *ctx)
{
    copy_tap = tap;
    copy_tap_ctx = ctx;
}

bool rs_image_copy_file(struct rs_tar_writer *tar, struct rs_entry *e, int fd, uint64_t size)
{
    static const unsigned char zero[4096];
    unsigned char              chunk[65536];
    struct rs_sha256           ctx;
    uint64_t                   copied = 0;

    e->copy = RS_COPY_OK;
    e->copy_errno = 0;
    rs_sha256_init(&ctx);
    for (;;)
    {
        size_t  want = copied < size && size - copied < sizeof(chunk) ? (size_t)(size - copied)
                                                                      : sizeof(chunk);
        ssize_t n = read(fd, chunk, want);

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            e->copy = RS_COPY_READ_ERROR;
            e->copy_errno = errno;
            break;
        }
        if (n == 0)
        {
            break;
        }
        rs_progress_bytes((uint64_t)n);
        if (copied >= size)
        {
            /* Read past what the header promised: it grew. */
            e->copy = RS_COPY_GREW;
            break;
        }
        rs_sha256_update(&ctx, chunk, (size_t)n);
        if (copy_tap)
        {
            copy_tap(copy_tap_ctx, chunk, (size_t)n);
        }
        if (!rs_tar_data(tar, chunk, (size_t)n))
        {
            return false;
        }
        copied += (uint64_t)n;
    }
    if (copied < size && e->copy == RS_COPY_OK)
    {
        e->copy = RS_COPY_SHRANK;
    }
    while (copied < size)
    {
        size_t take = size - copied < sizeof(zero) ? (size_t)(size - copied) : sizeof(zero);

        if (!rs_tar_data(tar, zero, take))
        {
            return false;
        }
        copied += take;
    }
    rs_sha256_final(&ctx, e->hash);
    e->hash_state = (e->copy == RS_COPY_OK || e->copy == RS_COPY_GREW) ? RS_HASH_PRESENT
                                                                       : RS_HASH_UNREADABLE;
    return rs_tar_pad(tar);
}

bool rs_image_member(const struct rs_entry *e, const char *name, uint64_t size,
                     struct rs_tar_member *m)
{
    memset(m, 0, sizeof(*m));
    switch (e->type)
    {
    case 'f':
        m->typeflag = '0';
        m->size = size;
        break;
    case 'd':
        m->typeflag = '5';
        break;
    case 'l':
        m->typeflag = '2';
        m->linkname = e->target;
        break;
    case 'p':
        m->typeflag = '6';
        break;
    default:
        /* Device nodes are recorded in the index and recreated from it, not
         * archived: a tar device member is not portable between systems. */
        return false;
    }
    m->name = name;
    m->mode = e->mode;
    m->uid = e->uid;
    m->gid = e->gid;
    m->uname = e->user;
    m->gname = e->group;
    m->mtime = e->mtime;
    m->atime = e->atime;
    return true;
}

/* A member's header, then its data from `copy` (NULL: none), then where the
 * kit has it; e->stored is set once it is all written. */
static bool store_member(struct rs_image_writer *iw, struct rs_entry *e, uint64_t size,
                         bool (*copy)(struct rs_image_writer *iw, struct rs_entry *e,
                                      uint64_t size, const void *ctx),
                         const void *ctx, struct rs_buf *err)
{
    struct rs_tar_member m;
    char                *name = rs_image_member_name(e->path);
    uint64_t             start = iw->tar.offset;
    bool                 ok;

    if (!rs_image_member(e, name, size, &m))
    {
        free(name);
        return true;
    }
    ok = rs_tar_header(&iw->tar, &m);
    if (ok && e->type == 'f')
    {
        ok = copy(iw, e, size, ctx);
    }
    if (!ok)
    {
        if (err->len == 0)
        {
            rs_buf_addf(err, "writing the image beside %s: %s", iw->dest, strerror(errno));
        }
        free(name);
        return false;
    }
    free(e->stored);
    e->stored = name;
    if (rs_image_in_list(e->path, iw->kit, iw->nkit))
    {
        iw->spans = rs_xreallocarray(iw->spans, iw->nspans + 1, sizeof(*iw->spans));
        iw->spans[iw->nspans].offset = start;
        iw->spans[iw->nspans].length = iw->tar.offset - start;
        iw->nspans++;
    }
    return true;
}

static bool copy_from_fd(struct rs_image_writer *iw, struct rs_entry *e, uint64_t size,
                         const void *ctx)
{
    return rs_image_copy_file(&iw->tar, e, *(const int *)ctx, size);
}

bool rs_image_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                    struct rs_buf *err)
{
    return store_member(ctx, e, e->type == 'f' ? (uint64_t)st->st_size : 0, copy_from_fd, &fd,
                        err);
}

/* The index, rendered into memory. */
static char *index_text(const struct rs_index *ix, size_t *len)
{
    char  *text = NULL;
    FILE  *fp = open_memstream(&text, len);
    bool   ok;

    if (!fp)
    {
        return NULL;
    }
    ok = rs_index_write(ix, fp);
    if (fclose(fp) != 0 || !ok)
    {
        free(text);
        return NULL;
    }
    return text;
}

static bool copy_content(int from, int to, struct rs_buf *err)
{
    char chunk[65536];

    if (lseek(from, 0, SEEK_SET) < 0)
    {
        rs_buf_addf(err, "rewinding the content: %s", strerror(errno));
        return false;
    }
    for (;;)
    {
        ssize_t n = read(from, chunk, sizeof(chunk));

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            rs_buf_addf(err, "reading the content back: %s", strerror(errno));
            return false;
        }
        if (n == 0)
        {
            return true;
        }
        if (!write_all(to, chunk, (size_t)n))
        {
            rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
            return false;
        }
        rs_progress_bytes((uint64_t)n);
    }
}

/* The end of a tar archive: two zero blocks. */
static bool tar_end(int fd)
{
    static const unsigned char zero[2 * RS_TAR_BLOCK];

    return write_all(fd, zero, sizeof(zero));
}

/* Copies `len` bytes of `from` at `offset` to `to`. */
static bool copy_range(int from, uint64_t offset, uint64_t len, int to, struct rs_buf *err)
{
    char chunk[65536];

    while (len > 0)
    {
        size_t  want = len < sizeof(chunk) ? (size_t)len : sizeof(chunk);
        ssize_t n = pread(from, chunk, want, (off_t)offset);

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            rs_buf_addf(err, "reading the content back: %s", n < 0 ? strerror(errno)
                                                                   : "it is shorter than written");
            return false;
        }
        if (!write_all(to, chunk, (size_t)n))
        {
            rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
            return false;
        }
        offset += (uint64_t)n;
        len -= (uint64_t)n;
    }
    return true;
}

/* What goes into one part of the image, written to `fd` (gzip's input). */
struct part {
    const char             *name;      /* "restate/kit.tar.gz", say */
    struct rs_image_writer *iw;
    const char             *text;      /* the index part's */
    size_t                  len;
    bool (*produce)(const struct part *pt, int fd, struct rs_buf *err);
};

static bool produce_index(const struct part *pt, int fd, struct rs_buf *err)
{
    if (!write_all(fd, pt->text, pt->len))
    {
        rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
        return false;
    }
    return true;
}

/* The kit: the members recorded as it went, copied out of the content. */
static bool produce_kit(const struct part *pt, int fd, struct rs_buf *err)
{
    size_t i;

    for (i = 0; i < pt->iw->nspans; i++)
    {
        if (!copy_range(pt->iw->content_fd, pt->iw->spans[i].offset, pt->iw->spans[i].length,
                        fd, err))
        {
            return false;
        }
    }
    if (!tar_end(fd))
    {
        rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
        return false;
    }
    return true;
}

static bool produce_files(const struct part *pt, int fd, struct rs_buf *err)
{
    struct stat staged;
    uint64_t    total = 0;
    bool        ok;

    /* The one step whose total is known: the content staged during the walk,
     * through gzip (and gpg) into the image. */
    if (fstat(pt->iw->content_fd, &staged) == 0)
    {
        total = (uint64_t)staged.st_size;
    }
    rs_progress_phase("writing", total);
    ok = copy_content(pt->iw->content_fd, fd, err);
    rs_progress_done();
    if (ok && !tar_end(fd))
    {
        rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
        ok = false;
    }
    return ok;
}

static bool to_buf(void *ctx, const void *data, size_t n)
{
    rs_buf_add(ctx, data, n);
    return true;
}

/*
 * One part of the image, as a member of the outer tar archive in `out`: its
 * content gzip'd (and encrypted, with recipients) straight into the file
 * after a header that is only written once the size is known. The header is
 * the same three blocks whatever the size -- a pax header, its records, the
 * ustar header -- so its place is kept with zeros first.
 */
static bool write_part(const struct part *pt, int out, const struct rs_time *mtime,
                       uint64_t *data_at, uint64_t *data_len, struct rs_buf *err)
{
    static const unsigned char zero[3 * RS_TAR_BLOCK];
    struct rs_tar_member       m;
    struct rs_tar_writer       tw;
    struct rs_gzip             gz;
    struct rs_pgp              pg;
    struct rs_buf              head;
    struct rs_image_writer    *iw = pt->iw;
    bool                       sealed = iw->nrecipients > 0;
    off_t                      at = lseek(out, 0, SEEK_CUR);
    off_t                      end;
    char                      *name;
    bool                       ok;

    if (at < 0 || !write_all(out, zero, sizeof(zero)))
    {
        rs_buf_addf(err, "writing %s: %s", iw->dest, strerror(errno));
        return false;
    }
    /* Encrypted, gzip writes into gpg and gpg into the file; our copy of the
     * pipe into gpg is closed once gzip has its own, so gpg sees the end of
     * the data when gzip exits. */
    memset(&pg, 0, sizeof(pg));
    pg.fd = -1;
    ok = !sealed || rs_pgp_encrypt(iw->recipients, iw->nrecipients, out, &pg, err);
    ok = ok && rs_gzip_compress(sealed ? pg.fd : out, &gz, err);
    if (sealed && pg.fd >= 0)
    {
        (void)close(pg.fd);
        pg.fd = -1;
    }
    if (ok)
    {
        ok = pt->produce(pt, gz.fd, err);
        if (!rs_gzip_finish(&gz, false, err))
        {
            ok = false;
        }
    }
    if (sealed && pg.pid > 0 && !rs_pgp_finish(&pg, false, err))
    {
        ok = false;
    }
    end = lseek(out, 0, SEEK_END);
    if (!ok || end < at + (off_t)sizeof(zero))
    {
        if (ok)
        {
            rs_buf_addf(err, "writing %s: %s", iw->dest, strerror(errno));
        }
        return false;
    }
    /* Padded to a whole block, then the header in its place. */
    {
        uint64_t size = (uint64_t)(end - at) - sizeof(zero);
        size_t   pad = (size_t)((RS_TAR_BLOCK - size % RS_TAR_BLOCK) % RS_TAR_BLOCK);

        *data_at = (uint64_t)at + sizeof(zero);
        *data_len = size;

        name = rs_xasprintf("%s%s", pt->name, sealed ? ".gpg" : "");
        memset(&m, 0, sizeof(m));
        m.name = name;
        m.typeflag = '0';
        m.mode = 0600;
        m.uid = (uint64_t)geteuid();
        m.gid = (uint64_t)getegid();
        m.size = size;
        m.mtime = *mtime;
        rs_buf_init(&head);
        rs_tar_writer_init(&tw, to_buf, &head);
        ok = rs_tar_header(&tw, &m) && head.len == sizeof(zero) && write_all(out, zero, pad) &&
             pwrite(out, head.data, head.len, at) == (ssize_t)head.len;
        if (!ok)
        {
            rs_buf_addf(err, "writing %s's header in %s: %s", name, iw->dest,
                        head.len == sizeof(zero) ? strerror(errno) : "it is not three blocks");
        }
        rs_buf_free(&head);
        free(name);
    }
    return ok;
}

/* A member of `len` bytes at `data`, header, data and padding, into `out`. */
static bool write_member(int out, const char *name, const void *data, size_t len,
                         const struct rs_time *mtime)
{
    static const unsigned char zero[RS_TAR_BLOCK];
    struct rs_tar_member       m;
    struct rs_tar_writer       tw;
    struct rs_buf              head;
    bool                       ok;

    memset(&m, 0, sizeof(m));
    m.name = name;
    m.typeflag = '0';
    m.mode = 0600;
    m.uid = (uint64_t)geteuid();
    m.gid = (uint64_t)getegid();
    m.size = len;
    m.mtime = *mtime;
    rs_buf_init(&head);
    rs_tar_writer_init(&tw, to_buf, &head);
    ok = rs_tar_header(&tw, &m) && write_all(out, head.data, head.len) &&
         write_all(out, data, len) &&
         write_all(out, zero, (RS_TAR_BLOCK - len % RS_TAR_BLOCK) % RS_TAR_BLOCK);
    rs_buf_free(&head);
    return ok;
}

/* Copies `len` bytes of `from` at `offset` into a new file `path`. */
static bool copy_out(int from, uint64_t offset, uint64_t len, const char *path,
                     struct rs_buf *err)
{
    int  to = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok;

    if (to < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    ok = copy_range(from, offset, len, to, err);
    if (close(to) != 0 && ok)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        ok = false;
    }
    return ok;
}

/* The signature over the `len` bytes of `fd` at `offset`, by `keyfile`. */
static bool sign_range(int fd, uint64_t offset, uint64_t len, const char *keyfile,
                       struct rs_buf *sig, struct rs_pgp_signer *signer, struct rs_buf *err)
{
    char *dir = rs_pgp_home(err);
    char *data;
    bool  ok;

    if (!dir)
    {
        return false;
    }
    data = rs_xasprintf("%s/index", dir);
    ok = copy_out(fd, offset, len, data, err) && rs_pgp_sign(keyfile, data, sig, signer, err);
    free(data);
    rs_pgp_home_remove(dir);
    return ok;
}

bool rs_image_finish(struct rs_image_writer *iw, const struct rs_index *ix,
                     struct rs_buf *err)
{
    struct sigaction ignore;
    struct sigaction saved;
    struct rs_time   mtime;
    struct part      parts[3];
    struct rs_buf    sig;
    char            *tmp = NULL;
    char            *text;
    size_t           len = 0;
    size_t           i;
    int              out;
    bool             ok = true;

    rs_buf_init(&sig);
    text = index_text(ix, &len);
    if (!text)
    {
        rs_buf_addstr(err, "could not render the index");
        rs_image_abort(iw);
        return false;
    }
    out = temp_beside(iw->dest, &tmp, err);
    if (out < 0)
    {
        free(text);
        rs_image_abort(iw);
        return false;
    }
    /* The index's own creation time, which honors SOURCE_DATE_EPOCH, so two
     * captures of an unchanged tree are the same bytes. */
    memset(&mtime, 0, sizeof(mtime));
    if (!ix->created || !rs_time_parse(ix->created, &mtime))
    {
        mtime.sec = (int64_t)time(NULL);
        mtime.set = true;
    }

    /* A gzip that dies would otherwise kill restate with SIGPIPE on the next
     * write, before it could say why or remove the half-written file. */
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &ignore, &saved);
    if (!rs_gzip_parallel())
    {
        rs_warn("pigz is not installed, so the image is compressed on one core with gzip; "
                "installing pigz makes this several times faster");
    }

    /* Three parts, each compressed on its own, so each can be read without
     * the others: the index, the kit a reinstall needs before anything else,
     * and every file kept. */
    memset(parts, 0, sizeof(parts));
    parts[0].name = RS_IMAGE_INDEX_PART;
    parts[0].text = text;
    parts[0].len = len;
    parts[0].produce = produce_index;
    parts[1].name = RS_IMAGE_KIT_PART;
    parts[1].produce = produce_kit;
    parts[2].name = RS_IMAGE_FILES_PART;
    parts[2].produce = produce_files;
    for (i = 0; ok && i < sizeof(parts) / sizeof(parts[0]); i++)
    {
        uint64_t data_at = 0;
        uint64_t data_len = 0;

        parts[i].iw = iw;
        ok = write_part(&parts[i], out, &mtime, &data_at, &data_len, err);
        /* Signed as soon as the index is written, before the long copy of
         * the files: gpg may ask for the key's passphrase. */
        if (ok && i == 0 && iw->sign_with)
        {
            ok = sign_range(out, data_at, data_len, iw->sign_with, &sig, &iw->signer, err);
        }
    }
    if (ok && sig.len > 0 && !write_member(out, RS_IMAGE_SIG_PART, sig.data, sig.len, &mtime))
    {
        rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
        ok = false;
    }
    if (ok && !tar_end(out))
    {
        rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
        ok = false;
    }
    (void)sigaction(SIGPIPE, &saved, NULL);

    if (ok && fsync(out) != 0)
    {
        rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
        ok = false;
    }
    if (close(out) != 0 && ok)
    {
        rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
        ok = false;
    }
    if (ok && rename(tmp, iw->dest) != 0)
    {
        rs_buf_addf(err, "%s: %s", iw->dest, strerror(errno));
        ok = false;
    }
    if (!ok)
    {
        (void)unlink(tmp);
    }
    free(tmp);
    free(text);
    rs_buf_free(&sig);
    rs_image_abort(iw);
    return ok;
}

void rs_image_part_command(struct rs_buf *out, const char *image, const char *part,
                           const char *dest, const char *extra)
{
    rs_buf_addstr(out, "tar -xOf ");
    rs_shell_word(out, image);
    rs_buf_addf(out, " %s | tar -xzpf - --numeric-owner -C ", part);
    rs_shell_word(out, dest);
    rs_buf_addstr(out, " --strip-components=2");
    if (extra && *extra)
    {
        rs_buf_addf(out, " %s", extra);
    }
}

void rs_image_restore_command(struct rs_buf *out, const char *image, const char *dest,
                              bool fstab, const char *trust, const char *as)
{
    const char *prefix = strcmp(dest, "/") == 0 ? "" : dest;

    static const char *const dirs[] = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
                                       "/usr/bin"};
    size_t                   i;

    /* sbin first: where `make install` puts it. */
    rs_buf_addstr(out, "r=; for p in");
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
    {
        rs_buf_addc(out, ' ');
        rs_shell_word(out, prefix);
        rs_buf_addf(out, "%s/restate", dirs[i]);
    }
    rs_buf_addstr(out, "; do [ -x \"$p\" ] && r=$p && break; done; "
                       "if [ -n \"$r\" ]; then \"$r\" restore --root ");
    rs_shell_word(out, dest);
    if (fstab)
    {
        rs_buf_addstr(out, " --exclude /etc/fstab --exclude /etc/crypttab");
    }
    if (trust && *trust)
    {
        rs_buf_addf(out, " %s", trust);
    }
    if (as)
    {
        rs_buf_addstr(out, " --as ");
        rs_shell_word(out, as);
        rs_buf_addstr(out, " --exclude /etc/netplan");
    }
    rs_buf_addc(out, ' ');
    rs_shell_word(out, image);
    if (as)
    {
        rs_buf_addstr(out, " || [ \"$?\" -eq 3 ]; else echo 'restate: no restate in the image to "
                           "restore with, and a copy needs restate restore --as' >&2; exit 1; fi");
        return;
    }
    rs_buf_addstr(out, " || [ \"$?\" -eq 3 ]; else echo 'restate: no restate in the image to "
                       "restore with; tar instead, owners by number' >&2; ");
    rs_image_part_command(out, image, RS_IMAGE_FILES_PART, dest,
                          fstab ? "--exclude=restate/files/etc/fstab "
                                  "--exclude=restate/files/etc/crypttab"
                                : NULL);
    rs_buf_addstr(out, "; fi");
}

/* ------------------------------------------------------------------------- */
/* Reading                                                                   */
/* ------------------------------------------------------------------------- */

static ssize_t read_fd(void *ctx, void *data, size_t n)
{
    return read(*(int *)ctx, data, n);
}

static bool slurp(int fd, struct rs_buf *out, const char *name, struct rs_buf *err)
{
    char chunk[65536];

    rs_buf_add(out, "", 0);
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            rs_buf_addf(err, "%s: %s", name, strerror(errno));
            return false;
        }
        if (n == 0)
        {
            return true;
        }
        if (out->len + (size_t)n > RS_IMAGE_INDEX_MAX)
        {
            rs_buf_addf(err, "%s: larger than any index restate writes", name);
            return false;
        }
        rs_buf_add(out, chunk, (size_t)n);
    }
}

static bool index_from_image(int fd, const char *path, bool sealed, struct rs_buf *text,
                             struct rs_buf *err)
{
    struct rs_gzip gz;
    struct rs_pgp  pg;
    struct rs_buf  name;
    struct rs_buf  terr;
    bool           ok;

    if (sealed && !rs_pgp_decrypt(fd, &pg, err))
    {
        return false;
    }
    ok = rs_gzip_decompress(sealed ? pg.fd : fd, &gz, err);
    if (sealed)
    {
        (void)close(pg.fd);
        pg.fd = -1;
    }
    if (!ok)
    {
        if (sealed)
        {
            (void)rs_pgp_finish(&pg, true, err);
        }
        return false;
    }
    rs_buf_init(&name);
    rs_buf_init(&terr);
    ok = rs_tar_read_first(read_fd, &gz.fd, RS_IMAGE_INDEX_MAX, &name, text, &terr);
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, terr.data);
    } else if (strcmp(name.data, RS_IMAGE_INDEX_NAME) != 0)
    {
        rs_buf_addf(err, "%s: not a restate image (it does not start with %s)", path,
                    RS_IMAGE_INDEX_NAME);
        ok = false;
    }
    /* Everything after the index is of no interest here. */
    (void)rs_gzip_finish(&gz, true, err);
    if (sealed)
    {
        struct rs_buf perr;

        rs_buf_init(&perr);
        /* Abandoned once the index is read. A gpg that could not decrypt (no
         * secret key, a wrong passphrase) leaves gzip nothing to read, and
         * gpg's failure is the message worth giving. */
        if (!rs_pgp_finish(&pg, ok, &perr) && !ok)
        {
            rs_buf_reset(err);
            rs_buf_addf(err, "%s: could not decrypt it (%s); is the secret key for it in "
                        "this user's GnuPG keyring?", path, perr.data);
        }
        rs_buf_free(&perr);
    }
    rs_buf_free(&name);
    rs_buf_free(&terr);
    return ok;
}

/*
 * The index of an image in parts: the first member of the outer archive,
 * read as it is -- a few megabytes of gzip -- and only then given to gzip
 * (and gpg), from a temporary file, so neither ever sees the rest.
 */
static bool index_from_parts(int fd, const char *path, struct rs_buf *text,
                             char digest[RS_SHA256_HEX_SIZE], struct rs_buf *err)
{
    struct rs_buf  name;
    struct rs_buf  packed;
    struct rs_buf  terr;
    struct rs_gzip gz;
    struct rs_pgp  pg;
    FILE          *tmp = NULL;
    bool           sealed = false;
    bool           ok;

    rs_buf_init(&name);
    rs_buf_init(&packed);
    rs_buf_init(&terr);
    memset(&pg, 0, sizeof(pg));
    pg.fd = -1;
    ok = rs_tar_read_first(read_fd, &fd, RS_IMAGE_INDEX_MAX, &name, &packed, &terr);
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, terr.data);
    } else if (strcmp(name.data, RS_IMAGE_INDEX_PART ".gpg") == 0)
    {
        sealed = true;
    } else if (strcmp(name.data, RS_IMAGE_INDEX_PART) != 0)
    {
        rs_buf_addf(err, "%s: not a restate image (it does not start with %s)", path,
                    RS_IMAGE_INDEX_PART);
        ok = false;
    }
    if (ok)
    {
        /* What a signature over the index covers, so a check of it can be
         * matched with what was read here. */
        rs_sha256_hex(packed.len > 0 ? packed.data : "", packed.len, digest);
        tmp = tmpfile();
        ok = tmp && (packed.len == 0 || fwrite(packed.data, 1, packed.len, tmp) == packed.len) &&
             fflush(tmp) == 0 && lseek(fileno(tmp), 0, SEEK_SET) == 0;
        if (!ok)
        {
            rs_buf_addf(err, "%s: a temporary file for its index: %s", path, strerror(errno));
        }
    }
    if (ok && sealed)
    {
        ok = rs_pgp_decrypt(fileno(tmp), &pg, err);
    }
    if (ok)
    {
        ok = rs_gzip_decompress(sealed ? pg.fd : fileno(tmp), &gz, err);
        if (sealed)
        {
            (void)close(pg.fd);
            pg.fd = -1;
        }
        if (ok)
        {
            bool read_ok = slurp(gz.fd, text, path, err);

            ok = rs_gzip_finish(&gz, !read_ok, err) && read_ok;
        }
    }
    if (sealed && pg.pid > 0)
    {
        struct rs_buf perr;

        rs_buf_init(&perr);
        if (!rs_pgp_finish(&pg, false, &perr))
        {
            rs_buf_reset(err);
            rs_buf_addf(err, "%s: could not decrypt it (%s); is the secret key for it in "
                        "this user's GnuPG keyring?", path, perr.data);
            ok = false;
        }
        rs_buf_free(&perr);
    }
    if (tmp)
    {
        (void)fclose(tmp);
    }
    rs_buf_free(&name);
    rs_buf_free(&packed);
    rs_buf_free(&terr);
    return ok;
}

/*
 * A snapshot in a repository, opened as an image's part is: its files, or
 * only its kit. 1 if it is open, 0 if `path` names no snapshot, -1 if it
 * does and it could not be opened. The repository is held open, shared,
 * until the stream is closed, so a prune does not remove what it reads.
 */
static int open_snapshot(const char *path, const char *part, struct rs_image_stream *s,
                         struct rs_buf *err)
{
    char  *dir;
    char  *name;
    char  *found = NULL;
    char **kit = NULL;
    size_t nkit = 0;
    bool   kit_only = strcmp(part, RS_IMAGE_KIT_PART) == 0;
    bool   busy;
    bool   ok;

    if (!rs_repo_ref(path, &dir, &name))
    {
        return 0;
    }
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->image_fd = -1;
    s->feed = -1;
    s->pg.fd = -1;
    s->repo = rs_repo_open(dir, RS_REPO_READ, &busy, err);
    ok = s->repo != NULL;
    if (ok)
    {
        found = rs_repo_resolve(s->repo, name, err);
        ok = found != NULL;
    }
    if (ok)
    {
        s->snapshot_ix = rs_xcalloc(1, sizeof(*s->snapshot_ix));
        rs_index_init(s->snapshot_ix);
        ok = rs_repo_load_index(s->repo, found, s->snapshot_ix, err);
    }
    if (ok && kit_only)
    {
        ok = rs_repo_kit(s->repo, found, &kit, &nkit, err);
    }
    if (ok)
    {
        s->snapshot = rs_repo_stream_open(s->repo, s->snapshot_ix,
                                          kit_only ? (const char *const *)(kit ? kit : &found)
                                                   : NULL,
                                          nkit, err);
        ok = s->snapshot != NULL;
    }
    rs_repo_free_names(kit, nkit);
    free(found);
    free(dir);
    free(name);
    if (!ok)
    {
        (void)rs_image_close_files(s, true, err);
        return -1;
    }
    return 1;
}

/* One part of an image in parts, `part` (RS_IMAGE_KIT_PART or
 * RS_IMAGE_FILES_PART); for an image from before 1.1, which has no parts,
 * the files are the one stream and there is no kit. */
static bool open_part(const char *path, const char *part, struct rs_image_stream *s,
                      struct rs_buf *err)
{
    unsigned char magic[RS_TAR_BLOCK];
    ssize_t       got;
    int           in = -1;
    int           snapshot = open_snapshot(path, part, s, err);

    if (snapshot != 0)
    {
        return snapshot > 0;
    }
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    s->pg.fd = -1;
    s->feed = -1;
    s->image_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (s->image_fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    got = pread(s->image_fd, magic, sizeof(magic), 0);
    if (got == (ssize_t)sizeof(magic) && memcmp(magic + 257, "ustar", 5) == 0)
    {
        /* In parts: find the files part, skipping past the others. */
        struct rs_tar_reader r;
        struct rs_tar_entry  e;
        int                  more;

        rs_tar_reader_init(&r, read_fd, &s->image_fd);
        rs_tar_entry_init(&e);
        while ((more = rs_tar_next(&r, &e, err)) == 1)
        {
            if (strcmp(e.name.data, part) == 0 ||
                (strncmp(e.name.data, part, strlen(part)) == 0 &&
                 strcmp(e.name.data + strlen(part), ".gpg") == 0))
            {
                off_t at = lseek(s->image_fd, 0, SEEK_CUR);
                int   p[2];

                s->sealed = strcmp(e.name.data, part) != 0;
                if (at >= 0 && pipe(p) == 0)
                {
                    /* Our end never blocks, and never reaches gzip or gpg. */
                    (void)fcntl(p[1], F_SETFD, FD_CLOEXEC);
                    (void)fcntl(p[1], F_SETFL, O_NONBLOCK);
                    (void)fcntl(p[0], F_SETFD, FD_CLOEXEC);
                    in = p[0];
                    s->feed = p[1];
                    s->feed_at = (uint64_t)at;
                    s->feed_left = e.size;
                    if (s->feed_left == 0)
                    {
                        (void)close(s->feed);
                        s->feed = -1;
                    }
                } else
                {
                    rs_buf_addf(err, "%s: %s", path, strerror(errno));
                }
                break;
            }
            if (lseek(s->image_fd, (off_t)(r.left + r.pad), SEEK_CUR) < 0)
            {
                rs_buf_addf(err, "%s: %s", path, strerror(errno));
                more = -1;
                break;
            }
            r.left = 0;
            r.pad = 0;
        }
        rs_tar_entry_free(&e);
        if (more == 0)
        {
            rs_buf_addf(err, "%s: there is no %s in it", path, part);
        }
        if (in < 0)
        {
            if (more < 0 && err->len)
            {
                char *why = rs_xstrdup(err->data);

                rs_buf_reset(err);
                rs_buf_addf(err, "%s: %s", path, why);
                free(why);
            }
            (void)rs_image_close_files(s, true, err);
            return false;
        }
    } else if (strcmp(part, RS_IMAGE_FILES_PART) != 0)
    {
        rs_buf_addf(err, "%s: an image from before restate 1.1 has no %s", path, part);
        (void)rs_image_close_files(s, true, err);
        return false;
    } else
    {
        /* From before 1.1: one gzip'd stream, which may be encrypted whole. */
        s->sealed = got > 0 && rs_pgp_detect(magic, (size_t)got);
        in = dup(s->image_fd);
        if (in < 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            (void)rs_image_close_files(s, true, err);
            return false;
        }
    }
    if (s->sealed && !rs_pgp_decrypt(in, &s->pg, err))
    {
        (void)close(in);
        (void)rs_image_close_files(s, true, err);
        return false;
    }
    if (!rs_gzip_decompress(s->sealed ? s->pg.fd : in, &s->gz, err))
    {
        (void)close(in);
        (void)rs_image_close_files(s, true, err);
        return false;
    }
    (void)close(in);
    if (s->sealed)
    {
        (void)close(s->pg.fd);
        s->pg.fd = -1;
    }
    s->fd = s->gz.fd;
    return true;
}

/* Writes what it can of the part into the pipe, without blocking. */
static void feed_some(struct rs_image_stream *s)
{
    if (s->chunk_pos == s->chunk_len)
    {
        size_t  want = s->feed_left < sizeof(s->chunk) ? (size_t)s->feed_left : sizeof(s->chunk);
        ssize_t n = pread(s->image_fd, s->chunk, want, (off_t)s->feed_at);

        if (n <= 0)
        {
            if (n < 0 && errno == EINTR)
            {
                return;
            }
            s->feed_failed = true;   /* the image is shorter than its part */
            (void)close(s->feed);
            s->feed = -1;
            return;
        }
        s->chunk_len = (size_t)n;
        s->chunk_pos = 0;
    }
    {
        ssize_t w = write(s->feed, s->chunk + s->chunk_pos, s->chunk_len - s->chunk_pos);

        if (w < 0)
        {
            if (errno != EAGAIN && errno != EINTR)
            {
                /* gzip or gpg has gone: what it said comes out of close. */
                s->feed_failed = true;
                (void)close(s->feed);
                s->feed = -1;
            }
            return;
        }
        s->chunk_pos += (size_t)w;
        if (s->chunk_pos == s->chunk_len)
        {
            s->feed_at += s->chunk_len;
            s->feed_left -= s->chunk_len;
            s->chunk_pos = 0;
            s->chunk_len = 0;
            if (s->feed_left == 0)
            {
                (void)close(s->feed);
                s->feed = -1;
            }
        }
    }
}

bool rs_image_open_files(const char *path, struct rs_image_stream *s, struct rs_buf *err)
{
    return open_part(path, RS_IMAGE_FILES_PART, s, err);
}

bool rs_image_open_kit(const char *path, struct rs_image_stream *s, struct rs_buf *err)
{
    return open_part(path, RS_IMAGE_KIT_PART, s, err);
}

ssize_t rs_image_read_files(struct rs_image_stream *s, void *buf, size_t n)
{
    if (s->snapshot)
    {
        return rs_repo_stream_read(s->snapshot, buf, n);
    }
    for (;;)
    {
        struct pollfd fds[2];
        nfds_t        nfds = 1;

        fds[0].fd = s->fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        if (s->feed >= 0)
        {
            fds[1].fd = s->feed;
            fds[1].events = POLLOUT;
            fds[1].revents = 0;
            nfds = 2;
        }
        if (poll(fds, nfds, -1) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (fds[0].revents != 0)
        {
            ssize_t r = read(s->fd, buf, n);

            if (r < 0 && (errno == EINTR || errno == EAGAIN))
            {
                continue;
            }
            return r;
        }
        if (nfds == 2 && fds[1].revents != 0)
        {
            feed_some(s);
        }
    }
}

bool rs_image_close_files(struct rs_image_stream *s, bool abandon, struct rs_buf *err)
{
    bool ok = true;

    if (s->repo)
    {
        ok = rs_repo_stream_close(s->snapshot, err);
        if (s->snapshot_ix)
        {
            rs_index_free(s->snapshot_ix);
            free(s->snapshot_ix);
        }
        rs_repo_close(s->repo);
        s->repo = NULL;
        s->snapshot = NULL;
        s->snapshot_ix = NULL;
        return ok;
    }

    if (!abandon && s->fd >= 0)
    {
        unsigned char rest[8192];

        /* A tar archive may run on past its end-of-archive blocks -- a tar
         * pads to its record size, and some to far more than a pipe holds.
         * Read to gzip's end, so it is not killed writing what nobody
         * reads. */
        while (rs_image_read_files(s, rest, sizeof(rest)) > 0)
        {
        }
    }
    if (s->feed >= 0)
    {
        (void)close(s->feed);
        s->feed = -1;
    }
    if (s->fd >= 0)
    {
        if (!rs_gzip_finish(&s->gz, abandon, err))
        {
            ok = false;
        }
        s->fd = -1;
    }
    if (s->sealed && s->pg.pid > 0)
    {
        if (!rs_pgp_finish(&s->pg, abandon, err))
        {
            ok = false;
        }
        s->pg.pid = 0;
    }
    if (!abandon && (s->feed_failed || s->feed_left > 0))
    {
        rs_buf_addstr(err, "the image's files part could not be read to its end");
        ok = false;
    }
    if (s->image_fd >= 0)
    {
        (void)close(s->image_fd);
        s->image_fd = -1;
    }
    return ok;
}

/* The repository and snapshot `path` names, opened to look at: 1 if it is
 * one, 0 if it is not, -1 with the reason in `err` if it is and it cannot
 * be opened or has no such snapshot. */
static int open_ref(const char *path, struct rs_repo **r, char **found, struct rs_buf *err)
{
    char *dir;
    char *name;
    bool  busy;

    *r = NULL;
    *found = NULL;
    if (!rs_repo_ref(path, &dir, &name))
    {
        return 0;
    }
    *r = rs_repo_open(dir, RS_REPO_LOOK, &busy, err);
    if (*r)
    {
        *found = rs_repo_resolve(*r, name, err);
    }
    free(dir);
    free(name);
    if (!*found)
    {
        rs_repo_close(*r);
        *r = NULL;
        return -1;
    }
    return 1;
}

bool rs_index_load(struct rs_index *ix, const char *path, struct rs_buf *err)
{
    struct rs_buf   text;
    bool            is_stdin = strcmp(path, "-") == 0;
    const char     *name = is_stdin ? "(standard input)" : path;
    struct rs_repo *repo;
    char           *found;
    int             fd;
    bool            ok;

    if (!is_stdin)
    {
        int snapshot = open_ref(path, &repo, &found, err);

        if (snapshot != 0)
        {
            ok = snapshot > 0 && rs_repo_load_index(repo, found, ix, err);
            free(found);
            rs_repo_close(repo);
            return ok;
        }
    }
    rs_buf_init(&text);
    fd = is_stdin ? STDIN_FILENO : open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    if (!is_stdin)
    {
        unsigned char magic[RS_TAR_BLOCK];
        ssize_t       got = pread(fd, magic, sizeof(magic), 0);
        bool          sealed = got > 0 && rs_pgp_detect(magic, (size_t)got);

        /* An image in parts: a tar archive, "ustar" at 257 of its first block. */
        if (got == (ssize_t)sizeof(magic) && memcmp(magic + 257, "ustar", 5) == 0)
        {
            ok = index_from_parts(fd, path, &text, ix->part_sha256, err);
            (void)close(fd);
            ok = ok && rs_index_parse(ix, text.data, text.len, name, err);
            ix->in_parts = ok;
            rs_buf_free(&text);
            return ok;
        }
        if (sealed || (got >= 2 && magic[0] == 0x1f && magic[1] == 0x8b))
        {
            ok = index_from_image(fd, path, sealed, &text, err);
            (void)close(fd);
            ok = ok && rs_index_parse(ix, text.data, text.len, name, err);
            rs_buf_free(&text);
            return ok;
        }
    }
    ok = slurp(fd, &text, name, err);
    if (!is_stdin)
    {
        (void)close(fd);
    }
    if (ok && ((text.len >= 2 && (unsigned char)text.data[0] == 0x1f &&
                (unsigned char)text.data[1] == 0x8b) ||
               (text.len >= RS_TAR_BLOCK && memcmp(text.data + 257, "ustar", 5) == 0)))
    {
        rs_buf_addf(err, "%s: an image cannot be read from standard input; "
                    "name the file instead", name);
        ok = false;
    }
    ok = ok && rs_index_parse(ix, text.data, text.len, name, err);
    rs_buf_free(&text);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Signatures                                                                */
/* ------------------------------------------------------------------------- */

/* A signature is a few hundred bytes; anything this large is not one. */
#define SIG_MAX ((size_t)64 * 1024)

/* Reads the current member's data, all of it, into `out`, up to `max`. */
static bool member_data(struct rs_tar_reader *r, size_t max, struct rs_buf *out,
                        struct rs_buf *err)
{
    char    chunk[65536];
    ssize_t n;

    if (r->left > max)
    {
        rs_buf_addstr(err, "larger than restate writes");
        return false;
    }
    while ((n = rs_tar_read(r, chunk, sizeof(chunk), err)) > 0)
    {
        rs_buf_add(out, chunk, (size_t)n);
    }
    return n == 0;
}

/*
 * Walks the members of the image in parts open on `fd`: the first, which
 * must be the index part, read into `index_part`; the signature, if there is
 * one, into `sig`. Where the archive's members end is put in *end, which is
 * where another goes.
 */
static bool walk_parts(int fd, const char *path, struct rs_buf *index_part, struct rs_buf *sig,
                       off_t *end, struct rs_buf *err)
{
    unsigned char        magic[RS_TAR_BLOCK];
    struct rs_tar_reader r;
    struct rs_tar_entry  e;
    struct rs_buf        why;
    size_t               k = 0;
    int                  more;
    bool                 ok = true;

    if (pread(fd, magic, sizeof(magic), 0) != (ssize_t)sizeof(magic) ||
        memcmp(magic + 257, "ustar", 5) != 0)
    {
        rs_buf_addf(err, "%s: not an image in parts (a bare index, or an image from before "
                    "restate 1.1), which has nowhere for a signature", path);
        return false;
    }
    rs_buf_init(&why);
    rs_tar_reader_init(&r, read_fd, &fd);
    rs_tar_entry_init(&e);
    *end = 0;
    while (ok && (more = rs_tar_next(&r, &e, &why)) == 1)
    {
        const char *name = e.name.data;

        if (k++ == 0)
        {
            if (strcmp(name, RS_IMAGE_INDEX_PART) != 0 &&
                strcmp(name, RS_IMAGE_INDEX_PART ".gpg") != 0)
            {
                rs_buf_addf(err, "%s: not a restate image (it does not start with %s)", path,
                            RS_IMAGE_INDEX_PART);
                ok = false;
            } else if (!member_data(&r, RS_IMAGE_INDEX_MAX, index_part, &why))
            {
                rs_buf_addf(err, "%s: its index: %s", path, why.data);
                ok = false;
            }
        } else if (strcmp(name, RS_IMAGE_SIG_PART) == 0)
        {
            rs_buf_reset(sig);
            if (!member_data(&r, SIG_MAX, sig, &why))
            {
                rs_buf_addf(err, "%s: its signature: %s", path, why.data);
                ok = false;
            }
        } else if (lseek(fd, (off_t)(r.left + r.pad), SEEK_CUR) < 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            ok = false;
        } else
        {
            r.left = 0;
            r.pad = 0;
        }
        if (ok && r.left == 0)
        {
            /* Past this member's data and its padding. */
            off_t at = lseek(fd, 0, SEEK_CUR);

            *end = at < 0 ? 0 : at + (off_t)r.pad;
        }
    }
    if (ok && more < 0)
    {
        rs_buf_addf(err, "%s: %s", path, why.data);
        ok = false;
    }
    rs_tar_entry_free(&e);
    rs_buf_free(&why);
    return ok;
}

bool rs_image_signed_bytes(const char *path, struct rs_buf *index_part, struct rs_buf *sig,
                           struct rs_buf *err)
{
    struct rs_repo *repo;
    char           *found;
    int             snapshot = open_ref(path, &repo, &found, err);
    int             fd;
    off_t           end;
    bool            ok;

    if (snapshot != 0)
    {
        ok = snapshot > 0 && rs_repo_index_bytes(repo, found, index_part, sig, err);
        free(found);
        rs_repo_close(repo);
        return ok;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    ok = walk_parts(fd, path, index_part, sig, &end, err);
    (void)close(fd);
    return ok;
}

bool rs_image_add_signature(const char *path, const void *sig, size_t len, struct rs_buf *err)
{
    struct rs_buf   index_part;
    struct rs_buf   old;
    struct rs_time  mtime;
    struct rs_repo *repo;
    char           *found;
    off_t           end = 0;
    int             snapshot = open_ref(path, &repo, &found, err);
    int             fd;
    bool            ok;

    if (snapshot != 0)
    {
        ok = snapshot > 0 && rs_repo_add_signature(repo, found, sig, len, err);
        free(found);
        rs_repo_close(repo);
        return ok;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    rs_buf_init(&index_part);
    rs_buf_init(&old);
    ok = walk_parts(fd, path, &index_part, &old, &end, err);
    if (ok && old.len > 0)
    {
        rs_buf_addf(err, "%s: it is signed already", path);
        ok = false;
    }
    memset(&mtime, 0, sizeof(mtime));
    mtime.sec = (int64_t)time(NULL);
    mtime.set = true;
    /* Over the end-of-archive blocks: the signature, then a new end. */
    ok = ok && end > 0 && lseek(fd, end, SEEK_SET) == end &&
         write_member(fd, RS_IMAGE_SIG_PART, sig, len, &mtime) && tar_end(fd) && fsync(fd) == 0;
    if (!ok && err->len == 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
    }
    if (close(fd) != 0 && ok)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        ok = false;
    }
    rs_buf_free(&index_part);
    rs_buf_free(&old);
    return ok;
}

bool rs_image_trusted(const char *path, const char *const *trusted, size_t n,
                      struct rs_pgp_signer *signer, char digest[RS_SHA256_HEX_SIZE],
                      struct rs_buf *why)
{
    struct rs_buf index_part;
    struct rs_buf sig;
    struct rs_buf status;
    char         *home;
    char        **rings;
    size_t        nrings = 0;
    size_t        i;
    bool          ok;

    memset(signer, 0, sizeof(*signer));
    digest[0] = '\0';
    rs_buf_init(&index_part);
    rs_buf_init(&sig);
    if (!rs_image_signed_bytes(path, &index_part, &sig, why))
    {
        rs_buf_reset(why);
        rs_buf_addstr(why, "it is not signed");
        rs_buf_free(&index_part);
        return false;
    }
    rs_sha256_hex(index_part.data ? index_part.data : "", index_part.len, digest);
    if (sig.len == 0)
    {
        rs_buf_addstr(why, "it is not signed");
        rs_buf_free(&index_part);
        return false;
    }
    home = rs_pgp_home(why);
    if (!home)
    {
        rs_buf_free(&index_part);
        rs_buf_free(&sig);
        return false;
    }
    rings = rs_xcalloc(n + 1, sizeof(*rings));
    {
        char *data = rs_xasprintf("%s/index", home);
        char *sigfile = rs_xasprintf("%s/index.sig", home);
        int   fd = open(data, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        int   sfd = open(sigfile, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

        ok = fd >= 0 && sfd >= 0 && write_all(fd, index_part.data, index_part.len) &&
             write_all(sfd, sig.data, sig.len);
        if (fd >= 0)
        {
            (void)close(fd);
        }
        if (sfd >= 0)
        {
            (void)close(sfd);
        }
        if (!ok)
        {
            rs_buf_addf(why, "%s: %s", home, strerror(errno));
        }
        for (i = 0; ok && i < n; i++)
        {
            rings[nrings] = rs_xasprintf("%s/trusted%zu.gpg", home, i);
            ok = rs_pgp_keyring(trusted[i], rings[nrings], why);
            nrings++;
        }
        rs_buf_init(&status);
        ok = ok && rs_pgp_gpgv(home, (const char *const *)rings, nrings, sigfile, data, &status,
                               why);
        ok = ok && rs_pgp_verdict(status.data ? status.data : "", signer, why);
        rs_buf_free(&status);
        free(data);
        free(sigfile);
    }
    for (i = 0; i < nrings; i++)
    {
        free(rings[i]);
    }
    free(rings);
    rs_pgp_home_remove(home);
    rs_buf_free(&index_part);
    rs_buf_free(&sig);
    return ok;
}

bool rs_image_knows_trust(const char *version)
{
    /* Signing came after 1.2.0.1: anything later, its -dev builds too.
     * Every release is numbered; a version that is not is a build of no
     * release, made from code newer than all of them. */
    static const unsigned long first[4] = { 1, 2, 0, 2 };
    const char                *p = version ? version : "";
    size_t                     i;

    for (i = 0; i < 4; i++)
    {
        char         *end;
        unsigned long v = strtoul(p, &end, 10);

        if (end == p)
        {
            return i == 0 && version && version[0] != '\0';
        }
        if (v != first[i])
        {
            return v > first[i];
        }
        p = end + (*end == '.' ? 1 : 0);
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* Exporting a snapshot                                                      */
/* ------------------------------------------------------------------------- */

static ssize_t read_stream(void *ctx, void *data, size_t n)
{
    return rs_image_read_files(ctx, data, n);
}

struct from_tar {
    struct rs_tar_reader *r;
    struct rs_buf        *err;
};

/* A member's data, from the snapshot's stream into the image, checked against
 * the index's digest on the way. */
static bool copy_from_tar(struct rs_image_writer *iw, struct rs_entry *e, uint64_t size,
                          const void *ctx)
{
    const struct from_tar *ft = ctx;
    unsigned char          chunk[65536];
    struct rs_sha256       sha;
    char                   hex[RS_SHA256_HEX_SIZE];
    uint64_t               copied = 0;
    ssize_t                n;

    rs_sha256_init(&sha);
    while ((n = rs_tar_read(ft->r, chunk, sizeof(chunk), ft->err)) > 0)
    {
        rs_sha256_update(&sha, chunk, (size_t)n);
        rs_progress_bytes((uint64_t)n);
        if (!rs_tar_data(&iw->tar, chunk, (size_t)n))
        {
            rs_buf_addf(ft->err, "writing the image beside %s: %s", iw->dest, strerror(errno));
            return false;
        }
        copied += (uint64_t)n;
    }
    rs_sha256_final(&sha, hex);
    if (n < 0 || copied != size)
    {
        if (ft->err->len == 0)
        {
            rs_buf_addf(ft->err, "%s: the repository's copy of it is cut short", e->path);
        }
        return false;
    }
    if (e->hash_state == RS_HASH_PRESENT && strcmp(hex, e->hash) != 0)
    {
        rs_buf_addf(ft->err, "%s: its content in the repository is not what the index says it is",
                    e->path);
        return false;
    }
    return rs_tar_pad(&iw->tar);
}

bool rs_image_export(const char *ref, struct rs_index *ix, struct rs_image_writer *iw,
                     struct rs_buf *err)
{
    static const char      prefix[] = RS_IMAGE_FILES_DIR "/";
    struct rs_image_stream s;
    struct rs_tar_reader   r;
    struct rs_tar_entry    m;
    struct from_tar        ft;
    struct rs_repo        *repo;
    char                  *found;
    char                 **kit = NULL;
    size_t                 nkit = 0;
    size_t                 missing = 0;
    size_t                 i;
    bool                  *seen;
    int                    more = 0;
    bool                   ok;

    if (open_ref(ref, &repo, &found, err) <= 0)
    {
        if (err->len == 0)
        {
            rs_buf_addf(err, "%s: not a snapshot in a repository", ref);
        }
        rs_image_abort(iw);
        return false;
    }
    ok = rs_repo_kit(repo, found, &kit, &nkit, err);
    free(found);
    rs_repo_close(repo);
    if (!ok || !rs_image_open_files(ref, &s, err))
    {
        rs_repo_free_names(kit, nkit);
        rs_image_abort(iw);
        return false;
    }
    iw->kit = (const char *const *)kit;
    iw->nkit = nkit;
    seen = rs_xcalloc(ix->count + 1, sizeof(*seen));
    ft.r = &r;
    ft.err = err;
    rs_tar_reader_init(&r, read_stream, &s);
    rs_tar_entry_init(&m);
    while (ok && (more = rs_tar_next(&r, &m, err)) == 1)
    {
        const char            *path = NULL;
        const struct rs_entry *e;

        while (m.name.len > 1 && m.name.data[m.name.len - 1] == '/')
        {
            m.name.data[--m.name.len] = '\0';
        }
        if (strcmp(m.name.data, RS_IMAGE_FILES_DIR) == 0)
        {
            path = "/";
        } else if (strncmp(m.name.data, prefix, sizeof(prefix) - 1) == 0)
        {
            path = m.name.data + sizeof(prefix) - 2;
        }
        e = path && rs_path_is_clean(path) ? rs_index_find(ix, path) : NULL;
        if (!e || !e->stored || strcmp(e->stored, m.name.data) != 0)
        {
            rs_buf_addf(err, "%s: the snapshot changed while it was being exported", ref);
            ok = false;
            break;
        }
        i = (size_t)(e - ix->entries);
        if (!seen[i])
        {
            seen[i] = true;
            ok = store_member(iw, &ix->entries[i], m.size, copy_from_tar, &ft, err);
        }
    }
    if (ok && more < 0)
    {
        ok = false;
    }
    rs_tar_entry_free(&m);
    if (!rs_image_close_files(&s, !ok, err))
    {
        ok = false;
    }
    for (i = 0; ok && i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];

        if (e->stored && e->type != 'c' && e->type != 'b' && !seen[i])
        {
            missing++;
        }
    }
    if (missing > 0)
    {
        rs_buf_addf(err, "%s: %zu files the snapshot keeps are not in the repository", ref,
                    missing);
        ok = false;
    }
    free(seen);
    if (ok)
    {
        ok = rs_image_finish(iw, ix, err);
    } else
    {
        rs_image_abort(iw);
    }
    rs_repo_free_names(kit, nkit);
    return ok;
}
