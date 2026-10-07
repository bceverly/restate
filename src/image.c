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

bool rs_image_begin(struct rs_image_writer *iw, const char *dest, struct rs_buf *err)
{
    char *tmp = NULL;

    memset(iw, 0, sizeof(*iw));
    iw->content_fd = temp_beside(dest, &tmp, err);
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

/* Whether `path` goes into the kit too: one of iw->kit, or beneath one that
 * ends in a slash. */
static bool in_kit(const struct rs_image_writer *iw, const char *path)
{
    size_t i;

    for (i = 0; i < iw->nkit; i++)
    {
        const char *k = iw->kit[i];
        size_t      n = strlen(k);

        if (n > 0 && k[n - 1] == '/' ? strncmp(path, k, n) == 0 : strcmp(path, k) == 0)
        {
            return true;
        }
    }
    return false;
}

/* "/etc/hosts" -> "restate/files/etc/hosts"; "/" -> "restate/files". */
static char *member_name(const char *path)
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
static bool copy_file(struct rs_image_writer *iw, struct rs_entry *e, int fd, uint64_t size)
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
        if (!rs_tar_data(&iw->tar, chunk, (size_t)n))
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

        if (!rs_tar_data(&iw->tar, zero, take))
        {
            return false;
        }
        copied += take;
    }
    rs_sha256_final(&ctx, e->hash);
    e->hash_state = (e->copy == RS_COPY_OK || e->copy == RS_COPY_GREW) ? RS_HASH_PRESENT
                                                                       : RS_HASH_UNREADABLE;
    return rs_tar_pad(&iw->tar);
}

bool rs_image_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                    struct rs_buf *err)
{
    struct rs_image_writer *iw = ctx;
    struct rs_tar_member    m;
    char                   *name;
    uint64_t                start;
    bool                    ok;

    memset(&m, 0, sizeof(m));
    switch (e->type)
    {
    case 'f':
        m.typeflag = '0';
        m.size = (uint64_t)st->st_size;
        break;
    case 'd':
        m.typeflag = '5';
        break;
    case 'l':
        m.typeflag = '2';
        m.linkname = e->target;
        break;
    case 'p':
        m.typeflag = '6';
        break;
    default:
        /* Device nodes are recorded in the index and recreated from it, not
         * archived: a tar device member is not portable between systems. */
        return true;
    }
    name = member_name(e->path);
    m.name = name;
    start = iw->tar.offset;
    m.mode = e->mode;
    m.uid = e->uid;
    m.gid = e->gid;
    m.uname = e->user;
    m.gname = e->group;
    m.mtime = e->mtime;
    m.atime = e->atime;

    ok = rs_tar_header(&iw->tar, &m);
    if (ok && e->type == 'f')
    {
        ok = copy_file(iw, e, fd, m.size);
    }
    if (!ok)
    {
        rs_buf_addf(err, "writing the image beside %s: %s", iw->dest, strerror(errno));
        free(name);
        return false;
    }
    e->stored = name;
    if (in_kit(iw, e->path))
    {
        iw->spans = rs_xreallocarray(iw->spans, iw->nspans + 1, sizeof(*iw->spans));
        iw->spans[iw->nspans].offset = start;
        iw->spans[iw->nspans].length = iw->tar.offset - start;
        iw->nspans++;
    }
    return true;
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
                       struct rs_buf *err)
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

bool rs_image_finish(struct rs_image_writer *iw, const struct rs_index *ix,
                     struct rs_buf *err)
{
    struct sigaction ignore;
    struct sigaction saved;
    struct rs_time   mtime;
    struct part      parts[3];
    char            *tmp = NULL;
    char            *text;
    size_t           len = 0;
    size_t           i;
    int              out;
    bool             ok = true;

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
        parts[i].iw = iw;
        ok = write_part(&parts[i], out, &mtime, err);
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
                              bool fstab)
{
    const char *prefix = strcmp(dest, "/") == 0 ? "" : dest;

    rs_buf_addstr(out, "r=; for p in ");
    rs_shell_word(out, prefix);
    rs_buf_addstr(out, "/usr/local/bin/restate ");
    rs_shell_word(out, prefix);
    rs_buf_addstr(out, "/usr/bin/restate; do [ -x \"$p\" ] && r=$p && break; done; "
                       "if [ -n \"$r\" ]; then \"$r\" restore --root ");
    rs_shell_word(out, dest);
    if (fstab)
    {
        rs_buf_addstr(out, " --exclude /etc/fstab --exclude /etc/crypttab");
    }
    rs_buf_addc(out, ' ');
    rs_shell_word(out, image);
    rs_buf_addstr(out, " || [ \"$?\" -eq 3 ]; else ");
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
static bool index_from_parts(int fd, const char *path, struct rs_buf *text, struct rs_buf *err)
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

/* One part of an image in parts, `part` (RS_IMAGE_KIT_PART or
 * RS_IMAGE_FILES_PART); for an image from before 1.1, which has no parts,
 * the files are the one stream and there is no kit. */
static bool open_part(const char *path, const char *part, struct rs_image_stream *s,
                      struct rs_buf *err)
{
    unsigned char magic[RS_TAR_BLOCK];
    ssize_t       got;
    int           in = -1;

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

bool rs_index_load(struct rs_index *ix, const char *path, struct rs_buf *err)
{
    struct rs_buf text;
    bool          is_stdin = strcmp(path, "-") == 0;
    const char   *name = is_stdin ? "(standard input)" : path;
    int           fd;
    bool          ok;

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
            ok = index_from_parts(fd, path, &text, err);
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
