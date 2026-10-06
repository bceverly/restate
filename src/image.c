/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "image.h"

#include <errno.h>
#include <fcntl.h>
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

bool rs_image_finish(struct rs_image_writer *iw, const struct rs_index *ix,
                     struct rs_buf *err)
{
    struct rs_tar_member m;
    struct rs_tar_writer tw;
    struct rs_gzip       gz;
    struct rs_pgp        pg;
    bool                 sealed = false;
    struct sigaction     ignore;
    struct sigaction     saved;
    char                *tmp = NULL;
    char                *text;
    size_t               len = 0;
    int                  out;
    bool                 ok;

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

    /* A gzip that dies would otherwise kill restate with SIGPIPE on the next
     * write, before it could say why or remove the half-written file. */
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &ignore, &saved);

    /* Encrypted, gzip writes into gpg and gpg into the file; our copy of the
     * pipe into gpg is closed once gzip has its own, so gpg sees the end of
     * the data when gzip exits. */
    ok = true;
    memset(&pg, 0, sizeof(pg));
    pg.fd = -1;
    if (iw->nrecipients > 0)
    {
        ok = rs_pgp_encrypt(iw->recipients, iw->nrecipients, out, &pg, err);
        sealed = ok;
    }
    if (ok && !rs_gzip_parallel())
    {
        rs_warn("pigz is not installed, so the image is compressed on one core with gzip; "
                "installing pigz makes this several times faster");
    }
    ok = ok && rs_gzip_compress(sealed ? pg.fd : out, &gz, err);
    if (sealed && pg.fd >= 0)
    {
        (void)close(pg.fd);
        pg.fd = -1;
    }
    if (ok)
    {
        memset(&m, 0, sizeof(m));
        m.name = RS_IMAGE_INDEX_NAME;
        m.typeflag = '0';
        m.mode = 0600;
        m.uid = (uint64_t)geteuid();
        m.gid = (uint64_t)getegid();
        m.size = len;
        /* The index's own creation time, which honors SOURCE_DATE_EPOCH, so two
         * captures of an unchanged tree are the same bytes. */
        if (!ix->created || !rs_time_parse(ix->created, &m.mtime))
        {
            m.mtime.sec = (int64_t)time(NULL);
            m.mtime.set = true;
        }
        rs_tar_writer_init(&tw, tar_to_fd, &gz.fd);
        ok = rs_tar_header(&tw, &m) && rs_tar_data(&tw, text, len) && rs_tar_pad(&tw);
        if (!ok)
        {
            rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
        }
        if (ok)
        {
            struct stat staged;
            uint64_t    total = 0;

            /* The one step whose total is known: the content staged during
             * the walk, through gzip (and gpg) into the image. */
            if (fstat(iw->content_fd, &staged) == 0)
            {
                total = (uint64_t)staged.st_size;
            }
            rs_progress_phase("writing", total);
            ok = copy_content(iw->content_fd, gz.fd, err);
            rs_progress_done();
        }
        if (ok)
        {
            /* Every member in the content ends on a block boundary, so the
             * archive's end is just the two zero blocks. */
            ok = rs_tar_finish(&tw);
            if (!ok)
            {
                rs_buf_addf(err, "writing to gzip: %s", strerror(errno));
            }
        }
        if (!rs_gzip_finish(&gz, false, err))
        {
            ok = false;
        }
    }
    if (sealed && !rs_pgp_finish(&pg, false, err))
    {
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
        unsigned char magic[64];
        ssize_t       got = pread(fd, magic, sizeof(magic), 0);
        bool          sealed = got > 0 && rs_pgp_detect(magic, (size_t)got);

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
    if (ok && text.len >= 2 && (unsigned char)text.data[0] == 0x1f &&
        (unsigned char)text.data[1] == 0x8b)
    {
        rs_buf_addf(err, "%s: an image cannot be read from standard input; "
                    "name the file instead", name);
        ok = false;
    }
    ok = ok && rs_index_parse(ix, text.data, text.len, name, err);
    rs_buf_free(&text);
    return ok;
}
