/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "tar.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The ustar header, POSIX.1-1988, laid out as offsets into a 512-byte block. */
enum {
    H_NAME = 0,       /* 100 */
    H_MODE = 100,     /*   8 */
    H_UID = 108,      /*   8 */
    H_GID = 116,      /*   8 */
    H_SIZE = 124,     /*  12 */
    H_MTIME = 136,    /*  12 */
    H_CHKSUM = 148,   /*   8 */
    H_TYPE = 156,     /*   1 */
    H_LINK = 157,     /* 100 */
    H_MAGIC = 257,    /*   6 */
    H_VERSION = 263,  /*   2 */
    H_UNAME = 265,    /*  32 */
    H_GNAME = 297     /*  32 */
};

static const unsigned char zeros[RS_TAR_BLOCK];

void rs_tar_writer_init(struct rs_tar_writer *w, rs_tar_write_fn fn, void *ctx)
{
    w->write = fn;
    w->ctx = ctx;
    w->offset = 0;
}

static bool emit(struct rs_tar_writer *w, const void *data, size_t n)
{
    if (!w->write(w->ctx, data, n))
    {
        return false;
    }
    w->offset += n;
    return true;
}

/* `v` in octal, zero-padded and NUL-terminated, if it fits in `width`;
 * otherwise zero, and the pax header carries the real value. */
static void octal(unsigned char *field, size_t width, uint64_t v)
{
    uint64_t limit = (uint64_t)1 << (3 * (width - 1));
    size_t   i;

    if (v >= limit)
    {
        v = 0;
    }
    /* width - 1 zero-padded digits, written from the right, then a NUL. */
    field[width - 1] = '\0';
    for (i = width - 1; i > 0; i--)
    {
        field[i - 1] = (unsigned char)('0' + (v & 7u));
        v >>= 3;
    }
}

/* Copies `s` into a fixed field if it fits as plain ASCII; otherwise leaves
 * the field empty, and the pax header carries it. */
static void text(unsigned char *field, size_t width, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    size_t i;

    if (n >= width)
    {
        return;
    }
    for (i = 0; i < n; i++)
    {
        if ((unsigned char)s[i] >= 0x80)
        {
            return;
        }
    }
    if (s)
    {
        /* n < width, so the terminator fits too, and copying it says so. */
        memcpy(field, s, n + 1);
    }
}

static void checksum(unsigned char *h)
{
    unsigned sum = 0;
    size_t   i;

    memset(h + H_CHKSUM, ' ', 8);
    for (i = 0; i < RS_TAR_BLOCK; i++)
    {
        sum += h[i];
    }
    (void)snprintf((char *)h + H_CHKSUM, 8, "%06o", sum);
    h[H_CHKSUM + 7] = ' ';
}

void rs_tar_pax_record(struct rs_buf *out, const char *key, const char *value, size_t vlen)
{
    /* "LEN key=value\n": LEN is the length of the whole record including its
     * own digits, so guess the digits, and grow the guess until it holds. */
    size_t body = 1 + strlen(key) + 1 + vlen + 1;
    size_t digits = 1;
    size_t total;

    for (;;)
    {
        char   num[24];
        size_t got;

        total = digits + body;
        got = (size_t)snprintf(num, sizeof(num), "%zu", total);
        if (got == digits)
        {
            break;
        }
        digits = got;
    }
    rs_buf_addf(out, "%zu %s=", total, key);
    rs_buf_add(out, value, vlen);
    rs_buf_addc(out, '\n');
}

static void pax_time(struct rs_buf *out, const char *key, const struct rs_time *t)
{
    char v[48];

    if (!t->set)
    {
        return;
    }
    if (t->sec < 0 && t->nsec > 0)
    {
        /* -1.25 seconds is sec = -2, nsec = 750000000. */
        int64_t s = t->sec + 1;
        long    ns = 1000000000L - (long)t->nsec;

        (void)snprintf(v, sizeof(v), "%s%lld.%09ld", s == 0 ? "-" : "", (long long)s, ns);
    } else
    {
        (void)snprintf(v, sizeof(v), "%lld.%09ld", (long long)t->sec, (long)t->nsec);
    }
    rs_tar_pax_record(out, key, v, strlen(v));
}

static void pax_number(struct rs_buf *out, const char *key, uint64_t v)
{
    char s[24];

    (void)snprintf(s, sizeof(s), "%llu", (unsigned long long)v);
    rs_tar_pax_record(out, key, s, strlen(s));
}

static bool block(struct rs_tar_writer *w, const unsigned char *h)
{
    return emit(w, h, RS_TAR_BLOCK);
}

bool rs_tar_header(struct rs_tar_writer *w, const struct rs_tar_member *m)
{
    struct rs_buf pax;
    unsigned char h[RS_TAR_BLOCK];
    bool          ok;

    /* The extended header first. */
    rs_buf_init(&pax);
    rs_tar_pax_record(&pax, "path", m->name, strlen(m->name));
    if (m->linkname)
    {
        rs_tar_pax_record(&pax, "linkpath", m->linkname, strlen(m->linkname));
    }
    pax_number(&pax, "uid", m->uid);
    pax_number(&pax, "gid", m->gid);
    if (m->uname)
    {
        rs_tar_pax_record(&pax, "uname", m->uname, strlen(m->uname));
    }
    if (m->gname)
    {
        rs_tar_pax_record(&pax, "gname", m->gname, strlen(m->gname));
    }
    pax_number(&pax, "size", m->size);
    pax_time(&pax, "mtime", &m->mtime);
    pax_time(&pax, "atime", &m->atime);

    memset(h, 0, sizeof(h));
    memcpy(h + H_NAME, "PaxHeader", 9);
    octal(h + H_MODE, 8, 0644);
    octal(h + H_UID, 8, 0);
    octal(h + H_GID, 8, 0);
    octal(h + H_SIZE, 12, pax.len);
    octal(h + H_MTIME, 12, m->mtime.set && m->mtime.sec > 0 ? (uint64_t)m->mtime.sec : 0);
    h[H_TYPE] = 'x';
    memcpy(h + H_MAGIC, "ustar", 6);
    memcpy(h + H_VERSION, "00", 2);
    checksum(h);
    ok = block(w, h) && emit(w, pax.data, pax.len) && rs_tar_pad(w);
    rs_buf_free(&pax);
    if (!ok)
    {
        return false;
    }

    /* Then the ustar header, as complete as the fields allow, for readers
     * that ignore pax. */
    memset(h, 0, sizeof(h));
    text(h + H_NAME, 100, m->name);
    if (h[H_NAME] == '\0')
    {
        /* Too long or not ASCII: a stand-in, which pax overrides. */
        (void)snprintf((char *)h + H_NAME, 100, "restate/long-name");
    }
    octal(h + H_MODE, 8, m->mode & 07777);
    octal(h + H_UID, 8, m->uid);
    octal(h + H_GID, 8, m->gid);
    octal(h + H_SIZE, 12, m->typeflag == '0' ? m->size : 0);
    octal(h + H_MTIME, 12, m->mtime.set && m->mtime.sec > 0 ? (uint64_t)m->mtime.sec : 0);
    h[H_TYPE] = (unsigned char)m->typeflag;
    if (m->linkname)
    {
        text(h + H_LINK, 100, m->linkname);
    }
    memcpy(h + H_MAGIC, "ustar", 6);
    memcpy(h + H_VERSION, "00", 2);
    text(h + H_UNAME, 32, m->uname);
    text(h + H_GNAME, 32, m->gname);
    checksum(h);
    return block(w, h);
}

bool rs_tar_data(struct rs_tar_writer *w, const void *data, size_t n)
{
    return n == 0 || emit(w, data, n);
}

bool rs_tar_pad(struct rs_tar_writer *w)
{
    size_t rem = (size_t)(w->offset % RS_TAR_BLOCK);

    return rem == 0 || emit(w, zeros, RS_TAR_BLOCK - rem);
}

bool rs_tar_finish(struct rs_tar_writer *w)
{
    return rs_tar_pad(w) && emit(w, zeros, RS_TAR_BLOCK) && emit(w, zeros, RS_TAR_BLOCK);
}

/* ------------------------------------------------------------------------- */
/* Reading                                                                   */
/* ------------------------------------------------------------------------- */

static bool read_full(rs_tar_read_fn fn, void *ctx, void *buf, size_t n, struct rs_buf *err)
{
    unsigned char *p = buf;
    size_t         got = 0;

    while (got < n)
    {
        ssize_t r = fn(ctx, p + got, n - got);

        if (r < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            rs_buf_addf(err, "read error: %s", strerror(errno));
            return false;
        }
        if (r == 0)
        {
            rs_buf_addstr(err, "the archive ends in the middle of a member");
            return false;
        }
        got += (size_t)r;
    }
    return true;
}

static bool parse_octal(const unsigned char *field, size_t width, uint64_t *out)
{
    uint64_t v = 0;
    size_t   i = 0;
    bool     any = false;

    while (i < width && field[i] == ' ')
    {
        i++;
    }
    for (; i < width && field[i] >= '0' && field[i] <= '7'; i++)
    {
        if (v > (UINT64_MAX >> 3))
        {
            return false;
        }
        v = (v << 3) | (uint64_t)(field[i] - '0');
        any = true;
    }
    for (; i < width; i++)
    {
        if (field[i] != ' ' && field[i] != '\0')
        {
            return false;
        }
    }
    *out = v;
    return any;
}

static bool checksum_ok(const unsigned char *h)
{
    uint64_t want;
    unsigned sum = 0;
    size_t   i;

    if (!parse_octal(h + H_CHKSUM, 8, &want))
    {
        return false;
    }
    for (i = 0; i < RS_TAR_BLOCK; i++)
    {
        sum += (i >= H_CHKSUM && i < H_CHKSUM + 8) ? (unsigned)' ' : h[i];
    }
    return sum == want;
}

/* Reads `size` bytes of member data, plus the padding, into `out`. */
static bool read_data(rs_tar_read_fn fn, void *ctx, uint64_t size, struct rs_buf *out,
                      struct rs_buf *err)
{
    unsigned char chunk[8192];
    uint64_t      left = size;
    uint64_t      pad = (RS_TAR_BLOCK - size % RS_TAR_BLOCK) % RS_TAR_BLOCK;

    rs_buf_reset(out);
    rs_buf_add(out, "", 0);
    while (left > 0)
    {
        size_t n = left < sizeof(chunk) ? (size_t)left : sizeof(chunk);

        if (!read_full(fn, ctx, chunk, n, err))
        {
            return false;
        }
        rs_buf_add(out, chunk, n);
        left -= n;
    }
    return pad == 0 || read_full(fn, ctx, chunk, (size_t)pad, err);
}

/* The "path" record of a pax header, if there is one, into `path`. */
static bool pax_path(const struct rs_buf *pax, struct rs_buf *path, struct rs_buf *err)
{
    size_t pos = 0;

    while (pos < pax->len)
    {
        size_t      len = 0;
        size_t      start = pos;
        const char *eq;
        const char *rec;

        while (pos < pax->len && pax->data[pos] >= '0' && pax->data[pos] <= '9')
        {
            if (len > pax->len)
            {
                break;
            }
            len = len * 10 + (size_t)(pax->data[pos] - '0');
            pos++;
        }
        if (pos == start || pos >= pax->len || pax->data[pos] != ' ' ||
            len <= pos - start + 1 || len > pax->len - start ||
            pax->data[start + len - 1] != '\n')
        {
            rs_buf_addstr(err, "a malformed pax header");
            return false;
        }
        rec = pax->data + pos + 1;
        eq = memchr(rec, '=', start + len - 1 - (pos + 1));
        if (!eq)
        {
            rs_buf_addstr(err, "a malformed pax header");
            return false;
        }
        if ((size_t)(eq - rec) == 4 && memcmp(rec, "path", 4) == 0)
        {
            rs_buf_reset(path);
            rs_buf_add(path, eq + 1, (size_t)(pax->data + start + len - 1 - (eq + 1)));
        }
        pos = start + len;
    }
    return true;
}

bool rs_tar_read_first(rs_tar_read_fn fn, void *ctx, size_t max,
                       struct rs_buf *name, struct rs_buf *content, struct rs_buf *err)
{
    unsigned char h[RS_TAR_BLOCK];
    struct rs_buf pax;
    bool          have_pax_name = false;
    int           headers;

    rs_buf_init(&pax);
    rs_buf_reset(name);
    rs_buf_add(name, "", 0);
    /* A handful of extension headers may precede a member; a stream of them
     * forever is an attack, not an archive. */
    for (headers = 0; headers < 8; headers++)
    {
        uint64_t size;

        if (!read_full(fn, ctx, h, sizeof(h), err))
        {
            rs_buf_free(&pax);
            return false;
        }
        if (memcmp(h, zeros, sizeof(h)) == 0)
        {
            rs_buf_addstr(err, "the archive is empty");
            rs_buf_free(&pax);
            return false;
        }
        if (!checksum_ok(h))
        {
            rs_buf_addstr(err, "not a tar archive (bad header checksum)");
            rs_buf_free(&pax);
            return false;
        }
        if (!parse_octal(h + H_SIZE, 12, &size))
        {
            rs_buf_addstr(err, "a bad size in a tar header");
            rs_buf_free(&pax);
            return false;
        }
        if (h[H_TYPE] == 'x' || h[H_TYPE] == 'g')
        {
            if (size > (uint64_t)1024 * 1024)
            {
                rs_buf_addstr(err, "a pax header larger than 1 MiB");
                rs_buf_free(&pax);
                return false;
            }
            if (!read_data(fn, ctx, size, &pax, err))
            {
                rs_buf_free(&pax);
                return false;
            }
            if (h[H_TYPE] == 'x')
            {
                if (!pax_path(&pax, name, err))
                {
                    rs_buf_free(&pax);
                    return false;
                }
                have_pax_name = name->len > 0;
            }
            continue;
        }
        if (!have_pax_name)
        {
            rs_buf_reset(name);
            rs_buf_add(name, h + H_NAME, strnlen((const char *)h + H_NAME, 100));
        }
        if (size > max)
        {
            rs_buf_addf(err, "the first member is larger than %zu bytes", max);
            rs_buf_free(&pax);
            return false;
        }
        rs_buf_free(&pax);
        return read_data(fn, ctx, size, content, err);
    }
    rs_buf_addstr(err, "too many extension headers");
    rs_buf_free(&pax);
    return false;
}

/* ------------------------------------------------------------------------- */
/* Member by member                                                          */
/* ------------------------------------------------------------------------- */

void rs_tar_reader_init(struct rs_tar_reader *r, rs_tar_read_fn fn, void *ctx)
{
    memset(r, 0, sizeof(*r));
    r->fn = fn;
    r->ctx = ctx;
}

void rs_tar_entry_init(struct rs_tar_entry *e)
{
    memset(e, 0, sizeof(*e));
    rs_buf_init(&e->name);
    rs_buf_init(&e->linkname);
}

void rs_tar_entry_free(struct rs_tar_entry *e)
{
    rs_buf_free(&e->name);
    rs_buf_free(&e->linkname);
}

/* Discards `n` bytes. */
static bool skip(struct rs_tar_reader *r, uint64_t n, struct rs_buf *err)
{
    unsigned char chunk[8192];

    while (n > 0)
    {
        size_t take = n < sizeof(chunk) ? (size_t)n : sizeof(chunk);

        if (!read_full(r->fn, r->ctx, chunk, take, err))
        {
            return false;
        }
        n -= take;
    }
    return true;
}

/* The pax records this reader uses: path, linkpath and size. */
static bool pax_records(const struct rs_buf *pax, struct rs_tar_entry *e, bool *have_name,
                        bool *have_link, bool *have_size, struct rs_buf *err)
{
    size_t pos = 0;

    while (pos < pax->len)
    {
        size_t      len = 0;
        size_t      start = pos;
        const char *rec;
        const char *eq;
        const char *val;
        size_t      vlen;

        while (pos < pax->len && pax->data[pos] >= '0' && pax->data[pos] <= '9' && len <= pax->len)
        {
            len = len * 10 + (size_t)(pax->data[pos] - '0');
            pos++;
        }
        if (pos == start || pos >= pax->len || pax->data[pos] != ' ' ||
            len <= pos - start + 1 || len > pax->len - start ||
            pax->data[start + len - 1] != '\n')
        {
            rs_buf_addstr(err, "a malformed pax header");
            return false;
        }
        rec = pax->data + pos + 1;
        eq = memchr(rec, '=', start + len - 1 - (pos + 1));
        if (!eq)
        {
            rs_buf_addstr(err, "a malformed pax header");
            return false;
        }
        val = eq + 1;
        vlen = (size_t)(pax->data + start + len - 1 - val);
        if ((size_t)(eq - rec) == 4 && memcmp(rec, "path", 4) == 0)
        {
            rs_buf_reset(&e->name);
            rs_buf_add(&e->name, val, vlen);
            rs_buf_add(&e->name, "", 0);
            *have_name = true;
        } else if ((size_t)(eq - rec) == 8 && memcmp(rec, "linkpath", 8) == 0)
        {
            rs_buf_reset(&e->linkname);
            rs_buf_add(&e->linkname, val, vlen);
            rs_buf_add(&e->linkname, "", 0);
            *have_link = true;
        } else if ((size_t)(eq - rec) == 4 && memcmp(rec, "size", 4) == 0)
        {
            uint64_t v = 0;
            size_t   i;

            for (i = 0; i < vlen; i++)
            {
                if (val[i] < '0' || val[i] > '9' || v > (UINT64_MAX - 9) / 10)
                {
                    rs_buf_addstr(err, "a bad size in a pax header");
                    return false;
                }
                v = v * 10 + (uint64_t)(val[i] - '0');
            }
            if (vlen == 0)
            {
                rs_buf_addstr(err, "a bad size in a pax header");
                return false;
            }
            e->size = v;
            *have_size = true;
        }
        pos = start + len;
    }
    return true;
}

int rs_tar_next(struct rs_tar_reader *r, struct rs_tar_entry *e, struct rs_buf *err)
{
    unsigned char h[RS_TAR_BLOCK];
    struct rs_buf pax;
    bool          have_name = false;
    bool          have_link = false;
    bool          have_size = false;
    int           headers;

    if (r->ended)
    {
        return 0;
    }
    if (!skip(r, r->left + r->pad, err))
    {
        return -1;
    }
    r->left = 0;
    r->pad = 0;
    rs_buf_reset(&e->name);
    rs_buf_reset(&e->linkname);
    rs_buf_init(&pax);
    for (headers = 0; headers < 8; headers++)
    {
        uint64_t size;

        if (!read_full(r->fn, r->ctx, h, sizeof(h), err))
        {
            rs_buf_free(&pax);
            return -1;
        }
        if (memcmp(h, zeros, sizeof(h)) == 0)
        {
            /* The end: two zero blocks, though one is enough to know. */
            r->ended = true;
            rs_buf_free(&pax);
            return 0;
        }
        if (!checksum_ok(h))
        {
            rs_buf_addstr(err, "not a tar archive (bad header checksum)");
            rs_buf_free(&pax);
            return -1;
        }
        if (!parse_octal(h + H_SIZE, 12, &size))
        {
            rs_buf_addstr(err, "a bad size in a tar header");
            rs_buf_free(&pax);
            return -1;
        }
        if (h[H_TYPE] == 'x' || h[H_TYPE] == 'g')
        {
            if (size > (uint64_t)1024 * 1024)
            {
                rs_buf_addstr(err, "a pax header larger than 1 MiB");
                rs_buf_free(&pax);
                return -1;
            }
            if (!read_data(r->fn, r->ctx, size, &pax, err) ||
                (h[H_TYPE] == 'x' &&
                 !pax_records(&pax, e, &have_name, &have_link, &have_size, err)))
            {
                rs_buf_free(&pax);
                return -1;
            }
            continue;
        }
        rs_buf_free(&pax);
        if (!have_name)
        {
            rs_buf_add(&e->name, h + H_NAME, strnlen((const char *)h + H_NAME, 100));
            rs_buf_add(&e->name, "", 0);
        }
        if (!have_link)
        {
            rs_buf_add(&e->linkname, h + H_LINK, strnlen((const char *)h + H_LINK, 100));
            rs_buf_add(&e->linkname, "", 0);
        }
        e->typeflag = (char)(h[H_TYPE] == '\0' ? '0' : h[H_TYPE]);
        if (!have_size)
        {
            e->size = size;
        }
        /* Only a regular file's size is data that follows it. */
        r->left = (e->typeflag == '0' || e->typeflag == '7') ? e->size : 0;
        r->pad = (RS_TAR_BLOCK - r->left % RS_TAR_BLOCK) % RS_TAR_BLOCK;
        return 1;
    }
    rs_buf_free(&pax);
    rs_buf_addstr(err, "too many extension headers");
    return -1;
}

ssize_t rs_tar_read(struct rs_tar_reader *r, void *buf, size_t n, struct rs_buf *err)
{
    size_t want = r->left < n ? (size_t)r->left : n;

    if (want == 0)
    {
        return 0;
    }
    if (!read_full(r->fn, r->ctx, buf, want, err))
    {
        return -1;
    }
    r->left -= want;
    return (ssize_t)want;
}
