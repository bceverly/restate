/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "repo.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
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
#if defined(__FreeBSD__)
#include <sys/acl.h>
#endif
#if defined(__FreeBSD__) && defined(_PC_ACL_NFS4)
#define RS_NFS4_ACLS 1
#endif

#include "fsflags.h"
#include "glob.h"
#include "gzip.h"
#include "image.h"
#include "pgp.h"
#include "progress.h"
#include "remote.h"
#include "sha256.h"
#include "store.h"
#include "tar.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

/* Version 1 is read, and made version 2 by the first capture or prune into
 * it: a version 1 pack is a version 2 pack whose files are a chunk each. */
#define REPO_FORMAT_1  RS_REPO_MARKER " 1\n"
#define REPO_FORMAT_2  RS_REPO_MARKER " 2\n"
#define PACK_FORMAT_1  "restate-pack 1\n"
#define PACK_FORMAT    "restate-pack 2\n"
/* A pack's .sum, and a snapshot's list of the packs it needs: neither is
 * encrypted, and neither says anything of what is in them, so the storage
 * the repository is on can check and prune it without its keys. */
#define SUM_FORMAT     "restate-sum 1\n"
#define PACKS_FORMAT   "restate-packs 1\n"
/* A pack's .seek: nor is it, and it says only where its segments begin. */
#define SEEK_FORMAT    "restate-seek 1\n"
/* A pack list names a few thousand packs at most. */
#define SMALL_MAX_LIST ((size_t)16 * 1024 * 1024)
/* A pack's .idx, a snapshot's kit and its info are small; anything larger is
 * not one restate wrote. */
#define SMALL_MAX      ((size_t)256 * 1024 * 1024)
#define NAME_MAX_LEN   64
/* A repository's identity, which names its cache: 16 random bytes in hex. */
#define ID_LEN         32

/* ------------------------------------------------------------------------- */
/* Files                                                                     */
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

static bool to_buf(void *ctx, const void *data, size_t n)
{
    rs_buf_add(ctx, data, n);
    return true;
}

static ssize_t read_fd(void *ctx, void *data, size_t n)
{
    return read(*(const int *)ctx, data, n);
}

void rs_repo_set_adopting(bool always)
{
    rs_store_set_adopting(always);
}

void rs_repo_set_refusing_creates(bool refuse)
{
    rs_store_set_refusing_creates(refuse);
}

static bool hex_digit(char c, unsigned *v)
{
    if (c >= '0' && c <= '9')
    {
        *v = (unsigned)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f')
    {
        *v = (unsigned)(c - 'a' + 10);
        return true;
    }
    return false;
}

/* A digest's 64 hex digits as its 32 bytes. */
static bool unhex(const char *hex, unsigned char out[32])
{
    size_t i;

    for (i = 0; i < 32; i++)
    {
        unsigned hi;
        unsigned lo;

        if (!hex_digit(hex[2 * i], &hi) || !hex_digit(hex[2 * i + 1], &lo))
        {
            return false;
        }
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return true;
}

/* A digest's 32 bytes as its 64 hex digits. */
static void to_hex(const unsigned char d[32], char hex[RS_SHA256_HEX_SIZE])
{
    static const char digits[] = "0123456789abcdef";
    size_t            i;

    for (i = 0; i < 32; i++)
    {
        hex[2 * i] = digits[d[i] >> 4];
        hex[2 * i + 1] = digits[d[i] & 15];
    }
    hex[64] = '\0';
}

/* Why `to` could not be renamed into, as errno says, into `err`. */
static void renamed_failed(const struct rs_store *st, const char *to, struct rs_buf *err)
{
    int         saved = errno;
    const char *said = rs_store_said(st);
    char       *path;

    /* Through restate-proxy, what it said of what was sent on. */
    if (said)
    {
        rs_buf_addstr(err, said);
        errno = saved;
        return;
    }
    path = rs_store_path(st, to);
    rs_buf_addf(err, "%s: %s", path, strerror(saved));
    free(path);
    errno = saved;
}

/* The digest and size of the file `name` as it is stored. */
static bool file_digest(const struct rs_store *st, const char *name, char hex[RS_SHA256_HEX_SIZE],
                        uint64_t *size, struct rs_buf *err)
{
    int              fd = rs_store_open(st, name);
    struct rs_sha256 sha;
    unsigned char    chunk[65536];
    ssize_t          n;

    *size = 0;
    if (fd < 0)
    {
        char *path = rs_store_path(st, name);

        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    rs_sha256_init(&sha);
    while ((n = read(fd, chunk, sizeof(chunk))) != 0)
    {
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0)
        {
            char *path = rs_store_path(st, name);

            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            free(path);
            (void)close(fd);
            return false;
        }
        rs_sha256_update(&sha, chunk, (size_t)n);
        rs_progress_bytes((uint64_t)n);
        *size += (uint64_t)n;
    }
    (void)close(fd);
    rs_sha256_final(&sha, hex);
    return true;
}

bool rs_repo_parse_sum(const char *text, size_t len, char hex[RS_SHA256_HEX_SIZE], uint64_t *size)
{
    const char *p = text;
    const char *end = text + len;
    size_t      i;

    *size = 0;
    if (len < strlen(SUM_FORMAT) || memcmp(text, SUM_FORMAT, strlen(SUM_FORMAT)) != 0)
    {
        return false;
    }
    p += strlen(SUM_FORMAT);
    if (end - p < 7 + 64 + 1 || memcmp(p, "sha256 ", 7) != 0)
    {
        return false;
    }
    p += 7;
    for (i = 0; i < 64; i++)
    {
        unsigned v;

        if (!hex_digit(p[i], &v))
        {
            return false;
        }
        hex[i] = p[i];
    }
    hex[64] = '\0';
    p += 64;
    if (*p != '\n' || end - p < 7 || memcmp(p + 1, "size ", 5) != 0)
    {
        return false;
    }
    p += 6;
    if (p >= end || *p < '0' || *p > '9' || (*p == '0' && p + 1 < end && p[1] != '\n'))
    {
        return false;
    }
    while (p < end && *p >= '0' && *p <= '9')
    {
        uint64_t digit = (uint64_t)(*p - '0');

        if (*size > (UINT64_MAX - digit) / 10)
        {
            return false;
        }
        *size = *size * 10 + digit;
        p++;
    }
    return p + 1 == end && *p == '\n';
}

/* A pack's .sum: what its content's file is as written -- its digest and
 * size -- so that it can be checked whole without decrypting it. */
static bool put_sum(const struct rs_store *st, const char *pack, const char *hex, uint64_t size,
                    struct rs_buf *err)
{
    char *sum = rs_xasprintf("packs/%s.sum", pack);
    char *text = rs_xasprintf(SUM_FORMAT "sha256 %s\nsize %" PRIu64 "\n", hex, size);
    bool  ok = rs_store_replace(st, sum, text, strlen(text), err);

    free(text);
    free(sum);
    return ok;
}

/* The .sum of a pack already written, read whole to make it. */
static bool write_sum(const struct rs_store *st, const char *pack, struct rs_buf *err)
{
    char    *content = rs_xasprintf("packs/%s.tar.gz", pack);
    char     hex[RS_SHA256_HEX_SIZE];
    uint64_t size = 0;
    bool     ok = file_digest(st, content, hex, &size, err) && put_sum(st, pack, hex, size, err);

    free(content);
    return ok;
}

/* The .sum of pack `pack`: false if it has none, or it is not one. */
static bool read_sum(const struct rs_store *st, const char *pack, char hex[RS_SHA256_HEX_SIZE],
                     uint64_t *size)
{
    char         *name = rs_xasprintf("packs/%s.sum", pack);
    struct rs_buf text;
    struct rs_buf ignore;
    bool          ok;

    rs_buf_init(&ignore);
    ok = rs_store_read(st, name, 4096, &text, &ignore) &&
         rs_repo_parse_sum(text.data, text.len, hex, size);
    rs_buf_free(&text);
    rs_buf_free(&ignore);
    free(name);
    return ok;
}

bool rs_repo_parse_pack_list(const char *text, size_t len, char ***names, size_t *n)
{
    const char *p = text;
    const char *end = text + len;

    *names = NULL;
    *n = 0;
    if (len < strlen(PACKS_FORMAT) || memcmp(text, PACKS_FORMAT, strlen(PACKS_FORMAT)) != 0)
    {
        return false;
    }
    p += strlen(PACKS_FORMAT);
    while (p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        char       *name;

        if (!nl)
        {
            break;
        }
        name = rs_xstrndup(p, (size_t)(nl - p));
        /* Strictly in order, each once: the order they are written in. */
        if (!rs_repo_name_valid(name) || (*n > 0 && strcmp((*names)[*n - 1], name) >= 0))
        {
            free(name);
            break;
        }
        *names = rs_xreallocarray(*names, *n + 1, sizeof(**names));
        (*names)[(*n)++] = name;
        p = nl + 1;
    }
    if (p != end)
    {
        rs_repo_free_names(*names, *n);
        *names = NULL;
        *n = 0;
        return false;
    }
    return true;
}

/* The packs snapshot `name` needs, as its pack list says: false if it has
 * none -- one written before restate 2.0 -- or it is not one. */
static bool read_pack_list(const struct rs_store *st, const char *name, char ***names, size_t *n)
{
    char         *path = rs_xasprintf("snapshots/%s/packs", name);
    struct rs_buf text;
    struct rs_buf ignore;
    bool          ok;

    *names = NULL;
    *n = 0;
    rs_buf_init(&ignore);
    ok = rs_store_read(st, path, SMALL_MAX_LIST, &text, &ignore) &&
         rs_repo_parse_pack_list(text.data, text.len, names, n);
    rs_buf_free(&text);
    rs_buf_free(&ignore);
    free(path);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* gzip and gpg                                                              */
/* ------------------------------------------------------------------------- */

/*
 * What is written into z->fd goes through gzip, if `gzip`, then gpg to the
 * keys in `recips`, if there are any, into `out`. Our copy of the pipe into
 * gpg is closed once gzip has its own, so gpg sees the end of the data when
 * gzip exits.
 */
struct zout {
    struct rs_gzip gz;
    struct rs_pgp  pg;
    bool           gzip;
    bool           sealed;
    int            fd;
};

static bool zout_open(struct zout *z, int out, bool gzip, const char *const *recips, size_t n,
                      struct rs_buf *err)
{
    bool ok = true;

    memset(z, 0, sizeof(*z));
    z->pg.fd = -1;
    z->gz.fd = -1;
    z->gzip = gzip;
    z->sealed = n > 0;
    z->fd = out;
    if (z->sealed)
    {
        ok = rs_pgp_encrypt(recips, n, out, &z->pg, err);
        z->fd = z->pg.fd;
    }
    if (ok && gzip)
    {
        ok = rs_gzip_compress(z->fd, &z->gz, err);
        if (z->sealed)
        {
            (void)close(z->pg.fd);
            z->pg.fd = -1;
        }
        z->fd = ok ? z->gz.fd : -1;
    }
    if (!ok && z->sealed && z->pg.pid > 0)
    {
        (void)rs_pgp_finish(&z->pg, true, err);
        z->sealed = false;
    }
    return ok;
}

/* Finishes the pipeline: true if everything in it exited cleanly. */
static bool zout_close(struct zout *z, bool failed, struct rs_buf *err)
{
    bool ok = !failed;

    if (z->gzip && !rs_gzip_finish(&z->gz, failed, err))
    {
        ok = false;
    }
    if (z->sealed && !rs_pgp_finish(&z->pg, failed, err))
    {
        ok = false;
    }
    memset(z, 0, sizeof(*z));
    z->fd = -1;
    return ok;
}

/* The other way: what is in `in` -- decrypted first if it is encrypted, which
 * is told from its first bytes -- read from z->fd, gunzip'd if `gzip`. */
struct zin {
    struct rs_gzip gz;
    struct rs_pgp  pg;
    bool           gzip;
    bool           sealed;
    int            fd;
};

static bool zin_open(struct zin *z, int in, bool gzip, struct rs_buf *err)
{
    unsigned char head[16];
    ssize_t       got = pread(in, head, sizeof(head), 0);
    bool          ok = true;

    memset(z, 0, sizeof(*z));
    z->pg.fd = -1;
    z->gz.fd = -1;
    z->gzip = gzip;
    z->sealed = got > 0 && rs_pgp_detect(head, (size_t)got);
    z->fd = in;
    if (z->sealed)
    {
        ok = rs_pgp_decrypt(in, &z->pg, err);
        z->fd = z->pg.fd;
    }
    if (ok && gzip)
    {
        ok = rs_gzip_decompress(z->fd, &z->gz, err);
        if (z->sealed)
        {
            (void)close(z->pg.fd);
            z->pg.fd = -1;
        }
        z->fd = ok ? z->gz.fd : -1;
    }
    if (!ok && z->sealed && z->pg.pid > 0)
    {
        (void)rs_pgp_finish(&z->pg, true, err);
        z->sealed = false;
    }
    return ok;
}

/* With `abandon`, a reader stopped early: how it ends does not matter. */
static bool zin_close(struct zin *z, bool abandon, struct rs_buf *err)
{
    bool ok = true;

    if (z->gzip && !rs_gzip_finish(&z->gz, abandon, err))
    {
        ok = false;
    }
    if (z->sealed && !rs_pgp_finish(&z->pg, abandon, err))
    {
        ok = false;
    }
    if (!ok && z->sealed && !abandon)
    {
        rs_buf_addf(err, "; it could not be decrypted: the secret key for it is not in %s, or "
                    "its passphrase was not given", rs_pgp_key_place());
    }
    memset(z, 0, sizeof(*z));
    z->fd = -1;
    return ok;
}

/* The whole of `fd`, up to `max` bytes, through zin_open; whether it was
 * encrypted into *sealed, if that is not NULL. */
static bool slurp_sealed(const char *path, int fd, bool gzip, size_t max, struct rs_buf *out,
                         bool *sealed, struct rs_buf *err)
{
    struct zin z;
    char       chunk[65536];
    ssize_t    n = 0;
    bool       big = false;
    bool       ok;

    rs_buf_reset(out);
    rs_buf_add(out, "", 0);
    if (!zin_open(&z, fd, gzip, err))
    {
        return false;
    }
    if (sealed)
    {
        *sealed = z.sealed;
    }
    while (!big && (n = read(z.fd, chunk, sizeof(chunk))) != 0)
    {
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0)
        {
            break;
        }
        big = out->len + (size_t)n > max;
        rs_buf_add(out, chunk, big ? 0 : (size_t)n);
    }
    ok = zin_close(&z, big || n < 0, err) && !big && n == 0;
    if (!ok)
    {
        if (big)
        {
            rs_buf_reset(err);
            rs_buf_addf(err, "%s: larger than restate writes", path);
        } else if (err->len == 0)
        {
            rs_buf_addf(err, "%s: it could not be read", path);
        } else if (!rs_starts_with(err->data, path))
        {
            char *why = rs_xstrdup(err->data);

            rs_buf_reset(err);
            rs_buf_addf(err, "%s: %s", path, why);
            free(why);
        }
    }
    return ok;
}

static bool slurp_fd(const char *path, int fd, bool gzip, size_t max, struct rs_buf *out,
                     struct rs_buf *err)
{
    return slurp_sealed(path, fd, gzip, max, out, NULL, err);
}

/* A small file restate wrote, decrypted if it is encrypted -- and not even
 * tried, if it is and `decrypt` is false: *sealed says whether it is. */
static bool read_sealed(const struct rs_store *st, const char *name, size_t max, bool decrypt,
                        struct rs_buf *out, bool *sealed, struct rs_buf *err)
{
    int           fd = rs_store_open(st, name);
    char         *path = rs_store_path(st, name);
    unsigned char head[16];
    ssize_t       got;
    bool          ok;

    rs_buf_init(out);
    rs_buf_add(out, "", 0);
    *sealed = false;
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    got = pread(fd, head, sizeof(head), 0);
    if (!decrypt && got > 0 && rs_pgp_detect(head, (size_t)got))
    {
        *sealed = true;
        rs_buf_addf(err, "%s: it is encrypted", path);
        (void)close(fd);
        free(path);
        return false;
    }
    ok = slurp_sealed(path, fd, false, max, out, sealed, err);
    (void)close(fd);
    free(path);
    return ok;
}

static bool read_plain(const struct rs_store *st, const char *name, size_t max, struct rs_buf *out,
                       struct rs_buf *err)
{
    bool sealed;

    return read_sealed(st, name, max, true, out, &sealed, err);
}

/* `len` bytes into a new file `name`, 0600, through gzip if `gzip` and
 * encrypted to `recips` if there are any; flushed to disk. */
static bool write_out(const struct rs_store *st, const char *name, const void *data, size_t len,
                      bool gzip, const char *const *recips, size_t n, struct rs_buf *err)
{
    int         fd = rs_store_create(st, name);
    char       *path = rs_store_path(st, name);
    struct zout z;
    bool        ok;

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    ok = zout_open(&z, fd, gzip, recips, n, err);
    if (ok)
    {
        bool wrote = write_all(z.fd, data, len);

        ok = zout_close(&z, !wrote, err) && wrote;
    }
    ok = ok && fsync(fd) == 0;
    if (close(fd) != 0)
    {
        ok = false;
    }
    if (!ok)
    {
        if (err->len == 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
        }
        (void)rs_store_remove(st, name, false);
    }
    free(path);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Digests                                                                   */
/* ------------------------------------------------------------------------- */

/* A set of digests, each with the pack that holds its content: open
 * addressing on the digest itself, which is as good a hash as there is. */
struct obj {
    unsigned char d[32];
    uint32_t      pack;     /* into rs_repo.packs; for prune, whether taken */
    uint32_t      member;   /* its number in the pack; for a list, which */
    bool          used;
};

struct objmap {
    struct obj *slots;
    size_t      cap;        /* a power of two, or 0 */
    size_t      n;
};

static size_t slot_of(const struct objmap *m, const unsigned char d[32])
{
    uint64_t h = 0;
    size_t   i;

    for (i = 0; i < 8; i++)
    {
        h = h << 8 | d[i];
    }
    return (size_t)(h & (uint64_t)(m->cap - 1));
}

static struct obj *map_find(const struct objmap *m, const unsigned char d[32])
{
    size_t i;

    if (m->cap == 0)
    {
        return NULL;
    }
    for (i = slot_of(m, d); m->slots[i].used; i = (i + 1) & (m->cap - 1))
    {
        if (memcmp(m->slots[i].d, d, 32) == 0)
        {
            return &m->slots[i];
        }
    }
    return NULL;
}

/* Puts a digest that is not there into the first free slot for it. */
static struct obj *map_put(struct objmap *m, const unsigned char d[32], uint32_t pack,
                           uint32_t member)
{
    size_t i;

    for (i = slot_of(m, d); m->slots[i].used; i = (i + 1) & (m->cap - 1))
    {
    }
    memcpy(m->slots[i].d, d, 32);
    m->slots[i].pack = pack;
    m->slots[i].member = member;
    m->slots[i].used = true;
    m->n++;
    return &m->slots[i];
}

/* The digest's entry, added with `pack` if it was not there; the table is
 * kept at most half full, so a search ends soon. */
static struct obj *map_add(struct objmap *m, const unsigned char d[32], uint32_t pack,
                           uint32_t member)
{
    struct obj *o = map_find(m, d);

    if (o)
    {
        return o;
    }
    if ((m->n + 1) * 2 > m->cap)
    {
        struct objmap bigger;
        size_t        i;

        bigger.cap = m->cap ? m->cap * 2 : 1024;
        bigger.n = 0;
        bigger.slots = rs_xcalloc(bigger.cap, sizeof(*bigger.slots));
        for (i = 0; i < m->cap; i++)
        {
            if (m->slots[i].used)
            {
                (void)map_put(&bigger, m->slots[i].d, m->slots[i].pack, m->slots[i].member);
            }
        }
        free(m->slots);
        *m = bigger;
    }
    return map_put(m, d, pack, member);
}

static void map_free(struct objmap *m)
{
    free(m->slots);
    memset(m, 0, sizeof(*m));
}

/* ------------------------------------------------------------------------- */
/* The repository                                                            */
/* ------------------------------------------------------------------------- */

/* A file stored as chunks: its digest, and theirs, in order. */
struct list {
    unsigned char d[32];
    uint64_t      size;
    uint32_t      pack;       /* whose .idx it is in */
    size_t        first;      /* into rs_repo.chunks */
    size_t        n;
};

struct rs_repo {
    char              *dir;
    struct rs_store   *st;         /* where its files are */
    int                lock_fd;
    enum rs_repo_lock  mode;       /* as it was opened */
    int                readers_fd;
    int                version;    /* of its format: 1 or 2 */
    bool               encrypted;
    char               id[ID_LEN + 1];
    char              *cache;      /* this machine's cache of it, if it is encrypted */
    const char *const *recips;     /* the keys to encrypt to, given for this run */
    size_t             nrecips;
    char             **packs;      /* names, without ".tar.gz", sorted */
    size_t             npacks;
    /* Once loaded: every live chunk in a pack, and every list whose chunks
     * are all there -- a file's content is held if either has its digest. */
    struct objmap      objects;
    struct objmap      listed;
    struct list       *lists;
    size_t             nlists;
    unsigned char    (*chunks)[32];
    size_t             nchunks;
    size_t             unreadable; /* packs whose .idx could not be read */
    bool               loaded;
    bool             (*stop)(void); /* see rs_repo_set_stop */
    /* An encrypted repository's chunk boundaries follow a key of its own
     * (see chunk_key); NULL for the fixed table everyone shares. */
    uint64_t          *gear;
};

bool rs_repo_name_valid(const char *name)
{
    size_t i;

    if (!name || name[0] == '\0' || name[0] == '.' || strlen(name) > NAME_MAX_LEN)
    {
        return false;
    }
    for (i = 0; name[i]; i++)
    {
        char c = name[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              c == '.' || c == '-' || c == '_'))
        {
            return false;
        }
    }
    return true;
}

bool rs_repo_is(const char *dir)
{
    struct rs_store *st;
    struct rs_buf    text;
    struct rs_buf    err;
    bool             ok;

    rs_buf_init(&err);
    /* Behind restate-proxy, a repository is taken to be one if its name is
     * one, and the proxy asked nothing until it is opened -- which says so,
     * if it is not: asking would be a session each time. */
    if (rs_remote_is(dir))
    {
        ok = rs_remote_url_ok(dir, &err);
        rs_buf_free(&err);
        return ok;
    }
    st = rs_store_at(dir);
    ok = rs_store_read(st, RS_REPO_MARKER, 4096, &text, &err) &&
         rs_starts_with(text.data, RS_REPO_MARKER " ");
    rs_buf_free(&text);
    rs_buf_free(&err);
    rs_store_free(st);
    return ok;
}

/* 16 bytes from the kernel's random source, in hex: a repository's identity,
 * which names its cache and nothing more, so the time and the process stand
 * in where there is no such source. */
static void random_id(char out[ID_LEN + 1])
{
    unsigned char bytes[ID_LEN / 2];
    int           fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t        got = 0;
    size_t        i;

    while (fd >= 0 && got < sizeof(bytes))
    {
        ssize_t n = read(fd, bytes + got, sizeof(bytes) - got);

        if (n <= 0)
        {
            break;
        }
        got += (size_t)n;
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    if (got < sizeof(bytes))
    {
        uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);

        for (i = 0; i < sizeof(bytes); i++)
        {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            bytes[i] = (unsigned char)(seed >> 56);
        }
    }
    for (i = 0; i < sizeof(bytes); i++)
    {
        (void)snprintf(out + 2 * i, 3, "%02x", bytes[i]);
    }
}

/* What a version 2 marker says: "restate-repository 2", "id HEX" and, for an
 * encrypted one, "encrypted". */
static char *marker_text(const char *id, bool encrypted)
{
    return rs_xasprintf(REPO_FORMAT_2 "id %s\n%s", id, encrypted ? "encrypted\n" : "");
}

/*
 * Reads a marker into r: false, with *newer set if it is a later format's,
 * when it is not one this restate reads.
 */
static bool parse_marker(const char *text, struct rs_repo *r, bool *newer);

bool rs_repo_parse_marker(const char *text, int *version, bool *encrypted, bool *newer)
{
    struct rs_repo r;
    bool           ok;

    memset(&r, 0, sizeof(r));
    ok = parse_marker(text, &r, newer);
    *version = ok ? r.version : 0;
    *encrypted = ok && r.encrypted;
    return ok;
}

static bool parse_marker(const char *text, struct rs_repo *r, bool *newer)
{
    const char *p;

    *newer = rs_starts_with(text, RS_REPO_MARKER " ");
    if (strcmp(text, REPO_FORMAT_1) == 0)
    {
        r->version = 1;
        *newer = false;
        return true;
    }
    if (!rs_starts_with(text, REPO_FORMAT_2))
    {
        return false;
    }
    r->version = 2;
    for (p = text + strlen(REPO_FORMAT_2); *p; )
    {
        size_t len = strcspn(p, "\n");

        if (len == 3 + ID_LEN && strncmp(p, "id ", 3) == 0 &&
            strspn(p + 3, "0123456789abcdef") >= ID_LEN)
        {
            memcpy(r->id, p + 3, ID_LEN);
            r->id[ID_LEN] = '\0';
        } else if (len == 9 && strncmp(p, "encrypted", 9) == 0)
        {
            r->encrypted = true;
        } else
        {
            return false;   /* something a later restate knows of */
        }
        if (p[len] != '\n')
        {
            return false;
        }
        p += len + 1;
    }
    *newer = false;
    return r->id[0] != '\0';
}

#ifdef RS_NFS4_ACLS
/* A directory a group adds to, where its filesystem has NFSv4 ACLs (see
 * protect_as). Its owner removes anything from it, as from a sticky one,
 * and its group nothing; what one of them makes -- a file, or a directory --
 * its maker may rename and remove, until protect makes it root's and its
 * chmod drops what it was given. */
static const char protect_aces[] = "owner@:----D---------:-------:allow,"
                                   "owner@:-----d--------:-d-----:allow,"
                                   "owner@:-----d--------:f------:allow,"
                                   "group@:----D---------:-------:deny";

static bool nfs4_acls(int fd)
{
    return fpathconf(fd, _PC_ACL_NFS4) > 0;
}

/* The ACL of `fd`, a directory the machines add to: protect_aces ahead of
 * what its mode gives. 1 if it was set, 0 if it was so, -1 if it could not
 * be, with errno. */
static int protect_acl(int fd)
{
    acl_t       now = acl_get_fd_np(fd, ACL_TYPE_NFS4);
    acl_t       want = now ? acl_strip_np(now, 0) : NULL;
    acl_t       aces = acl_from_text(protect_aces);
    char       *have = now ? acl_to_text_np(now, NULL, 0) : NULL;
    char       *wanted = NULL;
    acl_entry_t from;
    acl_entry_t to;
    int         at = 0;
    int         which = ACL_FIRST_ENTRY;
    int         did = -1;
    int         saved;

    while (want && aces && have && acl_get_entry(aces, which, &from) == 1 &&
           acl_create_entry_np(&want, &to, at) == 0 && acl_copy_entry(to, from) == 0)
    {
        which = ACL_NEXT_ENTRY;
        at++;
    }
    if (at == 4)
    {
        wanted = acl_to_text_np(want, NULL, 0);
    }
    if (wanted)
    {
        did = strcmp(wanted, have) == 0 ? 0 : acl_set_fd_np(fd, want, ACL_TYPE_NFS4) == 0 ? 1 : -1;
    } else if (errno == 0)
    {
        errno = EINVAL;
    }
    saved = errno;
    acl_free(wanted);
    acl_free(have);
    acl_free(aces);
    acl_free(want);
    acl_free(now);
    errno = saved;
    return did;
}

/* Whether `fd` has an ACL that is more than its mode: one made ready. */
static bool acl_made_ready(int fd)
{
    acl_t acl = nfs4_acls(fd) ? acl_get_fd_np(fd, ACL_TYPE_NFS4) : NULL;
    int   trivial = 1;

    if (acl)
    {
        (void)acl_is_trivial_np(acl, &trivial);
        acl_free(acl);
    }
    return !trivial;
}
#else
static bool nfs4_acls(int fd)
{
    (void)fd;
    return false;
}

static bool acl_made_ready(int fd)
{
    (void)fd;
    return false;
}
#endif

/* Whether `fd` is append-only: on Linux, a directory made ready. */
static bool append_only(int fd)
{
    unsigned flags;

    return rs_fsflags_supported() && rs_fsflags_get(fd, &flags) == 0 &&
           (flags & RS_FSFLAGS_APPEND) != 0;
}

/* Whether `name` in the directory `dfd` is what an unfinished
 * rs_repo_init() leaves: its empty lock or readers, or its empty packs or
 * snapshots. */
static bool init_leftover(int dfd, const char *name)
{
    struct stat st;
    int         fd;
    DIR        *d;
    bool        empty = true;

    if (dfd < 0)
    {
        return false;
    }
    if (strcmp(name, "lock") == 0 || strcmp(name, "readers") == 0)
    {
        return fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode) &&
               st.st_size == 0;
    }
    if (strcmp(name, "packs") != 0 && strcmp(name, "snapshots") != 0)
    {
        return false;
    }
    fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    d = fd >= 0 ? fdopendir(fd) : NULL;
    if (!d)
    {
        if (fd >= 0)
        {
            (void)close(fd);
        }
        return false;
    }
    for (;;)
    {
        const struct dirent *de = readdir(d);

        if (!de)
        {
            break;
        }
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
        {
            empty = false;
            break;
        }
    }
    (void)closedir(d);
    return empty;
}

bool rs_repo_init(const char *dir, bool encrypted, struct rs_buf *err)
{
    static const char *const subdirs[] = { "packs", "snapshots" };
    static const char *const empty[] = { "lock", "readers" };
    char                    *path;
    char                     id[ID_LEN + 1];
    size_t                   i;
    bool                     ok = true;
    /* What an unfinished create left, which this one finishes -- one that
     * failed partway, where what it made cannot be removed again, as in a
     * directory made ready by root for a group to add to, which no machine
     * can remove from: lock, readers, packs and snapshots, by bit. */
    unsigned                 left = 0;
    struct rs_store         *store = rs_store_at(dir);

    if (rs_remote_is(dir))
    {
        rs_buf_addf(err, "%s: a repository behind restate-proxy is made on the storage host, "
                    "with restate init there", dir);
        rs_store_free(store);
        return false;
    }
    /* Made, or else there already: then it has to be an empty directory, and
     * everything about it is learned through the one descriptor on it, so
     * nothing can be swapped in between. */
    if (rs_store_make_dir(store, "", 0700, false) != 0)
    {
        int         made = errno;
        int         fd = made == EEXIST ? open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                                        : -1;
        struct stat st;
        int         listing = fd >= 0 ? dup(fd) : -1;
        DIR        *d = listing >= 0 ? fdopendir(listing) : NULL;
        bool        has = !d;

        if (made != EEXIST)
        {
            rs_buf_addf(err, "%s: %s", dir, strerror(made));
            rs_store_free(store);
            return false;
        }
        if (!d && listing >= 0)
        {
            (void)close(listing);
        }
        while (d && !has)
        {
            const struct dirent *de = readdir(d);

            if (!de)
            {
                break;
            }
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            {
                continue;
            }
            if (init_leftover(dirfd(d), de->d_name))
            {
                left |= strcmp(de->d_name, "lock") == 0      ? 1U
                        : strcmp(de->d_name, "readers") == 0 ? 2U
                        : strcmp(de->d_name, "packs") == 0   ? 4U
                                                             : 8U;
            } else
            {
                has = true;
            }
        }
        if (d)
        {
            (void)closedir(d);
        }
        /* Its owner's alone, as a new one is made -- unless it is sticky,
         * append-only or has an ACL: made ready by root for a group to add
         * to (rs_repo_protect). */
        if (!has && fd >= 0 && fstat(fd, &st) == 0 && !(st.st_mode & S_ISVTX) &&
            !append_only(fd) && !acl_made_ready(fd))
        {
            (void)fchmod(fd, 0700);
        }
        if (fd >= 0)
        {
            (void)close(fd);
        }
        if (has)
        {
            rs_buf_addf(err, "%s: %s", dir,
                        rs_repo_is(dir) ? "it is a repository already"
                                        : "it is there already, and not an empty directory");
            rs_store_free(store);
            return false;
        }
    }
    for (i = 0; ok && i < sizeof(subdirs) / sizeof(subdirs[0]); i++)
    {
        ok = rs_store_make_dir(store, subdirs[i], 0700, (left & (4U << i)) != 0) == 0;
        if (!ok)
        {
            path = rs_store_path(store, subdirs[i]);
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            free(path);
        }
    }
    for (i = 0; ok && i < sizeof(empty) / sizeof(empty[0]); i++)
    {
        ok = (left & (1U << i)) != 0 || rs_store_write_new(store, empty[i], "", 0, err);
    }
    /* The marker last: until it is there, this is not a repository. */
    if (ok)
    {
        char *text;

        random_id(id);
        text = marker_text(id, encrypted);
        ok = rs_store_write_new(store, RS_REPO_MARKER, text, strlen(text), err);
        free(text);
        rs_store_sync_dir(store, "");
    }
    rs_store_free(store);
    return ok;
}

bool rs_repo_dir_encrypted(const char *dir)
{
    struct rs_store *st = rs_store_at(dir);
    struct rs_buf    text;
    struct rs_buf    err;
    struct rs_repo   r;
    bool             newer;
    bool             ok;

    memset(&r, 0, sizeof(r));
    rs_buf_init(&err);
    ok = rs_store_read(st, RS_REPO_MARKER, 4096, &text, &err) &&
         parse_marker(text.data, &r, &newer) && r.encrypted;
    rs_buf_free(&text);
    rs_buf_free(&err);
    rs_store_free(st);
    return ok;
}

bool rs_repo_ref(const char *ref, char **dir, char **name)
{
    const char *sep = NULL;
    /* Past a proxy's IPv6 address, which has "::" of its own. */
    const char *p = rs_remote_sep_from(ref);

    *dir = NULL;
    *name = NULL;
    while ((p = strstr(p, RS_REPO_SEP)) != NULL)
    {
        sep = p;
        p += strlen(RS_REPO_SEP);
    }
    if (sep)
    {
        char *d = rs_xstrndup(ref, (size_t)(sep - ref));

        if (rs_repo_is(d))
        {
            *dir = d;
            *name = rs_xstrdup(sep + strlen(RS_REPO_SEP));
            return true;
        }
        free(d);
        return false;
    }
    if (rs_repo_is(ref))
    {
        *dir = rs_xstrdup(ref);
        return true;
    }
    return false;
}

const char *rs_repo_dir(const struct rs_repo *r)
{
    return r->dir;
}

void rs_repo_set_locking(int (*lock)(int fd, bool shared), bool (*nfs)(int fd), long nap_ms)
{
    rs_store_set_locking(lock, nfs, nap_ms);
}

/* Takes the lock file `name`, shared or not, without waiting. */
static int take(const struct rs_store *st, const char *name, bool shared, bool *busy,
                struct rs_buf *err)
{
    const char *dir = rs_store_where(st);
    bool        refused = false;
    int         lock = rs_store_lock(st, name, shared, busy, &refused, err);

    if (lock < 0 && refused)
    {
        rs_buf_addf(err, "%s: the file server refused the lock on %s with an I/O error, "
                         "which is how an NFS client is told a program on the server "
                         "holds it; try again when that is done, and if nothing there is "
                         "using it, the connection to the server may be failing",
                    dir, name);
    } else if (lock < 0 && *busy)
    {
        rs_buf_addf(err, "%s: %s", dir,
                    strcmp(name, "lock") == 0
                        ? "another capture or prune is using it; try again when it is done"
                        : "a prune is running on it, or something is reading it while "
                          "prune wants to; try again when it is done");
    } else if (lock < 0 && shared && errno == EROFS)
    {
        /* rs_store_lock has said "Read-only file system" already. */
        rs_buf_addstr(err, "; to read a repository that cannot be written, as in a recovery "
                           "from a read-only mount, run with --no-lock");
    }
    return lock;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void rs_repo_free_names(char **names, size_t n)
{
    size_t i;

    /* None, whatever `n` says: rs_store_list, unread, could seem to give a
     * count with no names. */
    for (i = 0; names && i < n; i++)
    {
        free(names[i]);
    }
    free(names);
}

/* A pack counts once its .idx is there, beside its content. */
static bool is_pack(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                    char **out)
{
    size_t len = strlen(name);
    char  *stem;
    char  *content;
    bool   ok;

    (void)ctx;
    if (len <= 4 || strcmp(name + len - 4, ".idx") != 0)
    {
        return false;
    }
    stem = rs_xstrndup(name, len - 4);
    content = rs_xasprintf("%s/%s.tar.gz", dir, stem);
    ok = rs_repo_name_valid(stem) && rs_store_is_file(st, content);
    free(content);
    if (!ok)
    {
        free(stem);
        return false;
    }
    *out = stem;
    return true;
}

static void list_packs(struct rs_repo *r)
{
    rs_repo_free_names(r->packs, r->npacks);
    r->packs = rs_store_list(r->st, "packs", is_pack, NULL, &r->npacks);
}

/* Where this machine keeps its cache of the encrypted repository whose
 * identity is `id`: root's under /var/cache, anyone else's in their own. */
static char *cache_root;

void rs_repo_set_cache_dir(const char *dir)
{
    free(cache_root);
    cache_root = dir ? rs_xstrdup(dir) : NULL;
}

static char *cache_dir(const char *id)
{
    const char *xdg;
    const char *home;

    if (cache_root)
    {
        return rs_xasprintf("%s/%s", cache_root, id);
    }
    /* Root's is fixed, whatever the environment says. */
    if (geteuid() == 0)
    {
#ifdef __APPLE__
        return rs_xasprintf("/Library/Caches/restate/repositories/%s", id);
#else
        return rs_xasprintf("/var/cache/restate/repositories/%s", id);
#endif
    }
    /* Anyone else's is in their own cache directory, which their own
     * environment names: it can steer them only into what they can write. */
    xdg = getenv("XDG_CACHE_HOME"); /* Flawfinder: ignore */
    home = getenv("HOME");          /* Flawfinder: ignore */
    if (xdg && xdg[0] == '/')
    {
        return rs_xasprintf("%s/restate/repositories/%s", xdg, id);
    }
    if (home && home[0] == '/')
    {
        return rs_xasprintf("%s/.cache/restate/repositories/%s", home, id);
    }
    return NULL;
}

/* Makes `path` and the directories it is in that are missing, 0700. */
static bool make_dirs(const char *path)
{
    char  *copy = rs_xstrdup(path);
    char  *p;
    bool   ok = true;

    for (p = copy + 1; ok && *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            ok = mkdir(copy, 0700) == 0 || errno == EEXIST;
            *p = '/';
        }
    }
    ok = ok && (mkdir(copy, 0700) == 0 || errno == EEXIST);
    free(copy);
    return ok;
}

/* The cache's subdirectory `sub`, made if it is not there; NULL if there is
 * no cache, or it cannot be made. */
static char *cache_path(const struct rs_repo *r, const char *sub)
{
    char *path;

    if (!r->cache)
    {
        return NULL;
    }
    path = rs_xasprintf("%s/%s", r->cache, sub);
    if (!make_dirs(path))
    {
        free(path);
        return NULL;
    }
    return path;
}

/* `len` bytes into the cache file `name` in `sub`, replacing it whole. */
static void cache_put(const struct rs_repo *r, const char *sub, const char *name,
                      const void *data, size_t len)
{
    char            *dir = cache_path(r, sub);
    struct rs_store *cache;
    char            *tmp;
    struct rs_buf    ignore;

    if (!dir)
    {
        return;
    }
    cache = rs_store_local(dir);
    tmp = rs_xasprintf(".%s.%ld.tmp", name, (long)getpid());
    rs_buf_init(&ignore);
    (void)rs_store_remove(cache, tmp, false);
    if (rs_store_write_new(cache, tmp, data, len, &ignore) &&
        rs_store_rename(cache, tmp, name, false) != 0)
    {
        (void)rs_store_remove(cache, tmp, false);
    }
    rs_buf_free(&ignore);
    free(tmp);
    rs_store_free(cache);
    free(dir);
}

/* The cache file `name` in `sub`, if there is one. */
static bool cache_get(const struct rs_repo *r, const char *sub, const char *name, size_t max,
                      struct rs_buf *out)
{
    struct rs_store *cache;
    char            *path;
    struct rs_buf    ignore;
    bool             ok;

    rs_buf_init(out);
    if (!r->cache)
    {
        return false;
    }
    cache = rs_store_local(r->cache);
    path = rs_xasprintf("%s/%s", sub, name);
    rs_buf_init(&ignore);
    ok = rs_store_read(cache, path, max, out, &ignore);
    rs_buf_free(&ignore);
    free(path);
    rs_store_free(cache);
    if (!ok)
    {
        rs_buf_free(out);
    }
    return ok;
}

/* Writes the marker anew as version 2: the first capture or prune into a
 * version 1 repository makes it one, so an older restate does not misread
 * what is written into it. */
static bool upgrade(struct rs_repo *r, struct rs_buf *err)
{
    char *text;
    char *tmp = rs_xasprintf(".%s.tmp", RS_REPO_MARKER);
    bool  ok;

    random_id(r->id);
    text = marker_text(r->id, false);
    (void)rs_store_remove(r->st, tmp, true);
    ok = rs_store_write_new(r->st, tmp, text, strlen(text), err);
    /* Its directory append-only where protect made it so: root's prune
     * replaces the marker all the same; a machine's capture cannot. */
    if (ok && rs_store_rename(r->st, tmp, RS_REPO_MARKER, true) != 0)
    {
        char *final = rs_store_path(r->st, RS_REPO_MARKER);

        rs_buf_addf(err, "%s: %s", final, strerror(errno));
        (void)rs_store_remove(r->st, tmp, true);
        free(final);
        ok = false;
    }
    if (ok)
    {
        rs_store_sync_dir(r->st, "");
        r->version = 2;
    }
    free(text);
    free(tmp);
    return ok;
}

/*
 * What the store is opened for: through restate-proxy, the session -- `look`,
 * `read`, or `append` for any capture, which there is always --append-only --
 * holds the locks, and nothing is read before it is open. A prune, a repack
 * and what only a process on the storage host does are refused there.
 */
static bool begin(struct rs_store *st, enum rs_repo_lock lock, bool *busy, struct rs_buf *err)
{
    enum rs_store_use use = lock == RS_REPO_LOOK ? RS_STORE_LOOK
                          : lock == RS_REPO_READ ? RS_STORE_READ
                                                 : RS_STORE_APPEND;

    if (rs_store_remote(st) && (lock == RS_REPO_PRUNE || lock == RS_REPO_HELD))
    {
        rs_buf_addf(err, "%s: what removes or rewrites what a repository holds is run on the "
                    "storage host, not through restate-proxy", rs_store_where(st));
        return false;
    }
    return rs_store_begin(st, use, busy, err);
}

static bool no_readers_lock;

void rs_repo_set_no_lock(bool no_lock)
{
    no_readers_lock = no_lock;
}

struct rs_repo *rs_repo_open(const char *dir, enum rs_repo_lock lock, bool *busy,
                             struct rs_buf *err)
{
    struct rs_repo *r = rs_xcalloc(1, sizeof(*r));
    struct rs_buf   text;
    bool            newer = false;
    bool            ok;

    *busy = false;
    r->st = rs_store_at(dir);
    r->dir = rs_xstrdup(dir);
    r->lock_fd = -1;
    r->readers_fd = -1;
    if (!begin(r->st, lock, busy, err))
    {
        rs_repo_close(r);
        return NULL;
    }
    ok = rs_store_read(r->st, RS_REPO_MARKER, 4096, &text, err);
    r->mode = lock;
    if (ok && !parse_marker(text.data, r, &newer))
    {
        rs_buf_addf(err, "%s: %s", dir,
                    newer ? "a repository made by a newer restate" : "not a restate repository");
        ok = false;
    }
    rs_buf_free(&text);
    if (ok && (lock == RS_REPO_APPEND || lock == RS_REPO_HELD) && r->version == 1)
    {
        rs_buf_addf(err, "%s: made by restate 1.3 or older, and adding to it would change its "
                    "marker, which --append-only does not; capture into it once without "
                    "--append-only", dir);
        ok = false;
    }
    if (ok && (lock == RS_REPO_WRITE || lock == RS_REPO_PRUNE || lock == RS_REPO_APPEND))
    {
        r->lock_fd = take(r->st, "lock", false, busy, err);
        ok = r->lock_fd >= 0;
    }
    if (ok && lock == RS_REPO_READ && no_readers_lock)
    {
        rs_warn("%s: read without its readers lock (--no-lock): a prune on the storage host "
                "while this runs is not kept out, and could remove what it is reading", dir);
    } else if (ok && (lock == RS_REPO_READ || lock == RS_REPO_PRUNE))
    {
        r->readers_fd = take(r->st, "readers", lock != RS_REPO_PRUNE, busy, err);
        ok = r->readers_fd >= 0;
    }
    if (ok && r->version == 1 && (lock == RS_REPO_WRITE || lock == RS_REPO_PRUNE))
    {
        ok = upgrade(r, err);
    }
    if (!ok)
    {
        rs_repo_close(r);
        return NULL;
    }
    /* A remote repository's whether or not it is encrypted: what is read of
     * it once is not asked of the proxy again. */
    if (r->encrypted || rs_store_remote(r->st))
    {
        r->cache = cache_dir(r->id);
    }
    list_packs(r);
    return r;
}

bool rs_repo_encrypted(const struct rs_repo *r)
{
    return r->encrypted;
}

const char *rs_repo_cache_path(const struct rs_repo *r)
{
    return r->cache;
}

uint64_t rs_repo_cache_bytes(const struct rs_repo *r)
{
    static const char *const subs[] = { "packs", "snapshots" };
    uint64_t                 bytes = 0;
    size_t                   k;

    for (k = 0; r->cache && k < sizeof(subs) / sizeof(subs[0]); k++)
    {
        char                *dir = rs_xasprintf("%s/%s", r->cache, subs[k]);
        DIR                 *d = opendir(dir);
        const struct dirent *de;

        while (d && (de = readdir(d)) != NULL)
        {
            char       *path = rs_xasprintf("%s/%s", dir, de->d_name);
            struct stat st;

            if (lstat(path, &st) == 0 && S_ISREG(st.st_mode))
            {
                bytes += (uint64_t)st.st_size;
            }
            free(path);
        }
        if (d)
        {
            (void)closedir(d);
        }
        free(dir);
    }
    return bytes;
}

void rs_repo_set_recipients(struct rs_repo *r, const char *const *recips, size_t n)
{
    r->recips = recips;
    r->nrecips = n;
}

void rs_repo_set_stop(struct rs_repo *r, bool (*stop)(void))
{
    r->stop = stop;
}

/* Whether a prune has been asked to stop where it is. */
static bool stopping(const struct rs_repo *r)
{
    return r->stop && r->stop();
}

/* The keys what is written now is encrypted to: none for a repository that
 * is not encrypted, whatever was given. */
static size_t seal_n(const struct rs_repo *r)
{
    return r->encrypted ? r->nrecips : 0;
}

void rs_repo_close(struct rs_repo *r)
{
    if (!r)
    {
        return;
    }
    rs_store_unlock(r->st, r->lock_fd);
    rs_store_unlock(r->st, r->readers_fd);
    rs_repo_free_names(r->packs, r->npacks);
    free(r->gear);
    map_free(&r->objects);
    map_free(&r->listed);
    free(r->lists);
    free(r->chunks);
    free(r->cache);
    free(r->dir);
    rs_store_free(r->st);
    free(r);
}

/* Forgets what load_objects learned, for it to learn again. */
static void unload(struct rs_repo *r)
{
    map_free(&r->objects);
    map_free(&r->listed);
    free(r->lists);
    free(r->chunks);
    r->lists = NULL;
    r->nlists = 0;
    r->chunks = NULL;
    r->nchunks = 0;
    r->unreadable = 0;
    r->loaded = false;
}

/* ------------------------------------------------------------------------- */
/* Packs' indexes                                                            */
/* ------------------------------------------------------------------------- */

/* A decimal number of at most 20 digits, ending at a space or the line's end. */
static bool number(const char **p, const char *end, uint64_t *out)
{
    const char *s = *p;
    uint64_t    v = 0;

    /* No sign, no leading zero: one spelling for each number. */
    if (s >= end || *s < '0' || *s > '9')
    {
        return false;
    }
    if (*s == '0' && s + 1 < end && s[1] >= '0' && s[1] <= '9')
    {
        return false;
    }
    while (s < end && *s >= '0' && *s <= '9')
    {
        unsigned d = (unsigned)(*s - '0');

        if (v > (UINT64_MAX - d) / 10)
        {
            return false;
        }
        v = v * 10 + d;
        s++;
    }
    *p = s;
    *out = v;
    return true;
}

/* Moves past `c` at *p, if that is what is there. */
static bool skip(const char **p, const char *end, char c)
{
    if (*p >= end || **p != c)
    {
        return false;
    }
    (*p)++;
    return true;
}

/* A digest's 64 hex digits at *p, into `hash`. */
static bool hex_digest(const char **p, const char *end, char hash[RS_SHA256_HEX_SIZE])
{
    if ((size_t)(end - *p) < RS_SHA256_HEX_LEN)
    {
        return false;
    }
    memcpy(hash, *p, RS_SHA256_HEX_LEN);
    hash[RS_SHA256_HEX_LEN] = '\0';
    *p += RS_SHA256_HEX_LEN;
    return rs_sha256_valid_hex(hash) != 0;
}

/* "= FILE SIZE CHUNK CHUNK ...": a file stored as two chunks or more. */
static bool parse_list(const char **p, const char *end, struct rs_repo_idx *x, size_t *cap)
{
    struct rs_repo_list l;
    bool                ok;

    memset(&l, 0, sizeof(l));
    l.first = x->nchunks;
    ok = skip(p, end, ' ') && hex_digest(p, end, l.hash) && skip(p, end, ' ') &&
         number(p, end, &l.size);
    while (ok && !skip(p, end, '\n'))
    {
        char hash[RS_SHA256_HEX_SIZE];

        ok = skip(p, end, ' ') && hex_digest(p, end, hash);
        if (ok)
        {
            if (x->nchunks == *cap)
            {
                *cap = *cap ? *cap * 2 : 64;
                x->chunks = rs_xreallocarray(x->chunks, *cap, sizeof(*x->chunks));
            }
            memcpy(x->chunks[x->nchunks++], hash, RS_SHA256_HEX_SIZE);
            l.n++;
        }
    }
    ok = ok && l.n >= 2;
    if (ok)
    {
        x->lists = rs_xreallocarray(x->lists, x->nlists + 1, sizeof(*x->lists));
        x->lists[x->nlists++] = l;
    }
    return ok;
}

void rs_repo_idx_free(struct rs_repo_idx *x)
{
    free(x->members);
    free(x->lists);
    free(x->chunks);
    memset(x, 0, sizeof(*x));
}

bool rs_repo_parse_idx(const char *text, size_t len, struct rs_repo_idx *x)
{
    const char *p = text;
    const char *end = text + len;
    size_t      cap = 0;
    size_t      chunk_cap = 0;
    bool        v2;
    bool        ok = true;

    memset(x, 0, sizeof(*x));
    v2 = len >= strlen(PACK_FORMAT) && memcmp(text, PACK_FORMAT, strlen(PACK_FORMAT)) == 0;
    if (!v2 && (len < strlen(PACK_FORMAT_1) ||
                memcmp(text, PACK_FORMAT_1, strlen(PACK_FORMAT_1)) != 0))
    {
        return false;
    }
    p += strlen(PACK_FORMAT);
    while (ok && p < end)
    {
        struct rs_repo_member m;

        if (v2 && skip(&p, end, '='))
        {
            ok = parse_list(&p, end, x, &chunk_cap);
            continue;
        }
        memset(&m, 0, sizeof(m));
        ok = number(&p, end, &m.member) && m.member <= UINT32_MAX && skip(&p, end, ' ');
        if (ok && !skip(&p, end, '-'))
        {
            ok = hex_digest(&p, end, m.hash);
            m.live = true;
        }
        ok = ok && skip(&p, end, ' ') && number(&p, end, &m.size) && skip(&p, end, '\n') &&
             (x->nmembers == 0 || m.member > x->members[x->nmembers - 1].member);
        if (ok)
        {
            if (x->nmembers == cap)
            {
                cap = cap ? cap * 2 : 64;
                x->members = rs_xreallocarray(x->members, cap, sizeof(*x->members));
            }
            x->members[x->nmembers++] = m;
        }
    }
    if (!ok)
    {
        rs_repo_idx_free(x);
    }
    return ok;
}

bool rs_repo_parse_seek(const char *text, size_t len, struct rs_repo_seek **out, size_t *n)
{
    const char          *p = text;
    const char          *end = text + len;
    struct rs_repo_seek *at = NULL;
    size_t               cap = 0;
    size_t               k = 0;
    bool                 ok;

    *out = NULL;
    *n = 0;
    ok = len >= strlen(SEEK_FORMAT) && memcmp(text, SEEK_FORMAT, strlen(SEEK_FORMAT)) == 0;
    p += ok ? strlen(SEEK_FORMAT) : 0;
    while (ok && p < end)
    {
        struct rs_repo_seek e;

        ok = number(&p, end, &e.member) && skip(&p, end, ' ') && number(&p, end, &e.offset) &&
             skip(&p, end, '\n') &&
             (k == 0 ? e.member == 1 && e.offset == 0
                     : e.member > at[k - 1].member && e.offset > at[k - 1].offset);
        if (ok)
        {
            if (k == cap)
            {
                cap = cap ? cap * 2 : 16;
                at = rs_xreallocarray(at, cap, sizeof(*at));
            }
            at[k++] = e;
        }
    }
    if (!ok || k == 0)
    {
        free(at);
        return false;
    }
    *out = at;
    *n = k;
    return true;
}

/* A pack's .idx: this machine's copy of it if the repository is encrypted
 * and it has one, else the repository's, decrypted -- unless `decrypt` is
 * false, *sealed then saying why not -- and then cached. */
static bool pack_idx_sealed(const struct rs_repo *r, const char *pack, struct rs_repo_idx *x,
                            bool decrypt, bool *sealed, struct rs_buf *err)
{
    char         *name = rs_xasprintf("%s.idx", pack);
    char         *file = rs_xasprintf("packs/%s", name);
    char         *path = rs_store_path(r->st, file);
    struct rs_buf text;
    bool          cached = cache_get(r, "packs", name, SMALL_MAX, &text);
    bool          ok;

    *sealed = false;
    ok = cached || read_sealed(r->st, file, SMALL_MAX, decrypt, &text, sealed, err);

    memset(x, 0, sizeof(*x));
    if (ok && !rs_repo_parse_idx(text.data, text.len, x))
    {
        rs_buf_addf(err, "%s: not a pack index restate wrote", path);
        ok = false;
    }
    if (ok && !cached)
    {
        cache_put(r, "packs", name, text.data, text.len);
    }
    rs_buf_free(&text);
    free(path);
    free(file);
    free(name);
    return ok;
}

static bool pack_idx(const struct rs_repo *r, const char *pack, struct rs_repo_idx *x,
                     struct rs_buf *err)
{
    bool sealed;

    return pack_idx_sealed(r, pack, x, true, &sealed, err);
}

/* Through restate-proxy, the .idx of every pack this machine has no copy of,
 * fetched in one curl rather than one each. */
static void prefetch_idx(const struct rs_repo *r)
{
    char  **want;
    size_t  n = 0;
    size_t  i;

    if (!rs_store_remote(r->st) || r->npacks == 0)
    {
        return;
    }
    want = rs_xcalloc(r->npacks, sizeof(*want));
    for (i = 0; i < r->npacks; i++)
    {
        char         *name = rs_xasprintf("%s.idx", r->packs[i]);
        struct rs_buf text;

        if (cache_get(r, "packs", name, SMALL_MAX, &text))
        {
            rs_buf_free(&text);
        } else
        {
            want[n++] = rs_xasprintf("packs/%s", name);
        }
        free(name);
    }
    rs_store_prefetch(r->st, (const char *const *)want, n);
    rs_repo_free_names(want, n);
}

/*
 * Every live chunk in every pack, once, and every list whose chunks are all
 * there. A pack whose .idx cannot be read is passed over, with a warning: its
 * content is as good as gone.
 */
static void load_objects(struct rs_repo *r)
{
    size_t i;
    size_t chunk_cap = 0;
    size_t list_cap = 0;
    size_t passed = 0;
    bool   decrypt = true;

    if (r->loaded)
    {
        return;
    }
    r->loaded = true;
    prefetch_idx(r);
    for (i = 0; i < r->npacks; i++)
    {
        struct rs_repo_idx x;
        struct rs_buf      err;
        size_t             k;
        bool               sealed = false;

        rs_buf_init(&err);
        if (!pack_idx_sealed(r, r->packs[i], &x, decrypt, &sealed, &err))
        {
            r->unreadable++;
            /* One that cannot be decrypted says the key is not here: the
             * rest are not tried, each asking gpg in vain. */
            if (sealed && !decrypt)
            {
                passed++;
            } else
            {
                rs_warn("%s", err.data);
            }
            decrypt = decrypt && !sealed;
        }
        for (k = 0; k < x.nmembers; k++)
        {
            unsigned char d[32];

            if (x.members[k].live && unhex(x.members[k].hash, d))
            {
                (void)map_add(&r->objects, d, (uint32_t)i, (uint32_t)x.members[k].member);
            }
        }
        for (k = 0; k < x.nlists; k++)
        {
            const struct rs_repo_list *l = &x.lists[k];
            struct list               *to;
            size_t                     c;

            if (r->nlists == list_cap)
            {
                list_cap = list_cap ? list_cap * 2 : 64;
                r->lists = rs_xreallocarray(r->lists, list_cap, sizeof(*r->lists));
            }
            to = &r->lists[r->nlists];
            if (!unhex(l->hash, to->d))
            {
                continue;
            }
            to->size = l->size;
            to->pack = (uint32_t)i;
            to->first = r->nchunks;
            to->n = 0;
            for (c = 0; c < l->n; c++)
            {
                if (r->nchunks == chunk_cap)
                {
                    chunk_cap = chunk_cap ? chunk_cap * 2 : 1024;
                    r->chunks = rs_xreallocarray(r->chunks, chunk_cap, sizeof(*r->chunks));
                }
                if (unhex(x.chunks[l->first + c], r->chunks[r->nchunks]))
                {
                    r->nchunks++;
                    to->n++;
                }
            }
            r->nlists++;
        }
        rs_repo_idx_free(&x);
        rs_buf_free(&err);
    }
    if (passed > 0)
    {
        rs_warn("%s: %zu more packs' indexes are encrypted, and this machine has no copy of "
                "them; what is in them is stored again where it is needed", r->dir, passed);
    }
    /* A list counts only once every chunk of it is somewhere. */
    for (i = 0; i < r->nlists; i++)
    {
        const struct list *l = &r->lists[i];
        size_t             c;
        bool               whole = l->n >= 2;

        for (c = 0; whole && c < l->n; c++)
        {
            whole = map_find(&r->objects, r->chunks[l->first + c]) != NULL;
        }
        if (whole && !map_find(&r->listed, l->d))
        {
            (void)map_add(&r->listed, l->d, l->pack, (uint32_t)i);
        }
    }
}

/* Marks, in `used` (per pack of r->packs), the packs the content with digest
 * `d` is in: its chunk, or its list and that list's chunks. Content added by
 * a writer that has not finished yet has no pack to mark. */
static void mark_content(const struct rs_repo *r, const unsigned char d[32], bool *used)
{
    const struct obj *o = map_find(&r->objects, d);
    const struct obj *l = map_find(&r->listed, d);

    if (o && o->pack < r->npacks)
    {
        used[o->pack] = true;
    }
    if (l && l->pack < r->npacks && l->member < r->nlists)
    {
        const struct list *li = &r->lists[l->member];
        size_t             c;

        used[l->pack] = true;
        for (c = 0; c < li->n; c++)
        {
            const struct obj *ch = map_find(&r->objects, r->chunks[li->first + c]);

            if (ch && ch->pack < r->npacks)
            {
                used[ch->pack] = true;
            }
        }
    }
}

/* Marks the packs every file with content in `ix` needs. */
static void mark_index(const struct rs_repo *r, const struct rs_index *ix, bool *used)
{
    size_t i;

    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];
        unsigned char          d[32];

        if (e->stored && e->type == 'f' && e->hash_state == RS_HASH_PRESENT && unhex(e->hash, d))
        {
            mark_content(r, d, used);
        }
    }
}

/* A pack list naming the packs `used` marks of r->packs, and `more`: in
 * order, each once. */
static char *pack_list_text(const struct rs_repo *r, const bool *used, char *const *more,
                            size_t nmore, size_t *len)
{
    char        **all = rs_xcalloc(r->npacks + nmore + 1, sizeof(*all));
    size_t        n = 0;
    size_t        i;
    struct rs_buf text;

    for (i = 0; i < r->npacks; i++)
    {
        if (used[i])
        {
            all[n++] = r->packs[i];
        }
    }
    for (i = 0; i < nmore; i++)
    {
        all[n++] = more[i];
    }
    if (n > 1)
    {
        qsort(all, n, sizeof(*all), by_name);
    }
    rs_buf_init(&text);
    rs_buf_addstr(&text, PACKS_FORMAT);
    for (i = 0; i < n; i++)
    {
        if (i == 0 || strcmp(all[i], all[i - 1]) != 0)
        {
            rs_buf_addf(&text, "%s\n", all[i]);
        }
    }
    free(all);
    *len = text.len;
    return rs_buf_detach(&text);
}

/* ------------------------------------------------------------------------- */
/* Snapshots                                                                 */
/* ------------------------------------------------------------------------- */

static bool is_snapshot(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                        char **out)
{
    char *index = rs_xasprintf("%s/%s/index.json.gz", dir, name);
    bool  ok = rs_repo_name_valid(name) && rs_store_is_file(st, index);

    (void)ctx;
    free(index);
    if (ok)
    {
        *out = rs_xstrdup(name);
    }
    return ok;
}

char **rs_repo_snapshots(const struct rs_repo *r, size_t *n)
{
    return rs_store_list(r->st, "snapshots", is_snapshot, NULL, n);
}

char *rs_repo_resolve(struct rs_repo *r, const char *name, struct rs_buf *err)
{
    size_t n;
    char **names = rs_repo_snapshots(r, &n);
    char  *found = NULL;

    if (!name)
    {
        if (n == 0)
        {
            rs_buf_addf(err, "%s: there are no snapshots in it yet", r->dir);
        } else
        {
            found = rs_xstrdup(names[n - 1]);
        }
    } else
    {
        size_t i;

        for (i = 0; i < n && !found; i++)
        {
            if (strcmp(names[i], name) == 0)
            {
                found = rs_xstrdup(name);
            }
        }
        if (!found)
        {
            rs_buf_addf(err, "%s: there is no snapshot \"%s\" in it (restate snapshots %s "
                        "lists them)", r->dir, name, r->dir);
        }
    }
    rs_repo_free_names(names, n);
    return found;
}

/* A snapshot's file `file`, by its name in the repository. */
static char *snapshot_file(const char *name, const char *file)
{
    return rs_xasprintf("snapshots/%s/%s", name, file);
}

bool rs_repo_index_bytes(const struct rs_repo *r, const char *name, struct rs_buf *gz,
                         struct rs_buf *sig, struct rs_buf *err)
{
    char                *path = snapshot_file(name, "index.json.gz");
    struct rs_store_stat st;
    bool                 ok;

    rs_buf_free(gz);
    ok = rs_repo_name_valid(name) && rs_store_read(r->st, path, RS_IMAGE_INDEX_MAX, gz, err);
    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "\"%s\" is not the name of a snapshot", name);
    }
    free(path);
    path = snapshot_file(name, "index.sig");
    rs_buf_reset(sig);
    if (ok && rs_store_stat(r->st, path, &st) == 0)
    {
        struct rs_buf text;

        ok = rs_store_read(r->st, path, (size_t)64 * 1024, &text, err);
        if (ok)
        {
            rs_buf_add(sig, text.data, text.len);
        }
        rs_buf_free(&text);
    }
    free(path);
    return ok;
}

/* Parses a snapshot's index from `gz`, the bytes of it as stored --
 * encrypted, or not -- whose digest becomes ix->part_sha256. */
static bool parse_index(const struct rs_buf *gz, const char *label, struct rs_index *ix,
                        struct rs_buf *err)
{
    struct rs_buf text;
    FILE         *tmp;
    bool          ok;

    /* Handed to gzip from a file of its own: the bytes whose digest is
     * taken are the bytes that are read. */
    rs_sha256_hex(gz->data ? gz->data : "", gz->len, ix->part_sha256);
    rs_buf_init(&text);
    tmp = rs_tmpfile();
    ok = tmp && (gz->len == 0 || fwrite(gz->data ? gz->data : "", 1, gz->len, tmp) == gz->len) &&
         fflush(tmp) == 0 && lseek(fileno(tmp), 0, SEEK_SET) == 0;
    if (!ok)
    {
        rs_buf_addf(err, "%s: a temporary file for its index: %s", label, strerror(errno));
    }
    if (ok && !slurp_fd(label, fileno(tmp), true, RS_IMAGE_INDEX_MAX, &text, err))
    {
        rs_buf_reset(err);
        rs_buf_addf(err, "%s: its index could not be read", label);
        ok = false;
    }
    if (tmp)
    {
        (void)fclose(tmp);
    }
    ok = ok && rs_index_parse(ix, text.data, text.len, label, err);
    if (ok)
    {
        ix->in_parts = true;
    }
    rs_buf_free(&text);
    return ok;
}

bool rs_repo_load_index(struct rs_repo *r, const char *name, struct rs_index *ix,
                        struct rs_buf *err)
{
    struct rs_buf gz;
    struct rs_buf sig;
    char         *label = rs_xasprintf("%s" RS_REPO_SEP "%s", r->dir, name);
    bool          ok;

    rs_buf_init(&gz);
    rs_buf_init(&sig);
    ok = rs_repo_index_bytes(r, name, &gz, &sig, err);
    if (ok && !parse_index(&gz, label, ix, err))
    {
        /* Say why decrypting failed, where that is why. */
        if (rs_pgp_detect((const unsigned char *)gz.data, gz.len))
        {
            rs_buf_addf(err, "; it is encrypted, and could not be decrypted: the secret key "
                        "for it is not in %s, or its passphrase was not given",
                        rs_pgp_key_place());
        }
        ok = false;
    }
    rs_buf_free(&gz);
    rs_buf_free(&sig);
    free(label);
    return ok;
}

bool rs_repo_load_index_cached(struct rs_repo *r, const char *name, struct rs_index *ix,
                               struct rs_buf *err)
{
    struct rs_buf gz;
    char         *file = rs_xasprintf("%s.json.gz", name);
    char         *label = rs_xasprintf("%s" RS_REPO_SEP "%s", r->dir, name);
    bool          ok = false;

    if (rs_repo_name_valid(name) && cache_get(r, "snapshots", file, RS_IMAGE_INDEX_MAX, &gz))
    {
        struct rs_buf ignore;

        rs_buf_init(&ignore);
        ok = parse_index(&gz, label, ix, &ignore);
        rs_buf_free(&ignore);
        rs_buf_free(&gz);
        if (!ok)
        {
            rs_index_free(ix);
            rs_index_init(ix);
        }
    }
    free(file);
    free(label);
    return ok || rs_repo_load_index(r, name, ix, err);
}

bool rs_repo_add_signature(struct rs_repo *r, const char *name, const void *sig, size_t len,
                           struct rs_buf *err)
{
    char                *path;
    struct rs_store_stat st;
    bool                 ok;

    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "\"%s\" is not the name of a snapshot", name);
        return false;
    }
    path = snapshot_file(name, "index.sig");
    if (rs_store_stat(r->st, path, &st) == 0)
    {
        rs_buf_addf(err, "%s" RS_REPO_SEP "%s: it is signed already", r->dir, name);
        free(path);
        return false;
    }
    /* Into a snapshot protect made immutable, as root. */
    ok = rs_store_write_new_thawed(r->st, path, sig, len, err);
    free(path);
    return ok;
}

bool rs_repo_kit(const struct rs_repo *r, const char *name, char ***paths, size_t *n,
                 struct rs_buf *err)
{
    char         *path = snapshot_file(name, "kit");
    struct rs_buf text;
    const char   *p;
    bool          ok = rs_repo_name_valid(name) && read_plain(r->st, path, SMALL_MAX, &text, err);

    *paths = NULL;
    *n = 0;
    free(path);
    if (!ok)
    {
        if (!rs_repo_name_valid(name))
        {
            rs_buf_addf(err, "\"%s\" is not the name of a snapshot", name);
        } else
        {
            rs_buf_free(&text);
        }
        return false;
    }
    for (p = text.data; *p; )
    {
        size_t len = strcspn(p, "\n");

        if (len > 0 && p[0] == '/')
        {
            *paths = rs_xreallocarray(*paths, *n + 1, sizeof(**paths));
            (*paths)[(*n)++] = rs_xstrndup(p, len);
        }
        p += len + (p[len] == '\n' ? 1 : 0);
    }
    rs_buf_free(&text);
    return true;
}

bool rs_repo_info(const struct rs_repo *r, const char *name, struct rs_jval *info,
                  struct rs_buf *err)
{
    char                 *path = snapshot_file(name, "info");
    struct rs_buf         text;
    struct rs_json_parser jp;
    bool                  ok = rs_repo_name_valid(name) &&
                               read_plain(r->st, path, SMALL_MAX, &text, err);

    memset(info, 0, sizeof(*info));
    if (ok)
    {
        rs_json_init(&jp, text.data, text.len, err);
        ok = rs_json_value(&jp, info) && rs_json_at_end(&jp) && info->type == RS_JOBJECT;
        if (!ok)
        {
            rs_jval_free(info);
            memset(info, 0, sizeof(*info));
            char *where = rs_store_path(r->st, path);

            rs_buf_reset(err);
            rs_buf_addf(err, "%s: not a summary restate wrote", where);
            free(where);
        }
    }
    if (rs_repo_name_valid(name) || ok)
    {
        rs_buf_free(&text);
    }
    free(path);
    return ok;
}

char *rs_repo_snapshot_name(const char *created)
{
    char           buf[RS_TIME_STR_MAX];
    struct rs_time t;
    struct tm      tm;
    time_t         sec;

    memset(&t, 0, sizeof(t));
    if (!created || !rs_time_parse(created, &t))
    {
        t.sec = (int64_t)time(NULL);
    }
    sec = (time_t)t.sec;
    if (!gmtime_r(&sec, &tm) || strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm) == 0)
    {
        return rs_xstrdup("snapshot");
    }
    return rs_xstrdup(buf);
}

/* ------------------------------------------------------------------------- */
/* Writing packs                                                             */
/* ------------------------------------------------------------------------- */

static uint64_t pack_size = RS_REPO_PACK_SIZE;
static uint64_t segment_size = RS_REPO_SEGMENT_SIZE;

void rs_repo_set_pack_size(uint64_t bytes)
{
    pack_size = bytes ? bytes : RS_REPO_PACK_SIZE;
}

void rs_repo_set_segment_size(uint64_t bytes)
{
    segment_size = bytes ? bytes : RS_REPO_SEGMENT_SIZE;
}

/*
 * A pack being written. gzip (and gpg) write it into a pipe, `tap`, rather
 * than into the file: restate reads the pipe into the file, digesting what it
 * writes as it goes, so the pack's .sum needs no second read of the whole of
 * it -- which, over NFS, would be as much I/O again as writing it.
 */
struct pack_out {
    bool                   open;
    char                  *name;      /* without ".tar.gz" */
    const struct rs_store *st;        /* where it goes */
    char                  *tmp;       /* its content, until it is complete */
    char                  *tmp_path;  /* where that is, for messages */
    int                    fd;
    int                    tap;       /* what gzip or gpg writes; -1 at its end */
    int                    write_errno; /* the first write into `fd` that failed */
    struct rs_sha256       sha;       /* of what is written into `fd` */
    uint64_t               written;
    struct zout            z;
    struct rs_tar_writer   tar;
    struct rs_buf          idx;
    uint64_t               seq;
    /* Unless it is encrypted -- gpg reads only from the start -- gzip begins
     * again every segment_size, and `seek` says where. */
    bool                   seekable;
    uint64_t               segment_at; /* the tar offset the segment began at */
    struct rs_buf          seek;
};

/* How many packs this process has begun: with the time and the process,
 * what makes each one's name its own. */
static unsigned packs_begun;

/* A name for a new pack, "20261011T030000Z-1234-0001": when, which process,
 * and how many it has begun before -- and, should one by that name be there
 * all the same, the next number. */
static char *pack_name(const struct rs_repo *r)
{
    char      when[32];
    struct tm tm;
    time_t    now = time(NULL);
    char     *name = NULL;

    if (!gmtime_r(&now, &tm) || strftime(when, sizeof(when), "%Y%m%dT%H%M%SZ", &tm) == 0)
    {
        (void)snprintf(when, sizeof(when), "%lld", (long long)now);
    }
    for (;;)
    {
        struct rs_store_stat st;
        char                *idx;
        char                *content;
        bool                 taken;

        free(name);
        name = rs_xasprintf("%s-%ld-%04u", when, (long)getpid(), ++packs_begun);
        idx = rs_xasprintf("packs/%s.idx", name);
        content = rs_xasprintf("packs/%s.tar.gz", name);
        taken = rs_store_stat(r->st, idx, &st) == 0 || rs_store_stat(r->st, content, &st) == 0;
        free(idx);
        free(content);
        if (!taken)
        {
            return name;
        }
    }
}

/*
 * What gzip or gpg has written so far, into the pack's file and its digest:
 * all there is now, or, if `to_end`, all until they close it. False once it
 * is at its end. A write into the file that fails is remembered, and the
 * rest read all the same, so that gzip is never left blocked on a full pipe.
 */
static bool pack_take(struct pack_out *pk, bool to_end)
{
    unsigned char chunk[65536];

    while (pk->tap >= 0)
    {
        ssize_t n = read(pk->tap, chunk, sizeof(chunk));

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0 && errno == EAGAIN && to_end)
        {
            struct pollfd fd = { pk->tap, POLLIN, 0 };

            (void)poll(&fd, 1, -1);
            continue;
        }
        if (n < 0 && errno == EAGAIN)
        {
            return true;
        }
        if (n <= 0)
        {
            if (n < 0 && pk->write_errno == 0)
            {
                pk->write_errno = errno;
            }
            (void)close(pk->tap);
            pk->tap = -1;
            break;
        }
        rs_sha256_update(&pk->sha, chunk, (size_t)n);
        pk->written += (uint64_t)n;
        if (pk->write_errno == 0 && !write_all(pk->fd, chunk, (size_t)n))
        {
            pk->write_errno = errno;
        }
    }
    return false;
}

/* The tar writer's output, into gzip -- taking what gzip has written while
 * waiting for room, as neither can wait on the other. */
static bool pack_feed(void *ctx, const void *data, size_t n)
{
    struct pack_out *pk = ctx;
    const char      *p = data;

    while (n > 0)
    {
        struct pollfd fds[2];
        nfds_t        nfds = 1;
        ssize_t       w;

        fds[0].fd = pk->z.fd;
        fds[0].events = POLLOUT;
        fds[0].revents = 0;
        if (pk->tap >= 0)
        {
            fds[1].fd = pk->tap;
            fds[1].events = POLLIN;
            fds[1].revents = 0;
            nfds = 2;
        }
        if (poll(fds, nfds, -1) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (nfds == 2 && fds[1].revents != 0)
        {
            (void)pack_take(pk, false);
        }
        if (fds[0].revents == 0)
        {
            continue;
        }
        w = write(pk->z.fd, p, n);
        if (w < 0 && (errno == EAGAIN || errno == EINTR))
        {
            continue;
        }
        if (w < 0)
        {
            return false;
        }
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/* The pipe gzip or gpg writes the pack into, read by pack_take. */
static bool pack_pipe(int p[2], struct rs_buf *err)
{
    int i;

    if (pipe(p) < 0)
    {
        rs_buf_addf(err, "pipe: %s", strerror(errno));
        return false;
    }
    for (i = 0; i < 2; i++)
    {
        (void)fcntl(p[i], F_SETFD, FD_CLOEXEC);
    }
    (void)fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
    return true;
}

/* What pack_open made, let go again. */
static void pack_unmake(struct pack_out *pk)
{
    (void)close(pk->fd);
    (void)rs_store_remove(pk->st, pk->tmp, false);
    free(pk->name);
    free(pk->tmp);
    free(pk->tmp_path);
    memset(pk, 0, sizeof(*pk));
}

static bool pack_open(const struct rs_repo *r, struct pack_out *pk, struct rs_buf *err)
{
    int p[2];

    memset(pk, 0, sizeof(*pk));
    pk->st = r->st;
    pk->name = pack_name(r);
    pk->tmp = rs_xasprintf("packs/.%s.tar.gz.tmp", pk->name);
    pk->tmp_path = rs_store_path(r->st, pk->tmp);
    pk->fd = rs_store_create(r->st, pk->tmp);
    if (pk->fd < 0)
    {
        rs_buf_addf(err, "%s: %s", pk->tmp_path, strerror(errno));
        free(pk->name);
        free(pk->tmp);
        free(pk->tmp_path);
        memset(pk, 0, sizeof(*pk));
        return false;
    }
    if (!pack_pipe(p, err))
    {
        pack_unmake(pk);
        return false;
    }
    if (!zout_open(&pk->z, p[1], true, r->recips, seal_n(r), err))
    {
        (void)close(p[0]);
        (void)close(p[1]);
        pack_unmake(pk);
        return false;
    }
    /* gzip or gpg has the pipe now: with our copy closed, its end is theirs. */
    (void)close(p[1]);
    pk->tap = p[0];
    rs_sha256_init(&pk->sha);
    (void)fcntl(pk->z.fd, F_SETFL, fcntl(pk->z.fd, F_GETFL) | O_NONBLOCK);
    rs_tar_writer_init(&pk->tar, pack_feed, pk);
    rs_buf_init(&pk->idx);
    rs_buf_addstr(&pk->idx, PACK_FORMAT);
    pk->seekable = !pk->z.sealed;
    rs_buf_init(&pk->seek);
    rs_buf_addstr(&pk->seek, SEEK_FORMAT "1 0\n");
    pk->open = true;
    return true;
}

static void pack_discard(struct pack_out *pk)
{
    struct rs_buf ignore;

    if (!pk->open)
    {
        return;
    }
    /* Closed first, so that gzip or gpg, writing, is stopped rather than
     * left blocked on a pipe nobody reads. */
    if (pk->tap >= 0)
    {
        (void)close(pk->tap);
        pk->tap = -1;
    }
    rs_buf_init(&ignore);
    (void)zout_close(&pk->z, true, &ignore);
    rs_buf_free(&ignore);
    rs_buf_free(&pk->idx);
    rs_buf_free(&pk->seek);
    pack_unmake(pk);
}

/* Finishes the pack: its content in place, then its .idx, which is what makes
 * it count. Its name, on success, into *done. */
static bool pack_close(const struct rs_repo *r, struct pack_out *pk, char **done,
                       struct rs_buf *err)
{
    char *final = rs_xasprintf("packs/%s.tar.gz", pk->name);
    char *idx = rs_xasprintf("packs/.%s.idx.tmp", pk->name);
    char *idx_final = rs_xasprintf("packs/%s.idx", pk->name);
    char *seek = rs_xasprintf("packs/.%s.seek.tmp", pk->name);
    char *seek_final = rs_xasprintf("packs/%s.seek", pk->name);
    bool  ok = rs_tar_finish(&pk->tar);
    char  hex[RS_SHA256_HEX_SIZE];

    if (ok)
    {
        /* The end of gzip's input; then the rest of what it writes, to its
         * end, before waiting for it -- which would otherwise wait forever on
         * a gzip blocked writing into a full pipe. */
        (void)close(pk->z.fd);
        pk->z.gz.fd = -1;
        pk->z.fd = -1;
        (void)pack_take(pk, true);
    } else if (pk->tap >= 0)
    {
        (void)close(pk->tap);
        pk->tap = -1;
    }
    if (!zout_close(&pk->z, !ok, err))
    {
        ok = false;
    }
    if (ok && pk->write_errno != 0)
    {
        rs_buf_addf(err, "%s: %s", pk->tmp_path, strerror(pk->write_errno));
        ok = false;
    }
    rs_sha256_final(&pk->sha, hex);
    if (ok && fsync(pk->fd) != 0)
    {
        ok = false;
    }
    if (close(pk->fd) != 0)
    {
        ok = false;
    }
    if (!ok && err->len == 0)
    {
        rs_buf_addf(err, "%s: %s", pk->tmp_path, strerror(errno));
    }
    if (ok && rs_store_rename(r->st, pk->tmp, final, false) != 0)
    {
        renamed_failed(r->st, final, err);
        ok = false;
    }
    /* Its .sum before its .idx: a pack that counts has one. */
    ok = ok && put_sum(r->st, pk->name, hex, pk->written, err);
    /* Then its .seek: what reads it from the middle trusts nothing in it
     * that the content does not bear out. */
    if (ok && pk->seekable)
    {
        ok = write_out(r->st, seek, pk->seek.data, pk->seek.len, false, NULL, 0, err);
        if (ok && rs_store_rename(r->st, seek, seek_final, false) != 0)
        {
            renamed_failed(r->st, seek_final, err);
            ok = false;
        }
    }
    ok = ok && write_out(r->st, idx, pk->idx.data, pk->idx.len, false, r->recips, seal_n(r), err);
    if (ok && rs_store_rename(r->st, idx, idx_final, false) != 0)
    {
        renamed_failed(r->st, idx_final, err);
        ok = false;
    }
    if (ok)
    {
        char *name = rs_xasprintf("%s.idx", pk->name);

        cache_put(r, "packs", name, pk->idx.data, pk->idx.len);
        free(name);
    }
    if (!ok)
    {
        char *sum = rs_xasprintf("packs/%s.sum", pk->name);

        (void)rs_store_remove(r->st, pk->tmp, false);
        (void)rs_store_remove(r->st, final, false);
        (void)rs_store_remove(r->st, idx, false);
        (void)rs_store_remove(r->st, sum, false);
        (void)rs_store_remove(r->st, seek, false);
        (void)rs_store_remove(r->st, seek_final, false);
        free(sum);
    }
    free(final);
    free(idx);
    free(idx_final);
    free(seek);
    free(seek_final);
    free(pk->tmp);
    free(pk->tmp_path);
    rs_buf_free(&pk->idx);
    rs_buf_free(&pk->seek);
    *done = ok ? pk->name : NULL;
    if (!ok)
    {
        free(pk->name);
    }
    memset(pk, 0, sizeof(*pk));
    return ok;
}

/*
 * Ends the segment: gzip is told its input is over, and what it writes is
 * taken to its end; then a new gzip, writing into a new pipe, whose output
 * begins where the next member, its first, will be.
 */
static bool pack_cut(struct pack_out *pk, struct rs_buf *err)
{
    int  p[2];
    bool ok;

    (void)close(pk->z.fd);
    pk->z.gz.fd = -1;
    pk->z.fd = -1;
    (void)pack_take(pk, true);
    ok = zout_close(&pk->z, false, err);
    if (ok && pk->write_errno != 0)
    {
        rs_buf_addf(err, "%s: %s", pk->tmp_path, strerror(pk->write_errno));
        ok = false;
    }
    if (!ok || !pack_pipe(p, err))
    {
        return false;
    }
    if (!zout_open(&pk->z, p[1], true, NULL, 0, err))
    {
        (void)close(p[0]);
        (void)close(p[1]);
        return false;
    }
    (void)close(p[1]);
    pk->tap = p[0];
    (void)fcntl(pk->z.fd, F_SETFL, fcntl(pk->z.fd, F_GETFL) | O_NONBLOCK);
    pk->segment_at = pk->tar.offset;
    rs_buf_addf(&pk->seek, "%" PRIu64 " %" PRIu64 "\n", pk->seq + 1, pk->written);
    return true;
}

/* The header of the pack's next member, `size` bytes, numbered -- first in
 * a segment of its own, once the one before is full. */
static bool pack_header(struct pack_out *pk, uint64_t size, struct rs_buf *err)
{
    struct rs_tar_member m;
    char                *num;
    bool                 ok;

    if (pk->seekable && pk->seq > 0 && pk->tar.offset - pk->segment_at >= segment_size &&
        !pack_cut(pk, err))
    {
        return false;
    }
    num = rs_xasprintf("%" PRIu64, ++pk->seq);
    memset(&m, 0, sizeof(m));
    m.name = num;
    m.typeflag = '0';
    m.mode = 0600;
    m.size = size;
    ok = rs_tar_header(&pk->tar, &m);
    free(num);
    return ok;
}

static void pack_line(struct pack_out *pk, const char *hash, uint64_t size)
{
    rs_buf_addf(&pk->idx, "%" PRIu64 " %s %" PRIu64 "\n", pk->seq, hash ? hash : "-", size);
}

/* A file stored as the chunks `chunks`, in the pack's .idx. */
static void pack_list(struct pack_out *pk, const unsigned char d[32], uint64_t size,
                      const unsigned char (*chunks)[32], size_t n)
{
    char   hex[RS_SHA256_HEX_SIZE];
    size_t i;

    to_hex(d, hex);
    rs_buf_addf(&pk->idx, "= %s %" PRIu64, hex, size);
    for (i = 0; i < n; i++)
    {
        to_hex(chunks[i], hex);
        rs_buf_addf(&pk->idx, " %s", hex);
    }
    rs_buf_addc(&pk->idx, '\n');
}

/* ------------------------------------------------------------------------- */
/* Chunks                                                                    */
/* ------------------------------------------------------------------------- */

/* A random number for each byte value, the same every time: splitmix64 from
 * a fixed seed, so the table need not be written out. */
static uint64_t gear[256];
static bool     gear_made;

static void make_gear(void)
{
    uint64_t x = 0x7265737461746531ULL;   /* "restate1" */
    size_t   i;

    for (i = 0; i < 256; i++)
    {
        uint64_t z;

        x += 0x9e3779b97f4a7c15ULL;
        z = x;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        gear[i] = z ^ (z >> 31);
    }
    gear_made = true;
}

static size_t cut_with(const uint64_t *table, const unsigned char *p, size_t n);

size_t rs_repo_chunk_cut(const unsigned char *p, size_t n)
{
    if (!gear_made)
    {
        make_gear();
    }
    return cut_with(gear, p, n);
}

/* The table a key gives: each byte value's number the first eight bytes of
 * SHA-256(key, value). */
static void keyed_gear(const unsigned char key[32], uint64_t table[256])
{
    size_t i;

    for (i = 0; i < 256; i++)
    {
        struct rs_sha256 ctx;
        char             hex[RS_SHA256_HEX_SIZE];
        unsigned char    b = (unsigned char)i;
        uint64_t         v = 0;
        size_t           k;

        rs_sha256_init(&ctx);
        rs_sha256_update(&ctx, key, 32);
        rs_sha256_update(&ctx, &b, 1);
        rs_sha256_final(&ctx, hex);
        for (k = 0; k < 16; k++)
        {
            char c = hex[k];

            v = (v << 4) | (uint64_t)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        table[i] = v;
    }
}

size_t rs_repo_chunk_cut_keyed(const unsigned char key[32], const unsigned char *p, size_t n)
{
    uint64_t table[256];

    keyed_gear(key, table);
    return cut_with(table, p, n);
}

static size_t cut_with(const uint64_t *table, const unsigned char *p, size_t n)
{
    /* FastCDC: a rolling hash over the bytes since the chunk's minimum,
     * cut where its top bits are all zero -- harder to meet before the
     * average size, easier after, so most chunks are near it. The top bits
     * hang on the last 64 bytes; the low ones would on the last few only. */
    const uint64_t hard = ~(uint64_t)0 << (64 - 22);
    const uint64_t easy = ~(uint64_t)0 << (64 - 18);
    uint64_t       h = 0;
    size_t         normal;
    size_t         i;

    if (n <= RS_REPO_CHUNK_MIN)
    {
        return n;
    }
    if (n > RS_REPO_CHUNK_MAX)
    {
        n = RS_REPO_CHUNK_MAX;
    }
    normal = n < RS_REPO_CHUNK_AVG ? n : RS_REPO_CHUNK_AVG;
    for (i = RS_REPO_CHUNK_MIN; i < normal; i++)
    {
        h = (h << 1) + table[p[i]];
        if ((h & hard) == 0)
        {
            return i + 1;
        }
    }
    for (; i < n; i++)
    {
        h = (h << 1) + table[p[i]];
        if ((h & easy) == 0)
        {
            return i + 1;
        }
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* Adding a snapshot                                                         */
/* ------------------------------------------------------------------------- */

struct rs_repo_writer {
    struct rs_repo   *r;
    struct pack_out   pk;
    char            **made;     /* packs finished, removed again on abort */
    size_t            nmade;
    bool             *used;     /* per pack there before: the snapshot needs it */
    size_t            nused;
    char            **kit;
    size_t            nkit;
    uint64_t          objects;  /* files that added content */
    uint64_t          bytes;    /* the content they added, before gzip */
    struct sigaction  saved;
    /* The file being stored: its bytes gathered into `buf` and cut into
     * chunks there, and the digests of those, in order. */
    unsigned char    *buf;
    size_t            len;
    uint64_t          left;     /* of its bytes, still to come */
    unsigned char   (*flist)[32];
    size_t            nflist;
    size_t            flist_cap;
    bool              added;
    bool              failed;
    struct rs_buf    *err;
};

/* Clears a key, through a volatile pointer: a memset of what is not read
 * again is one the compiler may leave out. */
static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;

    while (n-- > 0)
    {
        *v++ = 0;
    }
}

/* 32 bytes from the kernel's random source, or false: a key has no
 * stand-in. */
static bool random_key(unsigned char key[32])
{
    int    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t got = 0;

    while (fd >= 0 && got < 32)
    {
        ssize_t n = read(fd, key + got, 32 - got);

        if (n <= 0)
        {
            break;
        }
        got += (size_t)n;
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    return got == 32;
}

/* `tmp` put in place as `name` unless something is there already, which is
 * kept: true for either (rs_store_place_new). */
static bool publish_once(const struct rs_store *st, const char *tmp, const char *name)
{
    return rs_store_place_new(st, tmp, name) >= 0;
}

/* What a file is encrypted to, from the session keys at its head: how many
 * key ids are in `ids`, and whether it is encrypted at all in `sealed`. */
#define KEYS_HEAD 16384   /* room for a session key to each of many RSA keys */
#define KEYS_MAX  32

static size_t sealed_to(const struct rs_store *st, const char *name, char ids[][17], bool *sealed)
{
    unsigned char *head = rs_xmalloc(KEYS_HEAD);
    ssize_t        got = rs_store_peek(st, name, head, KEYS_HEAD);
    size_t         n = 0;

    *sealed = false;
    if (got > 0 && rs_pgp_detect(head, (size_t)got))
    {
        *sealed = true;
        n = rs_pgp_recipients(head, (size_t)got, ids, KEYS_MAX);
    }
    free(head);
    return n;
}

/* Whether files `a` and `b` are encrypted to the same keys, as sets. */
static bool same_keys(const struct rs_store *st, const char *a, const char *b)
{
    char   ia[KEYS_MAX][17];
    char   ib[KEYS_MAX][17];
    bool   sa;
    bool   sb;
    size_t na = sealed_to(st, a, ia, &sa);
    size_t nb = sealed_to(st, b, ib, &sb);
    size_t i;
    size_t k;

    if (na != nb || na == 0)
    {
        return na == nb && sa == sb;
    }
    for (i = 0; i < na; i++)
    {
        bool found = false;

        for (k = 0; k < nb && !found; k++)
        {
            found = strcmp(ia[i], ib[k]) == 0;
        }
        if (!found)
        {
            return false;
        }
    }
    return true;
}

/* The copies of the chunking key in the repository, oldest first: chunk-key,
 * as the first capture made it, then each chunk-key.TIME a capture added when
 * the keys it was given were not the ones the newest copy is sealed to. Every
 * copy holds the same key. */
/* rs_store_list's keep for the copies after the first. */
static bool is_key_copy(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                        char **out)
{
    size_t len = strlen(RS_REPO_CHUNK_KEY);
    bool  *first = ctx;

    (void)st;
    (void)dir;
    if (strcmp(name, RS_REPO_CHUNK_KEY) == 0)
    {
        *first = true;
        return false;
    }
    if (strncmp(name, RS_REPO_CHUNK_KEY, len) == 0 && name[len] == '.' &&
        rs_repo_name_valid(name + len + 1))
    {
        *out = rs_xstrdup(name);
        return true;
    }
    return false;
}

static char **chunk_key_copies(const struct rs_store *st, size_t *n)
{
    bool   first = false;
    char **names = rs_store_list(st, "", is_key_copy, &first, n);

    if (first)
    {
        names = rs_xreallocarray(names, *n + 1, sizeof(*names));
        memmove(names + 1, names, *n * sizeof(*names));
        names[0] = rs_xstrdup(RS_REPO_CHUNK_KEY);
        (*n)++;
    }
    return names;
}

/*
 * The chunking key, `hex`, sealed to this run's keys in a copy of its own
 * where the newest copy, `newest`, is sealed to others -- so a key retired
 * from --encrypt-to is needed for it no longer. Added beside the others,
 * never in place of one, so an --append-only capture can; a prune removes
 * the older copies.
 */
static void add_sealed_copy(const struct rs_repo *r, const char *newest, const char *hex)
{
    char         *tmp = rs_xasprintf("packs/.%s.%ld.new", RS_REPO_CHUNK_KEY, (long)getpid());
    struct rs_buf err;
    char          when[32];
    time_t        now = time(NULL);
    struct tm     tm;

    rs_buf_init(&err);
    (void)rs_store_remove(r->st, tmp, false);
    if (write_out(r->st, tmp, hex, 64, false, r->recips, seal_n(r), &err) &&
        !same_keys(r->st, tmp, newest) && gmtime_r(&now, &tm) &&
        strftime(when, sizeof(when), "%Y%m%dT%H%M%SZ", &tm) > 0)
    {
        int placed = 0;
        int seq;

        /* Numbered within the second, so that two in one sort in the order
         * they were added. */
        for (seq = 0; placed == 0 && seq < 1000; seq++)
        {
            char *name = rs_xasprintf("%s.%s-%03d", RS_REPO_CHUNK_KEY, when, seq);

            placed = rs_store_place_new(r->st, tmp, name);
            free(name);
        }
    }
    (void)rs_store_remove(r->st, tmp, false);
    free(tmp);
    rs_buf_free(&err);
}

/* All but the newest copy of the chunking key removed, once the newest is
 * one whose keys can be read: they hold the same key, sealed to keys that
 * may since have been retired. Needs no key. */
static void drop_old_chunk_keys(const struct rs_repo *r)
{
    char   ids[KEYS_MAX][17];
    size_t n;
    char **names = chunk_key_copies(r->st, &n);
    bool   sealed = false;

    if (n > 1 && sealed_to(r->st, names[n - 1], ids, &sealed) > 0)
    {
        size_t i;

        for (i = 0; i + 1 < n; i++)
        {
            (void)rs_store_remove(r->st, names[i], true);
        }
    }
    rs_repo_free_names(names, n);
}

/*
 * The key an encrypted repository's chunk boundaries follow. Chunk sizes are
 * what is left to see of an encrypted chunk, and with boundaries anyone can
 * work out, they would say which known files a repository holds; keyed, they
 * say nothing. The key is kept in the repository, encrypted to its keys as
 * everything else is (RS_REPO_CHUNK_KEY), and in this machine's cache, where
 * a capture -- which has no secret key -- reads it. A machine that has
 * neither the cache nor the secret key makes a key of its own: the same files
 * are then cut differently there, and a large one that changed is stored
 * whole once more. Without a random source, the fixed table.
 */
static void chunk_key(struct rs_repo *r)
{
    unsigned char key[32];
    char          hex[RS_SHA256_HEX_SIZE];
    struct rs_buf b;
    struct rs_buf err;
    bool          have = false;
    size_t        ncopies;
    char        **copies = chunk_key_copies(r->st, &ncopies);
    bool          there = ncopies > 0;
    size_t        i;

    rs_buf_init(&err);
    if (cache_get(r, "keys", "chunks", 128, &b))
    {
        have = b.len >= 64 && unhex(b.data, key);
        rs_buf_free(&b);
    }
    /* Newest first: the one sealed to the keys most likely to be here. */
    for (i = ncopies; !have && i > 0; i--)
    {
        bool sealed;

        have = read_sealed(r->st, copies[i - 1], 4096, true, &b, &sealed, &err) &&
               b.len >= 64 && unhex(b.data, key);
        rs_buf_free(&b);
        if (have)
        {
            to_hex(key, hex);
            cache_put(r, "keys", "chunks", hex, 64);
        }
    }
    if (have && there && r->nrecips > 0)
    {
        to_hex(key, hex);
        add_sealed_copy(r, copies[ncopies - 1], hex);
    }
    rs_repo_free_names(copies, ncopies);
    if (!have)
    {
        if (!random_key(key))
        {
            rs_warn("%s: there is no random source to make its chunking key from; its chunks "
                    "are cut as an unencrypted repository's are", r->dir);
            rs_buf_free(&err);
            return;
        }
        to_hex(key, hex);
        cache_put(r, "keys", "chunks", hex, 64);
        if (!there)
        {
            /* Written in packs/ and linked from there: a machine adds to
             * the repository's own directory, and where protect made it
             * append-only, removes nothing from it, its own included. */
            char *tmp = rs_xasprintf("packs/.%s.%ld.tmp", RS_REPO_CHUNK_KEY, (long)getpid());

            rs_buf_reset(&err);
            if (!write_out(r->st, tmp, hex, 64, false, r->recips, seal_n(r), &err) ||
                !publish_once(r->st, tmp, RS_REPO_CHUNK_KEY))
            {
                rs_warn("%s: its chunking key could not be kept there (%s); this machine "
                        "keeps it", r->dir, err.len ? err.data : strerror(errno));
            }
            (void)rs_store_remove(r->st, tmp, false);
            free(tmp);
        } else
        {
            rs_warn("%s: its chunking key cannot be read here without the secret key, and "
                    "this machine has no copy of it; a new one is used, so large files are "
                    "stored whole once more", r->dir);
        }
    }
    r->gear = rs_xcalloc(256, sizeof(*r->gear));
    keyed_gear(key, r->gear);
    wipe(key, sizeof(key));
    wipe(hex, sizeof(hex));
    rs_buf_free(&err);
}

struct rs_repo_writer *rs_repo_writer_begin(struct rs_repo *r, struct rs_buf *err)
{
    struct rs_repo_writer *w;
    struct sigaction       ignore;

    if (r->encrypted && r->nrecips == 0)
    {
        rs_buf_addf(err, "%s: it is encrypted; give the public keys to encrypt to with "
                    "--encrypt-to", r->dir);
        return NULL;
    }
    if (!r->encrypted && r->nrecips > 0)
    {
        rs_buf_addf(err, "%s: it is not encrypted, so --encrypt-to cannot be used with it; "
                    "make an encrypted repository with restate init --encrypt-to", r->dir);
        return NULL;
    }
    w = rs_xcalloc(1, sizeof(*w));
    w->r = r;
    w->buf = rs_xmalloc(RS_REPO_CHUNK_MAX);
    load_objects(r);
    w->nused = r->npacks;
    w->used = rs_xcalloc(r->npacks + 1, sizeof(*w->used));
    if (r->encrypted && !r->gear)
    {
        chunk_key(r);
    }
    /* A gzip that dies would otherwise kill restate with SIGPIPE on the next
     * write into it, before it could say why or clear up. */
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &ignore, &w->saved);
    return w;
}

void rs_repo_writer_kit(struct rs_repo_writer *w, const char *const *kit, size_t n)
{
    size_t i;

    rs_repo_free_names(w->kit, w->nkit);
    w->kit = rs_xcalloc(n + 1, sizeof(*w->kit));
    for (i = 0; i < n; i++)
    {
        w->kit[i] = rs_xstrdup(kit[i]);
    }
    w->nkit = n;
}

bool rs_repo_have(const void *ctx, const char hash[RS_SHA256_HEX_SIZE])
{
    const struct rs_repo_writer *w = ctx;
    unsigned char                d[32];

    return unhex(hash, d) &&
           (map_find(&w->r->objects, d) != NULL || map_find(&w->r->listed, d) != NULL);
}

static bool ensure_pack(struct rs_repo_writer *w, struct rs_buf *err)
{
    return w->pk.open || pack_open(w->r, &w->pk, err);
}

static bool maybe_close(struct rs_repo_writer *w, struct rs_buf *err)
{
    char *done = NULL;

    if (!w->pk.open || w->pk.tar.offset < pack_size)
    {
        return true;
    }
    if (!pack_close(w->r, &w->pk, &done, err))
    {
        return false;
    }
    w->made = rs_xreallocarray(w->made, w->nmade + 1, sizeof(*w->made));
    w->made[w->nmade++] = done;
    return true;
}

/* One chunk of the file: its digest noted, and the chunk stored if no pack
 * has it already. */
static bool put_chunk(struct rs_repo_writer *w, const unsigned char *p, size_t len)
{
    char          hex[RS_SHA256_HEX_SIZE];
    unsigned char d[32];

    rs_sha256_hex(p, len, hex);
    (void)unhex(hex, d);
    if (w->nflist == w->flist_cap)
    {
        w->flist_cap = w->flist_cap ? w->flist_cap * 2 : 16;
        w->flist = rs_xreallocarray(w->flist, w->flist_cap, sizeof(*w->flist));
    }
    memcpy(w->flist[w->nflist++], d, 32);
    {
        const struct obj *o = map_find(&w->r->objects, d);

        if (o)
        {
            if (o->pack < w->nused)
            {
                w->used[o->pack] = true;
            }
            return true;
        }
    }
    if (!ensure_pack(w, w->err) || !pack_header(&w->pk, len, w->err) ||
        !rs_tar_data(&w->pk.tar, p, len) || !rs_tar_pad(&w->pk.tar))
    {
        if (w->err->len == 0)
        {
            rs_buf_addf(w->err, "writing a pack in %s: %s", w->r->dir, strerror(errno));
        }
        w->failed = true;
        return false;
    }
    pack_line(&w->pk, hex, len);
    (void)map_add(&w->r->objects, d, UINT32_MAX, 0);
    w->added = true;
    w->bytes += len;
    rs_progress_new_bytes(len);
    if (!maybe_close(w, w->err))
    {
        w->failed = true;
        return false;
    }
    return true;
}

/* Cuts the first chunk off what is gathered, and stores it. */
static bool cut_one(struct rs_repo_writer *w)
{
    size_t cut = w->r->gear ? cut_with(w->r->gear, w->buf, w->len)
                            : rs_repo_chunk_cut(w->buf, w->len);

    if (!put_chunk(w, w->buf, cut))
    {
        return false;
    }
    memmove(w->buf, w->buf + cut, w->len - cut);
    w->len -= cut;
    return true;
}

/* The tar writer's output, which rs_image_copy_file reads the file into: the
 * file's bytes, gathered for the chunker -- and then the member's padding,
 * which is not the file's, dropped. */
static bool chunk_sink(void *ctx, const void *data, size_t n)
{
    struct rs_repo_writer *w = ctx;
    const unsigned char   *p = data;

    if (n > w->left)
    {
        n = (size_t)w->left;
    }
    w->left -= n;
    while (n > 0)
    {
        size_t room = RS_REPO_CHUNK_MAX - w->len < n ? RS_REPO_CHUNK_MAX - w->len : n;

        memcpy(w->buf + w->len, p, room);
        w->len += room;
        p += room;
        n -= room;
        if (w->len == RS_REPO_CHUNK_MAX && !cut_one(w))
        {
            return false;
        }
    }
    return true;
}

/*
 * A file, read once -- exactly as rs_image_copy_file reads it, a file that
 * grows kept as it was when the read began, one that shrinks or cannot be
 * read marked so -- cut into chunks as it is read, each stored only if it is
 * new; and, for a file of more than one chunk, the list of them.
 */
static bool store_file(struct rs_repo_writer *w, struct rs_entry *e, int fd, uint64_t size,
                       struct rs_buf *err)
{
    struct rs_tar_writer tw;
    unsigned char        d[32];

    w->len = 0;
    w->left = size;
    w->nflist = 0;
    w->added = false;
    w->failed = false;
    w->err = err;
    rs_tar_writer_init(&tw, chunk_sink, w);
    if (!rs_image_copy_file(&tw, e, fd, size))
    {
        if (!w->failed)
        {
            rs_buf_addf(err, "reading %s: %s", e->path, strerror(errno));
        }
        return false;
    }
    /* What is left, cut; an empty file is one empty chunk. */
    while (w->len > 0 || w->nflist == 0)
    {
        if (!cut_one(w))
        {
            return false;
        }
    }
    if (e->hash_state == RS_HASH_PRESENT && w->nflist > 1 && unhex(e->hash, d) &&
        !map_find(&w->r->objects, d) && !map_find(&w->r->listed, d))
    {
        if (!ensure_pack(w, err))
        {
            return false;
        }
        pack_list(&w->pk, d, size, (const unsigned char (*)[32])w->flist, w->nflist);
        (void)map_add(&w->r->listed, d, UINT32_MAX, 0);
        w->added = true;
    }
    if (w->added)
    {
        w->objects++;
    }
    return true;
}

bool rs_repo_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                   struct rs_buf *err)
{
    struct rs_repo_writer *w = ctx;

    if (e->type == 'c' || e->type == 'b')
    {
        return true;   /* recreated from the index, as from an image */
    }
    if (e->type == 'f' && fd >= 0 && !store_file(w, e, fd, (uint64_t)st->st_size, err))
    {
        return false;
    }
    free(e->stored);
    e->stored = rs_image_member_name(e->path);
    return true;
}

/* The index, rendered into memory. */
static char *index_text(const struct rs_index *ix, size_t *len)
{
    char *text = NULL;
    FILE *fp = open_memstream(&text, len);
    bool  ok;

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

/* `len` bytes, gzip'd, into `out`. */
static bool gzip_bytes(const char *text, size_t len, struct rs_buf *out, struct rs_buf *err)
{
    FILE          *tmp = rs_tmpfile();
    struct rs_gzip gz;
    bool           ok;

    if (tmp == NULL)
    {
        rs_buf_addf(err, "a temporary file: %s", strerror(errno));
        return false;
    }
    ok = rs_gzip_compress(fileno(tmp), &gz, err);
    if (ok)
    {
        bool wrote = write_all(gz.fd, text, len);

        ok = rs_gzip_finish(&gz, !wrote, err) && wrote;
    }
    ok = ok && lseek(fileno(tmp), 0, SEEK_SET) == 0 &&
         slurp_fd("the index", fileno(tmp), false, RS_IMAGE_INDEX_MAX, out, err);
    (void)fclose(tmp);
    return ok;
}

/* The index, gzip'd -- and encrypted, where the repository is -- into the
 * new file `path`; and this machine's copy of it, for the next capture. */
static bool write_index(const struct rs_repo *r, const char *path, const char *name,
                        const struct rs_index *ix, struct rs_buf *err)
{
    struct rs_buf gz;
    size_t        len = 0;
    char         *text = index_text(ix, &len);
    bool          ok;

    if (!text)
    {
        rs_buf_addstr(err, "could not render the index");
        return false;
    }
    rs_buf_init(&gz);
    ok = gzip_bytes(text, len, &gz, err) &&
         write_out(r->st, path, gz.data, gz.len, false, r->recips, seal_n(r), err);
    if (ok && r->encrypted)
    {
        char *file = rs_xasprintf("%s.json.gz", name);

        cache_put(r, "snapshots", file, gz.data, gz.len);
        free(file);
    }
    rs_buf_free(&gz);
    free(text);
    return ok;
}

/* The snapshot's summary, for `restate snapshots`. */
static bool write_info(const char *path, const struct rs_index *ix, const char *name,
                       const struct rs_repo_writer *w, struct rs_buf *err)
{
    struct rs_jval info;
    struct rs_buf  text;
    uint64_t       kept = 0;
    uint64_t       bytes = 0;
    size_t         i;
    bool           ok;

    for (i = 0; i < ix->count; i++)
    {
        if (ix->entries[i].stored && ix->entries[i].type == 'f')
        {
            kept++;
            bytes += ix->entries[i].size;
        }
    }
    memset(&info, 0, sizeof(info));
    rs_jval_set_object(&info);
    rs_jobj_str(&info, "format", "restate-snapshot");
    rs_jobj_str(&info, "name", name);
    rs_jobj_str(&info, "created", ix->created ? ix->created : "");
    rs_jobj_str(&info, "host", ix->host ? ix->host : "");
    rs_jobj_str(&info, "root", ix->root ? ix->root : "");
    rs_jobj_str(&info, "restate", ix->version ? ix->version : "");
    rs_jobj_u64(&info, "paths", ix->count);
    rs_jobj_u64(&info, "files", kept);
    rs_jobj_u64(&info, "bytes", bytes);
    rs_jobj_u64(&info, "new_files", w->objects);
    rs_jobj_u64(&info, "new_bytes", w->bytes);
    rs_buf_init(&text);
    rs_json_write(&text, &info, 2, 0);
    rs_buf_addc(&text, '\n');
    ok = write_out(w->r->st, path, text.data, text.len, false, w->r->recips, seal_n(w->r), err);
    rs_buf_free(&text);
    rs_jval_free(&info);
    return ok;
}

/* The kit's paths, one per line. */
static bool write_kit(const char *path, const struct rs_repo_writer *w, struct rs_buf *err)
{
    struct rs_buf text;
    size_t        i;
    bool          ok;

    rs_buf_init(&text);
    rs_buf_add(&text, "", 0);
    for (i = 0; i < w->nkit; i++)
    {
        if (w->kit[i][0] == '/' && !strchr(w->kit[i], '\n'))
        {
            rs_buf_addf(&text, "%s\n", w->kit[i]);
        }
    }
    ok = write_out(w->r->st, path, text.data, text.len, false, w->r->recips, seal_n(w->r), err);
    rs_buf_free(&text);
    return ok;
}

/* A new directory for snapshot `name` to be made in, beside where it goes
 * ("snapshots/.NAME.XXXXXX"): its name in the store, or NULL, and why into
 * `err`. */
static char *temp_dir(const struct rs_store *st, const char *name, struct rs_buf *err)
{
    char *prefix = rs_xasprintf("snapshots/.%s.", name);
    char *tmp = rs_store_make_temp_dir(st, prefix);

    if (!tmp)
    {
        char *path = rs_store_path(st, prefix);

        rs_buf_addf(err, "%sXXXXXX: %s", path, strerror(errno));
        free(path);
    }
    free(prefix);
    return tmp;
}

/* Removes a snapshot directory's files, then the directory: only what
 * restate puts there, so nothing else is removed by mistake. */
static bool remove_snapshot_dir(const struct rs_store *st, const char *dir)
{
    static const char *const files[] = { "index.json.gz", "index.sig", "kit", "info", "packs" };
    size_t                   i;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++)
    {
        char *name = rs_xasprintf("%s/%s", dir, files[i]);

        (void)rs_store_remove(st, name, true);
        free(name);
    }
    return rs_store_remove_dir(st, dir, true) == 0;
}

static void writer_free(struct rs_repo_writer *w)
{
    (void)sigaction(SIGPIPE, &w->saved, NULL);
    rs_repo_free_names(w->made, w->nmade);
    rs_repo_free_names(w->kit, w->nkit);
    free(w->used);
    free(w->buf);
    free(w->flist);
    free(w);
}

/* This machine's copies of .idx files and indexes the repository no longer
 * has: a pack prune removed, a snapshot it dropped. */
static void tidy_cache(struct rs_repo *r)
{
    static const char *const subs[] = { "packs", "snapshots" };
    size_t                   nsnaps = 0;
    char                   **snaps;
    size_t                   k;

    if (!r->cache)
    {
        return;
    }
    snaps = rs_repo_snapshots(r, &nsnaps);
    for (k = 0; k < 2; k++)
    {
        char                *dir = rs_xasprintf("%s/%s", r->cache, subs[k]);
        DIR                 *d = opendir(dir);
        const struct dirent *de;

        while (d && (de = readdir(d)) != NULL)
        {
            const char *suffix = k == 0 ? ".idx" : ".json.gz";
            size_t      len = strlen(de->d_name);
            size_t      sl = strlen(suffix);
            char       *stem;
            bool        there = false;
            size_t      i;

            if (len <= sl || strcmp(de->d_name + len - sl, suffix) != 0 || de->d_name[0] == '.')
            {
                continue;
            }
            stem = rs_xstrndup(de->d_name, len - sl);
            for (i = 0; !there && i < (k == 0 ? r->npacks : nsnaps); i++)
            {
                there = strcmp(stem, k == 0 ? r->packs[i] : snaps[i]) == 0;
            }
            if (!there)
            {
                char *path = rs_xasprintf("%s/%s", dir, de->d_name);

                (void)unlink(path);
                free(path);
            }
            free(stem);
        }
        if (d)
        {
            (void)closedir(d);
        }
        free(dir);
    }
    rs_repo_free_names(snaps, nsnaps);
}

void rs_repo_writer_abort(struct rs_repo_writer *w)
{
    size_t i;

    if (!w)
    {
        return;
    }
    pack_discard(&w->pk);
    for (i = 0; i < w->nmade; i++)
    {
        char *idx = rs_xasprintf("packs/%s.idx", w->made[i]);
        char *content = rs_xasprintf("packs/%s.tar.gz", w->made[i]);
        char *sum = rs_xasprintf("packs/%s.sum", w->made[i]);

        (void)rs_store_remove(w->r->st, idx, false);
        (void)rs_store_remove(w->r->st, content, false);
        (void)rs_store_remove(w->r->st, sum, false);
        free(idx);
        free(content);
        free(sum);
    }
    writer_free(w);
}

bool rs_repo_writer_finish(struct rs_repo_writer *w, const struct rs_index *ix,
                           const char *sign_with, struct rs_repo_written *out,
                           struct rs_buf *err)
{
    char *base = rs_repo_snapshot_name(ix->created);
    char *name = NULL;
    char *tmp = NULL;
    char *final = NULL;
    char *done = NULL;
    char *path;
    bool  ok = true;
    int   k;
    int   attempt;

    memset(out, 0, sizeof(*out));
    if (w->pk.open)
    {
        ok = pack_close(w->r, &w->pk, &done, err);
        if (ok)
        {
            w->made = rs_xreallocarray(w->made, w->nmade + 1, sizeof(*w->made));
            w->made[w->nmade++] = done;
        }
    }
    for (attempt = 0;; attempt++)
    {
        size_t mark = err->len;

        /* Two captures in one second are told apart by a number after the time. */
        for (k = 1; ok && k < 1000 && !name; k++)
        {
            struct rs_store_stat st;
            char                *candidate = k == 1 ? rs_xstrdup(base)
                                                    : rs_xasprintf("%s-%d", base, k);

            free(final);
            final = rs_xasprintf("snapshots/%s", candidate);
            if (rs_store_stat(w->r->st, final, &st) != 0 && errno == ENOENT)
            {
                name = candidate;
            } else
            {
                free(candidate);
            }
        }
        if (ok && !name)
        {
            rs_buf_addf(err, "%s: no free name for the snapshot", w->r->dir);
            ok = false;
        }
        if (ok)
        {
            tmp = temp_dir(w->r->st, name, err);
            ok = tmp != NULL;
        }
        if (ok)
        {
            path = rs_xasprintf("%s/index.json.gz", tmp);
            ok = write_index(w->r, path, name, ix, err);
            if (ok && sign_with)
            {
                struct rs_buf sig;
                char         *sigpath = rs_xasprintf("%s/index.sig", tmp);

                /* gpg signs the file as it is stored, where it is. */
                char *where = rs_store_path(w->r->st, path);

                rs_buf_init(&sig);
                ok = rs_pgp_sign(sign_with, where, &sig, &out->signer, err) &&
                     rs_store_write_new(w->r->st, sigpath, sig.data, sig.len, err);
                rs_buf_free(&sig);
                free(sigpath);
                free(where);
            }
            free(path);
        }
        if (ok)
        {
            path = rs_xasprintf("%s/kit", tmp);
            ok = write_kit(path, w, err);
            free(path);
        }
        if (ok)
        {
            path = rs_xasprintf("%s/info", tmp);
            ok = write_info(path, ix, name, w, err);
            free(path);
        }
        if (ok)
        {
            /* Which packs it needs, for whatever cannot read its index: the
             * packs this capture wrote, and those before it that hold content
             * it uses. */
            size_t len = 0;
            char  *text;

            mark_index(w->r, ix, w->used);
            text = pack_list_text(w->r, w->used, w->made, w->nmade, &len);
            path = rs_xasprintf("%s/packs", tmp);
            ok = rs_store_write_new(w->r->st, path, text, len, err);
            free(path);
            free(text);
        }
        if (ok)
        {
            rs_store_sync_dir(w->r->st, tmp);
            if (rs_store_rename(w->r->st, tmp, final, false) != 0)
            {
                int e = errno;

                renamed_failed(w->r->st, final, err);
                ok = false;
                /* Taken between looking and putting it in place, which only
                 * a repository behind restate-proxy can say, its lock
                 * notwithstanding (the storage host's own ingest): made
                 * again under the next name, which says it in its index. */
                if (e == EEXIST && attempt < 3)
                {
                    err->len = mark;
                    if (err->data)
                    {
                        err->data[mark] = '\0';
                    }
                    (void)remove_snapshot_dir(w->r->st, tmp);
                    free(tmp);
                    tmp = NULL;
                    free(name);
                    name = NULL;
                    ok = true;
                    continue;
                }
            }
        }
        break;
    }
    if (ok)
    {
        rs_store_sync_dir(w->r->st, "snapshots");
        out->name = name;
        name = NULL;
        out->objects = w->objects;
        out->bytes = w->bytes;
        /* Its packs are the repository's now; the digests it added are
         * counted again from them if anything reads the repository next. */
        list_packs(w->r);
        unload(w->r);
        tidy_cache(w->r);
        writer_free(w);
    } else
    {
        if (tmp)
        {
            (void)remove_snapshot_dir(w->r->st, tmp);
        }
        rs_repo_writer_abort(w);
    }
    free(base);
    free(name);
    free(tmp);
    free(final);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Reading a snapshot's content                                              */
/* ------------------------------------------------------------------------- */

/* A file the snapshot keeps, by the digest of its content. */
struct ref {
    char   hash[RS_SHA256_HEX_SIZE];
    size_t entry;
};

/* A content to send: the refs [lo, hi) that have it, and its chunks. */
struct group {
    size_t                 lo;
    size_t                 hi;
    const unsigned char  (*chunks)[32];
    size_t                 n;
    unsigned char          one[32];   /* the content's digest; its chunk, if it is one */
    bool                   own;       /* it is one: `one`, not `chunks` */
    uint32_t               pack;      /* where its first chunk is: the order sent in */
    uint32_t               member;
};

/* Where a reader of a decrypted pack's file is in it. */
struct at_fd {
    int      fd;
    uint64_t off;
};

/* A pack being read, forward only: through gzip, and gpg if it is encrypted,
 * or from the file it was decrypted into once (struct unsealed). */
struct reader {
    bool                 open;
    uint32_t             pack;
    bool                 unsealed;    /* from that file, not `z` */
    struct at_fd         from;
    struct zin           z;
    struct rs_tar_reader tr;
    struct rs_tar_entry  te;
    uint64_t             at;          /* the member whose header was read last */
    bool                 pending;     /* and none of its data read yet */
    uint64_t             used;        /* when last, for the least recent to go */
};

/* A pack's .seek, once it is wanted: none, if it has none or it is not one. */
struct seeks {
    bool                 loaded;
    struct rs_repo_seek *at;
    size_t               n;
};

/*
 * An encrypted pack, decrypted and unzipped once into a temporary file of its
 * own, with where each member begins (its .seeks): gpg reads a pack only
 * from its start, and a file whose chunks are in several packs, or a chunk
 * more than one file has, sends the stream back into one it has read past.
 * Kept while a chunk still to come is in it (last_uses), and never more than
 * UNSEALED_BYTES of them: past that, the least recently read goes.
 */
struct unsealed {
    FILE    *f;
    uint64_t bytes;
    uint64_t used;
};

/* A chunk more than one content has, kept once read. */
struct cached {
    unsigned char  d[32];
    unsigned char *data;
    size_t         len;
    uint64_t       used;
};

/* Packs open at once: enough for a file whose chunks are in a few -- a disk
 * image's old chunks, and the few that changed since -- each read forward. */
#define READERS     8
#define CACHE_BYTES ((size_t)64 * 1024 * 1024)
/* A pack read forward this little way short of the segment wanted is read on
 * to it: gzip, started anew, reads a quarter of a mebibyte before it writes
 * anything, so a jump shorter than about twice that saves nothing. */
#define SEEK_NEAR   ((uint64_t)512 * 1024)
/* Of encrypted packs, decrypted: at most this much, and no more than a quarter
 * of what is free where temporary files go. */
#define UNSEALED_BYTES ((uint64_t)4 * 1024 * 1024 * 1024)
#ifndef P_tmpdir
#define P_tmpdir "/tmp"
#endif

enum phase {
    PH_OTHERS = 0,   /* directories, symlinks and FIFOs, from the index */
    PH_FILES,        /* the files, in the order their content was written */
    PH_UNREAD,       /* files that could not be read when they were captured */
    PH_END,          /* the end of the archive */
    PH_DONE
};

enum source {
    SRC_CONTENT = 0, /* made from chunks */
    SRC_SPOOL,       /* a copy of it, for each file with that content */
    SRC_ZERO
};

enum chunk_from {
    CH_NONE = 0,
    CH_READER,
    CH_CACHE,
    CH_ZERO          /* a chunk that could not be read */
};

struct rs_repo_stream {
    struct rs_repo        *r;
    const struct rs_index *ix;
    bool                  *want;      /* per entry */
    enum phase             phase;
    size_t                 pos;       /* the next entry, where a phase walks the index */
    struct ref            *refs;      /* sorted by digest */
    size_t                 nrefs;
    struct group          *groups;    /* in the order they are sent */
    size_t                 ngroups;
    size_t                 gi;
    struct objmap          multi;     /* chunks used more than once: pack is how often */
    struct reader          readers[READERS];
    uint64_t               tick;
    struct cached         *cache;
    size_t                 ncache;
    size_t                 cache_bytes;
    bool                  *warned;    /* per pack */
    struct seeks          *seeks;     /* per pack */
    struct unsealed       *unsealed;  /* per pack, in an encrypted repository */
    uint64_t               unsealed_bytes;
    uint64_t               unsealed_n;    /* how many are held */
    uint64_t               unsealed_max;
    bool                   unsealed_off;  /* no room for them: read through gpg */
    /* In an encrypted repository: where each group's chunks begin among all
     * the chunks the stream reads, in order; per pack, one more than where
     * the last chunk read from it is, 0 for none; and the packs in that
     * order, let go as the stream passes them (`done` of them so far). */
    size_t                *first_chunk;
    size_t                *last_use;
    uint32_t              *by_last;
    uint32_t               done;
    /* The content being made: its next chunk, and the chunk being read. */
    const struct group    *g;
    size_t                 ci;
    uint64_t               content_left;
    enum chunk_from        ch;
    struct reader         *rd;
    const struct cached   *cc;
    uint64_t               ch_left;
    uint64_t               ch_off;
    struct cached          filling;   /* a chunk to keep, as it is read */
    /* A content more than one file has, spooled: refs [at, hi) to send. */
    FILE                  *spool;
    uint64_t               spool_size;
    uint64_t               spool_at;
    size_t                 at;
    size_t                 hi;
    /* What read hands out next: `out`, then `data_left` bytes from `src`. */
    struct rs_buf          out;
    size_t                 out_pos;
    enum source            src;
    uint64_t               data_left;
    uint64_t               pad;
    bool                   failed;
    struct rs_buf          err;
};

static int by_ref(const void *a, const void *b)
{
    const struct ref *x = a;
    const struct ref *y = b;
    int               c = strcmp(x->hash, y->hash);

    if (c != 0)
    {
        return c;
    }
    return x->entry < y->entry ? -1 : x->entry > y->entry;
}

/* A group's chunk `c`. */
static const unsigned char *chunk_of(const struct group *g, size_t c)
{
    return g->own ? g->one : g->chunks[c];
}

static int by_place(const void *a, const void *b)
{
    const struct group *x = a;
    const struct group *y = b;

    if (x->pack != y->pack)
    {
        return x->pack < y->pack ? -1 : 1;
    }
    if (x->member != y->member)
    {
        return x->member < y->member ? -1 : 1;
    }
    return x->lo < y->lo ? -1 : x->lo > y->lo;
}

/* The chunks of the content `hash`, into g; false if the packs do not have
 * all of it. */
static bool resolve(const struct rs_repo *r, const char *hash, struct group *g)
{
    const struct obj *o;

    if (!unhex(hash, g->one))
    {
        return false;
    }
    if (map_find(&r->objects, g->one))
    {
        g->chunks = NULL;
        g->n = 1;
        g->own = true;
    } else
    {
        const struct obj *l = map_find(&r->listed, g->one);

        if (!l)
        {
            return false;
        }
        g->chunks = (const unsigned char (*)[32])r->chunks[r->lists[l->member].first];
        g->n = r->lists[l->member].n;
    }
    o = map_find(&r->objects, chunk_of(g, 0));
    if (!o)
    {
        return false;
    }
    g->pack = o->pack;
    g->member = o->member;
    return true;
}

/* Whether `path` is one of the files `include` covers; all are when there
 * are no patterns. */
static bool included(const char *path, const char *const *include, size_t ninclude)
{
    size_t k;

    for (k = 0; k < ninclude; k++)
    {
        if (rs_glob_covers(include[k], path))
        {
            return true;
        }
    }
    return ninclude == 0;
}

static uint64_t unsealed_set;
static uint64_t unsealed_made;
static uint64_t unsealed_most;

uint64_t rs_repo_unsealed(void)
{
    return unsealed_made;
}

uint64_t rs_repo_unsealed_most(void)
{
    uint64_t most = unsealed_most;

    unsealed_most = 0;
    return most;
}

void rs_repo_set_unsealed_bytes(uint64_t bytes)
{
    unsealed_set = bytes;
}

static uint64_t unsealed_budget(void)
{
    struct statvfs sv;
    uint64_t       max = UNSEALED_BYTES;

    if (unsealed_set)
    {
        return unsealed_set;
    }
    if (statvfs(P_tmpdir, &sv) == 0 && sv.f_frsize > 0 &&
        (uint64_t)sv.f_bavail / 4 < max / sv.f_frsize)
    {
        max = (uint64_t)sv.f_bavail / 4 * sv.f_frsize;
    }
    return max;
}

/* For sorting packs by their last use. */
static const size_t *last_of;

static int by_last_use(const void *a, const void *b)
{
    size_t x = last_of[*(const uint32_t *)a];
    size_t y = last_of[*(const uint32_t *)b];

    return x < y ? -1 : x > y;
}

/*
 * Where the stream is done with each pack: the last chunk it reads from it.
 * A decrypted pack is kept only while a chunk still to come is in it -- a
 * repository read forward holds one or two at a time, however many it has,
 * and however large a file -- and the budget is for the ones read again.
 */
static void last_uses(struct rs_repo_stream *s)
{
    size_t   i;
    size_t   at = 0;
    uint32_t p;

    s->first_chunk = rs_xcalloc(s->ngroups + 1, sizeof(*s->first_chunk));
    s->last_use = rs_xcalloc(s->r->npacks + 1, sizeof(*s->last_use));
    s->by_last = rs_xcalloc(s->r->npacks + 1, sizeof(*s->by_last));
    for (i = 0; i < s->ngroups; i++)
    {
        const struct group *g = &s->groups[i];
        size_t              c;

        s->first_chunk[i] = at;
        for (c = 0; c < g->n; c++, at++)
        {
            const struct obj *o = map_find(&s->r->objects, chunk_of(g, c));

            if (o && o->pack < s->r->npacks)
            {
                s->last_use[o->pack] = at + 1;
            }
        }
    }
    for (p = 0; p < s->r->npacks; p++)
    {
        s->by_last[p] = p;
    }
    last_of = s->last_use;
    if (s->r->npacks > 1)
    {
        qsort(s->by_last, s->r->npacks, sizeof(*s->by_last), by_last_use);
    }
    last_of = NULL;
}

struct rs_repo_stream *rs_repo_stream_open(struct rs_repo *r, const struct rs_index *ix,
                                           const char *const *only, size_t nonly,
                                           struct rs_buf *err)
{
    return rs_repo_stream_open_matching(r, ix, only, nonly, NULL, 0, NULL, err);
}

struct rs_repo_stream *rs_repo_stream_open_matching(struct rs_repo *r, const struct rs_index *ix,
                                                    const char *const *only, size_t nonly,
                                                    const char *const *include,
                                                    size_t ninclude, const bool *skip,
                                                    struct rs_buf *err)
{
    struct rs_repo_stream *s = rs_xcalloc(1, sizeof(*s));
    size_t                 i;

    (void)err;
    s->r = r;
    s->ix = ix;
    load_objects(r);
    s->want = rs_xcalloc(ix->count + 1, sizeof(*s->want));
    s->refs = rs_xcalloc(ix->count + 1, sizeof(*s->refs));
    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];

        s->want[i] = e->stored && (!only || rs_image_in_list(e->path, only, nonly)) &&
                     (e->type != 'f' || included(e->path, include, ninclude)) &&
                     !(e->type == 'f' && skip && skip[i]);
        if (s->want[i] && e->type == 'f' && e->hash_state == RS_HASH_PRESENT)
        {
            memcpy(s->refs[s->nrefs].hash, e->hash, RS_SHA256_HEX_SIZE);
            s->refs[s->nrefs].entry = i;
            s->nrefs++;
        }
    }
    if (s->nrefs > 1)
    {
        qsort(s->refs, s->nrefs, sizeof(*s->refs), by_ref);
    }
    /* One group per content; one the packs do not have all of is left out,
     * for whoever reads the stream to find missing. */
    s->groups = rs_xcalloc(s->nrefs + 1, sizeof(*s->groups));
    for (i = 0; i < s->nrefs; )
    {
        struct group *g = &s->groups[s->ngroups];
        size_t        hi = i + 1;

        while (hi < s->nrefs && strcmp(s->refs[hi].hash, s->refs[i].hash) == 0)
        {
            hi++;
        }
        memset(g, 0, sizeof(*g));
        g->lo = i;
        g->hi = hi;
        if (resolve(r, s->refs[i].hash, g))
        {
            s->ngroups++;
        }
        i = hi;
    }
    if (s->ngroups > 1)
    {
        qsort(s->groups, s->ngroups, sizeof(*s->groups), by_place);
    }
    for (i = 0; i < s->ngroups; i++)
    {
        const struct group *g = &s->groups[i];
        size_t              c;

        for (c = 0; c < g->n; c++)
        {
            struct obj *o = map_add(&s->multi, chunk_of(g, c), 0, 0);

            o->pack++;
        }
    }
    s->warned = rs_xcalloc(r->npacks + 1, sizeof(*s->warned));
    s->seeks = rs_xcalloc(r->npacks + 1, sizeof(*s->seeks));
    if (r->encrypted)
    {
        s->unsealed = rs_xcalloc(r->npacks + 1, sizeof(*s->unsealed));
        s->unsealed_max = unsealed_budget();
        last_uses(s);
    }
    rs_buf_init(&s->out);
    rs_buf_init(&s->err);
    return s;
}

/* The header of the member for `e`, with `size` bytes of data to follow. */
static void header(struct rs_repo_stream *s, const struct rs_entry *e, uint64_t size,
                   enum source src)
{
    struct rs_tar_member m;
    struct rs_tar_writer tw;

    rs_buf_reset(&s->out);
    s->out_pos = 0;
    rs_tar_writer_init(&tw, to_buf, &s->out);
    if (rs_image_member(e, e->stored, size, &m))
    {
        (void)rs_tar_header(&tw, &m);
    }
    s->src = src;
    s->data_left = e->type == 'f' ? size : 0;
    s->pad = (RS_TAR_BLOCK - s->data_left % RS_TAR_BLOCK) % RS_TAR_BLOCK;
}

/* Once for each pack: why what is in it cannot be had. */
static void warn_pack(struct rs_repo_stream *s, uint32_t pack, const char *why)
{
    if (pack < s->r->npacks && !s->warned[pack])
    {
        s->warned[pack] = true;
        rs_warn("%s/packs/%s.tar.gz: %s; the files with content in it are not put back", s->r->dir,
                s->r->packs[pack], why && *why ? why : "it could not be read");
    }
}

static void close_reader(struct reader *rd)
{
    struct rs_buf ignore;

    if (!rd->open)
    {
        return;
    }
    rs_buf_init(&ignore);
    if (!rd->unsealed)
    {
        (void)zin_close(&rd->z, true, &ignore);
    }
    rs_buf_free(&ignore);
    rs_tar_entry_free(&rd->te);
    memset(rd, 0, sizeof(*rd));
}

static ssize_t read_at_fd(void *ctx, void *data, size_t n)
{
    struct at_fd *a = ctx;
    ssize_t       got = pread(a->fd, data, n, (off_t)a->off);

    if (got > 0)
    {
        a->off += (uint64_t)got;
    }
    return got;
}

/* What is read through the pipeline, copied into `to` as it passes. */
struct tee {
    int      in;
    FILE    *to;
    uint64_t off;
    int      write_errno;
};

static ssize_t read_tee(void *ctx, void *data, size_t n)
{
    struct tee *t = ctx;
    ssize_t     got = read(t->in, data, n);

    if (got > 0 && fwrite(data, 1, (size_t)got, t->to) != (size_t)got)
    {
        t->write_errno = errno ? errno : EIO;
        errno = t->write_errno;
        return -1;
    }
    if (got > 0)
    {
        t->off += (uint64_t)got;
    }
    return got;
}

/* Room for another decrypted pack: the least recently read go, but none a
 * reader has open, nor `keep`. */
static void unsealed_room(struct rs_repo_stream *s, uint32_t keep)
{
    while (s->unsealed_bytes > s->unsealed_max)
    {
        struct unsealed *old = NULL;
        uint32_t         p;
        size_t           i;

        for (p = 0; p < s->r->npacks; p++)
        {
            struct unsealed *u = &s->unsealed[p];
            bool             reading = false;

            for (i = 0; i < READERS; i++)
            {
                reading = reading || (s->readers[i].open && s->readers[i].unsealed &&
                                      s->readers[i].pack == p);
            }
            if (u->f && p != keep && !reading && (!old || u->used < old->used))
            {
                old = u;
            }
        }
        if (!old)
        {
            return;
        }
        (void)fclose(old->f);
        old->f = NULL;
        s->unsealed_bytes -= old->bytes;
        s->unsealed_n--;
        old->bytes = 0;
    }
}

/* The decrypted packs no chunk from `next` on (of last_uses' count) is in,
 * let go -- with any reader still open on one, done with it too. */
static void unsealed_done(struct rs_repo_stream *s, size_t next)
{
    while (s->by_last && s->done < s->r->npacks && s->last_use[s->by_last[s->done]] <= next)
    {
        uint32_t         p = s->by_last[s->done++];
        struct unsealed *u = &s->unsealed[p];
        size_t           i;

        if (!u->f)
        {
            continue;
        }
        for (i = 0; i < READERS; i++)
        {
            if (s->readers[i].open && s->readers[i].unsealed && s->readers[i].pack == p)
            {
                close_reader(&s->readers[i]);
            }
        }
        (void)fclose(u->f);
        u->f = NULL;
        s->unsealed_bytes -= u->bytes;
        s->unsealed_n--;
        u->bytes = 0;
    }
}

/*
 * Encrypted pack `pack` decrypted, unzipped, into a temporary file, and where
 * its members begin into its .seeks -- once, unless it was let go to make
 * room. False if that file could not be made: this pack, and every one after
 * it, is then read through gpg each time, as before. A pack that could not be decrypted, or is not
 * whole, is said so, and what of it could be read is kept.
 */
static bool unseal(struct rs_repo_stream *s, uint32_t pack)
{
    struct unsealed     *u = &s->unsealed[pack];
    struct seeks        *t = &s->seeks[pack];
    char                *path;
    struct zin           z;
    struct tee           tee;
    struct rs_buf        why;
    size_t               cap = 0;
    int                  fd;
    bool                 ok;

    if (u->f)
    {
        u->used = ++s->tick;
        return true;
    }
    if (s->unsealed_off)
    {
        return false;
    }
    memset(&tee, 0, sizeof(tee));
    tee.to = rs_tmpfile();
    if (!tee.to)
    {
        s->unsealed_off = true;
        return false;
    }
    path = rs_xasprintf("packs/%s.tar.gz", s->r->packs[pack]);
    fd = rs_store_open(s->r->st, path);
    free(path);
    rs_buf_init(&why);
    ok = fd >= 0;
    if (!ok)
    {
        rs_buf_addstr(&why, strerror(errno));
    }
    ok = ok && zin_open(&z, fd, true, &why);
    if (fd >= 0)
    {
        (void)close(fd);
    }
    free(t->at);
    t->at = NULL;
    t->n = 0;
    t->loaded = true;
    if (ok)
    {
        struct rs_tar_reader tr;
        struct rs_tar_entry  te;
        uint64_t             begins = 0;
        int                  more;

        tee.in = z.fd;
        rs_tar_reader_init(&tr, read_tee, &tee);
        rs_tar_entry_init(&te);
        /* Each member's header begins where the one before ends: what came
         * before it in the file, its data, and the data's padding. */
        while ((more = rs_tar_next(&tr, &te, &why)) == 1)
        {
            const char *p = te.name.data;
            uint64_t    num = 0;

            if (te.typeflag == '0' && number(&p, te.name.data + te.name.len, &num) && *p == '\0')
            {
                if (t->n == cap)
                {
                    cap = cap ? cap * 2 : 256;
                    t->at = rs_xreallocarray(t->at, cap, sizeof(*t->at));
                }
                t->at[t->n].member = num;
                t->at[t->n].offset = begins;
                t->n++;
            }
            begins = tee.off + te.size + (RS_TAR_BLOCK - te.size % RS_TAR_BLOCK) % RS_TAR_BLOCK;
        }
        rs_tar_entry_free(&te);
        ok = more == 0;
        /* The rest, for gpg and gzip to finish -- and, failing, to say why:
         * the secret key not there, say, rather than that what came out of
         * them ended early. */
        {
            unsigned char rest[4096];
            struct rs_buf how;

            while (read(z.fd, rest, sizeof(rest)) > 0)
            {
            }
            rs_buf_init(&how);
            if (!zin_close(&z, false, &how))
            {
                rs_buf_reset(&why);
                rs_buf_addstr(&why, how.data ? how.data : "");
                ok = false;
            }
            rs_buf_free(&how);
        }
    }
    if (tee.write_errno != 0 || fflush(tee.to) != 0)
    {
        /* Not this pack's fault: this machine's temporary files', so no
         * other is tried either. */
        (void)fclose(tee.to);
        free(t->at);
        t->at = NULL;
        t->n = 0;
        t->loaded = false;
        s->unsealed_off = true;
        rs_buf_free(&why);
        return false;
    }
    if (!ok)
    {
        warn_pack(s, pack, why.data);
    }
    rs_buf_free(&why);
    unsealed_made++;
    u->f = tee.to;
    u->bytes = tee.off;
    u->used = ++s->tick;
    s->unsealed_bytes += u->bytes;
    s->unsealed_n++;
    unsealed_room(s, pack);
    if (s->unsealed_n > unsealed_most)
    {
        unsealed_most = s->unsealed_n;
    }
    return true;
}

/* Pack `pack` open from `offset` in its file, where a gzip stream starts --
 * or, encrypted, from `offset` in the file it was decrypted into. */
static bool open_reader(struct rs_repo_stream *s, struct reader *rd, uint32_t pack,
                        uint64_t offset)
{
    char         *path;
    int           fd;
    struct rs_buf why;
    bool          ok;

    memset(rd, 0, sizeof(*rd));
    if (s->unsealed && unseal(s, pack))
    {
        rd->open = true;
        rd->pack = pack;
        rd->unsealed = true;
        rd->from.fd = fileno(s->unsealed[pack].f);
        rd->from.off = offset;
        rs_tar_reader_init(&rd->tr, read_at_fd, &rd->from);
        rs_tar_entry_init(&rd->te);
        return true;
    }
    path = rs_xasprintf("packs/%s.tar.gz", s->r->packs[pack]);
    fd = rs_store_open_at(s->r->st, path, offset);
    ok = fd >= 0;
    rs_buf_init(&why);
    if (!ok)
    {
        rs_buf_addstr(&why, strerror(errno));
    }
    ok = ok && zin_open(&rd->z, fd, true, &why);
    if (fd >= 0)
    {
        (void)close(fd);
    }
    if (!ok)
    {
        warn_pack(s, pack, why.data);
    } else
    {
        rd->open = true;
        rd->pack = pack;
        rs_tar_reader_init(&rd->tr, read_fd, &rd->z.fd);
        rs_tar_entry_init(&rd->te);
    }
    rs_buf_free(&why);
    free(path);
    return ok;
}

/* The segment of pack `pack` that member `member` is in: its first member
 * and where it begins -- the pack's start, if the pack has no .seek. An
 * encrypted repository's pack has none; where its members begin in the file
 * it is decrypted into is its .seeks instead, each member a segment. */
static void segment_of(struct rs_repo_stream *s, uint32_t pack, uint64_t member,
                       uint64_t *first, uint64_t *offset)
{
    struct seeks *t = &s->seeks[pack];
    size_t        lo = 0;
    size_t        hi;

    if (s->unsealed)
    {
        (void)unseal(s, pack);
    } else if (!t->loaded)
    {
        char         *path = rs_xasprintf("packs/%s.seek", s->r->packs[pack]);
        struct rs_buf text;
        struct rs_buf ignore;

        rs_buf_init(&ignore);
        if (rs_store_read(s->r->st, path, SMALL_MAX_LIST, &text, &ignore) &&
            !rs_repo_parse_seek(text.data, text.len, &t->at, &t->n))
        {
            t->at = NULL;
            t->n = 0;
        }
        rs_buf_free(&text);
        rs_buf_free(&ignore);
        free(path);
    }
    t->loaded = true;
    *first = 1;
    *offset = 0;
    hi = t->n;
    /* The last segment whose first member is no later than `member`. */
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;

        if (t->at[mid].member <= member)
        {
            *first = t->at[mid].member;
            *offset = t->at[mid].offset;
            lo = mid + 1;
        } else
        {
            hi = mid;
        }
    }
}

/* Opens pack `pack` at the segment that begins with member `first`, at
 * `offset`: the reader at that member's header -- or, if what is there is not
 * that, at the pack's start, its .seek not used again. */
static bool open_at(struct rs_repo_stream *s, struct reader *rd, uint32_t pack, uint64_t first,
                    uint64_t offset)
{
    const char *p;
    uint64_t    num = 0;

    if (offset > 0 && open_reader(s, rd, pack, offset))
    {
        int more = rs_tar_next(&rd->tr, &rd->te, &s->err);

        p = rd->te.name.data;
        if (more == 1 && rd->te.typeflag == '0' &&
            number(&p, rd->te.name.data + rd->te.name.len, &num) && *p == '\0' && num == first)
        {
            rd->at = num;
            rd->pending = true;
            return true;
        }
        rs_buf_reset(&s->err);
        close_reader(rd);
    }
    if (offset > 0)
    {
        free(s->seeks[pack].at);
        s->seeks[pack].at = NULL;
        s->seeks[pack].n = 0;
    }
    return open_reader(s, rd, pack, 0);
}

/* A reader at the start of member `member` of pack `pack`: one already open
 * that has not passed it -- nor is a segment or more short of it -- or the
 * pack opened again, at the segment it is in. */
static struct reader *position(struct rs_repo_stream *s, uint32_t pack, uint32_t member)
{
    struct reader *rd = NULL;
    struct reader *oldest = &s->readers[0];
    struct reader *behind = NULL;
    uint64_t       first;
    uint64_t       offset;
    uint64_t       x_first;
    uint64_t       x_offset;
    size_t         i;

    segment_of(s, pack, member, &first, &offset);
    for (i = 0; i < READERS && !rd; i++)
    {
        struct reader *x = &s->readers[i];
        bool           ahead = x->open && x->pack == pack &&
                     (x->at < member || (x->at == member && x->pending));

        if (ahead)
        {
            segment_of(s, pack, x->at, &x_first, &x_offset);
        }
        if (ahead && (x->at + 1 >= first || offset - x_offset <= SEEK_NEAR))
        {
            rd = x;
        } else if (ahead)
        {
            behind = x;
        } else if (!x->open || (oldest->open && x->used < oldest->used))
        {
            oldest = x;
        }
    }
    if (!rd)
    {
        /* One a segment or more short of it in this pack is the one to
         * open again, nearer. */
        rd = behind ? behind : oldest;
        close_reader(rd);
        if (!open_at(s, rd, pack, first, offset))
        {
            return NULL;
        }
    }
    rd->used = ++s->tick;
    while (!(rd->at == member && rd->pending))
    {
        const char *p;
        uint64_t    num = 0;
        int         more = rs_tar_next(&rd->tr, &rd->te, &s->err);

        if (more <= 0)
        {
            warn_pack(s, pack, more < 0 ? s->err.data : "it holds less than its index says");
            rs_buf_reset(&s->err);
            close_reader(rd);
            return NULL;
        }
        p = rd->te.name.data;
        rd->pending = rd->te.typeflag == '0' &&
                      number(&p, rd->te.name.data + rd->te.name.len, &num) && *p == '\0';
        if (rd->pending)
        {
            rd->at = num;
        }
        if (rd->pending && num > member)
        {
            warn_pack(s, pack, "it holds less than its index says");
            return NULL;
        }
    }
    return rd;
}

static const struct cached *cache_find(struct rs_repo_stream *s, const unsigned char d[32])
{
    size_t i;

    for (i = 0; i < s->ncache; i++)
    {
        if (memcmp(s->cache[i].d, d, 32) == 0)
        {
            s->cache[i].used = ++s->tick;
            return &s->cache[i];
        }
    }
    return NULL;
}

/* Keeps the chunk just read whole, making room for it. */
static void cache_keep(struct rs_repo_stream *s, struct cached *c)
{
    while (s->ncache > 0 && s->cache_bytes + c->len > CACHE_BYTES)
    {
        size_t i;
        size_t old = 0;

        for (i = 1; i < s->ncache; i++)
        {
            old = s->cache[i].used < s->cache[old].used ? i : old;
        }
        s->cache_bytes -= s->cache[old].len;
        free(s->cache[old].data);
        s->cache[old] = s->cache[--s->ncache];
    }
    s->cache = rs_xreallocarray(s->cache, s->ncache + 1, sizeof(*s->cache));
    c->used = ++s->tick;
    s->cache[s->ncache++] = *c;
    s->cache_bytes += c->len;
    memset(c, 0, sizeof(*c));
}

static void end_chunk(struct rs_repo_stream *s)
{
    if (s->filling.data && s->ch_left == 0 && s->ch == CH_READER)
    {
        cache_keep(s, &s->filling);
    }
    free(s->filling.data);
    memset(&s->filling, 0, sizeof(s->filling));
    s->ch = CH_NONE;
}

/* Starts sending the chunk `d`: from the cache, else from its pack. */
static void start_chunk(struct rs_repo_stream *s, const unsigned char d[32])
{
    const struct obj *o;
    const struct obj *m;

    s->ch_off = 0;
    s->cc = cache_find(s, d);
    if (s->cc)
    {
        s->ch = CH_CACHE;
        s->ch_left = s->cc->len;
        return;
    }
    o = map_find(&s->r->objects, d);
    s->rd = o ? position(s, o->pack, o->member) : NULL;
    if (!s->rd)
    {
        /* The rest of the content as zeros, which restore refuses. */
        s->ch = CH_ZERO;
        s->ch_left = s->content_left;
        return;
    }
    s->ch = CH_READER;
    s->ch_left = s->rd->te.size;
    s->rd->pending = false;
    m = map_find(&s->multi, d);
    if (m && m->pack > 1 && s->rd->te.size <= RS_REPO_CHUNK_MAX)
    {
        memcpy(s->filling.d, d, 32);
        s->filling.len = (size_t)s->rd->te.size;
        s->filling.data = rs_xmalloc(s->filling.len + 1);
    }
}

/* Up to `n` bytes more of the content being made: its chunks, then zeros if
 * they end before the index's size does -- restore refuses a file that does
 * not match its digest. */
static ssize_t content_read(struct rs_repo_stream *s, unsigned char *buf, size_t n)
{
    size_t got = 0;

    while (got < n && s->content_left > 0)
    {
        size_t  want = n - got < s->content_left ? n - got : (size_t)s->content_left;
        size_t  k;
        ssize_t r;

        if (s->ch == CH_NONE)
        {
            if (s->ci >= s->g->n)
            {
                memset(buf + got, 0, want);
                got += want;
                s->content_left -= want;
                continue;
            }
            if (s->first_chunk)
            {
                /* What only the chunks before this one were in is done with. */
                unsealed_done(s, s->first_chunk[(size_t)(s->g - s->groups)] + s->ci);
            }
            start_chunk(s, chunk_of(s->g, s->ci++));
            continue;
        }
        if (s->ch_left == 0)
        {
            end_chunk(s);
            continue;
        }
        k = want < s->ch_left ? want : (size_t)s->ch_left;
        if (s->ch == CH_CACHE)
        {
            memcpy(buf + got, s->cc->data + s->ch_off, k);
            r = (ssize_t)k;
        } else if (s->ch == CH_ZERO)
        {
            memset(buf + got, 0, k);
            r = (ssize_t)k;
        } else
        {
            r = rs_tar_read(&s->rd->tr, buf + got, k, &s->err);
            if (r <= 0)
            {
                warn_pack(s, s->rd->pack, r < 0 ? s->err.data : "it ends in the middle of a chunk");
                rs_buf_reset(&s->err);
                close_reader(s->rd);
                free(s->filling.data);
                memset(&s->filling, 0, sizeof(s->filling));
                s->ch = CH_ZERO;
                s->ch_left = s->content_left;
                continue;
            }
            if (s->filling.data)
            {
                memcpy(s->filling.data + s->ch_off, buf + got, (size_t)r);
            }
        }
        got += (size_t)r;
        s->ch_off += (uint64_t)r;
        s->ch_left -= (uint64_t)r;
        s->content_left -= (uint64_t)r;
    }
    return (ssize_t)got;
}

static void begin_content(struct rs_repo_stream *s, const struct group *g, uint64_t size)
{
    end_chunk(s);
    s->g = g;
    s->ci = 0;
    s->content_left = size;
}

/* The content being made, all of it, into a spool of its own. */
static bool spool(struct rs_repo_stream *s)
{
    unsigned char chunk[65536];

    s->spool = rs_tmpfile();
    if (!s->spool)
    {
        rs_buf_addf(&s->err, "a temporary file: %s", strerror(errno));
        return false;
    }
    while (s->content_left > 0)
    {
        ssize_t n = content_read(s, chunk, sizeof(chunk));

        if (fwrite(chunk, 1, (size_t)n, s->spool) != (size_t)n)
        {
            rs_buf_addf(&s->err, "a temporary file: %s", strerror(errno));
            return false;
        }
    }
    return fflush(s->spool) == 0;
}

/* The next file's header; false once they are all sent. */
static bool next_file(struct rs_repo_stream *s)
{
    for (;;)
    {
        const struct group    *g;
        const struct rs_entry *e;

        while (s->at < s->hi)
        {
            e = &s->ix->entries[s->refs[s->at++].entry];
            /* Not what the index says: left for restore to find missing. */
            if (e->size == s->spool_size)
            {
                header(s, e, s->spool_size, SRC_SPOOL);
                s->spool_at = 0;
                return true;
            }
        }
        if (s->spool)
        {
            (void)fclose(s->spool);
            s->spool = NULL;
        }
        if (s->gi >= s->ngroups)
        {
            end_chunk(s);
            return false;
        }
        g = &s->groups[s->gi++];
        e = &s->ix->entries[s->refs[g->lo].entry];
        begin_content(s, g, e->size);
        if (g->hi - g->lo == 1)
        {
            header(s, e, e->size, SRC_CONTENT);
            return true;
        }
        if (!spool(s))
        {
            s->failed = true;
            return false;
        }
        s->spool_size = e->size;
        s->at = g->lo;
        s->hi = g->hi;
    }
}

/* Queues the next header, or the end; false at the very end. */
static bool next(struct rs_repo_stream *s)
{
    rs_buf_reset(&s->out);
    s->out_pos = 0;
    while (s->phase == PH_OTHERS)
    {
        const struct rs_entry *e;

        if (s->pos >= s->ix->count)
        {
            s->phase = PH_FILES;
            s->pos = 0;
            break;
        }
        e = &s->ix->entries[s->pos];
        if (s->want[s->pos++] && (e->type == 'd' || e->type == 'l' || e->type == 'p'))
        {
            header(s, e, 0, SRC_ZERO);
            return true;
        }
    }
    if (s->phase == PH_FILES)
    {
        if (next_file(s))
        {
            return true;
        }
        if (s->failed)
        {
            return false;
        }
        s->phase = PH_UNREAD;
    }
    while (s->phase == PH_UNREAD)
    {
        const struct rs_entry *e;

        if (s->pos >= s->ix->count)
        {
            s->phase = PH_END;
            break;
        }
        e = &s->ix->entries[s->pos];
        if (s->want[s->pos++] && e->type == 'f' && e->hash_state != RS_HASH_PRESENT)
        {
            /* Zeros, as an image holds for it, which restore refuses as a
             * file that could not be read when it was captured. */
            header(s, e, e->size, SRC_ZERO);
            return true;
        }
    }
    if (s->phase == PH_END)
    {
        static const char zero[2 * RS_TAR_BLOCK];

        rs_buf_add(&s->out, zero, sizeof(zero));
        s->phase = PH_DONE;
        return true;
    }
    return false;
}

static ssize_t read_data(struct rs_repo_stream *s, void *buf, size_t n)
{
    ssize_t got;

    switch (s->src)
    {
    case SRC_CONTENT:
        return content_read(s, buf, n);
    case SRC_SPOOL:
        got = pread(fileno(s->spool), buf, n, (off_t)s->spool_at);
        if (got > 0)
        {
            s->spool_at += (uint64_t)got;
        }
        return got;
    default:
        memset(buf, 0, n);
        return (ssize_t)n;
    }
}

ssize_t rs_repo_stream_read(struct rs_repo_stream *s, void *buf, size_t n)
{
    for (;;)
    {
        if (s->out_pos < s->out.len)
        {
            size_t k = s->out.len - s->out_pos < n ? s->out.len - s->out_pos : n;

            memcpy(buf, s->out.data + s->out_pos, k);
            s->out_pos += k;
            return (ssize_t)k;
        }
        if (s->data_left > 0)
        {
            size_t  want = s->data_left < n ? (size_t)s->data_left : n;
            ssize_t got = read_data(s, buf, want);

            if (got <= 0)
            {
                if (s->err.len == 0)
                {
                    rs_buf_addstr(&s->err, "a temporary file ends early");
                }
                s->failed = true;
                return -1;
            }
            s->data_left -= (uint64_t)got;
            if (s->data_left == 0)
            {
                static const char zero[RS_TAR_BLOCK];

                rs_buf_reset(&s->out);
                s->out_pos = 0;
                rs_buf_add(&s->out, zero, (size_t)s->pad);
            }
            return got;
        }
        if (s->failed)
        {
            return -1;
        }
        if (!next(s))
        {
            return s->failed ? -1 : 0;
        }
    }
}

bool rs_repo_stream_close(struct rs_repo_stream *s, struct rs_buf *err)
{
    bool   ok;
    size_t i;

    if (!s)
    {
        return true;
    }
    ok = !s->failed;
    end_chunk(s);
    for (i = 0; i < READERS; i++)
    {
        close_reader(&s->readers[i]);
    }
    for (i = 0; i < s->ncache; i++)
    {
        free(s->cache[i].data);
    }
    if (s->spool)
    {
        (void)fclose(s->spool);
    }
    if (!ok && s->err.len > 0)
    {
        rs_buf_addf(err, "%s: %s", s->r->dir, s->err.data);
    }
    rs_buf_free(&s->out);
    rs_buf_free(&s->err);
    map_free(&s->multi);
    free(s->cache);
    free(s->warned);
    for (i = 0; i < s->r->npacks; i++)
    {
        free(s->seeks[i].at);
    }
    free(s->seeks);
    for (i = 0; s->unsealed && i < s->r->npacks; i++)
    {
        if (s->unsealed[i].f)
        {
            (void)fclose(s->unsealed[i].f);
        }
    }
    free(s->unsealed);
    free(s->first_chunk);
    free(s->last_use);
    free(s->by_last);
    free(s->want);
    free(s->refs);
    free(s->groups);
    free(s);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Pruning                                                                   */
/* ------------------------------------------------------------------------- */

/* Days since 1970-01-01 of a date in the proleptic Gregorian calendar, and
 * back (Howard Hinnant's days_from_civil and civil_from_days). */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    int64_t  era;
    unsigned yoe;
    unsigned doy;
    unsigned doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static int64_t year_of(int64_t days)
{
    int64_t  z = days + 719468;
    int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned m = mp < 10 ? mp + 3 : mp - 9;

    return (int64_t)yoe + era * 400 + (m <= 2);
}

/* The date a snapshot's name starts with, "YYYYMMDDT". */
static bool date_of(const char *name, unsigned *y, unsigned *m, unsigned *d)
{
    unsigned v[8];
    size_t   i;

    for (i = 0; i < 8; i++)
    {
        if (name[i] < '0' || name[i] > '9')
        {
            return false;
        }
        v[i] = (unsigned)(name[i] - '0');
    }
    if (name[8] != 'T')
    {
        return false;
    }
    *y = v[0] * 1000 + v[1] * 100 + v[2] * 10 + v[3];
    *m = v[4] * 10 + v[5];
    *d = v[6] * 10 + v[7];
    return *m >= 1 && *m <= 12 && *d >= 1 && *d <= 31;
}

/* The ISO week a date falls in, as YYYYWW: weeks start on Monday, and the
 * first of a year is the one with its first Thursday. */
static int64_t iso_week(unsigned y, unsigned m, unsigned d)
{
    int64_t days = days_from_civil((int64_t)y, m, d);
    int64_t weekday = ((days % 7) + 7 + 3) % 7;   /* Monday 0; 1970-01-01 was a Thursday */
    int64_t thursday = days - weekday + 3;
    int64_t year = year_of(thursday);

    return year * 100 + (thursday - days_from_civil(year, 1, 1)) / 7 + 1;
}

void rs_repo_choose(char *const *names, size_t n, const struct rs_repo_keep *keep, bool *kept)
{
    const unsigned limit[4] = { keep->daily, keep->weekly, keep->monthly, keep->yearly };
    unsigned       count[4] = { 0, 0, 0, 0 };
    int64_t        last[4] = { -1, -1, -1, -1 };
    unsigned       newest = 0;
    size_t         i = n;

    /* Newest first: the first of a period met is the newest in it. */
    while (i-- > 0)
    {
        unsigned y;
        unsigned m;
        unsigned d;
        int64_t  period[4];
        size_t   k;

        kept[i] = false;
        if (!date_of(names[i], &y, &m, &d))
        {
            kept[i] = true;
            continue;
        }
        if (newest < keep->last)
        {
            kept[i] = true;
            newest++;
        }
        period[0] = (int64_t)y * 10000 + (int64_t)m * 100 + d;
        period[1] = iso_week(y, m, d);
        period[2] = (int64_t)y * 100 + m;
        period[3] = (int64_t)y;
        for (k = 0; k < 4; k++)
        {
            if (period[k] != last[k])
            {
                last[k] = period[k];
                if (count[k] < limit[k])
                {
                    count[k]++;
                    kept[i] = true;
                }
            }
        }
    }
}

void rs_repo_pruned_free(struct rs_repo_pruned *p)
{
    rs_repo_free_names(p->dropped, p->ndropped);
    memset(p, 0, sizeof(*p));
}

static uint64_t disk_size(const struct rs_store *st, const char *name)
{
    struct rs_store_stat s;

    return rs_store_stat(st, name, &s) == 0 ? s.size : 0;
}

/* Removes a pack: its .idx first, so that whatever happens after, it no
 * longer counts. */
static uint64_t remove_pack(const struct rs_repo *r, const char *name)
{
    char    *idx = rs_xasprintf("packs/%s.idx", name);
    char    *content = rs_xasprintf("packs/%s.tar.gz", name);
    char    *sum = rs_xasprintf("packs/%s.sum", name);
    char    *seek = rs_xasprintf("packs/%s.seek", name);
    uint64_t freed = disk_size(r->st, idx) + disk_size(r->st, content) + disk_size(r->st, sum) +
                     disk_size(r->st, seek);

    (void)rs_store_remove(r->st, idx, true);
    (void)rs_store_remove(r->st, content, true);
    (void)rs_store_remove(r->st, sum, true);
    (void)rs_store_remove(r->st, seek, true);
    free(idx);
    free(content);
    free(sum);
    free(seek);
    return freed;
}

/* Copies the members of pack `name` that `keep` marks, and the lists that
 * `keepl` does, into a new pack, then removes the old one -- only once every
 * one of them is in the new. */
static bool rewrite(const struct rs_repo *r, const char *name, const struct rs_repo_idx *x,
                    const bool *keep, const bool *keepl, uint64_t *freed, struct rs_buf *err)
{
    char                *file = rs_xasprintf("packs/%s.tar.gz", name);
    char                *path = rs_store_path(r->st, file);
    uint64_t             before = disk_size(r->st, file);
    struct pack_out      pk;
    struct zin           z;
    struct rs_tar_reader tr;
    struct rs_tar_entry  te;
    char                *done = NULL;
    size_t               wanted = 0;
    size_t               copied = 0;
    size_t               i;
    int                  fd = rs_store_open(r->st, file);
    bool                 ok = fd >= 0;

    free(file);
    for (i = 0; i < x->nmembers; i++)
    {
        wanted += keep[i] ? 1 : 0;
    }
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    ok = zin_open(&z, fd, true, err);
    (void)close(fd);
    if (!ok)
    {
        free(path);
        return false;
    }
    if (!pack_open(r, &pk, err))
    {
        (void)zin_close(&z, true, err);
        free(path);
        return false;
    }
    rs_tar_reader_init(&tr, read_fd, &z.fd);
    rs_tar_entry_init(&te);
    /* A pack cut short stops here, and the count below then refuses it. */
    while (ok && copied < wanted && rs_tar_next(&tr, &te, err) == 1)
    {
        const char *p = te.name.data;
        uint64_t    num = 0;
        char        chunk[65536];
        ssize_t     got = 0;

        if (!number(&p, te.name.data + te.name.len, &num) || *p != '\0')
        {
            continue;
        }
        for (i = 0; i < x->nmembers && x->members[i].member != num; i++)
        {
        }
        if (i == x->nmembers || !keep[i] || x->members[i].size != te.size)
        {
            continue;
        }
        ok = pack_header(&pk, te.size, err);
        while (ok && (got = rs_tar_read(&tr, chunk, sizeof(chunk), err)) > 0)
        {
            ok = rs_tar_data(&pk.tar, chunk, (size_t)got);
        }
        ok = ok && got == 0 && rs_tar_pad(&pk.tar);
        if (ok)
        {
            pack_line(&pk, x->members[i].hash, te.size);
            copied++;
        }
    }
    rs_tar_entry_free(&te);
    (void)zin_close(&z, true, err);
    for (i = 0; ok && i < x->nlists; i++)
    {
        const struct rs_repo_list *l = &x->lists[i];

        if (keepl[i])
        {
            size_t c;

            rs_buf_addf(&pk.idx, "= %s %" PRIu64, l->hash, l->size);
            for (c = 0; c < l->n; c++)
            {
                rs_buf_addf(&pk.idx, " %s", x->chunks[l->first + c]);
            }
            rs_buf_addc(&pk.idx, '\n');
        }
    }
    if (ok && copied == wanted)
    {
        ok = pack_close(r, &pk, &done, err);
    } else
    {
        if (ok)
        {
            rs_buf_addf(err, "%s: it holds less than its index says; left as it is", path);
        }
        pack_discard(&pk);
        ok = false;
    }
    if (ok)
    {
        char *made = rs_xasprintf("packs/%s.tar.gz", done);

        (void)remove_pack(r, name);
        *freed += before > disk_size(r->st, made) ? before - disk_size(r->st, made) : 0;
        free(made);
    }
    free(done);
    free(path);
    return ok;
}

/* What an interrupted capture or prune left behind: temporary files, and a
 * pack with no .idx. */
static void clear_leftovers(const struct rs_repo *r)
{
    size_t n;
    char **names = rs_store_list(r->st, "packs", rs_store_keep_all, NULL, &n);
    size_t i;

    for (i = 0; i < n; i++)
    {
        const char *name = names[i];
        size_t      len = strlen(name);
        char       *path = rs_xasprintf("packs/%s", name);

        if (name[0] == '.' && len > 4 && strcmp(name + len - 4, ".tmp") == 0)
        {
            (void)rs_store_remove(r->st, path, false);
        } else if (len > 7 && strcmp(name + len - 7, ".tar.gz") == 0)
        {
            char                *idx = rs_xasprintf("packs/%.*s.idx", (int)(len - 7), name);
            struct rs_store_stat st;

            if (rs_store_stat(r->st, idx, &st) != 0)
            {
                (void)rs_store_remove(r->st, path, true);
            }
            free(idx);
        } else if ((len > 4 && strcmp(name + len - 4, ".sum") == 0) ||
                   (len > 5 && strcmp(name + len - 5, ".seek") == 0))
        {
            size_t               ext = name[len - 1] == 'm' ? 4 : 5;
            char                *idx = rs_xasprintf("packs/%.*s.idx", (int)(len - ext), name);
            struct rs_store_stat st;

            /* A .sum or .seek is a pack's only while its .idx is there. */
            if (rs_store_stat(r->st, idx, &st) != 0)
            {
                (void)rs_store_remove(r->st, path, true);
            }
            free(idx);
        }
        free(path);
    }
    rs_repo_free_names(names, n);
    names = rs_store_list(r->st, "snapshots", rs_store_keep_all, NULL, &n);
    for (i = 0; i < n; i++)
    {
        if (names[i][0] == '.')
        {
            char *path = rs_xasprintf("snapshots/%s", names[i]);

            (void)remove_snapshot_dir(r->st, path);
            free(path);
        }
    }
    rs_repo_free_names(names, n);
}

/*
 * What the snapshots `names` need: the chunks, into `chunks`, and the lists,
 * into `lists` -- each with pack 0, for the first copy found to take.
 */
static bool live_content(struct rs_repo *r, char *const *names, size_t n, struct objmap *chunks,
                         struct objmap *lists, bool *stopped, struct rs_buf *err)
{
    size_t i;

    load_objects(r);
    /* A pack whose .idx cannot be read may hold the only list of a file
     * that needs chunks in the others. */
    if (r->unreadable > 0)
    {
        rs_buf_addf(err, "%s: %zu packs' indexes could not be read, so what the snapshots need "
                    "is not known; no content was removed", r->dir, r->unreadable);
        return false;
    }
    for (i = 0; i < n; i++)
    {
        struct rs_index ix;
        size_t          k;

        if (stopping(r))
        {
            *stopped = true;
            return true;
        }
        rs_index_init(&ix);
        if (!rs_repo_load_index_cached(r, names[i], &ix, err))
        {
            rs_index_free(&ix);
            return false;
        }
        for (k = 0; k < ix.count; k++)
        {
            const struct rs_entry *e = &ix.entries[k];
            unsigned char          d[32];
            const struct obj      *l;

            if (!e->stored || e->type != 'f' || e->hash_state != RS_HASH_PRESENT ||
                !unhex(e->hash, d))
            {
                continue;
            }
            (void)map_add(chunks, d, 0, 0);
            l = map_find(&r->listed, d);
            if (l && !map_find(lists, d))
            {
                const struct list *li = &r->lists[l->member];
                size_t             c;

                (void)map_add(lists, d, 0, 0);
                for (c = 0; c < li->n; c++)
                {
                    (void)map_add(chunks, r->chunks[li->first + c], 0, 0);
                }
            }
        }
        rs_index_free(&ix);
    }
    return true;
}

/*
 * The pack lists of the snapshots `names`, written again after a prune
 * moved their content into new packs -- and written for the first time for
 * snapshots restate 1 made, which have none. One that cannot be worked out
 * loses its list rather than keep one that may be wrong: a prune that goes
 * by the lists then refuses to run, instead of removing what it needs.
 */
static void refresh_pack_lists(struct rs_repo *r, char *const *names, size_t n)
{
    size_t i;

    load_objects(r);
    for (i = 0; i < n; i++)
    {
        char           *path = snapshot_file(names[i], "packs");
        bool           *used = rs_xcalloc(r->npacks + 1, sizeof(*used));
        struct rs_index ix;
        struct rs_buf   err;
        bool            ok;

        rs_index_init(&ix);
        rs_buf_init(&err);
        ok = r->unreadable == 0 && rs_repo_load_index_cached(r, names[i], &ix, &err);
        if (ok)
        {
            size_t len = 0;
            char  *text;

            mark_index(r, &ix, used);
            text = pack_list_text(r, used, NULL, 0, &len);
            ok = rs_store_replace(r->st, path, text, len, &err);
            free(text);
        }
        if (!ok)
        {
            (void)rs_store_remove(r->st, path, true);
        }
        rs_index_free(&ix);
        rs_buf_free(&err);
        free(used);
        free(path);
    }
}

/* A .sum for each pack restate 1 wrote, which has none. One that is there
 * but wrong is left as it is, for check to report. */
static void add_sums(const struct rs_repo *r)
{
    size_t i;

    for (i = 0; i < r->npacks; i++)
    {
        char                *path = rs_xasprintf("packs/%s.sum", r->packs[i]);
        struct rs_store_stat st;

        if (rs_store_stat(r->st, path, &st) != 0 && errno == ENOENT)
        {
            struct rs_buf err;

            rs_buf_init(&err);
            if (!write_sum(r->st, r->packs[i], &err))
            {
                rs_warn("%s", err.data);
            }
            rs_buf_free(&err);
        }
        free(path);
    }
}

/* Whether the digest `hash` is one `live` has, and this is the first copy of
 * it met: that one is kept, any other is dead. */
static bool first_live(const struct objmap *live, const char *hash)
{
    unsigned char d[32];
    struct obj   *o = unhex(hash, d) ? map_find(live, d) : NULL;

    if (!o || o->pack != 0)
    {
        return false;
    }
    o->pack = 1;
    return true;
}

/* Drops the snapshots out->dropped names, in turn, until asked to stop:
 * then out->dropped keeps only those that went. */
static void drop_snapshots(const struct rs_repo *r, struct rs_repo_pruned *out)
{
    size_t i;

    for (i = 0; i < out->ndropped; i++)
    {
        char *dir;

        if (stopping(r))
        {
            while (out->ndropped > i)
            {
                free(out->dropped[--out->ndropped]);
            }
            out->stopped = true;
            break;
        }
        dir = rs_xasprintf("snapshots/%s", out->dropped[i]);
        if (!remove_snapshot_dir(r->st, dir))
        {
            char *path = rs_store_path(r->st, dir);

            rs_warn("%s: %s; left as it is", path, strerror(errno));
            free(path);
        }
        free(dir);
    }
    rs_store_sync_dir(r->st, "");
}

/* A pack's files on disk: its content, its .idx, its .sum and its .seek. */
static uint64_t pack_disk(const struct rs_repo *r, const char *name)
{
    static const char *const ext[] = { "tar.gz", "idx", "sum", "seek" };
    uint64_t                 total = 0;
    size_t                   i;

    for (i = 0; i < sizeof(ext) / sizeof(ext[0]); i++)
    {
        char *path = rs_xasprintf("packs/%s.%s", name, ext[i]);

        total += disk_size(r->st, path);
        free(path);
    }
    return total;
}

/* Whether pack `name` has a .seek: whether it can be read from the middle. */
static bool has_seek(const struct rs_repo *r, const char *name)
{
    char *path = rs_xasprintf("packs/%s.seek", name);
    bool  there = rs_store_is_file(r->st, path);

    free(path);
    return there;
}

/*
 * The content the snapshots `left` need, kept, and the rest removed: a pack
 * with nothing needed in it goes, and one a quarter or more dead is written
 * again -- as, with `repack`, is every one with no .seek.
 */
static bool sweep(struct rs_repo *r, char *const *left, size_t nleft, bool repack,
                  struct rs_repo_pruned *out, struct rs_buf *err)
{
    struct objmap live;
    struct objmap live_lists;
    size_t        i;
    bool          ok;

    memset(&live, 0, sizeof(live));
    memset(&live_lists, 0, sizeof(live_lists));
    /* Content is removed only once every snapshot left has been read: one
     * that cannot be read might be the only thing that needs some of it. */
    ok = out->stopped || live_content(r, left, nleft, &live, &live_lists, &out->stopped, err);
    if (ok && repack)
    {
        uint64_t total = 0;

        for (i = 0; i < r->npacks; i++)
        {
            total += has_seek(r, r->packs[i]) ? 0 : pack_disk(r, r->packs[i]);
        }
        rs_progress_phase("repacking", total);
    }
    for (i = 0; ok && !out->stopped && i < r->npacks; i++)
    {
        struct rs_repo_idx x;
        struct rs_buf      why;
        size_t             k;
        bool              *keepm;
        bool              *keepl;
        uint64_t           total = 0;
        uint64_t           kept_bytes = 0;
        uint64_t           was = 0;
        size_t             nkept = 0;
        size_t             nlists = 0;
        bool               seekless = repack && !has_seek(r, r->packs[i]);

        if (stopping(r))
        {
            out->stopped = true;
            break;
        }
        rs_buf_init(&why);
        if (!pack_idx(r, r->packs[i], &x, &why))
        {
            rs_warn("%s; left as it is", why.data);
            rs_buf_free(&why);
            continue;
        }
        was = seekless ? pack_disk(r, r->packs[i]) : 0;
        keepm = rs_xcalloc(x.nmembers + 1, sizeof(*keepm));
        keepl = rs_xcalloc(x.nlists + 1, sizeof(*keepl));
        for (k = 0; k < x.nmembers; k++)
        {
            total += x.members[k].size;
            if (x.members[k].live && first_live(&live, x.members[k].hash))
            {
                keepm[k] = true;
                kept_bytes += x.members[k].size;
                nkept++;
            }
        }
        for (k = 0; k < x.nlists; k++)
        {
            keepl[k] = first_live(&live_lists, x.lists[k].hash);
            nlists += keepl[k] ? 1 : 0;
        }
        if (nkept == 0 && nlists == 0)
        {
            out->bytes_freed += remove_pack(r, r->packs[i]);
            out->packs_removed++;
        } else if (((total - kept_bytes) * 4 >= total && total > kept_bytes) || seekless)
        {
            /* A quarter or more of it is dead: worth writing again -- which,
             * encrypted, needs the keys to encrypt to. */
            if (r->encrypted && r->nrecips == 0)
            {
                out->packs_left++;
            } else if (rewrite(r, r->packs[i], &x, keepm, keepl, &out->bytes_freed, &why))
            {
                out->packs_rewritten++;
            } else
            {
                rs_warn("%s", why.data);
            }
        }
        rs_progress_bytes(was);
        free(keepm);
        free(keepl);
        rs_repo_idx_free(&x);
        rs_buf_free(&why);
    }
    if (repack)
    {
        rs_progress_done();
    }
    if (ok)
    {
        clear_leftovers(r);
        drop_old_chunk_keys(r);
        list_packs(r);
        unload(r);
        /* A rewrite moved content the lists name, so they are written again
         * even when stopping; what else is left waits for the next prune. */
        if (!out->stopped || out->packs_rewritten > 0)
        {
            refresh_pack_lists(r, left, nleft);
        }
        if (!out->stopped)
        {
            add_sums(r);
        }
        tidy_cache(r);
        rs_store_sync_dir(r->st, "packs");
    }
    map_free(&live);
    map_free(&live_lists);
    return ok;
}

bool rs_repo_prune(struct rs_repo *r, const struct rs_repo_keep *keep, bool dry_run,
                   struct rs_repo_pruned *out, struct rs_buf *err)
{
    size_t n;
    char **names = rs_repo_snapshots(r, &n);
    char **left = rs_xcalloc(n + 1, sizeof(*left));
    bool  *kept = rs_xcalloc(n + 1, sizeof(*kept));
    size_t nleft = 0;
    size_t i;
    bool   ok;

    memset(out, 0, sizeof(*out));
    rs_repo_choose(names, n, keep, kept);
    for (i = 0; i < n; i++)
    {
        if (kept[i])
        {
            left[nleft++] = names[i];
        } else
        {
            out->dropped = rs_xreallocarray(out->dropped, out->ndropped + 1,
                                            sizeof(*out->dropped));
            out->dropped[out->ndropped++] = rs_xstrdup(names[i]);
        }
    }
    if (dry_run)
    {
        free(left);
        free(kept);
        rs_repo_free_names(names, n);
        return true;
    }
    drop_snapshots(r, out);
    ok = sweep(r, left, nleft, false, out, err);
    free(left);
    free(kept);
    rs_repo_free_names(names, n);
    return ok;
}

bool rs_repo_repack(struct rs_repo *r, bool dry_run, struct rs_repo_pruned *out,
                    struct rs_buf *err)
{
    size_t n;
    char **names;
    bool   ok;

    memset(out, 0, sizeof(*out));
    if (r->encrypted)
    {
        rs_buf_addf(err, "%s: an encrypted repository's packs are encrypted whole, and gpg reads "
                    "one only from its start: written again, they would read no faster",
                    r->dir);
        return false;
    }
    if (dry_run)
    {
        size_t i;

        for (i = 0; i < r->npacks; i++)
        {
            out->packs_rewritten += has_seek(r, r->packs[i]) ? 0 : 1;
        }
        return true;
    }
    names = rs_repo_snapshots(r, &n);
    ok = sweep(r, names, n, true, out, err);
    rs_repo_free_names(names, n);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Protecting what is finished                                               */
/* ------------------------------------------------------------------------- */

/* What protect could not protect, as "PATH: why". */
static void protect_failed(struct rs_repo_protected *out, const char *dir, const char *name,
                           const char *why)
{
    out->failed = rs_xreallocarray(out->failed, out->nfailed + 1, sizeof(*out->failed));
    out->failed[out->nfailed++] = strcmp(name, ".") != 0 ? rs_xasprintf("%s/%s: %s", dir, name, why)
                                                         : rs_xasprintf("%s: %s", dir, why);
}

/*
 * What protect makes of each thing it protects.
 *
 * A directory the machines add to is, on Linux, 0770: the repository's own
 * append-only too, so that nothing in it is removed or renamed, and what is
 * finished in packs/ and snapshots/ immutable (fsflags.h), since a Linux NFS
 * client cannot use a sticky directory a share squashes it into. Where the
 * filesystem has NFSv4 ACLs (ZFS on FreeBSD), it is 0770 and an ACL says that
 * each removes only what is its own, for the same clients. Anywhere else, it
 * is sticky.
 */
enum protect_as {
    AS_FINISHED, /* a finished file: 0440 */
    AS_SNAPSHOT, /* a finished snapshot's directory: 0550 */
    AS_SHARED,   /* packs/ and snapshots/ */
    AS_TOP       /* the repository's own directory */
};

/*
 * A file the file server has lent out -- an NFSv4 write delegation, a lease --
 * cannot be opened without waiting (O_NONBLOCK) until the client gives it back:
 * EWOULDBLOCK. A Linux NFS client holds one on what it has just written for up
 * to the server's lease time, 90 seconds by default, so protect run as soon as
 * a capture finishes finds its last files lent. It goes on with the rest, then
 * tries those again, waiting longer each time, for up to two lease times.
 */
#define PROTECT_WAIT_MS (180L * 1000L)
#define PROTECT_NAP_MS  250L
#define PROTECT_NAP_MAX (15L * 1000L)
#define PROTECT_LENT    1024 /* at most this many waited for; the rest fail */

static bool lent(int err)
{
    return err == EWOULDBLOCK || err == EAGAIN;
}

/* The files protect is waiting for. */
struct protect_lent {
    struct lent_file {
        int   dfd; /* its directory, a descriptor of its own */
        char *dir;
        char *name;
    } *f;
    size_t n;
};

/* The flags `as` has on Linux. */
static unsigned protect_flags(enum protect_as as)
{
    if (!rs_fsflags_supported())
    {
        return 0;
    }
    return as == AS_TOP ? RS_FSFLAGS_APPEND : as == AS_SHARED ? 0 : RS_FSFLAGS_IMMUTABLE;
}

/* Why `fd`'s flags could not be set to protect's, as protect_failed says it. */
static const char *flags_failed(int err)
{
    if (rs_fsflags_none(err))
    {
        return "its filesystem has no immutable or append-only flags (chattr +i and +a), "
               "which protect sets on Linux";
    }
    if (err == EPERM)
    {
        return geteuid() == 0 ? "root here may not make it immutable or append-only (chattr +i "
                                "and +a need CAP_LINUX_IMMUTABLE, which a container's root "
                                "often lacks)"
                              : "only root can make it immutable or append-only (chattr +i "
                                "and +a)";
    }
    return strerror(err);
}

/* Gives `fd`, which `st` describes, `owner`, `group` and `mode`, then the
 * flags `want`: NULL, or why it could not. Its flags, `have`, are cleared
 * first, since nothing immutable or append-only changes owner or mode, and
 * put back if it could not be given away. */
static const char *protect_set(int fd, const struct stat *st, uid_t owner, gid_t group,
                               mode_t mode, unsigned have, unsigned want)
{
    bool owner_ok = st->st_uid == owner && st->st_gid == group;
    bool mode_ok = (st->st_mode & 07777) == mode;

    if ((!owner_ok || !mode_ok) && have != 0 && rs_fsflags_set(fd, 0) != 0)
    {
        return flags_failed(errno);
    }
    if ((!owner_ok && fchown(fd, owner, group) != 0) || (!mode_ok && fchmod(fd, mode) != 0))
    {
        const char *why = strerror(errno);

        if (have != 0)
        {
            (void)rs_fsflags_set(fd, have);
        }
        return why;
    }
    if (rs_fsflags_supported() && rs_fsflags_set(fd, want) != 0)
    {
        return flags_failed(errno);
    }
    return NULL;
}

/*
 * Makes `name` in the directory `dfd` (`dir`, for messages) `owner`'s and
 * `group`'s, with the mode and flags `as` has, where it is not so already: 1
 * if it was changed, 0 if it was so, -1 if it could not be, saying why. Only a
 * regular file or a directory, never through a symlink, and a file only with
 * one name: the machines that write here could plant a link to anything for
 * root to give away. One that is not there (a prune took it meanwhile) is
 * left out, as 2.
 */
/* How long protect waits for files the file server lends out, and the opens
 * it refuses as lent, for the unit tests (rs_repo_set_protect_wait). */
static long protect_wait_ms = PROTECT_WAIT_MS;
static int  protect_lent;

void rs_repo_set_protect_wait(long wait_ms, int lent)
{
    protect_wait_ms = wait_ms < 0 ? PROTECT_WAIT_MS : wait_ms;
    protect_lent = lent;
}

/*
 * `name` in `dfd` made what `as` says: 1 if it was changed, 0 if it was so
 * already, 2 if it is gone, -1 (and in out->failed) if it cannot be -- or,
 * with `wait`, 3 if it is a file the server has lent out (lent()).
 */
static int protect_one(int dfd, const char *dir, const char *name, bool is_dir, bool wait,
                       uid_t owner, gid_t group, enum protect_as as,
                       struct rs_repo_protected *out)
{
    struct stat before;
    struct stat st;
    int         fd;
    int         changed;
    bool        acl;
    const char *why;
    mode_t      mode = as == AS_FINISHED ? 0440 : as == AS_SNAPSHOT ? 0550 : 01770;
    unsigned    want = protect_flags(as);
    unsigned    have = 0;

    if (fstatat(dfd, name, &before, AT_SYMLINK_NOFOLLOW) != 0)
    {
        if (errno == ENOENT)
        {
            return 2;
        }
        protect_failed(out, dir, name, strerror(errno));
        return -1;
    }
    if (is_dir ? !S_ISDIR(before.st_mode) : !S_ISREG(before.st_mode))
    {
        protect_failed(out, dir, name, is_dir ? "not a directory" : "not a regular file");
        return -1;
    }
    fd = openat(dfd, name,
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (is_dir ? O_DIRECTORY : 0));
    if (fd >= 0 && !is_dir && protect_lent > 0)
    {
        protect_lent--;
        (void)close(fd);
        fd = -1;
        errno = EWOULDBLOCK;
    }
    if (fd < 0 && wait && !is_dir && lent(errno))
    {
        return 3;
    }
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_dev != before.st_dev ||
        st.st_ino != before.st_ino)
    {
        protect_failed(out, dir, name, fd < 0 ? strerror(errno) : "changed while it was looked at");
        if (fd >= 0)
        {
            (void)close(fd);
        }
        return -1;
    }
    acl = mode == 01770 && !rs_fsflags_supported() && nfs4_acls(fd);
    mode = mode == 01770 && (acl || rs_fsflags_supported()) ? 0770 : mode;
    if (rs_fsflags_supported() && rs_fsflags_get(fd, &have) != 0)
    {
        if (want != 0 || !rs_fsflags_none(errno))
        {
            protect_failed(out, dir, name, flags_failed(errno));
            (void)close(fd);
            return -1;
        }
        have = 0;
    }
    changed = st.st_uid != owner || st.st_gid != group || (st.st_mode & 07777) != mode ||
              have != want;
    /* One already protected is left as it is, whatever names it has: a
     * machine may link to it, and not give it away. */
    why = !changed                            ? NULL
          : !is_dir && st.st_nlink != 1 ? "it has other names (hard links), and is left as it is"
                                        : protect_set(fd, &st, owner, group, mode, have, want);
    if (why)
    {
        protect_failed(out, dir, name, why);
        changed = -1;
    }
#ifdef RS_NFS4_ACLS
    /* The ACL after the mode: a chmod can drop what an ACL adds. */
    if (changed >= 0 && acl)
    {
        int set = protect_acl(fd);

        if (set < 0)
        {
            protect_failed(out, dir, name, strerror(errno));
        }
        changed = set != 0 ? set : changed;
    }
#endif
    (void)close(fd);
    return changed;
}

/* Counts what protect_one did with a file. */
static void protect_file(int dfd, const char *dir, const char *name, uid_t owner, gid_t group,
                         struct rs_repo_protected *out, bool *any, struct protect_lent *later)
{
    int did = protect_one(dfd, dir, name, false, later && later->n < PROTECT_LENT, owner, group,
                          AS_FINISHED, out);

    if (did == 3 && later)
    {
        int               own = fcntl(dfd, F_DUPFD_CLOEXEC, 0);
        struct lent_file *f;

        if (own < 0)
        {
            protect_failed(out, dir, name, strerror(errno));
            return;
        }
        later->f = rs_xreallocarray(later->f, later->n + 1, sizeof(*later->f));
        f = &later->f[later->n++];
        f->dfd = own;
        f->dir = rs_xstrdup(dir);
        f->name = rs_xstrdup(name);
        return;
    }
    if (did == 1)
    {
        out->files++;
        *any = true;
    } else if (did == 0)
    {
        out->unchanged++;
    }
}

/* The directory `name` in `dfd`, opened never through a symlink; -1, saying
 * why, if it cannot be. */
static int protect_open_dir(int dfd, const char *dir, const char *name,
                            struct rs_repo_protected *out)
{
    int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

    if (fd < 0)
    {
        protect_failed(out, dir, name, strerror(errno));
    }
    return fd;
}

/* The suffixes of a pack's files: each is protected once the .idx, written
 * last, says the pack is finished. */
static const char *pack_suffix(const char *name)
{
    static const char *const sfx[] = { ".tar.gz", ".idx", ".sum", ".seek" };
    size_t                   len = strlen(name);
    size_t                   i;

    for (i = 0; i < sizeof(sfx) / sizeof(sfx[0]); i++)
    {
        size_t n = strlen(sfx[i]);

        if (len > n && strcmp(name + len - n, sfx[i]) == 0)
        {
            return name + len - n;
        }
    }
    return NULL;
}

/* Each finished pack's files in packs/, `pfd`. */
static void protect_packs(int pfd, const char *dir, uid_t owner, gid_t group,
                          struct rs_repo_protected *out, struct protect_lent *later)
{
    int                  listing = dup(pfd);
    DIR                 *d = listing >= 0 ? fdopendir(listing) : NULL;
    const struct dirent *de;
    bool                 any = false;

    if (!d && listing >= 0)
    {
        (void)close(listing);
    }
    while (d && (de = readdir(d)) != NULL)
    {
        const char *sfx = de->d_name[0] == '.' ? NULL : pack_suffix(de->d_name);
        char       *idx;
        struct stat st;

        if (!sfx)
        {
            continue;
        }
        idx = rs_xasprintf("%.*s.idx", (int)(sfx - de->d_name), de->d_name);
        /* Anything there by that name says it is finished; protect_one
         * refuses what is not a regular file, and says so. */
        if (fstatat(pfd, idx, &st, AT_SYMLINK_NOFOLLOW) == 0)
        {
            protect_file(pfd, dir, de->d_name, owner, group, out, &any, later);
        }
        free(idx);
    }
    if (d)
    {
        (void)closedir(d);
    }
}

/* Each finished snapshot in snapshots/, `sfd`: its files, then itself. */
static void protect_snapshots(int sfd, const char *dir, uid_t owner, gid_t group,
                              struct rs_repo_protected *out, struct protect_lent *later)
{
    int                  listing = dup(sfd);
    DIR                 *d = listing >= 0 ? fdopendir(listing) : NULL;
    const struct dirent *de;

    if (!d && listing >= 0)
    {
        (void)close(listing);
    }
    while (d && (de = readdir(d)) != NULL)
    {
        char                *path;
        int                  fd;
        int                  inner;
        DIR                 *files;
        const struct dirent *fe;
        bool                 any = false;
        int                  did;

        /* One being written has a name of its own, beginning with '.'. */
        if (!rs_repo_name_valid(de->d_name))
        {
            continue;
        }
        fd = protect_open_dir(sfd, dir, de->d_name, out);
        if (fd < 0)
        {
            continue;
        }
        path = rs_xasprintf("%s/%s", dir, de->d_name);
        inner = dup(fd);
        files = inner >= 0 ? fdopendir(inner) : NULL;
        if (!files && inner >= 0)
        {
            (void)close(inner);
        }
        while (files && (fe = readdir(files)) != NULL)
        {
            if (fe->d_name[0] != '.')
            {
                protect_file(fd, path, fe->d_name, owner, group, out, &any, later);
            }
        }
        if (files)
        {
            (void)closedir(files);
        }
        did = protect_one(sfd, dir, de->d_name, true, false, owner, group, AS_SNAPSHOT, out);
        if (did == 1 || (did == 0 && any))
        {
            out->snapshots++;
        }
        out->unchanged += did == 0 ? 1 : 0;
        (void)close(fd);
        free(path);
    }
    if (d)
    {
        (void)closedir(d);
    }
}

/* The files `later` holds, tried again with longer and longer pauses until
 * each is done or protect_wait_ms has gone by; then once more, saying why
 * for each still lent. */
static void protect_waiting(struct protect_lent *later, uid_t owner, gid_t group,
                            struct rs_repo_protected *out)
{
    long   waited = 0;
    long   nap = PROTECT_NAP_MS;
    size_t i;
    size_t left = later->n;

    out->waited_for = later->n;
    while (left > 0)
    {
        bool last = waited >= protect_wait_ms;

        if (!last)
        {
            struct timespec ts;
            long            ms = nap < protect_wait_ms - waited ? nap : protect_wait_ms - waited;

            ts.tv_sec = ms / 1000;
            ts.tv_nsec = (ms % 1000) * 1000000L;
            (void)nanosleep(&ts, NULL);
            waited += ms;
            nap = nap * 2 < PROTECT_NAP_MAX ? nap * 2 : PROTECT_NAP_MAX;
        }
        for (i = 0; i < later->n; i++)
        {
            struct lent_file *f = &later->f[i];
            int               did;

            if (f->dfd < 0)
            {
                continue;
            }
            /* The last time, one still lent fails, saying why. */
            did = protect_one(f->dfd, f->dir, f->name, false, !last, owner, group, AS_FINISHED,
                              out);
            if (did == 3)
            {
                continue;
            }
            out->files += did == 1 ? 1 : 0;
            out->unchanged += did == 0 ? 1 : 0;
            (void)close(f->dfd);
            f->dfd = -1;
            left--;
        }
        if (last)
        {
            break;
        }
    }
    for (i = 0; i < later->n; i++)
    {
        free(later->f[i].dir);
        free(later->f[i].name);
    }
    free(later->f);
}

bool rs_repo_protect(const char *dir, uid_t owner, gid_t group, struct rs_repo_protected *out,
                     struct rs_buf *err)
{
    static const char *const subs[] = { "packs", "snapshots" };
    int                      top;
    size_t                   i;
    bool                     any = false;
    struct protect_lent      later;

    memset(out, 0, sizeof(*out));
    memset(&later, 0, sizeof(later));
    if (rs_remote_is(dir))
    {
        rs_buf_addf(err, "%s: protect is run on the storage host, not through restate-proxy",
                    dir);
        return false;
    }
    if (!rs_repo_is(dir))
    {
        rs_buf_addf(err, "%s: not a restate repository", dir);
        return false;
    }
    top = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (top < 0)
    {
        rs_buf_addf(err, "%s: %s", dir, strerror(errno));
        return false;
    }
    /* On Linux, where it cannot be made append-only, nothing is changed: its
     * directories without their sticky bit and nothing made immutable would
     * leave what is finished for any machine to remove. */
    if (rs_fsflags_supported())
    {
        unsigned flags;

        if (rs_fsflags_get(top, &flags) != 0 ||
            rs_fsflags_set(top, flags | RS_FSFLAGS_APPEND) != 0)
        {
            rs_buf_addf(err, "%s: %s; nothing was changed", dir, flags_failed(errno));
            (void)close(top);
            return false;
        }
    }
    /* An encrypted repository's chunk key, each copy of it; never the marker,
     * the lock or readers, which the machines that write here open as their
     * own. */
    {
        struct rs_store *st = rs_store_local(dir);
        size_t           ncopies;
        char           **copies = chunk_key_copies(st, &ncopies);

        for (i = 0; i < ncopies; i++)
        {
            protect_file(top, dir, copies[i], owner, group, out, &any, &later);
        }
        rs_repo_free_names(copies, ncopies);
        rs_store_free(st);
    }
    for (i = 0; i < sizeof(subs) / sizeof(subs[0]); i++)
    {
        char *path = rs_xasprintf("%s/%s", dir, subs[i]);
        int   fd = protect_open_dir(top, dir, subs[i], out);
        int   did;

        if (fd >= 0)
        {
            if (i == 0)
            {
                protect_packs(fd, path, owner, group, out, &later);
            } else
            {
                protect_snapshots(fd, path, owner, group, out, &later);
            }
            (void)close(fd);
        }
        /* Anyone in the group adds to it, and removes only what is their
         * own -- what they have not finished. */
        did = protect_one(top, dir, subs[i], true, false, owner, group, AS_SHARED, out);
        out->dirs += did == 1 ? 1 : 0;
        out->unchanged += did == 0 ? 1 : 0;
        free(path);
    }
    {
        int did = protect_one(top, dir, ".", true, false, owner, group, AS_TOP, out);

        out->dirs += did == 1 ? 1 : 0;
        out->unchanged += did == 0 ? 1 : 0;
    }
    (void)close(top);
    protect_waiting(&later, owner, group, out);
    return true;
}

void rs_repo_protected_free(struct rs_repo_protected *p)
{
    size_t i;

    for (i = 0; i < p->nfailed; i++)
    {
        free(p->failed[i]);
    }
    free(p->failed);
    memset(p, 0, sizeof(*p));
}

/* Whether `name` is among `names`, which are in order. */
static bool listed_in(char *const *names, size_t n, const char *name)
{
    return n > 0 && bsearch(&name, names, n, sizeof(*names), by_name) != NULL;
}

bool rs_repo_prune_whole(struct rs_repo *r, const struct rs_repo_keep *keep, bool dry_run,
                         struct rs_repo_pruned *out, struct rs_buf *err)
{
    size_t  n;
    char  **names = rs_repo_snapshots(r, &n);
    bool   *kept = rs_xcalloc(n + 1, sizeof(*kept));
    char  **need = NULL;
    size_t  nneed = 0;
    size_t  i;
    bool    ok = true;

    memset(out, 0, sizeof(*out));
    rs_repo_choose(names, n, keep, kept);
    /* Every snapshot kept has to say what it needs before anything goes. */
    for (i = 0; ok && i < n; i++)
    {
        char **list;
        size_t nlist;

        if (!kept[i])
        {
            out->dropped = rs_xreallocarray(out->dropped, out->ndropped + 1,
                                            sizeof(*out->dropped));
            out->dropped[out->ndropped++] = rs_xstrdup(names[i]);
            continue;
        }
        if (!read_pack_list(r->st, names[i], &list, &nlist))
        {
            rs_buf_addf(err, "%s" RS_REPO_SEP "%s has no list of the packs it needs (restate "
                        "2.0 writes one; a prune with the secret key adds one to an older "
                        "snapshot), so what it needs is not known; nothing was removed",
                        r->dir, names[i]);
            ok = false;
            continue;
        }
        need = rs_xreallocarray(need, nneed + nlist + 1, sizeof(*need));
        memcpy(need + nneed, list, nlist * sizeof(*list));
        nneed += nlist;
        free(list);
    }
    if (nneed > 1)
    {
        qsort(need, nneed, sizeof(*need), by_name);
    }
    if (ok && !dry_run)
    {
        /* A snapshot left that was to go may need any pack it lists. */
        drop_snapshots(r, out);
        for (i = 0; !out->stopped && i < r->npacks; i++)
        {
            if (stopping(r))
            {
                out->stopped = true;
            } else if (!listed_in(need, nneed, r->packs[i]))
            {
                out->bytes_freed += remove_pack(r, r->packs[i]);
                out->packs_removed++;
            }
        }
        clear_leftovers(r);
        drop_old_chunk_keys(r);
        list_packs(r);
        unload(r);
        tidy_cache(r);
        rs_store_sync_dir(r->st, "packs");
    }
    if (!ok)
    {
        rs_repo_free_names(out->dropped, out->ndropped);
        out->dropped = NULL;
        out->ndropped = 0;
    }
    rs_repo_free_names(need, nneed);
    free(kept);
    rs_repo_free_names(names, n);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Usage                                                                     */
/* ------------------------------------------------------------------------- */

/* The entry for key `id` in `out`, made if it is not there. */
static struct rs_repo_key_use *key_use(struct rs_repo_keys *out, const char *id)
{
    struct rs_repo_key_use *k;
    size_t                  i;

    for (i = 0; i < out->nkeys; i++)
    {
        if (strcmp(out->keys[i].id, id) == 0)
        {
            return &out->keys[i];
        }
    }
    out->keys = rs_xreallocarray(out->keys, out->nkeys + 1, sizeof(*out->keys));
    k = &out->keys[out->nkeys++];
    memset(k, 0, sizeof(*k));
    memcpy(k->id, id, sizeof(k->id));
    return k;
}

/* The files of one pack or one snapshot, read for the keys they are encrypted
 * to: per key in `out`, whether any of them is, entered there if it was not. */
static bool *sealed_files(const struct rs_store *st, struct rs_repo_keys *out, char *const *paths,
                          size_t npaths)
{
    char   ids[KEYS_MAX][17];
    size_t at[5 * KEYS_MAX];
    size_t nat = 0;
    bool  *hit;
    size_t i;
    size_t k;

    for (i = 0; i < npaths; i++)
    {
        bool   sealed;
        size_t n = sealed_to(st, paths[i], ids, &sealed);

        out->unreadable += sealed && n == 0 ? 1 : 0;
        out->files += n > 0 ? 1 : 0;
        for (k = 0; k < n && nat < sizeof(at) / sizeof(at[0]); k++)
        {
            at[nat++] = (size_t)(key_use(out, ids[k]) - out->keys);
        }
    }
    hit = rs_xcalloc(out->nkeys + 1, sizeof(*hit));
    for (i = 0; i < nat; i++)
    {
        hit[at[i]] = true;
    }
    return hit;
}

void rs_repo_keys(struct rs_repo *r, struct rs_repo_keys *out)
{
    static const char *const pack_ext[] = { "tar.gz", "idx", "sum", "seek" };
    static const char *const snap_files[] = { "index.json.gz", "index.sig", "kit", "info",
                                              "packs" };
    char                     *paths[5];
    bool                     *hit;
    char                    **names;
    size_t                    n;
    size_t                    i;
    size_t                    k;

    memset(out, 0, sizeof(*out));
    list_packs(r);
    names = rs_repo_snapshots(r, &n);
    for (i = 0; i < r->npacks; i++)
    {
        for (k = 0; k < 4; k++)
        {
            paths[k] = rs_xasprintf("packs/%s.%s", r->packs[i], pack_ext[k]);
        }
        hit = sealed_files(r->st, out, paths, 4);
        for (k = 0; k < out->nkeys; k++)
        {
            if (hit[k])
            {
                out->keys[k].packs++;
                out->keys[k].bytes += pack_disk(r, r->packs[i]);
            }
        }
        free(hit);
        for (k = 0; k < 4; k++)
        {
            free(paths[k]);
        }
    }
    for (i = 0; i < n; i++)
    {
        for (k = 0; k < 5; k++)
        {
            paths[k] = snapshot_file(names[i], snap_files[k]);
        }
        hit = sealed_files(r->st, out, paths, 5);
        for (k = 0; k < out->nkeys; k++)
        {
            struct rs_repo_key_use *u = &out->keys[k];

            if (hit[k])
            {
                u->snapshots = rs_xreallocarray(u->snapshots, u->nsnapshots + 1,
                                                sizeof(*u->snapshots));
                u->snapshots[u->nsnapshots++] = rs_xstrdup(names[i]);
            }
        }
        free(hit);
        for (k = 0; k < 5; k++)
        {
            free(paths[k]);
        }
    }
    /* The newest copy of the chunking key: the older ones a prune removes. */
    {
        size_t ncopies;
        char **copies = chunk_key_copies(r->st, &ncopies);

        paths[0] = rs_xstrdup(ncopies > 0 ? copies[ncopies - 1] : RS_REPO_CHUNK_KEY);
        rs_repo_free_names(copies, ncopies);
    }
    hit = sealed_files(r->st, out, paths, 1);
    for (k = 0; k < out->nkeys; k++)
    {
        out->keys[k].chunk_key = hit[k];
    }
    free(hit);
    free(paths[0]);
    rs_repo_free_names(names, n);
}

void rs_repo_keys_free(struct rs_repo_keys *k)
{
    size_t i;

    for (i = 0; i < k->nkeys; i++)
    {
        rs_repo_free_names(k->keys[i].snapshots, k->keys[i].nsnapshots);
    }
    free(k->keys);
    memset(k, 0, sizeof(*k));
}

void rs_repo_du(struct rs_repo *r, struct rs_repo_usage *out)
{
    static const char *const files[] = { "index.json.gz", "index.sig", "kit", "info", "packs" };
    uint64_t                *size;
    unsigned                *users;     /* per pack: how many snapshots list it */
    bool                    *seen;      /* per pack: listed by an older snapshot */
    char                  ***lists;
    size_t                  *nlists;
    char                   **names;
    size_t                   n;
    size_t                   i;
    size_t                   k;

    memset(out, 0, sizeof(*out));
    list_packs(r);
    names = rs_repo_snapshots(r, &n);
    size = rs_xcalloc(r->npacks + 1, sizeof(*size));
    users = rs_xcalloc(r->npacks + 1, sizeof(*users));
    seen = rs_xcalloc(r->npacks + 1, sizeof(*seen));
    lists = rs_xcalloc(n + 1, sizeof(*lists));
    nlists = rs_xcalloc(n + 1, sizeof(*nlists));
    out->packs = r->npacks;
    for (i = 0; i < r->npacks; i++)
    {
        size[i] = pack_disk(r, r->packs[i]);
        out->pack_bytes += size[i];
    }
    out->bytes = out->pack_bytes;
    out->snapshots = rs_xcalloc(n + 1, sizeof(*out->snapshots));
    out->nsnapshots = n;
    for (i = 0; i < n; i++)
    {
        struct rs_repo_snapshot_usage *u = &out->snapshots[i];

        u->name = rs_xstrdup(names[i]);
        for (k = 0; k < sizeof(files) / sizeof(files[0]); k++)
        {
            char *path = snapshot_file(names[i], files[k]);

            out->bytes += disk_size(r->st, path);
            free(path);
        }
        u->listed = read_pack_list(r->st, names[i], &lists[i], &nlists[i]);
        for (k = 0; u->listed && k < nlists[i]; k++)
        {
            char *const *at = bsearch(&lists[i][k], r->packs, r->npacks, sizeof(*r->packs),
                                      by_name);

            if (at)
            {
                users[at - r->packs]++;
            }
        }
    }
    /* Oldest first: a pack is new in the first snapshot to list it. */
    for (i = 0; i < n; i++)
    {
        struct rs_repo_snapshot_usage *u = &out->snapshots[i];

        for (k = 0; u->listed && k < nlists[i]; k++)
        {
            char *const *at = bsearch(&lists[i][k], r->packs, r->npacks, sizeof(*r->packs),
                                      by_name);
            size_t       p;

            if (!at)
            {
                continue;
            }
            p = (size_t)(at - r->packs);
            u->bytes += size[p];
            u->unique_bytes += users[p] == 1 ? size[p] : 0;
            u->new_bytes += seen[p] ? 0 : size[p];
            seen[p] = true;
        }
        rs_repo_free_names(lists[i], nlists[i]);
    }
    free(lists);
    free(nlists);
    free(size);
    free(users);
    free(seen);
    rs_repo_free_names(names, n);
}

void rs_repo_usage_free(struct rs_repo_usage *u)
{
    size_t i;

    for (i = 0; i < u->nsnapshots; i++)
    {
        free(u->snapshots[i].name);
    }
    free(u->snapshots);
    memset(u, 0, sizeof(*u));
}

/* ------------------------------------------------------------------------- */
/* Copying a snapshot to another repository                                  */
/* ------------------------------------------------------------------------- */

/* Where copy_file writes `to` before renaming it into place: beside it, a
 * name prune and repack know to clear if a run dies before the rename. */
static char *beside(const char *to)
{
    const char *slash = strrchr(to, '/');

    return slash ? rs_xasprintf("%.*s/.%s.%ld.tmp", (int)(slash - to), to, slash + 1,
                                (long)getpid())
                 : rs_xasprintf(".%s.%ld.tmp", to, (long)getpid());
}

/* The errno of the last stage_copy that failed once it had its source
 * open: writing where it copies to, as a disk that is full fails. */
static int copy_errno;

/* The file `from` in `src`, byte for byte, as the new file `tmp` in `dst`,
 * synced. How many bytes into *bytes. */
static bool stage_copy(const struct rs_store *src, const char *from, const struct rs_store *dst,
                       const char *tmp, uint64_t *bytes, struct rs_buf *err)
{
    int           in = rs_store_open(src, from);
    int           out = -1;
    unsigned char chunk[65536];
    ssize_t       n = 0;
    bool          ok = in >= 0;

    if (!ok)
    {
        char *path = rs_store_path(src, from);

        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    (void)rs_store_remove(dst, tmp, false);
    out = rs_store_create(dst, tmp);
    ok = out >= 0;
    while (ok && (n = read(in, chunk, sizeof(chunk))) != 0)
    {
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        ok = n > 0 && write_all(out, chunk, (size_t)n);
        if (ok)
        {
            *bytes += (uint64_t)n;
            rs_progress_bytes((uint64_t)n);
        }
    }
    ok = ok && fsync(out) == 0;
    if (out >= 0 && close(out) != 0)
    {
        ok = false;
    }
    (void)close(in);
    if (!ok)
    {
        int   saved = errno;
        char *a = rs_store_path(src, from);
        char *b = rs_store_path(dst, tmp);

        rs_buf_addf(err, "copying %s to %s: %s", a, b, strerror(saved));
        (void)rs_store_remove(dst, tmp, false);
        free(a);
        free(b);
        copy_errno = saved;
    }
    return ok;
}

/* The file `from` in `src`, byte for byte, as the new file `to` in `dst`:
 * written beside it and renamed into place. How many bytes into *bytes. */
static bool copy_file(const struct rs_store *src, const char *from, const struct rs_store *dst,
                      const char *to, uint64_t *bytes, struct rs_buf *err)
{
    char *tmp = beside(to);
    bool  ok = stage_copy(src, from, dst, tmp, bytes, err);

    if (ok && rs_store_rename(dst, tmp, to, false) != 0)
    {
        int         saved = errno;
        const char *said = rs_store_said(dst);
        char       *a = rs_store_path(src, from);
        char       *b = rs_store_path(dst, to);

        rs_buf_addf(err, "copying %s to %s: %s", a, b, said ? said : strerror(saved));
        (void)rs_store_remove(dst, tmp, false);
        free(a);
        free(b);
        copy_errno = saved;
        ok = false;
    }
    free(tmp);
    return ok;
}

/* The packs snapshot `name` needs: its pack list, or what its index needs. */
static bool packs_needed(struct rs_repo *r, const char *name, char ***list, size_t *n,
                         struct rs_buf *err)
{
    struct rs_index ix;
    bool           *used;
    bool            ok;

    if (read_pack_list(r->st, name, list, n))
    {
        return true;
    }
    load_objects(r);
    if (r->unreadable > 0)
    {
        rs_buf_addf(err, "%s" RS_REPO_SEP "%s has no pack list, and %zu packs' indexes could not "
                    "be read here, so which packs it needs is not known", r->dir, name,
                    r->unreadable);
        return false;
    }
    rs_index_init(&ix);
    ok = rs_repo_load_index_cached(r, name, &ix, err);
    used = rs_xcalloc(r->npacks + 1, sizeof(*used));
    if (ok)
    {
        size_t i;

        mark_index(r, &ix, used);
        for (i = 0; i < r->npacks; i++)
        {
            if (used[i])
            {
                *list = rs_xreallocarray(*list, *n + 1, sizeof(**list));
                (*list)[(*n)++] = rs_xstrdup(r->packs[i]);
            }
        }
    }
    free(used);
    rs_index_free(&ix);
    return ok;
}

/* Copies pack `pack` from `r` to `dest`, unless dest has it: the content, its
 * .sum, its .seek if it has one, then its .idx, which makes it count there. */
static bool copy_pack(const struct rs_repo *r, const struct rs_repo *dest, const char *pack,
                      struct rs_repo_copied *out, struct rs_buf *err)
{
    static const char *const ext[] = { "tar.gz", "sum", "seek", "idx" };
    size_t                   i;
    bool                     ok = true;

    if (listed_in(dest->packs, dest->npacks, pack))
    {
        char     want[RS_SHA256_HEX_SIZE];
        char     have[RS_SHA256_HEX_SIZE];
        uint64_t wsize = 0;
        uint64_t hsize = 0;

        if (read_sum(r->st, pack, want, &wsize) && read_sum(dest->st, pack, have, &hsize) &&
            (strcmp(want, have) != 0 || wsize != hsize))
        {
            rs_buf_addf(err, "%s/packs/%s: there already, and not the same as %s's", dest->dir,
                        pack, r->dir);
            return false;
        }
        out->packs_there++;
        return true;
    }
    for (i = 0; ok && i < sizeof(ext) / sizeof(ext[0]); i++)
    {
        char                *file = rs_xasprintf("packs/%s.%s", pack, ext[i]);
        struct rs_store_stat st;

        if (i == 1 && rs_store_stat(r->st, file, &st) != 0)
        {
            /* One restate 1 wrote: given a .sum on the way. */
            ok = write_sum(dest->st, pack, err);
        } else if (i != 2 || rs_store_stat(r->st, file, &st) == 0)
        {
            /* A .seek only where there is one: a pack written before packs
             * had segments has none, and is read from its start. */
            ok = copy_file(r->st, file, dest->st, file, &out->bytes, err);
        }
        free(file);
    }
    if (ok)
    {
        out->packs_copied++;
    }
    return ok;
}

/* Copies the snapshot directory `name` into `dest`, whole, as a capture
 * puts one there: beside its name, then renamed into place. */
static bool copy_snapshot_dir(const struct rs_repo *r, const struct rs_repo *dest,
                              const char *name, char *const *list, size_t nlist,
                              struct rs_repo_copied *out, struct rs_buf *err)
{
    static const char *const files[] = { "index.json.gz", "index.sig", "kit", "info", "packs" };
    char                    *final = rs_xasprintf("snapshots/%s", name);
    char                    *tmp = temp_dir(dest->st, name, err);
    size_t                   i;
    bool                     made = tmp != NULL;
    bool                     ok = made;

    for (i = 0; ok && i < sizeof(files) / sizeof(files[0]); i++)
    {
        char                *from = snapshot_file(name, files[i]);
        char                *to = rs_xasprintf("%s/%s", tmp, files[i]);
        struct rs_store_stat st;

        if (rs_store_stat(r->st, from, &st) == 0)
        {
            ok = copy_file(r->st, from, dest->st, to, &out->bytes, err);
        } else if (strcmp(files[i], "packs") == 0)
        {
            /* One restate 1 wrote: given its list on the way. */
            struct rs_buf text;
            size_t        k;

            rs_buf_init(&text);
            rs_buf_addstr(&text, PACKS_FORMAT);
            for (k = 0; k < nlist; k++)
            {
                rs_buf_addf(&text, "%s\n", list[k]);
            }
            ok = rs_store_write_new(dest->st, to, text.data, text.len, err);
            rs_buf_free(&text);
        }
        free(from);
        free(to);
    }
    if (ok)
    {
        rs_store_sync_dir(dest->st, tmp);
        if (rs_store_rename(dest->st, tmp, final, false) != 0)
        {
            renamed_failed(dest->st, final, err);
            ok = false;
        }
    }
    if (!ok && made)
    {
        (void)remove_snapshot_dir(dest->st, tmp);
    }
    free(tmp);
    free(final);
    return ok;
}

/* Whether the snapshot `name` in `dest` is the one in `r`: the same index. */
static bool same_snapshot(const struct rs_repo *r, const struct rs_repo *dest, const char *name)
{
    char         *a = snapshot_file(name, "index.json.gz");
    char          ha[RS_SHA256_HEX_SIZE];
    char          hb[RS_SHA256_HEX_SIZE];
    uint64_t      sa = 0;
    uint64_t      sb = 0;
    bool          same;
    struct rs_buf ignore;

    rs_buf_init(&ignore);
    same = file_digest(r->st, a, ha, &sa, &ignore) && file_digest(dest->st, a, hb, &sb, &ignore) &&
           strcmp(ha, hb) == 0 && sa == sb;
    rs_buf_free(&ignore);
    free(a);
    return same;
}

void rs_repo_copied_free(struct rs_repo_copied *c)
{
    free(c->name);
    memset(c, 0, sizeof(*c));
}

bool rs_repo_copy(struct rs_repo *r, const char *name, const char *dest_dir,
                  struct rs_repo_copied *out, bool *busy, struct rs_buf *err)
{
    struct rs_repo      *dest = NULL;
    char               **list = NULL;
    size_t               nlist = 0;
    char                *snap;
    struct rs_store     *where;
    struct rs_store_stat st;
    size_t               i;
    bool                 ok;

    memset(out, 0, sizeof(*out));
    *busy = false;
    snap = rs_repo_resolve(r, name, err);
    if (!snap)
    {
        return false;
    }
    out->name = snap;
    ok = packs_needed(r, snap, &list, &nlist, err);
    where = rs_store_at(dest_dir);
    if (ok && rs_store_stat(where, "", &st) != 0 && errno == ENOENT)
    {
        ok = rs_repo_init(dest_dir, r->encrypted, err);
        out->made = ok;
    }
    if (ok)
    {
        dest = rs_repo_open(dest_dir, RS_REPO_WRITE, busy, err);
        ok = dest != NULL;
    }
    rs_store_free(where);
    if (ok && dest->encrypted != r->encrypted)
    {
        rs_buf_addf(err, "%s: %s, and %s is %s; a copy is the same kind as what it is a copy of",
                    dest_dir, dest->encrypted ? "it is encrypted" : "it is not encrypted",
                    r->dir, r->encrypted ? "encrypted" : "not");
        ok = false;
    }
    /* Its chunking key goes with it, as it is -- every copy, each encrypted
     * to the keys it is -- where the copy has none of its own. */
    if (ok && r->encrypted)
    {
        size_t ncopies;
        size_t nthere;
        char **copies = chunk_key_copies(r->st, &ncopies);
        char **there = chunk_key_copies(dest->st, &nthere);

        for (i = 0; ok && nthere == 0 && i < ncopies; i++)
        {
            ok = copy_file(r->st, copies[i], dest->st, copies[i], &out->bytes, err);
        }
        rs_repo_free_names(copies, ncopies);
        rs_repo_free_names(there, nthere);
    }
    if (ok)
    {
        char *there = snapshot_file(snap, "index.json.gz");

        if (rs_store_stat(dest->st, there, &st) == 0)
        {
            out->already = same_snapshot(r, dest, snap);
            if (!out->already)
            {
                rs_buf_addf(err, "%s" RS_REPO_SEP "%s: there already, and not the same snapshot",
                            dest_dir, snap);
                ok = false;
            }
        }
        free(there);
    }
    for (i = 0; ok && !out->already && i < nlist; i++)
    {
        ok = copy_pack(r, dest, list[i], out, err);
    }
    if (ok && !out->already)
    {
        rs_store_sync_dir(dest->st, "packs");
        ok = copy_snapshot_dir(r, dest, snap, list, nlist, out, err);
    }
    if (ok && !out->already)
    {
        rs_store_sync_dir(dest->st, "snapshots");
    }
    rs_repo_free_names(list, nlist);
    rs_repo_close(dest);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Checking                                                                  */
/* ------------------------------------------------------------------------- */

/* Warnings about one snapshot's files, before the rest are only counted. */
#define CHECK_SAID 10

/* A chunk checked against its digest: its size, where `sizes` keeps it. */
struct checking {
    struct rs_repo                  *r;
    const struct rs_repo_check_opts *opts;
    struct rs_repo_checked          *out;
    struct objmap                    good;      /* member: into sizes */
    uint64_t                        *sizes;
    size_t                           nsizes;
    struct list                     *lists;     /* every list every .idx has */
    size_t                           nlists;
    unsigned char         (*chunks)[32];
    size_t                  nchunks;
};

static void bad_pack(struct checking *k, const char *name, const char *why)
{
    rs_warn("%s/packs/%s: %s", k->r->dir, name, why);
    k->out->packs_bad++;
}

static void keep_good(struct checking *k, const unsigned char d[32], uint64_t size)
{
    if (!map_find(&k->good, d))
    {
        k->sizes = rs_xreallocarray(k->sizes, k->nsizes + 1, sizeof(*k->sizes));
        k->sizes[k->nsizes] = size;
        (void)map_add(&k->good, d, 0, (uint32_t)k->nsizes++);
    }
}

/* The lists of one .idx, kept to check the snapshots against. */
static void keep_lists(struct checking *k, const struct rs_repo_idx *x)
{
    size_t i;

    for (i = 0; i < x->nlists; i++)
    {
        const struct rs_repo_list *l = &x->lists[i];
        struct list               *to;
        size_t                     c;

        k->lists = rs_xreallocarray(k->lists, k->nlists + 1, sizeof(*k->lists));
        to = &k->lists[k->nlists];
        if (!unhex(l->hash, to->d))
        {
            continue;
        }
        to->size = l->size;
        to->first = k->nchunks;
        to->n = l->n;
        k->chunks = rs_xreallocarray(k->chunks, k->nchunks + l->n, sizeof(*k->chunks));
        for (c = 0; c < l->n; c++)
        {
            if (!unhex(x->chunks[l->first + c], k->chunks[k->nchunks + c]))
            {
                memset(k->chunks[k->nchunks + c], 0, 32);
            }
        }
        k->nchunks += l->n;
        k->nlists++;
    }
}

/* The first of what is wrong with a pack is what is said of it. */
static void wrong(struct rs_buf *why, bool *damaged, const char *what)
{
    if (!*damaged)
    {
        rs_buf_reset(why);
        rs_buf_addstr(why, what);
    }
    *damaged = true;
}

/*
 * The pack `name` in `st`, read through: each member is one its .idx lists, of the
 * size it gives, whose content -- for a live one -- hashes to the digest it
 * gives, and no member it lists is missing. False, with the first of what is
 * wrong in `why`, if not. With `k`, what does hash right is kept as good,
 * even in a pack that is damaged after it; without, nothing is counted.
 */
static bool pack_matches(const struct rs_store *st, const char *name, const struct rs_repo_idx *x,
                         struct checking *k, struct rs_buf *why)
{
    int                  fd = rs_store_open(st, name);
    struct zin           z;
    struct rs_tar_reader tr;
    struct rs_tar_entry  te;
    struct rs_buf        terr;
    unsigned char        chunk[65536];
    size_t               at = 0;
    bool                 damaged = false;
    bool                 broken = false;
    int                  more = 1;

    if (fd < 0 || !zin_open(&z, fd, true, why))
    {
        if (fd < 0)
        {
            rs_buf_reset(why);
            rs_buf_addstr(why, strerror(errno));
        } else
        {
            (void)close(fd);
        }
        return false;
    }
    (void)close(fd);
    rs_buf_init(&terr);
    rs_tar_reader_init(&tr, read_fd, &z.fd);
    rs_tar_entry_init(&te);
    /* A member that is wrong is said once, and the rest read on: what is
     * whole in a damaged pack still counts. Only a pack that cannot be read
     * further stops it. */
    while (!broken && (more = rs_tar_next(&tr, &te, &terr)) > 0)
    {
        const char                  *p = te.name.data;
        uint64_t                     num = 0;
        const struct rs_repo_member *m;
        struct rs_sha256             sha;
        char                         hex[RS_SHA256_HEX_SIZE];
        uint64_t                     got = 0;
        ssize_t                      n;

        if (te.typeflag != '0' || !number(&p, te.name.data + te.name.len, &num) || *p != '\0')
        {
            wrong(why, &damaged, "a member that is not a chunk");
            continue;
        }
        while (at < x->nmembers && x->members[at].member < num)
        {
            wrong(why, &damaged, "it holds less than its index says");
            at++;
        }
        m = at < x->nmembers && x->members[at].member == num ? &x->members[at] : NULL;
        if (!m)
        {
            wrong(why, &damaged, "a member that is not in its index");
            continue;
        }
        at++;
        rs_sha256_init(&sha);
        while ((n = rs_tar_read(&tr, chunk, sizeof(chunk), &terr)) > 0)
        {
            rs_sha256_update(&sha, chunk, (size_t)n);
            rs_progress_bytes((uint64_t)n);
            got += (uint64_t)n;
        }
        rs_sha256_final(&sha, hex);
        if (k)
        {
            k->out->bytes += got;
        }
        if (n < 0)
        {
            wrong(why, &damaged, terr.len ? terr.data : "it could not be read to its end");
            broken = true;
        } else if (got != m->size || (m->live && strcmp(hex, m->hash) != 0))
        {
            wrong(why, &damaged, "a chunk that is not what its index says");
        } else if (m->live && k)
        {
            unsigned char d[32];

            if (unhex(hex, d))
            {
                keep_good(k, d, got);
            }
            k->out->chunks++;
        }
    }
    if (more < 0)
    {
        wrong(why, &damaged, terr.len ? terr.data : "it could not be read to its end");
    } else if (!broken && at < x->nmembers)
    {
        wrong(why, &damaged, "it holds less than its index says");
    }
    rs_tar_entry_free(&te);
    rs_buf_free(&terr);
    {
        struct rs_buf closing;

        /* Past its end-of-archive blocks a pack runs on to its record size.
         * Read to gzip's end, so it is not killed writing what nobody reads:
         * FreeBSD holds a writer in a large write until all of it is read. */
        while (!damaged && read(z.fd, chunk, sizeof(chunk)) > 0)
        {
        }
        rs_buf_init(&closing);
        if (!zin_close(&z, damaged, &closing) && !damaged)
        {
            rs_buf_reset(why);
            rs_buf_addstr(why, closing.len ? closing.data : "it could not be read to its end");
            damaged = true;
        }
        rs_buf_free(&closing);
    }
    return !damaged;
}

/* One pack of the repository, read through as pack_matches reads one. */
static void check_pack(struct checking *k, const char *name, const struct rs_repo_idx *x)
{
    char         *path = rs_xasprintf("packs/%s.tar.gz", name);
    struct rs_buf why;

    rs_buf_init(&why);
    if (!pack_matches(k->r->st, path, x, k, &why))
    {
        char *file = rs_xasprintf("%s.tar.gz", name);

        bad_pack(k, file, why.len ? why.data : "it could not be read");
        free(file);
    }
    rs_buf_free(&why);
    free(path);
}

/* An .idx whose pack is gone, or a pack with no .idx: is_pack passes them
 * over, so the first is damage nothing else would see. */
static bool unpaired(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                     char **out)
{
    size_t               len = strlen(name);
    struct rs_store_stat s;
    char                *other;
    bool                 found;

    (void)ctx;
    if (len > 4 && strcmp(name + len - 4, ".idx") == 0)
    {
        other = rs_xasprintf("%s/%.*s.tar.gz", dir, (int)(len - 4), name);
    } else if (len > 7 && strcmp(name + len - 7, ".tar.gz") == 0)
    {
        other = rs_xasprintf("%s/%.*s.idx", dir, (int)(len - 7), name);
    } else
    {
        return false;
    }
    found = rs_store_stat(st, other, &s) == 0;
    free(other);
    if (found || name[0] == '.')
    {
        return false;
    }
    *out = rs_xstrdup(name);
    return true;
}

/* A snapshot directory, whether or not its index is there. */
static bool any_snapshot(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                         char **out)
{
    char                *path = rs_xasprintf("%s/%s", dir, name);
    struct rs_store_stat s;
    bool                 ok = rs_repo_name_valid(name) && rs_store_stat(st, path, &s) == 0 &&
                              s.kind == RS_STORE_DIR;

    (void)ctx;
    free(path);
    if (ok)
    {
        *out = rs_xstrdup(name);
    }
    return ok;
}

/* Whether the content with the digest `hash`, of `size` bytes, is whole
 * among the chunks found good: a chunk itself, or a list of them. */
static bool is_whole(const struct checking *k, const char *hash, uint64_t size,
                     const struct objmap *lists)
{
    unsigned char     d[32];
    const struct obj *o;
    uint64_t          sum = 0;
    size_t            c;

    /* Nothing found good, or no lists, is nothing whole: said outright, as
     * an analyzer cannot tell that an empty map finds nothing. */
    if (!unhex(hash, d) || !k->sizes)
    {
        return false;
    }
    o = map_find(&k->good, d);
    if (o)
    {
        return k->sizes[o->member] == size;
    }
    o = k->lists ? map_find(lists, d) : NULL;
    if (!o)
    {
        return false;
    }
    for (c = 0; c < k->lists[o->member].n; c++)
    {
        const struct obj *ch = map_find(&k->good, k->chunks[k->lists[o->member].first + c]);

        if (!ch)
        {
            return false;
        }
        sum += k->sizes[ch->member];
    }
    return sum == size && k->lists[o->member].size == size;
}

static void check_snapshot(struct checking *k, const char *name, const struct objmap *lists)
{
    struct rs_index ix;
    struct rs_buf   err;
    char          **kit = NULL;
    size_t          nkit = 0;
    size_t          i;
    uint64_t        missing = 0;

    rs_index_init(&ix);
    rs_buf_init(&err);
    k->out->snapshots++;
    if (!rs_repo_load_index(k->r, name, &ix, &err) || !rs_repo_kit(k->r, name, &kit, &nkit, &err))
    {
        rs_warn("%s::%s: %s", k->r->dir, name, err.data);
        k->out->snapshots_bad++;
        rs_index_free(&ix);
        rs_buf_free(&err);
        return;
    }
    rs_repo_free_names(kit, nkit);
    for (i = 0; i < ix.count; i++)
    {
        const struct rs_entry *e = &ix.entries[i];

        if (!e->stored || e->type != 'f' || e->hash_state != RS_HASH_PRESENT)
        {
            continue;
        }
        k->out->files++;
        if (is_whole(k, e->hash, e->size, lists))
        {
            continue;
        }
        if (missing++ < CHECK_SAID)
        {
            struct rs_buf b;

            rs_buf_init(&b);
            rs_escape(&b, e->path);
            rs_warn("%s::%s: %s: its content is not all in the repository", k->r->dir, name,
                    b.data ? b.data : "");
            rs_buf_free(&b);
        }
    }
    if (missing > CHECK_SAID)
    {
        rs_warn("%s::%s: and %" PRIu64 " files more", k->r->dir, name, missing - CHECK_SAID);
    }
    if (missing > 0)
    {
        k->out->snapshots_bad++;
        k->out->missing += missing;
    }
    rs_index_free(&ix);
    rs_buf_free(&err);
}

/* ------------------------------------------------------------------------- */
/* What was there: a check's record                                          */
/* ------------------------------------------------------------------------- */

#define RECORD_FORMAT "restate-record 1\n"
/* A record lists every file in a repository: a few per pack and snapshot. */
#define RECORD_MAX    ((size_t)256 * 1024 * 1024)

void rs_repo_record_free(struct rs_repo_record *rec)
{
    size_t i;

    for (i = 0; i < rec->n; i++)
    {
        free(rec->entries[i].path);
    }
    free(rec->entries);
    memset(rec, 0, sizeof(*rec));
}

/* A path in a record: the repository's own files' names, nothing more. */
static bool record_path_ok(const char *p, size_t len)
{
    size_t i;

    if (len == 0 || p[0] == '/' || p[0] == '.' || len > 512)
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        char c = p[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              c == '.' || c == '-' || c == '_' || c == '/'))
        {
            return false;
        }
        if (c == '/' && (i + 1 == len || p[i + 1] == '.' || p[i + 1] == '/'))
        {
            return false;
        }
    }
    return true;
}

static void record_add(struct rs_repo_record *rec, const char *path, const char *hash,
                       uint64_t size)
{
    struct rs_repo_record_entry *e;

    rec->entries = rs_xreallocarray(rec->entries, rec->n + 1, sizeof(*rec->entries));
    e = &rec->entries[rec->n++];
    e->path = rs_xstrdup(path);
    memcpy(e->hash, hash, RS_SHA256_HEX_SIZE);
    e->size = size;
}

bool rs_repo_parse_record(const char *text, size_t len, struct rs_repo_record *out)
{
    const char *p = text;
    const char *end = text + len;

    memset(out, 0, sizeof(*out));
    if (len < strlen(RECORD_FORMAT) || memcmp(text, RECORD_FORMAT, strlen(RECORD_FORMAT)) != 0)
    {
        return false;
    }
    p += strlen(RECORD_FORMAT);
    while (p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *sp = nl ? memchr(p, ' ', (size_t)(nl - p)) : NULL;
        const char *q;
        char        hash[RS_SHA256_HEX_SIZE];
        uint64_t    size = 0;
        char       *path;
        size_t      i;
        bool        ok;

        if (!sp || !record_path_ok(p, (size_t)(sp - p)) || nl - sp < 1 + 64 + 2 || sp[65] != ' ')
        {
            break;
        }
        q = sp + 1;
        ok = true;
        for (i = 0; ok && i < 64; i++)
        {
            unsigned v;

            ok = hex_digit(q[i], &v);
            hash[i] = q[i];
        }
        hash[64] = '\0';
        q += 65;
        ok = ok && number(&q, nl, &size) && q == nl;
        path = ok ? rs_xstrndup(p, (size_t)(sp - p)) : NULL;
        /* Each path once, and in order. */
        if (!ok || (out->n > 0 && strcmp(out->entries[out->n - 1].path, path) >= 0))
        {
            free(path);
            break;
        }
        record_add(out, path, hash, size);
        free(path);
        p = nl + 1;
    }
    if (p != end)
    {
        rs_repo_record_free(out);
        return false;
    }
    return true;
}

static int by_record_path(const void *a, const void *b)
{
    return strcmp(((const struct rs_repo_record_entry *)a)->path,
                  ((const struct rs_repo_record_entry *)b)->path);
}

/* The record entry for `path`, or NULL: the entries are in order. */
static const struct rs_repo_record_entry *record_find(const struct rs_repo_record *rec,
                                                      const char *path)
{
    size_t lo = 0;
    size_t hi = rec->n;

    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int    c = strcmp(path, rec->entries[mid].path);

        if (c == 0)
        {
            return &rec->entries[mid];
        }
        if (c < 0)
        {
            hi = mid;
        } else
        {
            lo = mid + 1;
        }
    }
    return NULL;
}

/* The repository's file `rel`, hashed into the record, if it is there. */
static void record_file(const struct rs_repo *r, struct rs_repo_record *rec, const char *rel)
{
    char          hex[RS_SHA256_HEX_SIZE];
    uint64_t      size = 0;
    struct rs_buf ignore;

    rs_buf_init(&ignore);
    if (rs_store_is_file(r->st, rel) && file_digest(r->st, rel, hex, &size, &ignore))
    {
        record_add(rec, rel, hex, size);
    }
    rs_buf_free(&ignore);
}

/* Everything in the record but the packs' content: their .idx, .sum and
 * .seek, and each snapshot's files. */
static void record_rest(const struct rs_repo *r, struct rs_repo_record *rec)
{
    static const char *const files[] = { "index.json.gz", "index.sig", "kit", "info", "packs" };
    char                   **snaps;
    size_t                   nsnaps;
    size_t                   i;
    size_t                   f;

    for (i = 0; i < r->npacks; i++)
    {
        char *idx = rs_xasprintf("packs/%s.idx", r->packs[i]);
        char *sum = rs_xasprintf("packs/%s.sum", r->packs[i]);
        char *seek = rs_xasprintf("packs/%s.seek", r->packs[i]);

        record_file(r, rec, idx);
        record_file(r, rec, sum);
        record_file(r, rec, seek);
        free(idx);
        free(sum);
        free(seek);
    }
    snaps = rs_store_list(r->st, "snapshots", any_snapshot, NULL, &nsnaps);
    for (i = 0; i < nsnaps; i++)
    {
        for (f = 0; f < sizeof(files) / sizeof(files[0]); f++)
        {
            char *rel = rs_xasprintf("snapshots/%s/%s", snaps[i], files[f]);

            record_file(r, rec, rel);
            free(rel);
        }
    }
    rs_repo_free_names(snaps, nsnaps);
    if (rec->n > 1)
    {
        qsort(rec->entries, rec->n, sizeof(*rec->entries), by_record_path);
    }
}

static bool read_record(const char *path, struct rs_repo_record *rec, bool *there,
                        struct rs_buf *err)
{
    struct rs_store     *files = rs_store_local("");
    struct rs_store_stat st;
    struct rs_buf        text;
    bool                 ok;

    memset(rec, 0, sizeof(*rec));
    *there = rs_store_stat(files, path, &st) == 0;
    if (!*there)
    {
        rs_store_free(files);
        return true;
    }
    ok = rs_store_read(files, path, RECORD_MAX, &text, err);
    rs_store_free(files);
    if (ok && !rs_repo_parse_record(text.data, text.len, rec))
    {
        rs_buf_addf(err, "%s: not a record restate wrote", path);
        ok = false;
    }
    rs_buf_free(&text);
    return ok;
}

static bool write_record(const char *path, const struct rs_repo_record *rec, struct rs_buf *err)
{
    struct rs_buf text;
    size_t        i;
    bool          ok;

    rs_buf_init(&text);
    rs_buf_addstr(&text, RECORD_FORMAT);
    for (i = 0; i < rec->n; i++)
    {
        rs_buf_addf(&text, "%s %s %" PRIu64 "\n", rec->entries[i].path, rec->entries[i].hash,
                    rec->entries[i].size);
    }
    {
        struct rs_store *files = rs_store_local("");

        ok = rs_store_replace(files, path, text.data, text.len, err);
        rs_store_free(files);
    }
    rs_buf_free(&text);
    return ok;
}

bool rs_repo_record_update(struct rs_repo *r, const char *record, struct rs_buf *err)
{
    struct rs_repo_record old;
    struct rs_repo_record cur;
    bool                  there;
    size_t                i;
    bool                  ok;

    if (!read_record(record, &old, &there, err))
    {
        return false;
    }
    memset(&cur, 0, sizeof(cur));
    list_packs(r);
    /* A pack's content never changes under its name: what the record had
     * for it stands. One new since -- a capture's, or what prune wrote -- is
     * recorded as its .sum says it was written, rather than read whole for
     * it: a check reads it against both, and says if it is not that. */
    for (i = 0; r->packs && i < r->npacks; i++)
    {
        char                              *rel = rs_xasprintf("packs/%s.tar.gz", r->packs[i]);
        const struct rs_repo_record_entry *e = record_find(&old, rel);
        char                               hex[RS_SHA256_HEX_SIZE];
        uint64_t                           size = 0;

        if (e)
        {
            record_add(&cur, rel, e->hash, e->size);
        } else if (read_sum(r->st, r->packs[i], hex, &size))
        {
            record_add(&cur, rel, hex, size);
        } else
        {
            record_file(r, &cur, rel);
        }
        free(rel);
    }
    record_rest(r, &cur);
    ok = write_record(record, &cur, err);
    rs_repo_record_free(&old);
    rs_repo_record_free(&cur);
    return ok;
}

/* What the record says has gone or changed since it was written: each said,
 * and into out->changed. */
static void record_compare(struct checking *k, const struct rs_repo_record *old,
                           const struct rs_repo_record *cur)
{
    size_t i;

    for (i = 0; i < old->n; i++)
    {
        const struct rs_repo_record_entry *was = &old->entries[i];
        const struct rs_repo_record_entry *now = record_find(cur, was->path);
        char                              *what;

        if (now && strcmp(now->hash, was->hash) == 0 && now->size == was->size)
        {
            continue;
        }
        what = rs_xasprintf("%s %s", now ? "changed" : "removed", was->path);
        rs_warn("%s/%s: %s since the last check", k->r->dir, was->path,
                now ? "changed" : "removed");
        k->out->changed = rs_xreallocarray(k->out->changed, k->out->nchanged + 1,
                                           sizeof(*k->out->changed));
        k->out->changed[k->out->nchanged++] = what;
    }
}

/* A pack's content against its .sum; its digest into the record, where
 * there is one. */
static void check_sum(struct checking *k, const char *name, struct rs_repo_record *rec)
{
    char         *rel = rs_xasprintf("packs/%s.tar.gz", name);
    char          want[RS_SHA256_HEX_SIZE];
    char          got[RS_SHA256_HEX_SIZE];
    uint64_t      want_size = 0;
    uint64_t      got_size = 0;
    bool          summed = read_sum(k->r->st, name, want, &want_size);
    struct rs_buf why;

    rs_buf_init(&why);
    if (!summed)
    {
        char                *sum = rs_xasprintf("packs/%s.sum", name);
        struct rs_store_stat st;

        if (rs_store_stat(k->r->st, sum, &st) == 0)
        {
            char *file = rs_xasprintf("%s.sum", name);

            bad_pack(k, file, "not a .sum restate wrote");
            free(file);
        } else
        {
            k->out->unsummed++;
        }
        free(sum);
    }
    if (!file_digest(k->r->st, rel, got, &got_size, &why))
    {
        char *file = rs_xasprintf("%s.tar.gz", name);

        bad_pack(k, file, why.data);
        free(file);
    } else
    {
        if (summed && (strcmp(got, want) != 0 || got_size != want_size))
        {
            char *file = rs_xasprintf("%s.tar.gz", name);

            bad_pack(k, file, "it is not what its .sum says: changed or damaged since it was "
                              "written");
            free(file);
        }
        if (k->opts->metadata_only)
        {
            k->out->bytes += got_size;
        }
        if (rec)
        {
            record_add(rec, rel, got, got_size);
        }
    }
    rs_buf_free(&why);
    free(rel);
}

/* A snapshot read without its index: its files there, and every pack its
 * list names. */
static void check_snapshot_meta(struct checking *k, const char *name)
{
    char  *kit = snapshot_file(name, "kit");
    char **list = NULL;
    size_t nlist = 0;
    size_t i;
    size_t gone = 0;

    k->out->snapshots++;
    if (!rs_store_is_file(k->r->st, kit))
    {
        rs_warn("%s::%s: its kit is not there", k->r->dir, name);
        k->out->snapshots_bad++;
        free(kit);
        return;
    }
    free(kit);
    if (!read_pack_list(k->r->st, name, &list, &nlist))
    {
        k->out->unlisted++;
        return;
    }
    for (i = 0; i < nlist; i++)
    {
        if (!listed_in(k->r->packs, k->r->npacks, list[i]))
        {
            if (gone++ < CHECK_SAID)
            {
                rs_warn("%s::%s: it needs the pack %s, which is not there", k->r->dir, name,
                        list[i]);
            }
        }
    }
    if (gone > CHECK_SAID)
    {
        rs_warn("%s::%s: and %zu packs more", k->r->dir, name, gone - CHECK_SAID);
    }
    if (gone > 0)
    {
        k->out->snapshots_bad++;
    }
    rs_repo_free_names(list, nlist);
}

void rs_repo_checked_free(struct rs_repo_checked *c)
{
    rs_repo_free_names(c->changed, c->nchanged);
    c->changed = NULL;
    c->nchanged = 0;
}

bool rs_repo_check(struct rs_repo *r, const struct rs_repo_check_opts *opts,
                   struct rs_repo_checked *out, struct rs_buf *err)
{
    static const struct rs_repo_check_opts none;
    struct checking                        k;
    struct objmap                          lists;
    struct rs_repo_record                  old;
    struct rs_repo_record                  cur;
    struct rs_repo_record                 *rec = NULL;
    char                                 **names;
    char                                 **odd;
    size_t                                 n;
    size_t                                 nodd;
    size_t                                 i;
    bool                                   there = false;

    memset(out, 0, sizeof(*out));
    memset(&k, 0, sizeof(k));
    memset(&lists, 0, sizeof(lists));
    memset(&cur, 0, sizeof(cur));
    memset(&old, 0, sizeof(old));
    k.r = r;
    k.out = out;
    k.opts = opts ? opts : &none;
    if (k.opts->record)
    {
        if (!read_record(k.opts->record, &old, &there, err))
        {
            return false;
        }
        rec = &cur;
    }
    /* The snapshots first, then the packs: a capture that finishes in
     * between wrote its packs before its snapshot, so every pack a listed
     * snapshot needs is in the list. */
    names = rs_repo_snapshots(r, &n);
    list_packs(r);
    for (i = 0; i < r->npacks; i++)
    {
        char              *path = rs_xasprintf("packs/%s.idx", r->packs[i]);
        struct rs_buf      text;
        struct rs_buf      why;
        struct rs_repo_idx x;
        bool               sealed = false;

        rs_buf_init(&why);
        rs_buf_init(&text);
        memset(&x, 0, sizeof(x));
        /* The repository's own .idx, never this machine's copy of it: that
         * could hide damage here. None at all for the metadata alone: it may
         * be encrypted. */
        if (!k.opts->metadata_only &&
            !read_sealed(r->st, path, SMALL_MAX, true, &text, &sealed, &why))
        {
            if (sealed && i == 0)
            {
                rs_buf_addf(err, "%s: its packs' indexes could not be decrypted, so it cannot be "
                            "checked: the secret key is not in %s, or its passphrase was not "
                            "given (check --metadata-only needs no key)",
                            r->dir, rs_pgp_key_place());
                rs_buf_free(&why);
                rs_buf_free(&text);
                free(path);
                rs_repo_free_names(names, n);
                map_free(&k.good);
                free(k.sizes);
                rs_repo_record_free(&old);
                return false;
            }
            bad_pack(&k, r->packs[i], why.data);
        } else if (!k.opts->metadata_only && !rs_repo_parse_idx(text.data, text.len, &x))
        {
            char *file = rs_xasprintf("%s.idx", r->packs[i]);

            bad_pack(&k, file, "not a pack index restate wrote");
            free(file);
        } else if (!k.opts->metadata_only)
        {
            keep_lists(&k, &x);
            check_pack(&k, r->packs[i], &x);
        }
        if (k.opts->metadata_only || rec)
        {
            check_sum(&k, r->packs[i], rec);
        }
        out->packs++;
        rs_repo_idx_free(&x);
        rs_buf_free(&text);
        rs_buf_free(&why);
        free(path);
    }
    odd = rs_store_list(r->st, "packs", unpaired, NULL, &nodd);
    for (i = 0; i < nodd; i++)
    {
        size_t len = strlen(odd[i]);

        if (strcmp(odd[i] + len - 4, ".idx") == 0)
        {
            bad_pack(&k, odd[i], "its pack is not there");
        } else
        {
            out->leftovers++;
        }
    }
    rs_repo_free_names(odd, nodd);
    for (i = 0; i < k.nlists; i++)
    {
        if (!map_find(&lists, k.lists[i].d))
        {
            (void)map_add(&lists, k.lists[i].d, 0, (uint32_t)i);
        }
    }
    for (i = 0; i < n; i++)
    {
        if (k.opts->metadata_only)
        {
            check_snapshot_meta(&k, names[i]);
        } else
        {
            check_snapshot(&k, names[i], &lists);
        }
    }
    rs_repo_free_names(names, n);
    odd = rs_store_list(r->st, "snapshots", any_snapshot, NULL, &nodd);
    for (i = 0; i < nodd; i++)
    {
        char                *index = snapshot_file(odd[i], "index.json.gz");
        struct rs_store_stat st;

        if (rs_store_stat(r->st, index, &st) != 0)
        {
            rs_warn("%s::%s: its index is not there", r->dir, odd[i]);
            out->snapshots++;
            out->snapshots_bad++;
        }
        free(index);
    }
    rs_repo_free_names(odd, nodd);
    if (rec)
    {
        record_rest(r, rec);
        if (there)
        {
            record_compare(&k, &old, rec);
        }
        if (!write_record(k.opts->record, rec, err))
        {
            rs_warn("%s", err->data);
            rs_buf_reset(err);
        }
    }
    rs_repo_record_free(&old);
    rs_repo_record_free(&cur);
    map_free(&lists);
    map_free(&k.good);
    free(k.sizes);
    free(k.lists);
    free(k.chunks);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Ingesting a pack or snapshot written elsewhere                            */
/* ------------------------------------------------------------------------- */

/* 1 if the file `name` begins as OpenPGP data does, 0 if it does not, -1
 * if it cannot be read. */
static int sealed_file(const struct rs_store *st, const char *name)
{
    unsigned char head[16];
    ssize_t       got = rs_store_peek(st, name, head, sizeof(head));

    if (got < 0)
    {
        return -1;
    }
    return got > 0 && rs_pgp_detect(head, (size_t)got) ? 1 : 0;
}

/* Whether the staged file `name` is encrypted exactly when `r` is: what is
 * wrong with it into `err`, as `label` names it, if not. */
static bool sealed_as_repo(const struct rs_repo *r, const char *name, const char *label,
                           struct rs_buf *err)
{
    int sealed = sealed_file(r->st, name);

    if (sealed < 0)
    {
        rs_buf_addf(err, "%s: %s", label, strerror(errno));
        return false;
    }
    if ((sealed == 1) != r->encrypted)
    {
        rs_buf_addf(err, "%s: %s, and %s is %s", label,
                    sealed ? "it is encrypted" : "it is not encrypted", r->dir,
                    r->encrypted ? "an encrypted repository" : "not encrypted");
        return false;
    }
    return true;
}

/* The pack's files, in the order they are put in place: the .idx last,
 * since it is what makes a pack count. */
static const char *const ingest_ext[] = { "tar.gz", "sum", "seek", "idx" };
#define INGEST_EXT (sizeof(ingest_ext) / sizeof(ingest_ext[0]))

/*
 * The staged pack `name` -- stage[] its files, by ingest_ext, stage[2] NULL
 * with no .seek -- checked: its content is what its .sum says; and in a
 * repository that is not encrypted, its .idx and .seek can be read and its
 * content is what its .idx says. Encrypted, the storage has no key, so the
 * .sum is all there is to go by, and everything but the .sum has to be
 * encrypted.
 */
static bool pack_staged_ok(const struct rs_repo *r, const char *name, char *const *stage,
                           struct rs_buf *err)
{
    struct rs_buf text;
    struct rs_buf why;
    char          want[RS_SHA256_HEX_SIZE];
    char          got[RS_SHA256_HEX_SIZE];
    uint64_t      want_size = 0;
    uint64_t      got_size = 0;
    bool          ok;

    rs_buf_init(&text);
    rs_buf_init(&why);
    ok = rs_store_read(r->st, stage[1], 4096, &text, &why) &&
         rs_repo_parse_sum(text.data, text.len, want, &want_size);
    if (!ok)
    {
        rs_buf_addf(err, "%s.sum: not a .sum restate wrote", name);
    }
    if (ok && !file_digest(r->st, stage[0], got, &got_size, &why))
    {
        rs_buf_addf(err, "%s.tar.gz: %s", name, why.data);
        ok = false;
    }
    if (ok && (strcmp(got, want) != 0 || got_size != want_size))
    {
        rs_buf_addf(err, "%s.tar.gz: it is not what its .sum says", name);
        ok = false;
    }
    if (ok && r->encrypted && stage[2])
    {
        rs_buf_addf(err, "%s.seek: an encrypted pack has none, as it is read from its start",
                    name);
        ok = false;
    }
    if (ok)
    {
        char *label = rs_xasprintf("%s.tar.gz", name);

        ok = sealed_as_repo(r, stage[0], label, err);
        free(label);
    }
    if (ok)
    {
        char *label = rs_xasprintf("%s.idx", name);

        ok = sealed_as_repo(r, stage[3], label, err);
        free(label);
    }
    if (ok && !r->encrypted)
    {
        struct rs_repo_idx x;

        memset(&x, 0, sizeof(x));
        rs_buf_free(&text);
        rs_buf_reset(&why);
        ok = rs_store_read(r->st, stage[3], SMALL_MAX, &text, &why) &&
             rs_repo_parse_idx(text.data, text.len, &x);
        if (!ok)
        {
            rs_buf_addf(err, "%s.idx: not a pack index restate wrote", name);
        }
        if (ok && stage[2])
        {
            struct rs_repo_seek *seek = NULL;
            size_t               nseek = 0;

            rs_buf_free(&text);
            ok = rs_store_read(r->st, stage[2], SMALL_MAX, &text, &why) &&
                 rs_repo_parse_seek(text.data, text.len, &seek, &nseek);
            free(seek);
            if (!ok)
            {
                rs_buf_addf(err, "%s.seek: not a .seek restate wrote", name);
            }
        }
        rs_buf_reset(&why);
        if (ok && !pack_matches(r->st, stage[0], &x, NULL, &why))
        {
            rs_buf_addf(err, "%s.tar.gz: %s", name,
                        why.len ? why.data : "it could not be read");
            ok = false;
        }
        rs_repo_idx_free(&x);
    }
    rs_buf_free(&text);
    rs_buf_free(&why);
    return ok;
}

/* The pack `name`, whose files are in `from`, into `r`. */
static bool ingest_pack(struct rs_repo *r, const char *from, const char *name,
                        struct rs_repo_ingested *out, struct rs_buf *err)
{
    struct rs_store *src_st;
    char            *src[INGEST_EXT];
    char            *stage[INGEST_EXT];
    char            *final[INGEST_EXT];
    size_t           staged = 0;
    size_t           placed = 0;
    size_t           i;
    uint64_t         bytes = 0;
    bool             ok = true;

    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "%s/%s.tar.gz: not a name restate gives a pack", from, name);
        return false;
    }
    src_st = rs_store_local(from);
    for (i = 0; i < INGEST_EXT; i++)
    {
        src[i] = rs_xasprintf("%s.%s", name, ingest_ext[i]);
        final[i] = rs_xasprintf("packs/%s.%s", name, ingest_ext[i]);
        stage[i] = NULL;
    }
    for (i = 0; ok && i < INGEST_EXT; i++)
    {
        struct rs_store_stat st;
        bool                 there = rs_store_stat(src_st, src[i], &st) == 0;

        if ((!there && i != 2) || (there && st.kind != RS_STORE_FILE))
        {
            char *path = rs_store_path(src_st, src[i]);

            rs_buf_addf(err, "%s: %s", path,
                        there ? "not a regular file"
                              : "not there; a pack comes with its .sum and .idx");
            free(path);
            ok = false;
        }
    }
    if (ok && listed_in(r->packs, r->npacks, name))
    {
        /* There already: the same pack again, as an upload tried twice
         * sends it, is nothing to do; any other is refused. */
        char          want[RS_SHA256_HEX_SIZE];
        char          have[RS_SHA256_HEX_SIZE];
        uint64_t      wsize = 0;
        uint64_t      hsize = 0;
        struct rs_buf text;
        struct rs_buf ignore;

        rs_buf_init(&text);
        rs_buf_init(&ignore);
        if (rs_store_read(src_st, src[1], 4096, &text, &ignore) &&
            rs_repo_parse_sum(text.data, text.len, want, &wsize) &&
            read_sum(r->st, name, have, &hsize) && strcmp(want, have) == 0 && wsize == hsize)
        {
            out->packs_there++;
        } else
        {
            rs_buf_addf(err, "%s/packs/%s: there already, and not the same pack", r->dir, name);
            out->taken = true;
            ok = false;
        }
        rs_buf_free(&text);
        rs_buf_free(&ignore);
        for (i = 0; i < INGEST_EXT; i++)
        {
            free(src[i]);
            free(final[i]);
        }
        rs_store_free(src_st);
        return ok;
    }
    /* Copied in first, under names nothing reads, and checked there: what
     * is checked is what goes in, whatever becomes of the files it came from. */
    for (i = 0; ok && i < INGEST_EXT; i++)
    {
        if (i == 2 && !rs_store_is_file(src_st, src[i]))
        {
            continue;
        }
        stage[i] = beside(final[i]);
        ok = stage_copy(src_st, src[i], r->st, stage[i], &bytes, err);
        staged = i + 1;
        if (!ok)
        {
            out->sys_errno = copy_errno;
        }
    }
    ok = ok && pack_staged_ok(r, name, stage, err);
    for (i = 0; ok && i < INGEST_EXT; i++)
    {
        if (!stage[i])
        {
            continue;
        }
        if (rs_store_rename(r->st, stage[i], final[i], false) != 0)
        {
            out->sys_errno = errno;
            renamed_failed(r->st, final[i], err);
            ok = false;
        } else
        {
            placed = i + 1;
        }
    }
    for (i = 0; i < INGEST_EXT; i++)
    {
        if (!ok && i < staged && stage[i])
        {
            (void)rs_store_remove(r->st, stage[i], false);
        }
        /* Placed, and then the rest could not be: without its .idx, which
         * goes last, nothing counts it, and it is taken out again. */
        if (!ok && i < placed && stage[i])
        {
            (void)rs_store_remove(r->st, final[i], false);
        }
        free(src[i]);
        free(stage[i]);
        free(final[i]);
    }
    rs_store_free(src_st);
    if (ok)
    {
        out->packs_added++;
        out->bytes += bytes;
        list_packs(r);
    }
    return ok;
}

/* The files a snapshot directory holds; the first four it must. */
static const char *const snapshot_files[] = { "index.json.gz", "kit", "info", "packs",
                                              "index.sig" };
#define SNAPSHOT_FILES (sizeof(snapshot_files) / sizeof(snapshot_files[0]))
#define SNAPSHOT_NEEDS 4

/* rs_store_list's keep for what is not a file a snapshot has. */
static bool not_snapshot_file(const struct rs_store *st, const char *dir, const char *name,
                              void *ctx, char **out)
{
    size_t i;

    (void)st;
    (void)dir;
    (void)ctx;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    {
        return false;
    }
    for (i = 0; i < SNAPSHOT_FILES; i++)
    {
        if (strcmp(name, snapshot_files[i]) == 0)
        {
            return false;
        }
    }
    *out = rs_xstrdup(name);
    return true;
}

/* Whether `from` holds only what a snapshot directory does, each a regular
 * file, and every one it must. */
static bool snapshot_dir_ok(const struct rs_store *from, struct rs_buf *err)
{
    size_t n;
    char **odd = rs_store_list(from, "", not_snapshot_file, NULL, &n);
    size_t i;
    bool   ok = true;

    if (!odd && errno != 0)
    {
        rs_buf_addf(err, "%s: %s", rs_store_where(from), strerror(errno));
        return false;
    }
    if (odd && n > 0)
    {
        rs_buf_addf(err, "%s/%s: not a file a snapshot has", rs_store_where(from), odd[0]);
        ok = false;
    }
    rs_repo_free_names(odd, n);
    for (i = 0; ok && i < SNAPSHOT_FILES; i++)
    {
        struct rs_store_stat st;
        bool                 there = rs_store_stat(from, snapshot_files[i], &st) == 0;

        if (there ? st.kind != RS_STORE_FILE : i < SNAPSHOT_NEEDS)
        {
            char *path = rs_store_path(from, snapshot_files[i]);

            rs_buf_addf(err, "%s: %s", path, there ? "not a regular file" : "not there");
            free(path);
            ok = false;
        }
    }
    return ok;
}

/*
 * The staged snapshot in `tmp` checked: its pack list can be read, and every
 * pack it names is in `r`; its index, kit and summary are encrypted exactly
 * when `r` is; and, not encrypted, its index can be read.
 */
static bool snapshot_staged_ok(struct rs_repo *r, const char *tmp, const char *name,
                               struct rs_buf *err)
{
    char         *path = rs_xasprintf("%s/packs", tmp);
    char        **list = NULL;
    size_t        nlist = 0;
    size_t        i;
    struct rs_buf text;
    struct rs_buf why;
    bool          ok;

    rs_buf_init(&text);
    rs_buf_init(&why);
    ok = rs_store_read(r->st, path, SMALL_MAX_LIST, &text, &why) &&
         rs_repo_parse_pack_list(text.data, text.len, &list, &nlist);
    free(path);
    if (!ok)
    {
        rs_buf_addf(err, "%s/packs: not a pack list restate wrote", name);
    }
    list_packs(r);
    for (i = 0; ok && i < nlist; i++)
    {
        if (!listed_in(r->packs, r->npacks, list[i]))
        {
            rs_buf_addf(err, "%s: it needs the pack %s, which %s has not got", name, list[i],
                        r->dir);
            ok = false;
        }
    }
    rs_repo_free_names(list, nlist);
    for (i = 0; ok && i < 3; i++)
    {
        char *file = rs_xasprintf("%s/%s", tmp, snapshot_files[i]);
        char *label = rs_xasprintf("%s/%s", name, snapshot_files[i]);

        ok = sealed_as_repo(r, file, label, err);
        free(file);
        free(label);
    }
    if (ok && !r->encrypted)
    {
        char           *index = rs_xasprintf("%s/index.json.gz", tmp);
        struct rs_index ix;

        rs_buf_free(&text);
        rs_index_init(&ix);
        ok = rs_store_read(r->st, index, RS_IMAGE_INDEX_MAX, &text, &why) &&
             parse_index(&text, name, &ix, &why);
        if (!ok)
        {
            rs_buf_addf(err, "%s/index.json.gz: not an index restate wrote", name);
        }
        rs_index_free(&ix);
        free(index);
    }
    rs_buf_free(&text);
    rs_buf_free(&why);
    return ok;
}

/* The snapshot directory `from`, named `name`, into `r`. */
static bool ingest_snapshot(struct rs_repo *r, const char *from, const char *name,
                            struct rs_repo_ingested *out, struct rs_buf *err)
{
    struct rs_store     *src;
    char                *final;
    char                *there;
    char                *tmp;
    struct rs_store_stat st;
    uint64_t             bytes = 0;
    size_t               i;
    bool                 made;
    bool                 ok;

    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "%s: not a name restate gives a snapshot", from);
        return false;
    }
    src = rs_store_local(from);
    if (!snapshot_dir_ok(src, err))
    {
        rs_store_free(src);
        return false;
    }
    final = rs_xasprintf("snapshots/%s", name);
    there = rs_xasprintf("%s/index.json.gz", final);
    if (rs_store_stat(r->st, there, &st) == 0)
    {
        /* There already: the same snapshot again is nothing to do. */
        char          ha[RS_SHA256_HEX_SIZE];
        char          hb[RS_SHA256_HEX_SIZE];
        uint64_t      sa = 0;
        uint64_t      sb = 0;
        struct rs_buf ignore;

        rs_buf_init(&ignore);
        ok = file_digest(src, "index.json.gz", ha, &sa, &ignore) &&
             file_digest(r->st, there, hb, &sb, &ignore) && strcmp(ha, hb) == 0 && sa == sb;
        if (ok)
        {
            out->snapshots_there++;
        } else
        {
            rs_buf_addf(err, "%s" RS_REPO_SEP "%s: there already, and not the same snapshot",
                        r->dir, name);
            out->taken = true;
        }
        rs_buf_free(&ignore);
        free(there);
        free(final);
        rs_store_free(src);
        return ok;
    }
    free(there);
    tmp = temp_dir(r->st, name, err);
    made = tmp != NULL;
    ok = made;
    if (!made)
    {
        out->sys_errno = errno;
    }
    for (i = 0; ok && i < SNAPSHOT_FILES; i++)
    {
        char *to = rs_xasprintf("%s/%s", tmp, snapshot_files[i]);

        if (i < SNAPSHOT_NEEDS || rs_store_is_file(src, snapshot_files[i]))
        {
            ok = copy_file(src, snapshot_files[i], r->st, to, &bytes, err);
            if (!ok)
            {
                out->sys_errno = copy_errno;
            }
        }
        free(to);
    }
    ok = ok && snapshot_staged_ok(r, tmp, name, err);
    if (ok)
    {
        rs_store_sync_dir(r->st, tmp);
        if (rs_store_rename(r->st, tmp, final, false) != 0)
        {
            out->sys_errno = errno;
            renamed_failed(r->st, final, err);
            ok = false;
        }
    }
    if (!ok && made)
    {
        (void)remove_snapshot_dir(r->st, tmp);
    }
    if (ok)
    {
        rs_store_sync_dir(r->st, "snapshots");
        out->snapshots_added++;
        out->bytes += bytes;
    }
    free(tmp);
    free(final);
    rs_store_free(src);
    return ok;
}

bool rs_repo_ingest(struct rs_repo *r, const char *path, struct rs_repo_ingested *out,
                    struct rs_buf *err)
{
    size_t               len = strlen(path);
    size_t               base;
    struct rs_store     *files = rs_store_local("");
    struct rs_store_stat st;
    int                  rc = rs_store_stat(files, path, &st);
    int                  saved = errno;
    bool                 ok;

    out->taken = false;
    out->sys_errno = 0;
    copy_errno = 0;
    /* The last component, trailing slashes aside: path[base] to path[len]. */
    while (len > 1 && path[len - 1] == '/')
    {
        len--;
    }
    base = len;
    while (base > 0 && path[base - 1] != '/')
    {
        base--;
    }
    rs_store_free(files);
    if (rc != 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(saved));
        return false;
    }
    if (st.kind == RS_STORE_DIR)
    {
        char *name = rs_xstrndup(path + base, len - base);

        ok = ingest_snapshot(r, path, name, out, err);
        free(name);
        return ok;
    }
    if (st.kind == RS_STORE_FILE && len - base > 7 && strncmp(path + len - 7, ".tar.gz", 7) == 0)
    {
        char *from = base == 0 ? rs_xstrdup(".") : rs_xstrndup(path, base == 1 ? 1 : base - 1);
        char *name = rs_xstrndup(path + base, len - base - 7);

        ok = ingest_pack(r, from, name, out, err);
        if (ok)
        {
            rs_store_sync_dir(r->st, "packs");
        }
        free(from);
        free(name);
        return ok;
    }
    rs_buf_addf(err, "%s: neither a pack (NAME.tar.gz, with its .sum and .idx beside it) nor a "
                     "snapshot's directory", path);
    return false;
}

/* Whether `name` is one a chunk key has: "chunk-key", or "chunk-key." and
 * a name. */
static bool chunk_key_name(const char *name)
{
    size_t len = strlen(RS_REPO_CHUNK_KEY);

    return strncmp(name, RS_REPO_CHUNK_KEY, len) == 0 &&
           (name[len] == '\0' || (name[len] == '.' && rs_repo_name_valid(name + len + 1)));
}

bool rs_repo_ingest_chunk_key(struct rs_repo *r, const char *path, const char *name, bool *placed,
                              struct rs_repo_ingested *out, struct rs_buf *err)
{
    struct rs_store     *files = rs_store_local("");
    struct rs_store_stat st;
    char                *tmp;
    uint64_t             bytes = 0;
    int                  rc;
    bool                 ok;

    *placed = false;
    out->taken = false;
    out->sys_errno = 0;
    copy_errno = 0;
    if (!chunk_key_name(name))
    {
        rs_buf_addf(err, "%s: not a name a chunk key has", name);
        rs_store_free(files);
        return false;
    }
    if (!r->encrypted)
    {
        rs_buf_addf(err, "%s: a repository that is not encrypted has no chunk key", r->dir);
        rs_store_free(files);
        return false;
    }
    if (rs_store_stat(files, path, &st) != 0)
    {
        rs_buf_addf(err, "%s: %s", name, strerror(errno));
        rs_store_free(files);
        return false;
    }
    if (st.kind != RS_STORE_FILE)
    {
        rs_buf_addf(err, "%s: not a regular file", name);
        rs_store_free(files);
        return false;
    }
    if (st.size > 4096 || sealed_file(files, path) != 1)
    {
        rs_buf_addf(err, "%s: not a chunk key restate wrote", name);
        rs_store_free(files);
        return false;
    }
    /* Copied in beside where it goes, and then put there only if nothing is:
     * two captures that each made one keep the first. */
    tmp = rs_xasprintf("packs/.%s.%ld.in", RS_REPO_CHUNK_KEY, (long)getpid());
    ok = stage_copy(files, path, r->st, tmp, &bytes, err);
    rs_store_free(files);
    if (!ok)
    {
        out->sys_errno = copy_errno;
        free(tmp);
        return false;
    }
    rc = rs_store_place_new(r->st, tmp, name);
    if (rc < 0)
    {
        out->sys_errno = errno;
        renamed_failed(r->st, name, err);
    }
    (void)rs_store_remove(r->st, tmp, false);
    free(tmp);
    *placed = rc == 1;
    if (rc == 1)
    {
        out->bytes += bytes;
    }
    return rc >= 0;
}

bool rs_repo_remove_pack(struct rs_repo *r, const char *name, struct rs_buf *err)
{
    static const char *const order[] = { "idx", "tar.gz", "sum", "seek" };
    size_t                   i;
    bool                     ok = true;

    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "%s: not a name restate gives a pack", name);
        return false;
    }
    for (i = 0; i < sizeof(order) / sizeof(order[0]); i++)
    {
        char *file = rs_xasprintf("packs/%s.%s", name, order[i]);

        if (rs_store_remove(r->st, file, false) != 0 && errno != ENOENT)
        {
            char *where = rs_store_path(r->st, file);

            rs_buf_addf(err, "%s%s: %s", err->len ? "; " : "", where, strerror(errno));
            free(where);
            ok = false;
        }
        free(file);
        /* Without its .idx, nothing counts the rest: they are what an
         * interrupted capture leaves, which prune clears. */
        if (!ok && i == 0)
        {
            break;
        }
    }
    rs_store_sync_dir(r->st, "packs");
    list_packs(r);
    return ok;
}
