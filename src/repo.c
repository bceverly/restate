/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "repo.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "gzip.h"
#include "image.h"
#include "progress.h"
#include "sha256.h"
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

#define REPO_FORMAT    RS_REPO_MARKER " 1\n"
#define PACK_FORMAT    "restate-pack 1\n"
/* A pack's .idx, a snapshot's kit and its info are small; anything larger is
 * not one restate wrote. */
#define SMALL_MAX      ((size_t)256 * 1024 * 1024)
/* A file this small is read whole before it is stored, so one whose content
 * the repository has already costs nothing but the reading. */
#define BUFFERED_MAX   ((uint64_t)1024 * 1024)
#define NAME_MAX_LEN   64

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

static bool tar_to_fd(void *ctx, const void *data, size_t n)
{
    return write_all(*(const int *)ctx, data, n);
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

/* The whole of a file restate wrote, up to `max` bytes, into `out`. */
static bool read_file(const char *path, size_t max, struct rs_buf *out, struct rs_buf *err)
{
    int  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char chunk[65536];
    bool ok = true;

    rs_buf_init(out);
    rs_buf_add(out, "", 0);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            ok = false;
            break;
        }
        if (n == 0)
        {
            break;
        }
        if (out->len + (size_t)n > max)
        {
            rs_buf_addf(err, "%s: larger than restate writes", path);
            ok = false;
            break;
        }
        rs_buf_add(out, chunk, (size_t)n);
    }
    (void)close(fd);
    return ok;
}

/* `len` bytes into a new file `path`, 0600, flushed to disk. */
static bool write_new(const char *path, const void *data, size_t len, struct rs_buf *err)
{
    int  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok;

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
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
    return ok;
}

/* A directory's own entries flushed, so a rename into it survives a crash. */
static void sync_dir(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    if (fd >= 0)
    {
        (void)fsync(fd);
        (void)close(fd);
    }
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

/* ------------------------------------------------------------------------- */
/* Digests                                                                   */
/* ------------------------------------------------------------------------- */

/* A set of digests, each with the pack that holds its content: open
 * addressing on the digest itself, which is as good a hash as there is. */
struct obj {
    unsigned char d[32];
    uint32_t      pack;     /* into rs_repo.packs; for prune, whether taken */
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
static struct obj *map_put(struct objmap *m, const unsigned char d[32], uint32_t pack)
{
    size_t i;

    for (i = slot_of(m, d); m->slots[i].used; i = (i + 1) & (m->cap - 1))
    {
    }
    memcpy(m->slots[i].d, d, 32);
    m->slots[i].pack = pack;
    m->slots[i].used = true;
    m->n++;
    return &m->slots[i];
}

/* The digest's entry, added with `pack` if it was not there; the table is
 * kept at most half full, so a search ends soon. */
static struct obj *map_add(struct objmap *m, const unsigned char d[32], uint32_t pack)
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
                (void)map_put(&bigger, m->slots[i].d, m->slots[i].pack);
            }
        }
        free(m->slots);
        *m = bigger;
    }
    return map_put(m, d, pack);
}

static void map_free(struct objmap *m)
{
    free(m->slots);
    memset(m, 0, sizeof(*m));
}

/* ------------------------------------------------------------------------- */
/* The repository                                                            */
/* ------------------------------------------------------------------------- */

struct rs_repo {
    char         *dir;
    int           lock_fd;
    int           readers_fd;
    char        **packs;      /* names, without ".tar.gz", sorted */
    size_t        npacks;
    struct objmap objects;    /* every live digest in a pack, once loaded */
    bool          loaded;
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
    char         *marker = rs_xasprintf("%s/%s", dir, RS_REPO_MARKER);
    struct rs_buf text;
    struct rs_buf err;
    bool          ok;

    rs_buf_init(&err);
    ok = read_file(marker, 4096, &text, &err) && rs_starts_with(text.data, RS_REPO_MARKER " ");
    rs_buf_free(&text);
    rs_buf_free(&err);
    free(marker);
    return ok;
}

bool rs_repo_init(const char *dir, struct rs_buf *err)
{
    static const char *const subdirs[] = { "packs", "snapshots" };
    static const char *const empty[] = { "lock", "readers" };
    char                    *path;
    size_t                   i;
    bool                     ok = true;

    /* Made, or else there already: then it has to be an empty directory, and
     * everything about it is learned through the one descriptor on it, so
     * nothing can be swapped in between. */
    if (mkdir(dir, 0700) != 0)
    {
        int  made = errno;
        int  fd = made == EEXIST ? open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
        int  listing = fd >= 0 ? dup(fd) : -1;
        DIR *d = listing >= 0 ? fdopendir(listing) : NULL;
        bool has = !d;

        if (made != EEXIST)
        {
            rs_buf_addf(err, "%s: %s", dir, strerror(made));
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
            has = strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0;
        }
        if (d)
        {
            (void)closedir(d);
        }
        if (!has)
        {
            /* Its owner's alone, as a new one is made. */
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
            return false;
        }
    }
    for (i = 0; ok && i < sizeof(subdirs) / sizeof(subdirs[0]); i++)
    {
        path = rs_xasprintf("%s/%s", dir, subdirs[i]);
        ok = mkdir(path, 0700) == 0;
        if (!ok)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
        }
        free(path);
    }
    for (i = 0; ok && i < sizeof(empty) / sizeof(empty[0]); i++)
    {
        path = rs_xasprintf("%s/%s", dir, empty[i]);
        ok = write_new(path, "", 0, err);
        free(path);
    }
    /* The marker last: until it is there, this is not a repository. */
    if (ok)
    {
        path = rs_xasprintf("%s/%s", dir, RS_REPO_MARKER);
        ok = write_new(path, REPO_FORMAT, strlen(REPO_FORMAT), err);
        free(path);
        sync_dir(dir);
    }
    return ok;
}

bool rs_repo_ref(const char *ref, char **dir, char **name)
{
    const char *sep = NULL;
    const char *p = ref;

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

/* Takes the lock file `name` as `how` says, without waiting. */
static int take(const char *dir, const char *name, int how, bool *busy, struct rs_buf *err)
{
    char *path = rs_xasprintf("%s/%s", dir, name);
    int   fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return -1;
    }
    if (flock(fd, how | LOCK_NB) != 0)
    {
        if (errno == EWOULDBLOCK)
        {
            *busy = true;
            rs_buf_addf(err, "%s: %s", dir,
                        strcmp(name, "lock") == 0
                            ? "another capture or prune is using it; try again when it is done"
                            : "a prune is running on it, or something is reading it while "
                              "prune wants to; try again when it is done");
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

static int by_name(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The entries of `dir` that `keep` accepts, sorted. */
static char **list_dir(const char *dir, bool (*keep)(const char *dir, const char *name, char **out),
                       size_t *n)
{
    DIR                 *d = opendir(dir);
    const struct dirent *de;
    char               **names = NULL;

    *n = 0;
    if (!d)
    {
        return NULL;
    }
    while ((de = readdir(d)) != NULL)
    {
        char *name = NULL;

        if (keep(dir, de->d_name, &name))
        {
            names = rs_xreallocarray(names, *n + 1, sizeof(*names));
            names[(*n)++] = name;
        }
    }
    (void)closedir(d);
    if (*n > 1)
    {
        qsort(names, *n, sizeof(*names), by_name);
    }
    return names;
}

void rs_repo_free_names(char **names, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(names[i]);
    }
    free(names);
}

/* A pack counts once its .idx is there, beside its content. */
static bool is_pack(const char *dir, const char *name, char **out)
{
    size_t      len = strlen(name);
    char       *stem;
    char       *content;
    struct stat st;
    bool        ok;

    if (len <= 4 || strcmp(name + len - 4, ".idx") != 0)
    {
        return false;
    }
    stem = rs_xstrndup(name, len - 4);
    content = rs_xasprintf("%s/%s.tar.gz", dir, stem);
    ok = rs_repo_name_valid(stem) && lstat(content, &st) == 0 && S_ISREG(st.st_mode);
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
    char *dir = rs_xasprintf("%s/packs", r->dir);

    rs_repo_free_names(r->packs, r->npacks);
    r->packs = list_dir(dir, is_pack, &r->npacks);
    free(dir);
}

struct rs_repo *rs_repo_open(const char *dir, enum rs_repo_lock lock, bool *busy,
                             struct rs_buf *err)
{
    struct rs_repo *r;
    char           *marker = rs_xasprintf("%s/%s", dir, RS_REPO_MARKER);
    struct rs_buf   text;
    bool            ok = read_file(marker, 4096, &text, err);

    *busy = false;
    free(marker);
    if (ok && strcmp(text.data, REPO_FORMAT) != 0)
    {
        bool newer = rs_starts_with(text.data, RS_REPO_MARKER " ");

        rs_buf_addf(err, "%s: %s", dir,
                    newer ? "a repository made by a newer restate" : "not a restate repository");
        ok = false;
    }
    rs_buf_free(&text);
    if (!ok)
    {
        return NULL;
    }
    r = rs_xcalloc(1, sizeof(*r));
    r->dir = rs_xstrdup(dir);
    r->lock_fd = -1;
    r->readers_fd = -1;
    if (lock == RS_REPO_WRITE || lock == RS_REPO_PRUNE)
    {
        r->lock_fd = take(dir, "lock", LOCK_EX, busy, err);
        ok = r->lock_fd >= 0;
    }
    if (ok && (lock == RS_REPO_READ || lock == RS_REPO_PRUNE))
    {
        r->readers_fd = take(dir, "readers", lock == RS_REPO_PRUNE ? LOCK_EX : LOCK_SH, busy, err);
        ok = r->readers_fd >= 0;
    }
    if (!ok)
    {
        rs_repo_close(r);
        return NULL;
    }
    list_packs(r);
    return r;
}

void rs_repo_close(struct rs_repo *r)
{
    if (!r)
    {
        return;
    }
    if (r->lock_fd >= 0)
    {
        (void)close(r->lock_fd);
    }
    if (r->readers_fd >= 0)
    {
        (void)close(r->readers_fd);
    }
    rs_repo_free_names(r->packs, r->npacks);
    map_free(&r->objects);
    free(r->dir);
    free(r);
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

bool rs_repo_parse_idx(const char *text, size_t len, struct rs_repo_member **out, size_t *n)
{
    const char *p = text;
    const char *end = text + len;
    size_t      cap = 0;
    bool        ok = true;

    *out = NULL;
    *n = 0;
    if (len < strlen(PACK_FORMAT) || memcmp(text, PACK_FORMAT, strlen(PACK_FORMAT)) != 0)
    {
        return false;
    }
    p += strlen(PACK_FORMAT);
    while (ok && p < end)
    {
        struct rs_repo_member m;

        memset(&m, 0, sizeof(m));
        ok = number(&p, end, &m.member) && skip(&p, end, ' ');
        if (ok && !skip(&p, end, '-'))
        {
            ok = (size_t)(end - p) >= RS_SHA256_HEX_LEN;
            if (ok)
            {
                memcpy(m.hash, p, RS_SHA256_HEX_LEN);
                m.hash[RS_SHA256_HEX_LEN] = '\0';
                ok = rs_sha256_valid_hex(m.hash) != 0;
                m.live = true;
                p += RS_SHA256_HEX_LEN;
            }
        }
        ok = ok && skip(&p, end, ' ') && number(&p, end, &m.size) && skip(&p, end, '\n') &&
             (*n == 0 || m.member > (*out)[*n - 1].member);
        if (ok)
        {
            if (*n == cap)
            {
                cap = cap ? cap * 2 : 64;
                *out = rs_xreallocarray(*out, cap, sizeof(**out));
            }
            (*out)[(*n)++] = m;
        }
    }
    if (!ok)
    {
        free(*out);
        *out = NULL;
        *n = 0;
    }
    return ok;
}

/* A pack's members, from its .idx. */
static bool pack_members(const struct rs_repo *r, const char *pack, struct rs_repo_member **m,
                         size_t *n, struct rs_buf *err)
{
    char         *path = rs_xasprintf("%s/packs/%s.idx", r->dir, pack);
    struct rs_buf text;
    bool          ok = read_file(path, SMALL_MAX, &text, err);

    if (ok && !rs_repo_parse_idx(text.data, text.len, m, n))
    {
        rs_buf_addf(err, "%s: not a pack index restate wrote", path);
        ok = false;
    }
    rs_buf_free(&text);
    free(path);
    return ok;
}

/* Every live digest in every pack, once. A pack whose .idx cannot be read is
 * passed over, with a warning: its content is as good as gone. */
static void load_objects(struct rs_repo *r)
{
    size_t i;

    if (r->loaded)
    {
        return;
    }
    r->loaded = true;
    for (i = 0; i < r->npacks; i++)
    {
        struct rs_repo_member *m = NULL;
        struct rs_buf          err;
        size_t                 n = 0;
        size_t                 k;

        rs_buf_init(&err);
        if (!pack_members(r, r->packs[i], &m, &n, &err))
        {
            rs_warn("%s", err.data);
        }
        for (k = 0; k < n; k++)
        {
            unsigned char d[32];

            if (m[k].live && unhex(m[k].hash, d))
            {
                (void)map_add(&r->objects, d, (uint32_t)i);
            }
        }
        free(m);
        rs_buf_free(&err);
    }
}

/* ------------------------------------------------------------------------- */
/* Snapshots                                                                 */
/* ------------------------------------------------------------------------- */

static bool is_snapshot(const char *dir, const char *name, char **out)
{
    char       *index = rs_xasprintf("%s/%s/index.json.gz", dir, name);
    struct stat st;
    bool        ok = rs_repo_name_valid(name) && lstat(index, &st) == 0 && S_ISREG(st.st_mode);

    free(index);
    if (ok)
    {
        *out = rs_xstrdup(name);
    }
    return ok;
}

char **rs_repo_snapshots(struct rs_repo *r, size_t *n)
{
    char  *dir = rs_xasprintf("%s/snapshots", r->dir);
    char **names = list_dir(dir, is_snapshot, n);

    free(dir);
    return names;
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

static char *snapshot_file(const struct rs_repo *r, const char *name, const char *file)
{
    return rs_xasprintf("%s/snapshots/%s/%s", r->dir, name, file);
}

bool rs_repo_index_bytes(const struct rs_repo *r, const char *name, struct rs_buf *gz,
                         struct rs_buf *sig, struct rs_buf *err)
{
    char       *path = snapshot_file(r, name, "index.json.gz");
    struct stat st;
    bool        ok;

    rs_buf_free(gz);
    ok = rs_repo_name_valid(name) && read_file(path, RS_IMAGE_INDEX_MAX, gz, err);
    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "\"%s\" is not the name of a snapshot", name);
    }
    free(path);
    path = snapshot_file(r, name, "index.sig");
    rs_buf_reset(sig);
    if (ok && lstat(path, &st) == 0)
    {
        struct rs_buf text;

        ok = read_file(path, (size_t)64 * 1024, &text, err);
        if (ok)
        {
            rs_buf_add(sig, text.data, text.len);
        }
        rs_buf_free(&text);
    }
    free(path);
    return ok;
}

bool rs_repo_load_index(struct rs_repo *r, const char *name, struct rs_index *ix,
                        struct rs_buf *err)
{
    struct rs_buf  gz;
    struct rs_buf  sig;
    struct rs_buf  text;
    struct rs_gzip unzip;
    FILE          *tmp = NULL;
    char          *label = rs_xasprintf("%s" RS_REPO_SEP "%s", r->dir, name);
    bool           ok;

    rs_buf_init(&gz);
    rs_buf_init(&sig);
    rs_buf_init(&text);
    ok = rs_repo_index_bytes(r, name, &gz, &sig, err);
    if (ok)
    {
        /* Read once, then handed to gzip from a file of its own: the bytes
         * whose digest is taken are the bytes that are read. */
        rs_sha256_hex(gz.data, gz.len, ix->part_sha256);
        tmp = tmpfile();
        ok = tmp && (gz.len == 0 || fwrite(gz.data, 1, gz.len, tmp) == gz.len) &&
             fflush(tmp) == 0 && lseek(fileno(tmp), 0, SEEK_SET) == 0;
        if (!ok)
        {
            rs_buf_addf(err, "%s: a temporary file for its index: %s", label, strerror(errno));
        }
    }
    ok = ok && rs_gzip_decompress(fileno(tmp), &unzip, err);
    if (ok)
    {
        char    chunk[65536];
        ssize_t n;
        bool    big = false;

        rs_buf_add(&text, "", 0);
        while ((n = read(unzip.fd, chunk, sizeof(chunk))) > 0 && !big)
        {
            big = text.len + (size_t)n > RS_IMAGE_INDEX_MAX;
            rs_buf_add(&text, chunk, big ? 0 : (size_t)n);
        }
        ok = rs_gzip_finish(&unzip, big || n < 0, err) && !big && n == 0;
        if (!ok && err->len == 0)
        {
            rs_buf_addf(err, "%s: its index could not be read", label);
        }
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
    rs_buf_free(&gz);
    rs_buf_free(&sig);
    rs_buf_free(&text);
    free(label);
    return ok;
}

bool rs_repo_add_signature(struct rs_repo *r, const char *name, const void *sig, size_t len,
                           struct rs_buf *err)
{
    char       *path;
    struct stat st;
    bool        ok;

    if (!rs_repo_name_valid(name))
    {
        rs_buf_addf(err, "\"%s\" is not the name of a snapshot", name);
        return false;
    }
    path = snapshot_file(r, name, "index.sig");
    if (lstat(path, &st) == 0)
    {
        rs_buf_addf(err, "%s" RS_REPO_SEP "%s: it is signed already", r->dir, name);
        free(path);
        return false;
    }
    ok = write_new(path, sig, len, err);
    free(path);
    return ok;
}

bool rs_repo_kit(const struct rs_repo *r, const char *name, char ***paths, size_t *n,
                 struct rs_buf *err)
{
    char         *path = snapshot_file(r, name, "kit");
    struct rs_buf text;
    const char   *p;
    bool          ok = rs_repo_name_valid(name) && read_file(path, SMALL_MAX, &text, err);

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
    char                 *path = snapshot_file(r, name, "info");
    struct rs_buf         text;
    struct rs_json_parser jp;
    bool                  ok = rs_repo_name_valid(name) && read_file(path, SMALL_MAX, &text, err);

    memset(info, 0, sizeof(*info));
    if (ok)
    {
        rs_json_init(&jp, text.data, text.len, err);
        ok = rs_json_value(&jp, info) && rs_json_at_end(&jp) && info->type == RS_JOBJECT;
        if (!ok)
        {
            rs_jval_free(info);
            memset(info, 0, sizeof(*info));
            rs_buf_reset(err);
            rs_buf_addf(err, "%s: not a summary restate wrote", path);
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

void rs_repo_set_pack_size(uint64_t bytes)
{
    pack_size = bytes ? bytes : RS_REPO_PACK_SIZE;
}

struct pack_out {
    bool                 open;
    char                *name;   /* without ".tar.gz" */
    char                *tmp;    /* its content, until it is complete */
    int                  fd;
    struct rs_gzip       gz;
    struct rs_tar_writer tar;
    struct rs_buf        idx;
    uint64_t             seq;
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
        struct stat st;
        char       *idx;
        char       *content;
        bool        taken;

        free(name);
        name = rs_xasprintf("%s-%ld-%04u", when, (long)getpid(), ++packs_begun);
        idx = rs_xasprintf("%s/packs/%s.idx", r->dir, name);
        content = rs_xasprintf("%s/packs/%s.tar.gz", r->dir, name);
        taken = lstat(idx, &st) == 0 || lstat(content, &st) == 0;
        free(idx);
        free(content);
        if (!taken)
        {
            return name;
        }
    }
}

static bool pack_open(struct rs_repo *r, struct pack_out *pk, struct rs_buf *err)
{
    memset(pk, 0, sizeof(*pk));
    pk->name = pack_name(r);
    pk->tmp = rs_xasprintf("%s/packs/.%s.tar.gz.tmp", r->dir, pk->name);
    pk->fd = open(pk->tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (pk->fd < 0)
    {
        rs_buf_addf(err, "%s: %s", pk->tmp, strerror(errno));
        free(pk->name);
        free(pk->tmp);
        memset(pk, 0, sizeof(*pk));
        return false;
    }
    if (!rs_gzip_compress(pk->fd, &pk->gz, err))
    {
        (void)close(pk->fd);
        (void)unlink(pk->tmp);
        free(pk->name);
        free(pk->tmp);
        memset(pk, 0, sizeof(*pk));
        return false;
    }
    rs_tar_writer_init(&pk->tar, tar_to_fd, &pk->gz.fd);
    rs_buf_init(&pk->idx);
    rs_buf_addstr(&pk->idx, PACK_FORMAT);
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
    rs_buf_init(&ignore);
    (void)rs_gzip_finish(&pk->gz, true, &ignore);
    rs_buf_free(&ignore);
    (void)close(pk->fd);
    (void)unlink(pk->tmp);
    free(pk->name);
    free(pk->tmp);
    rs_buf_free(&pk->idx);
    memset(pk, 0, sizeof(*pk));
}

/* Finishes the pack: its content in place, then its .idx, which is what makes
 * it count. Its name, on success, into *done. */
static bool pack_close(struct rs_repo *r, struct pack_out *pk, char **done, struct rs_buf *err)
{
    char *final = rs_xasprintf("%s/packs/%s.tar.gz", r->dir, pk->name);
    char *idx = rs_xasprintf("%s/packs/.%s.idx.tmp", r->dir, pk->name);
    char *idx_final = rs_xasprintf("%s/packs/%s.idx", r->dir, pk->name);
    bool  ok = rs_tar_finish(&pk->tar);

    if (!rs_gzip_finish(&pk->gz, !ok, err))
    {
        ok = false;
    }
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
        rs_buf_addf(err, "%s: %s", pk->tmp, strerror(errno));
    }
    if (ok && rename(pk->tmp, final) != 0)
    {
        rs_buf_addf(err, "%s: %s", final, strerror(errno));
        ok = false;
    }
    ok = ok && write_new(idx, pk->idx.data, pk->idx.len, err);
    if (ok && rename(idx, idx_final) != 0)
    {
        rs_buf_addf(err, "%s: %s", idx_final, strerror(errno));
        ok = false;
    }
    if (!ok)
    {
        (void)unlink(pk->tmp);
        (void)unlink(final);
        (void)unlink(idx);
    }
    free(final);
    free(idx);
    free(idx_final);
    free(pk->tmp);
    rs_buf_free(&pk->idx);
    *done = ok ? pk->name : NULL;
    if (!ok)
    {
        free(pk->name);
    }
    memset(pk, 0, sizeof(*pk));
    return ok;
}

/* The header of the pack's next member, `size` bytes, numbered. */
static bool pack_header(struct pack_out *pk, uint64_t size)
{
    struct rs_tar_member m;
    char                *num = rs_xasprintf("%" PRIu64, ++pk->seq);
    bool                 ok;

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

/* ------------------------------------------------------------------------- */
/* Adding a snapshot                                                         */
/* ------------------------------------------------------------------------- */

struct rs_repo_writer {
    struct rs_repo  *r;
    struct pack_out  pk;
    char           **made;     /* packs finished, removed again on abort */
    size_t           nmade;
    char           **kit;
    size_t           nkit;
    uint64_t         objects;
    uint64_t         bytes;
    struct sigaction saved;
};

struct rs_repo_writer *rs_repo_writer_begin(struct rs_repo *r, struct rs_buf *err)
{
    struct rs_repo_writer *w = rs_xcalloc(1, sizeof(*w));
    struct sigaction       ignore;

    (void)err;
    w->r = r;
    load_objects(r);
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

    return unhex(hash, d) && map_find(&w->r->objects, d) != NULL;
}

/* Counts the content just stored as the repository's, if it is new. */
static bool now_held(struct rs_repo_writer *w, const struct rs_entry *e)
{
    unsigned char d[32];

    if (e->hash_state != RS_HASH_PRESENT || !unhex(e->hash, d) ||
        map_find(&w->r->objects, d) != NULL)
    {
        return false;
    }
    (void)map_add(&w->r->objects, d, UINT32_MAX);
    w->objects++;
    w->bytes += e->size;
    return true;
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

/*
 * A small file, read whole first -- exactly as rs_image_copy_file reads it,
 * a file that grows kept as it was when the read began, one that shrinks or
 * cannot be read marked so -- and stored only if its content is new.
 */
static bool store_small(struct rs_repo_writer *w, struct rs_entry *e, int fd, uint64_t size,
                        struct rs_buf *err)
{
    struct rs_buf        data;
    struct rs_buf        sink;
    struct rs_tar_writer tw;
    bool                 ok = true;

    /* Through a tar writer into memory, so the reading is rs_image_copy_file's
     * own; the member's header and padding around it are dropped. */
    rs_buf_init(&sink);
    rs_tar_writer_init(&tw, to_buf, &sink);
    if (!rs_image_copy_file(&tw, e, fd, size))
    {
        rs_buf_free(&sink);
        rs_buf_addf(err, "reading %s: %s", e->path, strerror(errno));
        return false;
    }
    rs_buf_init(&data);
    rs_buf_add(&data, sink.data ? sink.data : "", (size_t)size);
    rs_buf_free(&sink);
    if (now_held(w, e))
    {
        ok = ensure_pack(w, err) && pack_header(&w->pk, size) &&
             rs_tar_data(&w->pk.tar, data.data ? data.data : "", (size_t)size) &&
             rs_tar_pad(&w->pk.tar);
        if (ok)
        {
            pack_line(&w->pk, e->hash, size);
        } else if (err->len == 0)
        {
            rs_buf_addf(err, "writing a pack in %s: %s", w->r->dir, strerror(errno));
        }
    }
    rs_buf_free(&data);
    return ok && maybe_close(w, err);
}

/* A larger file, written into the pack as it is read; if its content turns
 * out to be there already, the copy is marked dead for prune. */
static bool store_large(struct rs_repo_writer *w, struct rs_entry *e, int fd, uint64_t size,
                        struct rs_buf *err)
{
    if (!ensure_pack(w, err))
    {
        return false;
    }
    if (!pack_header(&w->pk, size) || !rs_image_copy_file(&w->pk.tar, e, fd, size))
    {
        rs_buf_addf(err, "writing a pack in %s: %s", w->r->dir, strerror(errno));
        return false;
    }
    pack_line(&w->pk, now_held(w, e) ? e->hash : NULL, size);
    return maybe_close(w, err);
}

bool rs_repo_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                   struct rs_buf *err)
{
    struct rs_repo_writer *w = ctx;
    bool                   ok = true;

    if (e->type == 'c' || e->type == 'b')
    {
        return true;   /* recreated from the index, as from an image */
    }
    if (e->type == 'f' && fd >= 0)
    {
        uint64_t size = (uint64_t)st->st_size;

        ok = size <= BUFFERED_MAX ? store_small(w, e, fd, size, err)
                                  : store_large(w, e, fd, size, err);
    }
    if (ok)
    {
        free(e->stored);
        e->stored = rs_image_member_name(e->path);
    }
    return ok;
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

/* The index, gzip'd, into the new file `path`. */
static bool write_index(const char *path, const struct rs_index *ix, struct rs_buf *err)
{
    struct rs_gzip gz;
    size_t         len = 0;
    char          *text = index_text(ix, &len);
    int            fd;
    bool           ok;

    if (!text)
    {
        rs_buf_addstr(err, "could not render the index");
        return false;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    ok = fd >= 0;
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
    }
    ok = ok && rs_gzip_compress(fd, &gz, err);
    if (ok)
    {
        bool wrote = write_all(gz.fd, text, len);

        ok = rs_gzip_finish(&gz, !wrote, err) && wrote;
        if (!ok && err->len == 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
        }
    }
    if (fd >= 0)
    {
        if (ok && fsync(fd) != 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            ok = false;
        }
        (void)close(fd);
    }
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
    ok = write_new(path, text.data, text.len, err);
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
    ok = write_new(path, text.data, text.len, err);
    rs_buf_free(&text);
    return ok;
}

/* Removes a snapshot directory's files, then the directory: only what
 * restate puts there, so nothing else is removed by mistake. */
static bool remove_snapshot_dir(const char *dir)
{
    static const char *const files[] = { "index.json.gz", "index.sig", "kit", "info" };
    size_t                   i;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++)
    {
        char *path = rs_xasprintf("%s/%s", dir, files[i]);

        (void)unlink(path);
        free(path);
    }
    return rmdir(dir) == 0;
}

static void writer_free(struct rs_repo_writer *w)
{
    (void)sigaction(SIGPIPE, &w->saved, NULL);
    rs_repo_free_names(w->made, w->nmade);
    rs_repo_free_names(w->kit, w->nkit);
    free(w);
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
        char *idx = rs_xasprintf("%s/packs/%s.idx", w->r->dir, w->made[i]);
        char *content = rs_xasprintf("%s/packs/%s.tar.gz", w->r->dir, w->made[i]);

        (void)unlink(idx);
        (void)unlink(content);
        free(idx);
        free(content);
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
    /* Two captures in one second are told apart by a number after the time. */
    for (k = 1; ok && k < 1000 && !name; k++)
    {
        struct stat st;
        char       *candidate = k == 1 ? rs_xstrdup(base) : rs_xasprintf("%s-%d", base, k);

        free(final);
        final = rs_xasprintf("%s/snapshots/%s", w->r->dir, candidate);
        if (lstat(final, &st) != 0 && errno == ENOENT)
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
        tmp = rs_xasprintf("%s/snapshots/.%s.XXXXXX", w->r->dir, name);
        if (!mkdtemp(tmp))
        {
            rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
            free(tmp);
            tmp = NULL;
            ok = false;
        }
    }
    if (ok)
    {
        path = rs_xasprintf("%s/index.json.gz", tmp);
        ok = write_index(path, ix, err);
        if (ok && sign_with)
        {
            struct rs_buf sig;
            char         *sigpath = rs_xasprintf("%s/index.sig", tmp);

            rs_buf_init(&sig);
            ok = rs_pgp_sign(sign_with, path, &sig, &out->signer, err) &&
                 write_new(sigpath, sig.data, sig.len, err);
            rs_buf_free(&sig);
            free(sigpath);
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
        sync_dir(tmp);
        if (rename(tmp, final) != 0)
        {
            rs_buf_addf(err, "%s: %s", final, strerror(errno));
            ok = false;
        }
    }
    if (ok)
    {
        path = rs_xasprintf("%s/snapshots", w->r->dir);
        sync_dir(path);
        free(path);
        out->name = name;
        name = NULL;
        out->objects = w->objects;
        out->bytes = w->bytes;
        /* Its packs are the repository's now; the digests it added are
         * counted again from them if anything reads the repository next. */
        list_packs(w->r);
        map_free(&w->r->objects);
        w->r->loaded = false;
        writer_free(w);
    } else
    {
        if (tmp)
        {
            (void)remove_snapshot_dir(tmp);
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

enum phase {
    PH_OTHERS = 0,   /* directories, symlinks and FIFOs, from the index */
    PH_PACKS,        /* the files, pack by pack */
    PH_UNREAD,       /* files that could not be read when they were captured */
    PH_END,          /* the end of the archive */
    PH_DONE
};

enum source {
    SRC_PACK = 0,    /* the member of the pack being read */
    SRC_SPOOL,       /* a copy of it, for the second file with that content */
    SRC_ZERO
};

struct rs_repo_stream {
    struct rs_repo        *r;
    const struct rs_index *ix;
    bool                  *want;      /* per entry */
    enum phase             phase;
    size_t                 pos;       /* the next entry, where a phase walks the index */
    struct ref            *refs;      /* sorted by digest */
    size_t                 nrefs;
    bool                  *sent;      /* per ref: the content of its digest was sent */
    uint32_t              *packs;     /* those to read, in order */
    size_t                 npacks;
    size_t                 pack_i;
    /* The pack being read. */
    bool                   in_pack;
    struct rs_gzip         gz;
    struct rs_tar_reader   tr;
    struct rs_tar_entry    te;
    struct rs_repo_member *members;
    size_t                 nmembers;
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

/* The refs with digest `hash`: [*lo, *hi). */
static void refs_of(const struct rs_repo_stream *s, const char *hash, size_t *lo, size_t *hi)
{
    size_t a = 0;
    size_t b = s->nrefs;

    while (a < b)
    {
        size_t mid = a + (b - a) / 2;

        if (strcmp(s->refs[mid].hash, hash) < 0)
        {
            a = mid + 1;
        } else
        {
            b = mid;
        }
    }
    *lo = a;
    while (a < s->nrefs && strcmp(s->refs[a].hash, hash) == 0)
    {
        a++;
    }
    *hi = a;
}

struct rs_repo_stream *rs_repo_stream_open(struct rs_repo *r, const struct rs_index *ix,
                                           const char *const *only, size_t nonly,
                                           struct rs_buf *err)
{
    struct rs_repo_stream *s = rs_xcalloc(1, sizeof(*s));
    bool                  *need;
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

        s->want[i] = e->stored && (!only || rs_image_in_list(e->path, only, nonly));
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
    s->sent = rs_xcalloc(s->nrefs + 1, sizeof(*s->sent));
    /* The packs to read: those that hold any of it, in order. */
    need = rs_xcalloc(r->npacks + 1, sizeof(*need));
    for (i = 0; i < s->nrefs; i++)
    {
        unsigned char     d[32];
        const struct obj *o = unhex(s->refs[i].hash, d) ? map_find(&r->objects, d) : NULL;

        if (o && o->pack < r->npacks)
        {
            need[o->pack] = true;
        }
    }
    s->packs = rs_xcalloc(r->npacks + 1, sizeof(*s->packs));
    for (i = 0; i < r->npacks; i++)
    {
        if (need[i])
        {
            s->packs[s->npacks++] = (uint32_t)i;
        }
    }
    free(need);
    rs_buf_init(&s->out);
    rs_buf_init(&s->err);
    rs_tar_entry_init(&s->te);
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

static void close_pack(struct rs_repo_stream *s, bool abandon)
{
    struct rs_buf why;

    rs_buf_init(&why);
    if (!rs_gzip_finish(&s->gz, abandon, &why) && !abandon)
    {
        rs_warn("%s/packs/%s.tar.gz: %s", s->r->dir, s->r->packs[s->packs[s->pack_i - 1]],
                why.data ? why.data : "it could not be read to its end");
    }
    rs_buf_free(&why);
    free(s->members);
    s->members = NULL;
    s->nmembers = 0;
    s->in_pack = false;
}

static bool open_pack(struct rs_repo_stream *s, uint32_t p)
{
    const char   *name = s->r->packs[p];
    char         *path = rs_xasprintf("%s/packs/%s.tar.gz", s->r->dir, name);
    struct rs_buf why;
    int           fd;
    bool          ok;

    rs_buf_init(&why);
    ok = pack_members(s->r, name, &s->members, &s->nmembers, &why);
    fd = ok ? open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    if (ok && fd < 0)
    {
        rs_buf_addf(&why, "%s: %s", path, strerror(errno));
        ok = false;
    }
    ok = ok && rs_gzip_decompress(fd, &s->gz, &why);
    if (fd >= 0)
    {
        (void)close(fd);
    }
    if (!ok)
    {
        rs_warn("%s; the files whose content is in it are missing", why.data);
        free(s->members);
        s->members = NULL;
        s->nmembers = 0;
    } else
    {
        rs_tar_reader_init(&s->tr, read_fd, &s->gz.fd);
        s->in_pack = true;
    }
    rs_buf_free(&why);
    free(path);
    return ok;
}

/* The pack member numbered by `name`, if its .idx calls it live. */
static const struct rs_repo_member *live_member(const struct rs_repo_stream *s, const char *name)
{
    const char *p = name;
    uint64_t    num;
    size_t      a = 0;
    size_t      b = s->nmembers;

    if (!number(&p, name + strlen(name), &num) || *p != '\0')
    {
        return NULL;
    }
    while (a < b)
    {
        size_t mid = a + (b - a) / 2;

        if (s->members[mid].member < num)
        {
            a = mid + 1;
        } else
        {
            b = mid;
        }
    }
    return a < s->nmembers && s->members[a].member == num && s->members[a].live ? &s->members[a]
                                                                              : NULL;
}

/* The current member's content, all of it, into a spool of its own. */
static bool spool(struct rs_repo_stream *s)
{
    char    chunk[65536];
    ssize_t n;

    s->spool = tmpfile();
    if (!s->spool)
    {
        rs_buf_addf(&s->err, "a temporary file: %s", strerror(errno));
        return false;
    }
    while ((n = rs_tar_read(&s->tr, chunk, sizeof(chunk), &s->err)) > 0)
    {
        if (fwrite(chunk, 1, (size_t)n, s->spool) != (size_t)n)
        {
            rs_buf_addf(&s->err, "a temporary file: %s", strerror(errno));
            return false;
        }
    }
    return n == 0 && fflush(s->spool) == 0;
}

/* The next file's header, from the packs; false once they are all read. */
static bool next_object(struct rs_repo_stream *s)
{
    for (;;)
    {
        const struct rs_repo_member *m;
        const struct rs_entry       *e;
        size_t                       lo;
        size_t                       hi;
        int                          more;

        if (s->at < s->hi)
        {
            header(s, &s->ix->entries[s->refs[s->at++].entry], s->spool_size, SRC_SPOOL);
            s->spool_at = 0;
            return true;
        }
        if (s->spool)
        {
            (void)fclose(s->spool);
            s->spool = NULL;
        }
        if (!s->in_pack)
        {
            if (s->pack_i >= s->npacks)
            {
                return false;
            }
            (void)open_pack(s, s->packs[s->pack_i++]);
            continue;
        }
        more = rs_tar_next(&s->tr, &s->te, &s->err);
        if (more <= 0)
        {
            if (more < 0)
            {
                rs_warn("%s/packs/%s.tar.gz: %s; the files whose content is in the rest of it "
                        "are missing", s->r->dir, s->r->packs[s->packs[s->pack_i - 1]],
                        s->err.data ? s->err.data : "");
                rs_buf_reset(&s->err);
            }
            close_pack(s, more < 0);
            continue;
        }
        m = s->te.typeflag == '0' ? live_member(s, s->te.name.data) : NULL;
        if (!m || m->size != s->te.size)
        {
            continue;
        }
        refs_of(s, m->hash, &lo, &hi);
        if (lo == hi || s->sent[lo])
        {
            continue;
        }
        s->sent[lo] = true;
        e = &s->ix->entries[s->refs[lo].entry];
        if (e->size != s->te.size)
        {
            continue;   /* not what the index says: left for restore to find missing */
        }
        if (hi - lo == 1)
        {
            header(s, e, s->te.size, SRC_PACK);
            return true;
        }
        if (!spool(s))
        {
            s->failed = true;
            return false;
        }
        s->spool_size = s->te.size;
        s->at = lo;
        s->hi = hi;
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
            s->phase = PH_PACKS;
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
    if (s->phase == PH_PACKS)
    {
        if (next_object(s))
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
    case SRC_PACK:
        return rs_tar_read(&s->tr, buf, n, &s->err);
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
                    rs_buf_addstr(&s->err, "a pack ends in the middle of a file");
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
    bool ok;

    if (!s)
    {
        return true;
    }
    ok = !s->failed;
    if (s->in_pack)
    {
        close_pack(s, true);
    }
    if (s->spool)
    {
        (void)fclose(s->spool);
    }
    if (!ok && s->err.len > 0)
    {
        rs_buf_addf(err, "%s: %s", s->r->dir, s->err.data);
    }
    rs_tar_entry_free(&s->te);
    rs_buf_free(&s->out);
    rs_buf_free(&s->err);
    free(s->want);
    free(s->refs);
    free(s->sent);
    free(s->packs);
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
    const unsigned limit[3] = { keep->daily, keep->weekly, keep->monthly };
    unsigned       count[3] = { 0, 0, 0 };
    int64_t        last[3] = { -1, -1, -1 };
    unsigned       newest = 0;
    size_t         i = n;

    /* Newest first: the first of a period met is the newest in it. */
    while (i-- > 0)
    {
        unsigned y;
        unsigned m;
        unsigned d;
        int64_t  period[3];
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
        for (k = 0; k < 3; k++)
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

static uint64_t disk_size(const char *path)
{
    struct stat st;

    return lstat(path, &st) == 0 ? (uint64_t)st.st_size : 0;
}

/* Removes a pack: its .idx first, so that whatever happens after, it no
 * longer counts. */
static uint64_t remove_pack(const struct rs_repo *r, const char *name)
{
    char    *idx = rs_xasprintf("%s/packs/%s.idx", r->dir, name);
    char    *content = rs_xasprintf("%s/packs/%s.tar.gz", r->dir, name);
    uint64_t freed = disk_size(idx) + disk_size(content);

    (void)unlink(idx);
    (void)unlink(content);
    free(idx);
    free(content);
    return freed;
}

/* Copies the members of pack `name` that `keep` marks into a new pack, then
 * removes the old one -- only once every one of them is in the new. */
static bool rewrite(struct rs_repo *r, const char *name, const struct rs_repo_member *m,
                    size_t n, const bool *keep, uint64_t *freed, struct rs_buf *err)
{
    char                *path = rs_xasprintf("%s/packs/%s.tar.gz", r->dir, name);
    uint64_t             before = disk_size(path);
    struct pack_out      pk;
    struct rs_gzip       gz;
    struct rs_tar_reader tr;
    struct rs_tar_entry  te;
    char                *done = NULL;
    size_t               wanted = 0;
    size_t               copied = 0;
    size_t               i;
    int                  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    bool                 ok = fd >= 0;

    for (i = 0; i < n; i++)
    {
        wanted += keep[i] ? 1 : 0;
    }
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        free(path);
        return false;
    }
    ok = rs_gzip_decompress(fd, &gz, err);
    (void)close(fd);
    if (!ok)
    {
        free(path);
        return false;
    }
    if (!pack_open(r, &pk, err))
    {
        (void)rs_gzip_finish(&gz, true, err);
        free(path);
        return false;
    }
    rs_tar_reader_init(&tr, read_fd, &gz.fd);
    rs_tar_entry_init(&te);
    /* A pack cut short stops here, and the count below then refuses it. */
    while (ok && rs_tar_next(&tr, &te, err) == 1)
    {
        const char *p = te.name.data;
        uint64_t    num;
        char        chunk[65536];
        ssize_t     got;

        if (!number(&p, te.name.data + te.name.len, &num) || *p != '\0')
        {
            continue;
        }
        for (i = 0; i < n && m[i].member != num; i++)
        {
        }
        if (i == n || !keep[i] || m[i].size != te.size)
        {
            continue;
        }
        ok = pack_header(&pk, te.size);
        while (ok && (got = rs_tar_read(&tr, chunk, sizeof(chunk), err)) > 0)
        {
            ok = rs_tar_data(&pk.tar, chunk, (size_t)got);
        }
        ok = ok && got == 0 && rs_tar_pad(&pk.tar);
        if (ok)
        {
            pack_line(&pk, m[i].hash, te.size);
            copied++;
        }
    }
    rs_tar_entry_free(&te);
    (void)rs_gzip_finish(&gz, true, err);
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
        char *made = rs_xasprintf("%s/packs/%s.tar.gz", r->dir, done);

        (void)remove_pack(r, name);
        *freed += before > disk_size(made) ? before - disk_size(made) : 0;
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
    char                *packs = rs_xasprintf("%s/packs", r->dir);
    char                *snaps = rs_xasprintf("%s/snapshots", r->dir);
    DIR                 *d = opendir(packs);
    const struct dirent *de;

    while (d && (de = readdir(d)) != NULL)
    {
        size_t len = strlen(de->d_name);
        char  *path = rs_xasprintf("%s/%s", packs, de->d_name);

        if (de->d_name[0] == '.' && len > 4 && strcmp(de->d_name + len - 4, ".tmp") == 0)
        {
            (void)unlink(path);
        } else if (len > 7 && strcmp(de->d_name + len - 7, ".tar.gz") == 0)
        {
            char       *idx = rs_xasprintf("%s/%.*s.idx", packs, (int)(len - 7), de->d_name);
            struct stat st;

            if (lstat(idx, &st) != 0)
            {
                (void)unlink(path);
            }
            free(idx);
        }
        free(path);
    }
    if (d)
    {
        (void)closedir(d);
    }
    d = opendir(snaps);
    while (d && (de = readdir(d)) != NULL)
    {
        if (de->d_name[0] == '.' && strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
        {
            char *path = rs_xasprintf("%s/%s", snaps, de->d_name);

            (void)remove_snapshot_dir(path);
            free(path);
        }
    }
    if (d)
    {
        (void)closedir(d);
    }
    free(packs);
    free(snaps);
}

/* Every digest the snapshots `names` refer to, into `live`. */
static bool live_digests(struct rs_repo *r, char *const *names, size_t n, struct objmap *live,
                         struct rs_buf *err)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        struct rs_index ix;
        size_t          k;

        rs_index_init(&ix);
        if (!rs_repo_load_index(r, names[i], &ix, err))
        {
            rs_index_free(&ix);
            return false;
        }
        for (k = 0; k < ix.count; k++)
        {
            const struct rs_entry *e = &ix.entries[k];
            unsigned char          d[32];

            if (e->stored && e->type == 'f' && e->hash_state == RS_HASH_PRESENT &&
                unhex(e->hash, d))
            {
                (void)map_add(live, d, 0);
            }
        }
        rs_index_free(&ix);
    }
    return true;
}

bool rs_repo_prune(struct rs_repo *r, const struct rs_repo_keep *keep, bool dry_run,
                   struct rs_repo_pruned *out, struct rs_buf *err)
{
    size_t        n;
    char        **names = rs_repo_snapshots(r, &n);
    char        **left = rs_xcalloc(n + 1, sizeof(*left));
    bool         *kept = rs_xcalloc(n + 1, sizeof(*kept));
    struct objmap live;
    size_t        nleft = 0;
    size_t        i;
    bool          ok = true;

    memset(out, 0, sizeof(*out));
    memset(&live, 0, sizeof(live));
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
    for (i = 0; i < out->ndropped; i++)
    {
        char *dir = rs_xasprintf("%s/snapshots/%s", r->dir, out->dropped[i]);

        if (!remove_snapshot_dir(dir))
        {
            rs_warn("%s: %s; left as it is", dir, strerror(errno));
        }
        free(dir);
    }
    sync_dir(r->dir);
    /* Content is removed only once every snapshot left has been read: one
     * that cannot be read might be the only thing that needs some of it. */
    ok = live_digests(r, left, nleft, &live, err);
    if (ok)
    {
        list_packs(r);
        for (i = 0; i < r->npacks; i++)
        {
            struct rs_repo_member *m = NULL;
            struct rs_buf          why;
            size_t                 nm = 0;
            size_t                 k;
            bool                  *keepm;
            uint64_t               total = 0;
            uint64_t               kept_bytes = 0;
            size_t                 nkept = 0;

            rs_buf_init(&why);
            if (!pack_members(r, r->packs[i], &m, &nm, &why))
            {
                rs_warn("%s; left as it is", why.data);
                rs_buf_free(&why);
                continue;
            }
            keepm = rs_xcalloc(nm + 1, sizeof(*keepm));
            for (k = 0; k < nm; k++)
            {
                unsigned char d[32];
                struct obj   *o = m[k].live && unhex(m[k].hash, d) ? map_find(&live, d) : NULL;

                total += m[k].size;
                /* The first copy found is kept; any other is dead. */
                if (o && o->pack == 0)
                {
                    o->pack = 1;
                    keepm[k] = true;
                    kept_bytes += m[k].size;
                    nkept++;
                }
            }
            if (nkept == 0)
            {
                out->bytes_freed += remove_pack(r, r->packs[i]);
                out->packs_removed++;
            } else if ((total - kept_bytes) * 4 >= total && total > kept_bytes)
            {
                /* A quarter or more of it is dead: worth writing again. */
                if (rewrite(r, r->packs[i], m, nm, keepm, &out->bytes_freed, &why))
                {
                    out->packs_rewritten++;
                } else
                {
                    rs_warn("%s", why.data);
                }
            }
            free(keepm);
            free(m);
            rs_buf_free(&why);
        }
        clear_leftovers(r);
        list_packs(r);
        map_free(&r->objects);
        r->loaded = false;
        {
            char *packs = rs_xasprintf("%s/packs", r->dir);

            sync_dir(packs);
            free(packs);
        }
    }
    map_free(&live);
    free(left);
    free(kept);
    rs_repo_free_names(names, n);
    return ok;
}
