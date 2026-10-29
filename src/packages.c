/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "packages.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "gzip.h"
#include "index.h"
#include "run.h"
#include "sha256.h"

/* A key file is a few kilobytes; one that is not is not a key file. */
#define KEY_MAX    ((size_t)1024 * 1024)
/* snapd's state grows with its change history: a few megabytes, usually. */
#define STATE_MAX  ((size_t)64 * 1024 * 1024)
#define SMALL_MAX  ((size_t)4 * 1024 * 1024)
/* A source names every URI, suite and component pairing; a machine has tens of
 * repositories, and a file that names more than this is not apt's. */
#define REPOS_MAX  ((size_t)4096)

/* ------------------------------------------------------------------------- */
/* Files                                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Everything here is read beneath `root`, and the names come partly from the
 * tree itself: a repository's signed-by, a home directory in /etc/passwd. So
 * nothing is opened by its whole path, which would follow a symlink anywhere
 * along it -- out of a disk mounted from another machine and into this one.
 * Each directory on the way is opened from the one before with O_NOFOLLOW,
 * as the scan walks, and a symlink anywhere stops the read.
 */

/* The directory holding the last component of `rel`, opened beneath `root`,
 * or -1; `*last` points at that component, inside `*copy` (the caller's to
 * free). `rel` must be absolute and clean. */
static int open_parent(const char *root, const char *rel, char **copy, const char **last)
{
    int   fd;
    char *p;
    char *slash;

    *copy = NULL;
    *last = NULL;
    if (!rs_path_is_clean(rel) || strcmp(rel, "/") == 0)
    {
        return -1;
    }
    fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
    {
        return -1;
    }
    *copy = rs_xstrdup(rel + 1);
    p = *copy;
    while ((slash = strchr(p, '/')) != NULL)
    {
        int next;

        *slash = '\0';
        next = openat(fd, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        (void)close(fd);
        if (next < 0)
        {
            free(*copy);
            *copy = NULL;
            return -1;
        }
        fd = next;
        p = slash + 1;
    }
    *last = p;
    return fd;
}

/* root + rel, opened beneath root with `flags` (O_NOFOLLOW added), or -1. */
static int open_beneath(const char *root, const char *rel, int flags)
{
    char       *copy;
    const char *last;
    int         dir = open_parent(root, rel, &copy, &last);
    int         fd = -1;

    if (dir >= 0)
    {
        fd = openat(dir, last, flags | O_NOFOLLOW | O_CLOEXEC);
        (void)close(dir);
    }
    free(copy);
    return fd;
}

/* What root + rel is, without following a symlink; false if it is not there. */
static bool stat_beneath(const char *root, const char *rel, struct stat *st)
{
    char       *copy;
    const char *last;
    int         dir = open_parent(root, rel, &copy, &last);
    bool        ok = false;

    if (dir >= 0)
    {
        ok = fstatat(dir, last, st, AT_SYMLINK_NOFOLLOW) == 0;
        (void)close(dir);
    }
    free(copy);
    return ok;
}

/* A regular file beneath root, opened for reading, or -1. */
static int open_file(const char *root, const char *rel)
{
    int         fd = open_beneath(root, rel, O_RDONLY | O_NONBLOCK);
    struct stat st;

    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)))
    {
        (void)close(fd);
        fd = -1;
    }
    return fd;
}

bool rs_read_beneath(const char *root, const char *rel, size_t max, struct rs_buf *out)
{
    int   fd = open_file(root, rel);
    char  chunk[8192];
    bool  ok = fd >= 0;

    rs_buf_init(out);
    rs_buf_add(out, "", 0);
    while (ok)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            ok = n == 0;
            break;
        }
        if (out->len + (size_t)n > max)
        {
            ok = false;
            break;
        }
        rs_buf_add(out, chunk, (size_t)n);
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    if (!ok)
    {
        rs_buf_free(out);
    }
    return ok;
}

bool rs_read_beneath_gz(const char *root, const char *rel, size_t max, struct rs_buf *out)
{
    struct rs_gzip gz;
    struct rs_buf  err;
    char           chunk[8192];
    ssize_t        n = 0;
    int            fd = open_file(root, rel);
    bool           ok;

    rs_buf_init(out);
    rs_buf_add(out, "", 0);
    rs_buf_init(&err);
    ok = fd >= 0 && rs_gzip_decompress(fd, &gz, &err);
    if (fd >= 0)
    {
        (void)close(fd);
    }
    while (ok)
    {
        n = read(gz.fd, chunk, sizeof(chunk));
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0 || out->len + (size_t)n > max)
        {
            break;
        }
        rs_buf_add(out, chunk, (size_t)n);
    }
    /* Stopped short -- too large, or a read that failed -- gzip is told to
     * stop, and what it held is not used. */
    ok = ok && rs_gzip_finish(&gz, n != 0, &err) && n == 0;
    rs_buf_free(&err);
    if (!ok)
    {
        rs_buf_free(out);
    }
    return ok;
}

/* root + rel opened as a stream, or NULL. */
static FILE *open_stream(const char *root, const char *rel)
{
    int   fd = open_file(root, rel);
    FILE *fp = fd >= 0 ? fdopen(fd, "r") : NULL;

    if (fd >= 0 && !fp)
    {
        (void)close(fd);
    }
    return fp;
}

static bool exists(const char *root, const char *rel)
{
    struct stat st;

    return stat_beneath(root, rel, &st);
}

static bool is_dir(const char *root, const char *rel)
{
    struct stat st;

    return stat_beneath(root, rel, &st) && S_ISDIR(st.st_mode);
}

/* A symlink's target, beneath root; false if rel is not a symlink. */
static bool read_link(const char *root, const char *rel, char *buf, size_t len)
{
    char       *copy;
    const char *last;
    int         dir = open_parent(root, rel, &copy, &last);
    ssize_t     n = -1;

    if (dir >= 0)
    {
        n = readlinkat(dir, last, buf, len - 1); /* Flawfinder: ignore */
        (void)close(dir);
    }
    free(copy);
    if (n <= 0)
    {
        return false;
    }
    buf[n] = '\0';
    return true;
}

static int compare_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The entries of a directory, sorted, without "." and ".." and anything else
 * starting with a dot. */
char **rs_list_beneath(const char *root, const char *rel, size_t *count)
{
    int                  fd = open_beneath(root, rel, O_RDONLY | O_DIRECTORY);
    DIR                 *d = fd >= 0 ? fdopendir(fd) : NULL;
    const struct dirent *de;
    char               **names = NULL;
    size_t               n = 0;

    *count = 0;
    if (!d)
    {
        if (fd >= 0)
        {
            (void)close(fd);
        }
        return NULL;
    }
    while ((de = readdir(d)) != NULL)
    {
        if (de->d_name[0] == '.')
        {
            continue;
        }
        names = rs_xreallocarray(names, n + 1, sizeof(*names));
        names[n++] = rs_xstrdup(de->d_name);
    }
    (void)closedir(d);
    if (n > 1)
    {
        qsort(names, n, sizeof(*names), compare_names);
    }
    *count = n;
    return names;
}

void rs_free_names(char **names, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(names[i]);
    }
    free(names);
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s);
    size_t m = strlen(suffix);

    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static void note(struct rs_jval *out, const char *text)
{
    size_t i;

    for (i = 0; i < out->n; i++)
    {
        if (strcmp(out->keys[i], "notes") == 0)
        {
            rs_jval_set_string(rs_jarr_add(&out->items[i]), text);
            return;
        }
    }
}

/* The member `key` of `obj`, as an array, made if it is not there. */
static struct rs_jval *array_member(struct rs_jval *obj, const char *key)
{
    struct rs_jval *v;
    size_t          i;

    for (i = 0; i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    v = rs_jobj_add(obj, key);
    rs_jval_set_array(v);
    return v;
}

/* ------------------------------------------------------------------------- */
/* deb822: dpkg's status, apt's lists, .sources files                        */
/* ------------------------------------------------------------------------- */

struct field {
    char         *key;
    struct rs_buf val;
};

struct stanza {
    struct field *f;
    size_t        n;
    size_t        cap;
    bool          skipping;   /* in a field not wanted: its continuation lines too */
    bool          eof;        /* the stream is used up: read no more of it */
};

static void stanza_clear(struct stanza *s)
{
    size_t i;

    for (i = 0; i < s->n; i++)
    {
        free(s->f[i].key);
        rs_buf_free(&s->f[i].val);
    }
    s->n = 0;
    s->skipping = false;
}

static void stanza_free(struct stanza *s)
{
    stanza_clear(s);
    free(s->f);
    s->f = NULL;
    s->cap = 0;
}

static bool wanted_key(const char *const *wanted, const char *key, size_t klen)
{
    size_t i;

    if (!wanted)
    {
        return true;
    }
    for (i = 0; wanted[i]; i++)
    {
        if (strlen(wanted[i]) == klen && strncasecmp(wanted[i], key, klen) == 0)
        {
            return true;
        }
    }
    return false;
}

/*
 * The next stanza of `fp` into `s`, keeping only the fields in `wanted` (a
 * NULL-terminated list; NULL keeps every field). A continuation line is added
 * to its field after a newline, and a line of "." -- deb822's empty line --
 * as an empty one. False at the end, with nothing read.
 */
static bool stanza_next(FILE *fp, const char *const *wanted, struct stanza *s)
{
    char  *line = NULL;
    size_t cap = 0;

    stanza_clear(s);
    while (!s->eof)
    {
        const char *colon;
        ssize_t     len;

        /* A last line with no newline leaves the stream at its end: asked
         * again, getline would only fail. */
        if (feof(fp) || ferror(fp))
        {
            s->eof = true;
            break;
        }
        len = getline(&line, &cap, fp);
        if (len < 0)
        {
            s->eof = true;
            break;
        }

        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        {
            line[--len] = '\0';
        }
        if (strspn(line, " \t") == (size_t)len)
        {
            if (s->n > 0 || s->skipping)
            {
                break;
            }
            continue;
        }
        if (line[0] == '#')
        {
            continue;
        }
        if (line[0] == ' ' || line[0] == '\t')
        {
            if (!s->skipping && s->n > 0)
            {
                const char    *text = line + strspn(line, " \t");
                struct rs_buf *v = &s->f[s->n - 1].val;

                rs_buf_addc(v, '\n');
                if (strcmp(text, ".") != 0)
                {
                    rs_buf_addstr(v, text);
                }
            }
            continue;
        }
        colon = strchr(line, ':');
        if (!colon || !wanted_key(wanted, line, (size_t)(colon - line)))
        {
            s->skipping = true;
            continue;
        }
        s->skipping = false;
        if (s->n == s->cap)
        {
            s->cap = s->cap ? s->cap * 2 : 8;
            s->f = rs_xreallocarray(s->f, s->cap, sizeof(*s->f));
        }
        s->f[s->n].key = rs_xstrndup(line, (size_t)(colon - line));
        rs_buf_init(&s->f[s->n].val);
        rs_buf_addstr(&s->f[s->n].val, colon + 1 + strspn(colon + 1, " \t"));
        s->n++;
    }
    free(line);
    return s->n > 0 || s->skipping;
}

/* A field's value, or NULL; field names are not case-sensitive. */
static const char *stanza_get(const struct stanza *s, const char *key)
{
    size_t i;

    for (i = 0; i < s->n; i++)
    {
        if (strcasecmp(s->f[i].key, key) == 0)
        {
            return s->f[i].val.data ? s->f[i].val.data : "";
        }
    }
    return NULL;
}

/* Each whitespace-separated word of `text` (commas too, with `commas`) as a
 * string in `arr`. */
static void add_words(struct rs_jval *arr, const char *text, bool commas)
{
    const char *seps = commas ? " \t\n," : " \t\n";
    size_t      len = text ? strlen(text) : 0;
    size_t      i = 0;

    while (i < len)
    {
        size_t n;

        i += strspn(text + i, seps);
        n = strcspn(text + i, seps);
        if (n > 0)
        {
            char *w = rs_xstrndup(text + i, n);

            rs_jval_set_string(rs_jarr_add(arr), w);
            free(w);
        }
        i += n;
    }
}

/* ------------------------------------------------------------------------- */
/* apt: installed packages                                                    */
/* ------------------------------------------------------------------------- */

struct pkg {
    char   *name;
    char   *arch;
    char   *version;
    char   *state;     /* dpkg's: "installed", or how far it got */
    bool    manual;
    bool    hold;
    bool    listed;    /* some repository has another version of it */
    size_t *origins;   /* indexes into the origin labels */
    size_t  norigins;
    size_t *others;    /* the labels of the repositories with another version */
    size_t  nothers;
};

struct apt {
    struct pkg *pkgs;
    size_t      npkgs;
    char      **labels;   /* where a version can be had: "URI SUITE/COMPONENT" */
    size_t      nlabels;
};

static int compare_pkgs(const void *a, const void *b)
{
    const struct pkg *x = a;
    const struct pkg *y = b;
    int               c = strcmp(x->name, y->name);

    return c != 0 ? c : strcmp(x->arch, y->arch);
}

static struct pkg *find_pkg(struct apt *apt, const char *name, const char *arch)
{
    size_t lo = 0;
    size_t hi = apt->npkgs;

    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int    c = strcmp(name, apt->pkgs[mid].name);

        c = c != 0 ? c : strcmp(arch, apt->pkgs[mid].arch);
        if (c == 0)
        {
            return &apt->pkgs[mid];
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

static void free_apt(struct apt *apt)
{
    size_t i;

    for (i = 0; i < apt->npkgs; i++)
    {
        free(apt->pkgs[i].name);
        free(apt->pkgs[i].arch);
        free(apt->pkgs[i].version);
        free(apt->pkgs[i].state);
        free(apt->pkgs[i].origins);
        free(apt->pkgs[i].others);
    }
    free(apt->pkgs);
    rs_free_names(apt->labels, apt->nlabels);
}

/*
 * Every package dpkg has unpacked, from /var/lib/dpkg/status: installed ones,
 * and ones it stopped part of the way through -- which a restore has to know
 * about as much as any. Removed packages whose configuration files are all
 * that is left are not installed, and are left out.
 */
static bool read_status(const char *root, struct apt *apt)
{
    static const char *const wanted[] = { "Package", "Architecture", "Version", "Status", NULL };
    FILE                    *fp = open_stream(root, "/var/lib/dpkg/status");
    struct stanza            s;

    if (!fp)
    {
        return false;
    }
    memset(&s, 0, sizeof(s));
    while (stanza_next(fp, wanted, &s))
    {
        const char *name = stanza_get(&s, "Package");
        const char *status = stanza_get(&s, "Status");
        const char *state = status ? strrchr(status, ' ') : NULL;
        const char *arch;
        const char *version;
        struct pkg *p;

        state = state ? state + 1 : NULL;
        if (!name || !state || strcmp(state, "not-installed") == 0 ||
            strcmp(state, "config-files") == 0)
        {
            continue;
        }
        apt->pkgs = rs_xreallocarray(apt->pkgs, apt->npkgs + 1, sizeof(*apt->pkgs));
        p = &apt->pkgs[apt->npkgs++];
        memset(p, 0, sizeof(*p));
        p->name = rs_xstrdup(name);
        arch = stanza_get(&s, "Architecture");
        version = stanza_get(&s, "Version");
        p->arch = rs_xstrdup(arch ? arch : "");
        p->version = rs_xstrdup(version ? version : "");
        p->state = rs_xstrdup(state);
        p->manual = true;
        p->hold = rs_starts_with(status, "hold ");
    }
    stanza_free(&s);
    (void)fclose(fp);
    if (apt->npkgs > 1)
    {
        qsort(apt->pkgs, apt->npkgs, sizeof(*apt->pkgs), compare_pkgs);
    }
    return true;
}

/*
 * Which packages apt installed as dependencies: /var/lib/apt/extended_states
 * marks them, and everything it does not mark was asked for. apt records an
 * Architecture: all package under the machine's own architecture.
 */
static void read_auto(const char *root, struct apt *apt)
{
    static const char *const wanted[] = { "Package", "Architecture", "Auto-Installed", NULL };
    FILE                    *fp = open_stream(root, "/var/lib/apt/extended_states");
    struct stanza            s;

    if (!fp)
    {
        return;
    }
    memset(&s, 0, sizeof(s));
    while (stanza_next(fp, wanted, &s))
    {
        const char *name = stanza_get(&s, "Package");
        const char *arch = stanza_get(&s, "Architecture");
        const char *a = stanza_get(&s, "Auto-Installed");
        struct pkg *p;

        if (!name || !arch || !a || strcmp(a, "1") != 0)
        {
            continue;
        }
        p = find_pkg(apt, name, arch);
        p = p ? p : find_pkg(apt, name, "all");
        if (p)
        {
            p->manual = false;
        }
    }
    stanza_free(&s);
    (void)fclose(fp);
}

/* ------------------------------------------------------------------------- */
/* apt: repositories                                                          */
/* ------------------------------------------------------------------------- */

void rs_apt_uri_file(struct rs_buf *out, const char *uri)
{
    static const char *const special = "\\|{}[]<>\"^~_=!@#$%^&*";
    const char              *p = strstr(uri, "://");
    const char              *at;
    const char              *slash;

    p = p ? p + 3 : uri;
    /* user:password@ -- before the host's end, not anywhere in the path. */
    at = strchr(p, '@');
    slash = strchr(p, '/');
    if (at && (!slash || at < slash))
    {
        p = at + 1;
    }
    for (; *p; p++)
    {
        unsigned char c = (unsigned char)*p;

        if (c == '/')
        {
            rs_buf_addc(out, '_');
        } else if (c <= 0x20 || c >= 0x7f || strchr(special, (int)c))
        {
            rs_buf_addf(out, "%%%02x", (unsigned)c);
        } else
        {
            rs_buf_addc(out, (char)c);
        }
    }
}

/* One repository: a URI, a suite, and one of its components ("" for a flat
 * repository), and the name apt's list files for it start with. */
struct repo {
    char *label;
    char *prefix;
    bool  flat;
};

struct repos {
    struct repo *r;
    size_t       n;
    size_t       cap;
    char       **keys;    /* key files the repositories name */
    size_t       nkeys;
};

static void add_key_path(struct repos *rs, const char *path)
{
    size_t i;

    for (i = 0; i < rs->nkeys; i++)
    {
        if (strcmp(rs->keys[i], path) == 0)
        {
            return;
        }
    }
    rs->keys = rs_xreallocarray(rs->keys, rs->nkeys + 1, sizeof(*rs->keys));
    rs->keys[rs->nkeys++] = rs_xstrdup(path);
}

static void add_repo(struct repos *rs, const char *uri, const char *suite, const char *component)
{
    struct rs_buf full;
    struct rs_buf name;
    struct repo  *r;
    bool          slash = uri[0] != '\0' && uri[strlen(uri) - 1] == '/';

    rs_buf_init(&full);
    rs_buf_init(&name);
    if (rs->n == rs->cap)
    {
        rs->cap = rs->cap ? rs->cap * 2 : 16;
        rs->r = rs_xreallocarray(rs->r, rs->cap, sizeof(*rs->r));
    }
    r = &rs->r[rs->n++];
    r->flat = component[0] == '\0';
    if (r->flat)
    {
        /* A flat repository's suite is a path, and its index is right there. */
        rs_buf_addf(&full, "%s%s%s", uri, slash ? "" : "/", suite);
        r->label = rs_xasprintf("%s %s", uri, suite);
    } else
    {
        rs_buf_addf(&full, "%s%sdists/%s/%s/", uri, slash ? "" : "/", suite, component);
        r->label = rs_xasprintf("%s %s/%s", uri, suite, component);
    }
    rs_apt_uri_file(&name, full.data);
    r->prefix = rs_buf_detach(&name);
    rs_buf_free(&full);
}

/* signed-by: a key file, several, a fingerprint, or the key itself. */
static void add_signed_by(struct repos *rs, struct rs_jval *src, const char *value)
{
    const char *p = value;

    const char *armor = strstr(value, "-----BEGIN PGP PUBLIC KEY BLOCK");

    if (armor)
    {
        struct rs_buf b64;

        /* The key itself, which a check of the source's index needs: the
         * file is in /etc/apt, but an inventory is read without the image. */
        rs_jobj_str(src, "signed_by", "the key in this file");
        rs_buf_init(&b64);
        rs_base64_encode(&b64, armor, strlen(armor));
        rs_jobj_str(src, "key", b64.data ? b64.data : "");
        rs_buf_free(&b64);
        return;
    }
    rs_jobj_str(src, "signed_by", value);
    while (*p)
    {
        size_t n;

        p += strspn(p, " \t\n,");
        n = strcspn(p, " \t\n,");
        if (n > 0 && p[0] == '/')
        {
            char *path = rs_xstrndup(p, n);

            add_key_path(rs, path);
            free(path);
        }
        p += n;
    }
}

/* Records one source definition, and the repositories it names. */
static void add_source(struct repos *rs, const struct rs_jval *src, const struct rs_jval *types,
                       const struct rs_jval *uris, const struct rs_jval *suites,
                       const struct rs_jval *components)
{
    size_t t;
    size_t u;
    size_t s;
    size_t c;
    bool   binary = false;

    for (t = 0; t < types->n; t++)
    {
        binary = binary || strcmp(types->items[t].s, "deb") == 0;
    }
    if (!binary || rs_jobject_get(src, "enabled") != NULL)
    {
        return;
    }
    for (u = 0; u < uris->n && rs->n < REPOS_MAX; u++)
    {
        for (s = 0; s < suites->n && rs->n < REPOS_MAX; s++)
        {
            if (components->n == 0)
            {
                add_repo(rs, uris->items[u].s, suites->items[s].s, "");
            }
            for (c = 0; c < components->n && rs->n < REPOS_MAX; c++)
            {
                add_repo(rs, uris->items[u].s, suites->items[s].s, components->items[c].s);
            }
        }
    }
}

/* A one-line source's [options]: signed-by=, arch=, and the rest as they are. */
static void list_options(struct repos *rs, struct rs_jval *src, const char *opts)
{
    const char *o = opts;

    while (o && *o)
    {
        size_t n;

        o += strspn(o, " \t");
        n = strcspn(o, " \t");
        if (n > 0)
        {
            char *opt = rs_xstrndup(o, n);

            if (rs_starts_with(opt, "signed-by="))
            {
                add_signed_by(rs, src, opt + 10);
            } else if (rs_starts_with(opt, "arch="))
            {
                add_words(array_member(src, "architectures"), opt + 5, true);
            } else
            {
                rs_jval_set_string(rs_jarr_add(array_member(src, "options")), opt);
            }
            free(opt);
        }
        o += n;
    }
}

/* A one-line-style file: "deb [options] URI SUITE [COMPONENT...]". */
static void read_list(const char *root, const char *rel, struct repos *rs, struct rs_jval *arr)
{
    FILE  *fp = open_stream(root, rel);
    char  *line = NULL;
    size_t cap = 0;

    if (!fp)
    {
        return;
    }
    while (getline(&line, &cap, fp) >= 0)
    {
        struct rs_jval *src;
        struct rs_jval  words;
        size_t          start = strspn(line, " \t");
        char           *hash = strchr(line + start, '#');
        const char     *p = line + start;
        char           *opts = NULL;

        /* The line is edited in place -- the comment cut off, the [options]
         * taken out -- through pointers into `line`; `p` only reads it. */
        if (hash)
        {
            *hash = '\0';
        }
        if (!rs_starts_with(p, "deb ") && !rs_starts_with(p, "deb\t") &&
            !rs_starts_with(p, "deb-src"))
        {
            continue;
        }
        memset(&words, 0, sizeof(words));
        rs_jval_set_array(&words);
        {
            char *open_b = strchr(line + start, '[');
            char *close_b = open_b ? strchr(open_b, ']') : NULL;

            if (open_b && close_b)
            {
                opts = rs_xstrndup(open_b + 1, (size_t)(close_b - open_b - 1));
                memmove(open_b, close_b + 1, strlen(close_b + 1) + 1);
            }
        }
        add_words(&words, p, false);
        if (words.n < 3)
        {
            free(opts);
            rs_jval_free(&words);
            continue;
        }
        src = rs_jarr_add(arr);
        rs_jval_set_object(src);
        rs_jobj_str(src, "file", rel);
        add_words(array_member(src, "types"), words.items[0].s, false);
        add_words(array_member(src, "uris"), words.items[1].s, false);
        add_words(array_member(src, "suites"), words.items[2].s, false);
        {
            struct rs_jval *comps = array_member(src, "components");
            size_t          w;

            for (w = 3; w < words.n; w++)
            {
                rs_jval_set_string(rs_jarr_add(comps), words.items[w].s);
            }
        }
        list_options(rs, src, opts);
        /* Only now, with every member added: adding one moves the others. */
        add_source(rs, src, rs_jobject_get(src, "types"), rs_jobject_get(src, "uris"),
                   rs_jobject_get(src, "suites"), rs_jobject_get(src, "components"));
        free(opts);
        rs_jval_free(&words);
    }
    free(line);
    (void)fclose(fp);
}

/* A deb822-style file: stanzas of Types, URIs, Suites, Components. */
static void read_sources(const char *root, const char *rel, struct repos *rs, struct rs_jval *arr)
{
    FILE         *fp = open_stream(root, rel);
    struct stanza s;

    if (!fp)
    {
        return;
    }
    memset(&s, 0, sizeof(s));
    while (stanza_next(fp, NULL, &s))
    {
        struct rs_jval *src;
        const char     *v;

        if (!stanza_get(&s, "URIs") || !stanza_get(&s, "Suites"))
        {
            continue;
        }
        src = rs_jarr_add(arr);
        rs_jval_set_object(src);
        rs_jobj_str(src, "file", rel);
        add_words(array_member(src, "types"),
                  stanza_get(&s, "Types") ? stanza_get(&s, "Types") : "deb", false);
        add_words(array_member(src, "uris"), stanza_get(&s, "URIs"), false);
        add_words(array_member(src, "suites"), stanza_get(&s, "Suites"), false);
        add_words(array_member(src, "components"), stanza_get(&s, "Components"), false);
        v = stanza_get(&s, "Architectures");
        if (v)
        {
            add_words(array_member(src, "architectures"), v, false);
        }
        v = stanza_get(&s, "Signed-By");
        if (v)
        {
            add_signed_by(rs, src, v);
        }
        v = stanza_get(&s, "Enabled");
        if (v && strcasecmp(v, "no") == 0)
        {
            rs_jobj_bool(src, "enabled", false);
        }
        /* Only now, with every member added: adding one moves the others. */
        add_source(rs, src, rs_jobject_get(src, "types"), rs_jobject_get(src, "uris"),
                   rs_jobject_get(src, "suites"), rs_jobject_get(src, "components"));
    }
    stanza_free(&s);
    (void)fclose(fp);
}

/* apt's own leftovers -- and editors' -- that apt does not read either. */
static bool source_file(const char *name, const char *suffix)
{
    return ends_with(name, suffix) && name[0] != '\0';
}

static void read_all_sources(const char *root, struct repos *rs, struct rs_jval *apt)
{
    struct rs_jval *arr = array_member(apt, "sources");
    char          **names;
    size_t          n;
    size_t          i;

    read_list(root, "/etc/apt/sources.list", rs, arr);
    names = rs_list_beneath(root, "/etc/apt/sources.list.d", &n);
    for (i = 0; i < n; i++)
    {
        char *rel = rs_xasprintf("/etc/apt/sources.list.d/%s", names[i]);

        if (source_file(names[i], ".list"))
        {
            read_list(root, rel, rs, arr);
        } else if (source_file(names[i], ".sources"))
        {
            read_sources(root, rel, rs, arr);
        }
        free(rel);
    }
    rs_free_names(names, n);
}

/* ------------------------------------------------------------------------- */
/* apt: where each installed version can be had                               */
/* ------------------------------------------------------------------------- */

static size_t label_index(struct apt *apt, const char *label)
{
    size_t i;

    for (i = 0; i < apt->nlabels; i++)
    {
        if (strcmp(apt->labels[i], label) == 0)
        {
            return i;
        }
    }
    apt->labels = rs_xreallocarray(apt->labels, apt->nlabels + 1, sizeof(*apt->labels));
    apt->labels[apt->nlabels] = rs_xstrdup(label);
    return apt->nlabels++;
}

/* Which repository a list file is the index of; its own name if none is
 * configured now (apt keeps lists until the next update). */
static const char *list_label(const struct repos *rs, const char *file)
{
    size_t i;

    for (i = 0; i < rs->n; i++)
    {
        const struct repo *r = &rs->r[i];
        size_t             n = strlen(r->prefix);

        if (strncmp(file, r->prefix, n) != 0)
        {
            continue;
        }
        if (r->flat ? strcmp(file + n, "Packages") == 0 || strcmp(file + n, "_Packages") == 0
                    : rs_starts_with(file + n, "binary-"))
        {
            return r->label;
        }
    }
    return file;
}

static void add_label(size_t **list, size_t *n, size_t label)
{
    size_t i;

    for (i = 0; i < *n; i++)
    {
        if ((*list)[i] == label)
        {
            return;
        }
    }
    *list = rs_xreallocarray(*list, *n + 1, sizeof(**list));
    (*list)[(*n)++] = label;
}

static size_t read_lists(const char *root, const struct repos *rs, struct apt *apt,
                         struct rs_jval *out)
{
    static const char *const wanted[] = { "Package", "Architecture", "Version", NULL };
    char                   **names;
    size_t                   n;
    size_t                   i;
    bool                     compressed = false;
    size_t                   read = 0;
    struct stanza            s;

    memset(&s, 0, sizeof(s));
    names = rs_list_beneath(root, "/var/lib/apt/lists", &n);
    for (i = 0; i < n; i++)
    {
        char  *rel;
        FILE  *fp;
        size_t label;

        if (strstr(names[i], "_Packages."))
        {
            compressed = true;
            continue;
        }
        if (!ends_with(names[i], "Packages"))
        {
            continue;
        }
        rel = rs_xasprintf("/var/lib/apt/lists/%s", names[i]);
        fp = open_stream(root, rel);
        free(rel);
        if (!fp)
        {
            continue;
        }
        label = label_index(apt, list_label(rs, names[i]));
        read++;
        s.eof = false;
        while (stanza_next(fp, wanted, &s))
        {
            const char *name = stanza_get(&s, "Package");
            const char *arch = stanza_get(&s, "Architecture");
            const char *version = stanza_get(&s, "Version");
            struct pkg *p = name && arch ? find_pkg(apt, name, arch) : NULL;

            if (p && version && strcmp(p->version, version) == 0)
            {
                add_label(&p->origins, &p->norigins, label);
            } else if (p)
            {
                p->listed = true;
                add_label(&p->others, &p->nothers, label);
            }
        }
        (void)fclose(fp);
    }
    stanza_free(&s);
    rs_free_names(names, n);
    if (compressed)
    {
        note(out, "apt keeps its package lists compressed here, and they were not read: "
                  "where each package came from is not recorded");
    }
    return read;
}

/* ------------------------------------------------------------------------- */
/* apt: keys                                                                  */
/* ------------------------------------------------------------------------- */

/* Every key apt trusts, beside the ones the repositories name. In
 * trusted.gpg.d, only the .gpg and .asc files: apt reads nothing else there,
 * and add-apt-repository leaves an empty NAME.gpg~ beside the key it adds. */
static void trusted_keys(const char *root, struct repos *rs)
{
    static const char *const dirs[] = { "/etc/apt/trusted.gpg.d", "/etc/apt/keyrings" };
    size_t                   d;

    if (exists(root, "/etc/apt/trusted.gpg"))
    {
        add_key_path(rs, "/etc/apt/trusted.gpg");
    }
    for (d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++)
    {
        char **names;
        size_t n;
        size_t i;

        names = rs_list_beneath(root, dirs[d], &n);
        for (i = 0; i < n; i++)
        {
            char *path;

            if (d == 0 && !ends_with(names[i], ".gpg") && !ends_with(names[i], ".asc"))
            {
                continue;
            }
            path = rs_xasprintf("%s/%s", dirs[d], names[i]);
            add_key_path(rs, path);
            free(path);
        }
        rs_free_names(names, n);
    }
}

/*
 * Whether `data` is an OpenPGP public key, as apt reads one: ASCII-armored,
 * or binary starting with a public-key packet (tag 6, in the old packet
 * format or the new). A signed-by in the tree can name any file at all, and
 * only a key's content belongs in the inventory.
 */
static bool looks_like_key(const unsigned char *data, size_t len)
{
    static const char armor[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    size_t            skip = 0;
    unsigned          tag;

    while (skip < len && (data[skip] == ' ' || data[skip] == '\t' || data[skip] == '\r' ||
                          data[skip] == '\n'))
    {
        skip++;
    }
    if (len - skip >= sizeof(armor) - 1 && memcmp(data + skip, armor, sizeof(armor) - 1) == 0)
    {
        return true;
    }
    if (len == 0 || (data[0] & 0x80) == 0)
    {
        return false;
    }
    tag = (data[0] & 0x40) ? (unsigned)(data[0] & 0x3f) : (unsigned)((data[0] >> 2) & 0x0f);
    return tag == 6;
}

/* Each key file, whole: a restore puts it back before adding its repository,
 * whether or not the file was kept in the image. */
static void describe_keys(const char *root, struct repos *rs, struct rs_jval *apt,
                          struct rs_jval *out)
{
    struct rs_jval *arr = array_member(apt, "keys");
    size_t          i;

    if (rs->nkeys > 1)
    {
        qsort(rs->keys, rs->nkeys, sizeof(*rs->keys), compare_names);
    }
    for (i = 0; i < rs->nkeys; i++)
    {
        struct rs_jval *k;
        struct rs_buf   data;
        struct rs_buf   b64;
        char            hex[RS_SHA256_HEX_SIZE];

        if (!rs_path_is_clean(rs->keys[i]))
        {
            continue;
        }
        k = rs_jarr_add(arr);
        rs_jval_set_object(k);
        rs_jobj_str(k, "path", rs->keys[i]);
        if (!rs_read_beneath(root, rs->keys[i], KEY_MAX, &data))
        {
            char *why = rs_xasprintf("the key %s could not be read", rs->keys[i]);

            rs_jobj_bool(k, "missing", true);
            note(out, why);
            free(why);
            continue;
        }
        rs_sha256_hex(data.data, data.len, hex);
        rs_jobj_u64(k, "size", data.len);
        rs_jobj_str(k, "sha256", hex);
        if (!looks_like_key((const unsigned char *)data.data, data.len))
        {
            char *why = rs_xasprintf("%s is named as a repository key and is not one: its "
                                     "content is not recorded", rs->keys[i]);

            rs_jobj_bool(k, "not_a_key", true);
            note(out, why);
            free(why);
            rs_buf_free(&data);
            continue;
        }
        rs_buf_init(&b64);
        rs_base64_encode(&b64, data.data, data.len);
        rs_jobj_str(k, "data", b64.data ? b64.data : "");
        rs_buf_free(&b64);
        rs_buf_free(&data);
    }
}

/*
 * When a package was installed, as "installed": when dpkg last wrote its list
 * of files, which it does as it unpacks each version. A version the archive
 * had moved on from by the capture was in the archive then, so the archive's
 * snapshot as of that time has it (--exact-versions).
 */
static void installed_at(const char *root, const struct pkg *p, struct rs_jval *o)
{
    static const char allowed[] = "abcdefghijklmnopqrstuvwxyz0123456789+.-";
    struct stat       st;
    char             *rel;
    bool              found;

    /* Both from the tree's own status file: nothing that leaves the directory. */
    if (p->name[0] == '\0' || p->name[0] == '.' || strspn(p->name, allowed) != strlen(p->name) ||
        strspn(p->arch, allowed) != strlen(p->arch))
    {
        return;
    }
    rel = rs_xasprintf("/var/lib/dpkg/info/%s:%s.list", p->name, p->arch);
    found = stat_beneath(root, rel, &st);
    free(rel);
    if (!found)
    {
        rel = rs_xasprintf("/var/lib/dpkg/info/%s.list", p->name);
        found = stat_beneath(root, rel, &st);
        free(rel);
    }
    if (found)
    {
        struct rs_time t;
        char           buf[RS_TIME_STR_MAX];

        t.sec = (int64_t)st.st_mtime;
        t.nsec = 0;
        t.set = true;
        rs_time_format(&t, buf);
        rs_jobj_str(o, "installed", buf);
    }
}

static void describe_apt(const char *root, struct rs_jval *out)
{
    struct apt      apt;
    struct repos    rs;
    struct rs_jval *a;
    struct rs_jval *arr;
    struct rs_buf   archs;
    size_t          i;
    size_t          j;
    uint64_t        manual = 0;
    uint64_t        superseded = 0;
    uint64_t        local = 0;
    size_t          lists;

    memset(&apt, 0, sizeof(apt));
    memset(&rs, 0, sizeof(rs));
    if (!read_status(root, &apt))
    {
        return;
    }
    read_auto(root, &apt);
    a = rs_jobj_add(out, "apt");
    rs_jval_set_object(a);
    if (rs_read_beneath(root, "/var/lib/dpkg/arch", SMALL_MAX, &archs))
    {
        add_words(array_member(a, "architectures"), archs.data, false);
        rs_buf_free(&archs);
    } else
    {
        /* dpkg writes the file only once a second architecture is added:
         * until then the machine's own is dpkg's. */
        const struct pkg *d = NULL;

        for (i = 0; !d && i < apt.npkgs; i++)
        {
            d = strcmp(apt.pkgs[i].name, "dpkg") == 0 ? &apt.pkgs[i] : NULL;
        }
        if (d && d->arch[0] && strcmp(d->arch, "all") != 0)
        {
            rs_jval_set_string(rs_jarr_add(array_member(a, "architectures")), d->arch);
        }
    }
    read_all_sources(root, &rs, a);
    trusted_keys(root, &rs);
    describe_keys(root, &rs, a, out);
    lists = read_lists(root, &rs, &apt, out);

    arr = array_member(a, "packages");
    for (i = 0; i < apt.npkgs; i++)
    {
        const struct pkg *p = &apt.pkgs[i];
        struct rs_jval   *o = rs_jarr_add(arr);
        struct rs_jval   *from;

        rs_jval_set_object(o);
        rs_jobj_str(o, "name", p->name);
        rs_jobj_str(o, "architecture", p->arch);
        rs_jobj_str(o, "version", p->version);
        rs_jobj_bool(o, "manual", p->manual);
        if (p->hold)
        {
            rs_jobj_bool(o, "hold", true);
        }
        if (strcmp(p->state, "installed") != 0)
        {
            rs_jobj_str(o, "state", p->state);
        }
        from = array_member(o, "origins");
        for (j = 0; j < p->norigins; j++)
        {
            rs_jval_set_string(rs_jarr_add(from), apt.labels[p->origins[j]]);
        }
        /* The ones a restore cannot simply ask apt for, because the version
         * installed is in no repository's list: "superseded" where a
         * repository has another version of it now, "local" where none has
         * it at all -- installed from a .deb. */
        if (p->norigins == 0 && lists > 0)
        {
            rs_jobj_str(o, "unavailable", p->listed ? "superseded" : "local");
            if (p->listed)
            {
                /* Where to look for it in the archive's snapshot. */
                from = array_member(o, "superseded_in");
                for (j = 0; j < p->nothers; j++)
                {
                    rs_jval_set_string(rs_jarr_add(from), apt.labels[p->others[j]]);
                }
                installed_at(root, p, o);
            }
            superseded += p->listed ? 1 : 0;
            local += p->listed ? 0 : 1;
        }
        manual += p->manual ? 1 : 0;
    }
    rs_jobj_u64(a, "count", apt.npkgs);
    rs_jobj_u64(a, "manual", manual);
    rs_jobj_u64(a, "superseded", superseded);
    rs_jobj_u64(a, "local", local);

    for (i = 0; i < rs.n; i++)
    {
        free(rs.r[i].label);
        free(rs.r[i].prefix);
    }
    free(rs.r);
    rs_free_names(rs.keys, rs.nkeys);
    free_apt(&apt);
}

/* ------------------------------------------------------------------------- */
/* snap                                                                       */
/* ------------------------------------------------------------------------- */

/* The revision `current` in a snap's sequence: its side information. */
static const struct rs_jval *snap_revision(const struct rs_jval *seq, const char *current)
{
    size_t i;

    for (i = 0; seq && seq->type == RS_JARRAY && i < seq->n; i++)
    {
        const struct rs_jval *e = &seq->items[i];
        const struct rs_jval *side = rs_jobject_get(e, "side-info");
        const char           *rev;

        /* Newer snapd writes {"side-info": {...}, "components": [...]}. */
        e = side ? side : e;
        rev = rs_jobject_str(e, "revision");
        if (rev && current && strcmp(rev, current) == 0)
        {
            return e;
        }
    }
    return NULL;
}

static bool flag(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return v && v->type == RS_JBOOL && v->b;
}

static void snaps_from_state(const struct rs_jval *snaps, struct rs_jval *arr)
{
    size_t i;

    for (i = 0; i < snaps->n; i++)
    {
        const struct rs_jval *v = &snaps->items[i];
        const char           *current = rs_jobject_str(v, "current");
        const struct rs_jval *side = snap_revision(rs_jobject_get(v, "sequence"), current);
        const char           *id = side ? rs_jobject_str(side, "snap-id") : NULL;
        struct rs_jval       *o;
        const struct rs_jval *active = rs_jobject_get(v, "active");

        o = rs_jarr_add(arr);
        rs_jval_set_object(o);
        rs_jobj_str(o, "name", snaps->keys[i]);
        rs_jobj_str(o, "revision", current);
        rs_jobj_str(o, "channel", rs_jobject_str(v, "channel"));
        rs_jobj_str(o, "type", rs_jobject_str(v, "type"));
        if (flag(v, "classic"))
        {
            rs_jobj_bool(o, "classic", true);
        }
        if (flag(v, "devmode"))
        {
            rs_jobj_bool(o, "devmode", true);
        }
        if (active && active->type == RS_JBOOL && !active->b)
        {
            rs_jobj_bool(o, "disabled", true);
        }
        /* Installed from a file, not the store: nothing to download it from. */
        if (!id || id[0] == '\0' || (current && current[0] == 'x'))
        {
            rs_jobj_bool(o, "local", true);
        }
    }
}

/* Without snapd's state -- it is root's alone -- /snap still says which snaps
 * are installed, and at which revision; not from which channel. */
static void snaps_from_mounts(const char *root, struct rs_jval *arr)
{
    char **names;
    size_t n;
    size_t i;

    names = rs_list_beneath(root, "/snap", &n);
    for (i = 0; i < n; i++)
    {
        char           *rel = rs_xasprintf("/snap/%s/current", names[i]);
        char            target[256];
        bool            ok = read_link(root, rel, target, sizeof(target));
        struct rs_jval *o;

        free(rel);
        if (!ok)
        {
            continue;
        }
        o = rs_jarr_add(arr);
        rs_jval_set_object(o);
        rs_jobj_str(o, "name", names[i]);
        rs_jobj_str(o, "revision", target);
        if (target[0] == 'x')
        {
            rs_jobj_bool(o, "local", true);
        }
    }
    rs_free_names(names, n);
}

static void describe_snap(const char *root, struct rs_jval *out)
{
    struct rs_buf         text;
    struct rs_jval        state;
    struct rs_jval       *arr;
    const struct rs_jval *snaps = NULL;

    if (!is_dir(root, "/var/lib/snapd") && !is_dir(root, "/snap"))
    {
        return;
    }
    arr = array_member(out, "snap");
    memset(&state, 0, sizeof(state));
    if (rs_read_beneath(root, "/var/lib/snapd/state.json", STATE_MAX, &text))
    {
        struct rs_json_parser jp;
        struct rs_buf         err;

        rs_buf_init(&err);
        rs_json_init(&jp, text.data, text.len, &err);
        if (rs_json_value(&jp, &state) && rs_json_at_end(&jp))
        {
            snaps = rs_jobject_get(rs_jobject_get(&state, "data"), "snaps");
        }
        rs_buf_free(&err);
        rs_buf_free(&text);
    }
    if (snaps && snaps->type == RS_JOBJECT)
    {
        snaps_from_state(snaps, arr);
    } else
    {
        note(out, "snapd's state (/var/lib/snapd/state.json) could not be read -- it is "
                  "root's -- so the snaps' channels are not recorded");
        snaps_from_mounts(root, arr);
    }
    rs_jval_free(&state);
}

/* A package manager that is present, and where. */
static void add_manager(struct rs_jval *out, const char *name, const char *where,
                        bool inventory)
{
    struct rs_jval *arr = array_member(out, "managers");
    struct rs_jval *m = NULL;
    size_t          i;

    for (i = 0; i < arr->n; i++)
    {
        if (strcmp(rs_jobject_str(&arr->items[i], "name"), name) == 0)
        {
            m = &arr->items[i];
            break;
        }
    }
    if (!m)
    {
        m = rs_jarr_add(arr);
        rs_jval_set_object(m);
        rs_jobj_str(m, "name", name);
        rs_jobj_bool(m, "inventory", inventory);
    }
    rs_jval_set_string(rs_jarr_add(array_member(m, "where")), where);
}

/* ------------------------------------------------------------------------- */
/* Keeping what cannot be fetched                                            */
/* ------------------------------------------------------------------------- */

/* The member `key` of `obj`, writable, or NULL. */
static struct rs_jval *member(struct rs_jval *obj, const char *key)
{
    size_t i;

    for (i = 0; obj && obj->type == RS_JOBJECT && i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    return NULL;
}

/* Whether a name taken from the inventory is one file name, no more. */
static bool plain_name(const char *s)
{
    return s && s[0] != '\0' && s[0] != '.' && !strchr(s, '/');
}

/* Records `rel` as kept if it is a regular file beneath root. */
static bool keep_one(const char *root, struct rs_jval *item, const char *rel,
                     char ***paths, size_t *n)
{
    struct stat st;

    if (!stat_beneath(root, rel, &st) || !S_ISREG(st.st_mode))
    {
        return false;
    }
    rs_jobj_str(item, "kept", rel);
    *paths = rs_xreallocarray(*paths, *n + 1, sizeof(**paths));
    (*paths)[(*n)++] = rs_xstrdup(rel);
    return true;
}

/* Whether root + rel is a .deb: an ar archive whose first member is
 * debian-binary. */
static bool is_deb(const char *root, const char *rel)
{
    static const char magic[] = "!<arch>\ndebian-binary";
    int               fd = open_file(root, rel);
    bool              ok = false;

    if (fd >= 0)
    {
        char head[sizeof(magic) - 1];

        ok = read(fd, head, sizeof(head)) == (ssize_t)sizeof(head) &&
             memcmp(head, magic, sizeof(head)) == 0;
        (void)close(fd);
    }
    return ok;
}

/* The --deb files: each NAME=PATH, checked, and kept for NAME. */
static void keep_named(const char *root, struct rs_jval *pkgs, const char *const *debs,
                       size_t ndebs, char ***paths, size_t *n, struct rs_buf *missing)
{
    size_t d;

    for (d = 0; d < ndebs; d++)
    {
        const char     *eq = strchr(debs[d], '=');
        char           *name = eq ? rs_xstrndup(debs[d], (size_t)(eq - debs[d])) : NULL;
        const char     *path = eq ? eq + 1 : NULL;
        struct rs_jval *p = NULL;
        size_t          i;

        for (i = 0; name && pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
        {
            const char *pn = rs_jobject_str(&pkgs->items[i], "name");

            if (pn && strcmp(pn, name) == 0)
            {
                p = &pkgs->items[i];
                break;
            }
        }
        if (!name || !path || !rs_path_is_clean(path))
        {
            rs_buf_addf(missing, "--deb %s: give it as NAME=PATH, PATH absolute\n", debs[d]);
        } else if (!p)
        {
            rs_buf_addf(missing, "--deb %s: no package %s is installed\n", debs[d], name);
        } else if (!rs_jobject_str(p, "unavailable"))
        {
            rs_buf_addf(missing, "--deb %s: a repository has %s's installed version, so it "
                        "is installed from there; not kept\n", debs[d], name);
        } else if (!is_deb(root, path))
        {
            rs_buf_addf(missing, "--deb %s: %s is not a .deb file\n", debs[d], path);
        } else
        {
            (void)keep_one(root, p, path, paths, n);
        }
        free(name);
    }
}

char **rs_packages_kept(const struct rs_jval *packages, size_t *n)
{
    const struct rs_jval *lists[2];
    char                **paths = NULL;
    size_t                l;
    size_t                i;

    lists[0] = rs_jobject_get(rs_jobject_get(packages, "apt"), "packages");
    lists[1] = rs_jobject_get(packages, "snap");
    *n = 0;
    for (l = 0; l < 2; l++)
    {
        for (i = 0; lists[l] && lists[l]->type == RS_JARRAY && i < lists[l]->n; i++)
        {
            const char *kept = rs_jobject_str(&lists[l]->items[i], "kept");

            if (kept && rs_path_is_clean(kept))
            {
                paths = rs_xreallocarray(paths, *n + 1, sizeof(*paths));
                paths[(*n)++] = rs_xstrdup(kept);
            }
        }
    }
    return paths;
}

char **rs_packages_keep(const char *root, struct rs_jval *packages, const char *const *debs,
                        size_t ndebs, size_t *n, struct rs_buf *missing)
{
    struct rs_jval *pkgs = member(member(packages, "apt"), "packages");
    struct rs_jval *snaps = member(packages, "snap");
    char          **paths = NULL;
    size_t          i;

    *n = 0;
    keep_named(root, pkgs, debs, ndebs, &paths, n, missing);
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        struct rs_jval *p = &pkgs->items[i];
        const char     *name = rs_jobject_str(p, "name");
        const char     *version = rs_jobject_str(p, "version");
        const char     *arch = rs_jobject_str(p, "architecture");
        struct rs_buf   rel;
        const char     *c;
        char           *bare;

        if (!rs_jobject_str(p, "unavailable") || rs_jobject_str(p, "kept") ||
            !plain_name(name) || !plain_name(version) || !plain_name(arch))
        {
            continue;
        }
        /* apt's own name for it: NAME_VERSION_ARCH.deb, an epoch's colon
         * written %3a -- or, as dpkg-repack names what it rebuilds, with no
         * epoch at all. */
        rs_buf_init(&rel);
        rs_buf_addf(&rel, "/var/cache/apt/archives/%s_", name);
        for (c = version; *c; c++)
        {
            if (*c == ':')
            {
                rs_buf_addstr(&rel, "%3a");
            } else
            {
                rs_buf_addc(&rel, *c);
            }
        }
        rs_buf_addf(&rel, "_%s.deb", arch);
        bare = rs_xasprintf("/var/cache/apt/archives/%s_%s_%s.deb", name,
                            strchr(version, ':') ? strchr(version, ':') + 1 : version, arch);
        if (!keep_one(root, p, rel.data, &paths, n) && !keep_one(root, p, bare, &paths, n) &&
            strcmp(rs_jobject_str(p, "unavailable"), "local") == 0)
        {
            rs_jobj_str(p, "not_kept", "not in apt's cache");
            rs_buf_addf(missing, "%s %s is not in /var/cache/apt/archives, so it cannot be "
                        "kept; `cd /var/cache/apt/archives && dpkg-repack %s` rebuilds it "
                        "there from the installed files, or --deb %s=FILE names its .deb\n",
                        name, version, name, name);
        }
        free(bare);
        rs_buf_free(&rel);
    }
    for (i = 0; snaps && snaps->type == RS_JARRAY && i < snaps->n; i++)
    {
        struct rs_jval *sn = &snaps->items[i];
        const char     *name = rs_jobject_str(sn, "name");
        const char     *rev = rs_jobject_str(sn, "revision");
        char           *rel;

        if (!flag(sn, "local") || !plain_name(name) || !plain_name(rev))
        {
            continue;
        }
        rel = rs_xasprintf("/var/lib/snapd/snaps/%s_%s.snap", name, rev);
        if (!keep_one(root, sn, rel, &paths, n))
        {
            rs_jobj_str(sn, "not_kept", "not in snapd's cache");
            rs_buf_addf(missing, "the snap %s (revision %s) is not in /var/lib/snapd/snaps, so "
                        "it cannot be kept\n", name, rev);
        }
        free(rel);
    }
    return paths;
}

/* ------------------------------------------------------------------------- */
/* Alternatives                                                              */
/* ------------------------------------------------------------------------- */

/*
 * The alternatives someone chose by hand: the ones dpkg's (or Fedora's)
 * alternatives database marks "manual", and what each points at. The rest are
 * automatic -- the highest priority wins -- and come back by themselves once
 * the packages providing them are installed.
 */
static void describe_alternatives(const char *root, struct rs_jval *out)
{
    static const char *const dbs[] = { "/var/lib/dpkg/alternatives", "/var/lib/alternatives" };
    size_t                   d;

    for (d = 0; d < sizeof(dbs) / sizeof(dbs[0]); d++)
    {
        char **names;
        size_t n;
        size_t i;

        names = rs_list_beneath(root, dbs[d], &n);
        for (i = 0; i < n; i++)
        {
            char         *rel = rs_xasprintf("%s/%s", dbs[d], names[i]);
            struct rs_buf text;
            char          target[1024];

            if (!rs_read_beneath(root, rel, SMALL_MAX, &text))
            {
                free(rel);
                continue;
            }
            free(rel);
            rel = rs_xasprintf("/etc/alternatives/%s", names[i]);
            if (rs_starts_with(text.data, "manual\n") &&
                read_link(root, rel, target, sizeof(target)))
            {
                struct rs_jval *o = rs_jarr_add(array_member(out, "alternatives"));

                rs_jval_set_object(o);
                rs_jobj_str(o, "name", names[i]);
                rs_jobj_str(o, "path", target);
            }
            free(rel);
            rs_buf_free(&text);
        }
        rs_free_names(names, n);
    }
}

/* ------------------------------------------------------------------------- */
/* Installing again                                                          */
/* ------------------------------------------------------------------------- */

static bool named_in(const struct rs_jval *arr, const char *name)
{
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        if (arr->items[i].type == RS_JSTRING && strcmp(arr->items[i].s, name) == 0)
        {
            return true;
        }
    }
    return false;
}

/*
 * The boot loader and the kernel are the installer's to choose: they follow
 * the firmware (grub-pc for BIOS conflicts with grub-efi-amd64 for UEFI) and
 * the hardware, and asking for the old ones by name onto a different machine
 * -- a VM, say -- can remove the boot loader the installer just set up.
 */
bool rs_packages_installers_choice(const char *name)
{
    static const char *const prefixes[] = { "grub-", "grub2-", "shim", "linux-image-",
                                            "linux-headers-", "linux-modules-", "linux-generic",
                                            "linux-signed-", "linux-virtual", "linux-oem-" };
    size_t                   i;

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
    {
        if (rs_starts_with(name, prefixes[i]))
        {
            return true;
        }
    }
    return false;
}

/* The snapshot ID as of when a superseded package was installed, or NULL. */
static char *dated(const struct rs_jval *p)
{
    const char *why = rs_jobject_str(p, "unavailable");
    const char *when = rs_jobject_str(p, "installed");

    struct rs_time t;
    struct tm      tm;
    time_t         sec;
    char           buf[RS_TIME_STR_MAX];

    if (!why || !when || strcmp(why, "superseded") != 0 || !rs_time_parse(when, &t))
    {
        return NULL;
    }
    sec = (time_t)t.sec;
    if (!gmtime_r(&sec, &tm) || strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm) == 0)
    {
        return NULL;
    }
    return rs_xstrdup(buf);
}

static char **apt_words(const struct rs_jval *packages, const struct rs_jval *skip, bool pinned,
                        bool leave_dated, size_t *n)
{
    const struct rs_jval *apt = rs_jobject_get(packages, "apt");
    const struct rs_jval *pkgs = rs_jobject_get(apt, "packages");
    const struct rs_jval *archs = rs_jobject_get(apt, "architectures");
    const char           *native = archs && archs->type == RS_JARRAY && archs->n > 0 &&
                                   archs->items[0].type == RS_JSTRING ? archs->items[0].s : NULL;
    char                **words = NULL;
    size_t                i;

    *n = 0;
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        const char           *name = rs_jobject_str(p, "name");
        const char           *arch = rs_jobject_str(p, "architecture");
        const char           *version = rs_jobject_str(p, "version");
        const char           *why = rs_jobject_str(p, "unavailable");
        bool                  foreign = arch && native && strcmp(arch, "all") != 0 &&
                                        strcmp(arch, native) != 0;

        if (!name || !flag(p, "manual") || (why && strcmp(why, "local") == 0) ||
            named_in(skip, name) || rs_packages_installers_choice(name))
        {
            continue;
        }
        if (leave_dated)
        {
            char *id = dated(p);
            bool  later = id != NULL;

            free(id);
            if (later)
            {
                continue;
            }
        }
        words = rs_xreallocarray(words, *n + 1, sizeof(*words));
        if (pinned && !why && version)
        {
            words[(*n)++] = rs_xasprintf("%s%s%s=%s", name, foreign ? ":" : "",
                                         foreign ? arch : "", version);
        } else
        {
            words[(*n)++] = rs_xasprintf("%s%s%s", name, foreign ? ":" : "", foreign ? arch : "");
        }
    }
    return words;
}

char **rs_packages_apt_words(const struct rs_jval *packages, const struct rs_jval *skip,
                             bool pinned, size_t *n)
{
    return apt_words(packages, skip, pinned, false, n);
}

/* Whether `word` (NAME[:ARCH][=VERSION]) is made only of what Debian allows
 * in package names, architectures and versions. */
static bool debian_word(const char *word)
{
    const char *eq = strchr(word, '=');
    size_t      name = eq ? (size_t)(eq - word) : strlen(word);
    size_t      i;

    if (name == 0 || !((word[0] >= 'a' && word[0] <= 'z') || (word[0] >= '0' && word[0] <= '9')))
    {
        return false;
    }
    for (i = 0; i < name; i++)
    {
        if (!strchr("abcdefghijklmnopqrstuvwxyz0123456789+.-:", word[i]))
        {
            return false;
        }
    }
    return !eq || (eq[1] != '\0' &&
                   strspn(eq + 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                  "0123456789.+~:-") == strlen(eq + 1));
}

/* Whether `id` is a snapshot ID as apt takes one: "20261011T030000Z". */
static bool snapshot_id(const char *id)
{
    size_t i;

    if (!id || strlen(id) != 16 || id[8] != 'T' || id[15] != 'Z')
    {
        return false;
    }
    for (i = 0; i < 15; i++)
    {
        if (i != 8 && (id[i] < '0' || id[i] > '9'))
        {
            return false;
        }
    }
    return true;
}

/* How the script decides on one package, `$want`: as recorded, or by name
 * at the version there is now -- or, with a snapshot, later from it -- or
 * not at all, into `$fail`'s list. `extra` goes before it in the simulated
 * install. */
static void decide(struct rs_buf *out, const char *indent, const char *extra, const char *fail,
                   bool snapshot)
{
    rs_buf_addf(out, "%s  name=${want%%%%=*}\n", indent);
    rs_buf_addf(out, "%s  if installed_newer \"$want\"; then\n", indent);
    rs_buf_addf(out, "%s    ok=\"$ok $name\"\n", indent);
    rs_buf_addf(out, "%s    kept=\"$kept $name\"\n", indent);
    rs_buf_addf(out, "%s  elif apt-get -s install %s\"$want\" > /dev/null 2>&1; then\n", indent,
                extra);
    rs_buf_addf(out, "%s    ok=\"$ok $want\"\n", indent);
    rs_buf_addf(out, "%s  elif apt-get -s install %s\"$name\" > /dev/null 2>&1; then\n", indent,
                extra);
    if (snapshot)
    {
        rs_buf_addf(out, "%s    older=\"$older $want\"\n", indent);
    } else
    {
        rs_buf_addf(out, "%s    ok=\"$ok $name\"\n", indent);
        rs_buf_addf(out, "%s    newer=\"$newer $name\"\n", indent);
    }
    rs_buf_addf(out, "%s  else\n", indent);
    rs_buf_addf(out, "%s    %s=\"$%s %s\"\n", indent, fail, fail,
                strcmp(fail, "gone") == 0 ? "$name" : "$want");
    rs_buf_addf(out, "%s  fi\n", indent);
}

static int compare_strings(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/*
 * The versions that had left the archive before the capture, each from the
 * archive's snapshot as of when it was installed ("ID WORD" lines, sorted, so
 * each snapshot's lists are fetched once); any that cannot be had there, at
 * the version there is now.
 */
static void dated_block(const struct rs_jval *packages, const struct rs_jval *skip,
                        struct rs_buf *out)
{
    const struct rs_jval *apt = rs_jobject_get(packages, "apt");
    const struct rs_jval *pkgs = rs_jobject_get(apt, "packages");
    const struct rs_jval *archs = rs_jobject_get(apt, "architectures");
    const char           *native = archs && archs->type == RS_JARRAY && archs->n > 0 &&
                                   archs->items[0].type == RS_JSTRING ? archs->items[0].s : NULL;
    char                **lines = NULL;
    size_t                n = 0;
    size_t                i;

    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        const char           *name = rs_jobject_str(p, "name");
        const char           *arch = rs_jobject_str(p, "architecture");
        const char           *version = rs_jobject_str(p, "version");
        bool                  foreign = arch && native && strcmp(arch, "all") != 0 &&
                                        strcmp(arch, native) != 0;
        char                 *id;
        char                 *word;

        if (!name || !version || !flag(p, "manual") || named_in(skip, name) ||
            rs_packages_installers_choice(name))
        {
            continue;
        }
        id = dated(p);
        if (!id)
        {
            continue;
        }
        word = rs_xasprintf("%s%s%s=%s", name, foreign ? ":" : "", foreign ? arch : "", version);
        if (debian_word(word))
        {
            lines = rs_xreallocarray(lines, n + 1, sizeof(*lines));
            lines[n++] = rs_xasprintf("%s %s", id, word);
        }
        free(word);
        free(id);
    }
    if (n == 0)
    {
        free(lines);
        return;
    }
    qsort(lines, n, sizeof(*lines), compare_strings);
    rs_buf_addstr(out,
                  "# The versions the archive had moved on from before the capture, each\n"
                  "# from its snapshot as of when it was installed; any it does not have,\n"
                  "# at the version there is now.\n"
                  "last=''\n"
                  "usable=''\n"
                  "later=''\n"
                  "while read -r id want; do\n"
                  "  if [ \"$id\" != \"$last\" ]; then\n"
                  "    last=$id\n"
                  "    usable=''\n"
                  "    if apt-get update --snapshot \"$id\" < /dev/null > /dev/null 2>&1; then\n"
                  "      usable=yes\n"
                  "    fi\n"
                  "  fi\n"
                  "  name=${want%%=*}\n"
                  "  if [ -n \"$usable\" ] && apt-get install -y --allow-downgrades "
                  "--snapshot \"$id\" "
                  "\"$want\" < /dev/null; then\n"
                  "    echo \"restate: $want, from the archive's snapshot as of $id\" >&2\n"
                  "    ok=\"$ok $want\"\n"
                  "  else\n"
                  "    later=\"$later $name\"\n"
                  "  fi\n"
                  "done <<'DATED'\n");
    for (i = 0; i < n; i++)
    {
        rs_buf_addf(out, "%s\n", lines[i]);
        free(lines[i]);
    }
    free(lines);
    rs_buf_addstr(out,
                  "DATED\n"
                  "apt-get update > /dev/null 2>&1 || true\n"
                  "# shellcheck disable=SC2086\n"
                  "if [ -n \"$later\" ] && ! apt-get install -y $later; then\n"
                  "  for p in $later; do\n"
                  "    apt-get install -y \"$p\" || true\n"
                  "  done\n"
                  "fi\n"
                  "ok=\"$ok $later\"\n"
                  "newer=\"$newer $later\"\n");
}

void rs_packages_apt_script(const struct rs_jval *packages, const struct rs_jval *skip,
                            const char *snapshot, struct rs_buf *out)
{
    size_t n;
    size_t i;
    size_t left_out = 0;
    bool   snap = snapshot_id(snapshot);
    char **words = apt_words(packages, skip, true, snap, &n);

    rs_buf_addstr(out,
                  "#!/bin/sh\n"
                  "# Written by restate: the packages installed by hand, put back as nearly\n"
                  "# as the repositories allow. Each is looked up first, so that one that\n"
                  "# cannot be had does not stop the others.\n"
                  "set -f\n"
                  "export DEBIAN_FRONTEND=noninteractive\n"
                  "ok=''\n"
                  "newer=''\n"
                  "gone=''\n"
                  "retry=''\n"
                  "kept=''\n"
                  "wanted=''\n"
                  "# Installed already at a newer version than the one recorded -- a\n"
                  "# security update since the capture, or the installer's own: left at\n"
                  "# it. Taking it back would have apt take back, or remove, everything\n"
                  "# that needs the newer one.\n"
                  "installed_newer() {\n"
                  "  case $1 in *=*) ;; *) return 1 ;; esac\n"
                  "  have=$(dpkg-query -W -f='${db:Status-Status} ${Version}' \"${1%%=*}\" "
                  "2> /dev/null) || return 1\n"
                  "  case $have in installed\\ ?*) ;; *) return 1 ;; esac\n"
                  "  dpkg --compare-versions \"${have#installed }\" gt \"${1#*=}\" 2> /dev/null\n"
                  "}\n");
    if (snap)
    {
        rs_buf_addf(out,
                    "# A version the archive has moved on from comes from its snapshot as of\n"
                    "# the capture, where apt can reach one (--exact-versions).\n"
                    "snap='%s'\n"
                    "older=''\n", snapshot);
    }
    rs_buf_addstr(out,
                  "# A simulated install, not apt-cache show, which finds a package by name\n"
                  "# whatever version is asked for: this checks the version, and that what\n"
                  "# it needs can be had too.\n"
                  "while read -r want; do\n"
                  "  wanted=\"$wanted $want\"\n");
    decide(out, "", "", "retry", snap);
    rs_buf_addstr(out, "done <<'PACKAGES'\n");
    for (i = 0; i < n; i++)
    {
        if (debian_word(words[i]))
        {
            rs_buf_addf(out, "%s\n", words[i]);
        } else
        {
            left_out++;
        }
        free(words[i]);
    }
    free(words);
    rs_buf_addstr(out,
                  "PACKAGES\n"
                  "# Alone, a package can look uninstallable when it needs a version of\n"
                  "# another that only the list asks for: npm needs Ubuntu's nodejs, which\n"
                  "# an apt pin on NodeSource's would otherwise pick, and NodeSource's\n"
                  "# conflicts with npm. So each that failed is tried again with the rest.\n"
                  "# shellcheck disable=SC2086\n"
                  "for want in $retry; do\n");
    decide(out, "", "$ok ", "gone", snap);
    rs_buf_addstr(out,
                  "done\n"
                  "if [ -n \"$gone\" ]; then\n"
                  "  echo \"restate: apt cannot install these (no repository has them, or "
                  "what\" \\\n"
                  "       \"they need):$gone\" >&2\n"
                  "fi\n"
                  "if [ -n \"$kept\" ]; then\n"
                  "  echo \"restate: installed already at a newer version than the one\" \\\n"
                  "       \"recorded, so left at it:$kept\" >&2\n"
                  "fi\n"
                  "# Together if apt will; one at a time if it will not.\n"
                  "# shellcheck disable=SC2086\n"
                  "if [ -n \"$ok\" ] && ! apt-get install -y $ok; then\n"
                  "  for p in $ok; do\n"
                  "    apt-get install -y \"$p\" || true\n"
                  "  done\n"
                  "fi\n");
    if (snap)
    {
        rs_buf_addstr(out,
                      "# The versions the archive has moved on from, from its snapshot; any\n"
                      "# it does not have, at the version there is now. Then the archive's\n"
                      "# lists as they are now again, for whatever runs next.\n"
                      "if [ -n \"$older\" ]; then\n"
                      "  exact=''\n"
                      "  if apt-get update --snapshot \"$snap\" > /dev/null 2>&1; then\n"
                      "    for want in $older; do\n"
                      "      if apt-get -s install --snapshot \"$snap\" \"$want\" > /dev/null "
                      "2>&1; "
                      "then\n"
                      "        exact=\"$exact $want\"\n"
                      "      else\n"
                      "        newer=\"$newer ${want%%=*}\"\n"
                      "      fi\n"
                      "    done\n"
                      "  else\n"
                      "    echo \"restate: apt could not use the archive's snapshot as of "
                      "$snap;\" \\\n"
                      "         \"the versions there are now instead\" >&2\n"
                      "    for want in $older; do\n"
                      "      newer=\"$newer ${want%%=*}\"\n"
                      "    done\n"
                      "  fi\n"
                      "  if [ -n \"$exact\" ]; then\n"
                      "    echo \"restate: from the archive's snapshot as of $snap, at the "
                      "versions\" "
                      "\\\n"
                      "         \"recorded:$exact\" >&2\n"
                      "    # shellcheck disable=SC2086\n"
                      "    if ! apt-get install -y --allow-downgrades --snapshot \"$snap\" $exact; "
                      "then\n"
                      "      for p in $exact; do\n"
                      "        apt-get install -y --allow-downgrades --snapshot \"$snap\" "
                      "\"$p\" || "
                      "true\n"
                      "      done\n"
                      "    fi\n"
                      "  fi\n"
                      "  apt-get update > /dev/null 2>&1 || true\n"
                      "  later=\"$newer\"\n"
                      "  # shellcheck disable=SC2086\n"
                      "  if [ -n \"$later\" ] && ! apt-get install -y $later; then\n"
                      "    for p in $later; do\n"
                      "      apt-get install -y \"$p\" || true\n"
                      "    done\n"
                      "  fi\n"
                      "  ok=\"$ok $exact $later\"\n"
                      "fi\n");
        dated_block(packages, skip, out);
    }
    rs_buf_addstr(out,
                  "if [ -n \"$newer\" ]; then\n"
                  "  echo \"restate: the version recorded has gone; the current one "
                  "instead:$newer\" >&2\n"
                  "fi\n"
                  "# What dpkg says is installed, not what apt-get exited with: one package\n"
                  "# that will not configure makes every later apt-get fail, whatever it did.\n"
                  "missing=''\n"
                  "for p in $ok; do\n"
                  "  name=${p%%=*}\n"
                  "  if [ \"$(dpkg-query -W -f='${db:Status-Status}' \"$name\" 2> /dev/null)\" "
                  "!= installed ]; then\n"
                  "    missing=\"$missing $name\"\n"
                  "  fi\n"
                  "done\n"
                  "if [ -n \"$missing\" ]; then\n"
                  "  echo \"restate: these did not install:$missing\" >&2\n"
                  "fi\n");
    if (left_out > 0)
    {
        rs_buf_addf(out, "echo \"restate: %zu packages were left out: their names or versions "
                    "are not ones Debian allows\" >&2\n", left_out);
    }
}

/* ------------------------------------------------------------------------- */
/* Homes                                                                      */
/* ------------------------------------------------------------------------- */

/* The home directories of root and of the people who log in, from the tree's
 * own /etc/passwd: where per-user installations are. */
static char **homes(const char *root, size_t *count)
{
    struct rs_buf text;
    char        **out = NULL;
    size_t        n = 0;
    const char   *p;

    *count = 0;
    if (!rs_read_beneath(root, "/etc/passwd", SMALL_MAX, &text))
    {
        return NULL;
    }
    for (p = text.data; p && *p; )
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);
        char       *line = rs_xstrndup(p, len);
        char       *f[7];
        char       *q = line;
        size_t      k;

        for (k = 0; k < 7 && q; k++)
        {
            f[k] = q;
            q = strchr(q, ':');
            if (q)
            {
                *q++ = '\0';
            }
        }
        if (k == 7)
        {
            char         *end = NULL;
            unsigned long uid = strtoul(f[2], &end, 10);
            size_t        j;
            bool          dup = false;

            for (j = 0; j < n; j++)
            {
                dup = dup || strcmp(out[j], f[5]) == 0;
            }
            if (end && *end == '\0' && (uid == 0 || (uid >= 1000 && uid < 60000)) &&
                strcmp(f[5], "/") != 0 && rs_path_is_clean(f[5]) && !dup)
            {
                out = rs_xreallocarray(out, n + 1, sizeof(*out));
                out[n++] = rs_xstrdup(f[5]);
            }
        }
        free(line);
        p = nl ? nl + 1 : NULL;
    }
    rs_buf_free(&text);
    if (n > 1)
    {
        qsort(out, n, sizeof(*out), compare_names);
    }
    *count = n;
    return out;
}

/* ------------------------------------------------------------------------- */
/* flatpak                                                                    */
/* ------------------------------------------------------------------------- */

/* The remotes in a flatpak repository's config: [remote "NAME"] url=URL. */
static void flatpak_remotes(const char *root, const char *dir, const char *scope,
                            struct rs_jval *arr, char ***names, size_t *count)
{
    char           *rel = rs_xasprintf("%s/repo/config", dir);
    struct rs_buf   text;
    const char     *p;
    struct rs_jval *cur = NULL;

    if (!rs_read_beneath(root, rel, SMALL_MAX, &text))
    {
        free(rel);
        return;
    }
    free(rel);
    for (p = text.data; p && *p; )
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);
        char       *line = rs_xstrndup(p, len);

        if (rs_starts_with(line, "[remote \"") && strchr(line + 9, '"'))
        {
            char *name = rs_xstrndup(line + 9, strcspn(line + 9, "\""));

            cur = rs_jarr_add(arr);
            rs_jval_set_object(cur);
            rs_jobj_str(cur, "name", name);
            rs_jobj_str(cur, "scope", scope);
            *names = rs_xreallocarray(*names, *count + 1, sizeof(**names));
            (*names)[(*count)++] = name;
        } else if (line[0] == '[')
        {
            cur = NULL;
        } else if (cur && rs_starts_with(line, "url="))
        {
            rs_jobj_str(cur, "url", line + 4);
        }
        free(line);
        p = nl ? nl + 1 : NULL;
    }
    rs_buf_free(&text);
}

/* The apps in one flatpak installation: app/ID/ARCH/BRANCH, deployed. */
static void flatpak_dir(const char *root, const char *dir, const char *scope, struct rs_jval *fp)
{
    char  *rel = rs_xasprintf("%s/app", dir);
    char **remotes = NULL;
    size_t nremotes = 0;
    char **ids;
    size_t nids;
    size_t i;

    flatpak_remotes(root, dir, scope, array_member(fp, "remotes"), &remotes, &nremotes);
    ids = rs_list_beneath(root, rel, &nids);
    free(rel);
    for (i = 0; i < nids; i++)
    {
        char **archs;
        size_t narchs;
        size_t a;

        rel = rs_xasprintf("%s/app/%s", dir, ids[i]);
        archs = rs_list_beneath(root, rel, &narchs);
        free(rel);
        for (a = 0; a < narchs; a++)
        {
            char **branches;
            size_t nbranches;
            size_t b;

            rel = rs_xasprintf("%s/app/%s/%s", dir, ids[i], archs[a]);
            branches = rs_list_beneath(root, rel, &nbranches);
            free(rel);
            for (b = 0; b < nbranches; b++)
            {
                struct rs_jval *o;
                size_t          r;

                rel = rs_xasprintf("%s/app/%s/%s/%s/active", dir, ids[i], archs[a],
                                   branches[b]);
                if (!exists(root, rel))
                {
                    free(rel);
                    continue;
                }
                free(rel);
                o = rs_jarr_add(array_member(fp, "apps"));
                rs_jval_set_object(o);
                rs_jobj_str(o, "id", ids[i]);
                rs_jobj_str(o, "architecture", archs[a]);
                rs_jobj_str(o, "branch", branches[b]);
                rs_jobj_str(o, "scope", scope);
                for (r = 0; r < nremotes; r++)
                {
                    rel = rs_xasprintf("%s/repo/refs/remotes/%s/app/%s/%s/%s", dir, remotes[r],
                                       ids[i], archs[a], branches[b]);
                    if (exists(root, rel))
                    {
                        rs_jobj_str(o, "remote", remotes[r]);
                        free(rel);
                        break;
                    }
                    free(rel);
                }
            }
            rs_free_names(branches, nbranches);
        }
        rs_free_names(archs, narchs);
    }
    rs_free_names(ids, nids);
    rs_free_names(remotes, nremotes);
}

static void describe_flatpak(const char *root, char **home, size_t nhome, struct rs_jval *out)
{
    struct rs_jval *fp = NULL;
    size_t          i;

    for (i = 0; i <= nhome; i++)
    {
        char *dir = i == 0 ? rs_xstrdup("/var/lib/flatpak")
                           : rs_xasprintf("%s/.local/share/flatpak", home[i - 1]);
        char *scope = i == 0 ? rs_xstrdup("system") : rs_xasprintf("user %s", home[i - 1]);

        if (is_dir(root, dir))
        {
            if (!fp)
            {
                fp = rs_jobj_add(out, "flatpak");
                rs_jval_set_object(fp);
                (void)array_member(fp, "remotes");
                (void)array_member(fp, "apps");
            }
            flatpak_dir(root, dir, scope, fp);
            add_manager(out, "flatpak", dir, true);
        }
        free(dir);
        free(scope);
    }
}

/* ------------------------------------------------------------------------- */
/* Language package managers                                                  */
/* ------------------------------------------------------------------------- */

/* An item added to `arr`, returned to add more to: good only until the next
 * is added. */
static struct rs_jval *add_item(struct rs_jval *arr, const char *name, const char *version,
                                const char *where)
{
    struct rs_jval *o = rs_jarr_add(arr);

    rs_jval_set_object(o);
    rs_jobj_str(o, "name", name);
    if (version)
    {
        rs_jobj_str(o, "version", version);
    }
    rs_jobj_str(o, "where", where);
    return o;
}

/*
 * Python packages installed into `rel` (a site-packages or dist-packages
 * directory): each NAME-VERSION.dist-info or .egg-info. A wheel's name has no
 * hyphen in it -- it is written as an underscore -- so the first one ends it.
 */
static bool pip_dir(const char *root, const char *rel, struct rs_jval *out)
{
    char **names;
    size_t n;
    size_t i;
    bool   any = false;

    names = rs_list_beneath(root, rel, &n);
    for (i = 0; i < n; i++)
    {
        const char *dash = strchr(names[i], '-');
        const char *dot = strrchr(names[i], '.');

        if (!dash || !dot || dot < dash ||
            (strcmp(dot, ".dist-info") != 0 && strcmp(dot, ".egg-info") != 0))
        {
            continue;
        }
        {
            char *name = rs_xstrndup(names[i], (size_t)(dash - names[i]));
            char *version = rs_xstrndup(dash + 1, (size_t)(dot - dash - 1));

            add_item(array_member(out, "pip"), name, version, rel);
            free(name);
            free(version);
        }
        any = true;
    }
    rs_free_names(names, n);
    return any;
}

/* Every pythonX.Y under `lib`, and the package directory `sub` in each. */
static bool pip_under(const char *root, const char *lib, const char *sub, struct rs_jval *out)
{
    char **names;
    size_t n;
    size_t i;
    bool   any = false;

    names = rs_list_beneath(root, lib, &n);
    for (i = 0; i < n; i++)
    {
        if (rs_starts_with(names[i], "python"))
        {
            char *rel = rs_xasprintf("%s/%s/%s", lib, names[i], sub);

            any = pip_dir(root, rel, out) || any;
            free(rel);
        }
    }
    rs_free_names(names, n);
    return any;
}

/* A package.json's "version". */
static char *npm_version(const char *root, const char *rel)
{
    struct rs_buf         text;
    struct rs_jval        v;
    struct rs_json_parser jp;
    struct rs_buf         err;
    char                 *out = NULL;

    if (!rs_read_beneath(root, rel, SMALL_MAX, &text))
    {
        return NULL;
    }
    memset(&v, 0, sizeof(v));
    rs_buf_init(&err);
    rs_json_init(&jp, text.data, text.len, &err);
    if (rs_json_value(&jp, &v) && v.type == RS_JOBJECT && rs_jobject_str(&v, "version"))
    {
        out = rs_xstrdup(rs_jobject_str(&v, "version"));
    }
    rs_jval_free(&v);
    rs_buf_free(&err);
    rs_buf_free(&text);
    return out;
}

/* npm's global packages: node_modules/NAME, and node_modules/@SCOPE/NAME. */
static bool npm_dir(const char *root, const char *rel, struct rs_jval *out)
{
    char **names;
    size_t n;
    size_t i;
    bool   any = false;

    names = rs_list_beneath(root, rel, &n);
    for (i = 0; i < n; i++)
    {
        char **sub = NULL;
        size_t nsub = 1;
        size_t j;

        if (names[i][0] == '@')
        {
            char *srel = rs_xasprintf("%s/%s", rel, names[i]);

            sub = rs_list_beneath(root, srel, &nsub);
            free(srel);
        }
        for (j = 0; j < nsub; j++)
        {
            char *name = sub ? rs_xasprintf("%s/%s", names[i], sub[j]) : rs_xstrdup(names[i]);
            char *pj = rs_xasprintf("%s/%s/package.json", rel, name);
            char *version = npm_version(root, pj);

            if (version)
            {
                add_item(array_member(out, "npm"), name, version, rel);
                any = true;
            }
            free(version);
            free(pj);
            free(name);
        }
        rs_free_names(sub, sub ? nsub : 0);
    }
    rs_free_names(names, n);
    return any;
}

/* cargo install's record, ~/.cargo/.crates2.json: "NAME VERSION (SOURCE)". */
static bool cargo_home(const char *root, const char *home, struct rs_jval *out)
{
    char                 *rel = rs_xasprintf("%s/.cargo/.crates2.json", home);
    struct rs_buf         text;
    struct rs_jval        v;
    struct rs_json_parser jp;
    struct rs_buf         err;
    const struct rs_jval *installs = NULL;
    bool                  any = false;

    if (!rs_read_beneath(root, rel, SMALL_MAX, &text))
    {
        free(rel);
        return false;
    }
    memset(&v, 0, sizeof(v));
    rs_buf_init(&err);
    rs_json_init(&jp, text.data, text.len, &err);
    if (rs_json_value(&jp, &v))
    {
        installs = rs_jobject_get(&v, "installs");
    }
    if (installs && installs->type == RS_JOBJECT)
    {
        size_t i;

        for (i = 0; i < installs->n; i++)
        {
            const char     *k = installs->keys[i];
            size_t          nlen = strcspn(k, " ");
            char           *name = rs_xstrndup(k, nlen);
            const char     *rest = k + nlen + strspn(k + nlen, " ");
            char           *version = rs_xstrndup(rest, strcspn(rest, " "));
            const char     *src = strchr(rest, '(');
            struct rs_jval *arr = array_member(out, "cargo");

            add_item(arr, name, version, home);
            if (src && ends_with(src, ")"))
            {
                char *s = rs_xstrndup(src + 1, strlen(src) - 2);

                rs_jobj_str(&arr->items[arr->n - 1], "source", s);
                free(s);
            }
            free(name);
            free(version);
            any = true;
        }
    }
    rs_jval_free(&v);
    rs_buf_free(&err);
    rs_buf_free(&text);
    free(rel);
    return any;
}

/* Each pipx application: a virtual environment of its own. */
static bool pipx_home(const char *root, const char *home, struct rs_jval *out)
{
    static const char *const dirs[] = { "/.local/share/pipx/venvs", "/.local/pipx/venvs" };
    size_t                   d;
    bool                     any = false;

    for (d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++)
    {
        char  *rel = rs_xasprintf("%s%s", home, dirs[d]);
        char **names;
        size_t n;
        size_t i;

        names = rs_list_beneath(root, rel, &n);
        for (i = 0; i < n; i++)
        {
            add_item(array_member(out, "pipx"), names[i], NULL, rel);
            any = true;
        }
        rs_free_names(names, n);
        free(rel);
    }
    return any;
}

/* Gems installed system-wide: /var/lib/gems/VERSION/specifications/NAME-VERSION.gemspec.
 * A gem's name can hold hyphens and its version cannot, so the last one ends it. */
static bool gem_dirs(const char *root, struct rs_jval *out)
{
    char **rubies;
    size_t nrubies;
    size_t r;
    bool   any = false;

    rubies = rs_list_beneath(root, "/var/lib/gems", &nrubies);
    for (r = 0; r < nrubies; r++)
    {
        char  *rel = rs_xasprintf("/var/lib/gems/%s/specifications", rubies[r]);
        char **names;
        size_t n;
        size_t i;

        names = rs_list_beneath(root, rel, &n);
        for (i = 0; i < n; i++)
        {
            const char *dash = strrchr(names[i], '-');

            if (dash && ends_with(names[i], ".gemspec"))
            {
                char *name = rs_xstrndup(names[i], (size_t)(dash - names[i]));
                char *version = rs_xstrndup(dash + 1, strlen(dash + 1) - strlen(".gemspec"));

                add_item(array_member(out, "gem"), name, version, rel);
                free(name);
                free(version);
                any = true;
            }
        }
        rs_free_names(names, n);
        free(rel);
    }
    rs_free_names(rubies, nrubies);
    return any;
}

/* ------------------------------------------------------------------------- */
/* The system's package managers, beyond apt and snap                         */
/* ------------------------------------------------------------------------- */

/* "NAME-VERSION" split where the BSDs and Nix split one: at the first '-'
 * before a digit. False, with nothing made, if there is no such '-'. */
static bool split_version(const char *s, char **name, char **version)
{
    size_t i;

    for (i = 1; s[i] != '\0'; i++)
    {
        if (s[i] == '-' && s[i + 1] >= '0' && s[i + 1] <= '9')
        {
            *name = rs_xstrndup(s, i);
            *version = rs_xstrdup(s + i + 1);
            return true;
        }
    }
    return false;
}

/* Whether `text` has a line that is exactly `want`. */
static bool has_line(const char *text, const char *want)
{
    size_t      n = strlen(want);
    const char *p = text;

    while (p && *p)
    {
        if (strncmp(p, want, n) == 0 && (p[n] == '\n' || p[n] == '\0'))
        {
            return true;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return false;
}

/*
 * OpenBSD's packages (/var/db/pkg) or pkgsrc's (/usr/pkg/pkgdb): one
 * directory each, NAME-VERSION, with a +CONTENTS. Each says whether it was
 * asked for or came as what another needs: OpenBSD's +CONTENTS has
 * "@option manual-installation" for one asked for, pkgsrc's +INSTALLED_INFO
 * "automatic=yes" for one that was not.
 */
/* One of bsd_pkgs's: the package in the directory rel/dir, if it is one. */
static bool bsd_pkg(const char *root, const char *rel, const char *dir, const char *key,
                    struct rs_jval *out)
{
    char *contents = rs_xasprintf("%s/%s/+CONTENTS", rel, dir);
    char *info = rs_xasprintf("%s/%s/+INSTALLED_INFO", rel, dir);
    char *name = NULL;
    char *version = NULL;
    bool  pkgsrc = strcmp(key, "pkgsrc") == 0;
    bool  is = exists(root, contents) && split_version(dir, &name, &version);

    if (is)
    {
        struct rs_buf text;
        bool          automatic = false;

        if (rs_read_beneath(root, pkgsrc ? info : contents, STATE_MAX, &text))
        {
            automatic = pkgsrc ? has_line(text.data, "automatic=yes")
                               : !has_line(text.data, "@option manual-installation");
            rs_buf_free(&text);
        }
        rs_jobj_bool(add_item(array_member(out, key), name, version, rel), "automatic", automatic);
    }
    free(name);
    free(version);
    free(contents);
    free(info);
    return is;
}

static bool bsd_pkgs(const char *root, const char *rel, const char *key, struct rs_jval *out)
{
    size_t n;
    char **names = rs_list_beneath(root, rel, &n);
    size_t i;
    bool   any = false;

    for (i = 0; i < n; i++)
    {
        any = bsd_pkg(root, rel, names[i], key, out) || any;
    }
    rs_free_names(names, n);
    return any;
}

/* Whether `root` is this system's own "/": all a package manager that keeps
 * its database in SQLite, and is asked rather than read, can answer for. */
static bool running_system(const char *root)
{
    char *real = realpath(root, NULL); /* Flawfinder: ignore */
    bool  yes = real && strcmp(real, "/") == 0;

    free(real);
    return yes;
}

/* What `prog` writes given `argv`, into `out`, if it is there to run and
 * says it succeeded. */
static bool tool_output(enum rs_program prog, char *const argv[], struct rs_buf *out)
{
    struct rs_buf errtext;
    struct rs_buf err;
    int           code = -1;
    bool          ok;

    rs_buf_init(out);
    rs_buf_init(&errtext);
    rs_buf_init(&err);
    ok = rs_program_path(prog) && rs_run(prog, argv, out, &errtext, &code, &err) && code == 0 &&
         out->len > 0;
    rs_buf_free(&errtext);
    rs_buf_free(&err);
    if (!ok)
    {
        rs_buf_free(out);
    }
    return ok;
}

/* The tab-separated fields of each line of `text`: `n` of them, the last
 * running to the line's end, into `cb`. */
static void each_row(const char *text, size_t n, void (*cb)(char **f, void *ctx), void *ctx)
{
    const char *p = text;

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);
        char       *line = rs_xstrndup(p, len);
        char       *f[8];
        char       *at = line;
        size_t      k;

        for (k = 0; k < n && k < 8 && at; k++)
        {
            char *tab = k + 1 < n ? strchr(at, '\t') : NULL;

            f[k] = at;
            if (tab)
            {
                *tab = '\0';
            }
            at = tab ? tab + 1 : NULL;
        }
        if (k == n && f[0][0] != '\0')
        {
            cb(f, ctx);
        }
        free(line);
        p = nl ? nl + 1 : NULL;
    }
}

static void freebsd_row(char **f, void *ctx)
{
    struct rs_jval *item = add_item(ctx, f[0], f[1], "/var/db/pkg");

    rs_jobj_bool(item, "automatic", strcmp(f[2], "1") == 0);
    rs_jobj_str(item, "origin", f[3]);
}

/* FreeBSD's packages, as pkg says them: its database is SQLite. */
static bool freebsd_pkgs(const char *root, struct rs_jval *out)
{
    static char   pkg[] = "pkg";
    static char   query[] = "query";
    static char   format[] = "%n\t%v\t%a\t%o";
    char *const   argv[] = { pkg, query, format, NULL };
    struct rs_buf text;

    if (!exists(root, "/var/db/pkg/local.sqlite") || !running_system(root) ||
        !tool_output(RS_PROG_PKG, argv, &text))
    {
        return false;
    }
    each_row(text.data, 4, freebsd_row, array_member(out, "freebsd-pkg"));
    rs_buf_free(&text);
    return true;
}

static void rpm_row(char **f, void *ctx)
{
    /* The keys rpm --import adds are no package to install. */
    if (strcmp(f[0], "gpg-pubkey") != 0)
    {
        rs_jobj_str(add_item(ctx, f[0], f[1], "/var/lib/rpm"), "architecture", f[2]);
    }
}

/* rpm's packages, as rpm says them: its database is SQLite. */
static bool rpm_pkgs(const char *root, struct rs_jval *out)
{
    static char   rpm[] = "rpm";
    static char   all[] = "-qa";
    static char   qf[] = "--qf";
    static char   format[] = "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\n";
    char *const   argv[] = { rpm, all, qf, format, NULL };
    struct rs_buf text;

    if ((!is_dir(root, "/var/lib/rpm") && !is_dir(root, "/usr/lib/sysimage/rpm")) ||
        !running_system(root) || !tool_output(RS_PROG_RPM, argv, &text))
    {
        return false;
    }
    each_row(text.data, 3, rpm_row, array_member(out, "rpm"));
    rs_buf_free(&text);
    return true;
}

/* The line after `field` ("%NAME%") in a pacman desc, or NULL. */
static char *desc_field(const char *text, const char *field)
{
    size_t      n = strlen(field);
    const char *p = text;

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');

        if (nl && (size_t)(nl - p) == n && strncmp(p, field, n) == 0)
        {
            const char *v = nl + 1;
            size_t      len = strcspn(v, "\n");

            return len > 0 ? rs_xstrndup(v, len) : NULL;
        }
        p = nl ? nl + 1 : NULL;
    }
    return NULL;
}

/* pacman's packages: a directory each in /var/lib/pacman/local, its desc
 * saying its name, its version and why it is there (%REASON% 1: as what
 * another needs). */
static bool pacman_pkgs(const char *root, struct rs_jval *out)
{
    static const char *const rel = "/var/lib/pacman/local";
    size_t                   n;
    char                   **names = rs_list_beneath(root, rel, &n);
    size_t                   i;
    bool                     any = false;

    for (i = 0; i < n; i++)
    {
        char         *path = rs_xasprintf("%s/%s/desc", rel, names[i]);
        struct rs_buf text;

        if (rs_read_beneath(root, path, SMALL_MAX, &text))
        {
            char *name = desc_field(text.data, "%NAME%");
            char *version = desc_field(text.data, "%VERSION%");
            char *reason = desc_field(text.data, "%REASON%");

            if (name)
            {
                struct rs_jval *item = add_item(array_member(out, "pacman"), name, version, rel);

                rs_jobj_bool(item, "automatic", reason && strcmp(reason, "1") == 0);
                any = true;
            }
            free(name);
            free(version);
            free(reason);
            rs_buf_free(&text);
        }
        free(path);
    }
    rs_free_names(names, n);
    return any;
}

/* Whether `name` is one /etc/apk/world asks for: a line each, the name
 * before any version constraint or tag. */
static bool in_world(const char *world, const char *name)
{
    size_t      n = strlen(name);
    const char *p = world;

    while (p && *p)
    {
        size_t len = strcspn(p, "=<>~@ \n");

        if (len == n && strncmp(p, name, n) == 0)
        {
            return true;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return false;
}

/* apk's packages: /lib/apk/db/installed, "P:" a name and "V:" a version a
 * record, a blank line between; asked for if /etc/apk/world names it. */
static bool apk_pkgs(const char *root, struct rs_jval *out)
{
    struct rs_buf text;
    struct rs_buf world;
    const char   *p;
    char         *name = NULL;
    char         *version = NULL;
    char         *arch = NULL;
    bool          any = false;
    bool          have_world;

    if (!rs_read_beneath(root, "/lib/apk/db/installed", STATE_MAX, &text))
    {
        return false;
    }
    have_world = rs_read_beneath(root, "/etc/apk/world", SMALL_MAX, &world);
    for (p = text.data; p; )
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        if (len > 2 && p[1] == ':' && (p[0] == 'P' || p[0] == 'V' || p[0] == 'A'))
        {
            char **slot = p[0] == 'P' ? &name : p[0] == 'V' ? &version : &arch;

            free(*slot);
            *slot = rs_xstrndup(p + 2, len - 2);
        } else if (len == 0 || !nl)
        {
            if (name)
            {
                struct rs_jval *item = add_item(array_member(out, "apk"), name, version,
                                                "/lib/apk/db/installed");

                rs_jobj_str(item, "architecture", arch);
                if (have_world)
                {
                    rs_jobj_bool(item, "automatic", !in_world(world.data, name));
                }
                any = true;
            }
            free(name);
            free(version);
            free(arch);
            name = version = arch = NULL;
        }
        p = nl ? nl + 1 : NULL;
    }
    rs_buf_free(&text);
    if (have_world)
    {
        rs_buf_free(&world);
    }
    return any;
}

/* Homebrew's formulae and casks beneath `prefix`: PREFIX/Cellar/NAME/VERSION,
 * each with an INSTALL_RECEIPT.json that says whether it was asked for, and
 * PREFIX/Caskroom/NAME/VERSION. */
static bool brew_pkgs(const char *root, const char *prefix, struct rs_jval *out)
{
    static const char *const kinds[] = { "Cellar", "Caskroom" };
    size_t                   k;
    bool                     any = false;

    for (k = 0; k < 2; k++)
    {
        char  *dir = rs_xasprintf("%s/%s", prefix, kinds[k]);
        size_t n;
        char **names = rs_list_beneath(root, dir, &n);
        size_t i;

        for (i = 0; i < n; i++)
        {
            char  *sub = rs_xasprintf("%s/%s", dir, names[i]);
            size_t nv;
            char **versions = rs_list_beneath(root, sub, &nv);
            size_t j;

            for (j = 0; j < nv; j++)
            {
                struct rs_jval *item = add_item(array_member(out, "homebrew"), names[i],
                                                versions[j], prefix);
                char           *receipt = rs_xasprintf("%s/%s/INSTALL_RECEIPT.json", sub,
                                                       versions[j]);
                struct rs_buf   text;

                if (k == 1)
                {
                    rs_jobj_bool(item, "cask", true);
                } else if (rs_read_beneath(root, receipt, SMALL_MAX, &text))
                {
                    struct rs_json_parser jp;
                    struct rs_jval        doc;
                    struct rs_buf         err;
                    const struct rs_jval *asked = NULL;

                    memset(&doc, 0, sizeof(doc));
                    rs_buf_init(&err);
                    rs_json_init(&jp, text.data, text.len, &err);
                    if (rs_json_value(&jp, &doc))
                    {
                        asked = rs_jobject_get(&doc, "installed_on_request");
                    }
                    if (asked && asked->type == RS_JBOOL)
                    {
                        rs_jobj_bool(item, "automatic", !asked->b);
                    }
                    rs_jval_free(&doc);
                    rs_buf_free(&err);
                    rs_buf_free(&text);
                }
                free(receipt);
                any = true;
            }
            rs_free_names(versions, nv);
            free(sub);
        }
        rs_free_names(names, n);
        free(dir);
    }
    return any;
}

/* The packages in one conda environment: ENV/conda-meta/NAME-VERSION-BUILD.json. */
static bool conda_env(const char *root, const char *env, struct rs_jval *out)
{
    char  *meta = rs_xasprintf("%s/conda-meta", env);
    size_t n;
    char **names = rs_list_beneath(root, meta, &n);
    size_t i;
    bool   any = false;

    for (i = 0; i < n; i++)
    {
        size_t len = strlen(names[i]);
        size_t last = 0;      /* the '-' before the build */
        size_t second = 0;    /* and the one before the version */
        size_t k;
        char  *stem;

        if (len <= 5 || strcmp(names[i] + len - 5, ".json") != 0)
        {
            continue;
        }
        stem = rs_xstrndup(names[i], len - 5);
        for (k = 0; stem[k] != '\0'; k++)
        {
            if (stem[k] == '-')
            {
                second = last;
                last = k;
            }
        }
        if (second > 0)
        {
            stem[second] = '\0';
            stem[last] = '\0';
            add_item(array_member(out, "conda"), stem, stem + second + 1, env);
            any = true;
        }
        free(stem);
    }
    rs_free_names(names, n);
    free(meta);
    return any;
}

/* A conda installation at `base`: its own environment and each in envs/. */
static bool conda_pkgs(const char *root, const char *base, struct rs_jval *out)
{
    char  *envs = rs_xasprintf("%s/envs", base);
    size_t n;
    char **names = rs_list_beneath(root, envs, &n);
    size_t i;
    bool   any = conda_env(root, base, out);

    for (i = 0; i < n; i++)
    {
        char *env = rs_xasprintf("%s/%s", envs, names[i]);

        any = conda_env(root, env, out) || any;
        free(env);
    }
    rs_free_names(names, n);
    free(envs);
    return any;
}

/* macOS's installer receipts: /var/db/receipts/ID.plist, one a package. */
static bool macos_receipts(const char *root, struct rs_jval *out)
{
    size_t n;
    char **names = rs_list_beneath(root, "/var/db/receipts", &n);
    size_t i;
    bool   any = false;

    for (i = 0; i < n; i++)
    {
        size_t len = strlen(names[i]);

        if (len > 6 && strcmp(names[i] + len - 6, ".plist") == 0)
        {
            char *id = rs_xstrndup(names[i], len - 6);

            add_item(array_member(out, "macos-receipts"), id, NULL, "/var/db/receipts");
            free(id);
            any = true;
        }
    }
    rs_free_names(names, n);
    return any;
}

/* `path` with ".", ".." and repeated slashes taken out, ".." going no higher
 * than "/". */
static char *clean_path(const char *path)
{
    char       *out = rs_xmalloc(strlen(path) + 2);
    size_t      k = 0;
    const char *p = path;

    out[k++] = '/';
    while (*p)
    {
        size_t len;

        while (*p == '/')
        {
            p++;
        }
        len = strcspn(p, "/");
        if (len == 0 || (len == 1 && p[0] == '.'))
        {
            p += len;
            continue;
        }
        if (len == 2 && p[0] == '.' && p[1] == '.')
        {
            while (k > 1 && out[k - 1] != '/')
            {
                k--;
            }
            if (k > 1)
            {
                k--;
            }
            p += len;
            continue;
        }
        if (k > 1)
        {
            out[k++] = '/';
        }
        memcpy(out + k, p, len);
        k += len;
        p += len;
    }
    out[k] = '\0';
    return out;
}

/*
 * `rel` with each symlink on the way followed, as if `root` were "/" -- so
 * none leads out of it -- and at most 40 of them; the caller's to free, or
 * NULL. Nix's and Guix's profiles are chains of symlinks into their stores.
 */
static char *resolve_beneath(const char *root, const char *rel)
{
    char  *path = clean_path(rel);
    size_t done = 0;
    int    hops = 0;

    while (path[done] != '\0')
    {
        size_t end = done + 1 + strcspn(path + done + 1, "/");
        char  *prefix = rs_xstrndup(path, end);
        char   target[4096];

        if (read_link(root, prefix, target, sizeof(target)))
        {
            char *dir = rs_xstrdup(prefix);
            char *slash = strrchr(dir, '/');    /* there is one: the path is absolute */
            char *joined;

            if (slash)
            {
                *slash = '\0';
            }
            joined = target[0] == '/' ? rs_xasprintf("%s%s", target, path + end)
                                      : rs_xasprintf("%s/%s%s", dir, target, path + end);
            free(dir);
            free(path);
            path = clean_path(joined);
            free(joined);
            done = 0;
            if (++hops > 40)
            {
                free(prefix);
                free(path);
                return NULL;
            }
        } else
        {
            done = end;
        }
        free(prefix);
        if (strcmp(path, "/") == 0)
        {
            break;
        }
    }
    return path;
}

/* The file at `rel`, its symlinks followed beneath root, read. */
static bool read_resolved(const char *root, const char *rel, size_t max, struct rs_buf *out)
{
    char *real = resolve_beneath(root, rel);
    bool  ok = real && rs_read_beneath(root, real, max, out);

    free(real);
    return ok;
}

/* A Nix store path's name: what follows its hash, "/nix/store/HASH-". */
static void nix_item(struct rs_jval *arr, const char *store_path, const char *profile)
{
    const char *base = strrchr(store_path, '/');
    char       *name;
    char       *version;

    base = base ? base + 1 : store_path;
    if (strlen(base) <= 33 || base[32] != '-')
    {
        return;
    }
    base += 33;
    if (split_version(base, &name, &version))
    {
        add_item(arr, name, version, profile);
        free(name);
        free(version);
    } else
    {
        add_item(arr, base, NULL, profile);
    }
}

/* The packages in a profile's manifest.json (nix profile): "elements", an
 * array (version 1) or an object by name (2 and later), each with its
 * "storePaths". */
static bool nix_json(const char *text, size_t len, const char *profile, struct rs_jval *arr)
{
    struct rs_json_parser jp;
    struct rs_jval        doc;
    struct rs_buf         err;
    const struct rs_jval *elements = NULL;
    bool                  any = false;

    memset(&doc, 0, sizeof(doc));
    rs_buf_init(&err);
    rs_json_init(&jp, text, len, &err);
    if (rs_json_value(&jp, &doc))
    {
        elements = rs_jobject_get(&doc, "elements");
    }
    if (elements && (elements->type == RS_JARRAY || elements->type == RS_JOBJECT))
    {
        size_t i;

        for (i = 0; i < elements->n; i++)
        {
            const struct rs_jval *paths = rs_jobject_get(&elements->items[i], "storePaths");

            if (paths && paths->type == RS_JARRAY && paths->n > 0 &&
                paths->items[0].type == RS_JSTRING)
            {
                nix_item(arr, paths->items[0].s, profile);
                any = true;
            }
        }
    }
    rs_jval_free(&doc);
    rs_buf_free(&err);
    return any;
}

/* The packages in a profile's manifest.nix (nix-env): each derivation's
 * `name = "...";`, at the top of its attribute set, not inside its meta. */
static bool nix_expr(const char *text, const char *profile, struct rs_jval *arr)
{
    const char *p = text;
    int         depth = 0;
    bool        any = false;

    while (*p)
    {
        if (*p == '"')
        {
            for (p++; *p && *p != '"'; p++)
            {
                if (*p == '\\' && p[1])
                {
                    p++;
                }
            }
            p += *p ? 1 : 0;
            continue;
        }
        if (*p == '{')
        {
            depth++;
        } else if (*p == '}')
        {
            depth--;
        } else if (depth == 1 && strncmp(p, "name = \"", 8) == 0 &&
                   (p == text || p[-1] == ' ' || p[-1] == '{' || p[-1] == ';'))
        {
            const char *v = p + 8;
            size_t      len = strcspn(v, "\"\\");
            char       *full = rs_xstrndup(v, len);
            char       *name;
            char       *version;

            if (split_version(full, &name, &version))
            {
                add_item(arr, name, version, profile);
                free(name);
                free(version);
            } else
            {
                add_item(arr, full, NULL, profile);
            }
            free(full);
            any = true;
            p = v + len + (v[len] == '"' ? 1 : 0);
            continue;
        }
        p++;
    }
    return any;
}

/* One Nix profile's packages, from whichever manifest it has. */
static bool nix_profile(const char *root, const char *profile, struct rs_jval *out)
{
    char         *json = rs_xasprintf("%s/manifest.json", profile);
    char         *expr = rs_xasprintf("%s/manifest.nix", profile);
    struct rs_buf text;
    bool          any = false;

    if (read_resolved(root, json, STATE_MAX, &text))
    {
        any = nix_json(text.data, text.len, profile, array_member(out, "nix"));
        rs_buf_free(&text);
    } else if (read_resolved(root, expr, STATE_MAX, &text))
    {
        any = nix_expr(text.data, profile, array_member(out, "nix"));
        rs_buf_free(&text);
    }
    free(json);
    free(expr);
    return any;
}

/* Nix's profiles: the default one, each user's, and each home's. */
static bool nix_pkgs(const char *root, char **home, size_t nhome, struct rs_jval *out)
{
    static const char *const per_user = "/nix/var/nix/profiles/per-user";
    size_t                   n;
    char                   **users = rs_list_beneath(root, per_user, &n);
    size_t                   i;
    bool                     any = nix_profile(root, "/nix/var/nix/profiles/default", out);

    for (i = 0; i < n; i++)
    {
        char *profile = rs_xasprintf("%s/%s/profile", per_user, users[i]);

        any = nix_profile(root, profile, out) || any;
        free(profile);
    }
    rs_free_names(users, n);
    for (i = 0; i < nhome; i++)
    {
        char *profile = rs_xasprintf("%s/.nix-profile", home[i]);
        char *state = rs_xasprintf("%s/.local/state/nix/profiles/profile", home[i]);

        any = nix_profile(root, profile, out) || any;
        any = nix_profile(root, state, out) || any;
        free(profile);
        free(state);
    }
    if (exists(root, "/nix/var/nix/profiles/system"))
    {
        note(out, "NixOS: the system's own packages are what /etc/nixos's configuration "
                  "declares, and are not listed");
    }
    return any;
}

/* The packages in a Guix profile's manifest: each ("NAME" "VERSION" "OUTPUT"
 * "/gnu/store/..." ...) at the depth of the manifest's own packages, not the
 * inputs each one propagates. */
static bool guix_manifest(const char *text, const char *profile, struct rs_jval *arr)
{
    const char *p = text;
    int         depth = 0;
    bool        any = false;

    while (*p)
    {
        if (*p == '"')
        {
            for (p++; *p && *p != '"'; p++)
            {
                if (*p == '\\' && p[1])
                {
                    p++;
                }
            }
            p += *p ? 1 : 0;
            continue;
        }
        if (*p == ')')
        {
            depth--;
        } else if (*p == '(')
        {
            const char *q = p + 1;
            const char *s[4];
            size_t      len[4];
            size_t      k;

            depth++;
            for (k = 0; k < 4; k++)
            {
                while (*q == ' ' || *q == '\n' || *q == '\t')
                {
                    q++;
                }
                if (*q != '"')
                {
                    break;
                }
                s[k] = q + 1;
                len[k] = strcspn(s[k], "\"\\");
                if (s[k][len[k]] != '"')
                {
                    break;
                }
                q = s[k] + len[k] + 1;
            }
            if (depth == 4 && k == 4 && strncmp(s[3], "/gnu/store/", 11) == 0)
            {
                char *name = rs_xstrndup(s[0], len[0]);
                char *version = rs_xstrndup(s[1], len[1]);

                add_item(arr, name, version, profile);
                free(name);
                free(version);
                any = true;
            }
        }
        p++;
    }
    return any;
}

static bool guix_profile(const char *root, const char *profile, struct rs_jval *out)
{
    char         *path = rs_xasprintf("%s/manifest", profile);
    struct rs_buf text;
    bool          any = false;

    if (read_resolved(root, path, STATE_MAX, &text))
    {
        any = guix_manifest(text.data, profile, array_member(out, "guix"));
        rs_buf_free(&text);
    }
    free(path);
    return any;
}

/* Guix's profiles: the system's, each user's and each home's. */
static bool guix_pkgs(const char *root, char **home, size_t nhome, struct rs_jval *out)
{
    static const char *const per_user = "/var/guix/profiles/per-user";
    size_t                   n;
    char                   **users = rs_list_beneath(root, per_user, &n);
    size_t                   i;
    bool                     any = guix_profile(root, "/var/guix/profiles/system/profile", out);

    for (i = 0; i < n; i++)
    {
        char *profile = rs_xasprintf("%s/%s/guix-profile", per_user, users[i]);

        any = guix_profile(root, profile, out) || any;
        free(profile);
    }
    rs_free_names(users, n);
    for (i = 0; i < nhome; i++)
    {
        char *profile = rs_xasprintf("%s/.guix-profile", home[i]);

        any = guix_profile(root, profile, out) || any;
        free(profile);
    }
    return any;
}

/* The managers restate reads beyond apt, snap and the languages', each
 * listed in "managers" where it has an inventory. */
static void describe_systems(const char *root, char **home, size_t nhome, struct rs_jval *out)
{
    static const char *const brews[] = { "/opt/homebrew", "/usr/local",
                                         "/home/linuxbrew/.linuxbrew" };
    static const char *const condas[] = { "/opt/conda", "/opt/miniconda3", "/opt/anaconda3",
                                          "/opt/miniforge3" };
    static const char *const user_condas[] = { "miniconda3", "anaconda3", "miniforge3" };
    size_t                   i;
    size_t                   k;

    if (bsd_pkgs(root, "/var/db/pkg", "pkg", out))
    {
        add_manager(out, "pkg", "/var/db/pkg", true);
    }
    if (bsd_pkgs(root, "/usr/pkg/pkgdb", "pkgsrc", out))
    {
        add_manager(out, "pkgsrc", "/usr/pkg/pkgdb", true);
    }
    if (freebsd_pkgs(root, out))
    {
        add_manager(out, "freebsd-pkg", "/var/db/pkg/local.sqlite", true);
    }
    if (rpm_pkgs(root, out))
    {
        add_manager(out, "rpm", "/var/lib/rpm", true);
    }
    if (pacman_pkgs(root, out))
    {
        add_manager(out, "pacman", "/var/lib/pacman/local", true);
    }
    if (apk_pkgs(root, out))
    {
        add_manager(out, "apk", "/lib/apk/db/installed", true);
    }
    for (i = 0; i < sizeof(brews) / sizeof(brews[0]); i++)
    {
        if (brew_pkgs(root, brews[i], out))
        {
            add_manager(out, "homebrew", brews[i], true);
        }
    }
    for (i = 0; i < sizeof(condas) / sizeof(condas[0]); i++)
    {
        if (conda_pkgs(root, condas[i], out))
        {
            add_manager(out, "conda", condas[i], true);
        }
    }
    for (i = 0; i < nhome; i++)
    {
        for (k = 0; k < sizeof(user_condas) / sizeof(user_condas[0]); k++)
        {
            char *base = rs_xasprintf("%s/%s", home[i], user_condas[k]);

            if (conda_pkgs(root, base, out))
            {
                add_manager(out, "conda", base, true);
            }
            free(base);
        }
    }
    if (macos_receipts(root, out))
    {
        add_manager(out, "macos-receipts", "/var/db/receipts", true);
    }
    if (nix_pkgs(root, home, nhome, out))
    {
        add_manager(out, "nix", "/nix/var/nix/profiles", true);
    }
    if (guix_pkgs(root, home, nhome, out))
    {
        add_manager(out, "guix", "/var/guix/profiles", true);
    }
}

/* ------------------------------------------------------------------------- */
/* Every package manager                                                      */
/* ------------------------------------------------------------------------- */

/* Whether a manager called `name` is listed already. */
static bool has_manager(struct rs_jval *out, const char *name)
{
    const struct rs_jval *arr = array_member(out, "managers");
    size_t                i;

    for (i = 0; i < arr->n; i++)
    {
        if (strcmp(rs_jobject_str(&arr->items[i], "name"), name) == 0)
        {
            return true;
        }
    }
    return false;
}

/* Package managers seen whose inventory was not taken: FreeBSD's pkg and
 * rpm of a tree that is not this system, which only their own tools read,
 * and any that has nothing restate could read. */
static void other_managers(const char *root, struct rs_jval *out)
{
    static const struct {
        const char *name;
        const char *path;
    } others[] = {
        { "rpm", "/var/lib/rpm" },
        { "rpm", "/usr/lib/sysimage/rpm" },
        { "pacman", "/var/lib/pacman/local" },
        { "apk", "/lib/apk/db/installed" },
        { "nix", "/nix/store" },
        { "guix", "/gnu/store" },
        { "homebrew", "/home/linuxbrew/.linuxbrew" },
        { "homebrew", "/opt/homebrew" },
        { "homebrew", "/usr/local/Homebrew" },
        { "conda", "/opt/conda" },
        { "conda", "/opt/miniconda3" },
        { "conda", "/opt/anaconda3" },
        { "freebsd-pkg", "/var/db/pkg/local.sqlite" },
        { "pkgsrc", "/usr/pkg/pkgdb" },
        { "macos-receipts", "/var/db/receipts" },
    };
    size_t i;

    for (i = 0; i < sizeof(others) / sizeof(others[0]); i++)
    {
        if (!has_manager(out, others[i].name) && exists(root, others[i].path))
        {
            add_manager(out, others[i].name, others[i].path, false);
        }
    }
}

static void describe_languages(const char *root, char **home, size_t nhome, struct rs_jval *out)
{
    size_t i;
    bool   dist = pip_under(root, "/usr/local/lib", "dist-packages", out);
    bool   site = pip_under(root, "/usr/local/lib", "site-packages", out);

    if (dist || site)
    {
        add_manager(out, "pip", "/usr/local/lib", true);
    }
    if (npm_dir(root, "/usr/local/lib/node_modules", out))
    {
        add_manager(out, "npm", "/usr/local/lib/node_modules", true);
    }
    if (npm_dir(root, "/usr/lib/node_modules", out))
    {
        add_manager(out, "npm", "/usr/lib/node_modules", true);
    }
    if (gem_dirs(root, out))
    {
        add_manager(out, "gem", "/var/lib/gems", true);
    }
    for (i = 0; i < nhome; i++)
    {
        char *lib = rs_xasprintf("%s/.local/lib", home[i]);

        if (pip_under(root, lib, "site-packages", out))
        {
            add_manager(out, "pip", lib, true);
        }
        free(lib);
        if (cargo_home(root, home[i], out))
        {
            add_manager(out, "cargo", home[i], true);
        }
        if (pipx_home(root, home[i], out))
        {
            add_manager(out, "pipx", home[i], true);
        }
    }
}

void rs_packages_describe(const char *root, struct rs_jval *out)
{
    char **home;
    size_t nhome;

    rs_jval_set_object(out);
    (void)array_member(out, "notes");
    (void)array_member(out, "managers");
    describe_apt(root, out);
    if (rs_jobject_get(out, "apt"))
    {
        add_manager(out, "apt", "/var/lib/dpkg/status", true);
    }
    describe_alternatives(root, out);
    describe_snap(root, out);
    if (rs_jobject_get(out, "snap"))
    {
        add_manager(out, "snap", "/var/lib/snapd", true);
    }
    home = homes(root, &nhome);
    describe_flatpak(root, home, nhome, out);
    describe_languages(root, home, nhome, out);
    describe_systems(root, home, nhome, out);
    other_managers(root, out);
    rs_free_names(home, nhome);
}
