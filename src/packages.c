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
#include <unistd.h>

#include "index.h"
#include "sha256.h"

/* A key file is a few kilobytes; one that is not is not a key file. */
#define KEY_MAX    ((size_t)1024 * 1024)
/* snapd's state grows with its change history: a few megabytes, usually. */
#define STATE_MAX  ((size_t)64 * 1024 * 1024)
#define SMALL_MAX  ((size_t)4 * 1024 * 1024)

/* ------------------------------------------------------------------------- */
/* Files                                                                     */
/* ------------------------------------------------------------------------- */

static char *path_join(const char *a, const char *b)
{
    size_t n = strlen(a);

    while (n > 1 && a[n - 1] == '/')
    {
        n--;
    }
    if (n == 1 && a[0] == '/')
    {
        return rs_xstrdup(b);
    }
    return rs_xasprintf("%.*s%s", (int)n, a, b);
}

/* A regular file, opened for reading, or -1. */
static int open_file(const char *path)
{
    int         fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    struct stat st;

    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)))
    {
        (void)close(fd);
        fd = -1;
    }
    return fd;
}

/* The whole of root + rel, up to `max` bytes, into `out`; false if it could
 * not be read, or is larger. */
static bool read_file(const char *root, const char *rel, size_t max, struct rs_buf *out)
{
    char *path = path_join(root, rel);
    int   fd = open_file(path);
    char  chunk[8192];
    bool  ok = fd >= 0;

    free(path);
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

/* root + rel opened as a stream, or NULL. */
static FILE *open_stream(const char *root, const char *rel)
{
    char *path = path_join(root, rel);
    int   fd = open_file(path);
    FILE *fp = fd >= 0 ? fdopen(fd, "r") : NULL;

    free(path);
    if (fd >= 0 && !fp)
    {
        (void)close(fd);
    }
    return fp;
}

static bool exists(const char *root, const char *rel)
{
    char       *path = path_join(root, rel);
    struct stat st;
    bool        ok = lstat(path, &st) == 0;

    free(path);
    return ok;
}

static bool is_dir(const char *root, const char *rel)
{
    char       *path = path_join(root, rel);
    struct stat st;
    bool        ok = lstat(path, &st) == 0 && S_ISDIR(st.st_mode);

    free(path);
    return ok;
}

static int compare_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The entries of a directory, sorted, without "." and ".." and anything else
 * starting with a dot. */
static char **list_dir(const char *root, const char *rel, size_t *count)
{
    char                *path = path_join(root, rel);
    DIR                 *d = opendir(path);
    const struct dirent *de;
    char               **names = NULL;
    size_t               n = 0;

    free(path);
    *count = 0;
    if (!d)
    {
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

static void free_list(char **names, size_t n)
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
    }
    free(apt->pkgs);
    free_list(apt->labels, apt->nlabels);
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
    rs->r = rs_xreallocarray(rs->r, rs->n + 1, sizeof(*rs->r));
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

    if (strstr(value, "BEGIN PGP PUBLIC KEY BLOCK"))
    {
        rs_jobj_str(src, "signed_by", "the key in this file");
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
    for (u = 0; u < uris->n; u++)
    {
        for (s = 0; s < suites->n; s++)
        {
            if (components->n == 0)
            {
                add_repo(rs, uris->items[u].s, suites->items[s].s, "");
            }
            for (c = 0; c < components->n; c++)
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
        char           *p = line + strspn(line, " \t");
        char           *hash = strchr(p, '#');
        char           *opts = NULL;

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
            char *open_b = strchr(p, '[');
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
    names = list_dir(root, "/etc/apt/sources.list.d", &n);
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
    free_list(names, n);
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

static void add_origin(struct pkg *p, size_t label)
{
    size_t i;

    for (i = 0; i < p->norigins; i++)
    {
        if (p->origins[i] == label)
        {
            return;
        }
    }
    p->origins = rs_xreallocarray(p->origins, p->norigins + 1, sizeof(*p->origins));
    p->origins[p->norigins++] = label;
}

static void read_lists(const char *root, const struct repos *rs, struct apt *apt,
                       struct rs_jval *out)
{
    static const char *const wanted[] = { "Package", "Architecture", "Version", NULL };
    char                   **names;
    size_t                   n;
    size_t                   i;
    bool                     compressed = false;
    struct stanza            s;

    memset(&s, 0, sizeof(s));
    names = list_dir(root, "/var/lib/apt/lists", &n);
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
        s.eof = false;
        while (stanza_next(fp, wanted, &s))
        {
            const char *name = stanza_get(&s, "Package");
            const char *arch = stanza_get(&s, "Architecture");
            const char *version = stanza_get(&s, "Version");
            struct pkg *p = name && arch ? find_pkg(apt, name, arch) : NULL;

            if (p && version && strcmp(p->version, version) == 0)
            {
                add_origin(p, label);
            } else if (p)
            {
                p->listed = true;
            }
        }
        (void)fclose(fp);
    }
    stanza_free(&s);
    free_list(names, n);
    if (compressed)
    {
        note(out, "apt keeps its package lists compressed here, and they were not read: "
                  "where each package came from is not recorded");
    }
}

/* ------------------------------------------------------------------------- */
/* apt: keys                                                                  */
/* ------------------------------------------------------------------------- */

/* Every key apt trusts, beside the ones the repositories name. */
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

        names = list_dir(root, dirs[d], &n);
        for (i = 0; i < n; i++)
        {
            char *path = rs_xasprintf("%s/%s", dirs[d], names[i]);

            add_key_path(rs, path);
            free(path);
        }
        free_list(names, n);
    }
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
        if (!read_file(root, rs->keys[i], KEY_MAX, &data))
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
        rs_buf_init(&b64);
        rs_base64_encode(&b64, data.data, data.len);
        rs_jobj_str(k, "data", b64.data ? b64.data : "");
        rs_buf_free(&b64);
        rs_buf_free(&data);
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

    memset(&apt, 0, sizeof(apt));
    memset(&rs, 0, sizeof(rs));
    if (!read_status(root, &apt))
    {
        return;
    }
    read_auto(root, &apt);
    a = rs_jobj_add(out, "apt");
    rs_jval_set_object(a);
    if (read_file(root, "/var/lib/dpkg/arch", SMALL_MAX, &archs))
    {
        add_words(array_member(a, "architectures"), archs.data, false);
        rs_buf_free(&archs);
    }
    read_all_sources(root, &rs, a);
    trusted_keys(root, &rs);
    describe_keys(root, &rs, a, out);
    read_lists(root, &rs, &apt, out);

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
        if (p->norigins == 0)
        {
            rs_jobj_str(o, "unavailable", p->listed ? "superseded" : "local");
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
    free_list(rs.keys, rs.nkeys);
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

    names = list_dir(root, "/snap", &n);
    for (i = 0; i < n; i++)
    {
        char           *rel = rs_xasprintf("/snap/%s/current", names[i]);
        char           *path = path_join(root, rel);
        char            target[256];
        ssize_t         len = readlink(path, target, sizeof(target) - 1); /* Flawfinder: ignore */
        struct rs_jval *o;

        free(rel);
        free(path);
        if (len <= 0)
        {
            continue;
        }
        target[len] = '\0';
        o = rs_jarr_add(arr);
        rs_jval_set_object(o);
        rs_jobj_str(o, "name", names[i]);
        rs_jobj_str(o, "revision", target);
        if (target[0] == 'x')
        {
            rs_jobj_bool(o, "local", true);
        }
    }
    free_list(names, n);
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
    if (read_file(root, "/var/lib/snapd/state.json", STATE_MAX, &text))
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
    if (!read_file(root, "/etc/passwd", SMALL_MAX, &text))
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

    if (!read_file(root, rel, SMALL_MAX, &text))
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
    ids = list_dir(root, rel, &nids);
    free(rel);
    for (i = 0; i < nids; i++)
    {
        char **archs;
        size_t narchs;
        size_t a;

        rel = rs_xasprintf("%s/app/%s", dir, ids[i]);
        archs = list_dir(root, rel, &narchs);
        free(rel);
        for (a = 0; a < narchs; a++)
        {
            char **branches;
            size_t nbranches;
            size_t b;

            rel = rs_xasprintf("%s/app/%s/%s", dir, ids[i], archs[a]);
            branches = list_dir(root, rel, &nbranches);
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
            free_list(branches, nbranches);
        }
        free_list(archs, narchs);
    }
    free_list(ids, nids);
    free_list(remotes, nremotes);
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

static void add_item(struct rs_jval *arr, const char *name, const char *version,
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

    names = list_dir(root, rel, &n);
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
    free_list(names, n);
    return any;
}

/* Every pythonX.Y under `lib`, and the package directory `sub` in each. */
static bool pip_under(const char *root, const char *lib, const char *sub, struct rs_jval *out)
{
    char **names;
    size_t n;
    size_t i;
    bool   any = false;

    names = list_dir(root, lib, &n);
    for (i = 0; i < n; i++)
    {
        if (rs_starts_with(names[i], "python"))
        {
            char *rel = rs_xasprintf("%s/%s/%s", lib, names[i], sub);

            any = pip_dir(root, rel, out) || any;
            free(rel);
        }
    }
    free_list(names, n);
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

    if (!read_file(root, rel, SMALL_MAX, &text))
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

    names = list_dir(root, rel, &n);
    for (i = 0; i < n; i++)
    {
        char **sub = NULL;
        size_t nsub = 1;
        size_t j;

        if (names[i][0] == '@')
        {
            char *srel = rs_xasprintf("%s/%s", rel, names[i]);

            sub = list_dir(root, srel, &nsub);
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
        free_list(sub, sub ? nsub : 0);
    }
    free_list(names, n);
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

    if (!read_file(root, rel, SMALL_MAX, &text))
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

        names = list_dir(root, rel, &n);
        for (i = 0; i < n; i++)
        {
            add_item(array_member(out, "pipx"), names[i], NULL, rel);
            any = true;
        }
        free_list(names, n);
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

    rubies = list_dir(root, "/var/lib/gems", &nrubies);
    for (r = 0; r < nrubies; r++)
    {
        char  *rel = rs_xasprintf("/var/lib/gems/%s/specifications", rubies[r]);
        char **names;
        size_t n;
        size_t i;

        names = list_dir(root, rel, &n);
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
        free_list(names, n);
        free(rel);
    }
    free_list(rubies, nrubies);
    return any;
}

/* OpenBSD's and NetBSD's packages: one directory each, NAME-VERSION. */
static bool bsd_pkgs(const char *root, const char *rel, struct rs_jval *out)
{
    char **names;
    size_t n;
    size_t i;
    bool   any = false;

    names = list_dir(root, rel, &n);
    for (i = 0; i < n; i++)
    {
        char *contents = rs_xasprintf("%s/%s/+CONTENTS", rel, names[i]);

        if (exists(root, contents))
        {
            add_item(array_member(out, "pkg"), names[i], NULL, rel);
            any = true;
        }
        free(contents);
    }
    free_list(names, n);
    return any;
}

/* ------------------------------------------------------------------------- */
/* Every package manager                                                      */
/* ------------------------------------------------------------------------- */

/* Package managers seen, but whose inventory this version does not take. */
static void other_managers(const char *root, struct rs_jval *out)
{
    static const struct {
        const char *name;
        const char *path;
    } others[] = {
        { "rpm", "/var/lib/rpm" },
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
        if (exists(root, others[i].path))
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
    describe_snap(root, out);
    if (rs_jobject_get(out, "snap"))
    {
        add_manager(out, "snap", "/var/lib/snapd", true);
    }
    home = homes(root, &nhome);
    describe_flatpak(root, home, nhome, out);
    describe_languages(root, home, nhome, out);
    if (bsd_pkgs(root, "/var/db/pkg", out))
    {
        add_manager(out, "pkg", "/var/db/pkg", true);
    }
    other_managers(root, out);
    free_list(home, nhome);
}
