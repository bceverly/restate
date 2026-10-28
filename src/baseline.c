/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "baseline.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "gzip.h"
#include "packages.h"
#include "pgp.h"
#include "run.h"
#include "sources.h"

/* A Packages list is read up to this much, uncompressed. */
#define PACKAGES_MAX ((size_t)512 * 1024 * 1024)
/* How many packages one curl fetches. */
#define BATCH 64

const char *rs_baseline_default_cache(void)
{
#if defined(__APPLE__)
    return "/Library/Caches/restate/baseline";
#else
    return "/var/cache/restate/baseline";
#endif
}

/* ------------------------------------------------------------------------- */
/* Names                                                                      */
/* ------------------------------------------------------------------------- */

static bool only(const char *s, const char *allowed)
{
    return s && s[0] != '\0' && strspn(s, allowed) == strlen(s);
}

char *rs_baseline_deb_name(const char *name, const char *version, const char *arch)
{
    static const char names[] = "abcdefghijklmnopqrstuvwxyz0123456789+.-";
    static const char versions[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                   "0123456789.+~:-";
    struct rs_buf     b;
    const char       *p;

    if (!only(name, names) || name[0] == '.' || name[0] == '-' || !only(version, versions) ||
        !only(arch, "abcdefghijklmnopqrstuvwxyz0123456789-"))
    {
        return NULL;
    }
    rs_buf_init(&b);
    rs_buf_addf(&b, "%s_", name);
    for (p = version; *p; p++)
    {
        if (*p == ':')
        {
            rs_buf_addstr(&b, "%3a");
        } else
        {
            rs_buf_addc(&b, *p);
        }
    }
    rs_buf_addf(&b, "_%s.deb", arch);
    return rs_buf_detach(&b);
}

bool rs_baseline_label(const char *label, char **uri, char **suite, char **component)
{
    const char *space = label ? strchr(label, ' ') : NULL;
    const char *rest;
    const char *slash;

    *uri = NULL;
    *suite = NULL;
    *component = NULL;
    if (!space || space == label || space[1] == '\0' || strchr(space + 1, ' '))
    {
        return false;
    }
    rest = space + 1;
    *uri = rs_xstrndup(label, (size_t)(space - label));
    /* A component has no slash; a suite may ("bookworm/updates"), and a flat
     * repository's is a path ending in one. */
    slash = strrchr(rest, '/');
    if (!slash || slash[1] == '\0')
    {
        *suite = rs_xstrdup(rest);
        *component = rs_xstrdup("");
    } else
    {
        *suite = rs_xstrndup(rest, (size_t)(slash - rest));
        *component = rs_xstrdup(slash + 1);
    }
    return true;
}

/* The host of an http(s) URI, and the path after it (without leading or
 * trailing slashes), or false. */
static bool split_uri(const char *uri, char **host, char **path)
{
    const char *p;
    const char *slash;
    size_t      n;

    if (rs_starts_with(uri, "https://"))
    {
        p = uri + 8;
    } else if (rs_starts_with(uri, "http://"))
    {
        p = uri + 7;
    } else
    {
        return false;
    }
    slash = strchr(p, '/');
    *host = slash ? rs_xstrndup(p, (size_t)(slash - p)) : rs_xstrdup(p);
    p = slash ? slash + 1 : "";
    n = strlen(p);
    while (n > 0 && p[n - 1] == '/')
    {
        n--;
    }
    *path = rs_xstrndup(p, n);
    return true;
}

static bool ends_with(const char *s, const char *suffix);

char *rs_baseline_uri_for(const char *uri, const char *arch)
{
    char *host = NULL;
    char *path = NULL;
    char *out = NULL;
    bool  pc = arch && (strcmp(arch, "amd64") == 0 || strcmp(arch, "i386") == 0);

    if (arch && split_uri(uri, &host, &path))
    {
        const char *scheme = rs_starts_with(uri, "https://") ? "https://" : "http://";
        bool        main = strcmp(path, "ubuntu") == 0 &&
                    (strcmp(host, "archive.ubuntu.com") == 0 ||
                     ends_with(host, ".archive.ubuntu.com") ||
                     strcmp(host, "security.ubuntu.com") == 0);
        bool        ports = strcmp(path, "ubuntu-ports") == 0 &&
                     (strcmp(host, "ports.ubuntu.com") == 0 ||
                      ends_with(host, ".ports.ubuntu.com"));

        if (main && !pc)
        {
            out = rs_xasprintf("%sports.ubuntu.com/ubuntu-ports/", scheme);
        } else if (ports && pc)
        {
            out = rs_xasprintf("%sarchive.ubuntu.com/ubuntu/", scheme);
        }
    }
    free(host);
    free(path);
    return out ? out : rs_xstrdup(uri);
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s);
    size_t m = strlen(suffix);

    return n >= m && strcmp(s + n - m, suffix) == 0;
}

bool rs_baseline_snapshot_uri(const char *uri, const char *id, struct rs_buf *out)
{
    char *host = NULL;
    char *path = NULL;
    bool  ok = true;

    if (!only(id, "0123456789TZ") || !split_uri(uri, &host, &path))
    {
        return false;
    }
    rs_buf_reset(out);
    if ((strcmp(host, "archive.ubuntu.com") == 0 || ends_with(host, ".archive.ubuntu.com") ||
         strcmp(host, "security.ubuntu.com") == 0) && strcmp(path, "ubuntu") == 0)
    {
        rs_buf_addf(out, "https://snapshot.ubuntu.com/ubuntu/%s/", id);
    } else if ((strcmp(host, "ports.ubuntu.com") == 0 || ends_with(host, ".ports.ubuntu.com")) &&
               strcmp(path, "ubuntu-ports") == 0)
    {
        rs_buf_addf(out, "https://snapshot.ubuntu.com/ubuntu-ports/%s/", id);
    } else if ((strcmp(host, "deb.debian.org") == 0 || ends_with(host, ".debian.org")) &&
               strcmp(host, "snapshot.debian.org") != 0 &&
               (strcmp(path, "debian") == 0 || strcmp(path, "debian-security") == 0))
    {
        rs_buf_addf(out, "https://snapshot.debian.org/archive/%s/%s/", path, id);
    } else
    {
        ok = false;
    }
    free(host);
    free(path);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* apt's credentials                                                          */
/* ------------------------------------------------------------------------- */

/* The host of `uri`, scheme and path and port dropped, into `host` (at most
 * `max` bytes); whether it was https in *tls. False if it has no scheme when
 * `need_scheme`, another scheme, or no host. */
static bool host_of(const char *uri, bool need_scheme, bool *tls, char *host, size_t max)
{
    const char *p = uri;
    size_t      n;

    *tls = true;
    if (rs_starts_with(p, "https://"))
    {
        p += 8;
    } else if (rs_starts_with(p, "http://"))
    {
        p += 7;
        *tls = false;
    } else if (need_scheme || strstr(p, "://"))
    {
        return false;
    }
    n = strcspn(p, "/:");
    if (n == 0 || n >= max)
    {
        return false;
    }
    memcpy(host, p, n);
    host[n] = '\0';
    return strspn(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") == n;
}

/* Whether `apt`'s sources reach `host`: over https at all, and over http. */
static void reached(const struct rs_jval *apt, const char *host, bool *https, bool *http)
{
    const struct rs_jval *sources = rs_jobject_get(apt, "sources");
    size_t                i;
    size_t                k;

    *https = false;
    *http = false;
    for (i = 0; sources && sources->type == RS_JARRAY && i < sources->n; i++)
    {
        const struct rs_jval *uris = rs_jobject_get(&sources->items[i], "uris");

        for (k = 0; uris && uris->type == RS_JARRAY && k < uris->n; k++)
        {
            char h[256];
            bool tls;

            if (uris->items[k].type == RS_JSTRING &&
                host_of(uris->items[k].s, true, &tls, h, sizeof(h)) && strcmp(h, host) == 0)
            {
                *https = *https || tls;
                *http = *http || !tls;
            }
        }
    }
}

/* The next whitespace-separated word at *p into `word` (at most `max` - 1
 * bytes; one longer is read past and left empty), or false at the end. */
static bool next_word(const char **p, char *word, size_t max)
{
    size_t n;

    for (;;)
    {
        *p += strspn(*p, " \t\r\n");
        if (**p != '#')
        {
            break;
        }
        *p += strcspn(*p, "\n");   /* a comment, to the end of its line */
    }
    n = strcspn(*p, " \t\r\n");
    if (n == 0)
    {
        return false;
    }
    if (n >= max)
    {
        word[0] = '\0';
    } else
    {
        memcpy(word, *p, n);
        word[n] = '\0';
    }
    *p += n;
    return true;
}

static bool is_keyword(const char *word)
{
    return strcmp(word, "machine") == 0 || strcmp(word, "default") == 0 ||
           strcmp(word, "login") == 0 || strcmp(word, "password") == 0;
}

static void flush_machine(const struct rs_jval *apt, const char *machine, const char *login,
                          const char *password, struct rs_buf *out, bool *any)
{
    char host[256];
    bool tls;
    bool https;
    bool http;

    if (!machine[0] || !login[0] || !password[0] ||
        !host_of(machine, false, &tls, host, sizeof(host)) || !tls)
    {
        return;
    }
    reached(apt, host, &https, &http);
    if (https && !http)
    {
        rs_buf_addf(out, "machine %s login %s password %s\n", host, login, password);
        *any = true;
    }
}

bool rs_baseline_netrc(const char *auth, const struct rs_jval *apt, struct rs_buf *out)
{
    const char *p = auth ? auth : "";
    char        word[1024];
    char        machine[512] = "";
    char        login[512] = "";
    char        password[1024] = "";
    bool        any = false;

    while (next_word(&p, word, sizeof(word)))
    {
        char       *into = NULL;
        size_t      max = 0;
        const char *before;

        if (strcmp(word, "machine") == 0 || strcmp(word, "default") == 0)
        {
            /* "default" is any host at all: never one to send a password to. */
            flush_machine(apt, machine, login, password, out, &any);
            machine[0] = '\0';
            login[0] = '\0';
            password[0] = '\0';
            into = strcmp(word, "machine") == 0 ? machine : NULL;
            max = sizeof(machine);
        } else if (strcmp(word, "login") == 0)
        {
            into = login;
            max = sizeof(login);
        } else if (strcmp(word, "password") == 0)
        {
            into = password;
            max = sizeof(password);
        }
        /* A value, unless what follows is the next keyword. */
        before = p;
        if (into && next_word(&p, word, sizeof(word)))
        {
            if (is_keyword(word))
            {
                p = before;
            } else if (strlen(word) < max)
            {
                memcpy(into, word, strlen(word) + 1);
            }
        }
    }
    flush_machine(apt, machine, login, password, out, &any);
    return any;
}

/* Clears what held a password before it is freed. */
static void wipe_buf(struct rs_buf *b)
{
    volatile char *v = b->data;
    size_t         n = b->len;

    while (v && n-- > 0)
    {
        *v++ = 0;
    }
    rs_buf_free(b);
}

/* apt's credentials on this system, as curl takes them, in `home`/netrc: its
 * path, or NULL if there are none (or they are not ours to read: root's). */
static char *netrc_file(const struct rs_jval *apt, const char *home)
{
    struct rs_buf auth;
    struct rs_buf one;
    struct rs_buf out;
    DIR          *d;
    char         *path = NULL;

    rs_buf_init(&auth);
    rs_buf_init(&out);
    if (rs_read_beneath("/", "/etc/apt/auth.conf", 65536, &one))
    {
        rs_buf_add(&auth, one.data ? one.data : "", one.len);
        rs_buf_addc(&auth, '\n');
        wipe_buf(&one);
    }
    d = opendir("/etc/apt/auth.conf.d");
    while (d)
    {
        struct dirent *e = readdir(d);
        char          *rel;
        size_t         n;

        if (!e)
        {
            break;
        }
        /* As apt takes them: a name of letters, digits, "_" and "-", with
         * ".conf" after it or nothing -- Ubuntu Pro's is 90ubuntu-advantage
         * -- and no other file left there, a .dpkg-old or a backup. */
        n = strcspn(e->d_name, ".");
        if (n == 0 ||
            strspn(e->d_name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") !=
                n ||
            (e->d_name[n] != '\0' && strcmp(e->d_name + n, ".conf") != 0))
        {
            continue;
        }
        rel = rs_xasprintf("/etc/apt/auth.conf.d/%s", e->d_name);
        if (rs_read_beneath("/", rel, 65536, &one))
        {
            rs_buf_add(&auth, one.data ? one.data : "", one.len);
            rs_buf_addc(&auth, '\n');
            wipe_buf(&one);
        }
        free(rel);
    }
    if (d)
    {
        (void)closedir(d);
    }
    rs_buf_add(&auth, "", 0);
    if (rs_baseline_netrc(auth.data, apt, &out))
    {
        int fd;

        path = rs_xasprintf("%s/netrc", home);
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0 || write(fd, out.data, out.len) != (ssize_t)out.len)
        {
            free(path);
            path = NULL;
        }
        if (fd >= 0)
        {
            (void)close(fd);
        }
    }
    wipe_buf(&auth);
    wipe_buf(&out);
    return path;
}

/* ------------------------------------------------------------------------- */
/* Release and Packages                                                       */
/* ------------------------------------------------------------------------- */

static bool is_hex64(const char *s, size_t n)
{
    size_t i;

    if (n != RS_SHA256_HEX_SIZE - 1)
    {
        return false;
    }
    for (i = 0; i < n; i++)
    {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
        {
            return false;
        }
    }
    return true;
}

/* A size of at most 18 digits, the whole of [s, s + n). */
static bool size_of(const char *s, size_t n, uint64_t *out)
{
    size_t i;

    *out = 0;
    if (n == 0 || n > 18)
    {
        return false;
    }
    for (i = 0; i < n; i++)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
        *out = *out * 10 + (uint64_t)(s[i] - '0');
    }
    return true;
}

bool rs_baseline_release_entry(const char *release, const char *path,
                               char sha[RS_SHA256_HEX_SIZE], uint64_t *size)
{
    const char *p = release;
    bool        in = false;
    size_t      plen = strlen(path);

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        if (len > 0 && p[len - 1] == '\r')
        {
            len--;
        }
        if (p[0] != ' ' && p[0] != '\t')
        {
            in = len == 7 && memcmp(p, "SHA256:", 7) == 0;
        } else if (in)
        {
            /* " HASH SIZE PATH", the columns padded with spaces */
            const char *words[3];
            size_t      lens[3];
            const char *q = p;
            const char *end = p + len;
            size_t      k;

            for (k = 0; k < 3; k++)
            {
                while (q < end && (*q == ' ' || *q == '\t'))
                {
                    q++;
                }
                words[k] = q;
                while (q < end && *q != ' ' && *q != '\t')
                {
                    q++;
                }
                lens[k] = (size_t)(q - words[k]);
            }
            if (q == end && lens[2] == plen && memcmp(words[2], path, plen) == 0 &&
                is_hex64(words[0], lens[0]) && size_of(words[1], lens[1], size))
            {
                memcpy(sha, words[0], RS_SHA256_HEX_SIZE - 1);
                sha[RS_SHA256_HEX_SIZE - 1] = '\0';
                return true;
            }
        }
        p = nl ? nl + 1 : NULL;
    }
    return false;
}

struct field {
    const char *key;
    char       *val;
};

/* One stanza's fields, those wanted. */
static void stanza_done(struct field *f, size_t nf, rs_baseline_fn fn, void *ctx)
{
    struct rs_baseline_entry e;
    const char              *size = NULL;
    size_t                   i;

    memset(&e, 0, sizeof(e));
    for (i = 0; i < nf; i++)
    {
        if (!f[i].val)
        {
            continue;
        }
        if (strcmp(f[i].key, "Package") == 0)
        {
            e.name = f[i].val;
        } else if (strcmp(f[i].key, "Version") == 0)
        {
            e.version = f[i].val;
        } else if (strcmp(f[i].key, "Architecture") == 0)
        {
            e.arch = f[i].val;
        } else if (strcmp(f[i].key, "Filename") == 0)
        {
            e.filename = f[i].val;
        } else if (strcmp(f[i].key, "SHA256") == 0)
        {
            e.sha256 = f[i].val;
        } else
        {
            size = f[i].val;
        }
    }
    if (e.name && e.version && e.arch && e.filename && e.sha256 && size &&
        is_hex64(e.sha256, strlen(e.sha256)) && size_of(size, strlen(size), &e.size))
    {
        fn(ctx, &e);
    }
    for (i = 0; i < nf; i++)
    {
        free(f[i].val);
        f[i].val = NULL;
    }
}

void rs_baseline_parse_packages(const char *text, size_t len, rs_baseline_fn fn, void *ctx)
{
    struct field f[] = { { "Package", NULL }, { "Version", NULL }, { "Architecture", NULL },
                         { "Filename", NULL }, { "SHA256", NULL }, { "Size", NULL } };
    const size_t nf = sizeof(f) / sizeof(f[0]);
    const char  *p = text;
    const char  *end = text + len;

    while (p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *stop = nl ? nl : end;
        const char *colon = NULL;
        size_t      n;

        if (stop > p && stop[-1] == '\r')
        {
            stop--;
        }
        n = (size_t)(stop - p);
        if (n > 0 && p[0] != ' ' && p[0] != '\t')
        {
            colon = memchr(p, ':', n);
        }
        if (n == 0)
        {
            stanza_done(f, nf, fn, ctx);
        } else if (colon)
        {
            size_t k;

            for (k = 0; k < nf; k++)
            {
                size_t      klen = strlen(f[k].key);
                const char *v = colon + 1;

                if ((size_t)(colon - p) != klen || memcmp(p, f[k].key, klen) != 0)
                {
                    continue;
                }
                while (v < stop && (*v == ' ' || *v == '\t'))
                {
                    v++;
                }
                free(f[k].val);
                f[k].val = memchr(v, '\0', (size_t)(stop - v))
                               ? NULL
                               : rs_xstrndup(v, (size_t)(stop - v));
            }
        }
        p = nl ? nl + 1 : end;
    }
    stanza_done(f, nf, fn, ctx);
}

/* ------------------------------------------------------------------------- */
/* Fetching                                                                   */
/* ------------------------------------------------------------------------- */

struct want {
    const char           *name;
    const char           *version;
    const char           *arch;
    const struct rs_jval *labels;   /* origins, or for a superseded one superseded_in */
    char                 *dated;    /* the snapshot as of when it was installed */
    char                 *deb;      /* its name in the cache */
    bool                  found;    /* in a list that was checked */
    bool                  from_snapshot;
    bool                  done;     /* in the cache, checked */
    char                  sha[RS_SHA256_HEX_SIZE];
    uint64_t              size;
    char                 *url;
    char                 *now;      /* the version its repository has instead */
};

/* One repository's suite, and what is wanted from it. */
struct group {
    char                 *root;       /* the archive's root, ending in a slash */
    char                 *suite;
    bool                  flat;
    bool                  snapshot;
    const struct rs_jval *src;        /* the source that names it */
    char                **parts;      /* "main/binary-amd64/" -- "" for a flat one */
    size_t                nparts;
};

struct run {
    const struct rs_jval          *apt;
    const struct rs_baseline_opts *o;
    struct rs_baseline_stats      *st;
    const char                    *cache;
    char                          *home;       /* gpgv's, and where lists are fetched to */
    char                          *netrc;      /* apt's credentials, for curl, or NULL */
    const char                    *native;
    const char                    *to;         /* --arch's, Debian's name; or NULL */
    struct want                   *w;
    size_t                         nw;
    struct group                  *g;
    size_t                         ng;
    const struct group            *at;         /* the group a list being read is from */
};

static void say(const struct run *r, const char *fmt, ...) RESTATE_PRINTF(2, 3);

static void say(const struct run *r, const char *fmt, ...)
{
    va_list ap;

    if (r->o->quiet)
    {
        return;
    }
    va_start(ap, fmt);
    (void)fputs("restate: ", stderr);
    /* Every caller's format is a literal, which RESTATE_PRINTF has the
     * compiler check against its arguments. */
    (void)vfprintf(stderr, fmt, ap); /* Flawfinder: ignore -- checked, as above */
    (void)fputc('\n', stderr);
    va_end(ap);
}

static int compare_wants(const void *a, const void *b)
{
    const struct want *x = a;
    const struct want *y = b;
    int                c = strcmp(x->name, y->name);

    c = c != 0 ? c : strcmp(x->arch, y->arch);
    return c != 0 ? c : strcmp(x->version, y->version);
}

static struct want *find_want(const struct run *r, const char *name, const char *arch,
                              const char *version)
{
    struct want key;

    memset(&key, 0, sizeof(key));
    key.name = name;
    key.arch = arch;
    key.version = version;
    return r->nw ? bsearch(&key, r->w, r->nw, sizeof(*r->w), compare_wants) : NULL;
}

static int compare_name_arch(const void *a, const void *b)
{
    const struct want *x = a;
    const struct want *y = b;
    int                c = strcmp(x->name, y->name);

    return c != 0 ? c : strcmp(x->arch, y->arch);
}

/* A package wanted at some version -- for saying what its repository has in
 * its place. */
static struct want *find_name(const struct run *r, const char *name, const char *arch)
{
    struct want key;

    memset(&key, 0, sizeof(key));
    key.name = name;
    key.arch = arch;
    return r->nw ? bsearch(&key, r->w, r->nw, sizeof(*r->w), compare_name_arch) : NULL;
}

/* The snapshot ID of a superseded package's installation, as packages.c
 * writes "installed". */
static char *dated(const struct rs_jval *p)
{
    const char *why = rs_jobject_str(p, "unavailable");
    const char *when = rs_jobject_str(p, "installed");
    char        buf[17];
    size_t      i;
    size_t      k = 0;

    /* "2026-10-03T14:00:00.000000000Z" -> "20261003T140000Z" */
    if (!why || strcmp(why, "superseded") != 0 || !when || strlen(when) < 20)
    {
        return NULL;
    }
    for (i = 0; i < 19 && k < 15; i++)
    {
        char c = when[i];

        if (c >= '0' && c <= '9')
        {
            buf[k++] = c;
        } else if (c == 'T' && k == 8)
        {
            buf[k++] = 'T';
        } else if (c != '-' && c != ':')
        {
            return NULL;
        }
    }
    if (k != 15)
    {
        return NULL;
    }
    buf[15] = 'Z';
    buf[16] = '\0';
    return rs_xstrdup(buf);
}

static bool has_string(const struct rs_jval *arr, const char *s)
{
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        if (arr->items[i].type == RS_JSTRING && strcmp(arr->items[i].s, s) == 0)
        {
            return true;
        }
    }
    return false;
}

/* The source that names `uri` and `suite`, or NULL. */
static const struct rs_jval *source_for(const struct rs_jval *apt, const char *uri,
                                        const char *suite)
{
    const struct rs_jval *sources = rs_jobject_get(apt, "sources");
    size_t                i;

    for (i = 0; sources && sources->type == RS_JARRAY && i < sources->n; i++)
    {
        const struct rs_jval *s = &sources->items[i];

        if (has_string(rs_jobject_get(s, "uris"), uri) &&
            has_string(rs_jobject_get(s, "suites"), suite))
        {
            return s;
        }
    }
    return NULL;
}

static char *with_slash(const char *s)
{
    size_t n = strlen(s);

    return n > 0 && s[n - 1] == '/' ? rs_xstrdup(s) : rs_xasprintf("%s/", s);
}

static void add_part(struct group *g, const char *part)
{
    size_t i;

    for (i = 0; i < g->nparts; i++)
    {
        if (strcmp(g->parts[i], part) == 0)
        {
            return;
        }
    }
    g->parts = rs_xreallocarray(g->parts, g->nparts + 1, sizeof(*g->parts));
    g->parts[g->nparts++] = rs_xstrdup(part);
}

/* The group for an archive root and suite, made if there is none. */
static struct group *group_for(struct run *r, const char *root, const char *suite, bool flat,
                               bool snapshot, const struct rs_jval *src)
{
    char  *norm = with_slash(root);
    size_t i;

    for (i = 0; i < r->ng; i++)
    {
        if (strcmp(r->g[i].root, norm) == 0 && strcmp(r->g[i].suite, suite) == 0)
        {
            free(norm);
            return &r->g[i];
        }
    }
    r->g = rs_xreallocarray(r->g, r->ng + 1, sizeof(*r->g));
    memset(&r->g[r->ng], 0, sizeof(r->g[r->ng]));
    r->g[r->ng].root = norm;
    r->g[r->ng].suite = rs_xstrdup(suite);
    r->g[r->ng].flat = flat;
    r->g[r->ng].snapshot = snapshot;
    r->g[r->ng].src = src;
    return &r->g[r->ng++];
}

static void free_groups(struct run *r)
{
    size_t i;
    size_t k;

    for (i = 0; i < r->ng; i++)
    {
        for (k = 0; k < r->g[i].nparts; k++)
        {
            free(r->g[i].parts[k]);
        }
        free(r->g[i].parts);
        free(r->g[i].root);
        free(r->g[i].suite);
    }
    free(r->g);
    r->g = NULL;
    r->ng = 0;
}

/* One of a wanted package's origins, into its group: the repository as it
 * is now, or with `id` its snapshot as of then, where it has one. */
static void plan_label(struct run *r, const struct want *w, const char *label, const char *id)
{
    const struct rs_jval *src;
    struct rs_buf         snap;
    char                 *uri;
    char                 *suite;
    char                 *comp;
    const char           *native = r->to ? r->to : r->native;
    const char           *arch = strcmp(w->arch, "all") == 0 && native ? native : w->arch;
    char                 *there;

    if (!rs_baseline_label(label, &uri, &suite, &comp))
    {
        return;
    }
    /* Trusted as the machine's source is; fetched from where the
     * processor's packages are. */
    src = source_for(r->apt, uri, suite);
    there = rs_baseline_uri_for(uri, r->to);
    rs_buf_init(&snap);
    if (src && (!id || rs_baseline_snapshot_uri(there, id, &snap)))
    {
        struct group *g = group_for(r, id ? snap.data : there, suite, comp[0] == '\0',
                                    id != NULL, src);
        char         *part = comp[0] ? rs_xasprintf("%s/binary-%s/", comp, arch)
                                     : rs_xstrdup("");

        add_part(g, part);
        free(part);
        /* A repository may list its Architecture: all packages apart. */
        if (comp[0] && strcmp(w->arch, "all") == 0)
        {
            part = rs_xasprintf("%s/binary-all/", comp);
            add_part(g, part);
            free(part);
        }
    }
    rs_buf_free(&snap);
    free(there);
    free(uri);
    free(suite);
    free(comp);
}

/* Groups each wanted package's repositories: as they are now, or, with
 * `snapshots`, their snapshots -- for what was not found as they are now. */
static void plan(struct run *r, bool snapshots)
{
    size_t i;
    size_t k;

    for (i = 0; i < r->nw; i++)
    {
        struct want *w = &r->w[i];
        const char  *id = w->dated ? w->dated : r->o->snapshot;

        if (w->found || (snapshots && !id) || (!snapshots && w->dated))
        {
            continue;
        }
        for (k = 0; w->labels && w->labels->type == RS_JARRAY && k < w->labels->n; k++)
        {
            if (w->labels->items[k].type == RS_JSTRING)
            {
                plan_label(r, w, w->labels->items[k].s, snapshots ? id : NULL);
            }
        }
    }
}

/* A path in a list, relative to the archive's root, that stays beneath it. */
static bool clean_relative(const char *path)
{
    const char *p = path;

    if (!path[0] || path[0] == '/' || strstr(path, "//") || strchr(path, '\\') ||
        strspn(path, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                     "/._+~%:-") != strlen(path))
    {
        return false;
    }
    while (*p)
    {
        size_t n = strcspn(p, "/");

        if (n == 2 && p[0] == '.' && p[1] == '.')
        {
            return false;
        }
        p += n;
        p += *p == '/';
    }
    return true;
}

static void found(void *ctx, const struct rs_baseline_entry *e)
{
    struct run  *r = ctx;
    struct want *w = find_want(r, e->name, e->arch, e->version);
    const char  *filename;

    if (!w)
    {
        w = r->at->snapshot ? NULL : find_name(r, e->name, e->arch);
        if (w && !w->now)
        {
            w->now = rs_xstrdup(e->version);
        }
        return;
    }
    if (w->found || !clean_relative(e->filename))
    {
        return;
    }
    w->found = true;
    w->from_snapshot = r->at->snapshot;
    memcpy(w->sha, e->sha256, RS_SHA256_HEX_SIZE);
    w->size = e->size;
    free(w->url);
    filename = e->filename[0] == '.' && e->filename[1] == '/' ? e->filename + 2 : e->filename;
    w->url = rs_xasprintf("%s%s", r->at->root, filename);
}

static bool hash_fd(int fd, char hex[RS_SHA256_HEX_SIZE], uint64_t *size)
{
    struct rs_sha256 ctx;
    unsigned char    chunk[65536];
    ssize_t          n;

    *size = 0;
    rs_sha256_init(&ctx);
    while ((n = read(fd, chunk, sizeof(chunk))) > 0)
    {
        rs_sha256_update(&ctx, chunk, (size_t)n);
        *size += (uint64_t)n;
    }
    if (n < 0)
    {
        return false;
    }
    rs_sha256_final(&ctx, hex);
    return true;
}

/* Whether the file at `path` is `size` bytes whose SHA-256 is `sha`; with
 * `mode`, given that mode once it is -- through the descriptor it was read
 * by, so it is the same file. */
static bool matches_mode(const char *path, const char *sha, uint64_t size, mode_t mode)
{
    char        got[RS_SHA256_HEX_SIZE];
    uint64_t    len;
    struct stat st;
    int         fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    bool        ok;

    if (fd < 0)
    {
        return false;
    }
    ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && hash_fd(fd, got, &len) && len == size &&
         strcmp(got, sha) == 0 && (mode == 0 || fchmod(fd, mode) == 0);
    (void)close(fd);
    return ok;
}

static bool matches(const char *path, const char *sha, uint64_t size)
{
    return matches_mode(path, sha, size, 0);
}

/* The uncompressed content of the gzip file at `path`. */
static bool gunzip(const char *path, struct rs_buf *out, struct rs_buf *err)
{
    struct rs_gzip gz;
    char           chunk[65536];
    ssize_t        n;
    int            fd = open(path, O_RDONLY | O_CLOEXEC);
    bool           ok;

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    ok = rs_gzip_decompress(fd, &gz, err);
    (void)close(fd);
    if (!ok)
    {
        return false;
    }
    while ((n = read(gz.fd, chunk, sizeof(chunk))) > 0 && out->len < PACKAGES_MAX)
    {
        rs_buf_add(out, chunk, (size_t)n);
    }
    ok = rs_gzip_finish(&gz, n != 0, err) && n == 0;
    if (!ok && err->len == 0)
    {
        rs_buf_addstr(err, "it is larger than restate reads");
    }
    return ok;
}

static bool read_all(const char *path, struct rs_buf *out)
{
    char    chunk[65536];
    ssize_t n;
    int     fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
    {
        return false;
    }
    while ((n = read(fd, chunk, sizeof(chunk))) > 0 && out->len < PACKAGES_MAX)
    {
        rs_buf_add(out, chunk, (size_t)n);
    }
    (void)close(fd);
    return n == 0;
}

/* One list of one group: fetched, checked against the index, and read. */
static void read_list(struct run *r, const struct group *g, const char *base, const char *release,
                      const char *part)
{
    static const char *const names[] = { "Packages.gz", "Packages" };
    size_t                   i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        char               *rel = rs_xasprintf("%s%s", part, names[i]);
        char               *url = rs_xasprintf("%s%s", base, rel);
        char               *dest = rs_xasprintf("%s/list", r->home);
        char                sha[RS_SHA256_HEX_SIZE];
        uint64_t            size;
        struct rs_curl_opts co;
        struct rs_buf       why;
        struct rs_buf       err;
        struct rs_buf       text;
        int                 code = -1;
        bool                ok;

        if (!rs_baseline_release_entry(release, rel, sha, &size))
        {
            free(rel);
            free(url);
            free(dest);
            continue;
        }
        memset(&co, 0, sizeof(co));
        co.plain_http = true;   /* checked by its digest, from the signed index */
        co.max_time = 1800;
        co.netrc = r->netrc;
        rs_buf_init(&why);
        rs_buf_init(&err);
        rs_buf_init(&text);
        ok = rs_curl(url, dest, &co, &code, &why, &err) && code == 0;
        if (!ok)
        {
            say(r, "%s: could not be fetched (%s)", url,
                err.len ? err.data : why.len ? why.data : "curl failed");
        } else if (!matches(dest, sha, size))
        {
            say(r, "%s: not what the repository's signed index says it is; not used", url);
            ok = false;
        } else if (i == 0 ? !gunzip(dest, &text, &err) : !read_all(dest, &text))
        {
            say(r, "%s: could not be read (%s)", url, err.len ? err.data : "too large");
            ok = false;
        }
        if (ok)
        {
            r->at = g;
            rs_baseline_parse_packages(text.data ? text.data : "", text.len, found, r);
        }
        (void)unlink(dest);
        rs_buf_free(&why);
        rs_buf_free(&err);
        rs_buf_free(&text);
        free(rel);
        free(url);
        free(dest);
        return;
    }
    /* A list of Architecture: all packages apart is looked for, not needed. */
    if (!ends_with(part, "binary-all/"))
    {
        say(r, "%s %s: its signed index lists no %sPackages", g->root, g->suite, part);
    }
}

static void read_groups(struct run *r)
{
    int64_t now = (int64_t)time(NULL);
    size_t  i;
    size_t  k;

    for (i = 0; i < r->ng; i++)
    {
        const struct group *g = &r->g[i];
        char               *base = g->flat ? rs_xasprintf("%s%s", g->root, g->suite)
                                           : rs_xasprintf("%sdists/%s", g->root, g->suite);
        char               *dir = with_slash(base);
        struct rs_buf       release;
        struct rs_buf       why;

        rs_buf_init(&release);
        rs_buf_init(&why);
        say(r, "checking %s", dir);
        if (!rs_sources_release(r->apt, g->src, dir, r->home, g->snapshot ? 0 : now, &release,
                                &why))
        {
            say(r, "%s %s: %s", g->root, g->suite, why.data ? why.data : "");
        } else
        {
            for (k = 0; k < g->nparts; k++)
            {
                read_list(r, g, dir, release.data, g->parts[k]);
            }
        }
        rs_buf_free(&release);
        rs_buf_free(&why);
        free(base);
        free(dir);
    }
}

static bool make_dirs(const char *path, struct rs_buf *err)
{
    char  *p = rs_xstrdup(path);
    size_t i;
    size_t n = strlen(p);

    for (i = 1; i <= n; i++)
    {
        if (p[i] == '/' || p[i] == '\0')
        {
            char saved = p[i];

            p[i] = '\0';
            if (mkdir(p, 0755) != 0 && errno != EEXIST)
            {
                rs_buf_addf(err, "%s: %s", p, strerror(errno));
                free(p);
                return false;
            }
            p[i] = saved;
        }
    }
    free(p);
    return true;
}

/* Downloads every package found and not in the cache, a batch at a time,
 * each checked before it is renamed into place. */
static void download(struct run *r)
{
    const char **urls = rs_xcalloc(BATCH, sizeof(*urls));
    const char **dests = rs_xcalloc(BATCH, sizeof(*dests));
    char       **parts = rs_xcalloc(BATCH, sizeof(*parts));
    size_t      *which = rs_xcalloc(BATCH, sizeof(*which));
    size_t       i = 0;

    while (i < r->nw)
    {
        size_t              n = 0;
        size_t              k;
        struct rs_curl_opts co;
        struct rs_buf       why;
        struct rs_buf       err;
        int                 code = -1;

        for (; i < r->nw && n < BATCH; i++)
        {
            struct want *w = &r->w[i];

            if (!w->found || w->done || !w->deb)
            {
                continue;
            }
            parts[n] = rs_xasprintf("%s/%s.part", r->cache, w->deb);
            urls[n] = w->url;
            dests[n] = parts[n];
            which[n++] = i;
        }
        if (n == 0)
        {
            break;
        }
        memset(&co, 0, sizeof(co));
        co.plain_http = true;   /* checked by its digest, from the signed list */
        co.netrc = r->netrc;
        rs_buf_init(&why);
        rs_buf_init(&err);
        if (!rs_curl_many(urls, dests, n, &co, &code, &why, &err))
        {
            say(r, "%s", err.data ? err.data : "curl could not be run");
        }
        for (k = 0; k < n; k++)
        {
            struct want *w = &r->w[which[k]];
            char        *final = rs_xasprintf("%s/%s", r->cache, w->deb);

            if (matches_mode(parts[k], w->sha, w->size, 0644) && rename(parts[k], final) == 0)
            {
                w->done = true;
                r->st->fetched++;
                r->st->snapshot += w->from_snapshot ? 1 : 0;
                r->st->bytes += w->size;
            } else
            {
                struct stat st;
                bool        got = lstat(parts[k], &st) == 0 && st.st_size > 0;

                (void)unlink(parts[k]);
                if (got)
                {
                    say(r, "%s %s (%s): %s is not what its list says it is", w->name,
                        w->version, w->arch, w->url);
                } else
                {
                    say(r, "%s %s (%s): %s could not be downloaded%s", w->name, w->version,
                        w->arch, w->url,
                        r->netrc            ? ""
                        : geteuid() != 0    ? " (a repository that needs a login, as Ubuntu "
                                              "Pro's does, needs restate run as root, to read "
                                              "apt's credentials)"
                                            : " (if it needs a login, apt has none for it in "
                                              "/etc/apt/auth.conf or auth.conf.d)");
                }
            }
            free(final);
            free(parts[k]);
            parts[k] = NULL;
        }
        rs_buf_free(&why);
        rs_buf_free(&err);
    }
    free(urls);
    free(dests);
    free(parts);
    free(which);
}

/* The packages found that the cache already has, checked. */
static void cached(struct run *r)
{
    size_t i;

    for (i = 0; i < r->nw; i++)
    {
        struct want *w = &r->w[i];
        char        *path;

        if (!w->found || w->done || !w->deb)
        {
            continue;
        }
        path = rs_xasprintf("%s/%s", r->cache, w->deb);
        if (matches(path, w->sha, w->size))
        {
            w->done = true;
            r->st->cached++;
        }
        free(path);
    }
}

/* The wanted packages, from the inventory. */
static void wants(struct run *r, const struct rs_jval *pkgs)
{
    size_t i;

    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        const char           *name = rs_jobject_str(p, "name");
        const char           *version = rs_jobject_str(p, "version");
        const char           *arch = rs_jobject_str(p, "architecture");
        const char           *why = rs_jobject_str(p, "unavailable");
        struct want          *w;

        if (!name || !version || !arch)
        {
            continue;
        }
        if (why && strcmp(why, "local") == 0)
        {
            r->st->local++;
            continue;
        }
        /* For another processor: the machine's own packages as that one's
         * builds; a third's, multiarch's, have nothing to be there. */
        if (r->to && strcmp(arch, "all") != 0)
        {
            if (!r->native || strcmp(arch, r->native) != 0)
            {
                r->st->foreign++;
                continue;
            }
            arch = r->to;
        }
        r->st->wanted++;
        r->w = rs_xreallocarray(r->w, r->nw + 1, sizeof(*r->w));
        w = &r->w[r->nw++];
        memset(w, 0, sizeof(*w));
        w->name = name;
        w->version = version;
        w->arch = arch;
        w->dated = dated(p);
        w->labels = rs_jobject_get(p, w->dated ? "superseded_in" : "origins");
        w->deb = rs_baseline_deb_name(name, version, arch);
    }
    if (r->nw > 1)
    {
        qsort(r->w, r->nw, sizeof(*r->w), compare_wants);
    }
}

static void free_wants(struct run *r)
{
    size_t i;

    for (i = 0; i < r->nw; i++)
    {
        free(r->w[i].dated);
        free(r->w[i].deb);
        free(r->w[i].url);
        free(r->w[i].now);
    }
    free(r->w);
}

static const char *native_arch(const struct rs_jval *apt)
{
    const struct rs_jval *archs = rs_jobject_get(apt, "architectures");

    return archs && archs->type == RS_JARRAY && archs->n > 0 && archs->items[0].type == RS_JSTRING
               ? archs->items[0].s
               : NULL;
}

bool rs_baseline_fetch(const struct rs_jval *packages, const struct rs_baseline_opts *o,
                       struct rs_baseline_stats *st, struct rs_buf *err)
{
    struct run r;
    size_t     i;
    size_t     shown = 0;

    memset(st, 0, sizeof(*st));
    memset(&r, 0, sizeof(r));
    r.apt = rs_jobject_get(packages, "apt");
    r.o = o;
    r.st = st;
    r.cache = o->cache ? o->cache : rs_baseline_default_cache();
    r.native = native_arch(r.apt);
    r.to = o->arch && r.native && strcmp(o->arch, r.native) != 0 ? o->arch : NULL;
    if (!r.apt)
    {
        rs_buf_addstr(err, "the inventory has no apt packages");
        return false;
    }
    if (!rs_program_path(RS_PROG_CURL) || !rs_program_path(RS_PROG_GPGV) || !rs_gzip_path())
    {
        rs_buf_addf(err, "fetching packages needs curl, gpgv and gzip (%s is not installed)",
                    !rs_program_path(RS_PROG_CURL) ? "curl"
                    : !rs_program_path(RS_PROG_GPGV) ? "gpgv"
                                                     : "gzip");
        return false;
    }
    if (!make_dirs(r.cache, err))
    {
        return false;
    }
    r.home = rs_pgp_home(err);
    if (!r.home)
    {
        return false;
    }
    r.netrc = netrc_file(r.apt, r.home);
    wants(&r, rs_jobject_get(r.apt, "packages"));
    /* The repositories as they are now, then their snapshots for what they
     * no longer have. */
    plan(&r, false);
    read_groups(&r);
    free_groups(&r);
    plan(&r, true);
    read_groups(&r);
    free_groups(&r);
    cached(&r);
    download(&r);
    for (i = 0; i < r.nw; i++)
    {
        const struct want *w = &r.w[i];

        if (w->done)
        {
            continue;
        }
        st->missing++;
        if (!w->found && shown < 20 && w->now)
        {
            say(&r, "%s %s (%s): gone -- its repository has %s now, and no snapshot restate "
                "could check has this one", w->name, w->version, w->arch, w->now);
            shown++;
        } else if (!w->found && shown < 20)
        {
            say(&r, "%s %s (%s): no repository restate could check has it", w->name,
                w->version, w->arch);
            shown++;
        }
    }
    if (st->missing > shown && shown == 20)
    {
        say(&r, "and %zu more", st->missing - shown);
    }
    rs_pgp_home_remove(r.home);   /* and the credentials with it */
    free(r.netrc);
    free_wants(&r);
    return true;
}

void rs_baseline_list(const struct rs_jval *packages, const char *cache, struct rs_buf *out,
                      struct rs_baseline_stats *st)
{
    const struct rs_jval *pkgs = rs_jobject_get(rs_jobject_get(packages, "apt"), "packages");
    size_t                i;

    memset(st, 0, sizeof(*st));
    cache = cache ? cache : rs_baseline_default_cache();
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        const char           *name = rs_jobject_str(p, "name");
        const char           *version = rs_jobject_str(p, "version");
        const char           *arch = rs_jobject_str(p, "architecture");
        const char           *why = rs_jobject_str(p, "unavailable");
        char                 *deb;
        char                 *path;
        struct stat           sb;
        const char           *state;

        if (!name || !version || !arch)
        {
            continue;
        }
        deb = rs_baseline_deb_name(name, version, arch);
        path = deb ? rs_xasprintf("%s/%s", cache, deb) : NULL;
        if (why && strcmp(why, "local") == 0)
        {
            state = rs_jobject_str(p, "kept") ? "installed from a .deb the image keeps"
                                              : "installed from a .deb no repository has";
            st->local++;
        } else if (path && lstat(path, &sb) == 0 && S_ISREG(sb.st_mode))
        {
            state = "cached";
            st->wanted++;
            st->cached++;
        } else
        {
            state = why ? "to fetch, from the archive's snapshot" : "to fetch";
            st->wanted++;
        }
        rs_buf_addf(out, "%s %s %s\t%s\n", name, version, arch, state);
        free(deb);
        free(path);
    }
}
