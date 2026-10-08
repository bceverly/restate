/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "pkgdb.h"

#include <stdlib.h>
#include <string.h>

#include "index.h"
#include "packages.h"
#include "util.h"

/* dpkg's status file is a few megabytes on a desktop; a package's file list
 * a few hundred kilobytes at most. Anything far past these is not dpkg's. */
#define STATUS_MAX ((size_t)256 * 1024 * 1024)
#define INFO_MAX   ((size_t)64 * 1024 * 1024)
#define DIV_MAX    ((size_t)4 * 1024 * 1024)

void rs_pkgdb_init(struct rs_pkgdb *db)
{
    memset(db, 0, sizeof(*db));
}

void rs_pkgdb_free(struct rs_pkgdb *db)
{
    size_t i;

    for (i = 0; i < db->nnames; i++)
    {
        free(db->names[i]);
    }
    free(db->names);
    for (i = 0; i < db->nfiles; i++)
    {
        free(db->files[i].path);
    }
    free(db->files);
    for (i = 0; i < db->ndiv; i++)
    {
        free(db->div[i].from);
        free(db->div[i].to);
        free(db->div[i].by);
    }
    free(db->div);
    rs_pkgdb_init(db);
}

/* One line of `text` at *p: its start and length, *p moved past it. False
 * at the end. */
static bool next_line(const char **p, const char **line, size_t *len)
{
    if (**p == '\0')
    {
        return false;
    }
    *line = *p;
    *len = strcspn(*p, "\n");
    *p += *len + ((*p)[*len] == '\n' ? 1 : 0);
    return true;
}

/* A package name as Debian allows one -- lowercase letters, digits, "+",
 * "-" and ".", starting with a letter or digit -- optionally followed by
 * ":arch". Anything else is not used to name a file to read. */
static bool good_name(const char *s)
{
    size_t i;
    bool   arch = false;

    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')))
    {
        return false;
    }
    for (i = 1; s[i] != '\0'; i++)
    {
        char c = s[i];

        if (c == ':' && !arch && s[i + 1] != '\0')
        {
            arch = true;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
              (!arch && (c == '+' || c == '.'))))
        {
            return false;
        }
    }
    return i <= 256;
}

/* The name without any ":arch", and its length. */
static size_t bare_len(const char *name)
{
    return strcspn(name, ":");
}

static void add_file(struct rs_pkgdb *db, const char *path, size_t len, uint32_t pkg,
                     unsigned flags, const unsigned char *md5)
{
    struct rs_pkgfile *f;
    char              *copy = rs_xstrndup(path, len);
    size_t             i;
    size_t             blen = bare_len(db->names[pkg]);

    if (copy[0] != '/' || !rs_path_is_clean(copy))
    {
        free(copy);
        return;
    }
    /* A file this package installed that another moved aside is at the
     * diversion's other name. */
    for (i = 0; i < db->ndiv; i++)
    {
        const struct rs_diversion *d = &db->div[i];

        if (strcmp(d->from, copy) == 0 &&
            !(strlen(d->by) == blen && strncmp(d->by, db->names[pkg], blen) == 0))
        {
            free(copy);
            copy = rs_xstrdup(d->to);
            break;
        }
    }
    if (db->nfiles == db->cap)
    {
        db->cap = db->cap ? db->cap * 2 : 1024;
        db->files = rs_xreallocarray(db->files, db->cap, sizeof(*db->files));
    }
    f = &db->files[db->nfiles++];
    memset(f, 0, sizeof(*f));
    f->path = copy;
    f->pkg = pkg;
    f->flags = (unsigned char)flags;
    if (md5)
    {
        memcpy(f->md5, md5, RS_MD5_SIZE);
    }
}

void rs_pkgdb_parse_diversions(struct rs_pkgdb *db, const char *text)
{
    const char *p = text;
    const char *l[3];
    size_t      n[3];

    while (next_line(&p, &l[0], &n[0]) && next_line(&p, &l[1], &n[1]) &&
           next_line(&p, &l[2], &n[2]))
    {
        struct rs_diversion d;

        d.from = rs_xstrndup(l[0], n[0]);
        d.to = rs_xstrndup(l[1], n[1]);
        d.by = rs_xstrndup(l[2], n[2]);
        if (d.from[0] != '/' || !rs_path_is_clean(d.from) || d.to[0] != '/' ||
            !rs_path_is_clean(d.to) || d.by[0] == '\0')
        {
            free(d.from);
            free(d.to);
            free(d.by);
            continue;
        }
        db->div = rs_xreallocarray(db->div, db->ndiv + 1, sizeof(*db->div));
        db->div[db->ndiv++] = d;
    }
}

/* What one stanza of the status file says. */
struct stanza {
    char       *package;
    char       *arch;
    bool        same;        /* Multi-Arch: same, so its files are "name:arch" */
    bool        installed;   /* its files are on disk */
    const char *conffiles;   /* the continuation lines after "Conffiles:" */
    size_t      nconffiles;
};

static void stanza_free(struct stanza *s)
{
    free(s->package);
    free(s->arch);
    memset(s, 0, sizeof(*s));
}

/* " /etc/x DIGEST" or " /etc/x DIGEST obsolete": read from the right, since
 * nothing stops a path holding a space. */
static void conffile(struct rs_pkgdb *db, uint32_t pkg, const char *line, size_t len)
{
    unsigned      flags = RS_PKGFILE_CONFFILE;
    unsigned char md5[RS_MD5_SIZE];
    size_t        end = len;
    size_t        sp;

    while (end > 0 && line[end - 1] == ' ')
    {
        end--;
    }
    for (;;)
    {
        sp = end;
        while (sp > 0 && line[sp - 1] != ' ')
        {
            sp--;
        }
        if (sp == 0)
        {
            return;
        }
        if (end - sp == 8 && strncmp(line + sp, "obsolete", 8) == 0)
        {
            flags |= RS_PKGFILE_OBSOLETE;
        } else if (!(end - sp == 17 && strncmp(line + sp, "remove-on-upgrade", 17) == 0))
        {
            break;
        }
        end = sp - 1;
    }
    /* "newconffile": installed, not yet configured, no digest to compare. */
    if (rs_md5_parse_hex(line + sp, end - sp, md5))
    {
        flags |= RS_PKGFILE_MD5;
    }
    end = sp - 1;
    sp = 0;
    while (sp < end && line[sp] == ' ')
    {
        sp++;
    }
    add_file(db, line + sp, end - sp, pkg, flags, (flags & RS_PKGFILE_MD5) ? md5 : NULL);
}

static size_t finish_stanza(struct rs_pkgdb *db, struct stanza *s)
{
    char       *name;
    uint32_t    pkg;
    const char *p;
    const char *line;
    size_t      len;

    if (!s->installed || !s->package)
    {
        return 0;
    }
    name = (s->same && s->arch) ? rs_xasprintf("%s:%s", s->package, s->arch)
                                : rs_xstrdup(s->package);
    if (!good_name(name) || db->nnames >= UINT32_MAX)
    {
        free(name);
        return 0;
    }
    pkg = (uint32_t)db->nnames;
    db->names = rs_xreallocarray(db->names, db->nnames + 1, sizeof(*db->names));
    db->names[db->nnames++] = name;
    if (s->conffiles)
    {
        char *block = rs_xstrndup(s->conffiles, s->nconffiles);

        p = block;
        while (next_line(&p, &line, &len))
        {
            conffile(db, pkg, line, len);
        }
        free(block);
    }
    return 1;
}

/* The value after "Field:" on `line`, if it is that field. */
static bool field(const char *line, size_t len, const char *name, const char **value,
                  size_t *vlen)
{
    size_t n = strlen(name);

    if (len <= n || strncmp(line, name, n) != 0 || line[n] != ':')
    {
        return false;
    }
    *value = line + n + 1;
    *vlen = len - n - 1;
    while (*vlen > 0 && (**value == ' ' || **value == '\t'))
    {
        (*value)++;
        (*vlen)--;
    }
    while (*vlen > 0 && ((*value)[*vlen - 1] == ' ' || (*value)[*vlen - 1] == '\r'))
    {
        (*vlen)--;
    }
    return true;
}

size_t rs_pkgdb_parse_status(struct rs_pkgdb *db, const char *text)
{
    struct stanza s;
    const char   *p = text;
    const char   *line;
    size_t        len;
    size_t        added = 0;
    bool          in_conffiles = false;

    memset(&s, 0, sizeof(s));
    while (next_line(&p, &line, &len))
    {
        const char *v;
        size_t      vlen;

        if (len == 0 || (len == 1 && line[0] == '\r'))
        {
            added += finish_stanza(db, &s);
            stanza_free(&s);
            in_conffiles = false;
            continue;
        }
        if (line[0] == ' ' || line[0] == '\t')
        {
            if (in_conffiles)
            {
                s.nconffiles = (size_t)(line + len - s.conffiles);
            }
            continue;
        }
        in_conffiles = false;
        if (field(line, len, "Package", &v, &vlen))
        {
            free(s.package);
            s.package = rs_xstrndup(v, vlen);
        } else if (field(line, len, "Architecture", &v, &vlen))
        {
            free(s.arch);
            s.arch = rs_xstrndup(v, vlen);
        } else if (field(line, len, "Multi-Arch", &v, &vlen))
        {
            s.same = vlen == 4 && strncmp(v, "same", 4) == 0;
        } else if (field(line, len, "Status", &v, &vlen))
        {
            /* "WANT ok STATE": every state but these has files on disk;
             * "config-files" has only conffiles left, which no reinstall
             * puts back, so they count as nobody's. */
            const char *state = v + vlen;

            while (state > v && state[-1] != ' ')
            {
                state--;
            }
            vlen -= (size_t)(state - v);
            s.installed = vlen > 0 &&
                          !(vlen == 13 && strncmp(state, "not-installed", 13) == 0) &&
                          !(vlen == 12 && strncmp(state, "config-files", 12) == 0);
        } else if (field(line, len, "Conffiles", &v, &vlen))
        {
            in_conffiles = true;
            s.conffiles = p;
            s.nconffiles = 0;
        }
    }
    added += finish_stanza(db, &s);
    stanza_free(&s);
    return added;
}

void rs_pkgdb_parse_md5sums(struct rs_pkgdb *db, uint32_t pkg, const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;

    if (pkg >= db->nnames)
    {
        return;
    }
    while (next_line(&p, &line, &len))
    {
        unsigned char md5[RS_MD5_SIZE];
        size_t        at = RS_MD5_SIZE * 2;
        char         *path;

        /* "DIGEST  PATH", PATH relative; md5sum's "DIGEST *PATH" as well. */
        if (len < at + 2 || !rs_md5_parse_hex(line, at, md5) || line[at] != ' ')
        {
            continue;
        }
        at++;
        if (line[at] == ' ' || line[at] == '*')
        {
            at++;
        }
        if (at >= len)
        {
            continue;
        }
        path = rs_xasprintf("/%.*s", (int)(len - at), line + at);
        add_file(db, path, strlen(path), pkg, RS_PKGFILE_MD5, md5);
        free(path);
    }
}

void rs_pkgdb_parse_list(struct rs_pkgdb *db, uint32_t pkg, const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;

    if (pkg >= db->nnames)
    {
        return;
    }
    while (next_line(&p, &line, &len))
    {
        /* "/." heads every list: the root, which every package "owns". */
        if (len > 2 && line[0] == '/')
        {
            add_file(db, line, len, pkg, 0, NULL);
        }
    }
}

/* By path; for one path, by package, the entry with a digest first. */
static int file_cmp(const void *a, const void *b)
{
    const struct rs_pkgfile *x = a;
    const struct rs_pkgfile *y = b;
    int                      c = strcmp(x->path, y->path);

    if (c != 0)
    {
        return c;
    }
    if (x->pkg != y->pkg)
    {
        return x->pkg < y->pkg ? -1 : 1;
    }
    return (int)(y->flags & RS_PKGFILE_MD5) - (int)(x->flags & RS_PKGFILE_MD5);
}

void rs_pkgdb_sort(struct rs_pkgdb *db)
{
    size_t in;
    size_t out = 0;

    if (db->nfiles == 0)
    {
        return;
    }
    qsort(db->files, db->nfiles, sizeof(*db->files), file_cmp);
    /* A file is in its package's list and its md5sums, or its list and its
     * conffiles: one entry each, the one with the digest. */
    for (in = 0; in < db->nfiles; in++)
    {
        if (out > 0 && db->files[out - 1].pkg == db->files[in].pkg &&
            strcmp(db->files[out - 1].path, db->files[in].path) == 0)
        {
            free(db->files[in].path);
            continue;
        }
        db->files[out++] = db->files[in];
    }
    db->nfiles = out;
}

static size_t find(const struct rs_pkgdb *db, const char *path, const struct rs_pkgfile **out)
{
    size_t lo = 0;
    size_t hi = db->nfiles;
    size_t n = 0;

    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;

        if (strcmp(db->files[mid].path, path) < 0)
        {
            lo = mid + 1;
        } else
        {
            hi = mid;
        }
    }
    while (lo + n < db->nfiles && strcmp(db->files[lo + n].path, path) == 0)
    {
        n++;
    }
    *out = n ? &db->files[lo] : NULL;
    return n;
}

size_t rs_pkgdb_lookup(const struct rs_pkgdb *db, const char *path,
                       const struct rs_pkgfile **out)
{
    static const char *const merged[] = { "/bin/", "/sbin/", "/lib/", "/lib32/",
                                          "/lib64/", "/libx32/" };
    size_t                   n = find(db, path, out);
    size_t                   i;

    for (i = 0; n == 0 && i < sizeof(merged) / sizeof(merged[0]); i++)
    {
        char *other = NULL;

        if (rs_starts_with(path, merged[i]))
        {
            other = rs_xasprintf("/usr%s", path);
        } else if (rs_starts_with(path, "/usr") && rs_starts_with(path + 4, merged[i]))
        {
            other = rs_xstrdup(path + 4);
        }
        if (other)
        {
            n = find(db, other, out);
            free(other);
        }
    }
    return n;
}

const char *rs_pkgdb_package(const struct rs_pkgdb *db, const struct rs_pkgfile *f,
                             size_t *len)
{
    const char *name = db->names[f->pkg];

    *len = bare_len(name);
    return name;
}

bool rs_pkgdb_load(struct rs_pkgdb *db, const char *root)
{
    struct rs_buf text;
    size_t        i;

    rs_pkgdb_init(db);
    if (rs_read_beneath(root, "/var/lib/dpkg/diversions", DIV_MAX, &text))
    {
        rs_pkgdb_parse_diversions(db, text.data);
        rs_buf_free(&text);
    }
    if (!rs_read_beneath(root, "/var/lib/dpkg/status", STATUS_MAX, &text))
    {
        rs_pkgdb_free(db);
        return false;
    }
    (void)rs_pkgdb_parse_status(db, text.data);
    rs_buf_free(&text);
    for (i = 0; i < db->nnames; i++)
    {
        static const char *const kinds[] = { "md5sums", "list" };
        size_t                   k;

        for (k = 0; k < 2; k++)
        {
            char *rel = rs_xasprintf("/var/lib/dpkg/info/%s.%s", db->names[i], kinds[k]);

            if (rs_read_beneath(root, rel, INFO_MAX, &text))
            {
                if (k == 0)
                {
                    rs_pkgdb_parse_md5sums(db, (uint32_t)i, text.data);
                } else
                {
                    rs_pkgdb_parse_list(db, (uint32_t)i, text.data);
                }
                rs_buf_free(&text);
            }
            free(rel);
        }
    }
    rs_pkgdb_sort(db);
    if (db->nfiles == 0)
    {
        rs_pkgdb_free(db);
        return false;
    }
    return true;
}
