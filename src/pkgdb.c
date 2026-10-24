/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "pkgdb.h"

#include <stdlib.h>
#include <string.h>

#include "blake2b.h"
#include "index.h"
#include "json.h"
#include "packages.h"
#include "run.h"
#include "util.h"

/* dpkg's status file is a few megabytes on a desktop; a package's file list
 * a few hundred kilobytes at most. Anything far past these is not dpkg's. */
#define STATUS_MAX ((size_t)256 * 1024 * 1024)
#define INFO_MAX   ((size_t)64 * 1024 * 1024)
#define DIV_MAX    ((size_t)4 * 1024 * 1024)
/* A BSD package's +CONTENTS: a few megabytes for the largest (TeX Live's). */
#define CONTENTS_MAX ((size_t)64 * 1024 * 1024)

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
    for (i = 0; i < db->nscopes; i++)
    {
        free(db->scopes[i]);
    }
    free(db->scopes);
    for (i = 0; i < db->nunscoped; i++)
    {
        free(db->unscoped[i]);
    }
    free(db->unscoped);
    rs_pkgdb_init(db);
}

size_t rs_pkgdigest_size(unsigned kind)
{
    return kind == RS_PKGDIGEST_MD5    ? RS_MD5_SIZE
           : kind == RS_PKGDIGEST_SHA1 ? RS_SHA1_SIZE
           : kind == RS_PKGDIGEST_SHA256 || kind == RS_PKGDIGEST_BLAKE2B ? RS_SHA256_SIZE
                                                                         : 0;
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

/* Adds `path` to package `pkg`, with its digest of kind `kind` if any; false
 * if the path is not one to add. */
static bool add_file(struct rs_pkgdb *db, const char *path, size_t len, uint32_t pkg,
                     unsigned flags, unsigned kind, const unsigned char *digest)
{
    struct rs_pkgfile *f;
    char              *copy = rs_xstrndup(path, len);
    size_t             i;
    size_t             blen = bare_len(db->names[pkg]);

    if (copy[0] != '/' || !rs_path_is_clean(copy))
    {
        free(copy);
        return false;
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
    if (digest && rs_pkgdigest_size(kind) > 0)
    {
        f->digest_kind = (unsigned char)kind;
        memcpy(f->digest, digest, rs_pkgdigest_size(kind));
    }
    return true;
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
    bool          have;
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
    have = rs_md5_parse_hex(line + sp, end - sp, md5);
    end = sp - 1;
    sp = 0;
    while (sp < end && line[sp] == ' ')
    {
        sp++;
    }
    (void)add_file(db, line + sp, end - sp, pkg, flags, RS_PKGDIGEST_MD5, have ? md5 : NULL);
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
        (void)add_file(db, path, strlen(path), pkg, 0, RS_PKGDIGEST_MD5, md5);
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
            (void)add_file(db, line, len, pkg, 0, RS_PKGDIGEST_NONE, NULL);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* OpenBSD's and pkgsrc's +CONTENTS                                          */
/* ------------------------------------------------------------------------- */

/* Whether `line` (`len` long) is the command `cmd` ("@cwd"), followed by its
 * argument or nothing; the argument into *arg, *alen. */
static bool command(const char *line, size_t len, const char *cmd, const char **arg,
                    size_t *alen)
{
    size_t n = strlen(cmd);

    if (len < n || strncmp(line, cmd, n) != 0 || (len > n && line[n] != ' '))
    {
        return false;
    }
    *arg = line + n + (len > n ? 1 : 0);
    *alen = len > n ? len - n - 1 : 0;
    return true;
}

/* A package's name from "@name NAME-VERSION": up to the first '-' before a
 * digit, as both systems split one. NULL if it is not a name to use: a
 * name names files nowhere, but is said in an index, so it is held to
 * printable characters, and no ':', which marks an architecture. */
static char *stem(const char *arg, size_t len)
{
    size_t i;
    size_t end = len;

    for (i = 1; i + 1 < len; i++)
    {
        if (arg[i] == '-' && arg[i + 1] >= '0' && arg[i + 1] <= '9')
        {
            end = i;
            break;
        }
    }
    if (end == 0 || end > 256 || arg[0] == '-')
    {
        return NULL;
    }
    for (i = 0; i < end; i++)
    {
        if (arg[i] <= ' ' || arg[i] > '~' || arg[i] == ':' || arg[i] == '/')
        {
            return NULL;
        }
    }
    return rs_xstrndup(arg, end);
}

/* A directory packages put files in, once: not "/", whose files are the
 * system's as well. */
static void add_scope(struct rs_pkgdb *db, const char *dir)
{
    size_t i;

    if (strcmp(dir, "/") == 0)
    {
        return;
    }
    for (i = 0; i < db->nscopes; i++)
    {
        if (strcmp(db->scopes[i], dir) == 0)
        {
            return;
        }
    }
    db->scopes = rs_xreallocarray(db->scopes, db->nscopes + 1, sizeof(*db->scopes));
    db->scopes[db->nscopes++] = rs_xstrdup(dir);
}

/* `rel` (`len` long) beneath `cwd`, or itself if it is absolute. */
static char *beneath_cwd(const char *cwd, const char *rel, size_t len)
{
    if (len > 0 && rel[0] == '/')
    {
        return rs_xstrndup(rel, len);
    }
    return rs_xasprintf("%s%s%.*s", cwd, strcmp(cwd, "/") == 0 ? "" : "/", (int)len, rel);
}

/* A file's annotation, OpenBSD's: "@bin PATH", "@man PATH" and the rest
 * are files as a plain line is. */
static bool file_line(const char *line, size_t len, const char **path, size_t *plen)
{
    static const char *const kinds[] = { "@bin",  "@file", "@info", "@lib", "@man",
                                         "@shell", "@so",  "@static-lib" };
    size_t                   i;

    if (len > 0 && line[0] != '@')
    {
        *path = line;
        *plen = len;
        return true;
    }
    for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
    {
        if (command(line, len, kinds[i], path, plen) && *plen > 0)
        {
            return true;
        }
    }
    return false;
}

/* rs_pkgdb_parse_contents, with the package's first directory into *prefix
 * (freed by the caller), or NULL. */
static bool parse_contents(struct rs_pkgdb *db, const char *text, char **prefix)
{
    const char *p = text;
    const char *line;
    size_t      len;
    char       *cwd = NULL;
    char       *name = NULL;
    uint32_t    pkg = 0;
    size_t      last = SIZE_MAX;     /* the file a digest after it is of */
    bool        ignore = false;
    bool        named;

    db->scoped = true;
    while (next_line(&p, &line, &len))
    {
        const char *arg;
        size_t      alen;

        if (ignore)
        {
            /* "@ignore": the next line is the package's own file, not one it
             * installs (pkgsrc's +BUILD_INFO and the rest). */
            ignore = false;
            continue;
        }
        if (!name && !command(line, len, "@cwd", &arg, &alen))
        {
            /* No file before the package is named; its directory (pkgsrc's
             * "@cwd", first of all) may be. */
            if (command(line, len, "@name", &arg, &alen) && db->nnames < UINT32_MAX)
            {
                name = stem(arg, alen);
                if (!name)
                {
                    break;
                }
                pkg = (uint32_t)db->nnames;
                db->names = rs_xreallocarray(db->names, db->nnames + 1, sizeof(*db->names));
                db->names[db->nnames++] = rs_xstrdup(name);
            }
            continue;
        }
        if (command(line, len, "@cwd", &arg, &alen) || command(line, len, "@src", &arg, &alen))
        {
            char *dir = rs_xstrndup(arg, alen);

            free(cwd);
            cwd = NULL;
            last = SIZE_MAX;
            if (dir[0] == '/' && rs_path_is_clean(dir))
            {
                cwd = dir;
                if (!*prefix)
                {
                    *prefix = rs_xstrdup(dir);
                }
            } else
            {
                free(dir);
            }
        } else if (command(line, len, "@ignore", &arg, &alen))
        {
            ignore = true;
            last = SIZE_MAX;
        } else if (command(line, len, "@sha", &arg, &alen))
        {
            struct rs_buf raw;

            rs_buf_init(&raw);
            if (last != SIZE_MAX && rs_base64_decode(arg, alen, &raw) &&
                raw.len == RS_SHA256_SIZE)
            {
                db->files[last].digest_kind = RS_PKGDIGEST_SHA256;
                memcpy(db->files[last].digest, raw.data, RS_SHA256_SIZE);
            }
            rs_buf_free(&raw);
        } else if (command(line, len, "@comment", &arg, &alen))
        {
            unsigned char md5[RS_MD5_SIZE];

            if (last != SIZE_MAX && alen == 4 + RS_MD5_SIZE * 2 && strncmp(arg, "MD5:", 4) == 0 &&
                rs_md5_parse_hex(arg + 4, RS_MD5_SIZE * 2, md5))
            {
                db->files[last].digest_kind = RS_PKGDIGEST_MD5;
                memcpy(db->files[last].digest, md5, RS_MD5_SIZE);
            }
        } else if (command(line, len, "@sample", &arg, &alen))
        {
            /* A configuration file, copied from the example before it when
             * the package was installed: as it was installed, it is the
             * package's; changed, it is the machine's. A directory made the
             * same way ("@sample DIR/") has nothing to compare. */
            if (cwd && alen > 0 && arg[alen - 1] != '/')
            {
                char         *path = beneath_cwd(cwd, arg, alen);
                const bool    from = last != SIZE_MAX;
                unsigned      kind = from ? db->files[last].digest_kind : RS_PKGDIGEST_NONE;
                unsigned char digest[RS_SHA256_SIZE];

                if (from)
                {
                    memcpy(digest, db->files[last].digest, sizeof(digest));
                }
                (void)add_file(db, path, strlen(path), pkg, RS_PKGFILE_CONFFILE, kind,
                               from ? digest : NULL);
                free(path);
            }
            last = SIZE_MAX;
        } else if (file_line(line, len, &arg, &alen))
        {
            char *path;

            last = SIZE_MAX;
            if (!cwd)
            {
                continue;
            }
            path = beneath_cwd(cwd, arg, alen);
            if (add_file(db, path, strlen(path), pkg, 0, RS_PKGDIGEST_NONE, NULL))
            {
                last = db->nfiles - 1;
                add_scope(db, cwd);
            }
            free(path);
        }
        /* Everything else -- @size, @ts, @mode, @owner, @dir, @pkgdep and the
         * rest -- says nothing of a file's content. */
    }
    named = name != NULL;
    free(cwd);
    free(name);
    return named;
}

bool rs_pkgdb_parse_contents(struct rs_pkgdb *db, const char *text)
{
    char *prefix = NULL;
    bool  named = parse_contents(db, text, &prefix);

    free(prefix);
    return named;
}

/* The next word of `line` at *at, as a pointer and length; false if there is
 * none. */
static bool word(const char *line, size_t len, size_t *at, const char **w, size_t *wlen)
{
    while (*at < len && line[*at] == ' ')
    {
        (*at)++;
    }
    if (*at >= len)
    {
        return false;
    }
    *w = line + *at;
    while (*at < len && line[*at] != ' ')
    {
        (*at)++;
    }
    *wlen = (size_t)(line + *at - *w);
    return true;
}

void rs_pkgdb_parse_install(struct rs_pkgdb *db, uint32_t pkg, const char *prefix,
                            const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;

    if (pkg >= db->nnames || prefix[0] != '/')
    {
        return;
    }
    while (next_line(&p, &line, &len))
    {
        const char *target;
        const char *flags;
        const char *source;
        size_t      tlen;
        size_t      flen;
        size_t      slen;
        size_t      at = 7;
        char       *from;
        char       *to;
        size_t      i;

        /* "# FILE: TARGET FLAGS SOURCE MODE...": a copy ('c' among FLAGS)
         * of SOURCE, each beneath the prefix unless it is absolute. */
        if (len <= at || strncmp(line, "# FILE:", at) != 0 ||
            !word(line, len, &at, &target, &tlen) || !word(line, len, &at, &flags, &flen) ||
            !word(line, len, &at, &source, &slen) || !memchr(flags, 'c', flen))
        {
            continue;
        }
        from = beneath_cwd(prefix, source, slen);
        to = beneath_cwd(prefix, target, tlen);
        /* The package's own files are the last added. */
        for (i = db->nfiles; i > 0 && db->files[i - 1].pkg == pkg; i--)
        {
            const struct rs_pkgfile *f = &db->files[i - 1];

            if (f->digest_kind != RS_PKGDIGEST_NONE && strcmp(f->path, from) == 0)
            {
                unsigned char digest[RS_SHA256_SIZE];
                unsigned      kind = f->digest_kind;

                memcpy(digest, f->digest, sizeof(digest));
                (void)add_file(db, to, strlen(to), pkg, RS_PKGFILE_CONFFILE, kind, digest);
                break;
            }
        }
        free(from);
        free(to);
    }
}

/* By path; for one path, by package, the entry with a digest first. */
/* ------------------------------------------------------------------------- */

/* `line`'s first `n` tab-separated fields: false if it has fewer. The last
 * runs to the end of the line, tabs and all -- a path, which may have one. */
static bool fields(const char *line, size_t len, size_t n, const char **f, size_t *flen)
{
    size_t at = 0;
    size_t i;

    for (i = 0; i < n; i++)
    {
        const char *tab = i + 1 < n ? memchr(line + at, '\t', len - at) : NULL;

        if (i + 1 < n && !tab)
        {
            return false;
        }
        f[i] = line + at;
        flen[i] = tab ? (size_t)(tab - f[i]) : len - at;
        at += flen[i] + (tab ? 1 : 0);
    }
    return true;
}

/* The package `name` (`len` long) as an index into names: the last one
 * again -- each tool lists a package's files together -- or a new one.
 * UINT32_MAX for a name not to use: as stem() holds a BSD's to. */
static uint32_t package_at(struct rs_pkgdb *db, const char *name, size_t len)
{
    size_t i;

    if (db->nnames > 0 && strncmp(db->names[db->nnames - 1], name, len) == 0 &&
        db->names[db->nnames - 1][len] == '\0')
    {
        return (uint32_t)(db->nnames - 1);
    }
    if (len == 0 || len > 256 || db->nnames >= UINT32_MAX)
    {
        return UINT32_MAX;
    }
    for (i = 0; i < len; i++)
    {
        if (name[i] <= ' ' || name[i] > '~' || name[i] == ':' || name[i] == '/')
        {
            return UINT32_MAX;
        }
    }
    db->names = rs_xreallocarray(db->names, db->nnames + 1, sizeof(*db->names));
    db->names[db->nnames++] = rs_xstrndup(name, len);
    return (uint32_t)(db->nnames - 1);
}

/* `len` hex digits, either case, into `len / 2` bytes. */
static bool hex_bytes(const char *s, size_t len, unsigned char *out)
{
    size_t i;

    if (len % 2 != 0)
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        char     c = s[i];
        unsigned v;

        if (c >= '0' && c <= '9')
        {
            v = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f')
        {
            v = (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F')
        {
            v = (unsigned)(c - 'A' + 10);
        } else
        {
            return false;
        }
        out[i / 2] = (unsigned char)(i % 2 == 0 ? v << 4 : (out[i / 2] | v));
    }
    return true;
}

/* pkg's base32: its own alphabet, five bits a character, the least
 * significant first. Exactly `n` bytes, or false. */
static bool pkg_base32(const char *s, size_t len, unsigned char *out, size_t n)
{
    static const char alphabet[] = "ybndrfg8ejkmcpqxot1uwisza345h769";
    uint32_t          acc = 0;
    unsigned          bits = 0;
    size_t            got = 0;
    size_t            i;

    for (i = 0; i < len; i++)
    {
        const char *at = s[i] ? strchr(alphabet, s[i]) : NULL;

        if (!at)
        {
            return false;
        }
        acc |= (uint32_t)(at - alphabet) << bits;
        bits += 5;
        if (bits >= 8)
        {
            if (got == n)
            {
                return false;
            }
            out[got++] = (unsigned char)acc;
            acc >>= 8;
            bits -= 8;
        }
    }
    return got == n && acc == 0;
}

size_t rs_pkgdb_parse_pkg(struct rs_pkgdb *db, const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;
    size_t      added = 0;

    db->scoped = true;
    while (next_line(&p, &line, &len))
    {
        const char   *f[4];
        size_t        fl[4];
        unsigned char raw[RS_BLAKE2B_SIZE];
        unsigned      kind = RS_PKGDIGEST_NONE;
        uint32_t      pkg;

        if (!fields(line, len, 4, f, fl))
        {
            continue;
        }
        /* The sum: "1$" SHA-256, "2$" BLAKE2b; one of a kind not known
         * compares nothing. */
        if (fl[2] == 2 + RS_SHA256_HEX_LEN && strncmp(f[2], "1$", 2) == 0 &&
            hex_bytes(f[2] + 2, RS_SHA256_HEX_LEN, raw))
        {
            kind = RS_PKGDIGEST_SHA256;
        } else if (fl[2] > 2 && strncmp(f[2], "2$", 2) == 0 &&
                   pkg_base32(f[2] + 2, fl[2] - 2, raw, RS_BLAKE2B_SIZE))
        {
            kind = RS_PKGDIGEST_BLAKE2B;
        }
        pkg = package_at(db, f[0], fl[0]);
        if (pkg == UINT32_MAX)
        {
            continue;
        }
        if (add_file(db, f[3], fl[3], pkg, 0, kind, kind != RS_PKGDIGEST_NONE ? raw : NULL))
        {
            char *prefix = rs_xstrndup(f[1], fl[1]);

            added++;
            if (prefix[0] == '/' && rs_path_is_clean(prefix))
            {
                add_scope(db, prefix);
            }
            free(prefix);
        }
    }
    return added;
}

size_t rs_pkgdb_parse_rpm(struct rs_pkgdb *db, const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;
    size_t      added = 0;

    while (next_line(&p, &line, &len))
    {
        const char   *f[6];
        size_t        fl[6];
        unsigned char raw[RS_SHA256_SIZE];
        unsigned      kind = RS_PKGDIGEST_NONE;
        unsigned      flags = 0;
        unsigned long fileflags;
        char         *end;
        char          num[16];
        uint32_t      pkg;
        bool          ghost;
        bool          md5;

        /* Installed as it is: not a file left out (--excludedocs, another
         * architecture's), or one another package's replaced. */
        if (!fields(line, len, 6, f, fl) || fl[3] != 1 || f[3][0] != '0' || fl[2] == 0 ||
            fl[2] >= sizeof(num))
        {
            continue;
        }
        memcpy(num, f[2], fl[2]);
        num[fl[2]] = '\0';
        fileflags = strtoul(num, &end, 10);
        if (*end != '\0')
        {
            continue;
        }
        /* SHA-256 (8) or MD5 (1, and an rpm that says none at all); a
         * ghost (64) is the package's to name, but none of its content. */
        ghost = (fileflags & 64u) != 0;
        md5 = (fl[1] == 1 && f[1][0] == '1') || (fl[1] == 6 && strncmp(f[1], "(none)", 6) == 0);
        if (!ghost && fl[4] == RS_SHA256_HEX_LEN && fl[1] == 1 && f[1][0] == '8' &&
            hex_bytes(f[4], fl[4], raw))
        {
            kind = RS_PKGDIGEST_SHA256;
        } else if (!ghost && fl[4] == RS_MD5_SIZE * 2 && md5 && hex_bytes(f[4], fl[4], raw))
        {
            kind = RS_PKGDIGEST_MD5;
        }
        if (fileflags & 1u)
        {
            flags |= RS_PKGFILE_CONFFILE;
        }
        pkg = package_at(db, f[0], fl[0]);
        if (pkg != UINT32_MAX &&
            add_file(db, f[5], fl[5], pkg, flags, kind, kind != RS_PKGDIGEST_NONE ? raw : NULL))
        {
            added++;
        }
    }
    return added;
}

/* An mtree path, its "\ooo" escapes undone: NULL if it holds a NUL. */
static char *mtree_path(const char *s, size_t len)
{
    char  *out = rs_xstrndup(s, len);
    size_t i;
    size_t k = 0;

    for (i = 0; i < len; i++)
    {
        if (s[i] == '\\' && i + 3 < len && s[i + 1] >= '0' && s[i + 1] <= '3' &&
            s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7')
        {
            out[k++] = (char)(((s[i + 1] - '0') << 6) | ((s[i + 2] - '0') << 3) |
                              (s[i + 3] - '0'));
            i += 3;
        } else
        {
            out[k++] = s[i];
        }
    }
    out[k] = '\0';
    if (strlen(out) != k)
    {
        free(out);
        return NULL;
    }
    return out;
}

void rs_pkgdb_parse_mtree(struct rs_pkgdb *db, uint32_t pkg, const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;
    bool        file_by_default = true;

    if (pkg >= db->nnames)
    {
        return;
    }
    while (next_line(&p, &line, &len))
    {
        size_t        at = 0;
        const char   *w;
        size_t        wlen;
        const char   *sha = NULL;
        bool          file;
        bool          set;
        char         *path;

        if (!word(line, len, &at, &w, &wlen))
        {
            continue;
        }
        set = wlen == 4 && strncmp(w, "/set", 4) == 0;
        /* Only "./PATH": not "/set" and the rest, not a comment, and not
         * pacman's own ./.PKGINFO, ./.BUILDINFO and ./.MTREE. */
        if (!set && (wlen < 3 || strncmp(w, "./", 2) != 0 ||
                     (w[2] == '.' && !memchr(w + 2, '/', wlen - 2))))
        {
            continue;
        }
        path = set ? NULL : mtree_path(w + 1, wlen - 1);
        file = file_by_default;
        while (word(line, len, &at, &w, &wlen))
        {
            if (wlen > 5 && strncmp(w, "type=", 5) == 0)
            {
                file = wlen == 9 && strncmp(w + 5, "file", 4) == 0;
            } else if (wlen == 13 + RS_SHA256_HEX_LEN && strncmp(w, "sha256digest=", 13) == 0)
            {
                sha = w + 13;
            }
        }
        if (set)
        {
            file_by_default = file;
            continue;
        }
        if (path)
        {
            unsigned char raw[RS_SHA256_SIZE];
            bool          known = file && sha && hex_bytes(sha, RS_SHA256_HEX_LEN, raw);

            (void)add_file(db, path, strlen(path), pkg, 0,
                           known ? RS_PKGDIGEST_SHA256 : RS_PKGDIGEST_NONE, known ? raw : NULL);
            free(path);
        }
    }
}

size_t rs_pkgdb_parse_apk(struct rs_pkgdb *db, const char *text)
{
    const char *p = text;
    const char *line;
    size_t      len;
    uint32_t    pkg = UINT32_MAX;
    char       *dir = NULL;
    size_t      last = SIZE_MAX;   /* the file a "Z:" after it is of */
    size_t      added = 0;

    while (next_line(&p, &line, &len))
    {
        if (len < 2 || line[1] != ':')
        {
            /* A blank line ends a package. */
            pkg = len == 0 ? UINT32_MAX : pkg;
            last = SIZE_MAX;
            continue;
        }
        if (line[0] == 'P')
        {
            pkg = package_at(db, line + 2, len - 2);
            free(dir);
            dir = NULL;
            last = SIZE_MAX;
        } else if (line[0] == 'F')
        {
            free(dir);
            dir = rs_xstrndup(line + 2, len - 2);
            last = SIZE_MAX;
        } else if (line[0] == 'R' && pkg != UINT32_MAX)
        {
            /* Relative to the "F:" before it, or to the root. */
            char *path = rs_xasprintf("/%s%s%.*s", dir ? dir : "", dir && dir[0] ? "/" : "",
                                      (int)(len - 2), line + 2);

            last = SIZE_MAX;
            if (add_file(db, path, strlen(path), pkg, 0, RS_PKGDIGEST_NONE, NULL))
            {
                last = db->nfiles - 1;
                added++;
            }
            free(path);
        } else if (line[0] == 'Z' && last != SIZE_MAX && len > 4 && line[2] == 'Q')
        {
            struct rs_buf raw;

            rs_buf_init(&raw);
            if (rs_base64_decode(line + 4, len - 4, &raw))
            {
                unsigned kind = line[3] == '1' && raw.len == RS_SHA1_SIZE     ? RS_PKGDIGEST_SHA1
                                : line[3] == '2' && raw.len == RS_SHA256_SIZE ? RS_PKGDIGEST_SHA256
                                                                              : RS_PKGDIGEST_NONE;

                if (kind != RS_PKGDIGEST_NONE)
                {
                    db->files[last].digest_kind = (unsigned char)kind;
                    memcpy(db->files[last].digest, raw.data, raw.len);
                }
            }
            rs_buf_free(&raw);
            last = SIZE_MAX;
        }
    }
    free(dir);
    return added;
}

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
    return (y->digest_kind != RS_PKGDIGEST_NONE) - (x->digest_kind != RS_PKGDIGEST_NONE);
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
     * conffiles: one entry each, the one with the digest. (A BSD package
     * lists a file once.) */
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

/* Whether `path` is `dir` or beneath it. */
static bool within(const char *path, const char *dir)
{
    size_t n = strlen(dir);

    return strncmp(path, dir, n) == 0 && (path[n] == '/' || path[n] == '\0');
}

bool rs_pkgdb_scoped(const struct rs_pkgdb *db, const char *path)
{
    size_t i;

    for (i = 0; i < db->nunscoped; i++)
    {
        if (within(path, db->unscoped[i]))
        {
            return false;
        }
    }
    if (!db->scoped)
    {
        return true;
    }
    for (i = 0; i < db->nscopes; i++)
    {
        if (within(path, db->scopes[i]))
        {
            return true;
        }
    }
    return false;
}

/* OpenBSD's packages, or pkgsrc's: each directory in `rel` with a +CONTENTS. */
static bool load_contents(struct rs_pkgdb *db, const char *root, const char *rel)
{
    size_t n;
    char **names = rs_list_beneath(root, rel, &n);
    size_t i;

    for (i = 0; i < n; i++)
    {
        char         *contents = rs_xasprintf("%s/%s/+CONTENTS", rel, names[i]);
        struct rs_buf text;

        char         *prefix = NULL;

        if (rs_read_beneath(root, contents, CONTENTS_MAX, &text))
        {
            bool named = parse_contents(db, text.data, &prefix);

            rs_buf_free(&text);
            /* pkgsrc's: the configuration files copied from examples. */
            free(contents);
            contents = rs_xasprintf("%s/%s/+INSTALL", rel, names[i]);
            if (named && prefix && rs_read_beneath(root, contents, CONTENTS_MAX, &text))
            {
                rs_pkgdb_parse_install(db, (uint32_t)(db->nnames - 1), prefix, text.data);
                rs_buf_free(&text);
            }
        }
        free(prefix);
        free(contents);
    }
    rs_free_names(names, n);
    if (db->nnames > 0)
    {
        /* The database is no package's file, and pkgsrc's reference counts
         * beside it neither: both are made again as packages are added. */
        db->unscoped = rs_xreallocarray(db->unscoped, db->nunscoped + 2, sizeof(*db->unscoped));
        db->unscoped[db->nunscoped++] = rs_xstrdup(rel);
        db->unscoped[db->nunscoped++] = rs_xasprintf("%s.refcount", rel);
    }
    return db->nnames > 0;
}

/* A pacman package's name: the line after "%NAME%" in its desc. */
static char *pacman_name(const char *desc)
{
    const char *p = desc;
    const char *line;
    size_t      len;

    while (next_line(&p, &line, &len))
    {
        if (len == 6 && strncmp(line, "%NAME%", 6) == 0)
        {
            return next_line(&p, &line, &len) && len > 0 ? rs_xstrndup(line, len) : NULL;
        }
    }
    return NULL;
}

/* pacman's packages: a directory each in /var/lib/pacman/local, with the
 * package's name in its desc and its files, and their SHA-256, in its
 * gzip'd mtree. */
static bool load_pacman(struct rs_pkgdb *db, const char *root)
{
    static const char *const rel = "/var/lib/pacman/local";
    size_t                   n;
    char                   **names = rs_list_beneath(root, rel, &n);
    size_t                   i;

    for (i = 0; i < n; i++)
    {
        char         *path = rs_xasprintf("%s/%s/desc", rel, names[i]);
        struct rs_buf text;
        char         *name = NULL;
        uint32_t      pkg;

        if (rs_read_beneath(root, path, INFO_MAX, &text))
        {
            name = pacman_name(text.data);
            rs_buf_free(&text);
        }
        free(path);
        pkg = name ? package_at(db, name, strlen(name)) : UINT32_MAX;
        free(name);
        path = rs_xasprintf("%s/%s/mtree", rel, names[i]);
        if (pkg != UINT32_MAX && rs_read_beneath_gz(root, path, INFO_MAX, &text))
        {
            rs_pkgdb_parse_mtree(db, pkg, text.data);
            rs_buf_free(&text);
        }
        free(path);
    }
    rs_free_names(names, n);
    return db->nfiles > 0;
}

/* apk's packages: all in /lib/apk/db/installed. */
static bool load_apk(struct rs_pkgdb *db, const char *root)
{
    struct rs_buf text;

    if (!rs_read_beneath(root, "/lib/apk/db/installed", STATUS_MAX, &text))
    {
        return false;
    }
    (void)rs_pkgdb_parse_apk(db, text.data);
    rs_buf_free(&text);
    return db->nfiles > 0;
}

/* Whether `root` is this system's own "/": all pkg and rpm can answer for. */
static bool running_root(const char *root)
{
    char *real = realpath(root, NULL); /* Flawfinder: ignore */
    bool  yes = real && strcmp(real, "/") == 0;

    free(real);
    return yes;
}

/* What `prog` writes to its standard output given `argv`, into `out`, if it
 * is there to run and says it succeeded; what it says on its standard error
 * is not restate's to repeat. */
static bool ask(enum rs_program prog, char *const argv[], struct rs_buf *out)
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

/* FreeBSD's pkg's database, or rpm's, as each tool says it. */
static void load_tools(struct rs_pkgdb *db)
{
    static char   pkg[] = "pkg";
    static char   query[] = "query";
    static char   pkg_format[] = "%n\t%p\t%Fs\t%Fp";
    static char   rpm[] = "rpm";
    static char   all[] = "-qa";
    static char   qf[] = "--qf";
    static char   rpm_format[] = RS_PKGDB_RPM_FORMAT;
    char *const   pkg_argv[] = { pkg, query, pkg_format, NULL };
    char *const   rpm_argv[] = { rpm, all, qf, rpm_format, NULL };
    struct rs_buf out;

    if (ask(RS_PROG_PKG, pkg_argv, &out))
    {
        if (rs_pkgdb_parse_pkg(db, out.data) > 0)
        {
            db->unscoped = rs_xreallocarray(db->unscoped, db->nunscoped + 1,
                                            sizeof(*db->unscoped));
            db->unscoped[db->nunscoped++] = rs_xstrdup("/var/db/pkg");
        }
        rs_buf_free(&out);
    }
    if (db->nfiles == 0 && ask(RS_PROG_RPM, rpm_argv, &out))
    {
        (void)rs_pkgdb_parse_rpm(db, out.data);
        rs_buf_free(&out);
    }
}

bool rs_pkgdb_load(struct rs_pkgdb *db, const char *root)
{
    static const char *const bsd[] = { "/var/db/pkg", "/usr/pkg/pkgdb" };
    struct rs_buf            text;
    size_t                   i;

    rs_pkgdb_init(db);
    if (rs_read_beneath(root, "/var/lib/dpkg/diversions", DIV_MAX, &text))
    {
        rs_pkgdb_parse_diversions(db, text.data);
        rs_buf_free(&text);
    }
    if (!rs_read_beneath(root, "/var/lib/dpkg/status", STATUS_MAX, &text))
    {
        /* No dpkg: OpenBSD's packages, or pkgsrc's, pacman's or apk's; or, on this
         * system, what FreeBSD's pkg or rpm says (pkg keeps its database in /var/db/pkg
         * too, in local.sqlite, with no +CONTENTS). */
        rs_pkgdb_free(db);
        for (i = 0; i < sizeof(bsd) / sizeof(bsd[0]) && db->nnames == 0; i++)
        {
            (void)load_contents(db, root, bsd[i]);
        }
        if (db->nnames == 0 && !load_pacman(db, root) && !load_apk(db, root) &&
            running_root(root))
        {
            load_tools(db);
        }
        rs_pkgdb_sort(db);
        if (db->nfiles == 0)
        {
            rs_pkgdb_free(db);
            return false;
        }
        return true;
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
