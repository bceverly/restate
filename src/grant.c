/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "grant.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "json.h"
#include "store.h"
#include "token.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif

#define CONF_SUFFIX   ".conf"
#define REPO_PATH_MAX 4096

bool rs_grant_client_valid(const char *name)
{
    size_t len = strlen(name);
    size_t i;

    if (len == 0 || len > RS_GRANT_CLIENT_MAX || name[0] == '.' || name[0] == '-')
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        char c = name[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-'))
        {
            return false;
        }
    }
    return true;
}

/* Whether `file` is a name the proxy looks at at all. */
static bool looked_at(const char *file)
{
    size_t len = strlen(file);
    size_t sl = sizeof(CONF_SUFFIX) - 1;

    return file[0] != '.' && len > sl && strcmp(file + len - sl, CONF_SUFFIX) == 0;
}

bool rs_grant_file_client(const char *file, char **client)
{
    char *name;

    *client = NULL;
    if (!looked_at(file))
    {
        return false;
    }
    name = rs_xstrndup(file, strlen(file) - (sizeof(CONF_SUFFIX) - 1));
    if (!rs_grant_client_valid(name))
    {
        free(name);
        return false;
    }
    *client = name;
    return true;
}

void rs_grant_free(struct rs_grant *g)
{
    free(g->client);
    free(g->repository);
    free(g->label);
    memset(g, 0, sizeof(*g));
}

/* ------------------------------------------------------------------------- */
/* Values                                                                    */
/* ------------------------------------------------------------------------- */

static bool is_leap(int64_t y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

/* Days from 1970-01-01 to y-m-d (Howard Hinnant's days_from_civil). */
static int64_t days_from_civil(int64_t y, int64_t m, int64_t d)
{
    int64_t era;
    int64_t yoe;
    int64_t doy;

    y -= m <= 2 ? 1 : 0;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    return era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
}

/* `n` digits at `s` as a number. */
static bool digits(const char *s, size_t n, int64_t *out)
{
    size_t i;

    *out = 0;
    for (i = 0; i < n; i++)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
        *out = *out * 10 + (s[i] - '0');
    }
    return true;
}

bool rs_grant_parse_time(const char *s, size_t len, int64_t *out)
{
    static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int64_t          y;
    int64_t          mo;
    int64_t          d;
    int64_t          h;
    int64_t          mi;
    int64_t          sec;

    /* YYYY-MM-DDTHH:MM:SSZ */
    if (len != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z' || !digits(s, 4, &y) || !digits(s + 5, 2, &mo) ||
        !digits(s + 8, 2, &d) || !digits(s + 11, 2, &h) || !digits(s + 14, 2, &mi) ||
        !digits(s + 17, 2, &sec))
    {
        return false;
    }
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 ||
        d > mdays[mo - 1] + (mo == 2 && is_leap(y) ? 1 : 0) || h > 23 || mi > 59 || sec > 59)
    {
        return false;
    }
    *out = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec;
    return true;
}

/* Whether [s, s + len) is an absolute path with no ".", "..", or empty
 * component, not "/" itself, and nothing in it but printable characters. */
static bool repo_path_ok(const char *s, size_t len)
{
    size_t i = 1;

    if (len < 2 || len > REPO_PATH_MAX || s[0] != '/' || s[len - 1] == '/')
    {
        return false;
    }
    while (i <= len)
    {
        size_t start = i;

        while (i < len && s[i] != '/')
        {
            if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
            {
                return false;
            }
            i++;
        }
        if (i == start || (i - start == 1 && s[start] == '.') ||
            (i - start == 2 && s[start] == '.' && s[start + 1] == '.'))
        {
            return false;
        }
        i++;
    }
    return true;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

/* 64 hex digits as a digest. */
static bool digest_of(const char *s, size_t len, unsigned char out[RS_SHA256_SIZE])
{
    size_t i;

    if (len != (size_t)2 * RS_SHA256_SIZE)
    {
        return false;
    }
    for (i = 0; i < RS_SHA256_SIZE; i++)
    {
        int hi = hex_value(s[2 * i]);
        int lo = hex_value(s[2 * i + 1]);

        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return true;
}

/* Whether [a, b) is the word `w`. */
static bool word_is(const char *a, const char *b, const char *w)
{
    size_t n = strlen(w);

    return (size_t)(b - a) == n && memcmp(a, w, n) == 0;
}

/* "append, read": into *ops, or false and why into `err`. */
static bool operations_of(const char *s, size_t len, unsigned *ops, struct rs_buf *err)
{
    const char *p = s;
    const char *end = s + len;

    *ops = 0;
    while (p <= end)
    {
        const char *comma = memchr(p, ',', (size_t)(end - p));
        const char *stop = comma ? comma : end;
        const char *a = p;
        const char *b = stop;
        unsigned    op;

        while (a < b && (*a == ' ' || *a == '\t'))
        {
            a++;
        }
        while (b > a && (b[-1] == ' ' || b[-1] == '\t'))
        {
            b--;
        }
        if (word_is(a, b, "append"))
        {
            op = RS_GRANT_APPEND;
        } else if (word_is(a, b, "read"))
        {
            op = RS_GRANT_READ;
        } else
        {
            rs_buf_addf(err, "operations: \"%.*s\" is not one; they are append and read",
                        (int)(b - a), a);
            return false;
        }
        if (*ops & op)
        {
            rs_buf_addf(err, "operations: %.*s is given twice", (int)(b - a), a);
            return false;
        }
        *ops |= op;
        if (!comma)
        {
            break;
        }
        p = comma + 1;
    }
    return true;
}

/* Whether a label is something to keep: no control characters, and UTF-8. */
static bool label_ok(const char *s, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
        {
            return false;
        }
    }
    return rs_utf8_valid(s, len);
}

/* ------------------------------------------------------------------------- */
/* Parsing                                                                   */
/* ------------------------------------------------------------------------- */

enum key {
    KEY_REPOSITORY = 0,
    KEY_OPERATIONS,
    KEY_TOKEN,
    KEY_EXPIRES,
    KEY_LABEL,
    KEYS
};

static const char *const key_names[KEYS] = { "repository", "operations", "token_sha256",
                                              "expires", "label" };

/* One value, for the key `k`, into `g`: false and why into `err`. */
static bool take_value(enum key k, const char *v, size_t vlen, struct rs_grant *g,
                       struct rs_buf *err)
{
    unsigned char d[RS_SHA256_SIZE];
    size_t        i;

    switch (k)
    {
    case KEY_REPOSITORY:
        if (!repo_path_ok(v, vlen))
        {
            rs_buf_addstr(err, "repository: not an absolute path to a directory, with no \".\" "
                          "or \"..\" in it");
            return false;
        }
        g->repository = rs_xstrndup(v, vlen);
        return true;
    case KEY_OPERATIONS:
        return operations_of(v, vlen, &g->operations, err);
    case KEY_TOKEN:
        if (!digest_of(v, vlen, d))
        {
            rs_buf_addstr(err, "token_sha256: not a SHA-256, 64 hex digits, of a token");
            return false;
        }
        if (g->ntokens >= RS_GRANT_TOKENS)
        {
            rs_buf_addf(err, "token_sha256: given more than %d times; a grant has a token, "
                        "and another while one replaces it", RS_GRANT_TOKENS);
            return false;
        }
        for (i = 0; i < g->ntokens; i++)
        {
            if (memcmp(g->tokens[i], d, sizeof(d)) == 0)
            {
                rs_buf_addstr(err, "token_sha256: the same token is given twice");
                return false;
            }
        }
        memcpy(g->tokens[g->ntokens++], d, sizeof(d));
        return true;
    case KEY_EXPIRES:
        if (!rs_grant_parse_time(v, vlen, &g->expires))
        {
            rs_buf_addstr(err, "expires: not a time in UTC, as 2026-12-31T00:00:00Z");
            return false;
        }
        g->expires_set = true;
        return true;
    case KEY_LABEL:
        if (vlen > RS_GRANT_LABEL_MAX || !label_ok(v, vlen))
        {
            rs_buf_addf(err, "label: more than %d bytes, or not text on one line",
                        RS_GRANT_LABEL_MAX);
            return false;
        }
        g->label = rs_xstrndup(v, vlen);
        return true;
    case KEYS:
    default:
        break;
    }
    return false;
}

bool rs_grant_parse(const char *client, const char *text, size_t len, struct rs_grant *g,
                    struct rs_buf *err)
{
    const char *p = text;
    const char *end = text + len;
    bool        seen[KEYS];
    unsigned    line = 0;
    bool        ok = true;
    size_t      k;

    memset(g, 0, sizeof(*g));
    memset(seen, 0, sizeof(seen));
    if (!rs_grant_client_valid(client))
    {
        rs_buf_addf(err, "\"%s\" is not a client's name", client);
        return false;
    }
    if (memchr(text, '\0', len))
    {
        rs_buf_addstr(err, "it has a NUL byte in it; a grant is text");
        return false;
    }
    while (ok && p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *ks = p;
        const char *ve = nl ? nl : end;
        const char *eq;
        const char *ke;
        const char *vs;

        line++;
        p = nl ? nl + 1 : end;
        while (ks < ve && (*ks == ' ' || *ks == '\t'))
        {
            ks++;
        }
        while (ve > ks && (ve[-1] == ' ' || ve[-1] == '\t' || ve[-1] == '\r'))
        {
            ve--;
        }
        if (ks == ve || *ks == '#')
        {
            continue;
        }
        eq = memchr(ks, '=', (size_t)(ve - ks));
        if (!eq)
        {
            rs_buf_addf(err, "line %u: not \"key = value\"", line);
            ok = false;
            break;
        }
        ke = eq;
        while (ke > ks && (ke[-1] == ' ' || ke[-1] == '\t'))
        {
            ke--;
        }
        vs = eq + 1;
        while (vs < ve && (*vs == ' ' || *vs == '\t'))
        {
            vs++;
        }
        for (k = 0; k < KEYS; k++)
        {
            if ((size_t)(ke - ks) == strlen(key_names[k]) &&
                memcmp(ks, key_names[k], (size_t)(ke - ks)) == 0)
            {
                break;
            }
        }
        if (k == KEYS)
        {
            rs_buf_addf(err, "line %u: \"%.*s\" is not a key a grant has", line,
                        (int)(ke - ks), ks);
            ok = false;
        } else if (seen[k] && k != KEY_TOKEN)
        {
            rs_buf_addf(err, "line %u: %s is given twice", line, key_names[k]);
            ok = false;
        } else if (vs == ve)
        {
            rs_buf_addf(err, "line %u: %s has no value", line, key_names[k]);
            ok = false;
        } else
        {
            struct rs_buf why;

            rs_buf_init(&why);
            seen[k] = true;
            ok = take_value((enum key)k, vs, (size_t)(ve - vs), g, &why);
            if (!ok)
            {
                rs_buf_addf(err, "line %u: %s", line, why.data ? why.data : "");
            }
            rs_buf_free(&why);
        }
    }
    for (k = 0; ok && k <= KEY_TOKEN; k++)
    {
        if (!seen[k])
        {
            rs_buf_addf(err, "it has no %s, which every grant has", key_names[k]);
            ok = false;
        }
    }
    if (!ok)
    {
        rs_grant_free(g);
        return false;
    }
    g->client = rs_xstrdup(client);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Files                                                                     */
/* ------------------------------------------------------------------------- */

/* Whether only its owner can change `st`: root's, or this user's, and
 * writable by no one else. */
static bool owned_safely(const struct stat *st)
{
    return (st->st_uid == 0 || st->st_uid == geteuid()) && (st->st_mode & 022) == 0;
}

bool rs_grant_load(const char *dir, const char *file, struct rs_grant *g, struct rs_buf *err)
{
    char         *path = rs_xasprintf("%s/%s", dir, file);
    char         *client = NULL;
    struct stat   st;
    struct stat   dst;
    char          chunk[4096];
    struct rs_buf text;
    struct rs_buf why;
    ssize_t       n;
    int           fd;
    bool          ok;

    memset(g, 0, sizeof(*g));
    if (!rs_grant_file_client(file, &client))
    {
        rs_buf_addf(err, "%s: not a grant's name, which is CLIENT.conf for a client's name: "
                    "1 to %d of A-Z, a-z, 0-9, \".\", \"_\" and \"-\", not beginning with "
                    "\".\" or \"-\"", path, RS_GRANT_CLIENT_MAX);
        free(path);
        return false;
    }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path,
                    lstat(path, &st) == 0 && S_ISLNK(st.st_mode)
                        ? "a symlink; a grant has to be the file itself"
                        : strerror(errno));
        free(client);
        free(path);
        return false;
    }
    ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && owned_safely(&st) &&
         lstat(dir, &dst) == 0 && S_ISDIR(dst.st_mode) && owned_safely(&dst);
    if (!ok)
    {
        rs_buf_addf(err, "%s: not read: it has to be a regular file, and it and %s have to be "
                    "root's (or the proxy's user's) and writable by no one else", path, dir);
        (void)close(fd);
        free(client);
        free(path);
        return false;
    }
    rs_buf_init(&text);
    rs_buf_add(&text, "", 0);
    while ((n = read(fd, chunk, sizeof(chunk))) != 0)
    {
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0 || text.len + (size_t)n > RS_GRANT_FILE_MAX)
        {
            break;
        }
        rs_buf_add(&text, chunk, (size_t)n);
    }
    (void)close(fd);
    if (n != 0)
    {
        rs_buf_addf(err, "%s: %s", path,
                    n < 0 ? strerror(errno) : "larger than a grant can be");
        rs_buf_free(&text);
        free(client);
        free(path);
        return false;
    }
    rs_buf_init(&why);
    ok = rs_grant_parse(client, text.data, text.len, g, &why);
    if (!ok)
    {
        rs_buf_addf(err, "%s: %s", path, why.data ? why.data : "");
    }
    rs_buf_free(&why);
    rs_buf_free(&text);
    free(client);
    free(path);
    return ok;
}

bool rs_grant_admits(const struct rs_grant *g, const char *token, size_t len, int64_t now)
{
    unsigned char d[RS_SHA256_SIZE];
    bool          match = false;
    size_t        i;

    if (!rs_token_valid(token, len) || (g->expires_set && now >= g->expires))
    {
        return false;
    }
    rs_token_digest(token, len, d);
    for (i = 0; i < g->ntokens; i++)
    {
        match = rs_digest_equal(d, g->tokens[i]) || match;
    }
    return match;
}

/* ------------------------------------------------------------------------- */
/* --check-grants                                                            */
/* ------------------------------------------------------------------------- */

static bool keep_looked_at(const struct rs_store *st, const char *dir, const char *name,
                           void *ctx, char **out)
{
    (void)st;
    (void)dir;
    (void)ctx;
    if (!looked_at(name))
    {
        return false;
    }
    *out = rs_xstrdup(name);
    return true;
}

bool rs_grants_check(const char *dir, struct rs_grant_checked **out, size_t *n,
                     struct rs_buf *err)
{
    struct rs_store *st = rs_store_local(dir);
    char           **names = rs_store_list(st, "", keep_looked_at, NULL, n);
    int              saved = errno;
    size_t           i;

    rs_store_free(st);
    *out = NULL;
    if (!names && saved != 0)
    {
        rs_buf_addf(err, "%s: %s", dir, strerror(saved));
        *n = 0;
        return false;
    }
    *out = rs_xcalloc(*n + 1, sizeof(**out));
    for (i = 0; names && i < *n; i++)
    {
        struct rs_grant_checked *c = &(*out)[i];
        struct rs_grant          g;
        struct rs_buf            why;

        rs_buf_init(&why);
        c->file = names[i];
        (void)rs_grant_file_client(names[i], &c->client);
        c->ok = rs_grant_load(dir, names[i], &g, &why);
        if (!c->ok)
        {
            c->error = rs_xstrdup(why.data ? why.data : "");
        }
        rs_grant_free(&g);
        rs_buf_free(&why);
    }
    free(names);
    return true;
}

bool rs_grants_load(const char *dir, struct rs_grant **out, size_t *n,
                    struct rs_grant_checked **bad, size_t *nbad, struct rs_buf *err)
{
    struct rs_store *st = rs_store_local(dir);
    size_t           count = 0;
    char           **names = rs_store_list(st, "", keep_looked_at, NULL, &count);
    int              saved = errno;
    size_t           i;

    rs_store_free(st);
    *out = NULL;
    *n = 0;
    *bad = NULL;
    *nbad = 0;
    if (!names && saved != 0)
    {
        rs_buf_addf(err, "%s: %s", dir, strerror(saved));
        return false;
    }
    *out = rs_xcalloc(count + 1, sizeof(**out));
    *bad = rs_xcalloc(count + 1, sizeof(**bad));
    for (i = 0; names && i < count; i++)
    {
        struct rs_grant *g = &(*out)[*n];
        struct rs_buf    why;

        rs_buf_init(&why);
        if (rs_grant_load(dir, names[i], g, &why))
        {
            (*n)++;
            free(names[i]);
        } else
        {
            struct rs_grant_checked *c = &(*bad)[(*nbad)++];

            rs_grant_free(g);
            c->file = names[i];
            (void)rs_grant_file_client(names[i], &c->client);
            c->error = rs_xstrdup(why.data ? why.data : "");
        }
        rs_buf_free(&why);
    }
    free(names);
    return true;
}

void rs_grants_free(struct rs_grant *g, size_t n)
{
    size_t i;

    for (i = 0; g && i < n; i++)
    {
        rs_grant_free(&g[i]);
    }
    free(g);
}

const struct rs_grant *rs_grants_find(const struct rs_grant *g, size_t n, const char *client)
{
    size_t i;

    for (i = 0; client && i < n; i++)
    {
        if (strcmp(g[i].client, client) == 0)
        {
            return &g[i];
        }
    }
    return NULL;
}

void rs_grants_checked_free(struct rs_grant_checked *c, size_t n)
{
    size_t i;

    for (i = 0; c && i < n; i++)
    {
        free(c[i].file);
        free(c[i].client);
        free(c[i].error);
    }
    free(c);
}

void rs_grants_report(const struct rs_grant_checked *c, size_t n, bool json, struct rs_buf *out)
{
    size_t i;

    if (json)
    {
        struct rs_jval  doc;
        struct rs_jval *list;

        memset(&doc, 0, sizeof(doc));
        rs_jval_set_object(&doc);
        rs_jobj_u64(&doc, "schema", 1);
        list = rs_jobj_add(&doc, "grants");
        rs_jval_set_array(list);
        for (i = 0; i < n; i++)
        {
            struct rs_jval *e = rs_jarr_add(list);

            rs_jval_set_object(e);
            rs_jobj_str(e, "file", c[i].file);
            if (c[i].client)
            {
                rs_jobj_str(e, "client", c[i].client);
            } else
            {
                (void)rs_jobj_add(e, "client");
            }
            rs_jobj_bool(e, "ok", c[i].ok);
            if (c[i].error)
            {
                rs_jobj_str(e, "error", c[i].error);
            } else
            {
                (void)rs_jobj_add(e, "error");
            }
        }
        rs_json_write(out, &doc, 2, 0);
        rs_buf_addc(out, '\n');
        rs_jval_free(&doc);
        return;
    }
    for (i = 0; i < n; i++)
    {
        if (c[i].ok)
        {
            rs_buf_addf(out, "%s: ok\n", c[i].file);
        } else
        {
            rs_buf_addf(out, "%s\n", c[i].error);
        }
    }
}
