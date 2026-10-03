/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "index.h"

#include <stdlib.h>
#include <string.h>

#include "json.h"

void rs_index_init(struct rs_index *ix)
{
    memset(ix, 0, sizeof(*ix));
}

void rs_entry_free(struct rs_entry *e)
{
    free(e->path);
    free(e->target);
    free(e->user);
    free(e->group);
    free(e->stored);
    e->path = e->target = e->user = e->group = e->stored = NULL;
}

void rs_index_free(struct rs_index *ix)
{
    size_t i;

    for (i = 0; i < ix->count; i++)
    {
        rs_entry_free(&ix->entries[i]);
    }
    free(ix->entries);
    free(ix->root);
    free(ix->os);
    free(ix->host);
    free(ix->created);
    free(ix->version);
    free(ix->content);
    rs_index_init(ix);
}

void rs_index_add(struct rs_index *ix, const struct rs_entry *e)
{
    if (ix->count == ix->cap)
    {
        ix->cap = ix->cap ? ix->cap * 2 : 256;
        ix->entries = rs_xreallocarray(ix->entries, ix->cap, sizeof(*ix->entries));
    }
    ix->entries[ix->count++] = *e;
}

static int compare_entries(const void *a, const void *b)
{
    const struct rs_entry *x = a;
    const struct rs_entry *y = b;

    return strcmp(x->path, y->path);
}

bool rs_index_sort(struct rs_index *ix, struct rs_buf *err)
{
    size_t i;

    if (ix->count > 1)
    {
        qsort(ix->entries, ix->count, sizeof(*ix->entries), compare_entries);
    }
    for (i = 1; i < ix->count; i++)
    {
        if (strcmp(ix->entries[i - 1].path, ix->entries[i].path) == 0)
        {
            struct rs_buf shown;

            rs_buf_init(&shown);
            rs_escape(&shown, ix->entries[i].path);
            rs_buf_addf(err, "%s appears more than once", shown.data);
            rs_buf_free(&shown);
            return false;
        }
    }
    return true;
}

const struct rs_entry *rs_index_find(const struct rs_index *ix, const char *path)
{
    size_t lo = 0;
    size_t hi = ix->count;

    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int    c = strcmp(ix->entries[mid].path, path);

        if (c == 0)
        {
            return &ix->entries[mid];
        }
        if (c < 0)
        {
            lo = mid + 1;
        } else
        {
            hi = mid;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */

static const struct {
    char        type;
    const char *name;
} type_names[] = {
    { 'f', "file" },
    { 'd', "directory" },
    { 'l', "symlink" },
    { 'c', "char" },
    { 'b', "block" },
    { 'p', "fifo" },
};

const char *rs_type_name(char type)
{
    size_t i;

    for (i = 0; i < sizeof(type_names) / sizeof(type_names[0]); i++)
    {
        if (type_names[i].type == type)
        {
            return type_names[i].name;
        }
    }
    return "?";
}

bool rs_type_parse(const char *name, char *out)
{
    size_t i;

    for (i = 0; i < sizeof(type_names) / sizeof(type_names[0]); i++)
    {
        if (strcmp(type_names[i].name, name) == 0)
        {
            *out = type_names[i].type;
            return true;
        }
    }
    return false;
}

void rs_escape(struct rs_buf *out, const char *s)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p;

    for (p = (const unsigned char *)s; *p != '\0'; p++)
    {
        switch (*p)
        {
        case '\\':
            rs_buf_addstr(out, "\\\\");
            break;
        case '\t':
            rs_buf_addstr(out, "\\t");
            break;
        case '\n':
            rs_buf_addstr(out, "\\n");
            break;
        case '\r':
            rs_buf_addstr(out, "\\r");
            break;
        default:
            if (*p < 0x20 || *p == 0x7f)
            {
                char esc[4] = { '\\', 'x', hex[*p >> 4], hex[*p & 0x0f] };

                rs_buf_add(out, esc, sizeof(esc));
            } else
            {
                rs_buf_addc(out, (char)*p);
            }
            break;
        }
    }
    if (!out->data)
    {
        rs_buf_add(out, "", 0);
    }
}

bool rs_path_is_clean(const char *path)
{
    const char *p = path;

    if (*p != '/')
    {
        return false;
    }
    if (p[1] == '\0')
    {
        return true;
    }
    while (*p == '/')
    {
        const char *start = ++p;
        size_t      n;

        while (*p != '\0' && *p != '/')
        {
            p++;
        }
        n = (size_t)(p - start);
        if (n == 0)
        {
            return false;   /* "//" or a trailing "/" */
        }
        if ((n == 1 && start[0] == '.') || (n == 2 && start[0] == '.' && start[1] == '.'))
        {
            return false;
        }
    }
    return *p == '\0';
}

/* ------------------------------------------------------------------------- */
/* Writing                                                                   */
/* ------------------------------------------------------------------------- */

static void put_key(struct rs_buf *b, const char *key, bool *first)
{
    if (!*first)
    {
        rs_buf_addstr(b, ", ");
    }
    *first = false;
    rs_json_put_string(b, key, strlen(key));
    rs_buf_addstr(b, ": ");
}

static void put_str(struct rs_buf *b, const char *key, const char *value, bool *first)
{
    put_key(b, key, first);
    if (value)
    {
        rs_json_put_string(b, value, strlen(value));
    } else
    {
        rs_buf_addstr(b, "null");
    }
}

/* A string that may not be UTF-8: lossy under `key`, exact under key_base64. */
static void put_bytes(struct rs_buf *b, const char *key, const char *value, bool *first)
{
    size_t len = strlen(value);

    if (rs_utf8_valid(value, len))
    {
        put_str(b, key, value, first);
    } else
    {
        char *lossy = rs_utf8_lossy(value, len);
        char *key64 = rs_xasprintf("%s_base64", key);

        put_str(b, key, lossy, first);
        put_key(b, key64, first);
        rs_buf_addc(b, '"');
        rs_base64_encode(b, value, len);
        rs_buf_addc(b, '"');
        free(lossy);
        free(key64);
    }
}

static void put_u64(struct rs_buf *b, const char *key, uint64_t v, bool *first)
{
    put_key(b, key, first);
    rs_buf_addf(b, "%llu", (unsigned long long)v);
}

static void put_time(struct rs_buf *b, const char *key, const struct rs_time *t, bool *first)
{
    if (t->set)
    {
        char s[RS_TIME_STR_MAX];

        rs_time_format(t, s);
        put_str(b, key, s, first);
    } else
    {
        put_str(b, key, NULL, first);
    }
}

static void entry_json(struct rs_buf *b, const struct rs_entry *e)
{
    bool        first = true;
    const char *slash = strrchr(e->path, '/');
    char        mode[8];

    rs_buf_addc(b, '{');
    put_bytes(b, "path", e->path, &first);
    put_bytes(b, "name", (slash && slash[1] != '\0') ? slash + 1 : e->path, &first);
    put_str(b, "type", rs_type_name(e->type), &first);
    put_str(b, "class", rs_class_name(e->cls), &first);
    (void)snprintf(mode, sizeof(mode), "%04o", (unsigned)e->mode);
    put_str(b, "mode", mode, &first);
    put_u64(b, "uid", e->uid, &first);
    put_str(b, "user", e->user, &first);
    put_u64(b, "gid", e->gid, &first);
    put_str(b, "group", e->group, &first);
    put_u64(b, "size", e->size, &first);
    put_u64(b, "nlink", e->nlink, &first);
    put_u64(b, "device", e->dev, &first);
    put_u64(b, "inode", e->ino, &first);
    if (e->type == 'c' || e->type == 'b')
    {
        put_u64(b, "rdev", e->rdev, &first);
    }
    put_time(b, "atime", &e->atime, &first);
    put_time(b, "mtime", &e->mtime, &first);
    put_time(b, "ctime", &e->ctime, &first);
    put_time(b, "btime", &e->btime, &first);
    put_str(b, "sha256", e->hash_state == RS_HASH_PRESENT ? e->hash : NULL, &first);
    if (e->hash_state == RS_HASH_UNREADABLE)
    {
        put_key(b, "unreadable", &first);
        rs_buf_addstr(b, "true");
    }
    if (e->type == 'l' && e->target)
    {
        put_bytes(b, "target", e->target, &first);
    }
    if (e->stored)
    {
        put_bytes(b, "stored", e->stored, &first);
    }
    rs_buf_addc(b, '}');
}

bool rs_index_write(const struct rs_index *ix, FILE *out)
{
    struct rs_buf b;
    bool          first = true;
    size_t        i;

    rs_buf_init(&b);
    rs_buf_addstr(&b, "{\n  ");
    put_str(&b, "format", RS_INDEX_FORMAT, &first);
    rs_buf_addstr(&b, ",\n  ");
    first = true;
    put_u64(&b, "version", RS_INDEX_VERSION, &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_str(&b, "restate", ix->version ? ix->version : RESTATE_VERSION, &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_bytes(&b, "root", ix->root ? ix->root : "/", &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_str(&b, "os", ix->os, &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_bytes(&b, "host", ix->host ? ix->host : "unknown", &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_str(&b, "created", ix->created, &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_str(&b, "hash", "sha256", &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_key(&b, "hashed", &first);
    rs_buf_addstr(&b, ix->hashed ? "true" : "false");
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_str(&b, "content", ix->content ? ix->content : "none", &first);
    first = true;
    rs_buf_addstr(&b, ",\n  ");
    put_u64(&b, "count", ix->count, &first);
    rs_buf_addstr(&b, ",\n  \"entries\": [");
    (void)fwrite(b.data, 1, b.len, out);

    for (i = 0; i < ix->count; i++)
    {
        rs_buf_reset(&b);
        rs_buf_addstr(&b, i == 0 ? "\n    " : ",\n    ");
        entry_json(&b, &ix->entries[i]);
        (void)fwrite(b.data, 1, b.len, out);
    }
    (void)fputs(ix->count ? "\n  ]\n}\n" : "]\n}\n", out);
    rs_buf_free(&b);
    return fflush(out) == 0 && !ferror(out);
}

/* ------------------------------------------------------------------------- */
/* Reading                                                                   */
/* ------------------------------------------------------------------------- */

/* A string member: exactly from key_base64 if present, else from key. NULL
 * with *bad set if either is present and malformed. */
static char *get_bytes(const struct rs_jval *obj, const char *key, bool *bad)
{
    char                 *key64 = rs_xasprintf("%s_base64", key);
    const struct rs_jval *v64 = rs_jobject_get(obj, key64);
    const struct rs_jval *v = rs_jobject_get(obj, key);

    free(key64);
    if (v64)
    {
        struct rs_buf raw;

        rs_buf_init(&raw);
        if (v64->type != RS_JSTRING || !rs_base64_decode(v64->s, v64->slen, &raw) ||
            strlen(raw.data) != raw.len || raw.len == 0)
        {
            rs_buf_free(&raw);
            *bad = true;
            return NULL;
        }
        return rs_buf_detach(&raw);
    }
    if (!v || v->type == RS_JNULL)
    {
        return NULL;
    }
    if (v->type != RS_JSTRING)
    {
        *bad = true;
        return NULL;
    }
    return rs_xstrdup(v->s);
}

static bool get_time(const struct rs_jval *obj, const char *key, struct rs_time *out,
                     bool required)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    memset(out, 0, sizeof(*out));
    if (!v || v->type == RS_JNULL)
    {
        return !required;
    }
    return v->type == RS_JSTRING && rs_time_parse(v->s, out);
}

static bool get_u64(const struct rs_jval *obj, const char *key, uint64_t *out, bool required)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    *out = 0;
    if (!v)
    {
        return !required;
    }
    return rs_jval_u64(v, out);
}

static bool parse_mode(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    size_t   i;
    size_t   len = strlen(s);

    if (len == 0 || len > 6)
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        if (s[i] < '0' || s[i] > '7')
        {
            return false;
        }
        v = v * 8 + (uint32_t)(s[i] - '0');
    }
    if (v > 07777)
    {
        return false;
    }
    *out = v;
    return true;
}

/* Converts one parsed entry object; on failure *why says what was wrong. */
static bool entry_from_json(const struct rs_jval *obj, struct rs_entry *e, const char **why)
{
    const struct rs_jval *v;
    bool                  bad = false;

    memset(e, 0, sizeof(*e));
    if (obj->type != RS_JOBJECT)
    {
        *why = "an entry is not an object";
        return false;
    }
    e->path = get_bytes(obj, "path", &bad);
    if (bad || !e->path)
    {
        *why = "missing or bad \"path\"";
        return false;
    }
    if (!rs_path_is_clean(e->path))
    {
        *why = "the path is not a clean absolute path";
        return false;
    }
    v = rs_jobject_get(obj, "type");
    if (!v || v->type != RS_JSTRING || !rs_type_parse(v->s, &e->type))
    {
        *why = "missing or unknown \"type\"";
        return false;
    }
    v = rs_jobject_get(obj, "class");
    if (!v || v->type != RS_JSTRING || !rs_class_parse(v->s, v->slen, &e->cls))
    {
        *why = "missing or unknown \"class\"";
        return false;
    }
    v = rs_jobject_get(obj, "mode");
    if (!v || v->type != RS_JSTRING || !parse_mode(v->s, &e->mode))
    {
        *why = "missing or bad \"mode\"";
        return false;
    }
    if (!get_u64(obj, "uid", &e->uid, true) || !get_u64(obj, "gid", &e->gid, true))
    {
        *why = "missing or bad \"uid\" or \"gid\"";
        return false;
    }
    if (!get_u64(obj, "size", &e->size, true) || !get_u64(obj, "nlink", &e->nlink, false) ||
        !get_u64(obj, "device", &e->dev, false) || !get_u64(obj, "inode", &e->ino, false) ||
        !get_u64(obj, "rdev", &e->rdev, false))
    {
        *why = "a bad number";
        return false;
    }
    if (!get_time(obj, "mtime", &e->mtime, true) || !get_time(obj, "atime", &e->atime, false) ||
        !get_time(obj, "ctime", &e->ctime, false) || !get_time(obj, "btime", &e->btime, false))
    {
        *why = "a bad timestamp";
        return false;
    }
    e->user = get_bytes(obj, "user", &bad);
    e->group = get_bytes(obj, "group", &bad);
    e->stored = get_bytes(obj, "stored", &bad);
    if (bad)
    {
        *why = "a bad \"user\", \"group\" or \"stored\"";
        return false;
    }
    v = rs_jobject_get(obj, "sha256");
    if (v && v->type == RS_JSTRING)
    {
        if (v->slen != RS_SHA256_HEX_LEN || !rs_sha256_valid_hex(v->s))
        {
            *why = "a bad \"sha256\"";
            return false;
        }
        memcpy(e->hash, v->s, RS_SHA256_HEX_SIZE);
        e->hash_state = RS_HASH_PRESENT;
    } else if (v && v->type != RS_JNULL)
    {
        *why = "a bad \"sha256\"";
        return false;
    }
    v = rs_jobject_get(obj, "unreadable");
    if (v && v->type == RS_JBOOL && v->b)
    {
        e->hash_state = RS_HASH_UNREADABLE;
    }
    if (e->hash_state != RS_HASH_NONE && e->type != 'f')
    {
        *why = "a digest on something that is not a regular file";
        return false;
    }
    if (e->type == 'l')
    {
        e->target = get_bytes(obj, "target", &bad);
        if (bad || !e->target || e->target[0] == '\0')
        {
            *why = "a symlink without a good \"target\"";
            return false;
        }
    }
    return true;
}

/* A top-level string member, which must be one. */
static bool set_string(char **slot, const struct rs_jval *v)
{
    if (v->type == RS_JNULL)
    {
        return true;
    }
    if (v->type != RS_JSTRING)
    {
        return false;
    }
    free(*slot);
    *slot = rs_xstrdup(v->s);
    return true;
}

static bool parse_entries(struct rs_index *ix, struct rs_json_parser *jp,
                          const char *name, struct rs_buf *err)
{
    size_t n = 0;

    if (!rs_json_expect(jp, '['))
    {
        return false;
    }
    if (rs_json_peek(jp, ']'))
    {
        jp->pos++;
        return true;
    }
    for (;;)
    {
        struct rs_jval  obj;
        struct rs_entry e;
        const char     *why = NULL;

        n++;
        if (!rs_json_value(jp, &obj))
        {
            rs_jval_free(&obj);
            return false;
        }
        if (!entry_from_json(&obj, &e, &why))
        {
            rs_entry_free(&e);
            rs_jval_free(&obj);
            rs_buf_addf(err, "%s: entry %zu: %s", name, n, why);
            return false;
        }
        rs_jval_free(&obj);
        rs_index_add(ix, &e);
        if (rs_json_peek(jp, ','))
        {
            jp->pos++;
            continue;
        }
        return rs_json_expect(jp, ']');
    }
}

bool rs_index_parse(struct rs_index *ix, const char *text, size_t len,
                    const char *name, struct rs_buf *err)
{
    struct rs_json_parser jp;
    struct rs_buf         key;
    struct rs_buf         jerr;
    bool                  ok = true;
    bool                  saw_format = false;
    bool                  saw_entries = false;

    rs_buf_init(&key);
    rs_buf_init(&jerr);
    rs_json_init(&jp, text, len, &jerr);
    if (!rs_json_expect(&jp, '{'))
    {
        rs_buf_reset(&jerr);
        rs_buf_addf(err, "%s: not a restate index", name);
        rs_buf_free(&key);
        rs_buf_free(&jerr);
        return false;
    }
    if (rs_json_peek(&jp, '}'))
    {
        jp.pos++;
    } else
    {
        for (;;)
        {
            if (!rs_json_string(&jp, &key) || !rs_json_expect(&jp, ':'))
            {
                ok = false;
                break;
            }
            if (strcmp(key.data, "entries") == 0)
            {
                if (saw_entries)
                {
                    rs_buf_addf(&jerr, "duplicate key");
                    ok = false;
                    break;
                }
                saw_entries = true;
                if (!parse_entries(ix, &jp, name, err))
                {
                    ok = false;
                    break;
                }
            } else
            {
                struct rs_jval v;

                if (!rs_json_value(&jp, &v))
                {
                    rs_jval_free(&v);
                    ok = false;
                    break;
                }
                if (strcmp(key.data, "format") == 0)
                {
                    saw_format = v.type == RS_JSTRING && strcmp(v.s, RS_INDEX_FORMAT) == 0;
                } else if (strcmp(key.data, "version") == 0)
                {
                    uint64_t ver = 0;

                    if (!rs_jval_u64(&v, &ver) || ver != RS_INDEX_VERSION)
                    {
                        rs_buf_addf(err, "%s: index version %llu; this restate reads %d",
                                    name, (unsigned long long)ver, RS_INDEX_VERSION);
                        rs_jval_free(&v);
                        ok = false;
                        break;
                    }
                } else if (strcmp(key.data, "hashed") == 0)
                {
                    ix->hashed = v.type == RS_JBOOL && v.b;
                } else if ((strcmp(key.data, "root") == 0 && !set_string(&ix->root, &v)) ||
                           (strcmp(key.data, "os") == 0 && !set_string(&ix->os, &v)) ||
                           (strcmp(key.data, "host") == 0 && !set_string(&ix->host, &v)) ||
                           (strcmp(key.data, "created") == 0 && !set_string(&ix->created, &v)) ||
                           (strcmp(key.data, "restate") == 0 && !set_string(&ix->version, &v)) ||
                           (strcmp(key.data, "content") == 0 && !set_string(&ix->content, &v)))
                {
                    rs_buf_addf(err, "%s: \"%s\" is not a string", name, key.data);
                    rs_jval_free(&v);
                    ok = false;
                    break;
                }
                rs_jval_free(&v);
            }
            if (rs_json_peek(&jp, ','))
            {
                jp.pos++;
                continue;
            }
            if (!rs_json_expect(&jp, '}'))
            {
                ok = false;
            }
            break;
        }
    }
    if (ok && !rs_json_at_end(&jp))
    {
        rs_buf_addstr(&jerr, "data after the index");
        ok = false;
    }
    if (ok && !saw_format)
    {
        rs_buf_addf(err, "%s: not a restate index (no \"format\": \"%s\")", name,
                    RS_INDEX_FORMAT);
        ok = false;
    }
    if (ok && !saw_entries)
    {
        rs_buf_addf(err, "%s: no \"entries\"", name);
        ok = false;
    }
    if (!ok && err->len == 0)
    {
        rs_buf_addf(err, "%s: %s", name, jerr.len ? jerr.data : "malformed JSON");
    }
    if (ok)
    {
        struct rs_buf dup;

        rs_buf_init(&dup);
        if (!rs_index_sort(ix, &dup))
        {
            rs_buf_addf(err, "%s: %s", name, dup.data);
            ok = false;
        }
        rs_buf_free(&dup);
    }
    rs_buf_free(&key);
    rs_buf_free(&jerr);
    return ok;
}
