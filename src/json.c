/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "json.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* UTF-8 and base64                                                          */
/* ------------------------------------------------------------------------- */

/* The length of the valid UTF-8 sequence at s[0..len), or 0 if it is not one.
 * Overlong forms, surrogates and code points past U+10FFFF are all invalid. */
static size_t utf8_seq(const unsigned char *s, size_t len)
{
    unsigned c = s[0];
    size_t   n;
    unsigned cp;
    size_t   i;

    if (c < 0x80)
    {
        return 1;
    }
    if (c >= 0xc2 && c <= 0xdf)
    {
        n = 2;
        cp = c & 0x1fu;
    } else if (c >= 0xe0 && c <= 0xef)
    {
        n = 3;
        cp = c & 0x0fu;
    } else if (c >= 0xf0 && c <= 0xf4)
    {
        n = 4;
        cp = c & 0x07u;
    } else
    {
        return 0;
    }
    if (len < n)
    {
        return 0;
    }
    for (i = 1; i < n; i++)
    {
        if ((s[i] & 0xc0u) != 0x80u)
        {
            return 0;
        }
        cp = (cp << 6) | (s[i] & 0x3fu);
    }
    if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10ffff ||
        (cp >= 0xd800 && cp <= 0xdfff))
    {
        return 0;
    }
    return n;
}

bool rs_utf8_valid(const char *s, size_t len)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t               i = 0;

    while (i < len)
    {
        size_t n = utf8_seq(p + i, len - i);

        if (n == 0)
        {
            return false;
        }
        i += n;
    }
    return true;
}

char *rs_utf8_lossy(const char *s, size_t len)
{
    const unsigned char *p = (const unsigned char *)s;
    struct rs_buf        out;
    size_t               i = 0;

    rs_buf_init(&out);
    rs_buf_add(&out, "", 0);
    while (i < len)
    {
        size_t n = utf8_seq(p + i, len - i);

        if (n == 0)
        {
            rs_buf_addstr(&out, "\xef\xbf\xbd");
            i++;
        } else
        {
            rs_buf_add(&out, s + i, n);
            i += n;
        }
    }
    return rs_buf_detach(&out);
}

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void rs_base64_encode(struct rs_buf *out, const void *data, size_t len)
{
    const unsigned char *p = data;
    size_t               i;

    for (i = 0; i + 2 < len; i += 3)
    {
        char     q[4];
        unsigned v = ((unsigned)p[i] << 16) | ((unsigned)p[i + 1] << 8) | p[i + 2];

        q[0] = b64[(v >> 18) & 63];
        q[1] = b64[(v >> 12) & 63];
        q[2] = b64[(v >> 6) & 63];
        q[3] = b64[v & 63];
        rs_buf_add(out, q, 4);
    }
    if (i < len)
    {
        char     q[4];
        unsigned v = (unsigned)p[i] << 16;

        if (i + 1 < len)
        {
            v |= (unsigned)p[i + 1] << 8;
        }
        q[0] = b64[(v >> 18) & 63];
        q[1] = b64[(v >> 12) & 63];
        q[2] = '=';
        q[3] = '=';
        if (i + 1 < len)
        {
            q[2] = b64[(v >> 6) & 63];
        }
        rs_buf_add(out, q, 4);
    }
    if (!out->data)
    {
        rs_buf_add(out, "", 0);
    }
}

static int b64_value(char c)
{
    const char *hit = c ? strchr(b64, c) : NULL;

    return hit ? (int)(hit - b64) : -1;
}

bool rs_base64_decode(const char *s, size_t len, struct rs_buf *out)
{
    size_t i;

    rs_buf_reset(out);
    rs_buf_add(out, "", 0);
    if (len % 4 != 0)
    {
        return false;
    }
    for (i = 0; i < len; i += 4)
    {
        int  v[4];
        int  k;
        bool last = i + 4 == len;

        for (k = 0; k < 4; k++)
        {
            v[k] = b64_value(s[i + (size_t)k]);
        }
        if (v[0] < 0 || v[1] < 0)
        {
            return false;
        }
        if (last && s[i + 2] == '=' && s[i + 3] == '=')
        {
            rs_buf_addc(out, (char)(unsigned char)((v[0] << 2) | (v[1] >> 4)));
            continue;
        }
        if (v[2] < 0)
        {
            return false;
        }
        if (last && s[i + 3] == '=')
        {
            rs_buf_addc(out, (char)(unsigned char)((v[0] << 2) | (v[1] >> 4)));
            rs_buf_addc(out, (char)(unsigned char)(((v[1] & 15) << 4) | (v[2] >> 2)));
            continue;
        }
        if (v[3] < 0)
        {
            return false;
        }
        rs_buf_addc(out, (char)(unsigned char)((v[0] << 2) | (v[1] >> 4)));
        rs_buf_addc(out, (char)(unsigned char)(((v[1] & 15) << 4) | (v[2] >> 2)));
        rs_buf_addc(out, (char)(unsigned char)(((v[2] & 3) << 6) | v[3]));
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* Writing                                                                   */
/* ------------------------------------------------------------------------- */

void rs_json_put_string(struct rs_buf *out, const char *s, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    size_t            i;

    rs_buf_addc(out, '"');
    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)s[i];

        switch (c)
        {
        case '"':
            rs_buf_addstr(out, "\\\"");
            break;
        case '\\':
            rs_buf_addstr(out, "\\\\");
            break;
        case '\n':
            rs_buf_addstr(out, "\\n");
            break;
        case '\t':
            rs_buf_addstr(out, "\\t");
            break;
        case '\r':
            rs_buf_addstr(out, "\\r");
            break;
        default:
            if (c < 0x20)
            {
                char esc[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] };

                rs_buf_add(out, esc, sizeof(esc));
            } else
            {
                rs_buf_addc(out, (char)c);
            }
            break;
        }
    }
    rs_buf_addc(out, '"');
}

/* ------------------------------------------------------------------------- */
/* Parsing                                                                   */
/* ------------------------------------------------------------------------- */

void rs_json_init(struct rs_json_parser *jp, const char *text, size_t len,
                  struct rs_buf *err)
{
    jp->p = text;
    jp->len = len;
    jp->pos = 0;
    jp->err = err;
}

static bool fail(struct rs_json_parser *jp, const char *what)
{
    if (jp->err && jp->err->len == 0)
    {
        rs_buf_addf(jp->err, "%s at byte %zu", what, jp->pos);
    }
    return false;
}

static void skip_ws(struct rs_json_parser *jp)
{
    while (jp->pos < jp->len)
    {
        char c = jp->p[jp->pos];

        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
        {
            break;
        }
        jp->pos++;
    }
}

bool rs_json_peek(struct rs_json_parser *jp, char c)
{
    skip_ws(jp);
    return jp->pos < jp->len && jp->p[jp->pos] == c;
}

bool rs_json_expect(struct rs_json_parser *jp, char c)
{
    char what[24];

    if (rs_json_peek(jp, c))
    {
        jp->pos++;
        return true;
    }
    memcpy(what, "expected 'x'", 13);
    what[10] = c;
    return fail(jp, what);
}

bool rs_json_at_end(struct rs_json_parser *jp)
{
    skip_ws(jp);
    return jp->pos == jp->len;
}

static int hex4(const char *s)
{
    int v = 0;
    int i;

    for (i = 0; i < 4; i++)
    {
        char c = s[i];
        int  d;

        if (c >= '0' && c <= '9')
        {
            d = c - '0';
        } else if (c >= 'a' && c <= 'f')
        {
            d = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F')
        {
            d = c - 'A' + 10;
        } else
        {
            return -1;
        }
        v = v * 16 + d;
    }
    return v;
}

static void put_utf8(struct rs_buf *out, unsigned cp)
{
    char b[4];

    if (cp < 0x80)
    {
        b[0] = (char)cp;
        rs_buf_add(out, b, 1);
    } else if (cp < 0x800)
    {
        b[0] = (char)(0xc0 | (cp >> 6));
        b[1] = (char)(0x80 | (cp & 0x3f));
        rs_buf_add(out, b, 2);
    } else if (cp < 0x10000)
    {
        b[0] = (char)(0xe0 | (cp >> 12));
        b[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        b[2] = (char)(0x80 | (cp & 0x3f));
        rs_buf_add(out, b, 3);
    } else
    {
        b[0] = (char)(0xf0 | (cp >> 18));
        b[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
        b[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
        b[3] = (char)(0x80 | (cp & 0x3f));
        rs_buf_add(out, b, 4);
    }
}

bool rs_json_string(struct rs_json_parser *jp, struct rs_buf *out)
{
    rs_buf_reset(out);
    rs_buf_add(out, "", 0);
    if (!rs_json_expect(jp, '"'))
    {
        return false;
    }
    for (;;)
    {
        unsigned char c;

        if (jp->pos >= jp->len)
        {
            return fail(jp, "unterminated string");
        }
        c = (unsigned char)jp->p[jp->pos];
        if (c == '"')
        {
            jp->pos++;
            return true;
        }
        if (c < 0x20)
        {
            return fail(jp, "control character in a string");
        }
        if (c == '\\')
        {
            char e;

            if (jp->pos + 1 >= jp->len)
            {
                return fail(jp, "unterminated escape");
            }
            e = jp->p[jp->pos + 1];
            jp->pos += 2;
            switch (e)
            {
            case '"':
            case '\\':
            case '/':
                rs_buf_addc(out, e);
                break;
            case 'b':
                rs_buf_addc(out, '\b');
                break;
            case 'f':
                rs_buf_addc(out, '\f');
                break;
            case 'n':
                rs_buf_addc(out, '\n');
                break;
            case 'r':
                rs_buf_addc(out, '\r');
                break;
            case 't':
                rs_buf_addc(out, '\t');
                break;
            case 'u':
            {
                int cp = jp->pos + 4 <= jp->len ? hex4(jp->p + jp->pos) : -1;

                if (cp < 0)
                {
                    return fail(jp, "bad \\u escape");
                }
                jp->pos += 4;
                if (cp >= 0xd800 && cp <= 0xdbff)
                {
                    int lo = -1;

                    if (jp->pos + 6 <= jp->len && jp->p[jp->pos] == '\\' &&
                        jp->p[jp->pos + 1] == 'u')
                    {
                        lo = hex4(jp->p + jp->pos + 2);
                    }
                    if (lo < 0xdc00 || lo > 0xdfff)
                    {
                        return fail(jp, "unpaired surrogate");
                    }
                    jp->pos += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                } else if (cp >= 0xdc00 && cp <= 0xdfff)
                {
                    return fail(jp, "unpaired surrogate");
                }
                if (cp == 0)
                {
                    return fail(jp, "NUL in a string");
                }
                put_utf8(out, (unsigned)cp);
                break;
            }
            default:
                return fail(jp, "bad escape");
            }
            continue;
        }
        {
            size_t n = utf8_seq((const unsigned char *)jp->p + jp->pos, jp->len - jp->pos);

            if (n == 0)
            {
                return fail(jp, "invalid UTF-8 in a string");
            }
            rs_buf_add(out, jp->p + jp->pos, n);
            jp->pos += n;
        }
    }
}

/* Recursive, but only as deep as the parser allowed: RS_JSON_MAX_DEPTH. */
void rs_jval_free(struct rs_jval *v) /* NOLINT(misc-no-recursion) */
{
    size_t i;

    if (!v)
    {
        return;
    }
    free(v->s);
    for (i = 0; i < v->n; i++)
    {
        rs_jval_free(&v->items[i]);
        if (v->keys)
        {
            free(v->keys[i]);
        }
    }
    free(v->items);
    free(v->keys);
    memset(v, 0, sizeof(*v));
}

static bool literal(struct rs_json_parser *jp, const char *word)
{
    size_t n = strlen(word);

    if (jp->len - jp->pos < n || memcmp(jp->p + jp->pos, word, n) != 0)
    {
        return fail(jp, "unexpected character");
    }
    jp->pos += n;
    return true;
}

static bool number(struct rs_json_parser *jp, struct rs_jval *out)
{
    uint64_t v = 0;
    size_t   start;

    out->type = RS_JINT;
    if (jp->p[jp->pos] == '-')
    {
        out->neg = true;
        jp->pos++;
    }
    start = jp->pos;
    while (jp->pos < jp->len && jp->p[jp->pos] >= '0' && jp->p[jp->pos] <= '9')
    {
        unsigned d = (unsigned)(jp->p[jp->pos] - '0');

        if (v > (UINT64_MAX - d) / 10)
        {
            return fail(jp, "number too large");
        }
        v = v * 10 + d;
        jp->pos++;
    }
    if (jp->pos == start || (jp->p[start] == '0' && jp->pos - start > 1))
    {
        return fail(jp, "bad number");
    }
    if (jp->pos < jp->len &&
        (jp->p[jp->pos] == '.' || jp->p[jp->pos] == 'e' || jp->p[jp->pos] == 'E'))
    {
        return fail(jp, "only integers are allowed");
    }
    out->u = v;
    if (out->neg && v == 0)
    {
        out->neg = false;
    }
    return true;
}

static bool value(struct rs_json_parser *jp, struct rs_jval *out, int depth);

static bool container(struct rs_json_parser *jp, struct rs_jval *out, int depth, /* NOLINT(misc-no-recursion) */
                      bool is_object)
{
    size_t        cap = 0;
    struct rs_buf key;
    char          close = is_object ? '}' : ']';

    out->type = is_object ? RS_JOBJECT : RS_JARRAY;
    jp->pos++;   /* the opening bracket */
    if (depth >= RS_JSON_MAX_DEPTH)
    {
        return fail(jp, "nested too deeply");
    }
    if (rs_json_peek(jp, close))
    {
        jp->pos++;
        return true;
    }
    rs_buf_init(&key);
    for (;;)
    {
        if (out->n == cap)
        {
            cap = cap ? cap * 2 : 8;
            out->items = rs_xreallocarray(out->items, cap, sizeof(*out->items));
            if (is_object)
            {
                out->keys = rs_xreallocarray(out->keys, cap, sizeof(*out->keys));
            }
        }
        memset(&out->items[out->n], 0, sizeof(out->items[0]));
        if (is_object)
        {
            size_t i;

            out->keys[out->n] = NULL;
            if (!rs_json_string(jp, &key))
            {
                rs_buf_free(&key);
                return false;
            }
            for (i = 0; i < out->n; i++)
            {
                if (strcmp(out->keys[i], key.data) == 0)
                {
                    rs_buf_free(&key);
                    return fail(jp, "duplicate key");
                }
            }
            out->keys[out->n] = rs_xstrdup(key.data);
            if (!rs_json_expect(jp, ':'))
            {
                out->n++;
                rs_buf_free(&key);
                return false;
            }
        }
        out->n++;
        if (!value(jp, &out->items[out->n - 1], depth + 1))
        {
            rs_buf_free(&key);
            return false;
        }
        if (rs_json_peek(jp, ','))
        {
            jp->pos++;
            continue;
        }
        rs_buf_free(&key);
        return rs_json_expect(jp, close);
    }
}

static bool value(struct rs_json_parser *jp, struct rs_jval *out, int depth) /* NOLINT(misc-no-recursion) */
{
    char c;

    memset(out, 0, sizeof(*out));
    skip_ws(jp);
    if (jp->pos >= jp->len)
    {
        return fail(jp, "unexpected end of input");
    }
    c = jp->p[jp->pos];
    switch (c)
    {
    case '{':
        return container(jp, out, depth, true);
    case '[':
        return container(jp, out, depth, false);
    case '"':
    {
        struct rs_buf s;

        rs_buf_init(&s);
        out->type = RS_JSTRING;
        if (!rs_json_string(jp, &s))
        {
            rs_buf_free(&s);
            return false;
        }
        out->slen = s.len;
        out->s = rs_buf_detach(&s);
        return true;
    }
    case 't':
        out->type = RS_JBOOL;
        out->b = true;
        return literal(jp, "true");
    case 'f':
        out->type = RS_JBOOL;
        return literal(jp, "false");
    case 'n':
        out->type = RS_JNULL;
        return literal(jp, "null");
    default:
        if (c == '-' || (c >= '0' && c <= '9'))
        {
            return number(jp, out);
        }
        return fail(jp, "unexpected character");
    }
}

bool rs_json_value(struct rs_json_parser *jp, struct rs_jval *out)
{
    return value(jp, out, 0);
}

const struct rs_jval *rs_jobject_get(const struct rs_jval *obj, const char *key)
{
    size_t i;

    if (!obj || obj->type != RS_JOBJECT)
    {
        return NULL;
    }
    for (i = 0; i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    return NULL;
}

bool rs_jval_u64(const struct rs_jval *v, uint64_t *out)
{
    if (!v || v->type != RS_JINT || v->neg)
    {
        return false;
    }
    *out = v->u;
    return true;
}

bool rs_jval_i64(const struct rs_jval *v, int64_t *out)
{
    if (!v || v->type != RS_JINT)
    {
        return false;
    }
    if (v->neg)
    {
        if (v->u > (uint64_t)INT64_MAX + 1u)
        {
            return false;
        }
        *out = v->u == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)v->u;
        return true;
    }
    if (v->u > (uint64_t)INT64_MAX)
    {
        return false;
    }
    *out = (int64_t)v->u;
    return true;
}
