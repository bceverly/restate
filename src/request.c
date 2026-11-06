/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "request.h"

#include <stdlib.h>
#include <string.h>

#include "grant.h"
#include "repo.h"
#include "util.h"

#define TOKEN_MAX 256       /* far past a token's 47: anything longer is not one */

void rs_request_free(struct rs_request *req)
{
    free(req->target);
    free(req->token);
    memset(req, 0, sizeof(*req));
}

/* Whether `c` is a tchar: what a method or a header's name is made of. */
static bool is_tchar(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

/* Whether [s, s + n) is `word`, ignoring case. */
static bool same_word(const char *s, size_t n, const char *word)
{
    size_t i;

    if (n != strlen(word))
    {
        return false;
    }
    for (i = 0; i < n; i++)
    {
        char a = s[i];
        char b = word[i];

        if (a >= 'A' && a <= 'Z')
        {
            a = (char)(a - 'A' + 'a');
        }
        if (a != b)
        {
            return false;
        }
    }
    return true;
}

/* Decimal digits [s, s + n) as a number no larger than 2^63 - 1. */
static bool decimal(const char *s, size_t n, uint64_t *out)
{
    size_t i;

    *out = 0;
    if (n == 0 || n > 19)
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
    return *out <= (uint64_t)INT64_MAX;
}

/* "bytes=FIRST-" or "bytes=FIRST-LAST", FIRST no later than LAST. */
static void parse_range(const char *v, size_t n, struct rs_request *req)
{
    const char *dash;
    const char *end = v + n;

    req->has_range = true;
    req->range_bad = true;
    if (n < 7 || memcmp(v, "bytes=", 6) != 0)
    {
        return;
    }
    v += 6;
    dash = memchr(v, '-', (size_t)(end - v));
    if (!dash || !decimal(v, (size_t)(dash - v), &req->range_first))
    {
        return;
    }
    if (dash + 1 == end)
    {
        req->range_open = true;
        req->range_bad = false;
        return;
    }
    if (!decimal(dash + 1, (size_t)(end - dash - 1), &req->range_last) ||
        req->range_last < req->range_first)
    {
        return;
    }
    req->range_bad = false;
}

/* What "Authorization: Bearer TOKEN" says. */
static void parse_authorization(const char *v, size_t n, struct rs_request *req)
{
    size_t i;

    if (n <= 7 || !same_word(v, 6, "bearer") || v[6] != ' ' || n - 7 > TOKEN_MAX)
    {
        req->token_malformed = true;
        return;
    }
    for (i = 7; i < n; i++)
    {
        if (v[i] == ' ' || v[i] == '\t')
        {
            req->token_malformed = true;
            return;
        }
    }
    req->token = rs_xstrndup(v + 7, n - 7);
}

/* Whether "Connection: ..." names close among its options. */
static bool says_close(const char *v, size_t n)
{
    const char *p = v;
    const char *end = v + n;

    while (p < end)
    {
        const char *comma = memchr(p, ',', (size_t)(end - p));
        const char *stop = comma ? comma : end;
        const char *a = p;
        const char *b = stop;

        while (a < b && (*a == ' ' || *a == '\t'))
        {
            a++;
        }
        while (b > a && (b[-1] == ' ' || b[-1] == '\t'))
        {
            b--;
        }
        if (same_word(a, (size_t)(b - a), "close"))
        {
            return true;
        }
        p = comma ? comma + 1 : end;
    }
    return false;
}

static bool is_session_id(const char *s, size_t n)
{
    size_t i;

    if (n != RS_SESSION_LEN)
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

/* The headers this protocol reads: each may be given once. */
enum header {
    H_HOST = 0,
    H_LENGTH,
    H_ENCODING,
    H_AUTH,
    H_SESSION,
    H_RANGE,
    H_EXPECT,
    H_CONNECTION,
    HEADERS
};

static const char *const header_names[HEADERS] = {
    "host", "content-length", "transfer-encoding", "authorization",
    "restate-session", "range", "expect", "connection"
};

/* The request line, [p, eol): into `req`, or minus a status. */
static long request_line(const char *p, const char *eol, struct rs_request *req,
                         const char **why)
{
    static const struct {
        const char    *name;
        enum rs_method m;
    } methods[] = { { "GET", RS_METHOD_GET },   { "HEAD", RS_METHOD_HEAD },
                    { "PUT", RS_METHOD_PUT },   { "POST", RS_METHOD_POST },
                    { "DELETE", RS_METHOD_DELETE } };
    const char *sp1 = memchr(p, ' ', (size_t)(eol - p));
    const char *sp2 = sp1 ? memchr(sp1 + 1, ' ', (size_t)(eol - sp1 - 1)) : NULL;
    const char *q;
    size_t      i;

    if (!sp1 || !sp2 || sp1 == p || sp2 == sp1 + 1)
    {
        *why = "not a request line";
        return -400;
    }
    for (q = p; q < sp1; q++)
    {
        if (!is_tchar((unsigned char)*q))
        {
            *why = "not a method";
            return -400;
        }
    }
    if ((size_t)(eol - sp2 - 1) != 8 || memcmp(sp2 + 1, "HTTP/", 5) != 0 || sp2[6] < '0' ||
        sp2[6] > '9' || sp2[7] != '.' || sp2[8] < '0' || sp2[8] > '9')
    {
        *why = "not HTTP";
        return -400;
    }
    if (sp2[6] != '1' || sp2[8] != '1')
    {
        *why = "not HTTP/1.1";
        return -505;
    }
    for (q = sp1 + 1; q < sp2; q++)
    {
        if ((unsigned char)*q <= 0x20 || (unsigned char)*q >= 0x7f)
        {
            *why = "not a target";
            return -400;
        }
    }
    if (sp1[1] != '/')
    {
        *why = "not an origin-form target";
        return -400;
    }
    req->method = RS_METHOD_OTHER;
    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        if ((size_t)(sp1 - p) == strlen(methods[i].name) &&
            memcmp(p, methods[i].name, (size_t)(sp1 - p)) == 0)
        {
            req->method = methods[i].m;
        }
    }
    req->target = rs_xstrndup(sp1 + 1, (size_t)(sp2 - sp1 - 1));
    return 0;
}

/* One header's value, [v, v + n), for the header `h`: 0, or minus a status. */
static long header_value(enum header h, const char *v, size_t n, struct rs_request *req,
                         const char **why)
{
    switch (h)
    {
    case H_HOST:
        return 0;
    case H_LENGTH:
        if (!decimal(v, n, &req->length))
        {
            *why = "a Content-Length that is not a number";
            return -400;
        }
        req->has_length = true;
        return 0;
    case H_ENCODING:
        *why = "a Transfer-Encoding: every body has a Content-Length";
        return -411;
    case H_AUTH:
        parse_authorization(v, n, req);
        return 0;
    case H_SESSION:
        if (!is_session_id(v, n))
        {
            *why = "a Restate-Session that is not one";
            return -400;
        }
        memcpy(req->session, v, n);
        req->session[n] = '\0';
        return 0;
    case H_RANGE:
        parse_range(v, n, req);
        return 0;
    case H_EXPECT:
        if (!same_word(v, n, "100-continue"))
        {
            *why = "an Expect other than 100-continue";
            return -417;
        }
        req->expect_continue = true;
        return 0;
    case H_CONNECTION:
        req->close = says_close(v, n);
        return 0;
    case HEADERS:
    default:
        break;
    }
    return 0;
}

long rs_request_parse(const char *data, size_t len, struct rs_request *req, const char **why)
{
    const char *end = NULL;
    const char *p;
    bool        seen[HEADERS];
    size_t      i;
    size_t      head;
    long        rc;

    memset(req, 0, sizeof(*req));
    memset(seen, 0, sizeof(seen));
    *why = "";
    for (i = 0; i + 3 < len && i + 4 <= RS_REQUEST_HEAD_MAX; i++)
    {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
        {
            end = data + i + 2;    /* past the last header's CRLF */
            break;
        }
    }
    if (!end)
    {
        if (len >= RS_REQUEST_HEAD_MAX)
        {
            *why = "a request line and headers over 8 KiB";
            return -431;
        }
        return 0;
    }
    head = (size_t)(end - data) + 2;
    if (memchr(data, '\0', head))
    {
        *why = "a NUL byte in the head";
        return -400;
    }
    p = data;
    {
        const char *eol = memchr(p, '\r', (size_t)(end - p));

        if (!eol || eol[1] != '\n')
        {
            *why = "a bare CR";
            return -400;
        }
        if (memchr(p, '\n', (size_t)(eol - p)))
        {
            *why = "a bare LF";
            return -400;
        }
        rc = request_line(p, eol, req, why);
        if (rc < 0)
        {
            rs_request_free(req);
            return rc;
        }
        p = eol + 2;
    }
    while (p < end)
    {
        const char *eol = memchr(p, '\r', (size_t)(end - p));
        const char *colon;
        const char *v;
        const char *ve;
        const char *q;
        size_t      h;

        if (!eol || eol[1] != '\n')
        {
            *why = "a bare CR, or a header not ended by CRLF";
            rs_request_free(req);
            return -400;
        }
        if (memchr(p, '\n', (size_t)(eol - p)))
        {
            *why = "a bare LF";
            rs_request_free(req);
            return -400;
        }
        if (*p == ' ' || *p == '\t')
        {
            *why = "a header folded over lines";
            rs_request_free(req);
            return -400;
        }
        colon = memchr(p, ':', (size_t)(eol - p));
        if (!colon || colon == p)
        {
            *why = "not a header";
            rs_request_free(req);
            return -400;
        }
        for (q = p; q < colon; q++)
        {
            if (!is_tchar((unsigned char)*q))
            {
                *why = "not a header's name";
                rs_request_free(req);
                return -400;
            }
        }
        v = colon + 1;
        ve = eol;
        while (v < ve && (*v == ' ' || *v == '\t'))
        {
            v++;
        }
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
        {
            ve--;
        }
        for (q = v; q < ve; q++)
        {
            unsigned char c = (unsigned char)*q;

            if ((c < 0x20 && c != '\t') || c == 0x7f)
            {
                *why = "a control character in a header";
                rs_request_free(req);
                return -400;
            }
        }
        for (h = 0; h < HEADERS; h++)
        {
            if (same_word(p, (size_t)(colon - p), header_names[h]))
            {
                break;
            }
        }
        if (h < HEADERS)
        {
            if (seen[h])
            {
                *why = "a header this protocol reads, given twice";
                rs_request_free(req);
                return -400;
            }
            seen[h] = true;
            rc = header_value((enum header)h, v, (size_t)(ve - v), req, why);
            if (rc < 0)
            {
                rs_request_free(req);
                return rc;
            }
        }
        p = eol + 2;
    }
    if (!seen[H_HOST])
    {
        *why = "no Host";
        rs_request_free(req);
        return -400;
    }
    return (long)head;
}

/* ------------------------------------------------------------------------- */
/* Routes                                                                    */
/* ------------------------------------------------------------------------- */

void rs_route_free(struct rs_route *route)
{
    free(route->client);
    free(route->name);
    memset(route, 0, sizeof(*route));
}

/* Whether [s, s + n) is a name restate gives a pack or a snapshot. */
static bool name_ok(const char *s, size_t n)
{
    char *name = rs_xstrndup(s, n);
    bool  ok = rs_repo_name_valid(name);

    free(name);
    return ok;
}

enum rs_file_kind rs_file_kind_of(const char *name)
{
    static const struct {
        const char       *ext;
        enum rs_file_kind k;
    } pack_files[] = { { ".tar.gz", RS_FK_PACK }, { ".idx", RS_FK_PACK_IDX },
                       { ".sum", RS_FK_PACK_SUM }, { ".seek", RS_FK_PACK_SEEK } };
    static const struct {
        const char       *file;
        enum rs_file_kind k;
    } snap_files[] = { { "index.json.gz", RS_FK_INDEX }, { "index.sig", RS_FK_INDEX_SIG },
                       { "kit", RS_FK_KIT }, { "info", RS_FK_INFO },
                       { "packs", RS_FK_PACK_LIST } };
    size_t i;

    if (strcmp(name, "restate-repository") == 0)
    {
        return RS_FK_MARKER;
    }
    if (strcmp(name, "chunk-key") == 0 ||
        (strncmp(name, "chunk-key.", 10) == 0 && rs_repo_name_valid(name + 10)))
    {
        return RS_FK_CHUNK_KEY;
    }
    if (strncmp(name, "packs/", 6) == 0 && !strchr(name + 6, '/'))
    {
        size_t len = strlen(name);

        for (i = 0; i < sizeof(pack_files) / sizeof(pack_files[0]); i++)
        {
            size_t el = strlen(pack_files[i].ext);

            if (len > 6 + el && strcmp(name + len - el, pack_files[i].ext) == 0 &&
                name_ok(name + 6, len - 6 - el))
            {
                return pack_files[i].k;
            }
        }
        return RS_FK_NONE;
    }
    if (strncmp(name, "snapshots/", 10) == 0)
    {
        const char *slash = strchr(name + 10, '/');

        if (!slash || !name_ok(name + 10, (size_t)(slash - name - 10)))
        {
            return RS_FK_NONE;
        }
        for (i = 0; i < sizeof(snap_files) / sizeof(snap_files[0]); i++)
        {
            if (strcmp(slash + 1, snap_files[i].file) == 0)
            {
                return snap_files[i].k;
            }
        }
    }
    return RS_FK_NONE;
}

uint64_t rs_upload_max(enum rs_file_kind k)
{
    switch (k)
    {
    case RS_FK_PACK:
        return (uint64_t)64 * 1024 * 1024;
    case RS_FK_PACK_IDX:
    case RS_FK_KIT:
    case RS_FK_INFO:
        return (uint64_t)256 * 1024 * 1024;
    case RS_FK_PACK_SUM:
    case RS_FK_CHUNK_KEY:
        return 4096;
    case RS_FK_PACK_SEEK:
    case RS_FK_PACK_LIST:
        return (uint64_t)16 * 1024 * 1024;
    case RS_FK_INDEX:
        return (uint64_t)2 * 1024 * 1024 * 1024 - 1;
    case RS_FK_INDEX_SIG:
        return (uint64_t)64 * 1024;
    case RS_FK_MARKER:
    case RS_FK_NONE:
    default:
        break;
    }
    return 0;
}

/* Whether `dir` is a directory a client may list: "", "packs", "snapshots"
 * or "snapshots/NAME". */
static bool listable(const char *dir)
{
    if (*dir == '\0' || strcmp(dir, "packs") == 0 || strcmp(dir, "snapshots") == 0)
    {
        return true;
    }
    return strncmp(dir, "snapshots/", 10) == 0 && rs_repo_name_valid(dir + 10);
}

/* Whether `name` is what a commit names: a pack, a snapshot or a chunk key. */
static bool committable(const char *name)
{
    if (strncmp(name, "packs/", 6) == 0)
    {
        return rs_repo_name_valid(name + 6);
    }
    if (strncmp(name, "snapshots/", 10) == 0)
    {
        return rs_repo_name_valid(name + 10);
    }
    return rs_file_kind_of(name) == RS_FK_CHUNK_KEY;
}

/* The rest of a target past "/v1/CLIENT/", `rest`, into `route`. */
static void route_rest(const char *rest, struct rs_route *route)
{
    size_t len = strlen(rest);

    if (strcmp(rest, "sessions") == 0)
    {
        route->endpoint = RS_EP_SESSION_OPEN;
        return;
    }
    if (strncmp(rest, "sessions/", 9) == 0 && len > 9 + RS_SESSION_LEN &&
        is_session_id(rest + 9, RS_SESSION_LEN) && rest[9 + RS_SESSION_LEN] == '/')
    {
        const char *what = rest + 9 + RS_SESSION_LEN + 1;

        memcpy(route->session, rest + 9, RS_SESSION_LEN);
        route->session[RS_SESSION_LEN] = '\0';
        if (strcmp(what, "renew") == 0)
        {
            route->endpoint = RS_EP_SESSION_RENEW;
        } else if (strcmp(what, "end") == 0)
        {
            route->endpoint = RS_EP_SESSION_END;
        } else if (strncmp(what, "files/", 6) == 0)
        {
            route->kind = rs_file_kind_of(what + 6);
            if (route->kind != RS_FK_NONE && route->kind != RS_FK_MARKER)
            {
                route->endpoint = RS_EP_UPLOAD;
                route->name = rs_xstrdup(what + 6);
            }
        } else if (strncmp(what, "commit/", 7) == 0 && committable(what + 7))
        {
            route->endpoint = RS_EP_COMMIT;
            route->name = rs_xstrdup(what + 7);
        }
        if (route->endpoint == RS_EP_NONE)
        {
            route->session[0] = '\0';
        }
        return;
    }
    if (strncmp(rest, "list/", 5) == 0 && rest[len - 1] == '/')
    {
        /* "list/" and DIR and "/": "list/" alone is the top, "". */
        char *dir = rs_xstrndup(rest + 5, len > 5 ? len - 6 : 0);

        if ((len == 5 || *dir != '\0') && listable(dir))
        {
            route->endpoint = RS_EP_LIST;
            route->name = dir;
        } else
        {
            free(dir);
        }
        return;
    }
    if (strncmp(rest, "f/", 2) == 0)
    {
        route->kind = rs_file_kind_of(rest + 2);
        if (route->kind != RS_FK_NONE)
        {
            route->endpoint = RS_EP_FILE;
            route->name = rs_xstrdup(rest + 2);
        }
    }
}

void rs_route_parse(const char *target, struct rs_route *route)
{
    const char *client;
    const char *slash;

    memset(route, 0, sizeof(*route));
    if (strcmp(target, "/v1/") == 0)
    {
        route->endpoint = RS_EP_HELLO;
        return;
    }
    if (strncmp(target, "/v1/", 4) != 0)
    {
        return;
    }
    client = target + 4;
    slash = strchr(client, '/');
    if (!slash)
    {
        return;
    }
    route->client = rs_xstrndup(client, (size_t)(slash - client));
    if (!rs_grant_client_valid(route->client))
    {
        free(route->client);
        route->client = NULL;
        return;
    }
    route_rest(slash + 1, route);
    if (route->endpoint == RS_EP_NONE)
    {
        route->kind = RS_FK_NONE;
    }
}

bool rs_route_method_ok(enum rs_endpoint ep, enum rs_method m)
{
    switch (ep)
    {
    case RS_EP_HELLO:
    case RS_EP_LIST:
    case RS_EP_FILE:
        return m == RS_METHOD_GET || m == RS_METHOD_HEAD;
    case RS_EP_SESSION_OPEN:
    case RS_EP_SESSION_RENEW:
    case RS_EP_SESSION_END:
    case RS_EP_COMMIT:
        return m == RS_METHOD_POST;
    case RS_EP_UPLOAD:
        return m == RS_METHOD_PUT;
    case RS_EP_NONE:
    default:
        break;
    }
    return true;
}
