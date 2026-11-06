/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "serve.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "repo.h"
#include "request.h"
#include "store.h"
#include "util.h"

#define HELLO "restate-proxy 1\n"
#define LIST_HEAD "restate-list 1\n"
/* How much of a file is read at a time to be sent. */
#define CHUNK ((size_t)64 * 1024)

/* How a request is answered, for the log and for what comes next. */
struct answer {
    int           status;
    const char   *reason;   /* Restate-Reason, or NULL for a success */
    bool          close;    /* the connection ends with it */
    struct rs_buf body;     /* the body, unless it is a file's */
    const char   *type;     /* its Content-Type: text/plain if NULL */
    /* A file's, sent from `fd` (-1 for none). */
    int           fd;
    uint64_t      first;
    uint64_t      length;
    uint64_t      size;
    bool          partial;  /* 206, with Content-Range */
    int64_t       mtime;
};

static void answer_init(struct answer *a)
{
    memset(a, 0, sizeof(*a));
    rs_buf_init(&a->body);
    a->fd = -1;
}

static void answer_free(struct answer *a)
{
    rs_buf_free(&a->body);
    if (a->fd >= 0)
    {
        (void)close(a->fd);
    }
    a->fd = -1;
}

static const char *status_text(int status)
{
    switch (status)
    {
    case 200:
        return "OK";
    case 206:
        return "Partial Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 411:
        return "Length Required";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 431:
        return "Request Header Fields Too Large";
    case 501:
        return "Not Implemented";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "Internal Server Error";
    }
}

/* What a person reads of an error: one line. */
static const char *error_text(int status, const char *reason)
{
    if (strcmp(reason, "unauthorized") == 0)
    {
        return "no good token or session for this client\n";
    }
    if (strcmp(reason, "forbidden") == 0)
    {
        return "not allowed in this kind of session\n";
    }
    if (strcmp(reason, "not-found") == 0)
    {
        return "no such file, directory or session\n";
    }
    if (strcmp(reason, "not-implemented") == 0)
    {
        return "this restate-proxy does not have sessions yet\n";
    }
    if (strcmp(reason, "proxy-failed") == 0)
    {
        return "the proxy failed; its log says why\n";
    }
    if (status == 416)
    {
        return "not one range of bytes within the file\n";
    }
    return "not a request this protocol has\n";
}

static void fail(struct answer *a, int status, const char *reason)
{
    a->status = status;
    a->reason = reason;
    rs_buf_reset(&a->body);
    rs_buf_addstr(&a->body, error_text(status, reason));
}

/* `t` as HTTP writes a time: "Tue, 20 Oct 2026 03:00:00 GMT". */
static void http_time(int64_t t, char out[40])
{
    time_t    tt = (time_t)t;
    struct tm tm;

    if (!gmtime_r(&tt, &tm) || strftime(out, 40, "%a, %d %b %Y %H:%M:%S GMT", &tm) == 0)
    {
        (void)snprintf(out, 40, "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}

/* Sends `length` bytes of `fd`, from where it is: false if it could not be
 * read or written, or ended first. */
static bool send_file(const struct rs_proxy_io *io, int fd, uint64_t length)
{
    char *buf = rs_xmalloc(CHUNK);
    bool  ok = true;

    while (ok && length > 0)
    {
        size_t  want = length < (uint64_t)CHUNK ? (size_t)length : CHUNK;
        ssize_t got = read(fd, buf, want);

        if (got < 0 && errno == EINTR)
        {
            continue;
        }
        ok = got > 0 && io->write(io->ctx, buf, (size_t)got);
        length -= ok ? (uint64_t)got : 0;
    }
    free(buf);
    return ok;
}

/* The answer: its head and, unless `head_only`, its body. False if it could
 * not all be written, which ends the connection. */
static bool respond(const struct rs_proxy_io *io, const struct answer *a, bool head_only)
{
    struct rs_buf out;
    bool          ok;

    rs_buf_init(&out);
    rs_buf_addf(&out, "HTTP/1.1 %d %s\r\n", a->status, status_text(a->status));
    rs_buf_addf(&out, "Content-Type: %s\r\n", a->type ? a->type : "text/plain; charset=utf-8");
    if (a->fd >= 0)
    {
        char when[40];

        http_time(a->mtime, when);
        rs_buf_addf(&out, "Content-Length: %" PRIu64 "\r\n", a->length);
        rs_buf_addstr(&out, "Accept-Ranges: bytes\r\n");
        rs_buf_addf(&out, "Last-Modified: %s\r\n", when);
        if (a->partial)
        {
            rs_buf_addf(&out, "Content-Range: bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64 "\r\n",
                        a->first, a->first + a->length - 1, a->size);
        }
    } else
    {
        rs_buf_addf(&out, "Content-Length: %zu\r\n", a->body.len);
    }
    if (a->status == 416)
    {
        rs_buf_addf(&out, "Content-Range: bytes */%" PRIu64 "\r\n", a->size);
    }
    if (a->reason)
    {
        rs_buf_addf(&out, "Restate-Reason: %s\r\n", a->reason);
    }
    if (a->status == 401)
    {
        rs_buf_addstr(&out, "WWW-Authenticate: Bearer\r\n");
    }
    if (a->close)
    {
        rs_buf_addstr(&out, "Connection: close\r\n");
    }
    rs_buf_addstr(&out, "\r\n");
    if (!head_only && a->fd < 0)
    {
        rs_buf_add(&out, a->body.data, a->body.len);
    }
    ok = io->write(io->ctx, out.data, out.len);
    rs_buf_free(&out);
    if (ok && !head_only && a->fd >= 0)
    {
        ok = send_file(io, a->fd, a->length);
    }
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Reading                                                                  */
/* ------------------------------------------------------------------------ */

/* `dir`'s entry `name` as the repository names it. */
static char *full_name(const char *dir, const char *name)
{
    return *dir ? rs_xasprintf("%s/%s", dir, name) : rs_xstrdup(name);
}

/* Whether a listing of `dir` names `name`: only what the protocol's table of
 * names knows, never a name beginning with "." -- in the top, the marker and
 * the chunk keys; in packs, a pack's files; in snapshots, a snapshot's
 * directory; in one, its files. */
static bool listed(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                   char **out)
{
    bool keep;

    (void)st;
    (void)ctx;
    if (name[0] == '.')
    {
        return false;
    }
    if (strcmp(dir, "snapshots") == 0)
    {
        keep = rs_repo_name_valid(name);
    } else
    {
        enum rs_file_kind k;
        char             *full = full_name(dir, name);

        k = rs_file_kind_of(full);
        free(full);
        keep = *dir ? k != RS_FK_NONE : (k == RS_FK_MARKER || k == RS_FK_CHUNK_KEY);
    }
    if (keep)
    {
        *out = rs_xstrdup(name);
    }
    return keep;
}

/* The listing of `dir` in the repository of `s`. */
static void list(const struct rs_proxy_session *s, const char *dir, struct answer *a)
{
    struct rs_store     *st = rs_store_local(s->repository);
    struct rs_store_stat is;
    size_t               n = 0;
    size_t               i;
    char               **names;

    /* A directory, not anything else of that name. */
    if (*dir && (rs_store_stat(st, dir, &is) != 0 || is.kind != RS_STORE_DIR))
    {
        rs_store_free(st);
        fail(a, 404, "not-found");
        return;
    }
    errno = 0;
    names = rs_store_list(st, dir, listed, NULL, &n);
    if (!names && errno != 0)
    {
        rs_store_free(st);
        fail(a, errno == ENOENT || errno == ENOTDIR ? 404 : 500,
             errno == ENOENT || errno == ENOTDIR ? "not-found" : "proxy-failed");
        return;
    }
    a->status = 200;
    rs_buf_addstr(&a->body, LIST_HEAD);
    for (i = 0; names && i < n; i++)
    {
        char *full = full_name(dir, names[i]);

        /* One gone since it was listed is not listed. */
        if (rs_store_stat(st, full, &is) == 0)
        {
            const char *kind = is.kind == RS_STORE_FILE ? "f" : is.kind == RS_STORE_DIR ? "d" : "o";

            rs_buf_addf(&a->body, "%s %" PRIu64 " %" PRId64 " %s\n", kind,
                        is.kind == RS_STORE_FILE ? is.size : 0, is.mtime, names[i]);
        }
        free(full);
        free(names[i]);
    }
    free(names);
    rs_store_free(st);
}

/* The file `name`, of kind `k`, in the repository of `s`, whole or the range
 * `req` asks for. */
static void file(const struct rs_proxy_session *s, const struct rs_request *req,
                 const char *name, enum rs_file_kind k, struct answer *a)
{
    struct rs_store     *st;
    struct rs_store_stat is;
    struct stat          fst;
    int                  fd;

    /* A pack's content is a restore's alone. */
    if (k == RS_FK_PACK && s->kind != RS_PROXY_READ)
    {
        fail(a, 403, "forbidden");
        return;
    }
    st = rs_store_local(s->repository);
    /* Looked at before it is opened, so that nothing that is no regular
     * file -- a FIFO, which an open would wait on -- is opened at all. */
    if (rs_store_stat(st, name, &is) != 0 || is.kind != RS_STORE_FILE)
    {
        rs_store_free(st);
        fail(a, 404, "not-found");
        return;
    }
    fd = rs_store_open(st, name);
    rs_store_free(st);
    if (fd < 0 || fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode))
    {
        int gone = fd < 0 ? errno : 0;

        if (fd >= 0)
        {
            (void)close(fd);
        }
        fail(a, gone == ENOENT || gone == 0 ? 404 : 500,
             gone == ENOENT || gone == 0 ? "not-found" : "proxy-failed");
        return;
    }
    a->size = (uint64_t)fst.st_size;
    a->mtime = (int64_t)fst.st_mtime;
    a->first = 0;
    a->length = a->size;
    if (req->has_range)
    {
        /* One range, beginning within the file; its end, past the file's,
         * is the file's. */
        if (req->range_bad || req->range_first >= a->size)
        {
            (void)close(fd);
            fail(a, 416, "bad-request");
            return;
        }
        uint64_t last = req->range_open || req->range_last >= a->size ? a->size - 1
                                                                        : req->range_last;

        a->first = req->range_first;
        a->length = last - a->first + 1;
        a->partial = true;
        if (lseek(fd, (off_t)a->first, SEEK_SET) < 0)
        {
            (void)close(fd);
            fail(a, 500, "proxy-failed");
            return;
        }
    }
    a->status = a->partial ? 206 : 200;
    a->type = "application/octet-stream";
    a->fd = fd;
}

/* ------------------------------------------------------------------------ */
/* A request                                                                */
/* ------------------------------------------------------------------------ */

/* The answer to a whole head, `req`, by what it asks for. */
static void decide(const struct rs_proxy_conn *c, const struct rs_request *req,
                   const struct rs_route *route, struct answer *a)
{
    struct rs_proxy_session s;
    const struct rs_grant  *g;
    int64_t                 now = c->now ? c->now : (int64_t)time(NULL);

    if (route->endpoint == RS_EP_HELLO)
    {
        if (req->method == RS_METHOD_GET || req->method == RS_METHOD_HEAD)
        {
            a->status = 200;
            rs_buf_addstr(&a->body, HELLO);
        } else
        {
            fail(a, 405, "bad-request");
        }
        return;
    }
    /* Anything not under a client's name is nothing this protocol has, and
     * says nothing more to anyone. */
    if (!route->client)
    {
        fail(a, 404, "not-found");
        return;
    }
    /* The token first: before the rest of the path, the session or a byte of
     * the body. No token, a malformed one, one nobody has, an expired one,
     * another client's: all the same 401. */
    g = rs_grants_find(c->grants, c->ngrants, route->client);
    if (!req->token || req->token_malformed || !g ||
        !rs_grant_admits(g, req->token, strlen(req->token), now))
    {
        fail(a, 401, "unauthorized");
        return;
    }
    if (route->endpoint == RS_EP_NONE)
    {
        fail(a, 404, "not-found");
        return;
    }
    if (!rs_route_method_ok(route->endpoint, req->method))
    {
        fail(a, 405, "bad-request");
        return;
    }
    if (!c->session || (route->endpoint != RS_EP_LIST && route->endpoint != RS_EP_FILE))
    {
        fail(a, 501, "not-implemented");
        return;
    }
    /* The session: given, the client's own, and not ended. */
    memset(&s, 0, sizeof(s));
    if (req->session[0] == '\0')
    {
        fail(a, 401, "unauthorized");
        return;
    }
    switch (c->session(c->session_ctx, route->client, req->session, &s))
    {
    case RS_PROXY_FOUND:
        break;
    case RS_PROXY_NOT_YOURS:
        fail(a, 401, "unauthorized");
        return;
    case RS_PROXY_NO_SESSION:
    default:
        fail(a, 404, "not-found");
        return;
    }
    if (route->endpoint == RS_EP_LIST)
    {
        list(&s, route->name, a);
    } else
    {
        file(&s, req, route->name, route->kind, a);
    }
}

static const char *method_name(enum rs_method m)
{
    switch (m)
    {
    case RS_METHOD_GET:
        return "GET";
    case RS_METHOD_HEAD:
        return "HEAD";
    case RS_METHOD_PUT:
        return "PUT";
    case RS_METHOD_POST:
        return "POST";
    case RS_METHOD_DELETE:
        return "DELETE";
    case RS_METHOD_OTHER:
    default:
        return "other";
    }
}

/* The request's line in the log, in key=value form; never its token. */
static void log_request(const struct rs_proxy_conn *c, const struct rs_request *req,
                        const struct rs_route *route, const struct answer *a, const char *why)
{
    struct rs_buf line;

    if (!c->log)
    {
        return;
    }
    rs_buf_init(&line);
    rs_buf_addf(&line, "request peer=%s", c->peer ? c->peer : "-");
    if (route && route->client)
    {
        rs_buf_addf(&line, " client=%s", route->client);
    }
    if (req)
    {
        rs_buf_addf(&line, " method=%s target=%s", method_name(req->method),
                    req->target ? req->target : "-");
    }
    rs_buf_addf(&line, " status=%d", a->status);
    if (a->reason)
    {
        rs_buf_addf(&line, " reason=%s", a->reason);
    }
    if (a->fd >= 0 && req && req->method != RS_METHOD_HEAD)
    {
        rs_buf_addf(&line, " bytes=%" PRIu64, a->length);
    }
    if (why && *why)
    {
        /* A fixed phrase of the parser's: quoted, as it has blanks. */
        rs_buf_addf(&line, " why=\"%s\"", why);
    }
    c->log(c->log_ctx, line.data);
    rs_buf_free(&line);
}

unsigned rs_proxy_serve(const struct rs_proxy_io *io, const struct rs_proxy_conn *c)
{
    char     buf[RS_REQUEST_HEAD_MAX];
    size_t   have = 0;
    unsigned served = 0;

    for (;;)
    {
        struct rs_request req;
        struct rs_route   route;
        struct answer     a;
        const char       *why = "";
        long              head;
        bool              ok;

        while ((head = rs_request_parse(buf, have, &req, &why)) == 0)
        {
            long n = io->read(io->ctx, buf + have, sizeof(buf) - have);

            rs_request_free(&req);
            if (n <= 0)
            {
                /* Closed, cut or idle: between requests that is the end of
                 * it, and in the middle of one there is no one to answer. */
                return served;
            }
            have += (size_t)n;
        }
        answer_init(&a);
        if (head < 0)
        {
            /* A head this protocol cannot read: answered, and the
             * connection ended, since where the next request would begin
             * cannot be known. */
            fail(&a, (int)-head, "bad-request");
            a.close = true;
            log_request(c, NULL, NULL, &a, why);
            (void)respond(io, &a, false);
            answer_free(&a);
            rs_request_free(&req);
            return served + 1;
        }
        rs_route_parse(req.target, &route);
        decide(c, &req, &route, &a);
        /* Nothing yet reads a request's body, so one that has a body ends
         * the connection rather than leave it unread there: an Expect:
         * 100-continue is never answered 100, and so the body never sent. */
        a.close = req.close || (req.has_length && req.length > 0) || a.status == 500;
        log_request(c, &req, &route, &a, NULL);
        served++;
        ok = respond(io, &a, req.method == RS_METHOD_HEAD);
        answer_free(&a);
        rs_route_free(&route);
        rs_request_free(&req);
        if (!ok || a.close)
        {
            return served;
        }
        /* What came after the head, the start of the next request. */
        memmove(buf, buf + head, have - (size_t)head);
        have -= (size_t)head;
    }
}
