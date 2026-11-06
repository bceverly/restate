/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "serve.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "request.h"
#include "util.h"

#define HELLO "restate-proxy 1\n"

/* How a request was answered, for the log and for what comes next. */
struct answer {
    int         status;
    const char *reason;     /* Restate-Reason, or NULL for a success */
    bool        close;      /* the connection ends with it */
};

static const char *status_text(int status)
{
    switch (status)
    {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 411:
        return "Length Required";
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
static const char *error_text(const char *reason)
{
    if (strcmp(reason, "unauthorized") == 0)
    {
        return "no good token for this client\n";
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
    return "not a request this protocol has\n";
}

/* The answer's head and, unless `head_only`, its body: false if it could
 * not be written. */
static bool respond(const struct rs_proxy_io *io, const struct answer *a, const char *body,
                    bool head_only)
{
    struct rs_buf out;
    size_t        len = strlen(body);
    bool          ok;

    rs_buf_init(&out);
    rs_buf_addf(&out, "HTTP/1.1 %d %s\r\n", a->status, status_text(a->status));
    rs_buf_addstr(&out, "Content-Type: text/plain; charset=utf-8\r\n");
    rs_buf_addf(&out, "Content-Length: %zu\r\n", len);
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
    if (!head_only)
    {
        rs_buf_add(&out, body, len);
    }
    ok = io->write(io->ctx, out.data, out.len);
    rs_buf_free(&out);
    return ok;
}

static void fail(struct answer *a, int status, const char *reason)
{
    a->status = status;
    a->reason = reason;
}

/* The answer to a whole head, `req`, by what it asks for. */
static void decide(const struct rs_proxy_conn *c, const struct rs_request *req,
                   const struct rs_route *route, struct answer *a)
{
    const struct rs_grant *g;
    int64_t                now = c->now ? c->now : (int64_t)time(NULL);

    if (route->endpoint == RS_EP_HELLO)
    {
        if (req->method == RS_METHOD_GET || req->method == RS_METHOD_HEAD)
        {
            a->status = 200;
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
    fail(a, 501, "not-implemented");
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
        struct answer     a = { 0, NULL, false };
        const char       *why = "";
        long              head;

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
        if (head < 0)
        {
            /* A head this protocol cannot read: answered, and the
             * connection ended, since where the next request would begin
             * cannot be known. */
            a.status = (int)-head;
            a.reason = "bad-request";
            a.close = true;
            log_request(c, NULL, NULL, &a, why);
            (void)respond(io, &a, error_text(a.reason), false);
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
        if (!respond(io, &a, a.status == 200 ? HELLO : error_text(a.reason),
                     req.method == RS_METHOD_HEAD) ||
            a.close)
        {
            rs_route_free(&route);
            rs_request_free(&req);
            return served;
        }
        rs_route_free(&route);
        rs_request_free(&req);
        /* What came after the head, the start of the next request. */
        memmove(buf, buf + head, have - (size_t)head);
        have -= (size_t)head;
    }
}
