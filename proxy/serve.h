/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * One connection to restate-proxy, served: its requests read one after
 * another, each checked as docs/proxy-protocol.md says and answered, until
 * the client closes it, a request that has to end it is answered, or it is
 * idle for longer than the socket allows.
 *
 * Answered: GET /v1/, and every check a request passes before its session
 * -- the head, the client, the token against the client's grant, the name,
 * the method -- and then, in a session, what reads: a directory's listing,
 * and a file, whole or a range of it, or only what HEAD says of one.
 *
 * Sessions themselves are the caller's (rs_proxy_conn.session): a request's
 * session is looked up there, by its client and id. Where there is no way
 * to look one up, or for what sessions do themselves -- open, renew, end,
 * upload, commit -- the answer is 501 (not-implemented), until they are
 * here.
 *
 * The connection is reached through `rs_proxy_io`, not TLS itself, so that
 * the tests can serve one from memory.
 */
#ifndef RESTATE_SERVE_H
#define RESTATE_SERVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "grant.h"

struct rs_proxy_io {
    void *ctx;
    /* Up to `len` bytes: how many, 0 at the end, -1 on an error or a timeout. */
    long (*read)(void *ctx, void *buf, size_t len);
    /* All `len` bytes, or false. */
    bool (*write)(void *ctx, const void *buf, size_t len);
};

/* The kinds of session (docs/proxy-protocol.md, "Sessions"). */
enum rs_proxy_kind {
    RS_PROXY_LOOK = 0,      /* indexes and lists: no lock */
    RS_PROXY_READ,          /* a restore: readers, shared */
    RS_PROXY_APPEND         /* a capture: lock, exclusive */
};

/* A session, as a request in it sees it. */
struct rs_proxy_session {
    enum rs_proxy_kind kind;
    const char        *repository;  /* its directory, as the grant names it */
};

/* What looking up a session found. */
enum rs_proxy_found {
    RS_PROXY_FOUND = 0,
    RS_PROXY_NO_SESSION,    /* none by that id: 404, as one ended or expired */
    RS_PROXY_NOT_YOURS      /* another client's: 401 */
};

/* What a connection is served with. */
struct rs_proxy_conn {
    const struct rs_grant *grants;
    size_t                 ngrants;
    const char            *peer;     /* its address, for the log */
    int64_t                now;      /* 0: the clock's; otherwise, for the tests */
    /* Each request's log line, without its newline; NULL logs nothing. */
    void                   (*log)(void *ctx, const char *line);
    void                  *log_ctx;
    /* The session `id` of `client`, into *s, which holds until the request
     * is answered; NULL where there are no sessions yet (501). */
    enum rs_proxy_found    (*session)(void *ctx, const char *client, const char *id,
                                      struct rs_proxy_session *s);
    void                  *session_ctx;
};

/* Serves `io` as `c` says: the number of requests answered. */
unsigned rs_proxy_serve(const struct rs_proxy_io *io, const struct rs_proxy_conn *c);

#endif /* RESTATE_SERVE_H */
