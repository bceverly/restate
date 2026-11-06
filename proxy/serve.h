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
 * the method -- and then sessions opened, renewed and ended, and, in one,
 * what reads: a directory's listing, and a file, whole or a range of it, or
 * only what HEAD says of one. Uploads and commits are answered 501
 * (not-implemented) until they are here.
 *
 * The sessions themselves are the caller's (rs_proxy_conn.sessions): each
 * of those requests asks them, by its client and id. Without them, every
 * request that needs a session is answered 501.
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

/* The word a session is opened with ("look", "read", "append"), as `len`
 * bytes of a body, a newline after it allowed: false if it is none of them. */
bool rs_proxy_kind_of(const char *word, size_t len, enum rs_proxy_kind *kind);
const char *rs_proxy_kind_name(enum rs_proxy_kind kind);

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

/*
 * The sessions, as a connection asks them. Each answers with the status a
 * request is to have: open 201 (and the id, and the lease in seconds), or
 * 403, 409, 423, 500 or 503; renew 204 (and the lease); end 204; renew and
 * end 404 for no such session and 401 for another client's.
 */
struct rs_proxy_sessions {
    void                *ctx;
    int                 (*open)(void *ctx, const char *client, enum rs_proxy_kind kind,
                                char id[33], unsigned *lease);
    /* The session `id` of `client`, into *s, held until release. */
    enum rs_proxy_found (*find)(void *ctx, const char *client, const char *id,
                                struct rs_proxy_session *s);
    void                (*release)(void *ctx, const char *id, uint64_t bytes_out);
    int                 (*renew)(void *ctx, const char *client, const char *id, unsigned *lease);
    int                 (*end)(void *ctx, const char *client, const char *id);
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
    /* NULL where there are none: 501 for whatever needs one. */
    const struct rs_proxy_sessions *sessions;
};

/* Serves `io` as `c` says: the number of requests answered. */
unsigned rs_proxy_serve(const struct rs_proxy_io *io, const struct rs_proxy_conn *c);

#endif /* RESTATE_SERVE_H */
