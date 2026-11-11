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
 * only what HEAD says of one; and, in an append session, uploads into its
 * staging and commits from there into the repository (commit.h).
 *
 * The sessions themselves are the caller's (rs_proxy_conn.sessions): each
 * of those requests asks them, by its client and id. Without them, every
 * request that needs a session is answered 501.
 *
 * A connection is one client's: the first request whose token is good for a
 * client binds the connection to it (rs_proxy_conn.bind, where the process
 * confines itself to that client's repository), and a request for any other
 * client on it afterwards is 401.
 *
 * The connection is reached through `rs_proxy_io`, not TLS itself, so that
 * the tests can serve one from memory.
 */
#ifndef RESTATE_SERVE_H
#define RESTATE_SERVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "commit.h"
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
    uint64_t           rate;        /* bytes a second this request may move each way; 0: no limit */
};

/* What opening a session says of a client at its grant's max_sessions: not
 * a status of the protocol's, which says it as 503 client-sessions-full. */
#define RS_PROXY_CLIENT_FULL 429

/* What looking up a session found. */
enum rs_proxy_found {
    RS_PROXY_FOUND = 0,
    RS_PROXY_NO_SESSION,    /* none by that id: 404, as one ended or expired */
    RS_PROXY_NOT_YOURS      /* another client's: 401 */
};

/*
 * The sessions, as a connection asks them. Each answers with the status a
 * request is to have: open 201 (and the id, and the lease in seconds), or
 * 403, 409, 423, 500, 503, RS_PROXY_CLIENT_FULL (the client's own limit,
 * which is said as 503) or 507 (over its quota, with what the quota
 * hook said in `message`, if it said anything); renew 204 (and the lease);
 * end 204; renew and end 404 for no such session and 401 for another
 * client's. quota is NULL where there is no quota hook; otherwise it is
 * asked before an upload of `bytes` as `name` in session `id`: 0 to take
 * it, 507 (and the hook's `message`) if it is over the client's quota, 500
 * if the hook could not say.
 */
struct rs_proxy_sessions {
    void                *ctx;
    int                 (*open)(void *ctx, const char *client, enum rs_proxy_kind kind,
                                char id[33], unsigned *lease, struct rs_buf *message);
    /* The session `id` of `client`, into *s, held until release. */
    enum rs_proxy_found (*find)(void *ctx, const char *client, const char *id,
                                struct rs_proxy_session *s);
    void                (*release)(void *ctx, const char *id, uint64_t bytes_out,
                                   uint64_t bytes_in);
    /* A commit in `id` put something there that was not: the pack
     * "packs/NAME" or the snapshot "snapshots/NAME", by `name`. */
    void                (*committed)(void *ctx, const char *id, const char *name);
    int                 (*renew)(void *ctx, const char *client, const char *id, unsigned *lease);
    int                 (*end)(void *ctx, const char *client, const char *id);
    int                 (*quota)(void *ctx, const char *client, const char *id, const char *name,
                                 uint64_t bytes, struct rs_buf *message);
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
    /* Where an append session's uploads go, STAGING/CLIENT/ID, which the
     * sessions make; NULL: uploads are 501. */
    const char            *staging;
    uint64_t               max_staging;  /* bytes one session's staging may hold; 0: the default */
    /* The connection bound to the client of grant `g`, at its first good
     * token: false, and the request is 500 and the connection ended, if it
     * could not be. NULL binds it to nothing. */
    bool                   (*bind)(void *ctx, const struct rs_grant *g);
    void                  *bind_ctx;
    /* A commit, as rs_proxy_commit does it -- which it is, if NULL. */
    void                   (*commit)(void *ctx, const char *repository, const char *staging,
                                     const char *name, struct rs_proxy_committed *out);
    void                  *commit_ctx;
};

/* How much one session's staging may hold, unless told otherwise: what one
 * capture's last commit, its snapshot, can need at the most. */
#define RS_PROXY_MAX_STAGING ((uint64_t)4 * 1024 * 1024 * 1024)

/* Serves `io` as `c` says: the number of requests answered. */
unsigned rs_proxy_serve(const struct rs_proxy_io *io, const struct rs_proxy_conn *c);

#endif /* RESTATE_SERVE_H */
