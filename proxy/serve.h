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
 * What is answered so far is what needs no session: GET /v1/, and every
 * check a request passes before one -- the head, the client, the token
 * against the client's grant, the name, the method. A request that passes
 * them all, for what a session does, is answered 501 (not-implemented) until
 * sessions are here.
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

/* What a connection is served with. */
struct rs_proxy_conn {
    const struct rs_grant *grants;
    size_t                 ngrants;
    const char            *peer;     /* its address, for the log */
    int64_t                now;      /* 0: the clock's; otherwise, for the tests */
    /* Each request's log line, without its newline; NULL logs nothing. */
    void                   (*log)(void *ctx, const char *line);
    void                  *log_ctx;
};

/* Serves `io` as `c` says: the number of requests answered. */
unsigned rs_proxy_serve(const struct rs_proxy_io *io, const struct rs_proxy_conn *c);

#endif /* RESTATE_SERVE_H */
