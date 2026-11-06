/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate-proxy's sessions (docs/proxy-protocol.md, "Sessions"): what holds
 * a repository's real locks while a client uses it.
 *
 * The table is the listening process's: a session outlives the connection
 * that opened it, and is used from others -- a renew on a connection of its
 * own while an upload goes on in another -- each served by a process of its
 * own, which asks this one (server.c). So here is only the table, with the
 * repositories it holds open; how it is asked is not its concern.
 *
 * A session's lease runs only while it is idle: a request in it holds it
 * (rs_sessions_find) until it is answered (rs_sessions_release), and the
 * lease starts again from then. One idle past its lease is ended, as one its
 * client ends is, and a request in it afterwards finds nothing.
 *
 * Each session that ends is a line of the log, in key=value form:
 *
 *   session-end client=web01 kind=read seconds=812 bytes_in=0 bytes_out=1048576 packs=0 result=ok
 */
#ifndef RESTATE_SESSIONS_H
#define RESTATE_SESSIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "grant.h"
#include "request.h"
#include "serve.h"

#define RS_PROXY_LEASE        300u
#define RS_PROXY_MAX_SESSIONS 64u

struct rs_sessions;

/* A table of at most `max` sessions, each leased for `lease` seconds; each
 * line for the log given to `log`. */
struct rs_sessions *rs_sessions_new(unsigned max, unsigned lease,
                                    void (*log)(void *ctx, const char *line), void *log_ctx);
/* Ends every session, as the proxy stopping does, and frees the table. */
void rs_sessions_free(struct rs_sessions *s, int64_t now);
/* Frees the table without ending a session or saying anything: for a
 * process forked from the one that holds it, whose copies of the locks are
 * only closed, which leaves them held by the holder. */
void rs_sessions_forget(struct rs_sessions *s);

unsigned rs_sessions_lease(const struct rs_sessions *s);
size_t   rs_sessions_count(const struct rs_sessions *s);

/*
 * A session of `kind` for the client of grant `g`, in its repository, at
 * `now`: 201, and its id in `id`; or the status to refuse it with -- 403 if
 * the grant does not allow the kind, 503 if the table is full, 409 for a
 * repository of version 1 an append session would have to change, 423 if
 * its lock is held, 500 if it is no repository the proxy can open, with why
 * in `why` for the log.
 */
int rs_sessions_open(struct rs_sessions *s, const struct rs_grant *g, enum rs_proxy_kind kind,
                     int64_t now, char id[RS_SESSION_LEN + 1], struct rs_buf *why);

/* The session `id`, for a request of `client`'s, into *out -- held until
 * rs_sessions_release, its repository's name valid until then. */
enum rs_proxy_found rs_sessions_find(struct rs_sessions *s, const char *client, const char *id,
                                     struct rs_proxy_session *out);
/* The request that rs_sessions_find held `id` for is answered, having sent
 * `bytes_out`: its lease starts again at `now`. */
void rs_sessions_release(struct rs_sessions *s, const char *id, uint64_t bytes_out, int64_t now);

/* `client`'s session `id` renewed, or ended: 204, 404 for none, 401 for
 * another client's. */
int rs_sessions_renew(struct rs_sessions *s, const char *client, const char *id, int64_t now);
int rs_sessions_end(struct rs_sessions *s, const char *client, const char *id, int64_t now);

/* Ends each session idle past its lease at `now`: how many. */
size_t rs_sessions_expire(struct rs_sessions *s, int64_t now);

/* Replaces where session ids' random bytes are read from, for the tests:
 * NULL for /dev/urandom. */
void rs_sessions_set_random(const char *path);

#endif /* RESTATE_SESSIONS_H */
