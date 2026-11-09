/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A repository behind restate-proxy: https://HOST[:PORT]/v1/CLIENT.
 *
 * A store (store.h) whose files are reached through the proxy, by running
 * curl -- the protocol is docs/proxy-protocol.md. Every request is made in a
 * session, opened as the store is first used: of the kind rs_remote_begin
 * gives, or else `look`. The session holds the repository's locks in the
 * proxy, so a store's lock is what its session holds, and a child process
 * renews its lease while it is open and ends it once this process is done
 * with it -- or is gone, however it went.
 *
 * curl is given everything on a config file (-K) in a directory of this
 * process's own, 0700 -- the token as a header, never on a command line --
 * and writes each answer's headers to a file there (-D), from which its
 * status and Restate-Reason are read. A file read is fetched whole into that
 * directory, and what is open is a descriptor on it, removed already.
 */
#ifndef RESTATE_REMOTE_H
#define RESTATE_REMOTE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "store.h"
#include "util.h"

struct rs_remote;

/* The kinds of session, as the protocol names them. */
enum rs_remote_kind {
    RS_REMOTE_LOOK = 0,   /* indexes and listings: no lock */
    RS_REMOTE_READ,       /* a restore: the readers lock, shared */
    RS_REMOTE_APPEND      /* a capture: the lock */
};

/* Whether `where` is a repository behind restate-proxy: it begins with
 * "https://". Nothing is asked of the network. */
bool rs_remote_is(const char *where);

/*
 * Whether `url` is one restate can use: https://HOST[:PORT]/v1/CLIENT, a
 * host name or an address (an IPv6 one in brackets), a port of 1 to 65535,
 * and CLIENT as the proxy's grants name one -- with nothing after it, a
 * trailing '/' aside. Why not, into `err`, if it is not.
 */
bool rs_remote_url_ok(const char *url, struct rs_buf *err);

/* Where the "::" of a reference REPO::NAME is looked for in `ref`: past the
 * brackets of a proxy's IPv6 address, which has "::" of its own, where `ref`
 * begins with one -- else at its start. */
const char *rs_remote_sep_from(const char *ref);

/*
 * What every remote store is reached with, for this run: the token file
 * (--repository-token-file), the certificate authorities to trust instead of
 * the system's (--repository-ca-file), and up to two keys the proxy's may be
 * (--repository-pin-sha256, base64 SHA-256). Borrowed; NULL and 0 for none.
 */
void rs_remote_configure(const char *token_file, const char *ca_file, const char *const *pins,
                         size_t npins);

/* Whether `pin` is one --repository-pin-sha256 takes: 44 characters of
 * base64, the last '='. */
bool rs_remote_pin_ok(const char *pin);

/* A store for `url`, which nothing has been asked of yet. */
struct rs_remote *rs_remote_new(const char *url);
/* Ends its session, if it has one, and frees it. */
void rs_remote_free(struct rs_remote *rm);

/*
 * Opens its session, of `kind`, unless it has one already of that kind. A
 * repository busy with a capture or a prune (423), and a proxy at its limit
 * of sessions (503), set *busy; anything else, `err` says.
 */
bool rs_remote_begin(struct rs_remote *rm, enum rs_remote_kind kind, bool *busy,
                     struct rs_buf *err);

/* The store's operations; store.h says what each does. Every one opens a
 * `look` session first, where none is open. */
int     rs_remote_stat(struct rs_remote *rm, const char *name, struct rs_store_stat *out);
char  **rs_remote_list(struct rs_remote *rm, const struct rs_store *st, const char *name,
                       rs_store_keep keep, void *ctx, size_t *n);
int     rs_remote_open_at(struct rs_remote *rm, const char *name, uint64_t offset);
ssize_t rs_remote_peek(struct rs_remote *rm, const char *name, void *buf, size_t max);
bool    rs_remote_read(struct rs_remote *rm, const char *name, size_t max, struct rs_buf *out,
                       struct rs_buf *err);
/* The lock the session holds for `name`: "lock" in an append session,
 * "readers" in a read one. A handle (1), or -1 with `err` saying why. */
int rs_remote_lock(struct rs_remote *rm, const char *name, bool shared, bool *busy,
                   struct rs_buf *err);

/*
 * Fetches `names` in one curl, over one connection, so that reading each
 * afterwards asks nothing more of the proxy: what a capture reads of every
 * pack it has no copy of. One that cannot be fetched is passed over; reading
 * it says why.
 */
void rs_remote_prefetch(struct rs_remote *rm, const char *const *names, size_t n);

/* Whether a proxy has refused a session as busy (423) or at its limit of
 * sessions (503) in this run, in any store. */
bool rs_remote_busy(void);

/* The Restate-Reason of the last answer from a proxy that was a failure, in
 * any store, for a result's proxy_reason; NULL if there has been none. */
const char *rs_remote_reason(void);

/* ------------------------------------------------------------------------- */
/* For the unit tests                                                        */
/* ------------------------------------------------------------------------- */

/*
 * Runs `conf` as `curl -q -K conf` would: 0, or curl's exit status. The
 * default runs curl. A test gives one that reads the file and writes each
 * request's headers and body where it says, as a proxy would answer it; NULL
 * restores curl. With one given, no child renews a lease.
 */
typedef int (*rs_remote_transport)(const char *conf, void *ctx);
void rs_remote_set_transport(rs_remote_transport fn, void *ctx);

/* What an answer's headers say: the status of the last response in them --
 * after any 100 Continue -- and its Restate-Reason, Restate-Session and
 * Restate-Lease. False if there is no status line in them. */
struct rs_remote_answer {
    int      status;
    char     reason[64];
    char     session[33];
    unsigned lease;
};
bool rs_remote_parse_headers(const char *text, size_t len, struct rs_remote_answer *out);

/* One entry of a `restate-list 1` listing. */
struct rs_remote_entry {
    char                *name;
    struct rs_store_stat st;
};
/* A listing's entries, in order; false if it is not one. */
bool rs_remote_parse_list(const char *text, size_t len, struct rs_remote_entry **out, size_t *n);
void rs_remote_entries_free(struct rs_remote_entry *e, size_t n);

/* What the renewing child does, once each: renew the lease, or end the
 * session -- for the tests, which run no child. */
bool rs_remote_renew(struct rs_remote *rm);
void rs_remote_end(struct rs_remote *rm);

#endif /* RESTATE_REMOTE_H */
