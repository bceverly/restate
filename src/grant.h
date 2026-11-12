/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate-proxy's allow list: one file per client in /etc/restate/proxy.d,
 * saying what that client may do (docs/proxy-protocol.md, "Grants").
 *
 *   # /etc/restate/proxy.d/web01.conf
 *   repository   = /srv/restate/web01
 *   operations   = append, read
 *   token_sha256 = 8f14e45fceea167a5a36dedd4bea2543c8d2d1e3c1b5d7d0a2a6a1f6c1f8a9e0
 *   expires      = 2026-12-31T00:00:00Z
 *   label        = managed by sysmanage-agent: web01.example.com
 *   max_sessions = 2
 *   bandwidth    = 08-18 2MiB/s
 *   bandwidth    = 20MiB/s
 *
 * Read as strictly as a job file: an unknown key, a key given twice that may
 * not be, a value of the wrong kind, a line that is not "key = value" -- any
 * of them, and the file grants nothing. Only a file named CLIENT.conf is a
 * grant; a dot file, or any other name, is not looked at, so a grant is
 * written beside its name and renamed into place.
 */
#ifndef RESTATE_GRANT_H
#define RESTATE_GRANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sha256.h"
#include "util.h"

/* What a grant allows: the kinds of session it may open. */
#define RS_GRANT_APPEND 1u
#define RS_GRANT_READ   2u

#define RS_GRANT_TOKENS    2        /* so that one can be rotated */
#define RS_GRANT_LABEL_MAX 256
#define RS_GRANT_FILE_MAX  65536    /* far more than a grant needs */
#define RS_GRANT_CLIENT_MAX 64
#define RS_GRANT_MAX_SESSIONS 1024u                  /* the most max_sessions may be */
#define RS_GRANT_RATE_MIN     ((uint64_t)64 * 1024)  /* the least a bandwidth may be, a second */
#define RS_GRANT_HOURS        24

struct rs_grant {
    char         *client;
    char         *repository;
    unsigned      operations;       /* RS_GRANT_* */
    unsigned char tokens[RS_GRANT_TOKENS][RS_SHA256_SIZE];
    size_t        ntokens;
    bool          expires_set;
    int64_t       expires;          /* seconds since the epoch, UTC */
    char         *label;            /* NULL if it has none */
    unsigned      max_sessions;     /* sessions it may have open at once; 0: no limit of its own */
    /* Bytes a second its requests may move, each way, in each hour of the
     * proxy host's local day; 0: no limit. bandwidth_hours has a bit for
     * each hour a "HH-HH RATE" set, which a RATE alone does not change. */
    uint64_t      bandwidth[RS_GRANT_HOURS];
    uint32_t      bandwidth_hours;
    bool          bandwidth_default; /* whether a RATE alone was given */
};

/* Whether `name` is a client's name: 1 to 64 of A-Z a-z 0-9 . _ -, not
 * beginning with "." or "-". */
bool rs_grant_client_valid(const char *name);

/* Whether the file name `file` is a grant's, CLIENT.conf: its client into
 * *client, which the caller frees. A name beginning with "." or not ending
 * in ".conf" is not, and nothing is said of it; one that ends in ".conf" but
 * whose CLIENT is not a client's name is not either -- *client is then NULL
 * and the result false, and rs_grant_load says why. */
bool rs_grant_file_client(const char *file, char **client);

/* The grant for `client` in the `len` bytes at `text`, into `g`, or false
 * and why into `err` ("line 3: ..."). `g` is always made empty first. */
bool rs_grant_parse(const char *client, const char *text, size_t len, struct rs_grant *g,
                    struct rs_buf *err);

/* The grant in the file `file` in the directory `dir`, as the proxy reads
 * it: a regular file, not a symlink, no larger than RS_GRANT_FILE_MAX, that
 * it and `dir` are root's or this user's and writable by no one else; then
 * rs_grant_parse. */
bool rs_grant_load(const char *dir, const char *file, struct rs_grant *g, struct rs_buf *err);

void rs_grant_free(struct rs_grant *g);

/* Whether `token` (`len` bytes, as the client sent it) is one of the grant's
 * at time `now`: a token, whose digest is one the grant has, in a grant not
 * expired. Every digest the grant has is compared, whichever matches. */
bool rs_grant_admits(const struct rs_grant *g, const char *token, size_t len, int64_t now);

/* Every key a grant file may use, in the order the parser knows them, `*n`
 * of them: `restate features --json` lists them as `grant_keys`, so a
 * program that writes grants (SysManage) writes a key only to a proxy that
 * reads it -- an older proxy refuses a grant with a key it does not know. */
const char *const *rs_grant_keys(size_t *n);

/* The bandwidth `g` allows in `hour` (0 to 23) of the local day: bytes a
 * second, each way, or 0 for no limit. */
uint64_t rs_grant_rate(const struct rs_grant *g, int hour);

/* "unlimited", or a rate as a grant gives one -- "512KiB/s", "2MiB/s",
 * "1GiB/s" -- as bytes a second into *out (0 for unlimited): false if it
 * is neither, or less than RS_GRANT_RATE_MIN. */
bool rs_grant_parse_rate(const char *s, size_t len, uint64_t *out);

/* What restate-proxy --check-grants says of one file. */
struct rs_grant_checked {
    char *file;
    char *client;                   /* NULL where the name is not a client's */
    bool  ok;
    char *error;                    /* NULL if ok */
};

/* Every grant in `dir`, read as rs_grant_load reads one, sorted by file
 * name, into *out: false, and why into `err`, if `dir` cannot be listed. */
bool rs_grants_check(const char *dir, struct rs_grant_checked **out, size_t *n,
                     struct rs_buf *err);
void rs_grants_checked_free(struct rs_grant_checked *c, size_t n);

/*
 * Every grant in `dir` that is good, into *out (*n of them), as the proxy
 * holds them, and each one that is not into *bad (*nbad, in
 * rs_grants_check's form), for its log. False, with why in `err`, only if
 * the directory cannot be read. A client is in *out at most once.
 */
bool rs_grants_load(const char *dir, struct rs_grant **out, size_t *n,
                    struct rs_grant_checked **bad, size_t *nbad, struct rs_buf *err);
void rs_grants_free(struct rs_grant *g, size_t n);

/* The grant for `client` among `n`, or NULL. */
const struct rs_grant *rs_grants_find(const struct rs_grant *g, size_t n, const char *client);

/* What rs_grants_check found, for a person -- one line per file -- or, with
 * `json`, as one object:
 * {"schema": 1, "grants": [{"file", "client", "ok", "error"}, ...]}. */
void rs_grants_report(const struct rs_grant_checked *c, size_t n, bool json, struct rs_buf *out);

/* "2026-12-31T00:00:00Z" as seconds since the epoch: exactly that form, a
 * real date and time, UTC. */
bool rs_grant_parse_time(const char *s, size_t len, int64_t *out);

#endif /* RESTATE_GRANT_H */
