/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A restate-proxy request: its head parsed, and what it asks for worked out
 * (docs/proxy-protocol.md).
 *
 * The head is the request line and the headers, read from a connection in
 * pieces as they come: rs_request_parse is given all that has come so far,
 * and says whether it is a whole head yet, how long, or what is wrong with
 * it, as the status code to answer with. Nothing past the head is looked
 * at: what follows is a body of exactly Content-Length bytes, which the
 * server reads only once the request has passed every other check.
 *
 * Only what this protocol has is accepted. HTTP/1.1, origin-form targets
 * made of the characters a repository's names have, and the few headers it
 * uses read strictly: a header it does not use is passed over, but one it
 * does, given twice or malformed, refuses the request. No obs-fold, no
 * Transfer-Encoding (411), nothing past 8 KiB (431).
 */
#ifndef RESTATE_REQUEST_H
#define RESTATE_REQUEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RS_REQUEST_HEAD_MAX 8192
#define RS_SESSION_LEN      32      /* 16 bytes in hex */

enum rs_method {
    RS_METHOD_OTHER = 0,            /* any method this protocol does not use */
    RS_METHOD_GET,
    RS_METHOD_HEAD,
    RS_METHOD_PUT,
    RS_METHOD_POST,
    RS_METHOD_DELETE                /* known, so that it is always 405 */
};

struct rs_request {
    enum rs_method method;
    char          *target;          /* as sent: "/v1/web01/f/packs/X.idx" */
    bool           has_length;
    uint64_t       length;          /* Content-Length */
    char          *token;           /* Authorization: Bearer's, NULL if none */
    bool           token_malformed; /* an Authorization that is not Bearer */
    char           session[RS_SESSION_LEN + 1];  /* Restate-Session, "" if none */
    bool           has_range;
    uint64_t       range_first;
    bool           range_open;      /* "bytes=FIRST-" */
    uint64_t       range_last;
    bool           range_bad;       /* a Range this protocol does not take: 416 */
    bool           expect_continue; /* Expect: 100-continue */
    bool           close;           /* Connection: close */
};

/*
 * The head at the start of the `len` bytes at `data`, into `req`: the
 * number of bytes it is, once it is all there; 0 while it is not, and could
 * still be; or minus the status to refuse it with -- -400, -405, -411, -417,
 * -431, -505 -- and why into *why, for the log. `req` is filled only when
 * the head is whole, and freed by rs_request_free either way.
 */
long rs_request_parse(const char *data, size_t len, struct rs_request *req, const char **why);
void rs_request_free(struct rs_request *req);

/* What a request's target asks for. */
enum rs_endpoint {
    RS_EP_NONE = 0,         /* nothing this protocol has: 404 */
    RS_EP_HELLO,            /* /v1/ */
    RS_EP_SESSION_OPEN,     /* /v1/C/sessions */
    RS_EP_SESSION_RENEW,    /* /v1/C/sessions/ID/renew */
    RS_EP_SESSION_END,      /* /v1/C/sessions/ID/end */
    RS_EP_LIST,             /* /v1/C/list/DIR/ */
    RS_EP_FILE,             /* /v1/C/f/NAME */
    RS_EP_UPLOAD,           /* /v1/C/sessions/ID/files/NAME */
    RS_EP_COMMIT            /* /v1/C/sessions/ID/commit/NAME */
};

/* What a repository's file is, by its name in it. */
enum rs_file_kind {
    RS_FK_NONE = 0,
    RS_FK_MARKER,           /* restate-repository */
    RS_FK_CHUNK_KEY,        /* chunk-key, chunk-key.NAME */
    RS_FK_PACK,             /* packs/NAME.tar.gz */
    RS_FK_PACK_IDX,
    RS_FK_PACK_SUM,
    RS_FK_PACK_SEEK,
    RS_FK_INDEX,            /* snapshots/NAME/index.json.gz */
    RS_FK_INDEX_SIG,
    RS_FK_KIT,
    RS_FK_INFO,
    RS_FK_PACK_LIST         /* snapshots/NAME/packs */
};

struct rs_route {
    enum rs_endpoint  endpoint;
    char             *client;   /* NULL for /v1/ and for what has none */
    char              session[RS_SESSION_LEN + 1];
    char             *name;     /* the file, directory or commit, as in the repository */
    enum rs_file_kind kind;     /* RS_EP_FILE and RS_EP_UPLOAD's */
};

/*
 * `target` worked out into `route`. The client is found first, from
 * "/v1/CLIENT/" alone, so that the token is checked before anything else
 * in the path is: a target whose client is a client's name has it in
 * route->client even when the rest is nothing this protocol has
 * (RS_EP_NONE). Freed by rs_route_free.
 */
void rs_route_parse(const char *target, struct rs_route *route);
void rs_route_free(struct rs_route *route);

/* Whether `m` is what endpoint `ep` takes: false is 405. */
bool rs_route_method_ok(enum rs_endpoint ep, enum rs_method m);

/* What a repository's file `name` is: RS_FK_NONE for anything else. */
enum rs_file_kind rs_file_kind_of(const char *name);

/* The most a file of kind `k` may be uploaded as: what restate writes, and
 * what it reads one back with. 0 for what is never uploaded. */
uint64_t rs_upload_max(enum rs_file_kind k);

#endif /* RESTATE_REQUEST_H */
