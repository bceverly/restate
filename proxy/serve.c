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
/* The most a session's opening says: "append" and a newline, and room. */
#define KIND_MAX 16
/* How much of a file is read at a time to be sent. */
#define CHUNK ((size_t)64 * 1024)

/* How a request is answered, for the log and for what comes next. */
struct answer {
    int           status;
    const char   *reason;   /* Restate-Reason, or NULL for a success */
    bool          close;    /* the connection ends with it */
    struct rs_buf headers;  /* any more, each with its CRLF */
    struct rs_buf body;     /* the body, unless it is a file's */
    const char   *type;     /* its Content-Type: text/plain if NULL */
    /* A file's, sent from `fd` (-1 for none). */
    int           fd;
    uint64_t      first;
    uint64_t      length;
    uint64_t      size;
    bool          partial;  /* 206, with Content-Range */
    int64_t       mtime;
    uint64_t      bytes_in; /* of an upload's body, taken into staging */
};

static void answer_init(struct answer *a)
{
    memset(a, 0, sizeof(*a));
    rs_buf_init(&a->headers);
    rs_buf_init(&a->body);
    a->fd = -1;
}

static void answer_free(struct answer *a)
{
    rs_buf_free(&a->headers);
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
    case 201:
        return "Created";
    case 204:
        return "No Content";
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
    case 409:
        return "Conflict";
    case 411:
        return "Length Required";
    case 413:
        return "Content Too Large";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 422:
        return "Unprocessable Content";
    case 423:
        return "Locked";
    case 431:
        return "Request Header Fields Too Large";
    case 501:
        return "Not Implemented";
    case 503:
        return "Service Unavailable";
    case 505:
        return "HTTP Version Not Supported";
    case 507:
        return "Insufficient Storage";
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
        return "this restate-proxy takes no uploads: it was started without staging\n";
    }
    if (strcmp(reason, "too-large") == 0)
    {
        return "larger than restate writes that file\n";
    }
    if (strcmp(reason, "storage-full") == 0)
    {
        return "the session's staging, or the disk, is full\n";
    }
    if (strcmp(reason, "name-taken") == 0)
    {
        return "a different pack or snapshot of that name is there\n";
    }
    if (strcmp(reason, "invalid") == 0)
    {
        return "not what restate writes\n";
    }
    if (strcmp(reason, "repository-version-1") == 0)
    {
        return "the repository was made by restate 1.3 or older: one capture on the storage "
               "host makes it version 2\n";
    }
    if (strcmp(reason, "busy") == 0)
    {
        return "the repository is busy: another capture, or a prune\n";
    }
    if (strcmp(reason, "sessions-full") == 0)
    {
        return "the proxy has as many sessions open as it allows; try again later\n";
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
    if (a->status != 204)
    {
        rs_buf_addf(&out, "Content-Type: %s\r\n",
                    a->type ? a->type : "text/plain; charset=utf-8");
    }
    /* A 204 has no body, and so, as HTTP has it, no Content-Length. */
    if (a->status != 204 && a->fd >= 0)
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
    } else if (a->status != 204)
    {
        rs_buf_addf(&out, "Content-Length: %zu\r\n", a->body.len);
    }
    if (a->status == 416)
    {
        rs_buf_addf(&out, "Content-Range: bytes */%" PRIu64 "\r\n", a->size);
    }
    rs_buf_add(&out, a->headers.data, a->headers.len);
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
/* Sessions                                                                 */
/* ------------------------------------------------------------------------ */

bool rs_proxy_kind_of(const char *word, size_t len, enum rs_proxy_kind *kind)
{
    static const char *const words[] = { "look", "read", "append" };
    size_t                   i;

    if (len > 0 && word[len - 1] == '\n')
    {
        len--;
    }
    for (i = 0; i < sizeof(words) / sizeof(words[0]); i++)
    {
        if (len == strlen(words[i]) && memcmp(word, words[i], len) == 0)
        {
            *kind = (enum rs_proxy_kind)i;
            return true;
        }
    }
    return false;
}

const char *rs_proxy_kind_name(enum rs_proxy_kind kind)
{
    switch (kind)
    {
    case RS_PROXY_READ:
        return "read";
    case RS_PROXY_APPEND:
        return "append";
    case RS_PROXY_LOOK:
    default:
        return "look";
    }
}

/* The reason a status the sessions answer with is given. */
static const char *reason_of(int status)
{
    switch (status)
    {
    case 401:
        return "unauthorized";
    case 403:
        return "forbidden";
    case 404:
        return "not-found";
    case 409:
        return "repository-version-1";
    case 423:
        return "busy";
    case 503:
        return "sessions-full";
    default:
        return "proxy-failed";
    }
}

/* Where a request's body is: what of it came after the head, in the
 * connection's buffer, and then the connection. */
struct body {
    const struct rs_proxy_io *io;
    const char               *buf;
    size_t                    have;     /* bytes in buf */
    size_t                    at;       /* the next one of the body there */
    bool                      read;     /* it was read, whole */
};

/* Up to `len` bytes of the body into `out`: what of it the buffer holds,
 * else what the connection gives. How many, or 0 if the connection ended. */
static size_t read_some(struct body *b, char *out, size_t len)
{
    long n;

    if (b->at < b->have)
    {
        size_t k = b->have - b->at < len ? b->have - b->at : len;

        memcpy(out, b->buf + b->at, k);
        b->at += k;
        return k;
    }
    n = b->io->read(b->io->ctx, out, len);
    return n > 0 ? (size_t)n : 0;
}

/* The `len` bytes of the body into `out`: false if the connection ended
 * first. */
static bool read_body(struct body *b, char *out, size_t len)
{
    size_t got = 0;

    while (got < len)
    {
        if (b->at < b->have)
        {
            size_t n = b->have - b->at < len - got ? b->have - b->at : len - got;

            memcpy(out + got, b->buf + b->at, n);
            b->at += n;
            got += n;
        } else
        {
            long n = b->io->read(b->io->ctx, out + got, len - got);

            if (n <= 0)
            {
                return false;
            }
            got += (size_t)n;
        }
    }
    b->read = true;
    return true;
}

/* POST /v1/CLIENT/sessions: its body the kind, read only now that every
 * check before it has passed -- which is when an Expect: 100-continue is
 * answered, so that a refused one sends nothing. */
static void open_session(const struct rs_proxy_conn *c, const struct rs_request *req,
                         const struct rs_route *route, struct body *b, struct answer *a)
{
    enum rs_proxy_kind kind;
    char               word[KIND_MAX];
    char               id[RS_SESSION_LEN + 1];
    unsigned           lease = 0;
    int                status;

    if (!req->has_length)
    {
        fail(a, 411, "bad-request");
        a->close = true;
        return;
    }
    if (req->length == 0 || req->length > KIND_MAX)
    {
        fail(a, 400, "bad-request");
        a->close = true;
        return;
    }
    if (req->expect_continue &&
        !b->io->write(b->io->ctx, "HTTP/1.1 100 Continue\r\n\r\n", 25))
    {
        fail(a, 400, "bad-request");
        a->close = true;
        return;
    }
    if (!read_body(b, word, (size_t)req->length))
    {
        fail(a, 400, "bad-request");
        a->close = true;
        return;
    }
    if (!rs_proxy_kind_of(word, (size_t)req->length, &kind))
    {
        fail(a, 400, "bad-request");
        return;
    }
    memset(id, 0, sizeof(id));
    status = c->sessions->open(c->sessions->ctx, route->client, kind, id, &lease);
    if (status != 201)
    {
        fail(a, status, reason_of(status));
        return;
    }
    a->status = 201;
    rs_buf_addf(&a->headers, "Restate-Session: %s\r\nRestate-Lease: %u\r\n", id, lease);
    rs_buf_addf(&a->body, "%s\n", id);
}

/* ------------------------------------------------------------------------ */
/* Writing                                                                  */
/* ------------------------------------------------------------------------ */

/* Where session `id` of `client` has its uploads. */
static char *session_staging(const struct rs_proxy_conn *c, const char *client, const char *id)
{
    return rs_xasprintf("%s/%s/%s", c->staging, client, id);
}

/* A directory to look in, and how many levels below it to go. */
struct to_walk {
    char *dir;
    int   depth;
};

/* The bytes the files in `st` hold, to `depth` levels below its top: as
 * deep as staging goes, snapshots/NAME/FILE. */
static uint64_t staged_bytes(const struct rs_store *st, int depth)
{
    struct to_walk *walk = rs_xmalloc(sizeof(*walk));
    size_t          nwalk = 1;
    uint64_t        total = 0;

    walk[0].dir = rs_xstrdup("");
    walk[0].depth = depth;
    while (nwalk > 0)
    {
        struct to_walk at = walk[--nwalk];
        size_t         n = 0;
        size_t         i;
        char         **names = rs_store_list(st, at.dir, rs_store_keep_all, NULL, &n);

        for (i = 0; names && i < n; i++)
        {
            char                *full = full_name(at.dir, names[i]);
            struct rs_store_stat is;
            /* One gone since it was listed counts for nothing. */
            bool                 there = rs_store_stat(st, full, &is) == 0;

            if (there && is.kind == RS_STORE_FILE)
            {
                total += is.size;
            } else if (there && is.kind == RS_STORE_DIR && at.depth > 0)
            {
                walk = rs_xreallocarray(walk, nwalk + 1, sizeof(*walk));
                walk[nwalk].dir = full;
                walk[nwalk++].depth = at.depth - 1;
                full = NULL;
            }
            free(full);
            free(names[i]);
        }
        free(names);
        free(at.dir);
    }
    free(walk);
    return total;
}

/* The directories an upload of `name` goes into, made: "packs", or
 * "snapshots" and the snapshot's own. False, errno set, if one could not be. */
static bool make_dirs_for(const struct rs_store *st, const char *name)
{
    const char *slash = strrchr(name, '/');
    const char *p;

    for (p = name; slash && (p = strchr(p, '/')) != NULL && p <= slash; p++)
    {
        char *dir = rs_xstrndup(name, (size_t)(p - name));
        int   rc = rs_store_make_dir(st, dir, 0700, true);

        free(dir);
        if (rc != 0)
        {
            return false;
        }
    }
    return true;
}

/* Whether errno `e` is a full disk, or a full quota. */
static bool full(int e)
{
#ifdef EDQUOT
    if (e == EDQUOT)
    {
        return true;
    }
#endif
    return e == ENOSPC;
}

/*
 * PUT /v1/CLIENT/sessions/ID/files/NAME: the body, written into the
 * session's staging as NAME, beside it first and renamed into place once it
 * is whole, so that a name there is a whole upload or the one before it.
 * Everything that refuses it is said before a byte of the body is read.
 */
static void upload(const struct rs_proxy_conn *c, const struct rs_request *req,
                   const struct rs_route *route, const struct rs_proxy_session *s,
                   struct body *b, struct answer *a)
{
    struct rs_store     *st;
    struct rs_store_stat is;
    char                *dir;
    char                *tmp;
    char                *buf;
    const char          *slash;
    uint64_t             max = c->max_staging ? c->max_staging : RS_PROXY_MAX_STAGING;
    uint64_t             used;
    uint64_t             left;
    int                  fd;
    int                  failure = 0;

    if (s->kind != RS_PROXY_APPEND)
    {
        fail(a, 403, "forbidden");
        return;
    }
    if (!req->has_length)
    {
        fail(a, 411, "bad-request");
        return;
    }
    if (req->length > rs_upload_max(route->kind))
    {
        fail(a, 413, "too-large");
        return;
    }
    dir = session_staging(c, route->client, route->session[0] ? route->session : req->session);
    st = rs_store_local(dir);
    if (rs_store_stat(st, "", &is) != 0 || is.kind != RS_STORE_DIR)
    {
        if (c->log)
        {
            char *line = rs_xasprintf("upload-failed client=%s error=\"the session's staging "
                                      "is not there\"", route->client);

            c->log(c->log_ctx, line);
            free(line);
        }
        rs_store_free(st);
        free(dir);
        fail(a, 500, "proxy-failed");
        return;
    }
    /* What staging holds, but the file this one replaces, and this one. */
    used = staged_bytes(st, 2);
    if (rs_store_stat(st, route->name, &is) == 0 && is.kind == RS_STORE_FILE)
    {
        used -= is.size < used ? is.size : used;
    }
    if (used > max || req->length > max - used)
    {
        rs_store_free(st);
        free(dir);
        fail(a, 507, "storage-full");
        return;
    }
    if (!make_dirs_for(st, route->name))
    {
        int e = errno;

        rs_store_free(st);
        free(dir);
        fail(a, full(e) ? 507 : 500, full(e) ? "storage-full" : "proxy-failed");
        return;
    }
    if (req->expect_continue &&
        !b->io->write(b->io->ctx, "HTTP/1.1 100 Continue\r\n\r\n", 25))
    {
        rs_store_free(st);
        free(dir);
        fail(a, 400, "bad-request");
        a->close = true;
        return;
    }
    slash = strrchr(route->name, '/');
    tmp = slash ? rs_xasprintf("%.*s/.%s.up", (int)(slash - route->name), route->name, slash + 1)
                : rs_xasprintf(".%s.up", route->name);
    (void)rs_store_remove(st, tmp, false);
    fd = rs_store_create(st, tmp);
    if (fd < 0)
    {
        failure = errno;
    }
    buf = rs_xmalloc(CHUNK);
    for (left = req->length; fd >= 0 && left > 0;)
    {
        size_t got = read_some(b, buf, left < (uint64_t)CHUNK ? (size_t)left : CHUNK);
        size_t done = 0;

        if (got == 0)
        {
            /* Cut short: nothing of it is kept, and there is no one to
             * answer. */
            break;
        }
        while (done < got)
        {
            ssize_t w = write(fd, buf + done, got - done);

            if (w < 0 && errno == EINTR)
            {
                continue;
            }
            if (w <= 0)
            {
                failure = errno ? errno : EIO;
                break;
            }
            done += (size_t)w;
        }
        if (failure)
        {
            break;
        }
        left -= got;
    }
    free(buf);
    if (fd >= 0 && close(fd) != 0 && !failure)
    {
        failure = errno;
    }
    if (left == 0 && !failure && rs_store_rename(st, tmp, route->name, false) != 0)
    {
        failure = errno;
    }
    if (left > 0 || failure)
    {
        (void)rs_store_remove(st, tmp, false);
        rs_store_free(st);
        free(tmp);
        free(dir);
        /* What is left of the body is not read: the connection ends. */
        if (left > 0 && !failure && fd >= 0)
        {
            fail(a, 400, "bad-request");
        } else
        {
            fail(a, full(failure) ? 507 : 500, full(failure) ? "storage-full" : "proxy-failed");
        }
        a->close = true;
        return;
    }
    b->read = true;
    rs_store_free(st);
    free(tmp);
    free(dir);
    a->status = 201;
    a->bytes_in = req->length;
}

/* POST /v1/CLIENT/sessions/ID/commit/NAME: what staging holds for NAME,
 * into the repository. */
static void commit(const struct rs_proxy_conn *c, const struct rs_request *req,
                   const struct rs_route *route, const struct rs_proxy_session *s,
                   struct answer *a)
{
    struct rs_proxy_committed out;
    char                     *dir;

    if (s->kind != RS_PROXY_APPEND)
    {
        fail(a, 403, "forbidden");
        return;
    }
    if (req->has_length && req->length > 0)
    {
        fail(a, 400, "bad-request");
        return;
    }
    dir = session_staging(c, route->client, route->session);
    rs_proxy_committed_init(&out);
    if (c->commit)
    {
        c->commit(c->commit_ctx, s->repository, dir, route->name, &out);
    } else
    {
        rs_proxy_commit(s->repository, dir, route->name, &out);
    }
    free(dir);
    if (out.status == 200 || out.status == 201)
    {
        a->status = out.status;
        if (out.pack_added || out.snapshot_added)
        {
            c->sessions->committed(c->sessions->ctx, route->session, route->name);
        }
    } else
    {
        fail(a, out.status, out.reason ? out.reason : "proxy-failed");
        if ((out.status == 422 || out.status == 409) && out.message.len > 0)
        {
            rs_buf_reset(&a->body);
            rs_buf_addf(&a->body, "%s\n", out.message.data);
        } else if (c->log)
        {
            char *line = rs_xasprintf("commit-failed client=%s name=%s error=\"%s\"",
                                      route->client, route->name,
                                      out.message.data ? out.message.data : "");

            c->log(c->log_ctx, line);
            free(line);
        }
    }
    rs_proxy_committed_free(&out);
}

/* ------------------------------------------------------------------------ */
/* A request                                                                */
/* ------------------------------------------------------------------------ */

/* The answer to a whole head, `req`, by what it asks for. */
static void decide(const struct rs_proxy_conn *c, const struct rs_request *req,
                   const struct rs_route *route, struct body *b, struct answer *a,
                   char held[RS_SESSION_LEN + 1], char **bound)
{
    struct rs_proxy_session s;
    const struct rs_grant  *g;
    const char             *sid;
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
    /* The connection is this client's from its first good token on: bound
     * to it, and no other's. */
    if (!*bound)
    {
        if (c->bind && !c->bind(c->bind_ctx, g))
        {
            fail(a, 500, "proxy-failed");
            a->close = true;
            return;
        }
        *bound = rs_xstrdup(route->client);
    } else if (strcmp(*bound, route->client) != 0)
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
    if (!c->sessions ||
        ((route->endpoint == RS_EP_UPLOAD || route->endpoint == RS_EP_COMMIT) && !c->staging))
    {
        fail(a, 501, "not-implemented");
        return;
    }
    if (route->endpoint == RS_EP_SESSION_OPEN)
    {
        open_session(c, req, route, b, a);
        return;
    }
    if (route->endpoint == RS_EP_SESSION_RENEW || route->endpoint == RS_EP_SESSION_END)
    {
        unsigned lease = 0;
        int      status = route->endpoint == RS_EP_SESSION_RENEW
                              ? c->sessions->renew(c->sessions->ctx, route->client,
                                                   route->session, &lease)
                              : c->sessions->end(c->sessions->ctx, route->client,
                                                 route->session);

        if (status != 204)
        {
            fail(a, status, reason_of(status));
            return;
        }
        a->status = 204;
        if (route->endpoint == RS_EP_SESSION_RENEW)
        {
            rs_buf_addf(&a->headers, "Restate-Lease: %u\r\n", lease);
        }
        return;
    }
    /* The session: given, the client's own, and not ended -- in the path,
     * for an upload and a commit, and in its header for the rest. */
    memset(&s, 0, sizeof(s));
    sid = route->session[0] ? route->session : req->session;
    if (sid[0] == '\0')
    {
        fail(a, 401, "unauthorized");
        return;
    }
    switch (c->sessions->find(c->sessions->ctx, route->client, sid, &s))
    {
    case RS_PROXY_FOUND:
        /* Held, its lease not running, until it is answered. */
        memcpy(held, sid, RS_SESSION_LEN + 1);
        break;
    case RS_PROXY_NOT_YOURS:
        fail(a, 401, "unauthorized");
        return;
    case RS_PROXY_NO_SESSION:
    default:
        fail(a, 404, "not-found");
        return;
    }
    switch (route->endpoint)
    {
    case RS_EP_LIST:
        list(&s, route->name, a);
        break;
    case RS_EP_UPLOAD:
        upload(c, req, route, &s, b, a);
        break;
    case RS_EP_COMMIT:
        commit(c, req, route, &s, a);
        break;
    case RS_EP_FILE:
    default:
        file(&s, req, route->name, route->kind, a);
        break;
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
    if (a->bytes_in > 0)
    {
        rs_buf_addf(&line, " bytes_in=%" PRIu64, a->bytes_in);
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
    char    *bound = NULL;

    for (;;)
    {
        struct rs_request req;
        struct rs_route   route;
        struct answer     a;
        struct body       body;
        char              held[RS_SESSION_LEN + 1];
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
                free(bound);
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
            free(bound);
            return served + 1;
        }
        rs_route_parse(req.target, &route);
        body.io = io;
        body.buf = buf;
        body.have = have;
        body.at = (size_t)head;
        body.read = false;
        held[0] = '\0';
        decide(c, &req, &route, &body, &a, held, &bound);
        /* A body that was not read ends the connection rather than be left
         * there unread: an Expect: 100-continue was not answered 100, and
         * so it was never sent. */
        a.close = a.close || req.close || (req.has_length && req.length > 0 && !body.read) ||
                  a.status == 500;
        log_request(c, &req, &route, &a, NULL);
        served++;
        ok = respond(io, &a, req.method == RS_METHOD_HEAD);
        if (held[0])
        {
            uint64_t sent = req.method == RS_METHOD_HEAD ? 0
                            : a.fd >= 0                  ? a.length
                                                         : (uint64_t)a.body.len;

            c->sessions->release(c->sessions->ctx, held, ok ? sent : 0, a.bytes_in);
        }
        answer_free(&a);
        rs_route_free(&route);
        rs_request_free(&req);
        if (!ok || a.close)
        {
            free(bound);
            return served;
        }
        /* What came after the head and its body, the start of the next
         * request. */
        memmove(buf, buf + body.at, have - body.at);
        have -= body.at;
    }
}
