/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "server.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "commit.h"
#include "confine.h"
#include "grant.h"
#include "quota.h"
#include "repo.h"
#include "restate.h"
#include "serve.h"
#include "sessions.h"
#include "tlsconn.h"
#include "util.h"

#define LISTEN_MAX   16
#define BACKLOG      128
/* How often the parent looks at proxy.d for a change, in milliseconds. */
#define WATCH_MS     2000
/* How long it waits for its children to stop, in seconds. */
#define STOP_WAIT    10

/* Set by the signal handlers, and the pipe that wakes poll for them. */
static volatile sig_atomic_t got_stop;
static volatile sig_atomic_t got_hup;
static int                   wake[2] = { -1, -1 };

static void on_signal(int sig)
{
    int  saved = errno;
    char c = 0;

    if (sig == SIGHUP)
    {
        got_hup = 1;
    } else if (sig == SIGTERM || sig == SIGINT)
    {
        got_stop = 1;
    }
    /* SIGCHLD only wakes the loop, to reap. */
    if (wake[1] >= 0)
    {
        ssize_t w = write(wake[1], &c, 1);

        (void)w;
    }
    errno = saved;
}

/* A line of the log: "restate-proxy: " and it, written at once, so that the
 * children's lines and the parent's do not cut into each other. */
static void say(const char *fmt, ...) RESTATE_PRINTF(1, 2);

static void say(const char *fmt, ...)
{
    struct rs_buf line;
    va_list       ap;
    char         *text;

    va_start(ap, fmt);
    text = rs_xvasprintf(fmt, ap);
    va_end(ap);
    rs_buf_init(&line);
    rs_buf_addf(&line, "restate-proxy: %s\n", text);
    if (write(STDERR_FILENO, line.data, line.len) < 0)
    {
        /* Nowhere else to say it. */
    }
    rs_buf_free(&line);
    free(text);
}

static void log_line(void *ctx, const char *line)
{
    (void)ctx;
    say("%s", line);
}

/* ------------------------------------------------------------------------ */
/* Listening                                                                */
/* ------------------------------------------------------------------------ */

/* `spec` as a host and a port: HOST:PORT, [V6]:PORT, :PORT or *:PORT, the
 * host NULL for every address. False if it is none of them. */
static bool split_listen(const char *spec, char **host, char **port)
{
    const char *colon;

    *host = NULL;
    *port = NULL;
    if (spec[0] == '[')
    {
        const char *close = strchr(spec, ']');

        if (!close || close[1] != ':' || close == spec + 1)
        {
            return false;
        }
        *host = rs_xstrndup(spec + 1, (size_t)(close - spec - 1));
        colon = close + 1;
    } else
    {
        colon = strrchr(spec, ':');
        if (!colon)
        {
            return false;
        }
        if (colon > spec && !(colon == spec + 1 && spec[0] == '*'))
        {
            *host = rs_xstrndup(spec, (size_t)(colon - spec));
        }
    }
    if (colon[1] == '\0' || strspn(colon + 1, "0123456789") != strlen(colon + 1))
    {
        free(*host);
        *host = NULL;
        return false;
    }
    *port = rs_xstrdup(colon + 1);
    return true;
}

/* `sa` as ADDRESS:PORT, [V6]:PORT, for the log. */
static void addr_text(const struct sockaddr *sa, socklen_t len, char *out, size_t size)
{
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];

    if (getnameinfo(sa, len, host, sizeof(host), port, sizeof(port),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    {
        (void)snprintf(out, size, "?");
        return;
    }
    if (sa->sa_family == AF_INET6)
    {
        (void)snprintf(out, size, "[%s]:%s", host, port);
    } else
    {
        (void)snprintf(out, size, "%s:%s", host, port);
    }
}

/* Binds every address `spec` names, adding each socket to fds: false, said,
 * if it names none that could be bound. */
static bool listen_on(const char *spec, int *fds, size_t *nfds)
{
    struct addrinfo  hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char            *host;
    char            *port;
    size_t           before = *nfds;
    int              rc;

    if (!split_listen(spec, &host, &port))
    {
        say("--listen %s: not HOST:PORT, [ADDRESS]:PORT or :PORT", spec);
        return false;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0)
    {
        say("--listen %s: %s", spec, gai_strerror(rc));
        free(host);
        free(port);
        return false;
    }
    for (ai = res; ai && *nfds < LISTEN_MAX; ai = ai->ai_next)
    {
        struct sockaddr_storage bound;
        socklen_t               blen = sizeof(bound);
        char                    text[NI_MAXHOST + NI_MAXSERV + 4];
        int                     one = 1;
        int                     fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        memset(&bound, 0, sizeof(bound));
        if (fd < 0)
        {
            continue;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef IPV6_V6ONLY
        /* Each family on its own socket: an IPv6 one that took IPv4 too
         * would be refused the IPv4 address its sibling binds. */
        if (ai->ai_family == AF_INET6)
        {
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        }
#endif
        addr_text(ai->ai_addr, ai->ai_addrlen, text, sizeof(text));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0 || listen(fd, BACKLOG) != 0)
        {
            say("listening on %s: %s", text, strerror(errno));
            (void)close(fd);
            continue;
        }
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        /* What was bound, which for port 0 is the port the system chose. */
        if (getsockname(fd, (struct sockaddr *)&bound, &blen) == 0)
        {
            addr_text((struct sockaddr *)&bound, blen, text, sizeof(text));
        }
        say("listening on %s", text);
        fds[(*nfds)++] = fd;
    }
    freeaddrinfo(res);
    free(host);
    free(port);
    return *nfds > before;
}

/* ------------------------------------------------------------------------ */
/* Grants                                                                   */
/* ------------------------------------------------------------------------ */

struct grants {
    struct rs_grant *g;
    size_t           n;
    bool             read;      /* the directory has been read at all */
    time_t           mtime;     /* the directory's, when it was read */
    time_t           at;        /* when it was read */
};

/* Reads the grants again, keeping the ones there were if the directory
 * cannot be read: a client loses nothing to a directory gone for a moment. */
static void read_grants(struct grants *gs, const char *dir)
{
    struct rs_grant_checked *bad = NULL;
    struct rs_grant         *g = NULL;
    struct rs_buf            err;
    struct stat              st;
    size_t                   n = 0;
    size_t                   nbad = 0;
    size_t                   i;

    rs_buf_init(&err);
    gs->at = time(NULL);
    gs->mtime = stat(dir, &st) == 0 ? st.st_mtime : 0;
    if (!rs_grants_load(dir, &g, &n, &bad, &nbad, &err))
    {
        say("grants: %s%s", err.data ? err.data : dir,
            gs->read ? "; the grants read before are kept" : "");
        rs_buf_free(&err);
        return;
    }
    rs_buf_free(&err);
    for (i = 0; i < nbad; i++)
    {
        say("grant-refused file=%s error=\"%s\"", bad[i].file, bad[i].error);
    }
    rs_grants_checked_free(bad, nbad);
    rs_grants_free(gs->g, gs->n);
    gs->g = g;
    gs->n = n;
    gs->read = true;
    say("grants dir=%s clients=%zu refused=%zu", dir, n, nbad);
}

/* Whether proxy.d has changed since it was read. A change in the same second
 * as the read is not seen in the time, so a read in the second the
 * directory last changed is taken as not the last. */
static bool grants_changed(const struct grants *gs, const char *dir)
{
    struct stat st;

    if (stat(dir, &st) != 0)
    {
        return gs->mtime != 0;
    }
    return st.st_mtime != gs->mtime || st.st_mtime >= gs->at;
}

/* ------------------------------------------------------------------------ */
/* What a connection asks the listener                                      */
/* ------------------------------------------------------------------------ */
/*
 * A connection's process asks the listening one, which holds the sessions,
 * over a socket pair of its own: a line, and a line in answer.
 *
 *   O CLIENT KIND          open        201 ID LEASE, or the status; 507 MESSAGE
 *                                      if the quota hook refused it
 *   F CLIENT ID            find        0 KIND RATE REPOSITORY, 1 (none), 2 (another's)
 *   Q CLIENT ID BYTES NAME quota       0, 507 MESSAGE or 500: the quota hook's
 *                                      answer for an upload
 *   R ID OUT IN            release     ok
 *   C ID NAME              committed   ok
 *   H CLIENT ID            holds       0 if this child holds append session ID of
 *                                      CLIENT's, 1 if not -- the committer's question
 *   N CLIENT ID            renew       204 LEASE, or the status
 *   E CLIENT ID            end         the status
 *
 * Every word in them is one the connection's process has checked already:
 * a client's name, a session id, a kind's word, an upload's name. The
 * repository and the hook's message are last, so that a blank in them is
 * still theirs.
 */

#define ASK_MAX 4352    /* a line: a repository's path, and the rest */

/* A connection's side: its end of the pair, and the repository it was last
 * told of, which a find's answer holds until it is released. */
struct asker {
    int  fd;
    char repository[ASK_MAX];
};

/* The status at the front of an answer: 500 for one that has none. */
static int status_of(const char *answer)
{
    long v = strtol(answer, NULL, 10);

    return v >= 100 && v <= 599 ? (int)v : 500;
}

/* `question` asked, and the answer's line into `answer` without its newline:
 * false if the listener could not be asked. */
static bool ask(struct asker *k, const char *question, char *answer, size_t size)
{
    size_t len = strlen(question);
    size_t got = 0;

    if (write(k->fd, question, len) != (ssize_t)len)
    {
        return false;
    }
    while (got + 1 < size)
    {
        ssize_t n = read(k->fd, answer + got, 1);

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            return false;
        }
        if (answer[got] == '\n')
        {
            answer[got] = '\0';
            return true;
        }
        got++;
    }
    return false;
}

/* What follows a 507's status, the quota hook's message, into `message`. */
static void message_of(const char *a, struct rs_buf *message)
{
    if (a[0] && a[1] && a[2] && a[3] == ' ' && a[4])
    {
        rs_buf_addstr(message, a + 4);
    }
}

static int ask_open(void *ctx, const char *client, enum rs_proxy_kind kind, char id[33],
                    unsigned *lease, struct rs_buf *message)
{
    char *q = rs_xasprintf("O %s %s\n", client, rs_proxy_kind_name(kind));
    char  a[RS_QUOTA_SAID_MAX + 64];
    int   status = 500;
    bool  ok = ask(ctx, q, a, sizeof(a));

    free(q);
    if (ok)
    {
        status = status_of(a);
        if (status == 507)
        {
            message_of(a, message);
        }
        if (status == 201 && strlen(a) > 4 + RS_SESSION_LEN)
        {
            memcpy(id, a + 4, RS_SESSION_LEN);
            id[RS_SESSION_LEN] = '\0';
            *lease = (unsigned)strtoul(a + 5 + RS_SESSION_LEN, NULL, 10);
        } else if (status == 201)
        {
            status = 500;
        }
    }
    return status;
}

static enum rs_proxy_found ask_find(void *ctx, const char *client, const char *id,
                                    struct rs_proxy_session *s)
{
    struct asker *k = ctx;
    char         *q = rs_xasprintf("F %s %s\n", client, id);
    bool          ok = ask(k, q, k->repository, sizeof(k->repository));
    const char   *kind;
    const char   *rate;
    const char   *repo;

    free(q);
    if (!ok || k->repository[0] == '1')
    {
        return RS_PROXY_NO_SESSION;
    }
    if (k->repository[0] == '2')
    {
        return RS_PROXY_NOT_YOURS;
    }
    kind = strchr(k->repository, ' ');
    rate = kind ? strchr(kind + 1, ' ') : NULL;
    repo = rate ? strchr(rate + 1, ' ') : NULL;
    if (!repo || !rs_proxy_kind_of(kind + 1, (size_t)(rate - kind - 1), &s->kind))
    {
        return RS_PROXY_NO_SESSION;
    }
    s->rate = strtoull(rate + 1, NULL, 10);
    s->repository = repo + 1;
    return RS_PROXY_FOUND;
}

static void ask_release(void *ctx, const char *id, uint64_t bytes_out, uint64_t bytes_in)
{
    char *q = rs_xasprintf("R %s %" PRIu64 " %" PRIu64 "\n", id, bytes_out, bytes_in);
    char  a[16];

    (void)ask(ctx, q, a, sizeof(a));
    free(q);
}

static void ask_committed(void *ctx, const char *id, const char *name)
{
    char *q = rs_xasprintf("C %s %s\n", id, name);
    char  a[16];

    (void)ask(ctx, q, a, sizeof(a));
    free(q);
}

static int ask_renew(void *ctx, const char *client, const char *id, unsigned *lease)
{
    char *q = rs_xasprintf("N %s %s\n", client, id);
    char  a[64];
    int   status = ask(ctx, q, a, sizeof(a)) ? status_of(a) : 500;

    free(q);
    if (status == 204)
    {
        *lease = (unsigned)strtoul(a + 4, NULL, 10);
    }
    return status;
}

static int ask_quota(void *ctx, const char *client, const char *id, const char *name,
                     uint64_t bytes, struct rs_buf *message)
{
    char *q = rs_xasprintf("Q %s %s %" PRIu64 " %s\n", client, id, bytes, name);
    char  a[RS_QUOTA_SAID_MAX + 64] = "";
    int   status = ask(ctx, q, a, sizeof(a)) ? status_of(a) : 500;

    free(q);
    if (strcmp(a, "0") == 0)
    {
        return 0;
    }
    if (status == 507)
    {
        message_of(a, message);
        return 507;
    }
    return 500;
}

static int ask_end(void *ctx, const char *client, const char *id)
{
    char *q = rs_xasprintf("E %s %s\n", client, id);
    char  a[16];
    int   status = ask(ctx, q, a, sizeof(a)) ? status_of(a) : 500;

    free(q);
    return status;
}

/* ------------------------------------------------------------------------ */
/* A connection                                                             */
/* ------------------------------------------------------------------------ */

static long tls_read(void *ctx, void *buf, size_t len)
{
    return rs_tls_read(ctx, buf, len);
}

static bool tls_write(void *ctx, const void *buf, size_t len)
{
    return rs_tls_write(ctx, buf, len);
}

/*
 * The committer: a process of the connection's own, made when the connection
 * is bound to a client whose grant allows append, that does its commits
 * (commit.h) -- the one that writes the repository and runs gzip, so that
 * the connection's process need do neither. It is told only a commit's name
 * and its session's id, each checked again here, and works out the
 * repository and the staging from what it was made for, never from what it
 * is told. Nor does it take the connection's word that the session is one:
 * before each commit it asks the listener, on the connection's own pair,
 * whether this connection holds an append session of that id for its
 * client -- so that nothing is ever committed without the session's lock
 * held, by a connection whose process a fault has taken over:
 *
 *   ID NAME                 STATUS ADDED BYTES REASON MESSAGE
 *
 * ADDED is "p" for a pack the commit put there, "s" for a snapshot, "-" for
 * neither; REASON "-" for none; MESSAGE the rest of the line.
 */

/* Whether `name` is what a commit names. */
static bool commit_name_ok(const char *name)
{
    if (strncmp(name, "packs/", 6) == 0)
    {
        return rs_repo_name_valid(name + 6);
    }
    if (strncmp(name, "snapshots/", 10) == 0)
    {
        return rs_repo_name_valid(name + 10);
    }
    return strcmp(name, "chunk-key") == 0 ||
           (strncmp(name, "chunk-key.", 10) == 0 && rs_repo_name_valid(name + 10));
}

static bool session_id_ok(const char *id)
{
    return strlen(id) == RS_SESSION_LEN && strspn(id, "0123456789abcdef") == RS_SESSION_LEN;
}

/* A line from `fd`, without its newline: false at the end, or past `size`. */
static bool read_line(int fd, char *line, size_t size)
{
    size_t got = 0;

    while (got + 1 < size)
    {
        ssize_t n = read(fd, line + got, 1);

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            return false;
        }
        if (line[got] == '\n')
        {
            line[got] = '\0';
            return true;
        }
        got++;
    }
    return false;
}

/* Whether the listener, on `ipc`, says this connection holds append session
 * `id` of `client`'s. */
static bool listener_says_held(int ipc, const char *client, const char *id)
{
    char *q = rs_xasprintf("H %s %s\n", client, id);
    char  a[16];
    bool  ok = write(ipc, q, strlen(q)) == (ssize_t)strlen(q) && read_line(ipc, a, sizeof(a)) &&
              strcmp(a, "0") == 0;

    free(q);
    return ok;
}

/* The committer's life: its questions on `fd`, answered, until it closes. */
static int committer(int fd, int ipc, const struct rs_grant *g, const char *staging)
{
    const char *repository = g->repository;

    char          line[ASK_MAX];
    struct rs_buf why;

    /* What a commit reads through gzip it writes to a file first (an
     * index), which is made in the client's staging: it may write nowhere
     * else. */
    rs_set_tmpfile_dir(staging);
    rs_buf_init(&why);
    if (!rs_confine(RS_CONFINE_COMMITTER, repository, staging, &why))
    {
        say("confine-failed role=committer error=\"%s\"", why.data ? why.data : "");
        rs_buf_free(&why);
        return 1;
    }
    rs_buf_free(&why);
    while (read_line(fd, line, sizeof(line)))
    {
        struct rs_proxy_committed out;
        struct rs_buf             answer;
        char                     *name = strchr(line, ' ');
        size_t                    i;

        rs_proxy_committed_init(&out);
        if (name)
        {
            *name++ = '\0';
        }
        if (!name || !session_id_ok(line) || !commit_name_ok(name))
        {
            out.status = 500;
            out.reason = "proxy-failed";
            rs_buf_addstr(&out.message, "the committer was asked something it does not do");
        } else if (!listener_says_held(ipc, g->client, line))
        {
            out.status = 403;
            out.reason = "forbidden";
            rs_buf_addstr(&out.message, "not in an append session this connection holds");
        } else
        {
            char *dir = rs_xasprintf("%s/%s", staging, line);

            rs_proxy_commit(repository, dir, name, &out);
            free(dir);
        }
        for (i = 0; out.message.data && i < out.message.len; i++)
        {
            if (out.message.data[i] == '\n')
            {
                out.message.data[i] = ' ';
            }
        }
        rs_buf_init(&answer);
        rs_buf_addf(&answer, "%d %s %" PRIu64 " %s %s\n", out.status,
                    out.pack_added ? "p" : out.snapshot_added ? "s" : "-", out.bytes,
                    out.reason ? out.reason : "-", out.message.data ? out.message.data : "");
        if (write(fd, answer.data, answer.len) != (ssize_t)answer.len)
        {
            rs_buf_free(&answer);
            rs_proxy_committed_free(&out);
            break;
        }
        rs_buf_free(&answer);
        rs_proxy_committed_free(&out);
    }
    return 0;
}

/* What a connection's process holds of its binding. */
struct binding {
    int         conn_fd;        /* the connection, which the committer closes */
    int         ipc_fd;         /* the listener's pair, likewise */
    const char *staging;        /* the proxy's: STAGING */
    char       *client_staging; /* STAGING/CLIENT, once bound */
    pid_t       committer;
    int         fd;             /* the committer's end, -1 while there is none */
};

/* The reason a committer's answer gave, as the protocol has it: one of the
 * fixed words, never what the line said otherwise. */
static const char *known_reason(const char *word)
{
    static const char *const reasons[] = { "name-taken", "invalid", "storage-full",
                                           "forbidden", "proxy-failed" };
    size_t                   i;

    for (i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++)
    {
        if (strcmp(word, reasons[i]) == 0)
        {
            return reasons[i];
        }
    }
    return NULL;
}

/* rs_proxy_conn.commit: asked of the committer. */
static void ask_commit(void *ctx, const char *repository, const char *staging, const char *name,
                       struct rs_proxy_committed *out)
{
    struct binding *b = ctx;
    const char     *slash = strrchr(staging, '/');
    char           *q;
    char            a[ASK_MAX];
    char           *p;
    char           *added;
    char           *bytes;
    char           *reason;

    (void)repository;
    out->status = 500;
    out->reason = "proxy-failed";
    if (b->fd < 0 || !slash)
    {
        rs_buf_addstr(&out->message, "there is no committer");
        return;
    }
    q = rs_xasprintf("%s %s\n", slash + 1, name);
    if (write(b->fd, q, strlen(q)) != (ssize_t)strlen(q) || !read_line(b->fd, a, sizeof(a)))
    {
        free(q);
        rs_buf_addstr(&out->message, "the committer did not answer");
        return;
    }
    free(q);
    added = strchr(a, ' ');
    bytes = added ? strchr(added + 1, ' ') : NULL;
    reason = bytes ? strchr(bytes + 1, ' ') : NULL;
    p = reason ? strchr(reason + 1, ' ') : NULL;
    if (!p)
    {
        rs_buf_addstr(&out->message, "the committer's answer was not one");
        return;
    }
    *added++ = '\0';
    *bytes++ = '\0';
    *reason++ = '\0';
    *p++ = '\0';
    out->status = (int)strtol(a, NULL, 10);
    out->pack_added = out->status == 201 && strcmp(added, "p") == 0;
    out->snapshot_added = out->status == 201 && strcmp(added, "s") == 0;
    out->bytes = strtoull(bytes, NULL, 10);
    out->reason = known_reason(reason);
    if (out->status != 200 && out->status != 201 && !out->reason)
    {
        out->status = 500;
        out->reason = "proxy-failed";
    }
    rs_buf_addstr(&out->message, p);
}

/* rs_proxy_conn.bind: the connection bound to the client of grant `g`. Its
 * staging is made, its committer started, and then this process confined
 * to the client's repository and its staging. */
static bool bind_client(void *ctx, const struct rs_grant *g)
{
    struct binding *b = ctx;
    struct rs_buf   why;
    int             pair[2];
    bool            ok;

    if (b->staging && (g->operations & RS_GRANT_APPEND) != 0)
    {
        b->client_staging = rs_xasprintf("%s/%s", b->staging, g->client);
        if (mkdir(b->client_staging, 0700) != 0 && errno != EEXIST)
        {
            say("bind-failed client=%s error=\"%s: %s\"", g->client, b->client_staging,
                strerror(errno));
            return false;
        }
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        {
            say("bind-failed client=%s error=\"socketpair: %s\"", g->client, strerror(errno));
            return false;
        }
        (void)fflush(NULL);
        b->committer = fork();
        if (b->committer < 0)
        {
            say("bind-failed client=%s error=\"fork: %s\"", g->client, strerror(errno));
            (void)close(pair[0]);
            (void)close(pair[1]);
            return false;
        }
        if (b->committer == 0)
        {
            int status;

            /* Nothing of the connection's but the listener's pair, to ask
             * it whether a commit is in a session: not its socket. */
            (void)close(b->conn_fd);
            (void)close(pair[0]);
            status = committer(pair[1], b->ipc_fd, g, b->client_staging);
            (void)close(pair[1]);
            (void)close(b->ipc_fd);
            exit(status);
        }
        (void)close(pair[1]);
        b->fd = pair[0];
    }
    rs_buf_init(&why);
    ok = rs_confine(RS_CONFINE_CONNECTION, g->repository, b->client_staging, &why);
    if (!ok)
    {
        say("confine-failed client=%s role=connection error=\"%s\"", g->client,
            why.data ? why.data : "");
    }
    rs_buf_free(&why);
    return ok;
}

/* In the child: the connection `fd` from `peer`, served, asking the
 * listener on `ipc` for its sessions, and its end. */
/* How long a closing connection's unread input is read and thrown away. */
#define LINGER_MS 2000

/* Ends connection `fd` the way a web server must when it answered before
 * reading what the client sent (a 413, a 403 to an upload): its own side is
 * shut, and what keeps arriving is read and dropped for a moment. Closed
 * with that input unread, the socket would answer with a reset, and a reset
 * can reach the client before the answer it has not read yet, which is
 * then lost. */
static void linger_close(int fd)
{
    struct timespec start;
    char            junk[16384];

    if (shutdown(fd, SHUT_WR) != 0 || clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return;
    }
    for (;;)
    {
        struct timespec now;
        struct pollfd   pfd;
        long long       spent;
        ssize_t         n;

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        {
            return;
        }
        spent = (long long)(now.tv_sec - start.tv_sec) * 1000 +
                (now.tv_nsec - start.tv_nsec) / 1000000;
        if (spent >= LINGER_MS)
        {
            return;
        }
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, (int)(LINGER_MS - spent)) <= 0)
        {
            return;
        }
        n = read(fd, junk, sizeof(junk)); /* Flawfinder: ignore */
        if (n <= 0)
        {
            return;
        }
    }
}

static int serve_child(struct rs_tls_config *tls, int fd, int ipc, const char *peer,
                       const struct grants *gs, const struct rs_proxy_options *o)
{
    struct rs_proxy_sessions sessions;
    struct rs_proxy_conn     c;
    struct rs_proxy_io       io;
    struct binding           b;
    struct timeval           tv;
    struct rs_buf            err;
    struct rs_tls           *t;
    struct asker            *k = rs_xcalloc(1, sizeof(*k));
    unsigned                 idle = o->idle_timeout ? o->idle_timeout : RS_PROXY_IDLE_TIMEOUT;

    tv.tv_sec = (time_t)idle;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    rs_buf_init(&err);
    t = rs_tls_accept(tls, fd, &err);
    if (!t)
    {
        say("tls-refused peer=%s error=\"%s\"", peer, err.data ? err.data : "");
        rs_buf_free(&err);
        free(k);
        return 1;
    }
    rs_buf_free(&err);
    k->fd = ipc;
    sessions.ctx = k;
    sessions.open = ask_open;
    sessions.find = ask_find;
    sessions.release = ask_release;
    sessions.committed = ask_committed;
    sessions.renew = ask_renew;
    sessions.end = ask_end;
    sessions.quota = o->quota_hook ? ask_quota : NULL;
    memset(&b, 0, sizeof(b));
    b.conn_fd = fd;
    b.ipc_fd = ipc;
    b.staging = o->staging;
    b.fd = -1;
    memset(&c, 0, sizeof(c));
    c.grants = gs->g;
    c.ngrants = gs->n;
    c.peer = peer;
    c.log = log_line;
    c.sessions = &sessions;
    c.staging = o->staging;
    c.max_staging = o->max_staging;
    c.bind = bind_client;
    c.bind_ctx = &b;
    c.commit = ask_commit;
    c.commit_ctx = &b;
    io.ctx = t;
    io.read = tls_read;
    io.write = tls_write;
    (void)rs_proxy_serve(&io, &c);
    rs_tls_close(t);
    linger_close(fd);
    if (b.fd >= 0)
    {
        (void)close(b.fd);
        (void)waitpid(b.committer, NULL, 0);
    }
    free(b.client_staging);
    free(k);
    return 0;
}

/* The children serving connections, and the session each holds. */
struct child {
    pid_t               pid;
    int                 fd;                       /* the listener's end of its pair */
    char                held[RS_SESSION_LEN + 1]; /* "" if none */
    char                in[ASK_MAX];
    size_t              nin;
    /* The quota hook, running for its question `waiting`, which is answered
     * once it is done; hook_said_yes while it is asked again, after. */
    struct rs_quota_run hook;
    char               *waiting;
    bool                hook_said_yes;
};

struct children {
    struct child  *c;
    unsigned       n;
    unsigned       max;
    /* The loop's: what it polls, and whose hook each of the last is. Kept
     * here so that a connection's process, forked from inside the loop,
     * holds them as it holds the rest of the listener's until it exits. */
    struct pollfd *pfd;
    unsigned      *hooked;
};

/* Child `i` is gone: what it held is let go, and its place taken. */
static void forget_child(struct children *ch, unsigned i, struct rs_sessions *s)
{
    rs_quota_abandon(&ch->c[i].hook);
    free(ch->c[i].waiting);
    ch->c[i].waiting = NULL;
    if (ch->c[i].held[0])
    {
        rs_sessions_release(s, ch->c[i].held, 0, 0, (int64_t)time(NULL));
    }
    if (ch->c[i].fd >= 0)
    {
        (void)close(ch->c[i].fd);
    }
    ch->c[i] = ch->c[--ch->n];
}

static void reap(struct children *ch, struct rs_sessions *s)
{
    pid_t pid;
    int   status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        unsigned i;

        for (i = 0; i < ch->n; i++)
        {
            if (ch->c[i].pid == pid)
            {
                forget_child(ch, i, s);
                break;
            }
            if (rs_quota_reaped(&ch->c[i].hook, pid, status))
            {
                break;
            }
        }
    }
}

/* The hour of the local day it is now, on the storage host: what a
 * grant's bandwidth is by. */
static int local_hour(void)
{
    time_t    now = time(NULL);
    struct tm tm;

    return localtime_r(&now, &tm) ? tm.tm_hour : 0;
}

/* The quota hook started for child `c`'s question `copy` -- the client of
 * grant `g` opening an append session, or uploading `bytes` as `name` --
 * which is answered once it is done: false, said, if it could not be
 * started, and then the question is answered 500 at once. */
static bool ask_hook(struct child *c, char *copy, const char *hook, const struct rs_grant *g,
                     const char *name, uint64_t bytes)
{
    struct rs_quota_ask q;
    struct rs_buf       why;

    q.event = name ? "upload" : "open";
    q.client = g->client;
    q.repository = g->repository;
    q.label = g->label;
    q.name = name;
    q.bytes = bytes;
    rs_buf_init(&why);
    if (!rs_quota_start(&c->hook, hook, &q, (int64_t)time(NULL), RS_QUOTA_TIMEOUT, &why))
    {
        say("quota-hook-failed client=%s event=%s error=\"%s\"", g->client, q.event,
            why.data ? why.data : "");
        rs_buf_free(&why);
        return false;
    }
    rs_buf_free(&why);
    c->waiting = copy;
    return true;
}

/*
 * One question from child `c`, answered into `out`: true; or, where the
 * quota hook (`hook`, NULL for none) has to be asked first, the hook
 * started and nothing put in `out` -- false, and the question is asked
 * again once it says yes (finish_hook).
 */
static bool answer_child(struct child *c, char *q, const struct grants *gs,
                         struct rs_sessions *s, const char *hook, struct rs_buf *out)
{
    int64_t now = (int64_t)time(NULL);
    char   *copy = rs_xstrdup(q);
    char   *client = strchr(q, ' ');
    char   *rest = client ? strchr(client + 1, ' ') : NULL;
    bool    yes = c->hook_said_yes;
    int     status;

    c->hook_said_yes = false;
    /* A session past its lease is gone, whether the loop has got to it yet
     * or not. */
    (void)rs_sessions_expire(s, now);
    if (!client || !rest)
    {
        rs_buf_addstr(out, "500\n");
        free(copy);
        return true;
    }
    *rest++ = '\0';
    client++;
    if (q[0] == 'O')
    {
        const struct rs_grant *g = rs_grants_find(gs->g, gs->n, client);
        enum rs_proxy_kind     kind;
        char                   id[RS_SESSION_LEN + 1];
        struct rs_buf          why;

        if (!g || !rs_proxy_kind_of(rest, strlen(rest), &kind))
        {
            rs_buf_addstr(out, g ? "500\n" : "401\n");
            free(copy);
            return true;
        }
        /* An append session stores more: the quota hook is asked first,
         * once the grant allows it at all. */
        if (hook && !yes && kind == RS_PROXY_APPEND && (g->operations & RS_GRANT_APPEND) != 0)
        {
            if (ask_hook(c, copy, hook, g, NULL, 0))
            {
                return false;
            }
            rs_buf_addstr(out, "500\n");
            free(copy);
            return true;
        }
        rs_buf_init(&why);
        status = rs_sessions_open(s, g, kind, now, id, &why);
        if (status == 500)
        {
            say("session-refused client=%s error=\"%s\"", client, why.data ? why.data : "");
        }
        rs_buf_free(&why);
        if (status == 201)
        {
            rs_buf_addf(out, "201 %s %u\n", id, rs_sessions_lease(s));
        } else
        {
            rs_buf_addf(out, "%d\n", status);
        }
    } else if (q[0] == 'F')
    {
        struct rs_proxy_session found;

        switch (rs_sessions_find(s, client, rest, &found))
        {
        case RS_PROXY_FOUND:
        {
            const struct rs_grant *g = rs_grants_find(gs->g, gs->n, client);
            uint64_t               rate = g ? rs_grant_rate(g, local_hour()) : 0;
            unsigned               busy;

            /* One request at a time on a connection: anything it held
             * before is let go first. */
            if (c->held[0])
            {
                rs_sessions_release(s, c->held, 0, 0, now);
            }
            (void)snprintf(c->held, sizeof(c->held), "%s", rest);
            /* The client's bandwidth, shared by its requests being answered
             * now, this one among them. */
            busy = rs_sessions_busy(s, client);
            if (rate > 0 && busy > 1)
            {
                rate /= busy;
            }
            rs_buf_addf(out, "0 %s %" PRIu64 " %s\n", rs_proxy_kind_name(found.kind), rate,
                        found.repository);
            break;
        }
        case RS_PROXY_NOT_YOURS:
            rs_buf_addstr(out, "2\n");
            break;
        case RS_PROXY_NO_SESSION:
        default:
            rs_buf_addstr(out, "1\n");
            break;
        }
    } else if (q[0] == 'Q')
    {
        /* "Q CLIENT ID BYTES NAME": an upload in the append session this
         * child holds, whose client's grant is still there. */
        const struct rs_grant *g = rs_grants_find(gs->g, gs->n, client);
        char                  *bytes = strchr(rest, ' ');
        const char            *name = bytes ? strchr(bytes + 1, ' ') : NULL;
        bool                   ok;

        if (bytes)
        {
            *bytes++ = '\0';
        }
        ok = g && name && strcmp(c->held, rest) == 0 && rs_sessions_appending(s, client, rest);
        if (ok && (!hook || yes))
        {
            rs_buf_addstr(out, "0\n");
        } else if (ok && ask_hook(c, copy, hook, g, name + 1, strtoull(bytes, NULL, 10)))
        {
            return false;
        } else
        {
            rs_buf_addstr(out, "500\n");
        }
    } else if (q[0] == 'R')
    {
        /* "R ID OUT IN": the id where the client is elsewhere. */
        const char *in = strchr(rest, ' ');
        uint64_t    bytes_in = in ? strtoull(in + 1, NULL, 10) : 0;

        rs_sessions_release(s, client, strtoull(rest, NULL, 10), bytes_in, now);
        if (strcmp(c->held, client) == 0)
        {
            c->held[0] = '\0';
        }
        rs_buf_addstr(out, "ok\n");
    } else if (q[0] == 'H')
    {
        /* The committer's, before each commit: asked of the listener's own
         * table, not of the connection, whose word it does not take. */
        bool held = strcmp(c->held, rest) == 0 && rs_sessions_appending(s, client, rest);

        rs_buf_addstr(out, held ? "0\n" : "1\n");
    } else if (q[0] == 'C')
    {
        /* "C ID NAME": only the session this child holds, as it is the one
         * its commit was in. */
        if (strcmp(c->held, client) == 0)
        {
            rs_sessions_committed(s, client, rest);
        }
        rs_buf_addstr(out, "ok\n");
    } else if (q[0] == 'N')
    {
        status = rs_sessions_renew(s, client, rest, now);
        if (status == 204)
        {
            rs_buf_addf(out, "204 %u\n", rs_sessions_lease(s));
        } else
        {
            rs_buf_addf(out, "%d\n", status);
        }
    } else if (q[0] == 'E')
    {
        rs_buf_addf(out, "%d\n", rs_sessions_end(s, client, rest, now));
    } else
    {
        rs_buf_addstr(out, "500\n");
    }
    free(copy);
    return true;
}

/* The questions child `c` has sent whole, answered in turn -- until one
 * waits for the quota hook, which is answered when it is done, and then the
 * rest. False once its end cannot be written to, or a line is longer than
 * any question. */
static bool answer_lines(struct child *c, const struct grants *gs, struct rs_sessions *s,
                         const char *hook)
{
    char *nl;

    while (!rs_quota_running(&c->hook) && (nl = strchr(c->in, '\n')) != NULL)
    {
        struct rs_buf out;
        size_t        used = (size_t)(nl - c->in) + 1;
        bool          ok = true;

        *nl = '\0';
        rs_buf_init(&out);
        if (answer_child(c, c->in, gs, s, hook, &out))
        {
            ok = write(c->fd, out.data, out.len) == (ssize_t)out.len;
        }
        rs_buf_free(&out);
        memmove(c->in, c->in + used, c->nin - used + 1);
        c->nin -= used;
        if (!ok)
        {
            return false;
        }
    }
    /* A line longer than any question is none. */
    return c->nin < sizeof(c->in) - 1;
}

/* What child `i` has asked, read and answered: false once it has closed
 * its end. */
static bool hear_child(struct children *ch, unsigned i, const struct grants *gs,
                       struct rs_sessions *s, const char *hook)
{
    struct child *c = &ch->c[i];
    ssize_t       n = read(c->fd, c->in + c->nin, sizeof(c->in) - c->nin - 1);

    if (n < 0 && (errno == EINTR || errno == EAGAIN))
    {
        return true;
    }
    if (n <= 0)
    {
        return false;
    }
    c->nin += (size_t)n;
    c->in[c->nin] = '\0';
    return answer_lines(c, gs, s, hook);
}

/*
 * Child `c`'s quota hook is done: its question answered -- refused, or the
 * hook failed, at once; a yes by asking the question again, this time to
 * be answered as it would be with no hook -- and then what it has asked
 * since. False as hear_child is.
 */
static bool finish_hook(struct child *c, const struct grants *gs, struct rs_sessions *s,
                        const char *hook)
{
    struct rs_buf message;
    struct rs_buf why;
    struct rs_buf out;
    char         *q = c->waiting;
    char         *client = strchr(q, ' ');
    char         *end = client ? strchr(client + 1, ' ') : NULL;
    const char   *event = q[0] == 'O' ? "open" : "upload";
    int           answer;
    bool          ok = true;

    c->waiting = NULL;
    rs_buf_init(&message);
    rs_buf_init(&why);
    rs_buf_init(&out);
    answer = rs_quota_answer(&c->hook, &message, &why);
    if (client && end)
    {
        *end = '\0';
        client++;
    } else
    {
        client = q;
    }
    if (answer == 0)
    {
        c->hook_said_yes = true;
        if (end)
        {
            *end = ' ';
        }
        (void)answer_child(c, q, gs, s, hook, &out);
    } else if (answer == 507)
    {
        say("quota-refused client=%s event=%s message=\"%s\"", client, event,
            message.data ? message.data : "");
        rs_buf_addf(&out, "507%s%s\n", message.len ? " " : "", message.data ? message.data : "");
    } else
    {
        say("quota-hook-failed client=%s event=%s error=\"%s\"", client, event,
            why.data ? why.data : "");
        rs_buf_addstr(&out, "500\n");
    }
    if (c->fd >= 0)
    {
        ok = write(c->fd, out.data, out.len) == (ssize_t)out.len;
    }
    rs_buf_free(&out);
    rs_buf_free(&why);
    rs_buf_free(&message);
    free(q);
    return ok && c->fd >= 0 && answer_lines(c, gs, s, hook);
}

/* Accepts what is waiting on `lfd`, and gives it a child. */
static void accept_one(int lfd, int *lfds, size_t nl, struct rs_tls_config *tls,
                       const struct grants *gs, struct children *ch, struct rs_sessions *s,
                       const struct rs_proxy_options *o)
{
    struct sockaddr_storage sa;
    socklen_t               len = sizeof(sa);
    char                    peer[NI_MAXHOST + NI_MAXSERV + 4];
    int                     fd;
    int                     pair[2];
    pid_t                   pid;

    memset(&sa, 0, sizeof(sa));
    fd = accept(lfd, (struct sockaddr *)&sa, &len);
    if (fd < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNABORTED)
        {
            say("accept: %s", strerror(errno));
        }
        return;
    }
    addr_text((struct sockaddr *)&sa, len, peer, sizeof(peer));
    if (ch->n >= ch->max)
    {
        say("connection-refused peer=%s why=\"%u connections already\"", peer, ch->n);
        (void)close(fd);
        return;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    {
        say("connection-refused peer=%s why=\"socketpair: %s\"", peer, strerror(errno));
        (void)close(fd);
        return;
    }
    /* Blocking, whatever the listener is: the child reads and writes it in
     * turn, with the socket's own timeouts. */
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    pid = fork();
    if (pid < 0)
    {
        say("connection-refused peer=%s why=\"fork: %s\"", peer, strerror(errno));
        (void)close(fd);
        (void)close(pair[0]);
        (void)close(pair[1]);
        return;
    }
    if (pid == 0)
    {
        size_t   i;
        unsigned j;
        int      status;

        /* Nothing of the listener's but the grants: not its sockets, not
         * the other children's pairs, and not its copies of the sessions'
         * locks -- closed, not unlocked, which leaves them the listener's. */
        for (i = 0; i < nl; i++)
        {
            (void)close(lfds[i]);
        }
        for (j = 0; j < ch->n; j++)
        {
            (void)close(ch->c[j].fd);
            if (ch->c[j].hook.fd >= 0)
            {
                (void)close(ch->c[j].hook.fd);
            }
        }
        rs_sessions_forget(s);
        (void)close(pair[0]);
        (void)close(wake[0]);
        (void)close(wake[1]);
        wake[0] = wake[1] = -1;
        (void)signal(SIGHUP, SIG_IGN);
        (void)signal(SIGTERM, SIG_DFL);
        (void)signal(SIGINT, SIG_DFL);
        (void)signal(SIGCHLD, SIG_DFL);
        status = serve_child(tls, fd, pair[1], peer, gs, o);
        (void)close(fd);
        (void)close(pair[1]);
        /* exit, not _exit: what a coverage build counts is written then. */
        exit(status);
    }
    (void)close(fd);
    (void)close(pair[1]);
    (void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    memset(&ch->c[ch->n], 0, sizeof(ch->c[ch->n]));
    rs_quota_init(&ch->c[ch->n].hook);
    ch->c[ch->n].pid = pid;
    ch->c[ch->n].fd = pair[0];
    ch->n++;
}

/* Tells every child to stop, and waits for them, for a while. */
static void stop_children(struct children *ch, struct rs_sessions *s)
{
    unsigned i;
    time_t   until = time(NULL) + STOP_WAIT;

    for (i = 0; i < ch->n; i++)
    {
        rs_quota_abandon(&ch->c[i].hook);
        (void)kill(ch->c[i].pid, SIGTERM);
    }
    while (ch->n > 0 && time(NULL) < until)
    {
        reap(ch, s);
        if (ch->n > 0)
        {
            (void)poll(NULL, 0, 100);
        }
    }
    for (i = 0; i < ch->n; i++)
    {
        (void)kill(ch->c[i].pid, SIGKILL);
    }
    while (ch->n > 0 && waitpid(-1, NULL, 0) > 0)
    {
        forget_child(ch, ch->n - 1, s);
    }
}

static void handle(int sig)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    (void)sigemptyset(&sa.sa_mask);
    /* No SA_RESTART: poll comes back for a signal, whatever the pipe. */
    sa.sa_flags = 0;
    (void)sigaction(sig, &sa, NULL);
}

/*
 * The staging directory, made if it is not there (its parent has to be) and
 * only its owner's, and emptied of what sessions before this start left:
 * its path as it really is, for the confinement's sake, or NULL -- said --
 * if it cannot be had, and then nothing can be uploaded.
 */
static char *staging_dir(const char *dir)
{
    struct rs_buf why;
    struct stat   st;
    char         *real;
    size_t        removed;

    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
    {
        say("staging dir=%s error=\"%s\"; nothing can be uploaded", dir, strerror(errno));
        return NULL;
    }
    /* NULL: the path is allocated, as long as it is. */
    real = realpath(dir, NULL); /* Flawfinder: ignore */
    if (!real || stat(real, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        say("staging dir=%s error=\"not a directory\"; nothing can be uploaded", dir);
        free(real);
        return NULL;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0)
    {
        say("staging dir=%s error=\"not this user's alone (it is mode %03o)\"; nothing can be "
            "uploaded", real, (unsigned)(st.st_mode & 0777));
        free(real);
        return NULL;
    }
    rs_buf_init(&why);
    removed = rs_sessions_clean_staging(real, &why);
    say("staging dir=%s removed=%zu%s%s%s", real, removed, why.len ? " error=\"" : "",
        why.len ? why.data : "", why.len ? "\"" : "");
    rs_buf_free(&why);
    return real;
}

int rs_proxy_run(const struct rs_proxy_options *o)
{
    static const char *const every[] = { ":" RS_PROXY_PORT };
    struct rs_proxy_options  opts = *o;
    char                    *staging;
    struct rs_tls_config    *tls;
    struct pollfd           *pfd;
    unsigned                *hooked;
    struct children          ch;
    struct grants            gs;
    struct rs_buf            err;
    struct rs_sessions      *sessions;
    const char *const       *listen = o->nlisten ? o->listen : every;
    size_t                   nlisten = o->nlisten ? o->nlisten : 1;
    int                      lfds[LISTEN_MAX];
    size_t                   nl = 0;
    size_t                   i;

    /* What it is told to listen on, checked before anything is read. */
    for (i = 0; i < nlisten; i++)
    {
        char *host;
        char *port;

        if (!split_listen(listen[i], &host, &port))
        {
            say("--listen %s: not HOST:PORT, [ADDRESS]:PORT or :PORT", listen[i]);
            return RESTATE_EXIT_TROUBLE;
        }
        free(host);
        free(port);
    }
    rs_buf_init(&err);
    if (o->quota_hook && !rs_quota_program_ok(o->quota_hook, &err))
    {
        say("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    tls = rs_tls_server_config(o->cert, o->key, &err);
    if (!tls)
    {
        say("%s", err.data ? err.data : "TLS");
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    for (i = 0; i < nlisten; i++)
    {
        if (!listen_on(listen[i], lfds, &nl))
        {
            while (nl > 0)
            {
                (void)close(lfds[--nl]);
            }
            rs_tls_config_free(tls);
            return RESTATE_EXIT_TROUBLE;
        }
    }
    if (pipe(wake) != 0)
    {
        say("pipe: %s", strerror(errno));
        while (nl > 0)
        {
            (void)close(lfds[--nl]);
        }
        rs_tls_config_free(tls);
        return RESTATE_EXIT_TROUBLE;
    }
    (void)fcntl(wake[0], F_SETFL, fcntl(wake[0], F_GETFL) | O_NONBLOCK);
    (void)fcntl(wake[1], F_SETFL, fcntl(wake[1], F_GETFL) | O_NONBLOCK);
    (void)fcntl(wake[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(wake[1], F_SETFD, FD_CLOEXEC);
    (void)signal(SIGPIPE, SIG_IGN);
    handle(SIGHUP);
    handle(SIGTERM);
    handle(SIGINT);
    handle(SIGCHLD);

    memset(&gs, 0, sizeof(gs));
    read_grants(&gs, o->grants);
    staging = staging_dir(o->staging ? o->staging : RS_PROXY_STAGING);
    opts.staging = staging;
    ch.max = o->max_connections ? o->max_connections : RS_PROXY_MAX_CONNECTIONS;
    ch.n = 0;
    ch.c = rs_xcalloc(ch.max, sizeof(*ch.c));
    /* The listeners, the wake pipe, each child's pair and each one's hook. */
    pfd = rs_xcalloc(LISTEN_MAX + 1 + 2 * (size_t)ch.max, sizeof(*pfd));
    hooked = rs_xcalloc(ch.max, sizeof(*hooked));
    ch.pfd = pfd;
    ch.hooked = hooked;
    sessions = rs_sessions_new(o->max_sessions, o->lease, staging, log_line, NULL);
    say("started version=%s tls=\"%s\" confinement=\"%s\" max_connections=%u max_sessions=%u "
        "lease=%u quota_hook=%s", RESTATE_VERSION, rs_tls_library(), rs_confine_how(), ch.max,
        o->max_sessions ? o->max_sessions : RS_PROXY_MAX_SESSIONS, rs_sessions_lease(sessions),
        o->quota_hook ? o->quota_hook : "none");

    while (!got_stop)
    {
        size_t   np = 0;
        size_t   nh = 0;
        unsigned nc = ch.n;
        unsigned j;
        int      ready;

        for (i = 0; i < nl; i++)
        {
            pfd[np].fd = lfds[i];
            pfd[np].events = POLLIN;
            pfd[np++].revents = 0;
        }
        pfd[np].fd = wake[0];
        pfd[np].events = POLLIN;
        pfd[np++].revents = 0;
        for (j = 0; j < nc; j++)
        {
            pfd[np].fd = ch.c[j].fd;
            pfd[np].events = POLLIN;
            pfd[np++].revents = 0;
        }
        /* A hook's output after them all, with whose it is: read as it
         * comes, so that it never waits to write. */
        for (j = 0; j < nc; j++)
        {
            if (ch.c[j].hook.fd >= 0)
            {
                hooked[nh++] = j;
                pfd[np].fd = ch.c[j].hook.fd;
                pfd[np].events = POLLIN;
                pfd[np++].revents = 0;
            }
        }
        /* While a hook runs, its deadline is looked at each second. */
        ready = poll(pfd, (nfds_t)np, nh > 0 ? 1000 : WATCH_MS);
        if (pfd[nl].revents & POLLIN)
        {
            char drain[64];

            while (read(wake[0], drain, sizeof(drain)) > 0)
            {
            }
        }
        /* The children's questions first, before any is reaped: a child that
         * asked and then went has its answer, or its hold let go. */
        for (j = nc; ready > 0 && j-- > 0;)
        {
            if ((pfd[nl + 1 + j].revents & (POLLIN | POLLHUP | POLLERR)) &&
                !hear_child(&ch, j, &gs, sessions, o->quota_hook))
            {
                (void)close(ch.c[j].fd);
                ch.c[j].fd = -1;
                rs_quota_abandon(&ch.c[j].hook);
                free(ch.c[j].waiting);
                ch.c[j].waiting = NULL;
                if (ch.c[j].held[0])
                {
                    rs_sessions_release(sessions, ch.c[j].held, 0, 0, (int64_t)time(NULL));
                    ch.c[j].held[0] = '\0';
                }
            }
        }
        for (i = 0; i < nh; i++)
        {
            if (pfd[nl + 1 + nc + i].revents & (POLLIN | POLLHUP | POLLERR))
            {
                rs_quota_read(&ch.c[hooked[i]].hook);
            }
        }
        reap(&ch, sessions);
        /* Each hook past its deadline killed, and each one done answered. */
        for (j = 0; j < ch.n; j++)
        {
            rs_quota_check_time(&ch.c[j].hook, (int64_t)time(NULL));
            if (rs_quota_done(&ch.c[j].hook) && !finish_hook(&ch.c[j], &gs, sessions,
                                                             o->quota_hook))
            {
                if (ch.c[j].fd >= 0)
                {
                    (void)close(ch.c[j].fd);
                    ch.c[j].fd = -1;
                }
                if (ch.c[j].held[0])
                {
                    rs_sessions_release(sessions, ch.c[j].held, 0, 0, (int64_t)time(NULL));
                    ch.c[j].held[0] = '\0';
                }
            }
        }
        (void)rs_sessions_expire(sessions, (int64_t)time(NULL));
        if (got_stop)
        {
            break;
        }
        if (got_hup)
        {
            got_hup = 0;
            say("SIGHUP: reading the grants again");
            read_grants(&gs, o->grants);
        } else if (grants_changed(&gs, o->grants))
        {
            read_grants(&gs, o->grants);
        }
        for (i = 0; ready > 0 && i < nl; i++)
        {
            if (pfd[i].revents & POLLIN)
            {
                accept_one(lfds[i], lfds, nl, tls, &gs, &ch, sessions, &opts);
            }
        }
    }

    say("stopping: %u connection(s) and %zu session(s) open", ch.n, rs_sessions_count(sessions));
    for (i = 0; i < nl; i++)
    {
        (void)close(lfds[i]);
    }
    stop_children(&ch, sessions);
    rs_sessions_free(sessions, (int64_t)time(NULL));
    free(ch.c);
    free(pfd);
    free(hooked);
    rs_grants_free(gs.g, gs.n);
    rs_tls_config_free(tls);
    free(staging);
    (void)close(wake[0]);
    (void)close(wake[1]);
    wake[0] = wake[1] = -1;
    say("stopped");
    return RESTATE_EXIT_OK;
}
