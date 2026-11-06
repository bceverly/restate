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

#include "grant.h"
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
 *   O CLIENT KIND          open        201 ID LEASE, or the status
 *   F CLIENT ID            find        0 KIND REPOSITORY, 1 (none), 2 (another's)
 *   R ID BYTES             release     ok
 *   N CLIENT ID            renew       204 LEASE, or the status
 *   E CLIENT ID            end         the status
 *
 * Every word in them is one the connection's process has checked already:
 * a client's name, a session id, a kind's word. The repository is last, so
 * that a blank in its name is still its own.
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

static int ask_open(void *ctx, const char *client, enum rs_proxy_kind kind, char id[33],
                    unsigned *lease)
{
    char *q = rs_xasprintf("O %s %s\n", client, rs_proxy_kind_name(kind));
    char  a[128];
    int   status = 500;
    bool  ok = ask(ctx, q, a, sizeof(a));

    free(q);
    if (ok)
    {
        status = status_of(a);
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
    repo = kind ? strchr(kind + 1, ' ') : NULL;
    if (!repo || !rs_proxy_kind_of(kind + 1, (size_t)(repo - kind - 1), &s->kind))
    {
        return RS_PROXY_NO_SESSION;
    }
    s->repository = repo + 1;
    return RS_PROXY_FOUND;
}

static void ask_release(void *ctx, const char *id, uint64_t bytes_out)
{
    char *q = rs_xasprintf("R %s %" PRIu64 "\n", id, bytes_out);
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

/* In the child: the connection `fd` from `peer`, served, asking the
 * listener on `ipc` for its sessions, and its end. */
static int serve_child(struct rs_tls_config *tls, int fd, int ipc, const char *peer,
                       const struct grants *gs, unsigned idle)
{
    struct rs_proxy_sessions sessions;
    struct rs_proxy_conn     c;
    struct rs_proxy_io       io;
    struct timeval           tv;
    struct rs_buf            err;
    struct rs_tls           *t;
    struct asker            *k = rs_xcalloc(1, sizeof(*k));

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
    sessions.renew = ask_renew;
    sessions.end = ask_end;
    memset(&c, 0, sizeof(c));
    c.grants = gs->g;
    c.ngrants = gs->n;
    c.peer = peer;
    c.log = log_line;
    c.sessions = &sessions;
    io.ctx = t;
    io.read = tls_read;
    io.write = tls_write;
    (void)rs_proxy_serve(&io, &c);
    rs_tls_close(t);
    free(k);
    return 0;
}

/* The children serving connections, and the session each holds. */
struct child {
    pid_t  pid;
    int    fd;                          /* the listener's end of its pair */
    char   held[RS_SESSION_LEN + 1];    /* "" if none */
    char   in[ASK_MAX];
    size_t nin;
};

struct children {
    struct child *c;
    unsigned      n;
    unsigned      max;
};

/* Child `i` is gone: what it held is let go, and its place taken. */
static void forget_child(struct children *ch, unsigned i, struct rs_sessions *s)
{
    if (ch->c[i].held[0])
    {
        rs_sessions_release(s, ch->c[i].held, 0, (int64_t)time(NULL));
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
        }
    }
}

/* One question from child `c`, answered into `out`. */
static void answer_child(struct child *c, char *q, const struct grants *gs,
                         struct rs_sessions *s, struct rs_buf *out)
{
    int64_t now = (int64_t)time(NULL);
    char   *client = strchr(q, ' ');
    char   *rest = client ? strchr(client + 1, ' ') : NULL;
    int     status;

    /* A session past its lease is gone, whether the loop has got to it yet
     * or not. */
    (void)rs_sessions_expire(s, now);
    if (!client || !rest)
    {
        rs_buf_addstr(out, "500\n");
        return;
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
            return;
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
            /* One request at a time on a connection: anything it held
             * before is let go first. */
            if (c->held[0])
            {
                rs_sessions_release(s, c->held, 0, now);
            }
            (void)snprintf(c->held, sizeof(c->held), "%s", rest);
            rs_buf_addf(out, "0 %s %s\n", rs_proxy_kind_name(found.kind), found.repository);
            break;
        case RS_PROXY_NOT_YOURS:
            rs_buf_addstr(out, "2\n");
            break;
        case RS_PROXY_NO_SESSION:
        default:
            rs_buf_addstr(out, "1\n");
            break;
        }
    } else if (q[0] == 'R')
    {
        /* "R ID BYTES": the id where the client is elsewhere. */
        rs_sessions_release(s, client, strtoull(rest, NULL, 10), now);
        if (strcmp(c->held, client) == 0)
        {
            c->held[0] = '\0';
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
}

/* What child `i` has asked, read and answered: false once it has closed
 * its end. */
static bool hear_child(struct children *ch, unsigned i, const struct grants *gs,
                       struct rs_sessions *s)
{
    struct child *c = &ch->c[i];
    ssize_t       n = read(c->fd, c->in + c->nin, sizeof(c->in) - c->nin - 1);
    char         *nl;

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
    while ((nl = strchr(c->in, '\n')) != NULL)
    {
        struct rs_buf out;
        size_t        used = (size_t)(nl - c->in) + 1;
        bool          ok;

        *nl = '\0';
        rs_buf_init(&out);
        answer_child(c, c->in, gs, s, &out);
        ok = write(c->fd, out.data, out.len) == (ssize_t)out.len;
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

/* Accepts what is waiting on `lfd`, and gives it a child. */
static void accept_one(int lfd, int *lfds, size_t nl, struct rs_tls_config *tls,
                       const struct grants *gs, struct children *ch, struct rs_sessions *s,
                       unsigned idle)
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
        status = serve_child(tls, fd, pair[1], peer, gs, idle);
        (void)close(fd);
        (void)close(pair[1]);
        /* exit, not _exit: what a coverage build counts is written then. */
        exit(status);
    }
    (void)close(fd);
    (void)close(pair[1]);
    (void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    memset(&ch->c[ch->n], 0, sizeof(ch->c[ch->n]));
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

int rs_proxy_run(const struct rs_proxy_options *o)
{
    static const char *const every[] = { ":" RS_PROXY_PORT };
    struct rs_tls_config    *tls;
    struct pollfd           *pfd;
    struct children          ch;
    struct grants            gs;
    struct rs_buf            err;
    struct rs_sessions      *sessions;
    const char *const       *listen = o->nlisten ? o->listen : every;
    size_t                   nlisten = o->nlisten ? o->nlisten : 1;
    unsigned                 idle = o->idle_timeout ? o->idle_timeout : RS_PROXY_IDLE_TIMEOUT;
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
    ch.max = o->max_connections ? o->max_connections : RS_PROXY_MAX_CONNECTIONS;
    ch.n = 0;
    ch.c = rs_xcalloc(ch.max, sizeof(*ch.c));
    pfd = rs_xcalloc(LISTEN_MAX + 1 + ch.max, sizeof(*pfd));
    sessions = rs_sessions_new(o->max_sessions, o->lease, log_line, NULL);
    say("started version=%s tls=\"%s\" max_connections=%u max_sessions=%u lease=%u",
        RESTATE_VERSION, rs_tls_library(), ch.max,
        o->max_sessions ? o->max_sessions : RS_PROXY_MAX_SESSIONS, rs_sessions_lease(sessions));

    while (!got_stop)
    {
        size_t   np = 0;
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
        ready = poll(pfd, (nfds_t)np, WATCH_MS);
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
                !hear_child(&ch, j, &gs, sessions))
            {
                (void)close(ch.c[j].fd);
                ch.c[j].fd = -1;
                if (ch.c[j].held[0])
                {
                    rs_sessions_release(sessions, ch.c[j].held, 0, (int64_t)time(NULL));
                    ch.c[j].held[0] = '\0';
                }
            }
        }
        reap(&ch, sessions);
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
                accept_one(lfds[i], lfds, nl, tls, &gs, &ch, sessions, idle);
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
    rs_grants_free(gs.g, gs.n);
    rs_tls_config_free(tls);
    (void)close(wake[0]);
    (void)close(wake[1]);
    wake[0] = wake[1] = -1;
    say("stopped");
    return RESTATE_EXIT_OK;
}
