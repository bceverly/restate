/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "server.h"

#include <errno.h>
#include <fcntl.h>
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
#include "tls.h"
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
    (void)snprintf(out, size, sa->sa_family == AF_INET6 ? "[%s]:%s" : "%s:%s", host, port);
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

/* In the child: the connection `fd` from `peer`, served, and its end. */
static int serve_child(struct rs_tls_config *tls, int fd, const char *peer,
                       const struct grants *gs, unsigned idle)
{
    struct rs_proxy_conn c;
    struct rs_proxy_io   io;
    struct timeval       tv;
    struct rs_buf        err;
    struct rs_tls       *t;

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
        return 1;
    }
    rs_buf_free(&err);
    memset(&c, 0, sizeof(c));
    c.grants = gs->g;
    c.ngrants = gs->n;
    c.peer = peer;
    c.log = log_line;
    io.ctx = t;
    io.read = tls_read;
    io.write = tls_write;
    (void)rs_proxy_serve(&io, &c);
    rs_tls_close(t);
    return 0;
}

/* The children serving connections, by pid. */
struct children {
    pid_t   *pid;
    unsigned n;
    unsigned max;
};

static void reap(struct children *ch)
{
    pid_t pid;
    int   status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        unsigned i;

        for (i = 0; i < ch->n; i++)
        {
            if (ch->pid[i] == pid)
            {
                ch->pid[i] = ch->pid[--ch->n];
                break;
            }
        }
    }
}

/* Accepts what is waiting on `lfd`, and gives it a child. */
static void accept_one(int lfd, int *lfds, size_t nl, struct rs_tls_config *tls,
                       const struct grants *gs, struct children *ch, unsigned idle)
{
    struct sockaddr_storage sa;
    socklen_t               len = sizeof(sa);
    char                    peer[NI_MAXHOST + NI_MAXSERV + 4];
    int                     fd;
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
    /* Blocking, whatever the listener is: the child reads and writes it in
     * turn, with the socket's own timeouts. */
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    pid = fork();
    if (pid < 0)
    {
        say("connection-refused peer=%s why=\"fork: %s\"", peer, strerror(errno));
        (void)close(fd);
        return;
    }
    if (pid == 0)
    {
        size_t i;
        int    status;

        for (i = 0; i < nl; i++)
        {
            (void)close(lfds[i]);
        }
        (void)close(wake[0]);
        (void)close(wake[1]);
        wake[0] = wake[1] = -1;
        (void)signal(SIGHUP, SIG_IGN);
        (void)signal(SIGTERM, SIG_DFL);
        (void)signal(SIGINT, SIG_DFL);
        (void)signal(SIGCHLD, SIG_DFL);
        status = serve_child(tls, fd, peer, gs, idle);
        (void)close(fd);
        /* exit, not _exit: what a coverage build counts is written then. */
        exit(status);
    }
    (void)close(fd);
    ch->pid[ch->n++] = pid;
}

/* Tells every child to stop, and waits for them, for a while. */
static void stop_children(struct children *ch)
{
    unsigned i;
    time_t   until = time(NULL) + STOP_WAIT;

    for (i = 0; i < ch->n; i++)
    {
        (void)kill(ch->pid[i], SIGTERM);
    }
    while (ch->n > 0 && time(NULL) < until)
    {
        reap(ch);
        if (ch->n > 0)
        {
            (void)poll(NULL, 0, 100);
        }
    }
    for (i = 0; i < ch->n; i++)
    {
        (void)kill(ch->pid[i], SIGKILL);
    }
    while (ch->n > 0 && waitpid(-1, NULL, 0) > 0)
    {
        ch->n--;
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
    struct pollfd            pfd[LISTEN_MAX + 1];
    struct children          ch;
    struct grants            gs;
    struct rs_buf            err;
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
    ch.pid = rs_xcalloc(ch.max, sizeof(*ch.pid));
    say("started version=%s tls=\"%s\" max_connections=%u", RESTATE_VERSION, rs_tls_library(),
        ch.max);

    while (!got_stop)
    {
        int ready;

        for (i = 0; i < nl; i++)
        {
            pfd[i].fd = lfds[i];
            pfd[i].events = POLLIN;
            pfd[i].revents = 0;
        }
        pfd[nl].fd = wake[0];
        pfd[nl].events = POLLIN;
        pfd[nl].revents = 0;
        ready = poll(pfd, (nfds_t)(nl + 1), WATCH_MS);
        if (pfd[nl].revents & POLLIN)
        {
            char drain[64];

            while (read(wake[0], drain, sizeof(drain)) > 0)
            {
            }
        }
        reap(&ch);
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
                accept_one(lfds[i], lfds, nl, tls, &gs, &ch, idle);
            }
        }
    }

    say("stopping: %u connection(s) open", ch.n);
    for (i = 0; i < nl; i++)
    {
        (void)close(lfds[i]);
    }
    stop_children(&ch);
    free(ch.pid);
    rs_grants_free(gs.g, gs.n);
    rs_tls_config_free(tls);
    (void)close(wake[0]);
    (void)close(wake[1]);
    wake[0] = wake[1] = -1;
    say("stopped");
    return RESTATE_EXIT_OK;
}
