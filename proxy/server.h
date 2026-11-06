/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate-proxy's server: the process that listens, and one child per
 * connection that serves it (serve.h).
 *
 * The parent reads the certificate and key once, binds every address it is
 * told to, and holds the grants in proxy.d, reading them again on SIGHUP
 * and whenever the directory changes (a grant is written beside its name
 * and renamed into place, which changes the directory). A connection is
 * served by a child of its own, with the grants as they were when it came:
 * one connection's failure is that connection's alone, and the parent never
 * touches a byte a client sends. Past --max-connections, a connection is
 * closed as it comes.
 *
 * The sessions are the parent's (sessions.h), with the repositories' locks
 * they hold: a session outlives the connection that opened it. A child asks
 * for them over a socket pair of its own, a line at a time, with words it
 * has checked already. Past --max-sessions, a session is refused (503); one
 * idle for --lease seconds is ended.
 *
 * SIGTERM and SIGINT stop it: it stops listening, tells each child to stop,
 * waits for them, and exits 0.
 *
 * Its log is standard error, a line per event in key=value form (which a
 * service manager's journal keeps): what it listens on, the grants it reads
 * and why any is not good, and each request.
 */
#ifndef RESTATE_SERVER_H
#define RESTATE_SERVER_H

#include <stddef.h>

#define RS_PROXY_PORT             "8443"
#define RS_PROXY_GRANTS           "/etc/restate/proxy.d"
#define RS_PROXY_CERT             "/etc/restate/proxy.crt"
#define RS_PROXY_KEY              "/etc/restate/proxy.key"
#define RS_PROXY_MAX_CONNECTIONS  64u
#define RS_PROXY_IDLE_TIMEOUT     60u

struct rs_proxy_options {
    const char *const *listen;      /* HOST:PORT, [V6]:PORT or :PORT, each */
    size_t             nlisten;     /* 0: every address, on RS_PROXY_PORT */
    const char        *cert;
    const char        *key;
    const char        *grants;
    unsigned           max_connections;
    unsigned           idle_timeout;    /* seconds a connection may say nothing */
    unsigned           max_sessions;    /* 0: RS_PROXY_MAX_SESSIONS */
    unsigned           lease;           /* seconds; 0: RS_PROXY_LEASE */
};

/* Runs the server until it is told to stop: the exit status. */
int rs_proxy_run(const struct rs_proxy_options *o);

#endif /* RESTATE_SERVER_H */
