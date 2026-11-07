/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "tlsconn.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef RS_TLS_LIBTLS
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <tls.h>
#else
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

/* The only protocol there is, as ALPN writes it: its length, then it. */
#define ALPN_NAME "http/1.1"

struct rs_tls {
#ifdef RS_TLS_LIBTLS
    struct tls *conn;
    int         fd;         /* its socket */
    bool        closed;     /* tls_close done, at the peer's close */
#else
    SSL        *ssl;
#endif
    char        alpn[sizeof ALPN_NAME];
};

#ifdef RS_TLS_LIBTLS

/* ------------------------------------------------------------------------ */
/* libtls                                                                   */
/* ------------------------------------------------------------------------ */

struct rs_tls_config {
    struct tls_config *cfg;
    struct tls        *server;      /* NULL for a client's */
};

const char *rs_tls_library(void)
{
    return "libtls";
}

static void why(struct rs_buf *err, const char *what, const char *detail)
{
    rs_buf_addf(err, "%s: %s", what, detail ? detail : "failed");
}

static struct tls_config *new_config(struct rs_buf *err)
{
    struct tls_config *cfg = tls_init() == 0 ? tls_config_new() : NULL;

    if (cfg == NULL)
    {
        rs_buf_addstr(err, "TLS: the library could not start");
        return NULL;
    }
    if (tls_config_set_protocols(cfg, TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3) != 0 ||
        tls_config_set_alpn(cfg, ALPN_NAME) != 0)
    {
        why(err, "TLS", tls_config_error(cfg));
        tls_config_free(cfg);
        return NULL;
    }
    return cfg;
}

struct rs_tls_config *rs_tls_server_config(const char *cert_file, const char *key_file,
                                           struct rs_buf *err)
{
    struct rs_tls_config *c;
    struct tls_config    *cfg = new_config(err);

    if (!cfg)
    {
        return NULL;
    }
    if (tls_config_set_cert_file(cfg, cert_file) != 0)
    {
        why(err, cert_file, tls_config_error(cfg));
        tls_config_free(cfg);
        return NULL;
    }
    if (tls_config_set_key_file(cfg, key_file) != 0)
    {
        why(err, key_file, tls_config_error(cfg));
        tls_config_free(cfg);
        return NULL;
    }
    c = rs_xcalloc(1, sizeof *c);
    c->cfg = cfg;
    c->server = tls_server();
    /* Where a key that is not the certificate's is found, so both are named. */
    if (!c->server || tls_configure(c->server, cfg) != 0)
    {
        rs_buf_addf(err, "%s and %s: %s", cert_file, key_file,
                    c->server && tls_error(c->server) ? tls_error(c->server) : "failed");
        rs_tls_config_free(c);
        return NULL;
    }
    return c;
}

struct rs_tls_config *rs_tls_client_config(const char *ca_file, struct rs_buf *err)
{
    struct rs_tls_config *c;
    struct tls_config    *cfg = new_config(err);

    if (!cfg)
    {
        return NULL;
    }
    if (ca_file && tls_config_set_ca_file(cfg, ca_file) != 0)
    {
        why(err, ca_file, tls_config_error(cfg));
        tls_config_free(cfg);
        return NULL;
    }
    c = rs_xcalloc(1, sizeof *c);
    c->cfg = cfg;
    return c;
}

void rs_tls_config_free(struct rs_tls_config *cfg)
{
    if (!cfg)
    {
        return;
    }
    if (cfg->server)
    {
        tls_free(cfg->server);
    }
    tls_config_free(cfg->cfg);
    free(cfg);
}

/* Milliseconds on a clock that only goes forward. */
static long long now_ms(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Whether libtls's TLS_WANT_POLLIN or TLS_WANT_POLLOUT, `r`, from a call on
 * socket `fd` begun at `since` (now_ms), is to be tried again: once the
 * socket is ready, within what is left of its own timeout (SO_RCVTIMEO,
 * SO_SNDTIMEO). The socket is blocking, so a "want" mostly comes of that
 * timeout having run out in the call -- the peer having said nothing for
 * that long -- which is then an error, not a reason to wait again: or an
 * idle connection would be tried forever. Waited for with poll(2), not told
 * by errno, which not every libtls leaves as the read left it.
 */
static bool again(int fd, long r, long long since)
{
    struct pollfd  p;
    struct timeval tv;
    socklen_t      len = sizeof(tv);
    long long      left = -1;

    if (r != TLS_WANT_POLLIN && r != TLS_WANT_POLLOUT)
    {
        return false;
    }
    memset(&tv, 0, sizeof(tv));
    if (getsockopt(fd, SOL_SOCKET, r == TLS_WANT_POLLIN ? SO_RCVTIMEO : SO_SNDTIMEO, &tv,
                   &len) == 0 &&
        (tv.tv_sec > 0 || tv.tv_usec > 0))
    {
        left = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000 - (now_ms() - since);
        if (left <= 0)
        {
            return false;
        }
    }
    p.fd = fd;
    p.events = r == TLS_WANT_POLLIN ? POLLIN : POLLOUT;
    p.revents = 0;
    return poll(&p, 1, left > INT_MAX ? INT_MAX : (int)left) > 0;
}

/* The handshake on `conn`, which is freed if it fails. */
static struct rs_tls *handshake(struct tls *conn, int fd, struct rs_buf *err)
{
    struct rs_tls *t;
    const char    *alpn;
    int            r;
    long long      since = now_ms();

    do
    {
        r = tls_handshake(conn);
    } while (again(fd, r, since));
    if (r != 0)
    {
        why(err, "TLS handshake", tls_error(conn));
        tls_free(conn);
        return NULL;
    }
    t = rs_xcalloc(1, sizeof *t);
    t->conn = conn;
    t->fd = fd;
    alpn = tls_conn_alpn_selected(conn);
    if (alpn && strcmp(alpn, ALPN_NAME) == 0)
    {
        memcpy(t->alpn, ALPN_NAME, sizeof ALPN_NAME);
    }
    return t;
}

struct rs_tls *rs_tls_accept(struct rs_tls_config *cfg, int fd, struct rs_buf *err)
{
    struct tls *conn = NULL;

    if (!cfg->server || tls_accept_socket(cfg->server, &conn, fd) != 0)
    {
        why(err, "TLS", cfg->server ? tls_error(cfg->server) : "not a server's configuration");
        return NULL;
    }
    return handshake(conn, fd, err);
}

struct rs_tls *rs_tls_connect(struct rs_tls_config *cfg, int fd, const char *name,
                              struct rs_buf *err)
{
    struct tls *conn = tls_client();

    if (!conn)
    {
        rs_buf_addstr(err, "TLS: the library could not start");
        return NULL;
    }
    if (cfg->server || tls_configure(conn, cfg->cfg) != 0 ||
        tls_connect_socket(conn, fd, name) != 0)
    {
        why(err, "TLS", cfg->server ? "not a client's configuration" : tls_error(conn));
        tls_free(conn);
        return NULL;
    }
    return handshake(conn, fd, err);
}

/*
 * Whether the end tls_read just reported was the peer's close_notify. libtls
 * reads a socket closed under it as an end too, and says which it was only
 * at tls_close: "EOF without close notify". So the close is done here, once,
 * and rs_tls_close does not do it again.
 */
static bool peer_closed(struct rs_tls *t)
{
    int         rv;
    const char *e;
    long long   since = now_ms();

    do
    {
        rv = tls_close(t->conn);
    } while (again(t->fd, rv, since));
    t->closed = true;
    if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
    {
        return false;
    }
    e = rv == 0 ? NULL : tls_error(t->conn);
    return !(e && strstr(e, "close notify"));
}

long rs_tls_read(struct rs_tls *t, void *buf, size_t len)
{
    ssize_t   n;
    long long since;

    if (len > LONG_MAX)
    {
        len = LONG_MAX;
    }
    since = now_ms();
    do
    {
        n = tls_read(t->conn, buf, len);
    } while (again(t->fd, n, since));
    if (n == 0 && !t->closed)
    {
        return peer_closed(t) ? 0 : -1;
    }
    return n < 0 ? -1 : (long)n;
}

bool rs_tls_write(struct rs_tls *t, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0)
    {
        long long since = now_ms();
        ssize_t   n = tls_write(t->conn, p, len);

        if (again(t->fd, n, since))
        {
            continue;
        }
        if (n <= 0)
        {
            return false;
        }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

const char *rs_tls_version(const struct rs_tls *t)
{
    const char *v = tls_conn_version(t->conn);

    return v ? v : "";
}

void rs_tls_close(struct rs_tls *t)
{
    if (!t)
    {
        return;
    }
    if (!t->closed)
    {
        (void)tls_close(t->conn);
    }
    tls_free(t->conn);
    free(t);
}

#else /* OpenSSL */

/* ------------------------------------------------------------------------ */
/* OpenSSL                                                                  */
/* ------------------------------------------------------------------------ */

struct rs_tls_config {
    SSL_CTX *ctx;
    bool     server;
};

static const unsigned char alpn_wire[] = "\x08" ALPN_NAME;

const char *rs_tls_library(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}

/* `what`, and the reason at the front of OpenSSL's queue; the queue emptied,
 * so the next failure is not blamed on this one's. */
static void why(struct rs_buf *err, const char *what)
{
    unsigned long e = ERR_get_error();
    const char   *reason = e ? ERR_reason_error_string(e) : NULL;

    /* A file that cannot be opened is the system's error, which OpenSSL
     * keeps as its number and has no text of its own for. */
    if (e && !reason && ERR_GET_LIB(e) == ERR_LIB_SYS)
    {
        reason = strerror(ERR_GET_REASON(e));
    }

    if (reason)
    {
        rs_buf_addf(err, "%s: %s", what, reason);
    } else
    {
        rs_buf_addf(err, "%s: failed", what);
    }
    ERR_clear_error();
}

/* A key with a passphrase is refused, rather than OpenSSL asking for one on
 * a terminal that a server does not have. */
static int no_passphrase(char *buf, int size, int rwflag, void *data)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)data;
    return 0;
}

/*
 * The protocol, when the client offers it among those it names. A client
 * that names others only is not refused: it is answered with no protocol, and
 * the first line it sends in anything but HTTP/1.1 is refused with 505.
 */
static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    unsigned int i = 0;

    (void)ssl;
    (void)arg;
    while (i < inlen)
    {
        unsigned int n = in[i];

        if (n > inlen - i - 1)
        {
            break;
        }
        if (n == sizeof alpn_wire - 2 && memcmp(in + i + 1, ALPN_NAME, n) == 0)
        {
            *out = in + i + 1;
            *outlen = (unsigned char)n;
            return SSL_TLSEXT_ERR_OK;
        }
        i += n + 1;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static SSL_CTX *new_ctx(const SSL_METHOD *method, struct rs_buf *err)
{
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        why(err, "TLS");
        return NULL;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
    {
        why(err, "TLS");
        SSL_CTX_free(ctx);
        return NULL;
    }
    (void)SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    return ctx;
}

struct rs_tls_config *rs_tls_server_config(const char *cert_file, const char *key_file,
                                           struct rs_buf *err)
{
    struct rs_tls_config *c;
    SSL_CTX              *ctx = new_ctx(TLS_server_method(), err);

    if (!ctx)
    {
        return NULL;
    }
    (void)SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_default_passwd_cb(ctx, no_passphrase);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1)
    {
        why(err, cert_file);
        SSL_CTX_free(ctx);
        return NULL;
    }
    /* Which also refuses a key that is not the certificate's. */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1)
    {
        why(err, key_file);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    c = rs_xcalloc(1, sizeof *c);
    c->ctx = ctx;
    c->server = true;
    return c;
}

/* A certificate is good only where OpenSSL's own check found it so: named
 * rather than left to a NULL callback, so that it is plain nothing here
 * accepts one OpenSSL refused. */
static int verified(int preverify_ok, X509_STORE_CTX *store)
{
    (void)store;
    return preverify_ok;
}

struct rs_tls_config *rs_tls_client_config(const char *ca_file, struct rs_buf *err)
{
    struct rs_tls_config *c;
    SSL_CTX              *ctx = new_ctx(TLS_client_method(), err);
    int                   ok;

    if (!ctx)
    {
        return NULL;
    }
    ok = ca_file ? SSL_CTX_load_verify_locations(ctx, ca_file, NULL)
                 : SSL_CTX_set_default_verify_paths(ctx);
    if (ok != 1)
    {
        why(err, ca_file ? ca_file : "the system's certificate authorities");
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verified);
    c = rs_xcalloc(1, sizeof *c);
    c->ctx = ctx;
    return c;
}

void rs_tls_config_free(struct rs_tls_config *cfg)
{
    if (!cfg)
    {
        return;
    }
    SSL_CTX_free(cfg->ctx);
    free(cfg);
}

static struct rs_tls *wrap(SSL *ssl)
{
    struct rs_tls       *t = rs_xcalloc(1, sizeof *t);
    const unsigned char *alpn = NULL;
    unsigned int         n = 0;

    t->ssl = ssl;
    SSL_get0_alpn_selected(ssl, &alpn, &n);
    if (alpn && n == sizeof ALPN_NAME - 1 && memcmp(alpn, ALPN_NAME, n) == 0)
    {
        memcpy(t->alpn, ALPN_NAME, sizeof ALPN_NAME);
    }
    return t;
}

/* The handshake's failure, with the certificate's own reason where it was
 * the certificate that failed. */
static void handshake_failed(SSL *ssl, struct rs_buf *err)
{
    long v = SSL_get_verify_result(ssl);

    if (v != X509_V_OK)
    {
        ERR_clear_error();
        rs_buf_addf(err, "TLS handshake: %s", X509_verify_cert_error_string(v));
    } else
    {
        why(err, "TLS handshake");
    }
    SSL_free(ssl);
}

struct rs_tls *rs_tls_accept(struct rs_tls_config *cfg, int fd, struct rs_buf *err)
{
    SSL *ssl;

    if (!cfg->server)
    {
        rs_buf_addstr(err, "TLS: not a server's configuration");
        return NULL;
    }
    ERR_clear_error();
    ssl = SSL_new(cfg->ctx);
    if (!ssl || SSL_set_fd(ssl, fd) != 1)
    {
        why(err, "TLS");
        SSL_free(ssl);
        return NULL;
    }
    if (SSL_accept(ssl) != 1)
    {
        why(err, "TLS handshake");
        SSL_free(ssl);
        return NULL;
    }
    return wrap(ssl);
}

struct rs_tls *rs_tls_connect(struct rs_tls_config *cfg, int fd, const char *name,
                              struct rs_buf *err)
{
    SSL  *ssl;
    char *host;
    long  sni;

    if (cfg->server)
    {
        rs_buf_addstr(err, "TLS: not a client's configuration");
        return NULL;
    }
    ERR_clear_error();
    ssl = SSL_new(cfg->ctx);
    if (!ssl || SSL_set_fd(ssl, fd) != 1)
    {
        why(err, "TLS");
        SSL_free(ssl);
        return NULL;
    }
    /* SSL_set_tlsext_host_name casts its argument's const away; this hands
     * it a copy that has none to lose. */
    host = rs_xstrdup(name);
    sni = SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, host);
    free(host);
    if (sni != 1 || SSL_set1_host(ssl, name) != 1 ||
        SSL_set_alpn_protos(ssl, alpn_wire, sizeof alpn_wire - 1) != 0)
    {
        why(err, "TLS");
        SSL_free(ssl);
        return NULL;
    }
    if (SSL_connect(ssl) != 1)
    {
        handshake_failed(ssl, err);
        return NULL;
    }
    return wrap(ssl);
}

long rs_tls_read(struct rs_tls *t, void *buf, size_t len)
{
    size_t got = 0;

    if (len > LONG_MAX)
    {
        len = LONG_MAX;
    }
    ERR_clear_error();
    if (SSL_read_ex(t->ssl, buf, len, &got) == 1)
    {
        return (long)got;
    }
    if (SSL_get_error(t->ssl, 0) == SSL_ERROR_ZERO_RETURN)
    {
        return 0;
    }
    ERR_clear_error();
    return -1;
}

bool rs_tls_write(struct rs_tls *t, const void *buf, size_t len)
{
    const unsigned char *p = buf;

    ERR_clear_error();
    while (len > 0)
    {
        size_t n = 0;

        if (SSL_write_ex(t->ssl, p, len, &n) != 1)
        {
            ERR_clear_error();
            return false;
        }
        p += n;
        len -= n;
    }
    return true;
}

const char *rs_tls_version(const struct rs_tls *t)
{
    return SSL_get_version(t->ssl);
}

void rs_tls_close(struct rs_tls *t)
{
    if (!t)
    {
        return;
    }
    /* Once: close_notify sent, the peer's not waited for. */
    (void)SSL_shutdown(t->ssl);
    ERR_clear_error();
    SSL_free(t->ssl);
    free(t);
}

#endif

const char *rs_tls_alpn(const struct rs_tls *t)
{
    return t->alpn;
}
