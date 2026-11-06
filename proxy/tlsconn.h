/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * TLS for restate-proxy, from the system's TLS library and never written
 * here: OpenSSL 3, or libtls on OpenBSD (scripts/tls.sh says which). This is
 * the whole of what the proxy asks of either, so that nothing else in it
 * names one. It is tlsconn.h, not tls.h, which is libtls's own: with
 * -Iproxy, a tls.h here would be the one <tls.h> found.
 *
 * What is fixed rather than configured, as docs/proxy-protocol.md says: TLS
 * 1.2 or newer, and ALPN http/1.1 when the client offers it. A client that
 * offers only other protocols is answered with none, and its first request
 * line, in anything but HTTP/1.1, with 505. Renegotiation and compression
 * are off.
 *
 * Connections are on blocking sockets, the caller's: a timeout is the
 * socket's (SO_RCVTIMEO, SO_SNDTIMEO), and closing the connection leaves the
 * socket open for the caller to close. Writing to a peer that has gone
 * raises SIGPIPE, which a caller ignores.
 *
 * The client half is here for the tests and for a proxy checking itself; the
 * restate program never links this, and reaches a proxy through curl.
 */
#ifndef RESTATE_TLSCONN_H
#define RESTATE_TLSCONN_H

#include <stdbool.h>
#include <stddef.h>

#include "util.h"

struct rs_tls_config;
struct rs_tls;

/* The library and its version, for --version: "OpenSSL 3.5.5 ...". */
const char *rs_tls_library(void);

/*
 * A server's configuration: the certificate chain in `cert_file` (PEM, the
 * server's own first) and its private key in `key_file`. NULL, and why in
 * `err`, if either cannot be read or they do not belong together.
 */
struct rs_tls_config *rs_tls_server_config(const char *cert_file, const char *key_file,
                                           struct rs_buf *err);

/* A client's: trusting the certificate authorities in `ca_file` (PEM), or the
 * system's own where it is NULL, and checking the name the server is at. */
struct rs_tls_config *rs_tls_client_config(const char *ca_file, struct rs_buf *err);

void rs_tls_config_free(struct rs_tls_config *cfg);

/*
 * The handshake on the connected socket `fd`, as its server or as a client
 * of the server named `name`. NULL, and why in `err`, if it fails.
 */
struct rs_tls *rs_tls_accept(struct rs_tls_config *cfg, int fd, struct rs_buf *err);
struct rs_tls *rs_tls_connect(struct rs_tls_config *cfg, int fd, const char *name,
                              struct rs_buf *err);

/* Up to `len` bytes into `buf`: how many, 0 once the peer has closed, -1 on
 * an error (a connection cut without the peer closing it among them). */
long rs_tls_read(struct rs_tls *t, void *buf, size_t len);

/* All `len` bytes of `buf`, or false. */
bool rs_tls_write(struct rs_tls *t, const void *buf, size_t len);

/* What was agreed: "TLSv1.3", and "http/1.1" or "" if the client named no
 * protocol. */
const char *rs_tls_version(const struct rs_tls *t);
const char *rs_tls_alpn(const struct rs_tls *t);

/* Says so to the peer and frees `t`; the socket is the caller's to close. */
void rs_tls_close(struct rs_tls *t);

#endif /* RESTATE_TLSCONN_H */
