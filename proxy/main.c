/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * restate-proxy -- restate's repositories over HTTPS (docs/proxy-protocol.md).
 *
 * --serve runs the server (server.h). The rest is what an administrator
 * needs to set one up, and needs no server running: checking the grants in
 * proxy.d, and making a client's token.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "grant.h"
#include "restate.h"
#include "server.h"
#include "sha256.h"
#include "tlsconn.h"
#include "token.h"
#include "util.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define GRANTS_DIR RS_PROXY_GRANTS

static void complain(const char *fmt, ...) RESTATE_PRINTF(1, 2);

static void complain(const char *fmt, ...)
{
    va_list ap;

    (void)fflush(stdout);
    (void)fputs("restate-proxy: ", stderr);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap); /* Flawfinder: ignore -- checked by RESTATE_PRINTF */
    va_end(ap);
    (void)fputc('\n', stderr);
}

/* Cleared through a volatile pointer, so that a store never read again is
 * not optimized away. */
static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;

    while (n-- > 0)
    {
        *v++ = 0;
    }
}

static void usage(FILE *out)
{
    (void)fprintf(out,
                  "usage: restate-proxy --serve [--listen HOST:PORT]... [--cert FILE]\n"
                  "                     [--key FILE] [--grants DIR] [--max-connections N]\n"
                  "                     [--idle-timeout SECONDS] [--max-sessions N]\n"
                  "                     [--lease SECONDS] [--staging DIR] [--max-staging MIB]\n"
                  "       restate-proxy --check-grants [DIR] [--json]\n"
                  "       restate-proxy --new-token FILE\n"
                  "       restate-proxy --version | --help\n"
                  "\n"
                  "  --serve               serve the repositories the grants allow over HTTPS,\n"
                  "                        until SIGTERM; SIGHUP reads the grants again\n"
                  "  --listen HOST:PORT    where: [ADDRESS]:PORT for IPv6, :PORT for every\n"
                  "                        address (:" RS_PROXY_PORT ", the default); repeatable\n"
                  "  --cert FILE           the certificate chain, PEM (" RS_PROXY_CERT ")\n"
                  "  --key FILE            its private key, PEM, unencrypted (" RS_PROXY_KEY ")\n"
                  "  --grants DIR          the grants (" GRANTS_DIR ")\n"
                  "  --max-connections N   connections served at once (64)\n"
                  "  --idle-timeout SECONDS\n"
                  "                        how long a connection may say nothing (60)\n"
                  "  --max-sessions N      sessions open at once (64)\n"
                  "  --lease SECONDS       how long a session lasts idle, unrenewed (300)\n"
                  "  --staging DIR         where uploads wait to be committed\n"
                  "                        (" RS_PROXY_STAGING ")\n"
                  "  --max-staging MIB     the most one session's staging may hold (4096)\n"
                  "  --check-grants [DIR]  read every grant in DIR (" GRANTS_DIR ")\n"
                  "                        as the proxy would, and say what is wrong\n"
                  "                        with each; exit 2 if one is not good\n"
                  "  --json                say it as JSON, schema 1\n"
                  "  --new-token FILE      write a new client token into FILE, which must\n"
                  "                        not exist, and print its token_sha256 line\n"
                  "  --version             print the version and the TLS library\n"
                  "  --help                print this\n");
}

static int finish(int status)
{
    if (fflush(stdout) != 0 || ferror(stdout))
    {
        complain("writing the output: %s", strerror(errno));
        return RESTATE_EXIT_TROUBLE;
    }
    return status;
}

static int check_grants(const char *dir, bool json)
{
    struct rs_grant_checked *c = NULL;
    struct rs_buf            err;
    struct rs_buf            out;
    size_t                   n = 0;
    size_t                   i;
    int                      status = RESTATE_EXIT_OK;

    rs_buf_init(&err);
    if (!rs_grants_check(dir, &c, &n, &err))
    {
        complain("%s", err.data);
        rs_buf_free(&err);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_buf_free(&err);
    rs_buf_init(&out);
    rs_grants_report(c, n, json, &out);
    (void)fwrite(out.data, 1, out.len, stdout);
    rs_buf_free(&out);
    for (i = 0; i < n; i++)
    {
        if (!c[i].ok)
        {
            status = RESTATE_EXIT_TROUBLE;
        }
    }
    rs_grants_checked_free(c, n);
    return finish(status);
}

/*
 * A token into `file`, created for this alone and readable only by its
 * owner; on standard output, the line its grant needs. The token itself is
 * never printed, so that it is in no terminal's scrollback and no log.
 */
static int new_token(const char *file)
{
    char   token[RS_TOKEN_SIZE];
    char   hex[RS_SHA256_HEX_SIZE];
    char   line[RS_TOKEN_SIZE + 1];
    int    fd;
    size_t len;

    if (!rs_token_new(token))
    {
        complain("making a token: the system's random source could not be read");
        return RESTATE_EXIT_TROUBLE;
    }
    fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        complain("%s: %s", file, strerror(errno));
        return RESTATE_EXIT_TROUBLE;
    }
    len = (size_t)snprintf(line, sizeof line, "%s\n", token);
    if (write(fd, line, len) != (ssize_t)len || fsync(fd) != 0)
    {
        complain("%s: %s", file, strerror(errno));
        (void)close(fd);
        (void)unlink(file);
        return RESTATE_EXIT_TROUBLE;
    }
    if (close(fd) != 0)
    {
        complain("%s: %s", file, strerror(errno));
        (void)unlink(file);
        return RESTATE_EXIT_TROUBLE;
    }
    rs_sha256_hex(token, RS_TOKEN_LEN, hex);
    wipe(token, sizeof token);
    wipe(line, sizeof line);
    (void)printf("token_sha256 = %s\n", hex);
    return finish(RESTATE_EXIT_OK);
}

/* `s` as a number from 1 to `max`, or false. */
static bool number(const char *s, unsigned max, unsigned *out)
{
    unsigned long v = 0;
    size_t        i;

    if (!s[0] || strlen(s) > 9 || strspn(s, "0123456789") != strlen(s))
    {
        return false;
    }
    for (i = 0; s[i]; i++)
    {
        v = v * 10 + (unsigned long)(s[i] - '0');
    }
    if (v == 0 || v > max)
    {
        return false;
    }
    *out = (unsigned)v;
    return true;
}

/* An option's value, as "--NAME VALUE" or "--NAME=VALUE": NULL, said, if
 * argv[*i] is not --NAME or has no value. */
static const char *value_of(int argc, char **argv, int *i, const char *name, bool *matched)
{
    size_t len = strlen(name);

    *matched = false;
    if (strncmp(argv[*i], name, len) != 0)
    {
        return NULL;
    }
    if (argv[*i][len] == '=')
    {
        *matched = true;
        return argv[*i] + len + 1;
    }
    if (argv[*i][len] != '\0')
    {
        return NULL;
    }
    *matched = true;
    if (*i + 1 >= argc)
    {
        complain("%s needs a value", name);
        return NULL;
    }
    return argv[++*i];
}

static int serve(int argc, char **argv)
{
    struct rs_proxy_options o;
    const char            **listen = rs_xcalloc((size_t)argc, sizeof(*listen));
    int                     i;
    int                     status;

    memset(&o, 0, sizeof(o));
    o.cert = RS_PROXY_CERT;
    o.key = RS_PROXY_KEY;
    o.grants = GRANTS_DIR;
    o.max_connections = RS_PROXY_MAX_CONNECTIONS;
    o.idle_timeout = RS_PROXY_IDLE_TIMEOUT;
    for (i = 2; i < argc; i++)
    {
        static const char *const names[] = { "--listen",          "--cert",
                                             "--key",             "--grants",
                                             "--max-connections", "--idle-timeout",
                                             "--max-sessions",    "--lease",
                                             "--staging",         "--max-staging" };
        static const unsigned    most[] = { 0, 0, 0, 0, 100000u, 86400u, 100000u, 86400u, 0,
                                            1048576u };
        const char              *v = NULL;
        bool                     matched = false;
        size_t                   k;

        for (k = 0; k < sizeof(names) / sizeof(names[0]) && !matched; k++)
        {
            v = value_of(argc, argv, &i, names[k], &matched);
        }
        k--;
        if (!matched)
        {
            complain("--serve: unexpected %s", argv[i]);
            usage(stderr);
            free(listen);
            return RESTATE_EXIT_TROUBLE;
        }
        if (!v || !v[0])
        {
            complain("%s needs a value", names[k]);
            free(listen);
            return RESTATE_EXIT_TROUBLE;
        }
        if (k == 0)
        {
            listen[o.nlisten++] = v;
        } else if (k == 1)
        {
            o.cert = v;
        } else if (k == 2)
        {
            o.key = v;
        } else if (k == 3)
        {
            o.grants = v;
        } else if (k == 8)
        {
            o.staging = v;
        } else if (k == 9)
        {
            unsigned mib = 0;

            if (!number(v, most[k], &mib))
            {
                complain("%s: \"%s\" is not a number from 1 to %u", names[k], v, most[k]);
                free(listen);
                return RESTATE_EXIT_TROUBLE;
            }
            o.max_staging = (uint64_t)mib * 1024 * 1024;
        } else
        {
            unsigned *into[] = { NULL, NULL, NULL, NULL, &o.max_connections, &o.idle_timeout,
                                 &o.max_sessions, &o.lease };

            if (!number(v, most[k], into[k]))
            {
                complain("%s: \"%s\" is not a number from 1 to %u", names[k], v, most[k]);
                free(listen);
                return RESTATE_EXIT_TROUBLE;
            }
        }
    }
    o.listen = listen;
    status = rs_proxy_run(&o);
    free(listen);
    return status;
}

int main(int argc, char **argv)
{
    (void)umask(077);

    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0))
    {
        usage(stdout);
        return finish(RESTATE_EXIT_OK);
    }
    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0))
    {
        (void)printf("restate-proxy %s (protocol 1, %s)\n", RESTATE_VERSION, rs_tls_library());
        return finish(RESTATE_EXIT_OK);
    }
    if (argc >= 2 && strcmp(argv[1], "--serve") == 0)
    {
        return serve(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "--check-grants") == 0)
    {
        const char *dir = NULL;
        bool        json = false;
        int         i;

        for (i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--json") == 0 && !json)
            {
                json = true;
            } else if (argv[i][0] != '-' && !dir)
            {
                dir = argv[i];
            } else
            {
                complain("--check-grants: unexpected %s", argv[i]);
                usage(stderr);
                return RESTATE_EXIT_TROUBLE;
            }
        }
        return check_grants(dir ? dir : GRANTS_DIR, json);
    }
    if (argc == 3 && strcmp(argv[1], "--new-token") == 0 && argv[2][0] != '\0')
    {
        return new_token(argv[2]);
    }
    usage(stderr);
    return RESTATE_EXIT_TROUBLE;
}
