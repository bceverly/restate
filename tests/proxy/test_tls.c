/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * proxy/tls.c: real handshakes over a socket pair, the server in a child.
 *
 * The certificates are made for the run by openssl(1), which every system
 * with the library has beside it (LibreSSL's on OpenBSD and macOS); where it
 * is missing, the handshakes are passed over and said to be.
 */
#include "test.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tlsconn.h"
#include "util.h"

/* Runs openssl with `args`, quietly: whether it succeeded. */
static bool openssl(char *const args[])
{
    pid_t pid;
    int   status;

    (void)fflush(NULL);
    pid = fork();
    if (pid < 0)
    {
        return false;
    }
    if (pid == 0)
    {
        int null = open("/dev/null", O_RDWR);

        if (null >= 0)
        {
            (void)dup2(null, STDIN_FILENO);
            (void)dup2(null, STDOUT_FILENO);
            (void)dup2(null, STDERR_FILENO);
        }
        execvp("openssl", args);
        _exit(127);
    }
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* A self-signed certificate for `cn` and its key, into DIR/NAME.crt and
 * DIR/NAME.key -- with this openssl's own openssl.cnf, or, where it has
 * none (NetBSD's may not), the least one there can be, DIR/openssl.cnf. */
static bool make_cert(const char *dir, const char *name, const char *cn)
{
    char *crt = rs_xasprintf("%s/%s.crt", dir, name);
    char *key = rs_xasprintf("%s/%s.key", dir, name);
    char *subj = rs_xasprintf("/CN=%s", cn);
    char *cnf = rs_xasprintf("%s/openssl.cnf", dir);
    char *args[] = {"openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "2", "-subj", subj, "-keyout", key, "-out", crt, NULL};
    bool  ok = openssl(args);

    if (!ok)
    {
        char *with[] = {"openssl", "req", "-config", cnf, "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-days", "2", "-subj", subj, "-keyout", key, "-out", crt,
                        NULL};

        rs_test_write(dir, "openssl.cnf",
                      "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n"
                      "basicConstraints = critical, CA:true\n", 0600);
        ok = openssl(with);
    }
    free(crt);
    free(key);
    free(subj);
    free(cnf);
    return ok;
}

enum serve {
    SERVE_ECHO,                 /* read a line, write it back, close properly */
    SERVE_CUT                   /* the handshake, then the socket closed under it */
};

/*
 * The server's half, run as `unittests --tls-serve FD CERT KEY HOW` (from
 * test_main.c): 0 if it went as HOW says.
 *
 * A process of its own rather than a forked child, so that it starts with
 * nothing allocated: a child of the tests would inherit all they hold, and
 * valgrind, which counts every block still held at exit, would report it
 * all as the child's. And it ends with a return from main, so that a
 * coverage build records what it ran.
 */
int test_tls_serve(char **args)
{
    struct rs_tls_config *cfg;
    struct rs_buf         err;
    struct rs_tls        *t;
    int                   fd = atoi(args[0]);
    int                   status = 1;

    /* As the proxy does: a close_notify written to a client gone already is
     * an error of the write, not the end of this process. */
    (void)signal(SIGPIPE, SIG_IGN);
    rs_buf_init(&err);
    cfg = rs_tls_server_config(args[1], args[2], &err);
    t = cfg ? rs_tls_accept(cfg, fd, &err) : NULL;
    if (t && strcmp(args[3], "cut") == 0)
    {
        /* The socket shut first, so that the close_notify rs_tls_close
         * sends goes nowhere, as from a connection that is cut. */
        (void)shutdown(fd, SHUT_RDWR);
        rs_tls_close(t);
        status = 0;
    } else if (t)
    {
        char buf[64];
        long n = rs_tls_read(t, buf, sizeof buf);

        if (n > 0 && rs_tls_write(t, buf, (size_t)n) && strcmp(rs_tls_alpn(t), "http/1.1") == 0)
        {
            status = rs_tls_read(t, buf, sizeof buf) == 0 ? 0 : 3;
        }
        rs_tls_close(t);
    }
    rs_buf_free(&err);
    rs_tls_config_free(cfg);
    (void)close(fd);
    return status;
}

/* The server on `fd`, as test_tls_serve in a process of its own. */
static pid_t serve(const char *crt, const char *key, int fd, int other, enum serve how)
{
    pid_t pid;

    /* Flushed first, or what the parent has buffered is written twice. */
    (void)fflush(NULL);
    pid = fork();
    if (pid == 0)
    {
        char  number[16];
        char *args[] = {(char *)rs_test_argv0, "--tls-serve", number, (char *)crt, (char *)key,
                        how == SERVE_CUT ? "cut" : "echo", NULL};

        (void)close(other);
        (void)snprintf(number, sizeof number, "%d", fd);
        execv(rs_test_argv0, args);
        _exit(127);
    }
    return pid;
}

static int reap(pid_t pid)
{
    int status;

    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
    {
        return -1;
    }
    return WEXITSTATUS(status);
}

/* A client's handshake with a server of `crt` and `key`, by `name`: the
 * connection, or NULL and why in `err`. The server's process is in *pid. */
static struct rs_tls *dial(const char *crt, const char *key, struct rs_tls_config *client,
                           const char *name, enum serve how, pid_t *pid, int *fd,
                           struct rs_buf *err)
{
    int            sv[2];
    struct rs_tls *t;

    *pid = -1;
    *fd = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    {
        return NULL;
    }
    *pid = serve(crt, key, sv[1], sv[0], how);
    (void)close(sv[1]);
    t = rs_tls_connect(client, sv[0], name, err);
    *fd = sv[0];
    return t;
}

static void handshakes(const char *dir)
{
    struct rs_buf         err;
    struct rs_tls_config *server;
    struct rs_tls_config *client;
    struct rs_tls_config *stranger;
    struct rs_tls        *t;
    char                 *crt = rs_xasprintf("%s/proxy.crt", dir);
    char                 *key = rs_xasprintf("%s/proxy.key", dir);
    char                 *other_key = rs_xasprintf("%s/other.key", dir);
    char                 *other_crt = rs_xasprintf("%s/other.crt", dir);
    char                  buf[64];
    pid_t                 pid;
    int                   fd;

    rs_buf_init(&err);

    TEST_CASE("tls: a server's configuration needs its key to be its certificate's");
    server = rs_tls_server_config(crt, other_key, &err);
    CHECK(server == NULL);
    CHECK_CONTAINS(err.data, "other.key");
    rs_buf_reset(&err);
    server = rs_tls_server_config(crt, key, &err);
    CHECK(server != NULL);
    client = rs_tls_client_config(crt, &err);
    CHECK(client != NULL);
    stranger = rs_tls_client_config(other_crt, &err);
    CHECK(stranger != NULL);
    if (!server || !client || !stranger)
    {
        goto out;
    }

    TEST_CASE("tls: a handshake, a line each way, and a proper close");
    t = dial(crt, key, client, "localhost", SERVE_ECHO, &pid, &fd, &err);
    CHECK(t != NULL);
    if (t)
    {
        CHECK(rs_starts_with(rs_tls_version(t), "TLSv1."));
        CHECK(strcmp(rs_tls_version(t), "TLSv1.1") != 0);
        CHECK_STR(rs_tls_alpn(t), "http/1.1");
        CHECK(rs_tls_write(t, "hello\n", 6));
        CHECK_INT(rs_tls_read(t, buf, sizeof buf), 6);
        CHECK(memcmp(buf, "hello\n", 6) == 0);
        rs_tls_close(t);
    }
    (void)close(fd);
    CHECK_INT(reap(pid), 0);

    TEST_CASE("tls: a connection cut without a close is an error, not an end");
    t = dial(crt, key, client, "localhost", SERVE_CUT, &pid, &fd, &err);
    CHECK(t != NULL);
    if (t)
    {
        CHECK_INT(rs_tls_read(t, buf, sizeof buf), -1);
        rs_tls_close(t);
    }
    (void)close(fd);
    CHECK_INT(reap(pid), 0);

    TEST_CASE("tls: a server by another name is refused");
    rs_buf_reset(&err);
    t = dial(crt, key, client, "proxy.example.com", SERVE_ECHO, &pid, &fd, &err);
    CHECK(t == NULL);
    CHECK_CONTAINS(err.data, "TLS handshake");
    (void)close(fd);
    CHECK(reap(pid) != 0);

    TEST_CASE("tls: a certificate no authority trusted signed is refused");
    rs_buf_reset(&err);
    t = dial(crt, key, stranger, "localhost", SERVE_ECHO, &pid, &fd, &err);
    CHECK(t == NULL);
    CHECK_CONTAINS(err.data, "TLS handshake");
    (void)close(fd);
    CHECK(reap(pid) != 0);

    TEST_CASE("tls: each configuration is for its own side");
    rs_buf_reset(&err);
    CHECK(rs_tls_accept(client, -1, &err) == NULL);
    CHECK_CONTAINS(err.data, "not a server's configuration");
    rs_buf_reset(&err);
    CHECK(rs_tls_connect(server, -1, "localhost", &err) == NULL);
    CHECK_CONTAINS(err.data, "not a client's configuration");

out:
    rs_tls_config_free(server);
    rs_tls_config_free(client);
    rs_tls_config_free(stranger);
    rs_buf_free(&err);
    free(crt);
    free(key);
    free(other_key);
    free(other_crt);
}

void test_tls(void)
{
    struct rs_buf err;
    char         *dir = rs_test_tmpdir();
    char         *missing = rs_xasprintf("%s/missing.pem", dir);
    void (*was)(int) = signal(SIGPIPE, SIG_IGN);

    rs_buf_init(&err);

    TEST_CASE("tls: the library names itself");
    CHECK(rs_tls_library()[0] != '\0');

    TEST_CASE("tls: files that are not there are said to be");
    CHECK(rs_tls_server_config(missing, missing, &err) == NULL);
    CHECK_CONTAINS(err.data, missing);
    rs_buf_reset(&err);
    CHECK(rs_tls_client_config(missing, &err) == NULL);
    CHECK_CONTAINS(err.data, missing);
    rs_tls_config_free(NULL);
    rs_tls_close(NULL);

    TEST_CASE("tls: the system's own authorities can be the ones trusted");
    {
        struct rs_tls_config *c = rs_tls_client_config(NULL, &err);

        CHECK(c != NULL);
        rs_tls_config_free(c);
    }

    if (!rs_test_argv0)
    {
        (void)printf("  - tls: this program cannot be found to run again; handshakes not run\n");
    } else if (make_cert(dir, "proxy", "localhost") && make_cert(dir, "other", "localhost"))
    {
        handshakes(dir);
    } else
    {
        (void)printf("  - tls: openssl(1) could not make a certificate; handshakes not run\n");
    }

    (void)signal(SIGPIPE, was);
    rs_buf_free(&err);
    rs_test_rmtree(dir);
    free(missing);
    free(dir);
}
