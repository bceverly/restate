/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "pgp.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "run.h"

#define ARMOR "-----BEGIN PGP MESSAGE-----"

bool rs_pgp_detect(const unsigned char *head, size_t len)
{
    unsigned tag;

    if (len >= sizeof(ARMOR) - 1 && memcmp(head, ARMOR, sizeof(ARMOR) - 1) == 0)
    {
        return true;
    }
    if (len < 2 || !(head[0] & 0x80))
    {
        return false;
    }
    /* RFC 9580 packet headers: the new format's tag is the low six bits, the
     * old format's the four above the length type. An encrypted message
     * starts with a session key, public-key (1) or symmetric (3). */
    tag = (head[0] & 0x40) ? (unsigned)(head[0] & 0x3f) : (unsigned)((head[0] >> 2) & 0x0f);
    return tag == 1 || tag == 3;
}

static void cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags >= 0)
    {
        (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

static bool make_pipe(int p[2], struct rs_buf *err)
{
    if (pipe(p) < 0)
    {
        rs_buf_addf(err, "pipe: %s", strerror(errno));
        return false;
    }
    cloexec(p[0]);
    cloexec(p[1]);
    return true;
}

/* The throwaway home, and whatever gpg left in it: files, and one level of
 * directories (private-keys-v1.d, public-keys.d). */
static void remove_home(const char *home) /* NOLINT(misc-no-recursion) */
{
    DIR           *d = opendir(home);
    struct dirent *e;

    while (d && (e = readdir(d)) != NULL)
    {
        char       *path;
        struct stat st;

        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
        {
            continue;
        }
        path = rs_xasprintf("%s/%s", home, e->d_name);
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
        {
            remove_home(path);
        } else
        {
            (void)unlink(path);
        }
        free(path);
    }
    if (d)
    {
        (void)closedir(d);
    }
    (void)rmdir(home);
}

bool rs_pgp_encrypt(const char *const *recipients, size_t n, int out_fd, struct rs_pgp *pg,
                    struct rs_buf *err)
{
    char  **argv;
    size_t  a = 0;
    size_t  i;
    int     p[2];
    bool    ok;

    memset(pg, 0, sizeof(*pg));
    pg->fd = -1;
    if (n == 0)
    {
        rs_buf_addstr(err, "encrypting needs at least one recipient's public key");
        return false;
    }
    for (i = 0; i < n; i++)
    {
        int fd = open(recipients[i], O_RDONLY | O_CLOEXEC);

        if (fd < 0)
        {
            rs_buf_addf(err, "%s: %s", recipients[i], strerror(errno));
            return false;
        }
        (void)close(fd);
    }
    pg->home = rs_xstrdup("/tmp/restate-gpg.XXXXXX");
    if (!mkdtemp(pg->home))
    {
        rs_buf_addf(err, "a GnuPG home under /tmp: %s", strerror(errno));
        free(pg->home);
        pg->home = NULL;
        return false;
    }
    argv = rs_xcalloc(16 + 2 * n, sizeof(*argv));
    argv[a++] = rs_xstrdup("gpg");
    argv[a++] = rs_xstrdup("--homedir");
    argv[a++] = rs_xstrdup(pg->home);
    argv[a++] = rs_xstrdup("--batch");
    argv[a++] = rs_xstrdup("--no-tty");
    argv[a++] = rs_xstrdup("--quiet");
    argv[a++] = rs_xstrdup("--no-options");
    /* The keys are the ones named on the command line, which is all the
     * trust there is to decide; and the data is gzip's, so not compressed again. */
    argv[a++] = rs_xstrdup("--trust-model");
    argv[a++] = rs_xstrdup("always");
    argv[a++] = rs_xstrdup("--compress-algo");
    argv[a++] = rs_xstrdup("none");
    argv[a++] = rs_xstrdup("--encrypt");
    for (i = 0; i < n; i++)
    {
        argv[a++] = rs_xstrdup("--recipient-file");
        argv[a++] = rs_xstrdup(recipients[i]);
    }
    argv[a] = NULL;
    ok = make_pipe(p, err);
    if (ok)
    {
        ok = rs_spawn(RS_PROG_GPG, argv, p[0], out_fd, -1, &pg->pid, err);
        (void)close(p[0]);
        if (ok)
        {
            pg->fd = p[1];
        } else
        {
            (void)close(p[1]);
        }
    }
    for (i = 0; i < a; i++)
    {
        free(argv[i]);
    }
    free(argv);
    if (!ok)
    {
        remove_home(pg->home);
        free(pg->home);
        pg->home = NULL;
    }
    return ok;
}

bool rs_pgp_decrypt(int in_fd, struct rs_pgp *pg, struct rs_buf *err)
{
    static char a0[] = "gpg";
    static char a1[] = "--quiet";
    static char a2[] = "--batch";
    static char a3[] = "--decrypt";
    char       *argv[] = { a0, a1, a2, a3, NULL };
    int         p[2];

    memset(pg, 0, sizeof(*pg));
    pg->fd = -1;
    if (!make_pipe(p, err))
    {
        return false;
    }
    if (!rs_spawn(RS_PROG_GPG, argv, in_fd, p[1], -1, &pg->pid, err))
    {
        (void)close(p[0]);
        (void)close(p[1]);
        return false;
    }
    (void)close(p[1]);
    pg->fd = p[0];
    return true;
}

bool rs_pgp_finish(struct rs_pgp *pg, bool abandon, struct rs_buf *err)
{
    int  code = 0;
    bool ok;

    if (pg->fd >= 0)
    {
        (void)close(pg->fd);
        pg->fd = -1;
    }
    if (abandon)
    {
        (void)kill(pg->pid, SIGTERM);
    }
    ok = rs_wait(pg->pid, &code, err);
    if (pg->home)
    {
        remove_home(pg->home);
        free(pg->home);
        pg->home = NULL;
    }
    if (!ok || abandon)
    {
        return ok;
    }
    if (code != 0)
    {
        rs_buf_addf(err, "gpg failed (exit %d)", code);
        return false;
    }
    return true;
}
