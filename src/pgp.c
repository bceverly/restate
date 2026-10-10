/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "pgp.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "json.h"
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

/* ------------------------------------------------------------------------- */
/* Armor, homes, gpgv and its verdict                                         */
/* ------------------------------------------------------------------------- */

bool rs_pgp_dearmor(const char *text, size_t len, struct rs_buf *out)
{
    const char *p = text;
    const char *end = text + len;
    bool        any = false;

    while (p < end)
    {
        const char   *begin = NULL;
        const char   *q;
        struct rs_buf body;
        bool          headers = true;
        bool          ended = false;

        /* The next "-----BEGIN PGP ": a line of its own. */
        for (q = p; q < end; )
        {
            const char *nl = memchr(q, '\n', (size_t)(end - q));
            size_t      n = nl ? (size_t)(nl - q) : (size_t)(end - q);

            if (n >= 15 && memcmp(q, "-----BEGIN PGP ", 15) == 0)
            {
                begin = nl ? nl + 1 : end;
                break;
            }
            q = nl ? nl + 1 : end;
        }
        if (!begin)
        {
            break;
        }
        rs_buf_init(&body);
        for (q = begin; q < end; )
        {
            const char *nl = memchr(q, '\n', (size_t)(end - q));
            size_t      n = nl ? (size_t)(nl - q) : (size_t)(end - q);

            while (n > 0 && (q[n - 1] == '\r' || q[n - 1] == ' ' || q[n - 1] == '\t'))
            {
                n--;
            }
            if (n >= 13 && memcmp(q, "-----END PGP ", 13) == 0)
            {
                ended = true;
                q = nl ? nl + 1 : end;
                break;
            }
            if (headers)
            {
                /* "Version: ..." and the like, up to a blank line. A block
                 * with no headers starts its base64 at once. */
                if (n == 0)
                {
                    headers = false;
                } else if (!memchr(q, ':', n))
                {
                    headers = false;
                    rs_buf_add(&body, q, n);
                }
            } else if (n == 0 || q[0] != '=')
            {
                /* Not the "=" line, the CRC24 checksum RFC 9580 makes
                 * optional, which is left out. */
                rs_buf_add(&body, q, n);
            }
            q = nl ? nl + 1 : end;
        }
        {
            struct rs_buf bytes;

            rs_buf_init(&bytes);
            if (!ended || !rs_base64_decode(body.data ? body.data : "", body.len, &bytes))
            {
                rs_buf_free(&bytes);
                rs_buf_free(&body);
                return false;
            }
            rs_buf_add(out, bytes.data ? bytes.data : "", bytes.len);
            rs_buf_free(&bytes);
        }
        rs_buf_free(&body);
        any = true;
        p = q;
    }
    return any;
}

char *rs_pgp_home(struct rs_buf *err)
{
    char *home = rs_xstrdup("/tmp/restate-gpg.XXXXXX");

    if (!mkdtemp(home))
    {
        rs_buf_addf(err, "a GnuPG home under /tmp: %s", strerror(errno));
        free(home);
        return NULL;
    }
    return home;
}

void rs_pgp_home_remove(char *home)
{
    if (home)
    {
        remove_home(home);
        free(home);
    }
}

bool rs_pgp_gpgv(const char *home, const char *const *keyrings, size_t n, const char *sig,
                 const char *data, struct rs_buf *status, struct rs_buf *err)
{
    char        **argv = rs_xcalloc(8 + 2 * n, sizeof(*argv));
    struct rs_buf errtext;
    size_t        a = 0;
    size_t        i;
    int           code = 0;
    bool          ok;

    argv[a++] = rs_xstrdup("gpgv");
    argv[a++] = rs_xstrdup("--homedir");
    argv[a++] = rs_xstrdup(home);
    argv[a++] = rs_xstrdup("--status-fd");
    argv[a++] = rs_xstrdup("1");
    for (i = 0; i < n; i++)
    {
        argv[a++] = rs_xstrdup("--keyring");
        argv[a++] = rs_xstrdup(keyrings[i]);
    }
    argv[a++] = rs_xstrdup(sig);
    if (data)
    {
        argv[a++] = rs_xstrdup(data);
    }
    argv[a] = NULL;
    rs_buf_init(&errtext);
    /* Its exit status says no more than the status lines do. */
    ok = rs_run(RS_PROG_GPGV, argv, status, &errtext, &code, err);
    rs_buf_free(&errtext);
    for (i = 0; i < a; i++)
    {
        free(argv[i]);
    }
    free(argv);
    return ok;
}

/* The status line starting "[GNUPG:] KEYWORD ", if there is one: its
 * arguments, up to the end of the line, in `args`. */
static bool status_line(const char *status, const char *keyword, char *args, size_t cap)
{
    const char *p = status;
    size_t      klen = strlen(keyword);

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      n = nl ? (size_t)(nl - p) : strlen(p);

        if (n > 9 + klen && strncmp(p, "[GNUPG:] ", 9) == 0 &&
            strncmp(p + 9, keyword, klen) == 0 && (p[9 + klen] == ' '))
        {
            size_t take = n - 9 - klen - 1;

            if (take >= cap)
            {
                take = cap - 1;
            }
            memcpy(args, p + 9 + klen + 1, take);
            args[take] = '\0';
            return true;
        }
        p = nl ? nl + 1 : NULL;
    }
    return false;
}

/* Whether `s` is exactly 40 hex digits. */
static bool fingerprint(const char *s, size_t n)
{
    return n == 40 && strspn(s, "0123456789ABCDEFabcdef") >= 40;
}

bool rs_pgp_verdict(const char *status, struct rs_pgp_signer *signer, struct rs_buf *why)
{
    char args[512];

    memset(signer, 0, sizeof(*signer));
    if (status_line(status, "BADSIG", args, sizeof(args)))
    {
        rs_buf_addstr(why, "a bad signature");
    } else if (status_line(status, "REVKEYSIG", args, sizeof(args)))
    {
        rs_buf_addstr(why, "signed by a key that has been revoked");
    } else if (status_line(status, "EXPKEYSIG", args, sizeof(args)))
    {
        rs_buf_addstr(why, "signed by a key that has expired");
    } else if (status_line(status, "EXPSIG", args, sizeof(args)))
    {
        rs_buf_addstr(why, "a signature that has expired");
    } else if (status_line(status, "NO_PUBKEY", args, sizeof(args)))
    {
        size_t n = strcspn(args, " ");

        rs_buf_addf(why, "signed by a key that is not given (ID %.*s)", (int)(n > 40 ? 40 : n),
                    args);
    } else if (status_line(status, "GOODSIG", args, sizeof(args)))
    {
        /* GOODSIG <long key ID> <user ID> */
        const char *uid = strchr(args, ' ');
        const char *last;

        (void)snprintf(signer->who, sizeof(signer->who), "%s", uid ? uid + 1 : "");
        if (!status_line(status, "VALIDSIG", args, sizeof(args)))
        {
            rs_buf_addstr(why, "a signature gpgv did not describe");
            return false;
        }
        /* VALIDSIG <fpr> <date> <ts> <expires> <ver> <res> <algo> <hash>
         * <class> <primary fpr>: the primary key's, where it is given. */
        last = strrchr(args, ' ');
        if (last && fingerprint(last + 1, strlen(last + 1)))
        {
            memcpy(signer->fpr, last + 1, 40);
        } else if (fingerprint(args, strcspn(args, " ")))
        {
            memcpy(signer->fpr, args, 40);
        } else
        {
            rs_buf_addstr(why, "a signature gpgv did not describe");
            memset(signer, 0, sizeof(*signer));
            return false;
        }
        signer->fpr[40] = '\0';
        {
            const char *date = strchr(args, ' ');

            if (date && strlen(date + 1) >= 10 && date[5] == '-' && date[8] == '-')
            {
                memcpy(signer->when, date + 1, 10);
                signer->when[10] = '\0';
            }
        }
        return true;
    } else if (status_line(status, "ERRSIG", args, sizeof(args)))
    {
        rs_buf_addstr(why, "a signature that could not be checked");
    } else
    {
        rs_buf_addstr(why, "not signed");
    }
    return false;
}

bool rs_pgp_armored(const char *data, size_t len)
{
    static const char begin[] = "-----BEGIN PGP ";
    size_t            skip = 0;

    while (skip < len && (data[skip] == ' ' || data[skip] == '\t' || data[skip] == '\r' ||
                          data[skip] == '\n'))
    {
        skip++;
    }
    return len - skip >= sizeof(begin) - 1 && memcmp(data + skip, begin, sizeof(begin) - 1) == 0;
}

/* A key file is read up to this much. */
#define KEYFILE_MAX ((size_t)16 * 1024 * 1024)

static bool read_file(const char *path, size_t max, struct rs_buf *out, struct rs_buf *err)
{
    char    chunk[8192];
    ssize_t n;
    int     fd = open(path, O_RDONLY | O_CLOEXEC);

    rs_buf_init(out);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    while ((n = read(fd, chunk, sizeof(chunk))) > 0 && out->len <= max)
    {
        rs_buf_add(out, chunk, (size_t)n);
    }
    (void)close(fd);
    if (n < 0 || out->len > max)
    {
        rs_buf_addf(err, "%s: %s", path, n < 0 ? strerror(errno) : "too large to be a key");
        rs_buf_free(out);
        return false;
    }
    /* Terminated, for a reader that wants text; the length is the bytes'. */
    rs_buf_add(out, "", 0);
    return true;
}

static bool write_new(const char *path, const void *data, size_t len, struct rs_buf *err)
{
    int     fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    ssize_t w;

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    w = write(fd, data, len);
    if (close(fd) != 0 || w != (ssize_t)len)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    return true;
}

bool rs_pgp_key_bytes(const char *path, struct rs_buf *out, struct rs_buf *err)
{
    struct rs_buf raw;
    size_t        before = out->len;
    bool          ok;

    if (!read_file(path, KEYFILE_MAX, &raw, err))
    {
        return false;
    }
    /* Binary starts with a packet, whose first byte has its top bit set;
     * anything else is armored, or not a key. */
    if (raw.len > 0 && (raw.data[0] & 0x80) != 0)
    {
        rs_buf_add(out, raw.data, raw.len);
        ok = true;
    } else
    {
        ok = rs_pgp_dearmor(raw.data, raw.len, out);
    }
    if (!ok || out->len == before)
    {
        rs_buf_addf(err, "%s: not an OpenPGP key (gpg --export writes one)", path);
        ok = false;
    }
    rs_buf_free(&raw);
    return ok;
}

bool rs_pgp_keyring(const char *path, const char *dest, struct rs_buf *err)
{
    struct rs_buf bin;
    bool          ok;

    rs_buf_init(&bin);
    ok = rs_pgp_key_bytes(path, &bin, err) && write_new(dest, bin.data, bin.len, err);
    rs_buf_free(&bin);
    return ok;
}

/* Runs gpg in `home` with the arguments after the common ones; false, with
 * what gpg said, unless it exits 0. */
static bool gpg_in(const char *home, const char *const *args, size_t n, struct rs_buf *err)
{
    char        **argv = rs_xcalloc(8 + n, sizeof(*argv));
    struct rs_buf out;
    struct rs_buf errtext;
    size_t        a = 0;
    size_t        i;
    int           code = 0;
    bool          ok;

    argv[a++] = rs_xstrdup("gpg");
    argv[a++] = rs_xstrdup("--homedir");
    argv[a++] = rs_xstrdup(home);
    argv[a++] = rs_xstrdup("--batch");
    argv[a++] = rs_xstrdup("--quiet");
    argv[a++] = rs_xstrdup("--no-options");
    for (i = 0; i < n; i++)
    {
        argv[a++] = rs_xstrdup(args[i]);
    }
    argv[a] = NULL;
    rs_buf_init(&out);
    rs_buf_init(&errtext);
    ok = rs_run(RS_PROG_GPG, argv, &out, &errtext, &code, err);
    if (ok && code != 0)
    {
        size_t len = errtext.len;

        while (len > 0 && errtext.data[len - 1] == '\n')
        {
            len--;
        }
        rs_buf_addf(err, "gpg %s failed: %.*s", args[0], (int)len, errtext.data ? errtext.data : "");
        ok = false;
    }
    rs_buf_free(&out);
    rs_buf_free(&errtext);
    for (i = 0; i < a; i++)
    {
        free(argv[i]);
    }
    free(argv);
    return ok;
}

bool rs_pgp_sign(const char *keyfile, const char *data, struct rs_buf *sig,
                 struct rs_pgp_signer *signer, struct rs_buf *err)
{
    char         *home = rs_pgp_home(err);
    char         *sigfile;
    char         *pubfile;
    struct rs_buf status;
    struct rs_buf why;
    bool          ok;

    memset(signer, 0, sizeof(*signer));
    if (!home)
    {
        return false;
    }
    sigfile = rs_xasprintf("%s/sig", home);
    pubfile = rs_xasprintf("%s/pub.gpg", home);
    {
        const char *import[] = { "--import", keyfile };
        const char *sign[] = { "--detach-sign", "--output", sigfile, data };
        const char *export[] = { "--output", pubfile, "--export" };

        ok = gpg_in(home, import, 2, err) && gpg_in(home, sign, 4, err) &&
             gpg_in(home, export, 3, err);
    }
    rs_buf_init(&status);
    rs_buf_init(&why);
    if (ok)
    {
        /* Checked, as anyone checking it later will check it. */
        const char *ring[] = { pubfile };

        ok = rs_pgp_gpgv(home, ring, 1, sigfile, data, &status, err);
        if (ok && !rs_pgp_verdict(status.data ? status.data : "", signer, &why))
        {
            rs_buf_addf(err, "the signature just made does not check: %s", why.data);
            ok = false;
        }
    }
    if (ok)
    {
        struct rs_buf bytes;

        ok = read_file(sigfile, KEYFILE_MAX, &bytes, err);
        if (ok)
        {
            rs_buf_add(sig, bytes.data, bytes.len);
            rs_buf_free(&bytes);
        }
    }
    rs_buf_free(&status);
    rs_buf_free(&why);
    /* The agent gpg started for the throwaway home goes with it. */
    if (rs_program_path(RS_PROG_GPGCONF))
    {
        char          a0[] = "gpgconf";
        char          a1[] = "--homedir";
        char          a3[] = "--kill";
        char          a4[] = "gpg-agent";
        char         *argv[6];
        int           code;
        struct rs_buf ignored;

        argv[0] = a0;
        argv[1] = a1;
        argv[2] = home;
        argv[3] = a3;
        argv[4] = a4;
        argv[5] = NULL;
        rs_buf_init(&ignored);
        (void)rs_run(RS_PROG_GPGCONF, argv, NULL, NULL, &code, &ignored);
        rs_buf_free(&ignored);
    }
    free(sigfile);
    free(pubfile);
    rs_pgp_home_remove(home);
    return ok;
}
