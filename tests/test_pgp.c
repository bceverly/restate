/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cmd.h"
#include "image.h"
#include "index.h"
#include "pgp.h"
#include "run.h"
#include "test.h"

static int quiet_system(const char *cmd)
{
    char *full = rs_xasprintf("%s > /dev/null 2>&1", cmd);
    int   rc = system(full);

    free(full);
    return rc;
}

static int run(const void *arg)
{
    return rs_cmd_run(arg);
}

/* How many GnuPG homes for a secret key there are, this user's. */
static size_t secret_homes(void)
{
    static const char *const dirs[] = { "/tmp", "/dev/shm", "/run" };
    size_t                   n = 0;
    size_t                   i;

    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
    {
        DIR           *d = opendir(dirs[i]);
        struct dirent *e;

        while (d && (e = readdir(d)) != NULL)
        {
            char       *path = rs_xasprintf("%s/%s", dirs[i], e->d_name);
            struct stat st;

            if (strncmp(e->d_name, "restate-gpg.", 12) == 0 && lstat(path, &st) == 0 &&
                st.st_uid == geteuid())
            {
                n++;
            }
            free(path);
        }
        if (d)
        {
            (void)closedir(d);
        }
    }
    return n;
}

/* Whether this gpg can decrypt with a secret key exported from `home` once it
 * is imported somewhere else, as --decrypt-with does: GnuPG 2.5 with
 * libgcrypt 1.12 cannot, with a cv25519 key, and libgcrypt 1.12.0 cannot
 * reliably (GnuPG T8094) -- as a service runs it, and depending on the very
 * path of the GnuPG home. So asked of restate itself, which imports into a
 * home of its own and says, before it starts, when it cannot. */
static bool gpg_reimports;

static bool reimports(const char *home, const char *dir)
{
    char         *probe = rs_xasprintf("%s/probe.sec", dir);
    char         *cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --export-secret-keys > '%s' "
                                     "2>/dev/null", home, probe);
    const char   *keys[1];
    struct rs_buf err;
    bool          ok;

    rs_buf_init(&err);
    keys[0] = probe;
    ok = system(cmd) == 0 && rs_pgp_use_secret_key(keys, 1, &err);
    rs_pgp_forget_secret_key();
    rs_buf_free(&err);
    (void)unlink(probe);
    free(cmd);
    free(probe);
    return ok;
}

/* The secret key in `sec` given with --decrypt-with: used, said, and gone
 * after, and gone too when a signal ends restate while it is there. */
static void secret_key_cases(const char *sec, const char *pub)
{
    struct rs_buf err;
    size_t        before = secret_homes();
    pid_t         pid;
    int           st = 0;

    rs_buf_init(&err);
    if (!gpg_reimports)
    {
        TEST_CASE("pgp: a secret key this gpg cannot use once imported, refused, saying so");
        CHECK(!rs_pgp_use_secret_key(&sec, 1, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "once it is imported");
        CHECK_INT(secret_homes(), before);
        rs_buf_free(&err);
        (void)printf("  (secret key file tests skipped: this gpg cannot use one it imports)\n");
        return;
    }
    TEST_CASE("pgp: a secret key given as a file, in a home of its own");
    CHECK_STR(rs_pgp_key_place(), "this user's GnuPG home");
    CHECK(rs_pgp_use_secret_key(&sec, 1, &err));
    CHECK_STR(rs_pgp_key_place(), "the key files --decrypt-with gives");
    CHECK_INT(secret_homes(), before + 1);
    rs_pgp_forget_secret_key();
    rs_pgp_forget_secret_key();
    CHECK_STR(rs_pgp_key_place(), "this user's GnuPG home");
    CHECK_INT(secret_homes(), before);

    TEST_CASE("pgp: a file with no secret key in it, or none at all");
    CHECK(!rs_pgp_use_secret_key(&pub, 1, &err));
    CHECK_CONTAINS(err.data, "no secret key in it");
    rs_buf_reset(&err);
    {
        const char *both[] = { sec, "/nonexistent/key.sec" };

        CHECK(!rs_pgp_use_secret_key(both, 2, &err));
        CHECK_CONTAINS(err.data, "gpg --with-colons failed");
    }
    CHECK_INT(secret_homes(), before);
    {
        static const char *const missing[] = { "/nonexistent/gpg" };

        rs_buf_reset(&err);
        rs_program_set_paths(RS_PROG_GPG, missing, 1);
        CHECK(!rs_pgp_use_secret_key(&sec, 1, &err));
        CHECK_CONTAINS(err.data, "decrypting needs gpg");
        rs_program_set_paths(RS_PROG_GPG, NULL, 0);
    }
    rs_buf_free(&err);

    TEST_CASE("pgp: a signal that ends restate takes the secret key's home with it");
    pid = fork();
    if (pid == 0)
    {
        struct rs_buf why;

        rs_buf_init(&why);
        if (rs_pgp_use_secret_key(&sec, 1, &why))
        {
            (void)raise(SIGTERM);
        }
        _exit(3);
    }
    CHECK(pid > 0 && waitpid(pid, &st, 0) == pid);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
    CHECK_INT(secret_homes(), before);
}

static void detect_cases(void)
{
    static const unsigned char gz[] = { 0x1f, 0x8b, 0x08, 0x00 };
    static const unsigned char old_pkesk[] = { 0x84, 0x5e, 0x03 };
    static const unsigned char old_skesk[] = { 0x8c, 0x0d, 0x04 };
    static const unsigned char new_pkesk[] = { 0xc1, 0x5e, 0x03 };
    static const unsigned char new_skesk[] = { 0xc3, 0x0d, 0x04 };
    static const unsigned char signature[] = { 0x89, 0x01, 0x33 };
    static const char          armor[] = "-----BEGIN PGP MESSAGE-----\n\nhQ==\n";

    TEST_CASE("pgp: what an encrypted message looks like");
    CHECK(rs_pgp_detect(old_pkesk, sizeof(old_pkesk)));
    CHECK(rs_pgp_detect(old_skesk, sizeof(old_skesk)));
    CHECK(rs_pgp_detect(new_pkesk, sizeof(new_pkesk)));
    CHECK(rs_pgp_detect(new_skesk, sizeof(new_skesk)));
    CHECK(rs_pgp_detect((const unsigned char *)armor, strlen(armor)));
    CHECK(!rs_pgp_detect(gz, sizeof(gz)));
    CHECK(!rs_pgp_detect(signature, sizeof(signature)));
    CHECK(!rs_pgp_detect(old_pkesk, 1));
    CHECK(!rs_pgp_detect((const unsigned char *)"{\"format\"", 9));
}

/* The key ids at the head of an encrypted message, from packets made by hand. */
static void recipient_cases(void)
{
    /* New format: a v3 PKESK to 0102030405060708, then the same again, then a
     * SKESK, then one to 1112131415161718 -- and then the message. */
    static const unsigned char v3[] = {
        0xc1, 0x0a, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x12,
        0xc1, 0x0a, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x12,
        0xc3, 0x02, 0x04, 0x09,
        0x84, 0x0a, 0x03, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x01,
        0xd2, 0x01, 0x01
    };
    /* v6 PKESKs (RFC 9580): to a v4 key, whose id is its fingerprint's last 8
     * bytes; to a v6 key, its first 8; and to no one in particular. */
    static const unsigned char v6[] = {
        0xc1, 0x18, 0x06, 0x15, 0x04,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0x19,
        0xc1, 0x24, 0x06, 0x21, 0x06,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
        0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
        0xdc, 0xdd, 0xde, 0xdf, 0x19,
        0xc1, 0x03, 0x06, 0x00, 0x19
    };
    /* Old-format two- and four-byte lengths, and a two-byte new-format one. */
    static const unsigned char lengths[] = {
        0x85, 0x00, 0x0a, 0x03, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x01,
        0x86, 0x00, 0x00, 0x00, 0x0a, 0x03, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x01
    };
    static const unsigned char partial[] = { 0xc1, 0xe0, 0x03, 0x01 };
    static const unsigned char indeterminate[] = { 0x87, 0x03, 0x01 };
    static const unsigned char signature[] = { 0x89, 0x01, 0x33 };
    char                       ids[4][17];

    TEST_CASE("pgp: the keys a message is encrypted to, read in the clear");
    CHECK_INT(rs_pgp_recipients(v3, sizeof(v3), ids, 4), 2);
    CHECK_STR(ids[0], "0102030405060708");
    CHECK_STR(ids[1], "1112131415161718");
    CHECK_INT(rs_pgp_recipients(v6, sizeof(v6), ids, 4), 3);
    CHECK_STR(ids[0], "B0B1B2B3B4B5B6B7");
    CHECK_STR(ids[1], "C0C1C2C3C4C5C6C7");
    CHECK_STR(ids[2], "0000000000000000");
    CHECK_INT(rs_pgp_recipients(lengths, sizeof(lengths), ids, 4), 2);
    CHECK_STR(ids[0], "2122232425262728");
    CHECK_STR(ids[1], "3132333435363738");

    TEST_CASE("pgp: no more keys than there is room for, or than the bytes hold");
    CHECK_INT(rs_pgp_recipients(v3, sizeof(v3), ids, 1), 1);
    CHECK_INT(rs_pgp_recipients(v3, 11, ids, 4), 0);
    CHECK_INT(rs_pgp_recipients(v3, 12, ids, 4), 1);
    CHECK_INT(rs_pgp_recipients(lengths, 2, ids, 4), 0);
    CHECK_INT(rs_pgp_recipients(partial, sizeof(partial), ids, 4), 0);
    CHECK_INT(rs_pgp_recipients(indeterminate, sizeof(indeterminate), ids, 4), 0);
    CHECK_INT(rs_pgp_recipients(signature, sizeof(signature), ids, 4), 0);
    CHECK_INT(rs_pgp_recipients((const unsigned char *)"plain", 5, ids, 4), 0);
    CHECK_INT(rs_pgp_recipients(v6 + 25, 5, ids, 4), 0);
}

static void failure_cases(const char *dir)
{
    static const char *const missing[] = { "/nonexistent/gpg" };
    const char              *keys[1] = { NULL };
    struct rs_pgp            pg;
    struct rs_buf            err;
    char                    *nokey = rs_xasprintf("%s/no-such-key.gpg", dir);

    rs_buf_init(&err);
    TEST_CASE("pgp: what stops an encryption before it starts");
    CHECK(!rs_pgp_encrypt(keys, 0, 1, &pg, &err));
    CHECK_CONTAINS(err.data, "at least one recipient");
    keys[0] = nokey;
    rs_buf_reset(&err);
    CHECK(!rs_pgp_encrypt(keys, 1, 1, &pg, &err));
    CHECK_CONTAINS(err.data, "no-such-key.gpg");
    rs_test_write(dir, "garbage.gpg", "not a key\n", 0644);
    free(nokey);
    nokey = rs_xasprintf("%s/garbage.gpg", dir);
    keys[0] = nokey;
    rs_program_set_paths(RS_PROG_GPG, missing, 1);
    rs_buf_reset(&err);
    CHECK(!rs_pgp_encrypt(keys, 1, 1, &pg, &err));
    CHECK_CONTAINS(err.data, "could not run gpg");
    rs_buf_reset(&err);
    CHECK(!rs_pgp_decrypt(0, &pg, &err));
    CHECK_CONTAINS(err.data, "could not run gpg");
    rs_program_set_paths(RS_PROG_GPG, NULL, 0);
    free(nokey);
    rs_buf_free(&err);
}

void test_pgp(void)
{
    char                  *dir = rs_test_tmpdir();
    char                  *home = rs_xasprintf("%s/gnupg", dir);
    char                  *empty = rs_xasprintf("%s/empty", dir);
    char                  *pub = rs_xasprintf("%s/pub.gpg", dir);
    char                  *img = rs_xasprintf("%s/img.tgz.gpg", dir);
    char                  *sec = rs_xasprintf("%s/sec.gpg", dir);
    char                  *tree = rs_xasprintf("%s/tree", dir);
    char                  *old_home = getenv("GNUPGHOME") ? rs_xstrdup(getenv("GNUPGHOME")) : NULL;
    const char            *keys[2];
    struct rs_image_writer iw;
    struct rs_index        ix;
    struct rs_index        back;
    struct rs_buf          err;
    char                  *cmd;

    detect_cases();
    recipient_cases();
    failure_cases(dir);

    if (!rs_program_path(RS_PROG_GPG) || !rs_test_have_gpg())
    {
        (void)printf("  (image encryption tests skipped: they need gpg)\n");
        goto done;
    }

    TEST_CASE("pgp: a key to encrypt to");
    (void)mkdir(home, 0700);
    (void)mkdir(empty, 0700);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --pinentry-mode loopback --passphrase '' "
                       "--quick-gen-key 'restate test <test@example.invalid>' "
                       "default default never",
                       home);
    CHECK(quiet_system(cmd) == 0);
    free(cmd);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --export > '%s' 2>/dev/null", home, pub);
    CHECK(system(cmd) == 0);
    free(cmd);
    gpg_reimports = reimports(home, dir);
    (void)setenv("GNUPGHOME", home, 1);

    TEST_CASE("pgp: an encrypted image, written and read back");
    rs_buf_init(&err);
    rs_index_init(&ix);
    ix.root = rs_xstrdup("/");
    CHECK(rs_image_begin(&iw, img, &err));
    keys[0] = pub;
    keys[1] = pub;
    iw.recipients = keys;
    iw.nrecipients = 2;
    CHECK(rs_image_finish(&iw, &ix, &err));
    CHECK_STR(err.data ? err.data : "", "");
    {
        /* Each part encrypted on its own, and named so. */
        char *list = rs_xasprintf("tar -tf '%s' | tr '\\n' ' ' | grep -qx "
                                  "'restate/index.json.gz.gpg restate/kit.tar.gz.gpg "
                                  "restate/files.tar.gz.gpg '", img);
        char *head = rs_xasprintf("cd '%s' && tar -xf '%s' restate/files.tar.gz.gpg && "
                                  "dd if=restate/files.tar.gz.gpg bs=2 count=1 2> /dev/null | "
                                  "od -An -tx1 | "
                                  "grep -qv '1f 8b'", dir, img);

        CHECK(system(list) == 0);
        CHECK(system(head) == 0);
        free(list);
        free(head);
    }
    rs_index_init(&back);
    CHECK(rs_index_load(&back, img, &err));
    CHECK_STR(back.root, "/");
    rs_index_free(&back);

    TEST_CASE("pgp: without the secret key it cannot be read");
    (void)setenv("GNUPGHOME", empty, 1);
    rs_index_init(&back);
    rs_buf_reset(&err);
    CHECK(!rs_index_load(&back, img, &err));
    CHECK_CONTAINS(err.data, "could not decrypt it");
    rs_index_free(&back);
    (void)setenv("GNUPGHOME", home, 1);

    TEST_CASE("pgp: a key file gpg cannot use leaves no image behind");
    (void)unlink(img);
    keys[0] = rs_xasprintf("%s/garbage.gpg", dir);
    CHECK(rs_image_begin(&iw, img, &err));
    iw.recipients = keys;
    iw.nrecipients = 1;
    rs_buf_reset(&err);
    CHECK(!rs_image_finish(&iw, &ix, &err));
    CHECK_CONTAINS(err.data, "gpg failed");
    CHECK(access(img, F_OK) != 0);
    free((char *)keys[0]);

    TEST_CASE("pgp: capture --encrypt-to");
    {
        struct rs_options o;
        const char       *recips[1];
        char             *out = NULL;
        char             *errs = NULL;

        (void)mkdir(tree, 0755);
        rs_test_write(tree, "secret.key", "the key\n", 0600);
        memset(&o, 0, sizeof(o));
        o.command = CMD_CAPTURE;
        o.root = tree;
        o.output = img;
        o.no_default_rules = true;
        o.quiet = true;
        recips[0] = pub;
        o.recipients = recips;
        o.nrecipients = 1;
        CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
        free(out);
        free(errs);
        o.command = CMD_VERIFY;
        o.args = &img;
        o.nargs = 1;
        o.output = NULL;
        CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
        free(out);
        free(errs);

        /* Restored: the files part decrypted on its own, and only it. */
        {
            char       *into = rs_xasprintf("%s/restored", dir);
            char       *key = rs_xasprintf("%s/restored/secret.key", dir);
            const char *keyf[1];

            (void)mkdir(into, 0755);
            o.command = CMD_RESTORE;
            o.root = into;
            o.allow_unverified = true;
            CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
            CHECK(access(key, F_OK) == 0);
            free(out);
            free(errs);

            /* Without the secret key, nothing is put back. */
            (void)unlink(key);
            (void)setenv("GNUPGHOME", empty, 1);
            CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
            CHECK(access(key, F_OK) != 0);
            (void)setenv("GNUPGHOME", home, 1);
            free(out);
            free(errs);

            /* Or with the secret key given as a file, no GnuPG home holding it. */
            cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --export-secret-keys > '%s' "
                               "2>/dev/null", home, sec);
            CHECK(system(cmd) == 0);
            free(cmd);
            (void)setenv("GNUPGHOME", empty, 1);
            keyf[0] = sec;
            o.decrypt_with = keyf;
            o.ndecrypt_with = 1;
            if (gpg_reimports)
            {
                CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
                CHECK(access(key, F_OK) == 0);
            } else
            {
                CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
                CHECK_CONTAINS(errs, "once it is imported");
            }
            CHECK_STR(rs_pgp_key_place(), "this user's GnuPG home");
            free(out);
            free(errs);
            keyf[0] = pub;
            CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
            CHECK_CONTAINS(errs, "--decrypt-with: ");
            free(out);
            free(errs);
            o.decrypt_with = NULL;
            o.ndecrypt_with = 0;
            secret_key_cases(sec, pub);
            (void)setenv("GNUPGHOME", home, 1);
            o.root = tree;
            free(key);
            free(into);
        }

        o.command = CMD_CAPTURE;
        o.output = img;
        o.args = NULL;
        o.nargs = 0;
        recips[0] = "/nonexistent/key.gpg";
        CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
        CHECK_CONTAINS(errs, "--encrypt-to /nonexistent/key.gpg");
        free(out);
        free(errs);
        {
            static const char *const missing[] = { "/nonexistent/gpg" };

            recips[0] = pub;
            rs_program_set_paths(RS_PROG_GPG, missing, 1);
            CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
            CHECK_CONTAINS(errs, "--encrypt-to needs gpg");
            rs_program_set_paths(RS_PROG_GPG, NULL, 0);
            free(out);
            free(errs);
        }
    }

    cmd = rs_xasprintf("GNUPGHOME='%s' gpgconf --kill gpg-agent", home);
    (void)quiet_system(cmd);
    free(cmd);
    rs_index_free(&ix);
    rs_buf_free(&err);

done:
    if (old_home)
    {
        (void)setenv("GNUPGHOME", old_home, 1);
    } else
    {
        (void)unsetenv("GNUPGHOME");
    }
    rs_test_rmtree(dir);
    free(old_home);
    free(home);
    free(empty);
    free(pub);
    free(img);
    free(sec);
    free(tree);
    free(dir);
}
