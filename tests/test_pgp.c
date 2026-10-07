/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <sys/stat.h>
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
    char                  *tree = rs_xasprintf("%s/tree", dir);
    char                  *old_home = getenv("GNUPGHOME") ? rs_xstrdup(getenv("GNUPGHOME")) : NULL;
    const char            *keys[2];
    struct rs_image_writer iw;
    struct rs_index        ix;
    struct rs_index        back;
    struct rs_buf          err;
    char                  *cmd;

    detect_cases();
    failure_cases(dir);

    if (!rs_program_path(RS_PROG_GPG) || access("/usr/bin/gpgconf", X_OK) != 0)
    {
        (void)printf("  (image encryption tests skipped: they need gpg)\n");
        goto done;
    }

    TEST_CASE("pgp: a key to encrypt to");
    (void)mkdir(home, 0700);
    (void)mkdir(empty, 0700);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --pinentry-mode loopback --passphrase '' "
                       "--quick-gen-key 'restate test <test@example.invalid>' default default never",
                       home);
    CHECK(quiet_system(cmd) == 0);
    free(cmd);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --export > '%s' 2>/dev/null", home, pub);
    CHECK(system(cmd) == 0);
    free(cmd);
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
                                  "head -c 2 restate/files.tar.gz.gpg | od -An -tx1 | "
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
    free(tree);
    free(dir);
}
