/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "packages.h"
#include "pgp.h"
#include "run.h"
#include "sources.h"
#include "test.h"

static int quiet(const char *cmd)
{
    char *full = rs_xasprintf("( %s ) > /dev/null 2>&1", cmd);
    int   rc = system(full);

    free(full);
    return rc;
}

static void mkdirs(const char *base, const char *rel)
{
    char *path = rs_xasprintf("%s/%s", base, rel);
    char *p;

    for (p = path + strlen(base) + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            (void)mkdir(path, 0755);
            *p = '/';
        }
    }
    (void)mkdir(path, 0755);
    free(path);
}

/* The problem recorded for the source in `file`, or "ok". */
static const char *problem_of(const struct rs_jval *packages, const char *file)
{
    const struct rs_jval *apt = rs_jobject_get(packages, "apt");
    const struct rs_jval *sources = apt ? rs_jobject_get(apt, "sources") : NULL;
    size_t                i;

    for (i = 0; sources && i < sources->n; i++)
    {
        const char *f = rs_jobject_str(&sources->items[i], "file");

        if (f && strcmp(f, file) == 0)
        {
            const char *p = rs_jobject_str(&sources->items[i], "problem");

            return p ? p : "ok";
        }
    }
    return "(no such source)";
}

static void pieces(void)
{
    struct rs_buf        out;
    struct rs_buf        why;
    struct rs_pgp_signer s;
    int64_t              when = 0;

    TEST_CASE("pgp: armor taken off, every block, and only real armor");
    rs_buf_init(&out);
    CHECK(rs_pgp_dearmor("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: x\nComment: y\n\n"
                         "AAEC\nAw==\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n"
                         "junk\n-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nBA==\r\n"
                         "-----END PGP PUBLIC KEY BLOCK-----\r\n",
                         strlen("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: x\nComment: y\n\n"
                                "AAEC\nAw==\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n"
                                "junk\n-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nBA==\r\n"
                                "-----END PGP PUBLIC KEY BLOCK-----\r\n"),
                         &out));
    CHECK_INT(out.len, 5);
    CHECK(out.len == 5 && memcmp(out.data, "\0\1\2\3\4", 5) == 0);
    rs_buf_reset(&out);
    /* No blank line after the header: the base64 starts at once. */
    {
        const char *text = "-----BEGIN PGP SIGNATURE-----\nAAEC\n-----END PGP SIGNATURE-----";

        CHECK(rs_pgp_dearmor(text, strlen(text), &out));
        CHECK_INT(out.len, 3);
    }
    rs_buf_reset(&out);
    {
        static const char *const bad[] = {
            "no armor here",
            "-----BEGIN PGP X-----\n\nAAEC\n",
            "-----BEGIN PGP X-----\n\n!!!!\n-----END PGP X-----\n",
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            CHECK(!rs_pgp_dearmor(bad[i], strlen(bad[i]), &out));
        }
    }
    rs_buf_free(&out);

    TEST_CASE("pgp: what gpgv's status lines say");
    rs_buf_init(&why);
    CHECK(rs_pgp_verdict("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG FC9CA96ACA026560 HashiCorp <x@y>\n"
                         "[GNUPG:] VALIDSIG D55C0D1AC78A8D8126CB631CFC9CA96ACA026560 2026-10-08 "
                         "1791430188 0 4 0 1 8 01 D55C0D1AC78A8D8126CB631CFC9CA96ACA026560\n",
                         &s, &why));
    CHECK_STR(s.fpr, "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560");
    CHECK_STR(s.who, "HashiCorp <x@y>");
    CHECK_STR(s.when, "2026-10-08");
    CHECK(rs_pgp_verdict("[GNUPG:] GOODSIG X y\n[GNUPG:] VALIDSIG "
                         "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560 2026-10-08\n",
                         &s, &why));
    CHECK_STR(s.fpr, "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560");
    CHECK(!rs_pgp_verdict("[GNUPG:] GOODSIG X y\n[GNUPG:] VALIDSIG nothing\n", &s, &why));
    CHECK_STR(s.fpr, "");
    CHECK_STR(why.data, "a signature gpgv did not describe");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] GOODSIG X y\n", &s, &why));
    CHECK_STR(why.data, "a signature gpgv did not describe");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] ERRSIG 0FFAF36C03EB18BD 1 10 01 1783456206 9 x\n"
                          "[GNUPG:] NO_PUBKEY 0FFAF36C03EB18BD\n", &s, &why));
    CHECK_STR(why.data, "signed by a key that is not given (ID 0FFAF36C03EB18BD)");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] EXPKEYSIG 1 a\n[GNUPG:] VALIDSIG x\n", &s, &why));
    CHECK_STR(why.data, "signed by a key that has expired");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] REVKEYSIG 1 a\n", &s, &why));
    CHECK_STR(why.data, "signed by a key that has been revoked");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] BADSIG 1 a\n", &s, &why));
    CHECK_STR(why.data, "a bad signature");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] EXPSIG 1 a\n", &s, &why));
    CHECK_STR(why.data, "a signature that has expired");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("[GNUPG:] ERRSIG 1\n", &s, &why));
    CHECK_STR(why.data, "a signature that could not be checked");
    rs_buf_reset(&why);
    CHECK(!rs_pgp_verdict("", &s, &why));
    CHECK_STR(why.data, "not signed");
    CHECK_STR(s.fpr, "");
    rs_buf_free(&why);

    TEST_CASE("sources: Valid-Until, as apt writes it");
    CHECK(rs_sources_valid_until("Origin: x\nValid-Until: Sat, 17 Oct 2026 08:12:29 UTC\n", &when));
    CHECK_INT(when, 1792224749);
    CHECK(rs_sources_valid_until("Valid-Until: 1 Jan 1970 00:00:00 GMT\n", &when));
    CHECK_INT(when, 0);
    CHECK(rs_sources_valid_until("Valid-Until: Thu, 29 Feb 2024 23:59:60 +0000", &when));
    CHECK(!rs_sources_valid_until("Origin: x\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: Sat, 17 Oct 2026 08:12:29 EST\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: Sat, 17 Foo 2026 08:12:29 UTC\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: Sat, 32 Oct 2026 08:12:29 UTC\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: Sat, 17 Oct 1969 08:12:29 UTC\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: 17 Oct 2026 8:2\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: Sat, 17 Oct 2026 24:00:00 UTC\n", &when));
    CHECK(!rs_sources_valid_until("Valid-Until: \n", &when));
}

/* A Release, signed inline as InRelease by `who`, into the tree's lists. */
static void signed_release(const char *home, const char *lists, const char *name, const char *who,
                           const char *extra, const char *when)
{
    char *release = rs_xasprintf("%s/%sRelease.txt", lists, name);
    char *text = rs_xasprintf("Origin: test\nSuite: stable\n%sSHA256:\n", extra ? extra : "");
    char *cmd;
    FILE *fp = fopen(release, "w");

    if (fp)
    {
        (void)fputs(text, fp);
        (void)fclose(fp);
    }
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --yes %s%s%s -u '%s' --clearsign "
                       "-o '%s/%sInRelease' '%s'",
                       home, when ? "--faked-system-time '" : "", when ? when : "",
                       when ? "!'" : "", who, lists, name, release);
    CHECK(quiet(cmd) == 0);
    (void)unlink(release);
    free(cmd);
    free(text);
    free(release);
}

void test_sources(void)
{
    char          *dir = rs_test_tmpdir();
    char          *home = rs_xasprintf("%s/gnupg", dir);
    char          *root = rs_xasprintf("%s/root", dir);
    char          *lists = rs_xasprintf("%s/root/var/lib/apt/lists", dir);
    struct rs_jval p;
    bool           checked = false;
    size_t         n;

    pieces();

    if ((access("/usr/bin/gpg", X_OK) != 0 && access("/usr/local/bin/gpg", X_OK) != 0) ||
        !rs_program_path(RS_PROG_GPGV))
    {
        (void)printf("  (apt source checks skipped: they need gpg and gpgv)\n");
        rs_test_rmtree(dir);
        free(home);
        free(root);
        free(lists);
        free(dir);
        return;
    }

    TEST_CASE("sources: keys and signed indexes for the tests");
    (void)mkdir(home, 0700);
    mkdirs(dir, "root/var/lib/apt/lists");
    mkdirs(dir, "root/var/lib/dpkg");
    mkdirs(dir, "root/etc/apt/sources.list.d");
    mkdirs(dir, "root/etc/apt/trusted.gpg.d");
    mkdirs(dir, "root/usr/share/keyrings");
    rs_test_write(root, "var/lib/dpkg/status",
                  "Package: hello\nStatus: install ok installed\nArchitecture: amd64\n"
                  "Version: 1\n", 0644);
    {
        char *cmd = rs_xasprintf(
            "export GNUPGHOME='%s'; "
            "gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "
            "a@example.invalid ed25519 sign never && "
            "gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "
            "b@example.invalid ed25519 sign never && "
            "gpg --batch --pinentry-mode loopback --passphrase '' "
            "--faked-system-time '20200101T000000!' --quick-gen-key "
            "c@example.invalid ed25519 sign 1d && "
            "gpg --batch --export a@example.invalid > '%s/usr/share/keyrings/a.gpg' && "
            "gpg --batch --armor --export a@example.invalid > '%s/usr/share/keyrings/a.asc' && "
            "gpg --batch --export b@example.invalid > '%s/usr/share/keyrings/b.gpg' && "
            "gpg --batch --export c@example.invalid > '%s/usr/share/keyrings/c.gpg' && "
            "gpg --batch --export a@example.invalid > '%s/etc/apt/trusted.gpg.d/a.gpg'",
            home, root, root, root, root, root);

        CHECK(quiet(cmd) == 0);
        free(cmd);
    }
    signed_release(home, lists, "good.example_deb_dists_stable_", "a@example.invalid", NULL,
                   NULL);
    signed_release(home, lists, "wrong.example_deb_dists_stable_", "a@example.invalid", NULL,
                   NULL);
    signed_release(home, lists, "nokey.example_deb_dists_stable_", "a@example.invalid", NULL,
                   NULL);
    signed_release(home, lists, "armored.example_deb_dists_stable_", "a@example.invalid", NULL,
                   NULL);
    signed_release(home, lists, "trusted.example_deb_dists_stable_", "a@example.invalid", NULL,
                   NULL);
    signed_release(home, lists, "flat.example_repo_._", "a@example.invalid", NULL, NULL);
    signed_release(home, lists, "stale.example_deb_dists_stable_", "a@example.invalid",
                   "Valid-Until: Thu, 01 Jan 2026 00:00:00 UTC\n", NULL);
    signed_release(home, lists, "fresh.example_deb_dists_stable_", "a@example.invalid",
                   "Valid-Until: Fri, 01 Jan 2100 00:00:00 UTC\n", NULL);
    signed_release(home, lists, "old.example_deb_dists_stable_", "c@example.invalid", NULL,
                   "20200101T120000");
    /* A Release with its signature beside it, as older repositories have. */
    {
        char *cmd = rs_xasprintf("cd '%s' && printf 'Origin: legacy\\n' > "
                                 "legacy.example_deb_dists_stable_Release && "
                                 "GNUPGHOME='%s' gpg --batch --yes -u a@example.invalid "
                                 "--detach-sign -o legacy.example_deb_dists_stable_Release.gpg "
                                 "legacy.example_deb_dists_stable_Release",
                                 lists, home);

        CHECK(quiet(cmd) == 0);
        free(cmd);
    }
    rs_test_write(root, "etc/apt/sources.list.d/test.sources",
                  "Types: deb\nURIs: https://good.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/a.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/wrong.sources",
                  "Types: deb\nURIs: https://wrong.example/deb/\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/b.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/nokey.sources",
                  "Types: deb\nURIs: https://nokey.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/gone.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/armored.sources",
                  "Types: deb\nURIs: https://armored.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/a.asc\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/trusted.list",
                  "deb https://trusted.example/deb stable main\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/flat.list",
                  "deb [signed-by=/usr/share/keyrings/a.gpg] https://flat.example/repo ./\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/stale.sources",
                  "Types: deb\nURIs: https://stale.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/a.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/fresh.sources",
                  "Types: deb\nURIs: https://fresh.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/a.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/old.sources",
                  "Types: deb\nURIs: https://old.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/c.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/legacy.sources",
                  "Types: deb\nURIs: https://legacy.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/a.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/never.sources",
                  "Types: deb\nURIs: https://never.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By: /usr/share/keyrings/a.gpg\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/off.sources",
                  "Types: deb\nURIs: https://off.example/deb\nSuites: stable\n"
                  "Components: main\nEnabled: no\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/src.sources",
                  "Types: deb-src\nURIs: https://src.example/deb\nSuites: stable\n"
                  "Components: main\n", 0644);
    rs_test_write(root, "etc/apt/sources.list.d/inline.sources",
                  "Types: deb\nURIs: https://inline.example/deb\nSuites: stable\n"
                  "Components: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n "
                  "AAEC\n -----END PGP PUBLIC KEY BLOCK-----\n", 0644);

    TEST_CASE("sources: each one apt cannot use, and why");
    memset(&p, 0, sizeof(p));
    rs_jval_set_object(&p);
    rs_packages_describe(root, &p);
    n = rs_sources_check(root, &p, (int64_t)time(NULL), &checked);
    CHECK(checked);
    CHECK_INT(n, 5);
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/test.sources"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/armored.sources"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/trusted.list"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/flat.list"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/fresh.sources"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/legacy.sources"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/off.sources"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/src.sources"), "ok");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/inline.sources"), "ok");
    CHECK_CONTAINS(problem_of(&p, "/etc/apt/sources.list.d/wrong.sources"),
                   "https://wrong.example/deb/ stable: signed by a key that is not given (ID ");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/nokey.sources"),
              "https://nokey.example/deb stable: its key, /usr/share/keyrings/gone.gpg, is not "
              "there");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/stale.sources"),
              "https://stale.example/deb stable: its index expired on 2026-01-01 and has not "
              "been updated since");
    CHECK_STR(problem_of(&p, "/etc/apt/sources.list.d/old.sources"),
              "https://old.example/deb stable: signed by a key that has expired");
    CHECK_CONTAINS(problem_of(&p, "/etc/apt/sources.list.d/never.sources"),
                   "apt has no index of it");
    rs_jval_free(&p);

    TEST_CASE("sources: nothing to check without apt, or without gpgv");
    {
        static const char *const none[] = { "/nonexistent/gpgv" };
        struct rs_jval           empty;

        memset(&empty, 0, sizeof(empty));
        rs_jval_set_object(&empty);
        CHECK_INT(rs_sources_check(root, &empty, 0, &checked), 0);
        CHECK(!checked);
        rs_jval_free(&empty);
        memset(&p, 0, sizeof(p));
        rs_jval_set_object(&p);
        rs_packages_describe(root, &p);
        rs_program_set_paths(RS_PROG_GPGV, none, 1);
        CHECK_INT(rs_sources_check(root, &p, (int64_t)time(NULL), &checked), 0);
        CHECK(!checked);
        rs_program_set_paths(RS_PROG_GPGV, NULL, 0);
        rs_jval_free(&p);
    }

    {
        char *cmd = rs_xasprintf("GNUPGHOME='%s' gpgconf --kill gpg-agent", home);

        (void)quiet(cmd);
        free(cmd);
    }
    rs_test_rmtree(dir);
    free(home);
    free(root);
    free(lists);
    free(dir);
}
