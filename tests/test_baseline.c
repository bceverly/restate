/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "baseline.h"
#include "json.h"
#include "packages.h"
#include "run.h"
#include "sha256.h"
#include "sources.h"
#include "test.h"

static int quiet(const char *cmd)
{
    char *full = rs_xasprintf("(%s) > /dev/null 2>&1", cmd);
    int   rc = system(full);

    free(full);
    return rc;
}

static void entry_seen(void *ctx, const struct rs_baseline_entry *e)
{
    struct rs_buf *b = ctx;

    rs_buf_addf(b, "%s %s %s %s %" PRIu64 " %.8s\n", e->name, e->version, e->arch, e->filename,
                e->size, e->sha256);
}

static void pure(void)
{
    struct rs_buf b;
    char          sha[RS_SHA256_HEX_SIZE];
    uint64_t      size = 0;
    char         *uri;
    char         *suite;
    char         *comp;
    char         *name;

    TEST_CASE("baseline: a package's name in apt's cache");
    name = rs_baseline_deb_name("libc6", "2.43-2ubuntu2", "amd64");
    CHECK_STR(name, "libc6_2.43-2ubuntu2_amd64.deb");
    free(name);
    name = rs_baseline_deb_name("vim", "2:9.1-1", "all");
    CHECK_STR(name, "vim_2%3a9.1-1_all.deb");
    free(name);
    CHECK(rs_baseline_deb_name("../x", "1", "amd64") == NULL);
    CHECK(rs_baseline_deb_name("x", "1/2", "amd64") == NULL);
    CHECK(rs_baseline_deb_name("x", "1", "amd 64") == NULL);
    CHECK(rs_baseline_deb_name(NULL, "1", "amd64") == NULL);
#if defined(__APPLE__)
    CHECK_STR(rs_baseline_default_cache(), "/Library/Caches/restate/baseline");
#else
    CHECK_STR(rs_baseline_default_cache(), "/var/cache/restate/baseline");
#endif

    TEST_CASE("baseline: an origin, split");
    CHECK(rs_baseline_label("https://a.example/ubuntu/ resolute-updates/main", &uri, &suite,
                            &comp));
    CHECK_STR(uri, "https://a.example/ubuntu/");
    CHECK_STR(suite, "resolute-updates");
    CHECK_STR(comp, "main");
    free(uri);
    free(suite);
    free(comp);
    CHECK(rs_baseline_label("http://security.debian.org buster/updates/main", &uri, &suite,
                            &comp));
    CHECK_STR(suite, "buster/updates");
    CHECK_STR(comp, "main");
    free(uri);
    free(suite);
    free(comp);
    CHECK(rs_baseline_label("https://vendor.example/apt/ ./", &uri, &suite, &comp));
    CHECK_STR(suite, "./");
    CHECK_STR(comp, "");
    free(uri);
    free(suite);
    free(comp);
    CHECK(!rs_baseline_label("nospace", &uri, &suite, &comp));
    CHECK(!rs_baseline_label(" leading", &uri, &suite, &comp));
    CHECK(!rs_baseline_label("a b c", &uri, &suite, &comp));
    CHECK(!rs_baseline_label(NULL, &uri, &suite, &comp));

    TEST_CASE("baseline: the archives that have snapshots");
    rs_buf_init(&b);
    CHECK(rs_baseline_snapshot_uri("http://archive.ubuntu.com/ubuntu/", "20261010T000000Z", &b));
    CHECK_STR(b.data, "https://snapshot.ubuntu.com/ubuntu/20261010T000000Z/");
    CHECK(rs_baseline_snapshot_uri("http://gb.archive.ubuntu.com/ubuntu", "20261010T000000Z", &b));
    CHECK_STR(b.data, "https://snapshot.ubuntu.com/ubuntu/20261010T000000Z/");
    CHECK(rs_baseline_snapshot_uri("https://security.ubuntu.com/ubuntu", "20261010T000000Z", &b));
    CHECK(rs_baseline_snapshot_uri("http://ports.ubuntu.com/ubuntu-ports/", "20261010T000000Z",
                                   &b));
    CHECK_STR(b.data, "https://snapshot.ubuntu.com/ubuntu-ports/20261010T000000Z/");
    CHECK(rs_baseline_snapshot_uri("http://deb.debian.org/debian", "20261010T000000Z", &b));
    CHECK_STR(b.data, "https://snapshot.debian.org/archive/debian/20261010T000000Z/");
    CHECK(rs_baseline_snapshot_uri("http://security.debian.org/debian-security",
                                   "20261010T000000Z", &b));
    CHECK_STR(b.data, "https://snapshot.debian.org/archive/debian-security/20261010T000000Z/");
    CHECK(!rs_baseline_snapshot_uri("https://ppa.launchpadcontent.net/x/y/ubuntu/",
                                    "20261010T000000Z", &b));
    CHECK(!rs_baseline_snapshot_uri("https://archive.ubuntu.com.evil.example/ubuntu",
                                    "20261010T000000Z", &b));
    CHECK(!rs_baseline_snapshot_uri("https://snapshot.debian.org/debian", "20261010T000000Z",
                                    &b));
    CHECK(!rs_baseline_snapshot_uri("file:///srv/mirror", "20261010T000000Z", &b));
    CHECK(!rs_baseline_snapshot_uri("http://archive.ubuntu.com/ubuntu", "2026/../x", &b));
    CHECK(!rs_baseline_snapshot_uri("http://archive.ubuntu.com/elsewhere", "20261010T000000Z",
                                    &b));

    TEST_CASE("baseline: a Release file's entry for a list");
    {
        static const char release[] =
            "Origin: Ubuntu\n"
            "MD5Sum:\n"
            " d41d8cd98f00b204e9800998ecf8427e        10 main/binary-amd64/Packages.gz\n"
            "SHA256:\n"
            " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa      3911707 "
            "main/binary-amd64/Packages\n"
            " bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb       907381 "
            "main/binary-amd64/Packages.gz\r\n"
            " cccc 12 main/binary-i386/Packages.gz\n"
            " dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd x "
            "main/binary-arm64/Packages.gz\n"
            " eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 5 "
            "main/binary-riscv64/Packages.gz extra\n"
            "Acquire-By-Hash: yes\n";

        CHECK(rs_baseline_release_entry(release, "main/binary-amd64/Packages.gz", sha, &size));
        CHECK_STR(sha, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        CHECK_INT(size, 907381);
        CHECK(rs_baseline_release_entry(release, "main/binary-amd64/Packages", sha, &size));
        CHECK_INT(size, 3911707);
        CHECK(!rs_baseline_release_entry(release, "main/binary-i386/Packages.gz", sha, &size));
        CHECK(!rs_baseline_release_entry(release, "main/binary-arm64/Packages.gz", sha, &size));
        CHECK(!rs_baseline_release_entry(release, "main/binary-riscv64/Packages.gz", sha,
                                         &size));
        CHECK(!rs_baseline_release_entry(release, "main/binary-s390x/Packages.gz", sha, &size));
    }

    TEST_CASE("baseline: a Packages list");
    {
        static const char list[] =
            "Package: hello\n"
            "Version: 1.0\n"
            "Architecture: amd64\n"
            "Description: a greeting\n"
            " Filename: not/this.deb\n"
            "Filename: pool/h/hello_1.0_amd64.deb\n"
            "Size: 42\n"
            "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
            "\r\n"
            "Package: nosize\n"
            "Version: 1\n"
            "Architecture: all\n"
            "Filename: pool/n.deb\n"
            "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
            "\n"
            "Package: badsha\n"
            "Version: 1\n"
            "Architecture: all\n"
            "Filename: pool/b.deb\n"
            "Size: 1\n"
            "SHA256: XYZ\n"
            "\n"
            "Package: last\n"
            "Version: 2\n"
            "Architecture: all\n"
            "Filename: pool/l.deb\n"
            "Size: 7\n"
            "SHA256: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        rs_buf_reset(&b);
        rs_baseline_parse_packages(list, sizeof(list) - 1, entry_seen, &b);
        CHECK_STR(b.data, "hello 1.0 amd64 pool/h/hello_1.0_amd64.deb 42 01234567\n"
                          "last 2 all pool/l.deb 7 fedcba98\n");
        rs_buf_reset(&b);
        rs_baseline_parse_packages("", 0, entry_seen, &b);
        CHECK(b.len == 0);
    }

    TEST_CASE("baseline: apt's credentials, for curl, and only over https");
    {
        static const char sources[] =
            "{\"sources\": ["
            " {\"uris\": [\"https://esm.ubuntu.com/apps/ubuntu\"]},"
            " {\"uris\": [\"https://both.example\", \"http://both.example/x\"]},"
            " {\"uris\": [\"http://plain.example/debian\"]},"
            " {\"uris\": [\"https://port.example:8443/apt/\"]},"
            " {\"uris\": 7}, {\"uris\": [7]}]}";
        static const char auth[] =
            "# written by ubuntu-pro-client: machine evil.example login x password y\n"
            "machine esm.ubuntu.com/apps/ubuntu/ login bearer password s3cret  # esm-apps\n"
            "machine https://port.example/apt login u\n password p\n"
            "machine both.example login u password p\n"
            "machine plain.example login u password p\n"
            "machine http://esm.ubuntu.com login u password leak\n"
            "machine nowhere.example login u password p\n"
            "machine esm.ubuntu.com login\n"
            "machine bad\"host login u password p\n"
            "default login x password y\n"
            "password";
        struct rs_jval        apt;
        struct rs_json_parser jp;
        struct rs_buf         jerr;

        memset(&apt, 0, sizeof(apt));
        rs_buf_init(&jerr);
        rs_json_init(&jp, sources, sizeof(sources) - 1, &jerr);
        CHECK(rs_json_value(&jp, &apt));
        rs_buf_free(&jerr);
        rs_buf_reset(&b);
        CHECK(rs_baseline_netrc(auth, &apt, &b));
        CHECK_STR(b.data, "machine esm.ubuntu.com login bearer password s3cret\n"
                          "machine port.example login u password p\n");
        rs_buf_reset(&b);
        CHECK(!rs_baseline_netrc("", &apt, &b));
        CHECK(!rs_baseline_netrc(NULL, &apt, &b));
        CHECK(!rs_baseline_netrc(auth, NULL, &b));
        rs_jval_free(&apt);
    }

    TEST_CASE("sources: the text an InRelease file's signature covers");
    {
        static const char good[] =
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            "Hash: SHA512\n"
            "\n"
            "Origin: test\n"
            "- -----not armor\n"
            "SHA256:\n"
            " aa 1 x\n"
            "-----BEGIN PGP SIGNATURE-----\n"
            "\n"
            "abc\n"
            "-----END PGP SIGNATURE-----\n"
            "\n";

        CHECK(rs_sources_signed_part(good, sizeof(good) - 1, &b));
        CHECK_STR(b.data, "Origin: test\n-----not armor\nSHA256:\n aa 1 x");
        /* Text before the armor, after the signature, or within it. */
        {
            static const char *const bad[] = {
                "Origin: evil\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nx\n"
                "-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nx\n"
                "-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\nSHA256:\n evil\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nx\n"
                "-----BEGIN PGP SIGNED MESSAGE-----\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n-x\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nNotHash: x\n\nx\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nx\n"
                "-----BEGIN PGP SIGNATURE-----\nabc\n-----BEGIN PGP OTHER-----\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nx\n"
                "-----BEGIN PGP SIGNATURE-----\nabc\n",
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nno signature\n",
                "",
            };
            size_t i;

            for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
            {
                CHECK(!rs_sources_signed_part(bad[i], strlen(bad[i]), &b));
            }
        }
    }
    rs_buf_free(&b);
}

static char *sha_of(const char *data, size_t len)
{
    char hex[RS_SHA256_HEX_SIZE];

    rs_sha256_hex(data, len, hex);
    return rs_xstrdup(hex);
}

/* A repository in `dir`/repo, served as file://, signed by `who`. */
static void make_repo(const char *dir, const char *home, const char *who)
{
    static const char deb[] = "!<arch>\nhello, a .deb\n";
    char             *hello_sha = sha_of(deb, sizeof(deb) - 1);
    char             *list;
    char             *cmd;
    struct rs_buf     gz;
    char             *list_sha;
    char             *gz_sha;
    char             *release;
    char             *all;
    char             *all_sha;
    size_t            list_len;

    list = rs_xasprintf("Package: hello\nVersion: 1.0\nArchitecture: amd64\n"
                        "Filename: pool/main/h/hello_1.0_amd64.deb\nSize: %zu\nSHA256: %s\n\n"
                        "Package: tzdata\nVersion: 2026a\nArchitecture: all\n"
                        "Filename: ./pool/main/t/tzdata_2026a_all.deb\nSize: %zu\nSHA256: %s\n\n"
                        "Package: broken\nVersion: 1\nArchitecture: amd64\n"
                        "Filename: pool/main/b/broken_1_amd64.deb\nSize: 3\n"
                        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n"
                        "Package: sneaky\nVersion: 1\nArchitecture: amd64\n"
                        "Filename: ../../etc/passwd\nSize: 3\nSHA256: %s\n",
                        sizeof(deb) - 1, hello_sha, sizeof(deb) - 1, hello_sha, hello_sha);
    /* A package of Architecture: all listed apart, as Tailscale's are. */
    all = rs_xasprintf("Package: keyring\nVersion: 2\nArchitecture: all\n"
                       "Filename: pool/main/h/hello_1.0_amd64.deb\nSize: %zu\nSHA256: %s\n",
                       sizeof(deb) - 1, hello_sha);
    list_len = strlen(list);
    cmd = rs_xasprintf("mkdir -p '%s/repo/dists/stable/main/binary-all' '%s/repo/dists/stable/main/binary-amd64' "
                       "'%s/repo/pool/main/h' '%s/repo/pool/main/t' '%s/repo/pool/main/b'",
                       dir, dir, dir, dir, dir);
    CHECK(quiet(cmd) == 0);
    free(cmd);
    rs_test_write(dir, "repo/dists/stable/main/binary-all/Packages", all, 0644);
    rs_test_write(dir, "repo/pool/main/h/hello_1.0_amd64.deb", deb, 0644);
    rs_test_write(dir, "repo/pool/main/t/tzdata_2026a_all.deb", deb, 0644);
    rs_test_write(dir, "repo/pool/main/b/broken_1_amd64.deb", "bad", 0644);
    rs_test_write(dir, "repo/dists/stable/main/binary-amd64/Packages", list, 0644);
    cmd = rs_xasprintf("gzip -9n -c '%s/repo/dists/stable/main/binary-amd64/Packages' > "
                       "'%s/repo/dists/stable/main/binary-amd64/Packages.gz'", dir, dir);
    CHECK(quiet(cmd) == 0);
    free(cmd);
    rs_buf_init(&gz);
    {
        char  *path = rs_xasprintf("%s/repo/dists/stable/main/binary-amd64/Packages.gz", dir);
        FILE  *fp = fopen(path, "rb");
        char   chunk[4096];
        size_t n;

        while (fp && (n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
        {
            rs_buf_add(&gz, chunk, n);
        }
        if (fp)
        {
            (void)fclose(fp);
        }
        free(path);
    }
    list_sha = sha_of(list, list_len);
    gz_sha = sha_of(gz.data ? gz.data : "", gz.len);
    all_sha = sha_of(all, strlen(all));
    release = rs_xasprintf("Origin: test\nSuite: stable\nSHA256:\n %s %zu main/binary-amd64/Packages\n"
                           " %s %zu main/binary-amd64/Packages.gz\n"
                           " %s %zu main/binary-all/Packages\n",
                           list_sha, list_len, gz_sha, gz.len, all_sha, strlen(all));
    rs_test_write(dir, "repo/dists/stable/Release.txt", release, 0644);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --yes -u '%s' --clearsign "
                       "-o '%s/repo/dists/stable/InRelease' '%s/repo/dists/stable/Release.txt'",
                       home, who, dir, dir);
    CHECK(quiet(cmd) == 0);
    free(cmd);
    rs_buf_free(&gz);
    free(list_sha);
    free(gz_sha);
    free(all_sha);
    free(all);
    free(release);
    free(list);
    free(hello_sha);
}

struct said {
    const struct rs_jval          *pk;
    const struct rs_baseline_opts *o;
};

static int fetch_aloud(const void *arg)
{
    const struct said       *a = arg;
    struct rs_baseline_stats st;
    struct rs_buf            err;
    bool                     ok;

    rs_buf_init(&err);
    ok = rs_baseline_fetch(a->pk, a->o, &st, &err);
    rs_buf_free(&err);
    return ok && st.missing == 2 ? 0 : 1;
}

static void fetching(void)
{
    char                    *dir = rs_test_tmpdir();
    char                    *home = rs_xasprintf("%s/gnupg", dir);
    char                    *cache = rs_xasprintf("%s/cache", dir);
    char                    *json;
    char                    *cmd;
    struct rs_jval           pk;
    struct rs_json_parser    jp;
    struct rs_buf            err;
    struct rs_buf            key;
    struct rs_buf            b64;
    struct rs_buf            text;
    struct rs_baseline_opts  o;
    struct rs_baseline_stats st;

    if ((access("/usr/bin/gpg", X_OK) != 0 && access("/usr/local/bin/gpg", X_OK) != 0) ||
        !rs_program_path(RS_PROG_GPGV) || !rs_program_path(RS_PROG_CURL))
    {
        (void)printf("  (baseline fetches skipped: they need gpg, gpgv and curl)\n");
        rs_test_rmtree(dir);
        free(home);
        free(cache);
        free(dir);
        return;
    }
    TEST_CASE("baseline fetch: from a signed repository, each package checked");
    (void)mkdir(home, 0700);
    cmd = rs_xasprintf("export GNUPGHOME='%s'; "
                       "gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "
                       "a@example.invalid ed25519 sign never && "
                       "gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "
                       "b@example.invalid ed25519 sign never && "
                       "gpg --batch --export a@example.invalid > '%s/a.gpg'",
                       home, dir);
    CHECK(quiet(cmd) == 0);
    free(cmd);
    make_repo(dir, home, "a@example.invalid");
    rs_buf_init(&key);
    rs_buf_init(&b64);
    CHECK(rs_read_beneath(dir, "/a.gpg", 65536, &key));
    rs_base64_encode(&b64, key.data ? key.data : "", key.len);
    json = rs_xasprintf(
        "{\"apt\": {\"architectures\": [\"amd64\"],"
        " \"sources\": [{\"file\": \"/etc/apt/sources.list.d/t.sources\", \"types\": [\"deb\"],"
        "  \"uris\": [\"file://%s/repo\"], \"suites\": [\"stable\"], \"components\": [\"main\"],"
        "  \"signed_by\": \"/usr/share/keyrings/a.gpg\"}],"
        " \"keys\": [{\"path\": \"/usr/share/keyrings/a.gpg\", \"data\": \"%s\"}],"
        " \"packages\": ["
        "  {\"name\": \"hello\", \"architecture\": \"amd64\", \"version\": \"1.0\","
        "   \"origins\": [\"file://%s/repo stable/main\"]},"
        "  {\"name\": \"tzdata\", \"architecture\": \"all\", \"version\": \"2026a\","
        "   \"origins\": [\"file://%s/repo stable/main\"]},"
        "  {\"name\": \"broken\", \"architecture\": \"amd64\", \"version\": \"1\","
        "   \"origins\": [\"file://%s/repo stable/main\"]},"
        "  {\"name\": \"sneaky\", \"architecture\": \"amd64\", \"version\": \"1\","
        "   \"origins\": [\"file://%s/repo stable/main\"]},"
        "  {\"name\": \"elsewhere\", \"architecture\": \"amd64\", \"version\": \"1\","
        "   \"origins\": [\"file://%s/nowhere stable/main\"]},"
        "  {\"name\": \"keyring\", \"architecture\": \"all\", \"version\": \"2\","
        "   \"origins\": [\"file://%s/repo stable/main\"]},"
        "  {\"name\": \"zoom\", \"architecture\": \"amd64\", \"version\": \"6\","
        "   \"unavailable\": \"local\"}]}}",
        dir, b64.data ? b64.data : "", dir, dir, dir, dir, dir, dir);
    memset(&pk, 0, sizeof(pk));
    rs_buf_init(&err);
    rs_json_init(&jp, json, strlen(json), &err);
    CHECK(rs_json_value(&jp, &pk));
    memset(&o, 0, sizeof(o));
    o.cache = cache;
    o.quiet = true;
    CHECK(rs_baseline_fetch(&pk, &o, &st, &err));
    CHECK_INT(st.wanted, 6);
    CHECK_INT(st.fetched, 3);
    CHECK_INT(st.cached, 0);
    CHECK_INT(st.missing, 3);
    CHECK_INT(st.local, 1);
    CHECK(st.bytes > 0);
    rs_buf_init(&text);
    CHECK(rs_read_beneath(cache, "/hello_1.0_amd64.deb", 4096, &text));
    rs_buf_free(&text);
    CHECK(rs_read_beneath(cache, "/tzdata_2026a_all.deb", 4096, &text));
    rs_buf_free(&text);
    CHECK(!rs_read_beneath(cache, "/broken_1_amd64.deb", 4096, &text));
    CHECK(!rs_read_beneath(cache, "/sneaky_1_amd64.deb", 4096, &text));

    TEST_CASE("baseline fetch: again, from the cache; and one changed there, fetched again");
    CHECK(rs_baseline_fetch(&pk, &o, &st, &err));
    CHECK_INT(st.cached, 3);
    CHECK_INT(st.fetched, 0);
    rs_test_write(cache, "hello_1.0_amd64.deb", "tampered", 0644);
    CHECK(rs_baseline_fetch(&pk, &o, &st, &err));
    CHECK_INT(st.cached, 2);
    CHECK_INT(st.fetched, 1);

    TEST_CASE("baseline: what would be fetched");
    rs_buf_init(&text);
    rs_baseline_list(&pk, cache, &text, &st);
    CHECK_CONTAINS(text.data, "hello 1.0 amd64\tcached\n");
    CHECK_CONTAINS(text.data, "broken 1 amd64\tto fetch\n");
    CHECK_CONTAINS(text.data, "zoom 6 amd64\tinstalled from a .deb no repository has\n");
    CHECK_INT(st.wanted, 6);
    CHECK_INT(st.cached, 3);
    CHECK_INT(st.local, 1);
    rs_buf_free(&text);

    TEST_CASE("baseline fetch: what is gone says what its repository has now");
    {
        struct rs_jval          old;
        struct rs_baseline_opts loud = o;
        struct said             a;
        char                   *out = NULL;
        char                   *said = NULL;
        char                   *old_json = rs_xasprintf(
            "{\"apt\": {\"architectures\": [\"amd64\"],"
            " \"sources\": [{\"file\": \"/etc/apt/sources.list.d/t.sources\", \"types\": [\"deb\"],"
            "  \"uris\": [\"file://%s/repo\"], \"suites\": [\"stable\"], \"components\": [\"main\"],"
            "  \"signed_by\": \"/usr/share/keyrings/a.gpg\"}],"
            " \"keys\": [{\"path\": \"/usr/share/keyrings/a.gpg\", \"data\": \"%s\"}],"
            " \"packages\": ["
            "  {\"name\": \"hello\", \"architecture\": \"amd64\", \"version\": \"0.9\","
            "   \"origins\": [\"file://%s/repo stable/main\"]},"
            "  {\"name\": \"elsewhere\", \"architecture\": \"amd64\", \"version\": \"1\","
            "   \"origins\": [\"file://%s/repo stable/main\"]}]}}",
            dir, b64.data ? b64.data : "", dir, dir);

        memset(&old, 0, sizeof(old));
        rs_buf_reset(&err);
        rs_json_init(&jp, old_json, strlen(old_json), &err);
        CHECK(rs_json_value(&jp, &old));
        loud.quiet = false;
        a.pk = &old;
        a.o = &loud;
        CHECK_INT(rs_test_capture(fetch_aloud, &a, &out, &said), 0);
        CHECK_CONTAINS(said, "hello 0.9 (amd64): gone -- its repository has 1.0 now");
        CHECK_CONTAINS(said, "elsewhere 1 (amd64): no repository restate could check has it");
        free(out);
        free(said);
        rs_jval_free(&old);
        free(old_json);
    }

    TEST_CASE("baseline fetch: an index signed by another key is not used");
    rs_test_rmtree(cache);
    make_repo(dir, home, "b@example.invalid");
    CHECK(rs_baseline_fetch(&pk, &o, &st, &err));
    CHECK_INT(st.fetched, 0);
    CHECK_INT(st.missing, 6);

    TEST_CASE("baseline fetch: nothing to fetch with");
    {
        static const char *const none[] = { "/nonexistent/curl" };

        rs_program_set_paths(RS_PROG_CURL, none, 1);
        rs_buf_reset(&err);
        CHECK(!rs_baseline_fetch(&pk, &o, &st, &err));
        CHECK_CONTAINS(err.data, "needs curl, gpgv and gzip");
        rs_program_set_paths(RS_PROG_CURL, NULL, 0);
    }
    {
        struct rs_jval empty;

        memset(&empty, 0, sizeof(empty));
        rs_jval_set_object(&empty);
        rs_buf_reset(&err);
        CHECK(!rs_baseline_fetch(&empty, &o, &st, &err));
        CHECK_CONTAINS(err.data, "no apt packages");
        rs_jval_free(&empty);
    }

    cmd = rs_xasprintf("GNUPGHOME='%s' gpgconf --kill gpg-agent", home);
    (void)quiet(cmd);
    free(cmd);
    rs_jval_free(&pk);
    rs_buf_free(&err);
    rs_buf_free(&key);
    rs_buf_free(&b64);
    free(json);
    rs_test_rmtree(dir);
    free(home);
    free(cache);
    free(dir);
}

void test_baseline(void)
{
    pure();
    fetching();
}
