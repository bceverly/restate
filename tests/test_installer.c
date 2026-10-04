/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cmd.h"
#include "index.h"
#include "installer.h"
#include "json.h"
#include "run.h"
#include "test.h"

/* A machine description with just the system section. */
static void machine(struct rs_jval *m, const char *id, const char *version_id,
                    const char *version, const char *arch, const char *type)
{
    struct rs_jval *sys;

    memset(m, 0, sizeof(*m));
    rs_jval_set_object(m);
    sys = rs_jobj_add(m, "system");
    rs_jval_set_object(sys);
    rs_jobj_str(sys, "id", id);
    rs_jobj_str(sys, "version_id", version_id);
    rs_jobj_str(sys, "version", version);
    rs_jobj_str(sys, "architecture", arch);
    rs_jobj_str(sys, "type", type);
    rs_jobj_str(sys, "type_evidence", type ? "the test says so" : NULL);
}

static void write_file(const char *path, const void *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK(write(fd, data, len) == (ssize_t)len);
        (void)close(fd);
    }
}

static unsigned char *read_all(const char *path, size_t *len)
{
    struct rs_buf b;
    char          chunk[4096];
    int           fd = open(path, O_RDONLY);
    ssize_t       n;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    while (fd >= 0 && (n = read(fd, chunk, sizeof(chunk))) > 0)
    {
        rs_buf_add(&b, chunk, (size_t)n);
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    *len = b.len;
    return (unsigned char *)rs_buf_detach(&b);
}

static int quiet_system(const char *cmd)
{
    char *full = rs_xasprintf("%s > /dev/null 2>&1", cmd);
    int   rc = system(full);

    free(full);
    return rc;
}

static void resolve_cases(void)
{
    struct rs_jval      m;
    struct rs_installer in;
    struct rs_buf       err;

    rs_buf_init(&err);

    TEST_CASE("installer: an amd64 desktop");
    machine(&m, "ubuntu", "26.04", "26.04.1 LTS (Resolute Raccoon)", "x86_64", "desktop");
    CHECK(rs_installer_resolve(&m, &in, &err));
    CHECK_STR(in.flavor, "desktop");
    CHECK_STR(in.arch, "amd64");
    CHECK_STR(in.point, "26.04.1");
    CHECK_STR(in.url, "https://releases.ubuntu.com/26.04/");
    CHECK_STR(in.fallback_url, "https://old-releases.ubuntu.com/releases/26.04/");
    CHECK_STR(in.pattern, "ubuntu-26.04[.N]-desktop-amd64.iso");
    CHECK_STR(in.description, "Ubuntu 26.04 Desktop for amd64");
    CHECK_CONTAINS(in.reason, "the test says so");
    CHECK(in.key && strcmp(in.key->fingerprint, "843938DF228D22F7B3742BC0D94AA3F0EFE21092") == 0);
    rs_installer_free(&in);
    rs_jval_free(&m);

    TEST_CASE("installer: an arm64 server, and the first release of a version");
    machine(&m, "ubuntu", "24.04", "24.04 LTS (Noble Numbat)", "aarch64", "server");
    CHECK(rs_installer_resolve(&m, &in, &err));
    CHECK_STR(in.flavor, "live-server");
    CHECK_STR(in.url, "https://cdimage.ubuntu.com/releases/24.04/release/");
    CHECK(in.fallback_url == NULL);
    CHECK(in.point == NULL);
    rs_installer_free(&in);
    rs_jval_free(&m);

    TEST_CASE("installer: a riscv64 desktop gets the server installer, and says why");
    machine(&m, "ubuntu", "26.04", "26.04.1 LTS", "riscv64", "desktop");
    CHECK(rs_installer_resolve(&m, &in, &err));
    CHECK_STR(in.flavor, "live-server");
    CHECK_CONTAINS(in.reason, "only for amd64 and arm64");
    rs_installer_free(&in);
    rs_jval_free(&m);

    TEST_CASE("installer: no type recorded, and a version that is not a point release");
    machine(&m, "ubuntu", "26.04", "26.10 (something else)", "ppc64le", NULL);
    CHECK(rs_installer_resolve(&m, &in, &err));
    CHECK_STR(in.flavor, "live-server");
    CHECK_STR(in.arch, "ppc64el");
    CHECK(in.point == NULL);
    CHECK_CONTAINS(in.reason, "does not say whether");
    rs_installer_free(&in);
    rs_jval_free(&m);

    TEST_CASE("installer: what cannot be resolved");
    machine(&m, "fedora", "40", NULL, "x86_64", "server");
    rs_buf_reset(&err);
    CHECK(!rs_installer_resolve(&m, &in, &err));
    CHECK_CONTAINS(err.data, "installers for fedora are not supported yet");
    rs_installer_free(&in);
    rs_jval_free(&m);
    machine(&m, "ubuntu", "26.04/../x", NULL, "x86_64", "server");
    rs_buf_reset(&err);
    CHECK(!rs_installer_resolve(&m, &in, &err));
    CHECK_CONTAINS(err.data, "no Ubuntu release number");
    rs_installer_free(&in);
    rs_jval_free(&m);
    machine(&m, "ubuntu", "26.04", NULL, "m68k", "server");
    rs_buf_reset(&err);
    CHECK(!rs_installer_resolve(&m, &in, &err));
    CHECK_CONTAINS(err.data, "no installer for the m68k architecture");
    rs_installer_free(&in);
    rs_jval_free(&m);
    memset(&m, 0, sizeof(m));
    rs_jval_set_object(&m);
    rs_buf_reset(&err);
    CHECK(!rs_installer_resolve(&m, &in, &err));
    CHECK_CONTAINS(err.data, "does not say what system");
    rs_installer_free(&in);
    rs_jval_free(&m);

    TEST_CASE("installer: picking the image from SHA256SUMS");
    {
        static const char sums[] =
            "1111111111111111111111111111111111111111111111111111111111111111 *ubuntu-26.04-live-server-amd64.iso\n"
            "2222222222222222222222222222222222222222222222222222222222222222 *ubuntu-26.04.2-live-server-amd64.iso\n"
            "3333333333333333333333333333333333333333333333333333333333333333 *ubuntu-26.04.1-live-server-amd64.iso\r\n"
            "4444444444444444444444444444444444444444444444444444444444444444  ubuntu-26.04.3-desktop-amd64.iso\n"
            "5555555555555555555555555555555555555555555555555555555555555555 *ubuntu-26.04.9-live-server-amd64.iso/x\n"
            "6666666666666666666666666666666666666666666666666666666666666666 *ubuntu-26.04.x-live-server-amd64.iso\n"
            "zzzz *short\n"
            "777777777777777777777777777777777777777777777777777777777777777G *ubuntu-26.04.8-live-server-amd64.iso\n";
        char *name = NULL;
        char  hash[RS_SHA256_HEX_SIZE];

        machine(&m, "ubuntu", "26.04", "26.04.1 LTS", "x86_64", "server");
        CHECK(rs_installer_resolve(&m, &in, &err));
        CHECK(rs_installer_pick(&in, sums, strlen(sums), &name, hash));
        CHECK_STR(name, "ubuntu-26.04.1-live-server-amd64.iso");   /* its own point release */
        CHECK(hash[0] == '3');
        free(name);
        free(in.point);
        in.point = NULL;
        CHECK(rs_installer_pick(&in, sums, strlen(sums), &name, hash));
        CHECK_STR(name, "ubuntu-26.04.2-live-server-amd64.iso");   /* else the newest */
        free(name);
        free(in.point);
        in.point = rs_xstrdup("26.04.5");                          /* not listed: newest */
        CHECK(rs_installer_pick(&in, sums, strlen(sums), &name, hash));
        CHECK_STR(name, "ubuntu-26.04.2-live-server-amd64.iso");
        free(name);
        CHECK(!rs_installer_pick(&in, "nothing here\n", 13, &name, hash));
        CHECK(name == NULL);
        rs_installer_free(&in);
        rs_jval_free(&m);
    }
    rs_buf_free(&err);
}

static void write_machine_json(const char *path, const struct rs_jval *m)
{
    struct rs_buf b;

    rs_buf_init(&b);
    rs_json_write(&b, m, 2, 0);
    write_file(path, b.data, b.len);
    rs_buf_free(&b);
}

static void write_index(const char *path, const struct rs_jval *m)
{
    struct rs_index ix;
    FILE           *fp = fopen(path, "w");

    rs_index_init(&ix);
    if (m)
    {
        rs_jval_copy(&ix.machine, m);
    }
    CHECK(fp && rs_index_write(&ix, fp));
    if (fp)
    {
        (void)fclose(fp);
    }
    rs_index_free(&ix);
}

static int run(const void *arg)
{
    return rs_cmd_run(arg);
}

/* `restate installer` on descriptions in files: what it prints and refuses. */
static void command_cases(const char *dir)
{
    char             *json = rs_xasprintf("%s/machine.json", dir);
    char             *bare = rs_xasprintf("%s/bare.json", dir);
    char             *index = rs_xasprintf("%s/with.idx", dir);
    char             *empty = rs_xasprintf("%s/without.idx", dir);
    char             *fedora = rs_xasprintf("%s/fedora.json", dir);
    char             *args[2];
    char             *out = NULL;
    char             *errs = NULL;
    struct rs_options o;
    struct rs_jval    m;

    machine(&m, "ubuntu", "26.04", "26.04.1 LTS", "x86_64", "desktop");
    rs_jobj_str((struct rs_jval *)rs_jobject_get(&m, "system"), "hostname", "builder");
    write_machine_json(json, &m);
    write_index(index, &m);
    rs_jval_free(&m);
    write_index(empty, NULL);
    write_file(bare, "{\"other\": 1}\n", 13);
    machine(&m, "fedora", "40", NULL, "x86_64", "server");
    write_machine_json(fedora, &m);
    rs_jval_free(&m);

    memset(&o, 0, sizeof(o));
    o.command = CMD_INSTALLER;
    o.args = args;

    TEST_CASE("installer command: a description written by restate machine");
    args[0] = json;
    o.nargs = 1;
    CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
    CHECK_CONTAINS(out, "installer   Ubuntu 26.04 Desktop for amd64\n");
    CHECK_CONTAINS(out, "for         builder (26.04)");
    CHECK_CONTAINS(out, "or, after end of life, https://old-releases.ubuntu.com/releases/26.04/");
    CHECK_CONTAINS(out, "8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092");
    CHECK_CONTAINS(out, "fetch it    restate installer fetch ");
    free(out);
    free(errs);

    TEST_CASE("installer command: the description inside an index");
    args[0] = index;
    CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
    CHECK_CONTAINS(out, "file        ubuntu-26.04[.N]-desktop-amd64.iso -- 26.04.1");
    free(out);
    free(errs);

    TEST_CASE("installer command: what it refuses");
    args[0] = empty;
    CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "has no machine description");
    free(out);
    free(errs);
    args[0] = bare;
    CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
    free(out);
    free(errs);
    args[0] = fedora;
    CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "installers for fedora are not supported yet");
    free(out);
    free(errs);
    args[0] = json;
    args[1] = json;
    o.nargs = 2;
    CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "usage: restate installer [fetch] [IMAGE]");
    free(out);
    free(errs);

    TEST_CASE("installer command: this machine");
    o.nargs = 0;
    CHECK(rs_test_capture(run, &o, &out, &errs) != RESTATE_EXIT_INCOMPLETE);
    free(out);
    free(errs);

    free(json);
    free(bare);
    free(index);
    free(empty);
    free(fedora);
}

/* The program runner, with /bin/sh standing in for a program. */
static void run_cases(void)
{
    static const char *const sh[] = { "/bin/sh" };
    static const char *const missing[] = { "/nonexistent/program" };
    char                     a0[] = "sh";
    char                     a1[] = "-c";
    char                     killed[] = "kill -9 $$";
    char                     proxy[] = "printf %s \"$https_proxy\"";
    char                    *argv[] = { a0, a1, killed, NULL };
    struct rs_buf            out;
    struct rs_buf            err;
    int                      code = 0;

    rs_buf_init(&out);
    rs_buf_init(&err);

    TEST_CASE("run: names, a death by signal, and nothing said");
    CHECK_STR(rs_program_name(RS_PROG_GPGV), "gpgv");
    CHECK(rs_vendor_key("nobody") == NULL);
    rs_program_set_paths(RS_PROG_GZIP, sh, 1);
    CHECK(rs_run(RS_PROG_GZIP, argv, &out, NULL, &code, &err));
    CHECK_INT(code, 128 + 9);
    CHECK_STR(out.data, "");

    TEST_CASE("run: the proxy is passed through");
    argv[2] = proxy;
    (void)setenv("https_proxy", "http://proxy.example.invalid:3128", 1);
    rs_buf_reset(&out);
    CHECK(rs_run(RS_PROG_GZIP, argv, &out, NULL, &code, &err));
    CHECK_STR(out.data, "http://proxy.example.invalid:3128");
    (void)unsetenv("https_proxy");

    TEST_CASE("run: a program that is not there");
    rs_program_set_paths(RS_PROG_GZIP, missing, 1);
    CHECK(!rs_run(RS_PROG_GZIP, argv, &out, &out, &code, &err));
    CHECK_CONTAINS(err.data, "could not run gzip (looked for /nonexistent/program)");
    rs_program_set_paths(RS_PROG_GZIP, NULL, 0);

    rs_buf_free(&out);
    rs_buf_free(&err);
}

void test_installer(void)
{
    char                *dir = rs_test_tmpdir();
    char                *home = rs_xasprintf("%s/gnupg", dir);
    char                *mirror = rs_xasprintf("%s/mirror", dir);
    char                *cache = rs_xasprintf("%s/cache", dir);
    char                *url = NULL;
    struct rs_vendor_key test_key;
    unsigned char       *keydata = NULL;
    size_t               keylen = 0;
    char                 fpr[64] = "";
    struct rs_jval       m;
    struct rs_installer  in;
    struct rs_fetch_opts fo;
    struct rs_buf        err;
    char                *path = NULL;

    resolve_cases();
    run_cases();
    command_cases(dir);

    TEST_CASE("installer: the default cache");
    CHECK_CONTAINS(rs_installer_default_cache(), "restate/installers");

    /* The fetch tests need gpg to make a signing key, and gpgv and curl to
     * run; on a system without them they are skipped, not failed. */
    if ((access("/usr/bin/gpg", X_OK) != 0 && access("/usr/local/bin/gpg", X_OK) != 0) ||
        !rs_program_path(RS_PROG_GPGV) || !rs_program_path(RS_PROG_CURL))
    {
        (void)printf("  (installer fetch tests skipped: they need gpg, gpgv and curl)\n");
        rs_test_rmtree(dir);
        free(home);
        free(mirror);
        free(cache);
        free(dir);
        return;
    }

    TEST_CASE("installer: a signed mirror for the tests");
    {
        char *cmd;
        char *keyfile = rs_xasprintf("%s/key.gpg", dir);
        char *listing = rs_xasprintf("%s/fpr.txt", dir);
        FILE *fp;
        char  line[512];

        (void)mkdir(home, 0700);
        (void)mkdir(mirror, 0755);
        cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --pinentry-mode loopback --passphrase '' "
                           "--quick-gen-key 'restate test <test@example.invalid>' ed25519 sign never",
                           home);
        CHECK(quiet_system(cmd) == 0);
        free(cmd);
        cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --export > '%s' 2>/dev/null; "
                           "GNUPGHOME='%s' gpg --batch --with-colons --list-keys > '%s' 2>/dev/null",
                           home, keyfile, home, listing);
        CHECK(system(cmd) == 0);
        free(cmd);
        fp = fopen(listing, "r");
        while (fp && fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, "fpr:", 4) == 0 && fpr[0] == '\0')
            {
                const char *f = line + 4;
                int         colons = 0;

                while (*f && colons < 8)
                {
                    colons += *f++ == ':';
                }
                memcpy(fpr, f, 40);
                fpr[40] = '\0';
            }
        }
        if (fp)
        {
            (void)fclose(fp);
        }
        CHECK(strlen(fpr) == 40);
        keydata = read_all(keyfile, &keylen);
        CHECK(keylen > 0);
        test_key.vendor = "ubuntu";
        test_key.name = "restate test <test@example.invalid>";
        test_key.fingerprint = fpr;
        test_key.data = keydata;
        test_key.len = keylen;
        free(keyfile);
        free(listing);
    }

    /* Two point releases, and the hashes of both, signed. */
    {
        char *iso1 = rs_xasprintf("%s/ubuntu-26.04.1-live-server-amd64.iso", mirror);
        char *iso0 = rs_xasprintf("%s/ubuntu-26.04-live-server-amd64.iso", mirror);
        char *sums = rs_xasprintf("%s/SHA256SUMS", mirror);
        char  h1[RS_SHA256_HEX_SIZE];
        char  h0[RS_SHA256_HEX_SIZE];
        char *text;
        char *cmd;

        write_file(iso1, "the 26.04.1 image\n", 18);
        write_file(iso0, "the 26.04 image\n", 16);
        rs_sha256_hex("the 26.04.1 image\n", 18, h1);
        rs_sha256_hex("the 26.04 image\n", 16, h0);
        text = rs_xasprintf("%s *ubuntu-26.04-live-server-amd64.iso\n"
                            "%s *ubuntu-26.04.1-live-server-amd64.iso\n", h0, h1);
        write_file(sums, text, strlen(text));
        cmd = rs_xasprintf("cd '%s' && GNUPGHOME='%s' gpg --batch --yes --armor --detach-sign "
                           "-o SHA256SUMS.gpg SHA256SUMS", mirror, home);
        CHECK(quiet_system(cmd) == 0);
        free(cmd);
        free(text);
        free(iso1);
        free(iso0);
        free(sums);
    }
    url = rs_xasprintf("file://%s", mirror);
    rs_installer_set_key(&test_key);
    rs_buf_init(&err);
    machine(&m, "ubuntu", "26.04", "26.04.1 LTS", "x86_64", "server");
    CHECK(rs_installer_resolve(&m, &in, &err));
    fo.cache = cache;
    fo.mirror = url;
    fo.quiet = true;

    TEST_CASE("installer: fetch, verify, and keep");
    CHECK(rs_installer_fetch(&in, &fo, &path, &err));
    CHECK_STR(err.data ? err.data : "", "");
    CHECK(path && strstr(path, "/ubuntu/26.04/ubuntu-26.04.1-live-server-amd64.iso"));
    {
        size_t         len;
        unsigned char *got = read_all(path, &len);

        CHECK(len == 18 && memcmp(got, "the 26.04.1 image\n", 18) == 0);
        free(got);
    }

    TEST_CASE("installer: a second fetch finds it already verified");
    free(path);
    path = NULL;
    CHECK(rs_installer_fetch(&in, &fo, &path, &err));

    TEST_CASE("installer: a damaged copy in the cache is fetched again");
    write_file(path, "garbage", 7);
    free(path);
    path = NULL;
    {
        char *part = rs_xasprintf("%s/ubuntu/26.04/ubuntu-26.04.1-live-server-amd64.iso.part",
                                  cache);

        write_file(part, "wrong start", 11);   /* a resume that cannot be right */
        CHECK(rs_installer_fetch(&in, &fo, &path, &err));
        CHECK(access(part, F_OK) != 0);
        free(part);
    }

    TEST_CASE("installer: a mirror URL without its trailing slash");
    free(path);
    path = NULL;
    {
        char *trimmed = rs_xstrdup(url);

        fo.mirror = trimmed;
        CHECK(rs_installer_fetch(&in, &fo, &path, &err));
        fo.mirror = url;
        free(trimmed);
    }

    TEST_CASE("installer command: fetch");
    {
        char             *json = rs_xasprintf("%s/machine.json", dir);
        char              fetch[] = "fetch";
        char             *args[2] = { fetch, json };
        char             *out = NULL;
        char             *errs = NULL;
        struct rs_options o;

        write_machine_json(json, &m);
        memset(&o, 0, sizeof(o));
        o.command = CMD_INSTALLER;
        o.args = args;
        o.nargs = 2;
        o.cache = cache;
        o.mirror = url;
        CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_OK);
        CHECK_CONTAINS(out, "/ubuntu/26.04/ubuntu-26.04.1-live-server-amd64.iso\n");
        CHECK_CONTAINS(errs, "matches the signed checksum");
        CHECK_CONTAINS(errs, "dd ");
        free(out);
        free(errs);
        o.mirror = "file:///nonexistent/mirror";
        o.quiet = true;
        CHECK_INT(rs_test_capture(run, &o, &out, &errs), RESTATE_EXIT_TROUBLE);
        CHECK_CONTAINS(errs, "could not download");
        free(out);
        free(errs);
        free(json);
    }

    TEST_CASE("installer: an image that does not match its signed checksum");
    {
        char *iso1 = rs_xasprintf("%s/ubuntu-26.04.1-live-server-amd64.iso", mirror);
        char *cached = rs_xasprintf("%s/ubuntu/26.04/ubuntu-26.04.1-live-server-amd64.iso", cache);

        (void)unlink(cached);
        write_file(iso1, "a swapped image!!!\n", 19);
        free(path);
        path = NULL;
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "does not match the signed checksum");
        CHECK(access(cached, F_OK) != 0);
        write_file(iso1, "the 26.04.1 image\n", 18);
        free(iso1);
        free(cached);
    }

    TEST_CASE("installer: a checksum file that is not what was signed");
    {
        char *sums = rs_xasprintf("%s/SHA256SUMS", mirror);
        char *orig = rs_xasprintf("%s/SHA256SUMS.orig", mirror);
        char *cmd = rs_xasprintf("cp '%s' '%s' && echo '' >> '%s'", sums, orig, sums);

        CHECK(system(cmd) == 0);
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "is not a valid signature");
        free(cmd);
        cmd = rs_xasprintf("mv '%s' '%s'", orig, sums);
        CHECK(system(cmd) == 0);
        free(cmd);
        free(sums);
        free(orig);
    }

    TEST_CASE("installer: a signature by any other key");
    {
        struct rs_vendor_key other = test_key;

        other.fingerprint = "843938DF228D22F7B3742BC0D94AA3F0EFE21092";
        rs_installer_set_key(&other);
        in.key = &other;
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "is not a valid signature");
        rs_installer_set_key(&test_key);
        in.key = &test_key;
    }

    TEST_CASE("installer: what the mirror does not have");
    {
        struct rs_installer desk;
        struct rs_jval      dm;

        machine(&dm, "ubuntu", "26.04", "26.04.1 LTS", "x86_64", "desktop");
        CHECK(rs_installer_resolve(&dm, &desk, &err));
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&desk, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "SHA256SUMS lists no ubuntu-26.04[.N]-desktop-amd64.iso");
        rs_installer_free(&desk);
        rs_jval_free(&dm);
        fo.mirror = "file:///nonexistent/mirror";
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "could not download");
        fo.mirror = url;
    }

    TEST_CASE("installer: no key, no curl, no gpgv, nowhere to write");
    {
        static const char *const missing[] = { "/nonexistent/program" };
        const struct rs_vendor_key *keep = in.key;

        in.key = NULL;
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "no signing key for ubuntu");
        in.key = keep;
        rs_program_set_paths(RS_PROG_CURL, missing, 1);
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "curl is not installed");
        rs_program_set_paths(RS_PROG_CURL, NULL, 0);
        rs_program_set_paths(RS_PROG_GPGV, missing, 1);
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "gpgv is not installed");
        rs_program_set_paths(RS_PROG_GPGV, NULL, 0);
        char *blocked = rs_xasprintf("%s/key.gpg/cache", dir);   /* under a file: even root */

        fo.cache = blocked;
        rs_buf_reset(&err);
        CHECK(!rs_installer_fetch(&in, &fo, &path, &err));
        CHECK_CONTAINS(err.data, "key.gpg");
        fo.cache = cache;
        free(blocked);
    }

    {
        /* gpg started an agent for the test keyring; it should not outlive it. */
        char *cmd = rs_xasprintf("GNUPGHOME='%s' gpgconf --kill gpg-agent", home);

        (void)quiet_system(cmd);
        free(cmd);
    }
    rs_installer_set_key(NULL);
    rs_installer_free(&in);
    rs_jval_free(&m);
    rs_buf_free(&err);
    free(path);
    free(url);
    free(keydata);
    rs_test_rmtree(dir);
    free(home);
    free(mirror);
    free(cache);
    free(dir);
}
