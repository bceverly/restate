/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "image.h"
#include "json.h"
#include "md5.h"
#include "pkgdb.h"
#include "progress.h"
#include "scan.h"
#include "sha256.h"
#include "test.h"

static void md5_hex(const char *text, char hex[RS_MD5_SIZE * 2 + 1])
{
    static const char digits[] = "0123456789abcdef";
    struct rs_md5     ctx;
    unsigned char     d[RS_MD5_SIZE];
    size_t            i;

    rs_md5_init(&ctx);
    rs_md5_update(&ctx, text, strlen(text));
    rs_md5_final(&ctx, d);
    for (i = 0; i < RS_MD5_SIZE; i++)
    {
        hex[i * 2] = digits[d[i] >> 4];
        hex[i * 2 + 1] = digits[d[i] & 0x0fu];
    }
    hex[RS_MD5_SIZE * 2] = '\0';
}

void test_md5(void)
{
    char          hex[RS_MD5_SIZE * 2 + 1];
    struct rs_md5 ctx;
    unsigned char a[RS_MD5_SIZE];
    unsigned char b[RS_MD5_SIZE];
    char          million[1001];
    int           i;

    TEST_CASE("md5: the RFC 1321 test vectors");
    md5_hex("", hex);
    CHECK_STR(hex, "d41d8cd98f00b204e9800998ecf8427e");
    md5_hex("abc", hex);
    CHECK_STR(hex, "900150983cd24fb0d6963f7d28e17f72");
    md5_hex("message digest", hex);
    CHECK_STR(hex, "f96b697d7cb7938d525a2f31aaf161d0");
    md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            hex);
    CHECK_STR(hex, "57edf4a22be3c955ac49da2e2107b67a");

    TEST_CASE("md5: fed in pieces, the same as all at once");
    memset(million, 'a', 1000);
    million[1000] = '\0';
    rs_md5_init(&ctx);
    for (i = 0; i < 1000; i++)
    {
        rs_md5_update(&ctx, million, 1000);
    }
    rs_md5_final(&ctx, a);
    CHECK(rs_md5_parse_hex("7707d6ae4e027c70eea2a935c2296f21", 32, b));
    CHECK(memcmp(a, b, sizeof(a)) == 0);
    rs_md5_init(&ctx);
    rs_md5_update(&ctx, "ab", 2);
    rs_md5_update(&ctx, "c", 1);
    rs_md5_final(&ctx, a);
    CHECK(rs_md5_parse_hex("900150983CD24FB0D6963F7D28E17F72", 32, b));
    CHECK(memcmp(a, b, sizeof(a)) == 0);
    CHECK(!rs_md5_parse_hex("900150983cd24fb0d6963f7d28e17f7", 31, b));
    CHECK(!rs_md5_parse_hex("900150983cd24fb0d6963f7d28e17fxz", 32, b));
}

static void mkdirs(const char *root, const char *rel)
{
    char *p = rs_xasprintf("%s/%s", root, rel);
    char *s;

    for (s = p + strlen(root) + 1; (s = strchr(s, '/')) != NULL; s++)
    {
        *s = '\0';
        (void)mkdir(p, 0755);
        *s = '/';
    }
    (void)mkdir(p, 0755);
    free(p);
}

/* A machine dpkg has installed things on: what each package put where, and
 * what has happened to those files since. */
static void build_debian(const char *root)
{
    char        ls[33];
    char        tru[33];
    char        div[33];
    char        changed[33];
    char        foo[33];
    char        old[33];
    char        edited[33];
    char        gone[33];
    char       *text;

    md5_hex("ls-binary", ls);
    md5_hex("true-binary", tru);
    md5_hex("diverted-binary", div);
    md5_hex("as shipped", changed);
    md5_hex("a=1\n", foo);
    md5_hex("old\n", old);
    md5_hex("orig\n", edited);
    md5_hex("gone\n", gone);

    mkdirs(root, "var/lib/dpkg/info");
    mkdirs(root, "usr/bin");
    mkdirs(root, "etc");
    text = rs_xasprintf(
        "Package: coreutils\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Description: tools\n"
        " with a continuation line\n"
        "\n"
        "Package: libfoo\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Multi-Arch: same\n"
        "Conffiles:\n"
        " /etc/foo.conf %s\n"
        " /etc/old.conf %s obsolete\n"
        " /etc/edited.conf %s\n"
        " /etc/new.conf newconffile\n"
        " /etc/with space.conf %s remove-on-upgrade\n"
        "Description: a library\n"
        "\n"
        "Package: gone\n"
        "Status: deinstall ok config-files\n"
        "Conffiles:\n"
        " /etc/gone.conf %s\n"
        "\n"
        "Package: Bad/Name\n"
        "Status: install ok installed\n"
        "\n"
        "Package: never\n"
        "Status: purge ok not-installed\n",
        foo, old, edited, foo, gone);
    rs_test_write(root, "var/lib/dpkg/status", text, 0644);
    free(text);
    rs_test_write(root, "var/lib/dpkg/diversions",
                  "/usr/bin/diverted\n/usr/bin/diverted.distrib\nother-pkg\n"
                  "/usr/bin/own\n/usr/bin/own.real\ncoreutils\n"
                  "relative\n/x\npkg\n"
                  "/incomplete\n",
                  0644);
    text = rs_xasprintf("%s  usr/bin/ls\n"
                        "%s  bin/true\n"
                        "%s  usr/bin/diverted\n"
                        "%s *usr/bin/changed\n"
                        "not a digest  usr/bin/x\n"
                        "%s  \n"
                        "%s  ../escape\n",
                        ls, tru, div, changed, ls, ls);
    rs_test_write(root, "var/lib/dpkg/info/coreutils.md5sums", text, 0644);
    free(text);
    rs_test_write(root, "var/lib/dpkg/info/coreutils.list",
                  "/.\n/usr\n/usr/bin\n/usr/bin/ls\n/bin/true\n/usr/bin/diverted\n"
                  "/usr/bin/changed\n/usr/bin/nomd5\n",
                  0644);
    rs_test_write(root, "var/lib/dpkg/info/libfoo:amd64.list",
                  "/etc\n/etc/foo.conf\n/etc/old.conf\n/etc/edited.conf\n", 0644);

    rs_test_write(root, "usr/bin/ls", "ls-binary", 0755);
    rs_test_write(root, "usr/bin/true", "true-binary", 0755);
    rs_test_write(root, "usr/bin/diverted.distrib", "diverted-binary", 0755);
    rs_test_write(root, "usr/bin/diverted", "the administrator's", 0755);
    rs_test_write(root, "usr/bin/changed", "tampered", 0755);
    rs_test_write(root, "usr/bin/nomd5", "no digest", 0755);
    rs_test_write(root, "usr/bin/handmade", "#!/bin/sh\n", 0755);
    rs_test_write(root, "etc/foo.conf", "a=1\n", 0644);
    rs_test_write(root, "etc/old.conf", "old\n", 0644);
    rs_test_write(root, "etc/edited.conf", "mine\n", 0644);
    rs_test_write(root, "etc/gone.conf", "gone\n", 0644);
    rs_test_write(root, "etc/hosts", "127.0.0.1 localhost\n", 0644);
}

static const struct rs_entry *find(const struct rs_index *m, const char *path)
{
    return rs_index_find(m, path);
}

static int stored_count;

static bool counting_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                           struct rs_buf *err)
{
    (void)ctx;
    (void)st;
    (void)err;
    if (fd >= 0)
    {
        if (rs_hash_fd(fd, e->hash, NULL))
        {
            e->hash_state = RS_HASH_PRESENT;
        }
        stored_count++;
    }
    e->stored = rs_xstrdup("x");
    return true;
}

static bool discard(void *ctx, const void *data, size_t n)
{
    (void)ctx;
    (void)data;
    (void)n;
    return true;
}

/* A store that copies as the real ones do, through rs_image_copy_file. */
static bool copying_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                          struct rs_buf *err)
{
    struct rs_tar_writer tw;

    (void)ctx;
    (void)err;
    if (fd >= 0)
    {
        rs_tar_writer_init(&tw, discard, NULL);
        if (!rs_image_copy_file(&tw, e, fd, (uint64_t)st->st_size))
        {
            return false;
        }
        stored_count++;
    }
    e->stored = rs_xstrdup("x");
    return true;
}

/* The last read_bytes a progress file `fp` says. */
static unsigned long long last_read_bytes(FILE *fp)
{
    char               line[512];
    unsigned long long n = 0;

    rewind(fp);
    while (fgets(line, sizeof(line), fp))
    {
        const char *at = strstr(line, "\"read_bytes\": ");

        if (at)
        {
            n = strtoull(at + strlen("\"read_bytes\": "), NULL, 10);
        }
    }
    return n;
}

static bool have_all(const void *ctx, const char hash[RS_SHA256_HEX_SIZE])
{
    (void)ctx;
    (void)hash;
    return true;
}

static bool have_none(const void *ctx, const char hash[RS_SHA256_HEX_SIZE])
{
    (void)ctx;
    (void)hash;
    return false;
}

/* `text`'s SHA-256 as OpenBSD's +CONTENTS gives it: base64. */
static char *sha256_b64(const char *text)
{
    struct rs_sha256 ctx;
    unsigned char    raw[RS_SHA256_SIZE];
    struct rs_buf    out;

    rs_sha256_init(&ctx);
    rs_sha256_update(&ctx, text, strlen(text));
    rs_sha256_final_raw(&ctx, raw);
    rs_buf_init(&out);
    rs_base64_encode(&out, raw, sizeof(raw));
    return rs_buf_detach(&out);
}

/*
 * A machine OpenBSD's pkg_add has installed a package on, beneath `root`:
 * its files under /usr/local, one changed since, a configuration file made
 * from the package's sample, and a base system no package owns.
 */
static void build_openbsd(const char *root)
{
    char *foo = sha256_b64("foo\n");
    char *conf = sha256_b64("setting = 1\n");
    char *was = sha256_b64("as shipped\n");
    char *contents = rs_xasprintf("@name foo-1.2p0\n"
                                  "@comment pkgpath=misc/foo\n"
                                  "@cwd /usr/local\n"
                                  "@bin bin/foo\n@sha %s\n@size 4\n@ts 1700000000\n"
                                  "@man man/man1/foo.1\n"
                                  "bin/changed\n@sha %s\n"
                                  "bin/nosha\n"
                                  "share/examples/foo/foo.conf\n@sha %s\n"
                                  "@sample /etc/foo.conf\n"
                                  "@sample /etc/foo.d/\n"
                                  "@sha nonsense\n",
                                  foo, was, conf);

    mkdirs(root, "var/db/pkg/foo-1.2p0");
    rs_test_write(root, "var/db/pkg/foo-1.2p0/+CONTENTS", contents, 0644);
    mkdirs(root, "var/db/pkg/broken");
    rs_test_write(root, "var/db/pkg/broken/+CONTENTS", "no name here\n", 0644);
    mkdirs(root, "usr/local/bin");
    mkdirs(root, "usr/local/man/man1");
    mkdirs(root, "usr/local/share/examples/foo");
    mkdirs(root, "usr/bin");
    mkdirs(root, "etc");
    rs_test_write(root, "usr/local/bin/foo", "foo\n", 0755);
    rs_test_write(root, "usr/local/bin/changed", "changed since\n", 0755);
    rs_test_write(root, "usr/local/bin/nosha", "x\n", 0755);
    rs_test_write(root, "usr/local/bin/handmade", "mine\n", 0755);
    rs_test_write(root, "usr/local/man/man1/foo.1", ".TH FOO 1\n", 0644);
    rs_test_write(root, "usr/local/share/examples/foo/foo.conf", "setting = 1\n", 0644);
    rs_test_write(root, "etc/foo.conf", "setting = 1\n", 0644);
    rs_test_write(root, "usr/bin/base", "the base set\n", 0755);
    free(foo);
    free(conf);
    free(was);
    free(contents);
}

static void test_bsd_packages(void)
{
    char                    *root = rs_test_tmpdir();
    struct rs_pkgdb          db;
    const struct rs_pkgfile *f;
    struct rs_rules          rules;
    struct rs_scan_opts      o;
    struct rs_scan_stats     st;
    struct rs_index          m;
    struct rs_buf            err;
    const struct rs_entry   *e;
    size_t                   len;
    char                     hex[RS_SHA256_HEX_SIZE];
    const char              *text = "baseline /usr\nbaseline /usr/local\nstate /etc\n"
                                    "baseline /var/db/pkg\n";

    rs_buf_init(&err);
    build_openbsd(root);

    TEST_CASE("pkgdb: OpenBSD's packages, read from each one's +CONTENTS");
    CHECK(rs_pkgdb_load(&db, root));
    CHECK_INT(db.nnames, 1);
    CHECK_STR(db.names[0], "foo");
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/local/bin/foo", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_SHA256);
    CHECK_STR(rs_pkgdb_package(&db, f, &len), "foo");
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/local/man/man1/foo.1", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_NONE);
    /* A sample's copy is a configuration file with the sample's digest; a
     * directory made from one is nothing to compare. */
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/foo.conf", &f), 1);
    CHECK(f->flags & RS_PKGFILE_CONFFILE);
    CHECK(f->digest_kind == RS_PKGDIGEST_SHA256);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/foo.d", &f), 0);
    /* Only packages put files in /usr/local; the base system and the
     * database are no package's. */
    CHECK(rs_pkgdb_scoped(&db, "/usr/local/bin/handmade"));
    CHECK(rs_pkgdb_scoped(&db, "/usr/local"));
    CHECK(!rs_pkgdb_scoped(&db, "/usr/localx"));
    CHECK(!rs_pkgdb_scoped(&db, "/usr/bin/base"));
    CHECK(!rs_pkgdb_scoped(&db, "/var/db/pkg/foo-1.2p0/+CONTENTS"));
    rs_pkgdb_free(&db);

    TEST_CASE("scan: an OpenBSD package's files checked against their SHA-256");
    rs_rules_init(&rules);
    CHECK(rs_rules_parse(&rules, text, strlen(text), "test", &err));
    CHECK(rs_pkgdb_load(&db, root));
    memset(&o, 0, sizeof(o));
    o.root = root;
    o.rules = &rules;
    o.hash = true;
    o.pkgdb = &db;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = find(&m, "/usr/local/bin/foo");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->package && !e->modified);
    /* The index's digest is the one compared with the package's. */
    rs_sha256_hex("foo\n", 4, hex);
    CHECK_STR(e ? e->hash : "", hex);
    e = find(&m, "/usr/local/bin/changed");
    CHECK(e && e->cls == RS_CLASS_STATE && e->modified);
    CHECK_STR(e ? e->package : "", "foo");
    e = find(&m, "/usr/local/bin/nosha");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->package && !e->modified);
    e = find(&m, "/usr/local/bin/handmade");
    CHECK(e && e->cls == RS_CLASS_STATE && !e->package);
    e = find(&m, "/etc/foo.conf");
    CHECK(e && e->cls == RS_CLASS_BASELINE);
    CHECK_STR(e ? e->package : "", "foo");
    /* The base system, which no package owns, is as the rules say. */
    e = find(&m, "/usr/bin/base");
    CHECK(e && e->cls == RS_CLASS_BASELINE && !e->package);
    e = find(&m, "/var/db/pkg/foo-1.2p0/+CONTENTS");
    CHECK(e && e->cls == RS_CLASS_BASELINE);
    CHECK_INT(st.pkg_modified, 1);
    CHECK_INT(st.unpackaged, 1);
    rs_index_free(&m);

    TEST_CASE("scan: without hashing, OpenBSD's files are still compared");
    o.hash = false;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = find(&m, "/usr/local/bin/foo");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->hash_state != RS_HASH_PRESENT);
    e = find(&m, "/usr/local/bin/changed");
    CHECK(e && e->cls == RS_CLASS_STATE && e->modified);
    rs_index_free(&m);
    rs_pkgdb_free(&db);
    rs_rules_free(&rules);

    TEST_CASE("pkgdb: pkgsrc's packages, and the files their +INSTALL copied");
    rs_pkgdb_init(&db);
    CHECK(rs_pkgdb_parse_contents(&db, "@cwd /usr/pkg\n"
                                       "@name hello-2.12nb1\n"
                                       "@pkgdep libiconv>=1.9\n"
                                       "@ignore\n+BUILD_INFO\n"
                                       "bin/hello\n"
                                       "@comment MD5:a723176f804503c15766073170b99298\n"
                                       "share/examples/hello/hello.conf\n"
                                       "@comment MD5:f968f33f844c98de1d3b4fe70f2e1a0f\n"
                                       "share/doc/hello\n"
                                       "@comment MD5:short\n"
                                       "@comment not a digest\n"
                                       "@pkgdir share/hello\n"));
    rs_pkgdb_parse_install(&db, 0, "/usr/pkg",
                           "#!/bin/sh\n"
                           "# FILE: etc/hello.conf c share/examples/hello/hello.conf 0644\n"
                           "# FILE: /etc/rc.d/hello cr share/examples/hello/hello.conf 0755\n"
                           "# FILE: etc/linked.conf l share/examples/hello/hello.conf\n"
                           "# FILE: etc/nosource.conf c share/examples/none 0644\n"
                           "# FILE: etc/short.conf c\n"
                           "# DIR: etc m\n");
    rs_pkgdb_parse_install(&db, 9, "/usr/pkg", "# FILE: etc/x c bin/hello 0644\n");
    rs_pkgdb_parse_install(&db, 0, "relative", "# FILE: etc/x c bin/hello 0644\n");
    rs_pkgdb_sort(&db);
    CHECK_STR(db.names[0], "hello");
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/+BUILD_INFO", &f), 0);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/bin/hello", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_MD5);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/share/doc/hello", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_NONE);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/etc/hello.conf", &f), 1);
    CHECK(f->flags & RS_PKGFILE_CONFFILE);
    CHECK(f->digest_kind == RS_PKGDIGEST_MD5);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/rc.d/hello", &f), 1);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/etc/linked.conf", &f), 0);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/etc/nosource.conf", &f), 0);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/pkg/etc/x", &f), 0);
    CHECK(rs_pkgdb_scoped(&db, "/usr/pkg/bin/other"));
    CHECK(!rs_pkgdb_scoped(&db, "/etc/rc.d/other"));
    rs_pkgdb_free(&db);

    TEST_CASE("pkgdb: a +CONTENTS no package manager would write");
    rs_pkgdb_init(&db);
    CHECK(!rs_pkgdb_parse_contents(&db, "bin/x\n@sha abc\n"));
    CHECK(!rs_pkgdb_parse_contents(&db, "@name -1.0\n"));
    CHECK(!rs_pkgdb_parse_contents(&db, "@name a:b-1.0\n"));
    CHECK(rs_pkgdb_parse_contents(&db, "@name nocwd-1\nbin/x\n@cwd relative\nbin/y\n"
                                       "@cwd /\netc/z\n@cwd /opt/../etc\nbin/w\n"));
    CHECK(rs_pkgdb_parse_contents(&db, "@name ab\n@cwd /usr/local\n../escape\n@sha\n"));
    rs_pkgdb_sort(&db);
    CHECK_INT(db.nnames, 2);
    CHECK_STR(db.names[1], "ab");
    CHECK_INT(db.nfiles, 1);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/z", &f), 1);
    /* "/" holds the system's files too: it is no package's scope. */
    CHECK(!rs_pkgdb_scoped(&db, "/etc/hosts"));
    rs_pkgdb_free(&db);

    rs_buf_free(&err);
    rs_test_rmtree(root);
    free(root);
}

void test_pkgdb(void)
{
    char                    *root = rs_test_tmpdir();
    struct rs_pkgdb          db;
    const struct rs_pkgfile *f;
    struct rs_rules          rules;
    struct rs_scan_opts      o;
    struct rs_scan_stats     st;
    struct rs_index          m;
    struct rs_buf            err;
    const struct rs_entry   *e;
    size_t                   len;
    const char              *text = "baseline /usr\n";

    build_debian(root);
    rs_buf_init(&err);

    TEST_CASE("pkgdb: dpkg's database, read beneath the root");
    CHECK(rs_pkgdb_load(&db, root));
    /* coreutils, libfoo:amd64; not the removed one, the purged one, or a
     * name no package could have. */
    CHECK_INT(db.nnames, 2);
    CHECK_STR(db.names[1], "libfoo:amd64");
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/ls", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_MD5);
    CHECK_STR(rs_pkgdb_package(&db, f, &len), "coreutils");
    CHECK_INT(len, 9);
    /* Merged /usr: listed as /bin/true, found as /usr/bin/true. */
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/true", &f), 1);
    CHECK_INT(rs_pkgdb_lookup(&db, "/bin/ls", &f), 1);
    /* Diverted by another package: the file is at the diversion's name;
     * diverted by the package itself, where it was. */
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/diverted.distrib", &f), 1);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/diverted", &f), 0);
    CHECK_INT(db.ndiv, 2);
    /* In the list and the md5sums: one entry, the one with the digest. */
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/changed", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_MD5);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/nomd5", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_NONE);
    /* Conffiles, from the status file. */
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/old.conf", &f), 1);
    CHECK(f->flags & RS_PKGFILE_OBSOLETE);
    CHECK(f->flags & RS_PKGFILE_CONFFILE);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/new.conf", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_NONE);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/with space.conf", &f), 1);
    CHECK(f->digest_kind == RS_PKGDIGEST_MD5);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/gone.conf", &f), 0);
    CHECK_INT(rs_pkgdb_lookup(&db, "/escape", &f), 0);
    CHECK_INT(rs_pkgdb_lookup(&db, "/", &f), 0);
    rs_pkgdb_free(&db);

    TEST_CASE("pkgdb: no dpkg, no database");
    {
        char *empty = rs_test_tmpdir();

        CHECK(!rs_pkgdb_load(&db, empty));
        CHECK(db.nfiles == 0 && db.names == NULL);
        mkdirs(empty, "var/lib/dpkg");
        rs_test_write(empty, "var/lib/dpkg/status", "Package: x\nStatus: install ok installed\n",
                      0644);
        CHECK(!rs_pkgdb_load(&db, empty));
        rs_test_rmtree(empty);
        free(empty);
    }

    TEST_CASE("pkgdb: the parsers, given what dpkg would never write");
    rs_pkgdb_init(&db);
    rs_pkgdb_parse_md5sums(&db, 7, "d41d8cd98f00b204e9800998ecf8427e  x\n");
    rs_pkgdb_parse_list(&db, 7, "/x\n");
    CHECK_INT(db.nfiles, 0);
    CHECK_INT(rs_pkgdb_parse_status(&db, "Package: a\r\nStatus: install ok installed\r\n\r\n"
                                         "Package: b\nStatus:\n\nConffiles:\n /etc/x\n"
                                         " lonely\n\nPackage: c\nStatus: install ok installed\n"
                                         "Conffiles:\n /etc/y d41d8cd98f00b204e9800998ecf8427e"
                                         "   \n"),
              2);
    rs_pkgdb_sort(&db);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/y", &f), 1);
    rs_pkgdb_free(&db);

    rs_rules_init(&rules);
    CHECK(rs_rules_parse(&rules, text, strlen(text), "test", &err));
    CHECK(rs_pkgdb_load(&db, root));
    memset(&o, 0, sizeof(o));
    o.root = root;
    o.rules = &rules;
    o.hash = true;
    o.pkgdb = &db;

    TEST_CASE("scan: each file checked against the package that installed it");
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = find(&m, "/usr/bin/ls");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->package && !e->modified);
    CHECK(e && e->hash_state == RS_HASH_PRESENT);
    CHECK_STR(e ? e->package : "", "coreutils");
    e = find(&m, "/usr/bin/true");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->package);
    e = find(&m, "/usr/bin/diverted.distrib");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->package);
    /* What is at the diverted name is the administrator's. */
    e = find(&m, "/usr/bin/diverted");
    CHECK(e && e->cls == RS_CLASS_STATE && !e->package);
    e = find(&m, "/usr/bin/changed");
    CHECK(e && e->cls == RS_CLASS_STATE && e->modified);
    CHECK_STR(e ? e->package : "", "coreutils");
    e = find(&m, "/usr/bin/nomd5");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->package && !e->modified);
    e = find(&m, "/usr/bin/handmade");
    CHECK(e && e->cls == RS_CLASS_STATE && !e->package);
    /* /etc is state by rule; an untouched conffile is its package's. */
    e = find(&m, "/etc/foo.conf");
    CHECK(e && e->cls == RS_CLASS_BASELINE);
    CHECK_STR(e ? e->package : "", "libfoo");
    e = find(&m, "/etc/old.conf");
    CHECK(e && e->cls == RS_CLASS_BASELINE);
    e = find(&m, "/etc/edited.conf");
    CHECK(e && e->cls == RS_CLASS_STATE && e->modified);
    e = find(&m, "/etc/gone.conf");
    CHECK(e && e->cls == RS_CLASS_STATE && !e->package);
    e = find(&m, "/etc/hosts");
    CHECK(e && e->cls == RS_CLASS_STATE && !e->package);
    /* Directories and the database itself are as the rules say. */
    e = find(&m, "/usr/bin");
    CHECK(e && e->cls == RS_CLASS_BASELINE && !e->package);
    CHECK_INT(st.pkg_unmodified, 5);
    CHECK_INT(st.pkg_modified, 2);
    CHECK_INT(st.unpackaged, 2);
    rs_index_free(&m);

    TEST_CASE("scan: what changed is kept, what matches is not");
    o.store = counting_store;
    stored_count = 0;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = find(&m, "/usr/bin/changed");
    CHECK(e && e->stored && e->hash_state == RS_HASH_PRESENT);
    e = find(&m, "/usr/bin/handmade");
    CHECK(e && e->stored);
    e = find(&m, "/usr/bin/ls");
    CHECK(e && !e->stored && e->hash_state == RS_HASH_PRESENT);
    e = find(&m, "/etc/foo.conf");
    CHECK(e && !e->stored);
    rs_index_free(&m);

    TEST_CASE("scan: with baseline content, a packaged file is compared in the read that keeps it");
    {
        FILE *fp = tmpfile();

        CHECK(fp != NULL);
        o.store = copying_store;
        o.store_baseline = true;
        stored_count = 0;
        rs_progress_json(fp);
        rs_progress_phase("walking", 0);
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        rs_progress_done();
        rs_progress_json(NULL);
        e = find(&m, "/usr/bin/ls");
        CHECK(e && e->stored && e->cls == RS_CLASS_BASELINE && !e->modified);
        CHECK_STR(e && e->package ? e->package : "", "coreutils");
        e = find(&m, "/usr/bin/changed");
        CHECK(e && e->stored && e->cls == RS_CLASS_STATE && e->modified);
        e = find(&m, "/etc/edited.conf");
        CHECK(e && e->stored && e->cls == RS_CLASS_STATE && e->modified);
        CHECK_INT(st.pkg_unmodified, 5);
        CHECK_INT(st.pkg_modified, 2);
        /* Each file read once: as much read as kept. */
        CHECK(st.bytes_hashed > 0);
        CHECK_INT(fp ? (long long)last_read_bytes(fp) : -1, (long long)st.bytes_hashed);
        if (fp)
        {
            (void)fclose(fp);
        }
        rs_index_free(&m);

        /* A store that copies some other way: read again to compare. */
        o.store = counting_store;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        e = find(&m, "/usr/bin/ls");
        CHECK(e && e->stored && e->cls == RS_CLASS_BASELINE && !e->modified);
        e = find(&m, "/usr/bin/changed");
        CHECK(e && e->stored && e->cls == RS_CLASS_STATE && e->modified);
        CHECK_INT(st.pkg_unmodified, 5);
        CHECK_INT(st.pkg_modified, 2);
        rs_index_free(&m);
        o.store_baseline = false;

        /* Without: what changed is copied from the file already open. */
        o.store = copying_store;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        e = find(&m, "/usr/bin/changed");
        CHECK(e && e->stored && e->cls == RS_CLASS_STATE && e->hash_state == RS_HASH_PRESENT);
        e = find(&m, "/usr/bin/ls");
        CHECK(e && !e->stored && e->cls == RS_CLASS_BASELINE);
        rs_index_free(&m);
    }
    o.store = NULL;

    TEST_CASE("scan: an incremental run takes what is unchanged from the last one");
    {
        struct rs_index  prev;
        struct rs_entry *was;

        rs_index_init(&prev);
        o.store = NULL;
        CHECK(rs_scan(&o, &prev, &st, &err));
        o.prev = &prev;
        o.store = counting_store;
        o.have = have_all;
        stored_count = 0;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        /* Nothing read: what is kept the store has, and the rest is as it was. */
        CHECK_INT(stored_count, 0);
        CHECK_INT(st.bytes_hashed, 0);
        CHECK(st.reused >= 14);
        e = find(&m, "/usr/bin/ls");
        CHECK(e && e->cls == RS_CLASS_BASELINE && !e->modified && e->hash_state == RS_HASH_PRESENT);
        CHECK_STR(e && e->package ? e->package : "", "coreutils");
        e = find(&m, "/usr/bin/changed");
        CHECK(e && e->cls == RS_CLASS_STATE && e->modified && e->stored);
        e = find(&m, "/usr/bin/nomd5");
        CHECK(e && e->cls == RS_CLASS_BASELINE && e->package && !e->modified);
        e = find(&m, "/usr/bin/handmade");
        CHECK(e && e->cls == RS_CLASS_STATE && !e->package && e->stored);
        CHECK_INT(st.pkg_unmodified, 5);
        CHECK_INT(st.pkg_modified, 2);
        CHECK_INT(st.unpackaged, 2);
        rs_index_free(&m);

        /* A store without the content: what is kept is read after all. */
        o.have = have_none;
        stored_count = 0;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK(stored_count > 0);
        rs_index_free(&m);

        /* Owned by a package now and not then: read, to be checked. */
        was = (struct rs_entry *)rs_index_find(&prev, "/usr/bin/ls");
        free(was ? was->package : NULL);
        if (was)
        {
            was->package = NULL;
        }
        o.store = NULL;
        o.have = NULL;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        e = find(&m, "/usr/bin/ls");
        CHECK_STR(e && e->package ? e->package : "", "coreutils");
        CHECK(st.bytes_hashed == 9);
        rs_index_free(&m);

        /* A file changed since is read; the count leaves out what is not. */
        rs_test_write(root, "etc/hosts", "127.0.0.1 localhost host\n", 0644);
        o.count_only = true;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK_INT(st.bytes_hashed, 25);
        rs_index_free(&m);
        o.count_only = false;
        o.prev = NULL;
        rs_index_free(&prev);
    }

    TEST_CASE("scan: without hashing, packaged files are still read to compare");
    o.hash = false;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = find(&m, "/usr/bin/ls");
    CHECK(e && e->cls == RS_CLASS_BASELINE && e->hash_state == RS_HASH_NONE);
    rs_index_free(&m);
    o.count_only = true;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    /* ls, true, diverted.distrib, changed, and the three conffiles there. */
    CHECK_INT(st.bytes_hashed, 9 + 11 + 15 + 8 + 4 + 4 + 5);
    rs_index_free(&m);
    o.count_only = false;
    o.hash = true;

    TEST_CASE("scan: a packaged file that cannot be read");
    if (geteuid() != 0)
    {
        char *p = rs_xasprintf("%s/usr/bin/ls", root);

        CHECK(chmod(p, 0) == 0);
        rs_index_init(&m);
        (void)rs_scan(&o, &m, &st, &err);
        e = find(&m, "/usr/bin/ls");
        CHECK(e && e->hash_state == RS_HASH_UNREADABLE && e->cls == RS_CLASS_BASELINE);
        CHECK(st.unreadable >= 1);
        rs_index_free(&m);
        (void)chmod(p, 0755);
        free(p);
    }

    TEST_CASE("scan: --rules-only, the rules alone");
    o.pkgdb = NULL;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = find(&m, "/usr/bin/handmade");
    CHECK(e && e->cls == RS_CLASS_BASELINE && !e->package);
    e = find(&m, "/etc/foo.conf");
    CHECK(e && e->cls == RS_CLASS_STATE);
    CHECK_INT(st.pkg_unmodified + st.pkg_modified + st.unpackaged, 0);

    TEST_CASE("index: a file's package, and whether it changed, written and read back");
    {
        FILE           *fp = tmpfile();
        struct rs_buf   text_out;
        struct rs_index back;
        size_t          i;

        /* Named as a package-aware scan would have named them. */
        for (i = 0; i < m.count; i++)
        {
            if (strcmp(m.entries[i].path, "/usr/bin/changed") == 0 ||
                strcmp(m.entries[i].path, "/usr/bin/ls") == 0)
            {
                m.entries[i].package = rs_xstrdup("coreutils");
                m.entries[i].modified = strcmp(m.entries[i].path, "/usr/bin/changed") == 0;
            }
        }
        CHECK(fp != NULL);
        rs_buf_init(&text_out);
        if (fp)
        {
            char   chunk[4096];
            size_t n;

            CHECK(rs_index_write(&m, fp));
            rewind(fp);
            while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
            {
                rs_buf_add(&text_out, chunk, n);
            }
            (void)fclose(fp);
        }
        rs_buf_add(&text_out, "", 0);
        CHECK_CONTAINS(text_out.data, "\"package\": \"coreutils\", \"modified\": true}");
        rs_index_init(&back);
        CHECK(rs_index_parse(&back, text_out.data, text_out.len, "test", &err));
        e = find(&back, "/usr/bin/changed");
        CHECK(e && e->modified && e->package && strcmp(e->package, "coreutils") == 0);
        e = find(&back, "/usr/bin/ls");
        CHECK(e && !e->modified && e->package);
        e = find(&back, "/etc/hosts");
        CHECK(e && !e->package && !e->modified);
        rs_index_free(&back);
        rs_buf_free(&text_out);
    }
    rs_index_free(&m);

    rs_pkgdb_free(&db);
    rs_rules_free(&rules);
    rs_buf_free(&err);
    rs_test_rmtree(root);
    free(root);
    test_bsd_packages();
}
