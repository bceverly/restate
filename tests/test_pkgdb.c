/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "md5.h"
#include "pkgdb.h"
#include "scan.h"
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
    CHECK(f->flags & RS_PKGFILE_MD5);
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
    CHECK(f->flags & RS_PKGFILE_MD5);
    CHECK_INT(rs_pkgdb_lookup(&db, "/usr/bin/nomd5", &f), 1);
    CHECK(!(f->flags & RS_PKGFILE_MD5));
    /* Conffiles, from the status file. */
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/old.conf", &f), 1);
    CHECK(f->flags & RS_PKGFILE_OBSOLETE);
    CHECK(f->flags & RS_PKGFILE_CONFFILE);
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/new.conf", &f), 1);
    CHECK(!(f->flags & RS_PKGFILE_MD5));
    CHECK_INT(rs_pkgdb_lookup(&db, "/etc/with space.conf", &f), 1);
    CHECK(f->flags & RS_PKGFILE_MD5);
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
    o.store = NULL;

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
}
