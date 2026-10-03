/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gzip.h"
#include "image.h"
#include "scan.h"
#include "tar.h"
#include "test.h"

/* A tar stream in memory. */
struct mem {
    struct rs_buf buf;
    size_t        pos;
    size_t        fail_after;   /* writes allowed before failing; 0: never */
    size_t        writes;
};

static bool mem_write(void *ctx, const void *data, size_t n)
{
    struct mem *m = ctx;

    if (m->fail_after && ++m->writes > m->fail_after)
    {
        errno = ENOSPC;
        return false;
    }
    rs_buf_add(&m->buf, data, n);
    return true;
}

static ssize_t mem_read(void *ctx, void *data, size_t n)
{
    struct mem *m = ctx;
    size_t      left = m->buf.len - m->pos;

    if (n > left)
    {
        n = left;
    }
    /* A short read now and then, as a pipe gives. */
    if (n > 100)
    {
        n = 100;
    }
    memcpy(data, m->buf.data + m->pos, n);
    m->pos += n;
    return (ssize_t)n;
}

static void member(struct rs_tar_writer *w, const char *name, const char *data)
{
    struct rs_tar_member m;

    memset(&m, 0, sizeof(m));
    m.name = name;
    m.typeflag = '0';
    m.mode = 0644;
    m.size = strlen(data);
    m.uname = "root";
    m.gname = "wheel";
    m.mtime.sec = 1700000000;
    m.mtime.nsec = 5;
    m.mtime.set = true;
    m.atime.sec = -2;
    m.atime.nsec = 750000000;
    m.atime.set = true;
    CHECK(rs_tar_header(w, &m));
    CHECK(rs_tar_data(w, data, strlen(data)));
    CHECK(rs_tar_pad(w));
}

/* Runs gzip on `in` into `out`, for building test images by hand. */
static void gzip_file(const char *in, const char *out)
{
    int            ifd = open(in, O_RDONLY);
    int            ofd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    struct rs_gzip gz;
    struct rs_buf  err;
    char           chunk[4096];
    ssize_t        n;

    rs_buf_init(&err);
    CHECK(rs_gzip_compress(ofd, &gz, &err));
    while ((n = read(ifd, chunk, sizeof(chunk))) > 0)
    {
        CHECK(write(gz.fd, chunk, (size_t)n) == n);
    }
    CHECK(rs_gzip_finish(&gz, false, &err));
    (void)close(ifd);
    (void)close(ofd);
    rs_buf_free(&err);
}

void test_image(void)
{
    struct mem           m;
    struct rs_tar_writer w;
    struct rs_buf        name;
    struct rs_buf        content;
    struct rs_buf        err;
    char                *dir = rs_test_tmpdir();

    rs_buf_init(&name);
    rs_buf_init(&content);
    rs_buf_init(&err);

    TEST_CASE("tar: pax record lengths count themselves");
    {
        struct rs_buf r;

        rs_buf_init(&r);
        rs_tar_pax_record(&r, "path", "abc", 3);
        CHECK_STR(r.data, "12 path=abc\n");
        rs_buf_reset(&r);
        /* " k=123456\n" is 10 bytes, so the length has two digits: 12. */
        rs_tar_pax_record(&r, "k", "123456", 6);
        CHECK_STR(r.data, "12 k=123456\n");
        rs_buf_reset(&r);
        /* A 93-byte value is a 97-byte body; two digits make 99, which still
         * has two digits, so it holds. */
        rs_tar_pax_record(&r, "k", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 93);
        CHECK(strncmp(r.data, "99 ", 3) == 0);
        CHECK_INT(r.len, 99);
        rs_buf_reset(&r);
        /* One byte more is a 98-byte body: two digits would make 100, which
         * has three, so the record is 101. */
        rs_tar_pax_record(&r, "k", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 94);
        CHECK(strncmp(r.data, "101 ", 4) == 0);
        CHECK_INT(r.len, 101);
        rs_buf_free(&r);
    }

    TEST_CASE("tar: write members, read the first one back");
    memset(&m, 0, sizeof(m));
    rs_buf_init(&m.buf);
    rs_tar_writer_init(&w, mem_write, &m);
    {
        struct rs_buf longname;
        int           i;

        rs_buf_init(&longname);
        for (i = 0; i < 30; i++)
        {
            rs_buf_addstr(&longname, "dir\xc3\xa9/");
        }
        rs_buf_addstr(&longname, "index.json");
        member(&w, longname.data, "{\"hello\": 1}");
        member(&w, "second", "two");
        CHECK(rs_tar_finish(&w));
        CHECK_INT(m.buf.len % RS_TAR_BLOCK, 0);
        CHECK(rs_tar_read_first(mem_read, &m, 1000, &name, &content, &err));
        CHECK_STR(name.data, longname.data);
        CHECK_STR(content.data, "{\"hello\": 1}");
        rs_buf_free(&longname);
    }
    m.pos = 0;
    rs_buf_reset(&err);
    CHECK(!rs_tar_read_first(mem_read, &m, 4, &name, &content, &err));
    CHECK_CONTAINS(err.data, "larger than 4 bytes");

    TEST_CASE("tar: damaged streams are refused, not misread");
    {
        struct mem bad;

        memset(&bad, 0, sizeof(bad));
        rs_buf_init(&bad.buf);
        rs_buf_add(&bad.buf, m.buf.data, m.buf.len);
        bad.buf.data[10] ^= 0x55;   /* inside the first header's name */
        rs_buf_reset(&err);
        CHECK(!rs_tar_read_first(mem_read, &bad, 1000, &name, &content, &err));
        CHECK_CONTAINS(err.data, "bad header checksum");

        rs_buf_reset(&bad.buf);
        rs_buf_add(&bad.buf, m.buf.data, 700);
        bad.pos = 0;
        rs_buf_reset(&err);
        CHECK(!rs_tar_read_first(mem_read, &bad, 1000, &name, &content, &err));
        CHECK_CONTAINS(err.data, "ends in the middle");

        rs_buf_reset(&bad.buf);
        rs_buf_add(&bad.buf, m.buf.data + m.buf.len - 1024, 1024);
        bad.pos = 0;
        rs_buf_reset(&err);
        CHECK(!rs_tar_read_first(mem_read, &bad, 1000, &name, &content, &err));
        CHECK_CONTAINS(err.data, "empty");
        rs_buf_free(&bad.buf);
    }
    rs_buf_free(&m.buf);

    TEST_CASE("tar: a write failure is reported");
    memset(&m, 0, sizeof(m));
    rs_buf_init(&m.buf);
    m.fail_after = 1;
    rs_tar_writer_init(&w, mem_write, &m);
    {
        struct rs_tar_member t;

        memset(&t, 0, sizeof(t));
        t.name = "x";
        t.typeflag = '5';
        CHECK(!rs_tar_header(&w, &t));
    }
    rs_buf_free(&m.buf);

    TEST_CASE("gzip: found at a fixed path");
    CHECK(rs_gzip_path() != NULL);

    TEST_CASE("image: capture a tree, read its index back");
    {
        char                  *tree = rs_xasprintf("%s/tree", dir);
        char                  *img = rs_xasprintf("%s/img.tgz", dir);
        char                  *sub = rs_xasprintf("%s/etc", tree);
        struct rs_rules        rules;
        struct rs_scan_opts    so;
        struct rs_scan_stats   st;
        struct rs_index        ix;
        struct rs_index        back;
        struct rs_image_writer iw;
        const struct rs_entry *e;
        struct stat            sb;

        (void)mkdir(tree, 0755);
        (void)mkdir(sub, 0755);
        rs_test_write(tree, "etc/conf", "setting=1\n", 0640);
        rs_test_write(tree, "big", "", 0644);
        {
            /* Big enough to span several reads and pipe buffers. */
            char  *big = rs_xasprintf("%s/big", tree);
            FILE  *fp = fopen(big, "w");
            int    i;

            for (i = 0; fp && i < 20000; i++)
            {
                (void)fprintf(fp, "line %d of a file large enough to matter\n", i);
            }
            if (fp)
            {
                (void)fclose(fp);
            }
            free(big);
        }
        rs_rules_init(&rules);
        memset(&so, 0, sizeof(so));
        so.root = tree;
        so.rules = &rules;
        so.hash = true;
        rs_index_init(&ix);
        rs_buf_reset(&err);
        CHECK(rs_image_begin(&iw, img, &err));
        so.store = rs_image_store;
        so.store_ctx = &iw;
        CHECK(rs_scan(&so, &ix, &st, &err));
        CHECK_INT(st.stored, 4);
        ix.created = rs_xstrdup("2026-10-03T00:00:00.000000000Z");
        ix.content = rs_xstrdup("state");
        CHECK(rs_image_finish(&iw, &ix, &err));
        CHECK_STR(err.data ? err.data : "", "");
        CHECK(stat(img, &sb) == 0 && (sb.st_mode & 0777) == 0600);

        rs_index_init(&back);
        CHECK(rs_index_load(&back, img, &err));
        CHECK_INT(back.count, ix.count);
        e = rs_index_find(&back, "/etc/conf");
        CHECK(e && e->hash_state == RS_HASH_PRESENT && e->mode == 0640);
        CHECK(e && e->stored && strcmp(e->stored, "restate/files/etc/conf") == 0);
        e = rs_index_find(&back, "/big");
        CHECK(e && e->size > 500000 && e->hash_state == RS_HASH_PRESENT);
        {
            /* The stored digest is the digest of the file. */
            char hex[RS_SHA256_HEX_SIZE];
            int  dfd = open(tree, O_RDONLY);

            CHECK(rs_hash_file_at(dfd, "big", NULL, hex, NULL));
            CHECK(e && strcmp(e->hash, hex) == 0);
            (void)close(dfd);
        }
        rs_index_free(&back);

        TEST_CASE("image: system tar can unpack it");
        {
            char *cmd = rs_xasprintf("cd '%s' && gzip -dc img.tgz | tar -xf - && "
                                     "cmp tree/etc/conf restate/files/etc/conf", dir);

            CHECK(system(cmd) == 0);
            free(cmd);
        }

        TEST_CASE("image: a store that cannot write stops the scan");
        {
            struct rs_index        ix2;
            struct rs_image_writer bad;

            rs_index_init(&ix2);
            CHECK(rs_image_begin(&bad, img, &err));
            (void)close(bad.content_fd);
            bad.content_fd = open("/dev/full", O_WRONLY);
            if (bad.content_fd >= 0)
            {
                so.store_ctx = &bad;
                rs_buf_reset(&err);
                CHECK(!rs_scan(&so, &ix2, &st, &err));
                CHECK_CONTAINS(err.data, "writing the image");
            }
            rs_image_abort(&bad);
            rs_index_free(&ix2);
        }

        TEST_CASE("image: refusing what is not an image");
        {
            char *notgz = rs_xasprintf("%s/plain.tar", dir);
            char *gz = rs_xasprintf("%s/plain.tgz", dir);
            char *junk = rs_xasprintf("%s/junk.gz", dir);

            /* A real tgz whose first member is not the index. */
            memset(&m, 0, sizeof(m));
            rs_buf_init(&m.buf);
            rs_tar_writer_init(&w, mem_write, &m);
            member(&w, "something/else", "x");
            CHECK(rs_tar_finish(&w));
            {
                FILE *fp = fopen(notgz, "w");

                if (fp)
                {
                    (void)fwrite(m.buf.data, 1, m.buf.len, fp);
                    (void)fclose(fp);
                }
            }
            rs_buf_free(&m.buf);
            gzip_file(notgz, gz);
            rs_index_init(&back);
            rs_buf_reset(&err);
            CHECK(!rs_index_load(&back, gz, &err));
            CHECK_CONTAINS(err.data, "does not start with restate/index.json");
            rs_index_free(&back);

            /* gzip magic, then garbage. */
            rs_test_write(dir, "junk.gz", "\x1f\x8bnot really gzip at all", 0644);
            rs_buf_reset(&err);
            CHECK(!rs_index_load(&back, junk, &err));
            rs_index_free(&back);

            /* An image on standard input is refused with a reason. */
            {
                int saved = dup(STDIN_FILENO);
                int fd = open(img, O_RDONLY);

                (void)dup2(fd, STDIN_FILENO);
                (void)close(fd);
                rs_buf_reset(&err);
                CHECK(!rs_index_load(&back, "-", &err));
                CHECK_CONTAINS(err.data, "cannot be read from standard input");
                (void)dup2(saved, STDIN_FILENO);
                (void)close(saved);
                rs_index_free(&back);
            }
            free(notgz);
            free(gz);
            free(junk);
        }

        TEST_CASE("image: content that changes while it is stored");
        {
            struct rs_image_writer cw;
            struct rs_entry        ce;
            struct stat            fake;
            int                    fd;
            char                  *f = rs_xasprintf("%s/etc/conf", tree);
            char                  *dest = rs_xasprintf("%s/changing.tgz", dir);

            CHECK(rs_image_begin(&cw, dest, &err));
            memset(&ce, 0, sizeof(ce));
            ce.type = 'f';
            ce.path = rs_xstrdup("/etc/conf");
            CHECK(stat(f, &fake) == 0);

            /* It shrank: the header promised more than there was. */
            fake.st_size += 100;
            fd = open(f, O_RDONLY);
            CHECK(rs_image_store(&cw, &ce, fd, &fake, &err));
            (void)close(fd);
            CHECK_INT(ce.hash_state, RS_HASH_UNREADABLE);
            free(ce.stored);
            ce.stored = NULL;

            /* It grew: there was more than the header promised. */
            fake.st_size = 3;
            fd = open(f, O_RDONLY);
            CHECK(rs_image_store(&cw, &ce, fd, &fake, &err));
            (void)close(fd);
            CHECK_INT(ce.hash_state, RS_HASH_UNREADABLE);
            CHECK_INT(cw.tar.offset % RS_TAR_BLOCK, 0);
            free(ce.stored);
            ce.stored = NULL;

            /* A read that fails outright. */
            fake.st_size = 10;
            fd = open(tree, O_RDONLY);
            CHECK(rs_image_store(&cw, &ce, fd, &fake, &err));
            (void)close(fd);
            CHECK_INT(ce.hash_state, RS_HASH_UNREADABLE);
            free(ce.stored);
            ce.stored = NULL;

            /* A device node is in the index, not the archive. */
            ce.type = 'c';
            CHECK(rs_image_store(&cw, &ce, -1, &fake, &err));
            CHECK(ce.stored == NULL);
            rs_entry_free(&ce);

            /* The image is still well-formed, with no creation time given:
             * the clock stands in for it. */
            rs_index_init(&back);
            rs_buf_reset(&err);
            CHECK(rs_image_finish(&cw, &back, &err));
            rs_index_free(&back);
            CHECK(rs_index_load(&back, dest, &err));
            rs_index_free(&back);
            free(f);
            free(dest);
        }

        TEST_CASE("image: every way assembling the image can fail");
        {
            struct rs_image_writer fw;
            struct rs_index        empty;
            char                  *gone = rs_xasprintf("%s/gone", dir);
            char                  *gone_dest = rs_xasprintf("%s/gone/x.tgz", dir);
            char                  *isdir = rs_xasprintf("%s/isdir", dir);
            char                  *inside = rs_xasprintf("%s/isdir/keep", dir);
            int                    p[2];

            rs_index_init(&empty);

            /* The destination's directory vanishes before the end. */
            CHECK(mkdir(gone, 0700) == 0);
            CHECK(rs_image_begin(&fw, gone_dest, &err));
            CHECK(rmdir(gone) == 0);
            rs_buf_reset(&err);
            CHECK(!rs_image_finish(&fw, &empty, &err));
            CHECK_CONTAINS(err.data, gone_dest);

            /* The destination is a directory that will not be replaced. */
            CHECK(mkdir(isdir, 0700) == 0);
            rs_test_write(isdir, "keep", "x", 0600);
            CHECK(rs_image_begin(&fw, isdir, &err));
            rs_buf_reset(&err);
            CHECK(!rs_image_finish(&fw, &empty, &err));
            CHECK_CONTAINS(err.data, isdir);
            CHECK(access(inside, F_OK) == 0);

            /* The content cannot be read back. */
            CHECK(rs_image_begin(&fw, img, &err));
            CHECK(pipe(p) == 0);
            (void)close(fw.content_fd);
            (void)close(p[1]);
            fw.content_fd = p[0];
            rs_buf_reset(&err);
            CHECK(!rs_image_finish(&fw, &empty, &err));
            CHECK_CONTAINS(err.data, "rewinding the content");

            rs_index_free(&empty);
            free(gone);
            free(gone_dest);
            free(isdir);
            free(inside);
        }

        TEST_CASE("image: standard input that cannot be read");
        {
            int saved = dup(STDIN_FILENO);
            int fd = open(dir, O_RDONLY);

            (void)dup2(fd, STDIN_FILENO);
            (void)close(fd);
            rs_index_init(&back);
            rs_buf_reset(&err);
            CHECK(!rs_index_load(&back, "-", &err));
            CHECK_CONTAINS(err.data, "(standard input)");
            (void)dup2(saved, STDIN_FILENO);
            (void)close(saved);
            rs_index_free(&back);
        }

        TEST_CASE("gzip: missing, failing, killed");
        {
            static const char *const missing[] = { "/nonexistent/gzip", "/nonexistent/bin/gzip" };
            static const char *const failing[] = { "/usr/bin/false", "/bin/false" };
            struct rs_gzip           gz;
            struct rs_image_writer   gw;
            struct rs_index          empty;
            int                      devnull = open("/dev/null", O_RDWR);

            rs_index_init(&empty);
            rs_gzip_set_paths(missing, 2);
            CHECK(rs_gzip_path() == NULL);
            rs_buf_reset(&err);
            CHECK(!rs_gzip_compress(devnull, &gz, &err));
            CHECK_CONTAINS(err.data, "could not run gzip");
            rs_buf_reset(&err);
            CHECK(!rs_gzip_decompress(devnull, &gz, &err));
            CHECK_CONTAINS(err.data, "could not run gzip");
            rs_buf_reset(&err);
            CHECK(!rs_index_load(&back, img, &err));
            CHECK_CONTAINS(err.data, "could not run gzip");
            rs_index_free(&back);
            CHECK(rs_image_begin(&gw, img, &err));
            rs_buf_reset(&err);
            CHECK(!rs_image_finish(&gw, &empty, &err));
            CHECK_CONTAINS(err.data, "could not run gzip");

            /* A gzip that exits non-zero, and an image written through it. */
            rs_gzip_set_paths(failing, 2);
            rs_buf_reset(&err);
            CHECK(rs_gzip_compress(devnull, &gz, &err));
            CHECK(!rs_gzip_finish(&gz, false, &err));
            CHECK_CONTAINS(err.data, "gzip failed (exit 1)");
            CHECK(rs_image_begin(&gw, img, &err));
            rs_buf_reset(&err);
            CHECK(!rs_image_finish(&gw, &empty, &err));
            CHECK_CONTAINS(err.data, "gzip");
            rs_gzip_set_paths(NULL, 0);
            CHECK(rs_gzip_path() != NULL);

            /* One killed underneath us; then waited for a second time. */
            rs_buf_reset(&err);
            CHECK(rs_gzip_compress(devnull, &gz, &err));
            CHECK(kill(gz.pid, SIGKILL) == 0);
            CHECK(!rs_gzip_finish(&gz, false, &err));
            CHECK_CONTAINS(err.data, "killed by a signal");
            rs_buf_reset(&err);
            CHECK(!rs_gzip_finish(&gz, false, &err));
            CHECK_CONTAINS(err.data, "waiting for gzip");

            (void)close(devnull);
            rs_index_free(&empty);
        }

        TEST_CASE("image: an unwritable destination fails cleanly");
        rs_buf_reset(&err);
        CHECK(!rs_image_begin(&iw, "/nonexistent/dir/x.tgz", &err));
        CHECK_CONTAINS(err.data, "/nonexistent/dir/x.tgz");

        rs_index_free(&ix);
        rs_rules_free(&rules);
        free(tree);
        free(img);
        free(sub);
    }

    rs_test_rmtree(dir);
    free(dir);
    rs_buf_free(&name);
    rs_buf_free(&content);
    rs_buf_free(&err);
}
