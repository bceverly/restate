/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "scan.h"
#include "test.h"

/* Builds a small tree that exercises every kind of entry. */
static void build_tree(const char *root)
{
    char *p;

    p = rs_xasprintf("%s/etc", root);
    (void)mkdir(p, 0755);
    free(p);
    p = rs_xasprintf("%s/usr", root);
    (void)mkdir(p, 0755);
    free(p);
    p = rs_xasprintf("%s/tmp", root);
    (void)mkdir(p, 01777);
    free(p);
    p = rs_xasprintf("%s/var", root);
    (void)mkdir(p, 0755);
    free(p);
    p = rs_xasprintf("%s/var/cache", root);
    (void)mkdir(p, 0755);
    free(p);
    rs_test_write(root, "etc/hosts", "127.0.0.1 localhost\n", 0644);
    rs_test_write(root, "etc/empty", "", 0600);
    rs_test_write(root, "usr/tool", "#!/bin/sh\n", 0755);
    rs_test_write(root, "tmp/junk", "junk", 0644);
    rs_test_write(root, "var/cache/blob", "blob", 0644);
    rs_test_write(root, "etc/daemon.pid", "123\n", 0644);
    p = rs_xasprintf("%s/etc/link", root);
    CHECK(symlink("hosts", p) == 0);
    free(p);
    p = rs_xasprintf("%s/etc/fifo", root);
    CHECK(mkfifo(p, 0600) == 0);
    free(p);
}

static struct rs_rules test_rules_set(void)
{
    struct rs_rules rs;
    struct rs_buf   err;
    const char     *text = "baseline /usr\n"
                           "ephemeral /tmp\n"
                           "expendable /var/cache\n"
                           "ephemeral *.pid\n";

    rs_rules_init(&rs);
    rs_buf_init(&err);
    (void)rs_rules_parse(&rs, text, strlen(text), "test", &err);
    rs_buf_free(&err);
    return rs;
}

/* Each call of the scan's `around`, in order, and how many entries the index
 * had when it came: "b0:N" before group 0, "a0:N" after. */
struct around_log {
    const struct rs_index *ix;
    struct rs_buf         *calls;
    bool                   stop;
};

static bool log_around(const void *ctx, size_t group, bool before)
{
    const struct around_log *l = ctx;

    rs_buf_addf(l->calls, "%s%zu:%zu ", before ? "b" : "a", group, l->ix->count);
    return !(before && l->stop);
}

static int quiet_scan(const void *arg)
{
    const struct rs_scan_opts *o = arg;
    struct rs_index            m;
    struct rs_scan_stats       st;
    struct rs_buf              err;
    int                        unreadable;

    rs_index_init(&m);
    rs_buf_init(&err);
    (void)rs_scan(o, &m, &st, &err);
    unreadable = (int)st.unreadable;
    rs_buf_free(&err);
    rs_index_free(&m);
    return unreadable;
}

/* A store that pretends each file's copy went one of the ways it can go,
 * chosen by name, so the walk's reporting of each can be checked. */
static bool pretend_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                          struct rs_buf *err)
{
    (void)ctx;
    (void)fd;
    (void)st;
    (void)err;
    if (e->type != 'f')
    {
        return true;
    }
    e->hash_state = RS_HASH_PRESENT;
    e->copy = RS_COPY_OK;
    if (strstr(e->path, "hosts"))
    {
        e->copy = RS_COPY_GREW;
    } else if (strstr(e->path, "empty"))
    {
        e->hash_state = RS_HASH_UNREADABLE;
        e->copy = RS_COPY_SHRANK;
    } else if (strstr(e->path, "tool"))
    {
        e->hash_state = RS_HASH_UNREADABLE;
        e->copy = RS_COPY_READ_ERROR;
        e->copy_errno = EIO;
    }
    return true;
}

static int scan_pretending(const void *arg)
{
    struct rs_scan_opts  o = *(const struct rs_scan_opts *)arg;
    struct rs_scan_stats st;
    struct rs_index      m;
    struct rs_buf        err;
    bool                 ok;

    o.store = pretend_store;
    o.store_baseline = true;
    rs_index_init(&m);
    rs_buf_init(&err);
    ok = rs_scan(&o, &m, &st, &err);
    rs_index_free(&m);
    rs_buf_free(&err);
    return ok && st.grew == 1 && st.unreadable == 2 ? 1 : 0;
}

void test_scan(void)
{
    char                  *root = rs_test_tmpdir();
    struct rs_rules        rules = test_rules_set();
    struct rs_scan_opts    o;
    struct rs_scan_stats   st;
    struct rs_index        m;
    struct rs_buf          err;
    const struct rs_entry *e;

    build_tree(root);
    rs_buf_init(&err);
    memset(&o, 0, sizeof(o));
    o.root = root;
    o.rules = &rules;
    o.hash = true;

    TEST_CASE("scan: every kind of entry, classified");
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    CHECK_INT(st.unreadable, 0);
    CHECK(rs_index_find(&m, "/") != NULL);
    e = rs_index_find(&m, "/etc/hosts");
    CHECK(e != NULL);
    if (e)
    {
        CHECK_INT(e->type, 'f');
        CHECK_INT(e->mode, 0644);
        CHECK_INT(e->size, 20);
        CHECK_INT(e->hash_state, RS_HASH_PRESENT);
        CHECK_INT(e->cls, RS_CLASS_STATE);
    }
    e = rs_index_find(&m, "/etc/empty");
    CHECK(e && strcmp(e->hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    e = rs_index_find(&m, "/etc/link");
    CHECK(e && e->type == 'l' && e->target && strcmp(e->target, "hosts") == 0);
    e = rs_index_find(&m, "/etc/fifo");
    CHECK(e && e->type == 'p' && e->hash_state == RS_HASH_NONE);
    e = rs_index_find(&m, "/usr/tool");
    CHECK(e && e->cls == RS_CLASS_BASELINE);
    CHECK(rs_index_find(&m, "/tmp") == NULL);
    CHECK(rs_index_find(&m, "/tmp/junk") == NULL);
    CHECK(rs_index_find(&m, "/var/cache") == NULL);
    CHECK(rs_index_find(&m, "/etc/daemon.pid") == NULL);
    CHECK(rs_index_find(&m, "/var") != NULL);
    CHECK_INT(st.skipped_ephemeral, 2);
    CHECK_INT(st.skipped_expendable, 1);
    CHECK_INT(st.by_class[RS_CLASS_BASELINE], 2);
    CHECK(st.bytes_hashed > 0);
    rs_index_free(&m);

    TEST_CASE("scan: a file written to while copied is kept; one cut short is not");
    {
        char *out = NULL;
        char *errs = NULL;

        CHECK_INT(rs_test_capture(scan_pretending, &o, &out, &errs), 1);
        CHECK_CONTAINS(errs, "/etc/hosts: written to while it was being copied; kept as it was");
        CHECK_CONTAINS(errs, "/etc/empty: cut short while it was being copied");
        CHECK_CONTAINS(errs, "/usr/tool: Input/output error");
        free(out);
        free(errs);
    }

    TEST_CASE("scan: --all keeps expendable paths, --no-hash keeps no digests");
    o.all = true;
    o.hash = false;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    e = rs_index_find(&m, "/var/cache/blob");
    CHECK(e && e->cls == RS_CLASS_EXPENDABLE && e->hash_state == RS_HASH_NONE);
    CHECK_INT(st.bytes_hashed, 0);
    rs_index_free(&m);
    o.all = false;
    o.hash = true;

    TEST_CASE("scan: kept paths are recorded as state, under a directory left out");
    {
        const char *keep[] = { "/var/cache/blob", "/etc/hosts", "/var/cache/missing",
                               "/etc/link/through", "/etc/../etc/hosts", "/" };
        char       *dir = rs_xasprintf("%s/var/cache/sub", root);
        char       *ln = rs_xasprintf("%s/var/cache/sub/escape", root);

        o.keep = keep;
        o.nkeep = sizeof(keep) / sizeof(keep[0]);
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        e = rs_index_find(&m, "/var/cache/blob");
        CHECK(e && e->cls == RS_CLASS_STATE && e->hash_state == RS_HASH_PRESENT);
        /* Recorded once, by the walk, not again. */
        CHECK(rs_index_find(&m, "/etc/hosts") != NULL);
        CHECK(rs_index_find(&m, "/var/cache/missing") == NULL);
        CHECK_INT(st.unreadable, 0);
        CHECK(rs_index_find(&m, "/etc/link/through") == NULL);
        CHECK(rs_index_find(&m, "/var/cache") == NULL);
        rs_index_free(&m);

        /* Never through a symlink on the way. */
        CHECK(mkdir(dir, 0755) == 0);
        CHECK(symlink("/etc", ln) == 0);
        keep[0] = "/var/cache/sub/escape/hosts";
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK(rs_index_find(&m, "/var/cache/sub/escape/hosts") == NULL);
        rs_index_free(&m);

        /* Counted, for a progress total, as the walk would read it. */
        keep[0] = "/var/cache/blob";
        o.count_only = true;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK(st.bytes_hashed >= 4);
        rs_index_free(&m);
        o.count_only = false;
        o.keep = NULL;
        o.nkeep = 0;
        CHECK(unlink(ln) == 0);
        CHECK(rmdir(dir) == 0);
        free(ln);
        free(dir);
    }

    TEST_CASE("scan: deferred paths walked last, each group between its two calls");
    {
        const char *const          g0[] = { "/etc/hosts", "/usr", "/etc/missing" };
        const char *const          g1[] = { "/var/cache/blob", "/tmp/junk" };
        const struct rs_scan_group groups[] = { { g0, 3 }, { g1, 2 } };
        struct around_log          log;
        struct rs_buf              calls;
        size_t                     before;

        rs_index_init(&m);
        log.ix = &m;
        log.stop = false;
        rs_buf_init(&calls);
        log.calls = &calls;
        o.defer = groups;
        o.ndefer = 2;
        o.around = log_around;
        o.around_ctx = &log;
        CHECK(rs_scan(&o, &m, &st, &err));
        /* The rest first; then /etc/hosts, /usr and /usr/tool; then nothing,
         * since the walk would not have gone into /var/cache or /tmp. */
        before = m.count - 3;
        {
            char *want = rs_xasprintf("b0:%zu a0:%zu b1:%zu a1:%zu ", before, before + 3,
                                      before + 3, before + 3);

            CHECK_STR(calls.data, want);
            free(want);
        }
        e = rs_index_find(&m, "/usr/tool");
        CHECK(e && e->cls == RS_CLASS_BASELINE);
        CHECK(rs_index_find(&m, "/etc/hosts") != NULL);
        CHECK(rs_index_find(&m, "/var/cache/blob") == NULL);
        CHECK(rs_index_find(&m, "/tmp/junk") == NULL);
        rs_index_free(&m);

        /* With --all the expendable one is reached too. */
        o.all = true;
        rs_index_init(&m);
        rs_buf_reset(&calls);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK(rs_index_find(&m, "/var/cache/blob") != NULL);
        rs_index_free(&m);
        o.all = false;

        /* Stopped before a group: it is resumed anyway, and nothing after. */
        rs_index_init(&m);
        rs_buf_reset(&calls);
        log.stop = true;
        CHECK(!rs_scan(&o, &m, &st, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "interrupted");
        CHECK(strncmp(calls.data ? calls.data : "", "b0:", 3) == 0);
        CHECK(strstr(calls.data ? calls.data : "", " a0:") != NULL);
        CHECK(strstr(calls.data ? calls.data : "", "b1:") == NULL);
        CHECK(rs_index_find(&m, "/etc/hosts") == NULL);
        rs_index_free(&m);
        rs_buf_reset(&err);

        /* Counting walks everything in place: there is nothing to pause, and
         * `around` is not called, stop or not. */
        o.count_only = true;
        rs_index_init(&m);
        rs_buf_reset(&calls);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK(calls.data == NULL || calls.len == 0);
        rs_index_free(&m);
        o.count_only = false;

        o.defer = NULL;
        o.ndefer = 0;
        o.around = NULL;
        rs_buf_free(&calls);
    }

    TEST_CASE("scan: --one-file-system on a single filesystem changes nothing");
    o.one_fs = true;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    CHECK_INT(st.skipped_mounts, 0);
    CHECK(rs_index_find(&m, "/etc/hosts") != NULL);
    rs_index_free(&m);
    o.one_fs = false;

    TEST_CASE("scan: sockets are never recorded");
    {
        struct sockaddr_un sun;
        char              *sock = rs_xasprintf("%s/etc/s", root);
        int                fd = socket(AF_UNIX, SOCK_STREAM, 0);

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        if (fd >= 0 && strlen(sock) < sizeof(sun.sun_path))
        {
            memcpy(sun.sun_path, sock, strlen(sock));
            if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0)
            {
                rs_index_init(&m);
                CHECK(rs_scan(&o, &m, &st, &err));
                CHECK_INT(st.skipped_sockets, 1);
                CHECK(rs_index_find(&m, "/etc/s") == NULL);
                rs_index_free(&m);
                (void)unlink(sock);
            }
        }
        if (fd >= 0)
        {
            (void)close(fd);
        }
        free(sock);
    }

    TEST_CASE("scan: --verbose names what it skips");
    {
        char *out;
        char *errtext;

        o.verbose = true;
        CHECK_INT(rs_test_capture(quiet_scan, &o, &out, &errtext), 0);
        CHECK_CONTAINS(errtext, "skipped /tmp (ephemeral)");
        CHECK_CONTAINS(errtext, "skipped /var/cache (expendable)");
        free(out);
        free(errtext);
        o.verbose = false;
    }

    TEST_CASE("scan: unreadable paths are counted, not fatal");
    if (geteuid() != 0)
    {
        char *locked = rs_xasprintf("%s/etc/locked", root);
        char *secret = rs_xasprintf("%s/etc/secret", root);
        char *out;
        char *errtext;

        (void)mkdir(locked, 0700);
        rs_test_write(root, "etc/locked/inside", "x", 0644);
        (void)chmod(locked, 0);
        rs_test_write(root, "etc/secret", "s", 0600);
        (void)chmod(secret, 0);
        CHECK_INT(rs_test_capture(quiet_scan, &o, &out, &errtext), 2);
        CHECK_CONTAINS(errtext, "/etc/locked");
        CHECK_CONTAINS(errtext, "/etc/secret");
        free(out);
        free(errtext);
        rs_index_init(&m);
        rs_quiet = true;
        CHECK(rs_scan(&o, &m, &st, &err));
        rs_quiet = false;
        e = rs_index_find(&m, "/etc/secret");
        CHECK(e && e->hash_state == RS_HASH_UNREADABLE);
        CHECK(rs_index_find(&m, "/etc/locked") != NULL);
        rs_index_free(&m);
        (void)chmod(locked, 0700);
        (void)chmod(secret, 0600);
        free(locked);
        free(secret);
    }

    TEST_CASE("scan: hashing refuses anything but the file it was promised");
    {
        char        hex[RS_SHA256_HEX_SIZE];
        char       *etc = rs_xasprintf("%s/etc", root);
        int         dirfd = open(etc, O_RDONLY);
        struct stat st_hosts;
        struct stat st_empty;
        uint64_t    bytes = 0;

        CHECK(dirfd >= 0);
        CHECK(fstatat(dirfd, "hosts", &st_hosts, AT_SYMLINK_NOFOLLOW) == 0);
        CHECK(fstatat(dirfd, "empty", &st_empty, AT_SYMLINK_NOFOLLOW) == 0);
        CHECK(rs_hash_file_at(dirfd, "hosts", &st_hosts, hex, &bytes));
        CHECK_INT(bytes, 20);
        CHECK(rs_hash_file_at(dirfd, "hosts", NULL, hex, NULL));
        /* A different file than the stat described: swapped under us. */
        CHECK(!rs_hash_file_at(dirfd, "hosts", &st_empty, hex, NULL));
        CHECK_INT(errno, ESTALE);
        /* A symlink is not followed. */
        CHECK(!rs_hash_file_at(dirfd, "link", NULL, hex, NULL));
        /* A FIFO opens without blocking and is then refused. */
        CHECK(!rs_hash_file_at(dirfd, "fifo", NULL, hex, NULL));
        CHECK(!rs_hash_file_at(dirfd, "missing", NULL, hex, NULL));
        (void)close(dirfd);
        free(etc);
    }

    TEST_CASE("scan: nesting deeper than the limit is reported, not followed");
    {
        char *deep = rs_xasprintf("%s/etc/d1", root);
        char *p;
        char *errtext;
        char *out;

        (void)mkdir(deep, 0755);
        p = rs_xasprintf("%s/d2", deep);
        (void)mkdir(p, 0755);
        free(p);
        p = rs_xasprintf("%s/d2/d3", deep);
        (void)mkdir(p, 0755);
        free(p);
        /* Two levels below the root are entered -- /etc and /etc/d1 -- and the
         * directory at the third, /etc/d1/d2, is recorded but not entered. */
        o.max_depth = 2;
        CHECK_INT(rs_test_capture(quiet_scan, &o, &out, &errtext), 1);
        CHECK_CONTAINS(errtext, "/etc/d1/d2");
        free(out);
        free(errtext);
        rs_index_init(&m);
        rs_quiet = true;
        CHECK(rs_scan(&o, &m, &st, &err));
        rs_quiet = false;
        CHECK(rs_index_find(&m, "/etc/d1/d2") != NULL);
        CHECK(rs_index_find(&m, "/etc/d1/d2/d3") == NULL);
        rs_index_free(&m);
        o.max_depth = 0;
        rs_index_init(&m);
        CHECK(rs_scan(&o, &m, &st, &err));
        CHECK(rs_index_find(&m, "/etc/d1/d2/d3") != NULL);
        rs_index_free(&m);
        free(deep);
    }

    TEST_CASE("scan: a root that is not there, or not a directory");
    {
        char *file = rs_xasprintf("%s/etc/hosts", root);

        o.root = "/nonexistent/restate-root";
        rs_index_init(&m);
        rs_buf_reset(&err);
        CHECK(!rs_scan(&o, &m, &st, &err));
        CHECK_CONTAINS(err.data, "/nonexistent/restate-root");
        rs_index_free(&m);
        o.root = file;
        rs_buf_reset(&err);
        CHECK(!rs_scan(&o, &m, &st, &err));
        rs_index_free(&m);
        free(file);
    }

    rs_buf_free(&err);
    rs_rules_free(&rules);
    rs_test_rmtree(root);
    free(root);
}
