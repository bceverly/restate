/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "index.h"
#include "mounts.h"
#include "rules.h"
#include "run.h"
#include "scan.h"
#include "test.h"
#include "util.h"
#include "zfs.h"

static struct rs_mount mount_of(const char *path, const char *type, const char *source, bool part)
{
    struct rs_mount m;

    m.path = (char *)(uintptr_t)path;
    m.type = (char *)(uintptr_t)type;
    m.source = (char *)(uintptr_t)source;
    m.part = part;
    return m;
}

/* The source z has for `tree`, or NULL. */
static const struct rs_scan_source *source_for(const struct rs_zfs *z, const char *tree)
{
    size_t i;

    for (i = 0; i < z->nsources; i++)
    {
        if (strcmp(z->sources[i].tree, tree) == 0)
        {
            return &z->sources[i];
        }
    }
    return NULL;
}

/* Whether `paths`, run as restate runs zfs -- "zfs" its first argument --
 * exits `code`: not so where it is a multi-call binary, busybox's, that
 * runs the applet that argument names. */
static bool stands_in(const char *const *paths, size_t n, int code)
{
    static char   name[] = "zfs";
    char         *argv[] = { name, NULL };
    struct rs_buf err;
    int           got = -1;
    bool          ran;

    rs_buf_init(&err);
    rs_program_set_paths(RS_PROG_ZFS, paths, n);
    ran = rs_run(RS_PROG_ZFS, argv, NULL, NULL, &got, &err);
    rs_program_set_paths(RS_PROG_ZFS, NULL, 0);
    rs_buf_free(&err);
    return ran && got == code;
}

static bool stop_now(void)
{
    return true;
}

static void test_plan(void)
{
    /* An Ubuntu installed on ZFS, more or less. */
    const struct rs_mount ubuntu[] = {
        mount_of("/", "zfs", "rpool/ROOT/ubuntu_a1", false),
        mount_of("/boot", "zfs", "bpool/BOOT/ubuntu_a1", false),
        mount_of("/boot/efi", "vfat", "/dev/nvme0n1p1", false),
        mount_of("/home", "zfs", "rpool/USERDATA/home", false),
        mount_of("/home/alice", "zfs", "rpool/USERDATA/alice", false),
        mount_of("/mnt/nas", "nfs4", "nas:/tank", false),
        mount_of("/proc", "proc", "proc", false),
        mount_of("/srv/bound", "zfs", "rpool/data", true),
        mount_of("/var/lib/x/.zfs/snapshot/old", "zfs", "rpool/x@old", false),
    };
    const size_t                 n = sizeof(ubuntu) / sizeof(ubuntu[0]);
    struct rs_zfs                z;
    struct rs_buf                err;
    const struct rs_scan_source *s;
    size_t                       i;

    rs_buf_init(&err);
    TEST_CASE("zfs: a snapshot's name says when, and which capture");
    {
        char *name = rs_zfs_snapshot_name(1795000000, 4242);

        CHECK_STR(name, "restate-20261118T110640Z-4242");
        free(name);
    }

    TEST_CASE("zfs: every dataset under the root, and what is not ZFS read as it is");
    CHECK(rs_zfs_plan("/", ubuntu, n, false, "restate-T-1", &z, &err));
    CHECK_INT(z.ndatasets, 4);
    if (z.ndatasets == 4)
    {
        CHECK_STR(z.datasets[0].name, "rpool/ROOT/ubuntu_a1");
        CHECK_STR(z.datasets[0].snapdir, "/.zfs/snapshot/restate-T-1");
        CHECK_STR(z.datasets[1].snapdir, "/boot/.zfs/snapshot/restate-T-1");
        CHECK_STR(z.datasets[3].name, "rpool/USERDATA/alice");
    }
    s = source_for(&z, "/");
    CHECK_STR(s ? s->dir : "", "/.zfs/snapshot/restate-T-1");
    s = source_for(&z, "/home/alice");
    CHECK_STR(s ? s->dir : "", "/home/alice/.zfs/snapshot/restate-T-1");
    s = source_for(&z, "/boot/efi");
    CHECK_STR(s ? s->dir : "", "/boot/efi");
    s = source_for(&z, "/srv/bound");   /* a bind of a directory: as it is */
    CHECK_STR(s ? s->dir : "", "/srv/bound");
    CHECK(source_for(&z, "/mnt/nas") == NULL);   /* the walk leaves it out */
    for (i = 1; i < z.nsources; i++)
    {
        CHECK(strcmp(z.sources[i - 1].tree, z.sources[i].tree) < 0);
    }
    CHECK_INT(z.nlive, 4);
    CHECK_STR(z.nlive > 0 ? z.live[0] : "", "/boot/efi");
    rs_zfs_free(&z);

    TEST_CASE("zfs: a root inside a dataset reads that part of its snapshot");
    CHECK(rs_zfs_plan("/home/bob", ubuntu, n, false, "restate-T-1", &z, &err));
    CHECK_INT(z.ndatasets, 1);
    s = source_for(&z, "/");
    CHECK_STR(s ? s->dir : "", "/home/.zfs/snapshot/restate-T-1/bob");
    rs_zfs_free(&z);
    CHECK(rs_zfs_plan("/home", ubuntu, n, false, "restate-T-1", &z, &err));
    CHECK_INT(z.ndatasets, 2);
    s = source_for(&z, "/alice");
    CHECK_STR(s ? s->dir : "", "/home/alice/.zfs/snapshot/restate-T-1");
    rs_zfs_free(&z);

    TEST_CASE("zfs: --one-file-system, the root's own dataset alone");
    CHECK(rs_zfs_plan("/", ubuntu, n, true, "restate-T-1", &z, &err));
    CHECK_INT(z.ndatasets, 1);
    CHECK_INT(z.nsources, 1);
    rs_zfs_free(&z);

    TEST_CASE("zfs: nothing on ZFS, or a dataset restate will not name to zfs");
    {
        const struct rs_mount plain[] = {
            mount_of("/", "ext4", "/dev/sda1", false),
            mount_of("/tank", "zfs", "tank", false),
        };
        const struct rs_mount odd[] = {
            mount_of("/", "zfs", "-o", false),
        };
        const struct rs_mount spaced[] = {
            mount_of("/", "zfs", "rpool/my data", false),
        };

        CHECK(!rs_zfs_plan("/", plain, 1, false, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "nothing at or under / is on ZFS");
        rs_buf_reset(&err);
        CHECK(!rs_zfs_plan("/", plain, 2, true, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "--one-file-system");
        rs_buf_reset(&err);
        /* ext4 at /, ZFS under it: the dataset from its snapshot. */
        CHECK(rs_zfs_plan("/", plain, 2, false, "restate-T-1", &z, &err));
        CHECK_INT(z.ndatasets, 1);
        CHECK_INT(z.nlive, 1);
        CHECK(source_for(&z, "/") == NULL);
        rs_zfs_free(&z);
        CHECK(!rs_zfs_plan("/", odd, 1, false, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "not a ZFS dataset's name");
        rs_buf_reset(&err);
        CHECK(!rs_zfs_plan("/", spaced, 1, false, "restate-T-1", &z, &err));
        rs_buf_reset(&err);
    }
    rs_buf_free(&err);
}

static void test_take(const char *dir)
{
    static const char *const missing[] = { "/nonexistent/zfs" };
    static const char *const failing[] = { "/usr/bin/false", "/bin/false" };
    static const char *const working[] = { "/usr/bin/true", "/bin/true" };
    const struct rs_mount    two[] = {
        mount_of("/", "zfs", "rpool/ROOT/x", false),
        mount_of("/home", "zfs", "rpool/home", false),
        mount_of("/tank", "zfs", "tank/data", false),
    };
    struct rs_zfs            z;
    struct rs_buf            err;
    char                    *a = rs_xasprintf("%s/rpool_ROOT_x", dir);
    char                    *b = rs_xasprintf("%s/rpool_home", dir);
    char                    *c = rs_xasprintf("%s/tank_data", dir);
    char                   **left;
    size_t                   nleft;

    rs_buf_init(&err);
    rs_zfs_pretend(dir);

    TEST_CASE("zfs: no zfs to run");
    rs_program_set_paths(RS_PROG_ZFS, missing, 1);
    CHECK(rs_zfs_plan("/", two, 3, false, "restate-T-1", &z, &err));
    CHECK(!rs_zfs_take(&z, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "there is no zfs that restate would run");
    rs_buf_reset(&err);
    rs_zfs_leftovers(&z, &left, &nleft);
    CHECK(left == NULL && nleft == 0);
    rs_zfs_free(&z);

    /* true and false stand in for zfs; where they are busybox's, which runs
     * the applet its first argument names -- "zfs" -- they cannot. */
    if (stands_in(working, 2, 0) && stands_in(failing, 2, 1))
    {
        TEST_CASE("zfs: a snapshot zfs refuses");
        rs_program_set_paths(RS_PROG_ZFS, failing, 2);
        CHECK(rs_zfs_plan("/", two, 3, false, "restate-T-1", &z, &err));
        CHECK(!rs_zfs_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "zfs snapshot of rpool: exit status 1");
        CHECK(!z.datasets[0].taken && !z.datasets[2].taken);
        rs_buf_reset(&err);
        rs_zfs_leftovers(&z, &left, &nleft);   /* zfs list failing says none */
        CHECK(nleft == 0);
        rs_zfs_free(&z);

        TEST_CASE("zfs: taken, but one cannot be opened, and all destroyed again");
        rs_program_set_paths(RS_PROG_ZFS, working, 2);
        CHECK(mkdir(a, 0755) == 0 && mkdir(b, 0755) == 0);
        CHECK(rs_zfs_plan("/", two, 3, false, "restate-T-1", &z, &err));
        CHECK(!rs_zfs_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "tank_data");
        CHECK(!z.datasets[0].taken && !z.datasets[1].taken && !z.datasets[2].taken);
        CHECK(z.datasets[0].fd < 0);
        rs_buf_reset(&err);
        rs_zfs_free(&z);

        TEST_CASE("zfs: taken and opened for the walk, then destroyed");
        CHECK(mkdir(c, 0755) == 0);
        CHECK(rs_zfs_plan("/", two, 3, false, "restate-T-1", &z, &err));
        CHECK(rs_zfs_take(&z, &err));
        CHECK(z.datasets[0].taken && z.datasets[2].taken && z.datasets[2].fd >= 0);
        CHECK(source_for(&z, "/") && source_for(&z, "/")->fd == z.datasets[0].fd);
        CHECK(source_for(&z, "/tank") && source_for(&z, "/tank")->fd >= 0);
        CHECK(rs_zfs_release(&z, &err));
        CHECK(!z.datasets[0].taken && z.datasets[0].fd < 0);
        CHECK(source_for(&z, "/")->fd < 0);
        rs_zfs_free(&z);

        TEST_CASE("zfs: one that cannot be destroyed is said, with how to");
        {
            const struct rs_mount one[] = { mount_of("/", "zfs", "rpool/ROOT/x", false) };

            CHECK(rs_zfs_plan("/", one, 1, false, "restate-T-1", &z, &err));
            CHECK(rs_zfs_take(&z, &err));
            rs_program_set_paths(RS_PROG_ZFS, failing, 2);
            CHECK(!rs_zfs_release(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "",
                           "zfs destroy rpool/ROOT/x@restate-T-1 removes it");
            CHECK(z.datasets[0].taken);
            rs_buf_reset(&err);
            rs_zfs_free(&z);
        }
    } else
    {
        (void)printf("  (zfs snapshot tests skipped: true and false run as zfs here do not "
                     "exit 0 and 1)\n");
    }

    TEST_CASE("zfs: snapshots an earlier capture left");
    rs_zfs_parse_leftovers("rpool/a@daily\t-\n"
                           "rpool/a@restate-old-1\trestate-old-1\n"
                           "rpool/a@restate-T-1\trestate-T-1\n"
                           "no tab here\n"
                           "rpool/b@restate-old-2\trestate-old-2",
                           "restate-T-1", &left, &nleft);
    CHECK_INT(nleft, 2);
    CHECK_STR(nleft > 0 ? left[0] : "", "rpool/a@restate-old-1");
    CHECK_STR(nleft > 1 ? left[1] : "", "rpool/b@restate-old-2");
    while (nleft > 0)
    {
        free(left[--nleft]);
    }
    free(left);
    rs_zfs_parse_leftovers(NULL, "restate-T-1", &left, &nleft);
    CHECK(left == NULL && nleft == 0);

    rs_program_set_paths(RS_PROG_ZFS, NULL, 0);
    rs_zfs_pretend(NULL);
    rs_buf_free(&err);
    free(a);
    free(b);
    free(c);
}

/* A walk with `s` read from `dir`, into *st. */
static void reread(const struct rs_scan_opts *o, struct rs_scan_source *s, const char *dir,
                   struct rs_scan_stats *st)
{
    struct rs_index m;
    struct rs_buf   err;

    s->dir = dir;
    rs_index_init(&m);
    rs_buf_init(&err);
    CHECK(rs_scan(o, &m, st, &err));
    rs_index_free(&m);
    rs_buf_free(&err);
}

/* The walk reading from elsewhere, as it reads a snapshot. */
static void test_walk(const char *dir)
{
    struct rs_rules       rules;
    struct rs_scan_opts   o;
    struct rs_scan_stats  st;
    struct rs_index       m;
    struct rs_buf         err;
    struct rs_scan_source src[4];
    const char           *text = "ephemeral /tmp\nephemeral /data/more\n";
    char                 *live = rs_xasprintf("%s/live", dir);
    char                 *snap = rs_xasprintf("%s/snap", dir);
    char                 *other = rs_xasprintf("%s/other", dir);
    const char           *keep[] = { "/data/more" };
    int                   fd;

    rs_rules_init(&rules);
    rs_buf_init(&err);
    (void)rs_rules_parse(&rules, text, strlen(text), "test", &err);
    /* The live tree, as it is now; its snapshot, as it was; and what is
     * mounted on its empty /data. */
    CHECK(mkdir(live, 0755) == 0 && mkdir(snap, 0755) == 0 && mkdir(other, 0755) == 0);
    rs_test_write(live, "etc-now", "now\n", 0644);
    rs_test_write(snap, "etc-then", "then\n", 0644);
    {
        char *p = rs_xasprintf("%s/data", snap);

        CHECK(mkdir(p, 0755) == 0);
        free(p);
    }
    rs_test_write(other, "kept", "kept\n", 0644);
    rs_test_write(other, "more", "more\n", 0644);
    fd = open(snap, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(fd >= 0);
    memset(src, 0, sizeof(src));
    src[0].tree = "/";
    src[0].dir = snap;
    src[0].fd = fd;
    src[1].tree = "/data";
    src[1].dir = other;
    src[1].fd = -1;
    src[2].tree = "/tmp";   /* left out: not opened, so not missed */
    src[2].dir = "/nonexistent";
    src[2].fd = -1;
    src[3].tree = "/zz";    /* nothing there to read it in place of */
    src[3].dir = "/nonexistent";
    src[3].fd = -1;

    memset(&o, 0, sizeof(o));
    o.root = live;
    o.rules = &rules;
    o.hash = true;
    o.sources = src;
    o.nsources = 4;

    TEST_CASE("scan: a root and a mount read from elsewhere, recorded where they are");
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    CHECK(rs_index_find(&m, "/etc-then") != NULL);
    CHECK(rs_index_find(&m, "/etc-now") == NULL);
    CHECK(rs_index_find(&m, "/data/kept") != NULL && rs_index_find(&m, "/data/more") == NULL);
    CHECK_INT(st.unreadable, 0);
    rs_index_free(&m);

    TEST_CASE("scan: a path kept whatever the rules say, reached through one");
    o.keep = keep;
    o.nkeep = 1;
    rs_index_init(&m);
    CHECK(rs_scan(&o, &m, &st, &err));
    CHECK(rs_index_find(&m, "/data/more") != NULL);
    rs_index_free(&m);
    o.keep = NULL;
    o.nkeep = 0;

    TEST_CASE("scan: one that is not there is gone, as a path removed meanwhile is");
    reread(&o, &src[1], "/nonexistent/mount", &st);
    CHECK_INT(st.vanished, 1);
    CHECK_INT(st.unreadable, 0);
    /* A file, not a directory: unreadable. */
    rs_test_write(dir, "plain", "x", 0644);
    {
        char *plain = rs_xasprintf("%s/plain", dir);

        reread(&o, &src[1], plain, &st);
        CHECK_INT(st.unreadable, 1);
        free(plain);
    }
    src[1].dir = other;

    TEST_CASE("scan: asked to stop, it stops");
    o.stop = stop_now;
    rs_index_init(&m);
    CHECK(!rs_scan(&o, &m, &st, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "interrupted");
    rs_index_free(&m);
    rs_buf_reset(&err);

    (void)close(fd);
    rs_rules_free(&rules);
    rs_buf_free(&err);
    free(live);
    free(snap);
    free(other);
}

void test_zfs(void)
{
    char *dir = rs_test_tmpdir();

    test_plan();
    test_take(dir);
    test_walk(dir);
    rs_test_rmtree(dir);
    free(dir);
}
