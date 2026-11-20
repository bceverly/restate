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
#include "snap.h"
#include "test.h"
#include "util.h"

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
static const struct rs_scan_source *source_for(const struct rs_snap *z, const char *tree)
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

/* Whether `paths`, run as restate runs program `p` -- its name the first
 * argument -- exits `code`: not so where it is a multi-call binary,
 * busybox's, that runs the applet that argument names. */
static bool stands_in(enum rs_program p, const char *const *paths, size_t n, int code)
{
    char         *name = rs_xstrdup(rs_program_name(p));
    char         *argv[2];
    struct rs_buf err;
    int           got = -1;
    bool          ran;

    argv[0] = name;
    argv[1] = NULL;
    rs_buf_init(&err);
    rs_program_set_paths(p, paths, n);
    ran = rs_run(p, argv, NULL, NULL, &got, &err);
    rs_program_set_paths(p, NULL, 0);
    rs_buf_free(&err);
    free(name);
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
    struct rs_snap               z;
    struct rs_buf                err;
    const struct rs_scan_source *s;
    size_t                       i;

    rs_buf_init(&err);
    TEST_CASE("zfs: a snapshot's name says when, and which capture");
    {
        char *name = rs_snap_name(1795000000, 4242);

        CHECK_STR(name, "restate-20261118T110640Z-4242");
        free(name);
    }

    TEST_CASE("zfs: every dataset under the root, and what is not ZFS read as it is");
    CHECK(rs_snap_plan("/", ubuntu, n, false, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 4);
    if (z.nfs == 4)
    {
        CHECK_STR(z.fs[0].name, "rpool/ROOT/ubuntu_a1");
        CHECK_STR(z.fs[0].snapdir, "/.zfs/snapshot/restate-T-1");
        CHECK_STR(z.fs[1].snapdir, "/boot/.zfs/snapshot/restate-T-1");
        CHECK_STR(z.fs[3].name, "rpool/USERDATA/alice");
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
    rs_snap_free(&z);

    TEST_CASE("zfs: a root inside a dataset reads that part of its snapshot");
    CHECK(rs_snap_plan("/home/bob", ubuntu, n, false, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 1);
    s = source_for(&z, "/");
    CHECK_STR(s ? s->dir : "", "/home/.zfs/snapshot/restate-T-1/bob");
    rs_snap_free(&z);
    CHECK(rs_snap_plan("/home", ubuntu, n, false, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 2);
    s = source_for(&z, "/alice");
    CHECK_STR(s ? s->dir : "", "/home/alice/.zfs/snapshot/restate-T-1");
    rs_snap_free(&z);

    TEST_CASE("zfs: --one-file-system, the root's own dataset alone");
    CHECK(rs_snap_plan("/", ubuntu, n, true, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 1);
    CHECK_INT(z.nsources, 1);
    rs_snap_free(&z);

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

        CHECK(!rs_snap_plan("/", plain, 1, false, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "nothing at or under / is on ZFS");
        rs_buf_reset(&err);
        CHECK(!rs_snap_plan("/", plain, 2, true, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "--one-file-system");
        rs_buf_reset(&err);
        /* ext4 at /, ZFS under it: the dataset from its snapshot. */
        CHECK(rs_snap_plan("/", plain, 2, false, "restate-T-1", &z, &err));
        CHECK_INT(z.nfs, 1);
        CHECK_INT(z.nlive, 1);
        CHECK(source_for(&z, "/") == NULL);
        rs_snap_free(&z);
        CHECK(!rs_snap_plan("/", odd, 1, false, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "not a ZFS dataset's name");
        rs_buf_reset(&err);
        CHECK(!rs_snap_plan("/", spaced, 1, false, "restate-T-1", &z, &err));
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
    struct rs_snap           z;
    struct rs_buf            err;
    char                    *a = rs_xasprintf("%s/rpool_ROOT_x", dir);
    char                    *b = rs_xasprintf("%s/rpool_home", dir);
    char                    *c = rs_xasprintf("%s/tank_data", dir);
    char                   **left;
    size_t                   nleft;
    struct rs_snap_leftover *gone;
    size_t                   ngone;

    rs_buf_init(&err);
    rs_snap_pretend(dir);

    TEST_CASE("zfs: no zfs to run");
    rs_program_set_paths(RS_PROG_ZFS, missing, 1);
    CHECK(rs_snap_plan("/", two, 3, false, "restate-T-1", &z, &err));
    CHECK(!rs_snap_take(&z, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "there is no zfs that restate would run");
    rs_buf_reset(&err);
    rs_snap_leftovers(&z, &gone, &ngone);
    CHECK(gone == NULL && ngone == 0);
    rs_snap_free(&z);

    /* true and false stand in for zfs; where they are busybox's, which runs
     * the applet its first argument names -- "zfs" -- they cannot. */
    if (stands_in(RS_PROG_ZFS, working, 2, 0) && stands_in(RS_PROG_ZFS, failing, 2, 1))
    {
        TEST_CASE("zfs: a snapshot zfs refuses");
        rs_program_set_paths(RS_PROG_ZFS, failing, 2);
        CHECK(rs_snap_plan("/", two, 3, false, "restate-T-1", &z, &err));
        CHECK(!rs_snap_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "zfs snapshot of rpool: exit status 1");
        CHECK(!z.fs[0].taken && !z.fs[2].taken);
        rs_buf_reset(&err);
        rs_snap_leftovers(&z, &gone, &ngone);   /* zfs list failing says none */
        CHECK(ngone == 0);
        rs_snap_leftovers_free(gone, ngone);
        rs_snap_free(&z);

        TEST_CASE("zfs: taken, but one cannot be opened, and all destroyed again");
        rs_program_set_paths(RS_PROG_ZFS, working, 2);
        CHECK(mkdir(a, 0755) == 0 && mkdir(b, 0755) == 0);
        CHECK(rs_snap_plan("/", two, 3, false, "restate-T-1", &z, &err));
        CHECK(!rs_snap_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "tank_data");
        CHECK(!z.fs[0].taken && !z.fs[1].taken && !z.fs[2].taken);
        CHECK(z.fs[0].fd < 0);
        rs_buf_reset(&err);
        rs_snap_free(&z);

        TEST_CASE("zfs: taken and opened for the walk, then destroyed");
        CHECK(mkdir(c, 0755) == 0);
        CHECK(rs_snap_plan("/", two, 3, false, "restate-T-1", &z, &err));
        CHECK(rs_snap_take(&z, &err));
        CHECK(z.fs[0].taken && z.fs[2].taken && z.fs[2].fd >= 0);
        CHECK(source_for(&z, "/") && source_for(&z, "/")->fd == z.fs[0].fd);
        CHECK(source_for(&z, "/tank") && source_for(&z, "/tank")->fd >= 0);
        CHECK(rs_snap_release(&z, &err));
        CHECK(!z.fs[0].taken && z.fs[0].fd < 0);
        CHECK(source_for(&z, "/")->fd < 0);
        rs_snap_free(&z);

        TEST_CASE("zfs: one that cannot be destroyed is said, with how to");
        {
            const struct rs_mount one[] = { mount_of("/", "zfs", "rpool/ROOT/x", false) };

            CHECK(rs_snap_plan("/", one, 1, false, "restate-T-1", &z, &err));
            CHECK(rs_snap_take(&z, &err));
            rs_program_set_paths(RS_PROG_ZFS, failing, 2);
            CHECK(!rs_snap_release(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "",
                           "zfs destroy rpool/ROOT/x@restate-T-1 removes it");
            CHECK(z.fs[0].taken);
            rs_buf_reset(&err);
            rs_snap_free(&z);
        }
    } else
    {
        (void)printf("  (zfs snapshot tests skipped: true and false run as zfs here do not "
                     "exit 0 and 1)\n");
    }

    TEST_CASE("zfs: snapshots an earlier capture left");
    rs_snap_parse_zfs_leftovers("rpool/a@daily\t-\n"
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
    rs_snap_parse_zfs_leftovers(NULL, "restate-T-1", &left, &nleft);
    CHECK(left == NULL && nleft == 0);

    rs_program_set_paths(RS_PROG_ZFS, NULL, 0);
    rs_snap_pretend(NULL);
    rs_buf_free(&err);
    free(a);
    free(b);
    free(c);
}

/* UFS's, pretending: mksnap_ffs alone, with true and false for it. */
static void test_ufs(const char *dir)
{
    static const char *const missing[] = { "/nonexistent/mksnap_ffs" };
    static const char *const failing[] = { "/usr/bin/false", "/bin/false" };
    static const char *const working[] = { "/usr/bin/true", "/bin/true" };
    char                    *fs = rs_xasprintf("%s/ufs", dir);
    char                    *dotsnap = rs_xasprintf("%s/.snap", fs);
    char                    *file = rs_xasprintf("%s/restate-T-1", dotsnap);
    char                    *base = rs_xasprintf("%s/snaps", dir);
    char                    *flat = rs_xstrdup(fs);
    char                    *read_from;
    char                    *p;
    struct rs_snap           z;
    struct rs_buf            err;
    struct rs_buf            said;
    struct rs_snap_leftover *gone;
    size_t                   ngone;

    for (p = flat; *p; p++)
    {
        if (*p == '/')
        {
            *p = '_';
        }
    }
    read_from = rs_xasprintf("%s/%s", base, flat);
    rs_buf_init(&err);
    rs_buf_init(&said);
    CHECK(mkdir(fs, 0755) == 0 && mkdir(dotsnap, 0755) == 0 && mkdir(base, 0755) == 0);

    TEST_CASE("ufs: planned where mksnap_ffs is, read as it is elsewhere");
    {
        const struct rs_mount bsd[] = {
            mount_of("/", "ufs", "/dev/ada0p2", false),
            mount_of("/home", "ufs", "/dev/ada0p3", false),
            mount_of("/var", "zfs", "zroot/var", false),
        };

#ifdef __FreeBSD__
        CHECK(rs_snap_plan("/", bsd, 3, false, "restate-T-1", &z, &err));
        CHECK_INT(z.nfs, 3);
        CHECK_STR(z.nfs > 1 ? z.fs[1].snapdir : "", "/var/run/restate-T-1/1");
        CHECK_STR(z.nfs > 1 ? z.fs[1].file : "", "/home/.snap/restate-T-1");
        rs_snap_free(&z);
#else
        CHECK(rs_snap_plan("/", bsd, 3, false, "restate-T-1", &z, &err));
        CHECK_INT(z.nfs, 1);   /* the ZFS dataset alone */
        CHECK_INT(z.nlive, 2);
        rs_snap_free(&z);
        CHECK(!rs_snap_plan("/", bsd, 2, false, "restate-T-1", &z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "nothing at or under / is on ZFS");
        rs_buf_reset(&err);
#endif
        rs_snap_pretend(base);
        CHECK(rs_snap_plan("/", bsd, 3, false, "restate-T-1", &z, &err));
        CHECK_INT(z.nfs, 3);
        CHECK(z.nfs == 3 && z.fs[0].kind == RS_SNAP_UFS && z.fs[2].kind == RS_SNAP_ZFS);
        CHECK_STR(z.nfs > 0 ? z.fs[0].file : "", "/.snap/restate-T-1");
        rs_snap_describe(&z, &said);
        CHECK_STR(said.data ? said.data : "", "1 ZFS dataset and 2 UFS filesystems");
        rs_snap_free(&z);
        rs_buf_reset(&said);
        CHECK(rs_snap_plan("/", bsd, 1, false, "restate-T-1", &z, &err));
        rs_snap_describe(&z, &said);
        CHECK_STR(said.data ? said.data : "", "1 UFS filesystem");
        rs_snap_free(&z);
    }

    {
        const struct rs_mount one[] = { mount_of(fs, "ufs", "/dev/md9", false) };

        TEST_CASE("ufs: no mksnap_ffs to run");
        rs_program_set_paths(RS_PROG_MKSNAP_FFS, missing, 1);
        CHECK(rs_snap_plan(fs, one, 1, false, "restate-T-1", &z, &err));
        CHECK(!rs_snap_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "there is no mksnap_ffs that restate would run");
        rs_buf_reset(&err);
        rs_snap_free(&z);

        if (stands_in(RS_PROG_MKSNAP_FFS, working, 2, 0) &&
            stands_in(RS_PROG_MKSNAP_FFS, failing, 2, 1))
        {
            TEST_CASE("ufs: a snapshot mksnap_ffs refuses");
            rs_program_set_paths(RS_PROG_MKSNAP_FFS, failing, 2);
            CHECK(rs_snap_plan(fs, one, 1, false, "restate-T-1", &z, &err));
            CHECK(!rs_snap_take(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "", "mksnap_ffs ");
            CHECK_CONTAINS(err.data ? err.data : "", "restate-T-1: exit status 1");
            CHECK(!z.fs[0].taken);
            rs_buf_reset(&err);
            rs_snap_free(&z);

            TEST_CASE("ufs: taken, read, and its file removed after");
            rs_program_set_paths(RS_PROG_MKSNAP_FFS, working, 2);
            CHECK(mkdir(read_from, 0755) == 0);
            rs_test_write(dotsnap, "restate-T-1", "", 0600);   /* as mksnap_ffs makes it */
            CHECK(rs_snap_plan(fs, one, 1, false, "restate-T-1", &z, &err));
            CHECK(rs_snap_take(&z, &err));
            CHECK(z.fs[0].taken && z.fs[0].fd >= 0);
            CHECK(source_for(&z, "/") && source_for(&z, "/")->fd == z.fs[0].fd);
            CHECK(rs_snap_release(&z, &err));
            CHECK(!z.fs[0].taken);
            CHECK(access(file, F_OK) != 0);
            rs_snap_free(&z);

            TEST_CASE("ufs: a .snap made where there is none, refused where it is not one");
            {
                char                 *bare = rs_xasprintf("%s/bare", dir);
                char                 *made = rs_xasprintf("%s/.snap", bare);
                const struct rs_mount fresh[] = { mount_of(bare, "ufs", "/dev/md8", false) };

                CHECK(mkdir(bare, 0755) == 0);
                rs_program_set_paths(RS_PROG_MKSNAP_FFS, failing, 2);
                CHECK(rs_snap_plan(bare, fresh, 1, false, "restate-T-1", &z, &err));
                CHECK(!rs_snap_take(&z, &err));
                CHECK(access(made, F_OK) == 0);
                rs_buf_reset(&err);
                rs_snap_free(&z);
                CHECK(rmdir(made) == 0);
                rs_test_write(bare, ".snap", "a file\n", 0644);
                CHECK(rs_snap_plan(bare, fresh, 1, false, "restate-T-1", &z, &err));
                CHECK(!rs_snap_take(&z, &err));
                CHECK_CONTAINS(err.data ? err.data : "", "where UFS keeps its snapshots");
                rs_buf_reset(&err);
                rs_snap_free(&z);
                free(made);
                free(bare);
            }

            TEST_CASE("ufs: attached and mounted, then unmounted and detached");
            rs_snap_pretend_devices(true);
            rs_program_set_paths(RS_PROG_MKSNAP_FFS, working, 2);
            rs_program_set_paths(RS_PROG_MDCONFIG, missing, 1);
            CHECK(rs_snap_plan(fs, one, 1, false, "restate-T-1", &z, &err));
            CHECK(!rs_snap_take(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "", "there is no mdconfig that restate would run");
            rs_buf_reset(&err);
            rs_snap_free(&z);
            /* true for mdconfig says nothing, which is no memory disk. */
            rs_program_set_paths(RS_PROG_MDCONFIG, working, 2);
            rs_program_set_paths(RS_PROG_MOUNT, working, 2);
            rs_program_set_paths(RS_PROG_UMOUNT, working, 2);
            rs_test_write(dotsnap, "restate-T-1", "", 0600);
            CHECK(rs_snap_plan(fs, one, 1, false, "restate-T-1", &z, &err));
            CHECK(!rs_snap_take(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "", "not a memory disk's name");
            CHECK(!z.fs[0].taken && access(file, F_OK) != 0);
            rs_buf_reset(&err);
            /* As a take that got that far leaves it. */
            z.fs[0].taken = true;
            z.fs[0].md = rs_xstrdup("md7");
            z.fs[0].mounted = true;
            CHECK(rs_snap_release(&z, &err));
            CHECK(!z.fs[0].mounted && z.fs[0].md == NULL && !z.fs[0].taken);
            z.fs[0].md = rs_xstrdup("md7");
            z.fs[0].mounted = true;
            rs_program_set_paths(RS_PROG_UMOUNT, failing, 2);
            CHECK(!rs_snap_release(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "", "was not unmounted");
            CHECK_CONTAINS(err.data ? err.data : "", "mdconfig -d -u 7");
            rs_buf_reset(&err);
            z.fs[0].mounted = false;
            rs_program_set_paths(RS_PROG_MDCONFIG, failing, 2);
            CHECK(!rs_snap_release(&z, &err));
            CHECK_CONTAINS(err.data ? err.data : "", "md7, the snapshot of");
            rs_buf_reset(&err);
            rs_snap_free(&z);
            rs_snap_pretend_devices(false);
            rs_program_set_paths(RS_PROG_MDCONFIG, NULL, 0);
            rs_program_set_paths(RS_PROG_MOUNT, NULL, 0);
            rs_program_set_paths(RS_PROG_UMOUNT, NULL, 0);
        } else
        {
            (void)printf("  (ufs snapshot tests skipped: true and false run as mksnap_ffs here "
                         "do not exit 0 and 1)\n");
        }

        TEST_CASE("ufs: snapshots an earlier capture left in .snap");
        rs_test_write(dotsnap, "restate-old-9", "", 0600);
        rs_test_write(dotsnap, "nightly", "", 0600);
        CHECK(rs_snap_plan(fs, one, 1, false, "restate-T-1", &z, &err));
        rs_snap_leftovers(&z, &gone, &ngone);
        CHECK_INT(ngone, 1);
        CHECK(ngone == 1 && strstr(gone[0].name, "/.snap/restate-old-9") != NULL);
        CHECK(ngone == 1 && strncmp(gone[0].remove, "rm ", 3) == 0);
        rs_snap_leftovers_free(gone, ngone);
        rs_snap_free(&z);
    }

    rs_program_set_paths(RS_PROG_MKSNAP_FFS, NULL, 0);
    rs_snap_pretend(NULL);
    rs_buf_free(&err);
    rs_buf_free(&said);
    free(read_from);
    free(flat);
    free(base);
    free(file);
    free(dotsnap);
    free(fs);
}

static bool not_system_volumes(const char *tree, const void *ctx)
{
    (void)ctx;
    return strncmp(tree, "/System/Volumes", 15) != 0;
}

static bool nothing_wanted(const char *tree, const void *ctx)
{
    (void)tree;
    (void)ctx;
    return false;
}

static void test_apfs(const char *dir)
{
    static const char *const missing[] = { "/nonexistent/tmutil" };
    static const char *const failing[] = { "/usr/bin/false", "/bin/false" };
    static const char *const working[] = { "/usr/bin/true", "/bin/true" };
    /* A Mac, more or less: the sealed system volume at /, the Data volume
     * and the system's others under /System/Volumes, and a USB stick. */
    const struct rs_mount mac[] = {
        mount_of("/", "apfs", "/dev/disk3s1s1", false),
        mount_of("/System/Volumes/Data", "apfs", "/dev/disk3s5", false),
        mount_of("/System/Volumes/Preboot", "apfs", "/dev/disk3s2", false),
        mount_of("/System/Volumes/VM", "apfs", "/dev/disk3s6", false),
        mount_of("/Volumes/STICK", "msdos", "/dev/disk4s1", false),
        mount_of("/dev", "devfs", "devfs", false),
    };
    char                        *base = rs_xasprintf("%s/apfs", dir);
    char                        *links = rs_xasprintf("%s/firmlinks", dir);
    char                        *data = rs_xasprintf("%s/_System_Volumes_Data", base);
    char                        *users = rs_xasprintf("%s/Users", data);
    char                        *pat = rs_xasprintf("%s/Users/pat", data);
    const struct rs_scan_source *s;
    struct rs_snap               z;
    struct rs_buf                err;
    struct rs_buf                said;
    char                        *date;

    rs_buf_init(&err);
    rs_buf_init(&said);
    CHECK(mkdir(base, 0755) == 0);
    rs_test_write(dir, "firmlinks",
                  "/Applications\tApplications\n/Users\tUsers\n/Volumes\tVolumes\n"
                  "/private\tprivate\r\nno-tab\n/abs\t/Users\n/up\t../x\n",
                  0644);

    TEST_CASE("apfs: what tmutil said it made");
    date = rs_snap_parse_tmutil_date("NOTE: local snapshots are considered purgeable\n"
                                     "Created local snapshot with date: 2026-11-18-030000\n");
    CHECK_STR(date ? date : "", "2026-11-18-030000");
    free(date);
    date = rs_snap_parse_tmutil_date("date: 2026-11-18-0300\ndate: 2026-11-18-030001");
    CHECK_STR(date ? date : "", "2026-11-18-030001");
    free(date);
    CHECK(rs_snap_parse_tmutil_date("date: 2026-11-18-03000x") == NULL);
    CHECK(rs_snap_parse_tmutil_date("date: 2026-11-18-0300001") == NULL);
    CHECK(rs_snap_parse_tmutil_date("") == NULL);
    CHECK(rs_snap_parse_tmutil_date(NULL) == NULL);

#ifndef __APPLE__
    TEST_CASE("apfs: read as it is but on macOS");
    CHECK(!rs_snap_plan("/", mac, 6, false, "restate-T-1", &z, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "nothing at or under / is on ZFS");
    rs_buf_reset(&err);
#endif

    TEST_CASE("apfs: the Data volume read from its snapshot, through the firmlinks too");
    rs_snap_pretend(base);
    rs_snap_pretend_firmlinks(links);
    CHECK(rs_snap_plan("/", mac, 6, false, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 3);   /* not the sealed system volume */
    CHECK(z.nfs > 0 && z.fs[0].kind == RS_SNAP_APFS);
    CHECK_STR(z.nfs > 0 ? z.fs[0].name : "", "/System/Volumes/Data");
    CHECK(source_for(&z, "/") == NULL);
    s = source_for(&z, "/Users");
    CHECK_STR(s ? s->dir : "", users);
    CHECK(source_for(&z, "/private") != NULL && source_for(&z, "/Applications") != NULL);
    CHECK(source_for(&z, "/Volumes") != NULL && source_for(&z, "/Volumes/STICK") != NULL);
    CHECK(source_for(&z, "/abs") == NULL && source_for(&z, "/up") == NULL);
    CHECK_INT(z.nlive, 2);   /* the stick and /dev */

    TEST_CASE("apfs: kept to what the walk reads, and nothing else snapshotted");
    CHECK(rs_snap_keep(&z, not_system_volumes, NULL, &err));
    CHECK_INT(z.nfs, 1);
    CHECK(source_for(&z, "/System/Volumes/VM") == NULL);
    CHECK(source_for(&z, "/Users") != NULL && source_for(&z, "/Volumes/STICK") != NULL);
    rs_snap_describe(&z, &said);
    CHECK_STR(said.data ? said.data : "", "1 APFS volume");
    rs_buf_reset(&said);
    rs_snap_free(&z);
    CHECK(rs_snap_plan("/", mac, 6, false, "restate-T-1", &z, &err));
    CHECK(!rs_snap_keep(&z, nothing_wanted, NULL, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "nothing the rules leave in");
    rs_buf_reset(&err);
    rs_snap_free(&z);

    TEST_CASE("apfs: a root beneath a firmlink, and --one-file-system");
    CHECK(rs_snap_plan("/Users/pat", mac, 6, false, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 1);
    s = source_for(&z, "/");
    CHECK_STR(s ? s->dir : "", pat);
    CHECK(rs_snap_keep(&z, nothing_wanted, NULL, &err));   /* the root's own, always */
    rs_snap_free(&z);
    CHECK(rs_snap_plan("/Users/pat", mac, 6, true, "restate-T-1", &z, &err));
    CHECK_INT(z.nfs, 1);
    rs_snap_free(&z);
    CHECK(!rs_snap_plan("/", mac, 2, true, "restate-T-1", &z, &err));
    rs_buf_reset(&err);

    TEST_CASE("apfs: no tmutil to run");
    rs_program_set_paths(RS_PROG_TMUTIL, missing, 1);
    CHECK(rs_snap_plan("/Users/pat", mac, 6, false, "restate-T-1", &z, &err));
    CHECK(!rs_snap_take(&z, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "there is no tmutil that restate would run");
    rs_buf_reset(&err);
    rs_snap_free(&z);

    if (stands_in(RS_PROG_TMUTIL, working, 2, 0) && stands_in(RS_PROG_TMUTIL, failing, 2, 1))
    {
        TEST_CASE("apfs: a snapshot tmutil refuses");
        rs_program_set_paths(RS_PROG_TMUTIL, failing, 2);
        CHECK(rs_snap_plan("/", mac, 2, false, "restate-T-1", &z, &err));
        CHECK(!rs_snap_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "tmutil localsnapshot: exit status 1");
        CHECK(z.apfs == NULL && !z.fs[0].taken);
        rs_buf_reset(&err);
        rs_snap_free(&z);

        TEST_CASE("apfs: taken, read, and deleted by its date after");
        rs_program_set_paths(RS_PROG_TMUTIL, working, 2);
        CHECK(mkdir(data, 0755) == 0);
        CHECK(rs_snap_plan("/", mac, 2, false, "restate-T-1", &z, &err));
        CHECK(rs_snap_take(&z, &err));
        CHECK_STR(z.apfs ? z.apfs : "", "2026-01-01-000000");
        CHECK(z.fs[0].taken && z.fs[0].fd >= 0);
        CHECK(rs_snap_release(&z, &err));
        CHECK(z.apfs == NULL && !z.fs[0].taken);
        rs_snap_free(&z);
        CHECK(rs_snap_plan("/", mac, 2, false, "restate-T-1", &z, &err));
        CHECK(rs_snap_take(&z, &err));
        rs_program_set_paths(RS_PROG_TMUTIL, failing, 2);
        CHECK(!rs_snap_release(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "",
                       "tmutil deletelocalsnapshots 2026-01-01-000000 removes it");
        CHECK(z.apfs != NULL);
        rs_buf_reset(&err);
        rs_snap_free(&z);
        CHECK(rmdir(data) == 0);

        TEST_CASE("apfs: mounted, then unmounted");
        rs_snap_pretend_devices(true);
        rs_program_set_paths(RS_PROG_TMUTIL, working, 2);
        rs_program_set_paths(RS_PROG_MOUNT_APFS, failing, 2);
        rs_program_set_paths(RS_PROG_UMOUNT, working, 2);
        CHECK(rs_snap_plan("/", mac, 2, false, "restate-T-1", &z, &err));
        CHECK(!rs_snap_take(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "leave /System/Volumes/Data out with --exclude");
        CHECK(z.apfs == NULL);   /* deleted again */
        CHECK(access(data, F_OK) != 0);
        rs_buf_reset(&err);
        rs_snap_free(&z);
        /* true for mount_apfs mounts nothing, but says it did. */
        rs_program_set_paths(RS_PROG_MOUNT_APFS, working, 2);
        CHECK(rs_snap_plan("/", mac, 2, false, "restate-T-1", &z, &err));
        CHECK(rs_snap_take(&z, &err));
        CHECK(z.fs[0].mounted && z.fs[0].fd >= 0);
        rs_program_set_paths(RS_PROG_UMOUNT, failing, 2);
        CHECK(!rs_snap_release(&z, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "was not unmounted");
        CHECK_CONTAINS(err.data ? err.data : "", "still mounted");
        CHECK(z.apfs != NULL && z.fs[0].mounted);
        rs_buf_reset(&err);
        rs_program_set_paths(RS_PROG_UMOUNT, working, 2);
        CHECK(rs_snap_release(&z, &err));
        CHECK(z.apfs == NULL && !z.fs[0].mounted);
        CHECK(access(data, F_OK) != 0);
        rs_snap_free(&z);
        rs_snap_pretend_devices(false);
        rs_program_set_paths(RS_PROG_MOUNT_APFS, NULL, 0);
        rs_program_set_paths(RS_PROG_UMOUNT, NULL, 0);
    } else
    {
        (void)printf("  (apfs snapshot tests skipped: true and false run as tmutil here do "
                     "not exit 0 and 1)\n");
    }

    rs_program_set_paths(RS_PROG_TMUTIL, NULL, 0);
    rs_snap_pretend(NULL);
    rs_buf_free(&err);
    rs_buf_free(&said);
    free(pat);
    free(users);
    free(data);
    free(links);
    free(base);
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

void test_snapshots(void)
{
    char *dir = rs_test_tmpdir();

    test_plan();
    test_take(dir);
    test_ufs(dir);
    test_apfs(dir);
    test_walk(dir);
    rs_test_rmtree(dir);
    free(dir);
}
