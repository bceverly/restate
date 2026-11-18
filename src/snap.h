/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * capture --from-snapshot: the capture read from snapshots of the
 * filesystems the tree is on, taken at one moment, rather than from files
 * that change while they are read.
 *
 * ZFS, on Linux and FreeBSD: every dataset mounted at or under the root is
 * snapshotted with one `zfs snapshot` for each pool -- atomic across that
 * pool's datasets, so a database whose data and logs are on two datasets is
 * caught at one moment -- each named restate-TIME-PID and marked with the
 * user property restate:capture, and read through
 * MOUNTPOINT/.zfs/snapshot/NAME.
 *
 * UFS, on FreeBSD: each filesystem is snapshotted with mksnap_ffs, into
 * MOUNTPOINT/.snap/restate-TIME-PID (.snap made, as newfs makes it, where it
 * is not there); the snapshot file is attached read-only with mdconfig and
 * mounted read-only in a directory of restate's own under /var/run, and read
 * there. UFS stops writes to a filesystem while it takes its snapshot --
 * usually well under a second -- and takes one filesystem's at a time, so
 * two UFS filesystems are each caught at a moment, not the same one.
 *
 * Everything is recorded at its live path, so the image is the one a
 * capture of the live tree would make. What is mounted under the root and
 * is neither -- an EFI partition, a tmpfs -- is read as it is, as without
 * --from-snapshot; a network filesystem is still left out.
 *
 * Only the snapshots restate took in this capture are ever removed: ZFS's by
 * their full names, one at a time, never recursively or by pattern; UFS's by
 * unmounting what restate mounted, detaching the device it attached and
 * removing the file it made. One an earlier capture left -- killed before it
 * could -- is said, with the command that removes it, and left for a person
 * to.
 */
#ifndef RESTATE_SNAP_H
#define RESTATE_SNAP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#include "mounts.h"
#include "scan.h"
#include "util.h"

enum rs_snap_kind {
    RS_SNAP_ZFS = 0,
    RS_SNAP_UFS
};

struct rs_snap_fs {
    enum rs_snap_kind kind;
    char             *name;      /* ZFS: the dataset, "rpool/ROOT/ubuntu"; UFS: its mount point */
    char             *snapdir;   /* where its snapshot is read */
    char             *file;      /* UFS: the snapshot file, MOUNTPOINT/.snap/NAME */
    char             *md;        /* UFS: the device it is attached as, "md3" */
    int               fd;        /* open on snapdir once taken, or -1 */
    bool              taken;     /* the snapshot is there */
    bool              mounted;   /* UFS: mounted on snapdir */
};

struct rs_snap {
    char                  *snapshot;  /* "restate-20261118T030000Z-1234" */
    struct rs_snap_fs     *fs;
    size_t                 nfs;
    struct rs_scan_source *sources;   /* for the walk, sorted by tree path */
    size_t                *of;        /* the filesystem each reads, or SIZE_MAX */
    size_t                 nsources;
    char                 **live;      /* at or under the root, neither: read as they are */
    size_t                 nlive;
    char                 **owned;     /* the sources' paths, to free */
    size_t                 nowned;
    char                  *mounts;    /* UFS: the directory its snapshots are mounted in */
};

/* What an earlier capture left: its name, and the command that removes it. */
struct rs_snap_leftover {
    char *name;
    char *remove;
};

/* restate-YYYYMMDDTHHMMSSZ-PID: what this capture's snapshots are called. */
char *rs_snap_name(time_t when, pid_t pid);

/*
 * What a walk of `root` (absolute, resolved) reads from which snapshot, from
 * the host's mounts `m` (rs_mounts_all), into *z. With `one_fs`, only the
 * root's own filesystem. False, with why, where nothing at or under the
 * root can be snapshotted, or a dataset's name is not one restate would
 * pass to zfs.
 */
bool rs_snap_plan(const char *root, const struct rs_mount *m, size_t n, bool one_fs,
                  const char *snapshot, struct rs_snap *z, struct rs_buf *err);

/* Takes the snapshots and opens each, for the walk. False, with why and
 * with every one it took removed again, if any could not be. */
bool rs_snap_take(struct rs_snap *z, struct rs_buf *err);

/* Closes and removes the snapshots rs_snap_take took. False, with each that
 * could not be removed and the command that would, in `err`. */
bool rs_snap_release(struct rs_snap *z, struct rs_buf *err);

/* "4 ZFS datasets", "1 UFS filesystem", "2 ZFS datasets and 1 UFS
 * filesystem": what z snapshots, for a message. */
void rs_snap_describe(const struct rs_snap *z, struct rs_buf *out);

/* The snapshots of the planned filesystems an earlier capture left behind:
 * marked as restate's, and not this one's. */
void rs_snap_leftovers(const struct rs_snap *z, struct rs_snap_leftover **out, size_t *n);
void rs_snap_leftovers_free(struct rs_snap_leftover *l, size_t n);

/* The names in `zfs list -H -o name,restate:capture` output `text` of
 * snapshots marked as restate's that are not `snapshot`. */
void rs_snap_parse_zfs_leftovers(const char *text, const char *snapshot, char ***out,
                                 size_t *n);

void rs_snap_free(struct rs_snap *z);

/* For the tests: each filesystem's snapshot read from BASE/NAME, with every
 * '/' in its name a '_' -- UFS's taken with mksnap_ffs alone, neither
 * attached nor mounted -- and UFS planned on any system. NULL for the real
 * thing again. */
void rs_snap_pretend(const char *base);

/* For the tests, while pretending: UFS's snapshots attached and mounted
 * too, through whatever mdconfig, mount and umount are set to. */
void rs_snap_pretend_devices(bool on);

#endif /* RESTATE_SNAP_H */
