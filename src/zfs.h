/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * capture --from-snapshot on ZFS: the capture read from snapshots of the datasets
 * the tree is on, taken at one moment, rather than from files that change
 * while they are read.
 *
 * Every ZFS dataset mounted at or under the root is snapshotted, with one
 * `zfs snapshot` for each pool -- atomic across that pool's datasets, so a
 * database whose data and logs are on two datasets is caught at one moment
 * -- each snapshot named restate-TIME-PID and marked with the user property
 * restate:capture. The walk then reads each dataset's snapshot, through
 * MOUNTPOINT/.zfs/snapshot/NAME, in place of the dataset: everything is
 * recorded at its live path, so the image is the one a capture of the live
 * tree would make. What is mounted under the root and is not ZFS -- an EFI
 * partition, a /boot on ext4 -- is read as it is, as it would be without
 * --from-snapshot; a network filesystem is still left out.
 *
 * Only the snapshots restate took in this capture are ever destroyed: by
 * their full names, one at a time, never recursively and never by pattern.
 * One an earlier capture left behind -- killed before it could destroy it --
 * is said, with the command that removes it, and left for a person to.
 */
#ifndef RESTATE_ZFS_H
#define RESTATE_ZFS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#include "mounts.h"
#include "scan.h"
#include "util.h"

struct rs_zfs_dataset {
    char *name;     /* "rpool/ROOT/ubuntu" */
    char *snapdir;  /* its mount point's .zfs/snapshot/NAME */
    int   fd;       /* open on snapdir once taken, or -1 */
    bool  taken;
};

struct rs_zfs {
    char                  *snapshot;  /* "restate-20261118T030000Z-1234" */
    struct rs_zfs_dataset *datasets;
    size_t                 ndatasets;
    struct rs_scan_source *sources;   /* for the walk, sorted by tree path */
    size_t                *of;        /* the dataset each reads, or SIZE_MAX */
    size_t                 nsources;
    char                 **live;      /* at or under the root, not ZFS: read as they are */
    size_t                 nlive;
    char                 **owned;     /* the sources' paths, to free */
    size_t                 nowned;
};

/* restate-YYYYMMDDTHHMMSSZ-PID: what this capture's snapshots are called. */
char *rs_zfs_snapshot_name(time_t when, pid_t pid);

/*
 * What a walk of `root` (absolute, resolved) reads from which snapshot, from
 * the host's mounts `m` (rs_mounts_all), into *z. With `one_fs`, only the
 * root's own filesystem. False, with why, where nothing at or under the
 * root is on ZFS, or a dataset's name is not one restate would pass to zfs.
 */
bool rs_zfs_plan(const char *root, const struct rs_mount *m, size_t n, bool one_fs,
                 const char *snapshot, struct rs_zfs *z, struct rs_buf *err);

/* Takes the snapshots and opens each, for the walk. False, with why and
 * with every one it took destroyed again, if any could not be. */
bool rs_zfs_take(struct rs_zfs *z, struct rs_buf *err);

/* Closes and destroys the snapshots rs_zfs_take took. False, with each that
 * could not be destroyed and the command that would, in `err`. */
bool rs_zfs_release(struct rs_zfs *z, struct rs_buf *err);

/* The snapshots of the planned datasets an earlier capture left behind:
 * marked restate:capture, and not this one's. */
void rs_zfs_leftovers(const struct rs_zfs *z, char ***out, size_t *n);

/* The names in `zfs list -H -o name,restate:capture` output `text` of
 * snapshots marked as restate's that are not `snapshot`. */
void rs_zfs_parse_leftovers(const char *text, const char *snapshot, char ***out, size_t *n);

void rs_zfs_free(struct rs_zfs *z);

/* For the tests: each dataset's snapshot read from BASE/NAME, with every '/'
 * in its name a '_', in place of its .zfs directory. NULL for .zfs again. */
void rs_zfs_pretend(const char *base);

#endif /* RESTATE_ZFS_H */
