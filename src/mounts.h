/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The mounts a walk of the live system goes no further into: network
 * filesystems -- another server's files, which are that server's to back up,
 * and which can hang the walk on a server that is gone -- and automounts,
 * which mount what they stand for the moment anything opens them. Each is
 * told by its filesystem type, never by where it is mounted: mountinfo's on
 * Linux, getmntinfo's (which asks no server) on the BSDs and macOS.
 */
#ifndef RESTATE_MOUNTS_H
#define RESTATE_MOUNTS_H

#include <stdbool.h>
#include <stddef.h>

struct rs_mount {
    char *path;  /* where it is mounted, absolute */
    char *type;  /* "nfs4", "cifs", "autofs", ... */
};

/* True if a filesystem of `type` is a network one, or an automount. */
bool rs_mount_remote_type(const char *type);

/* mountinfo's octal escapes ("\040" for a space) undone. */
char *rs_mount_unescape(const char *s, size_t len);

/* The remote mounts (rs_mount_remote_type) in mountinfo's `text`, in its
 * order; the caller frees them with rs_mounts_free. */
void rs_mounts_parse_mountinfo(const char *text, size_t len, struct rs_mount **out, size_t *n);

/* This host's remote mounts, sorted by path, each path once. */
void rs_mounts_remote(struct rs_mount **out, size_t *n);

void rs_mounts_free(struct rs_mount *m, size_t n);

/*
 * Replaces the mountinfo rs_mounts_remote reads, on every system, for the
 * tests' benefit; NULL restores the default. No option or variable reaches
 * it.
 */
void rs_mounts_set_mountinfo(const char *path);

#endif /* RESTATE_MOUNTS_H */
