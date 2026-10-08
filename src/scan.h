/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Walking a filesystem tree into an index.
 *
 * The walk never follows a symbolic link and never opens anything by a path
 * longer than one component. Every directory and file is opened relative to
 * its parent's descriptor with O_NOFOLLOW and checked against what fstatat
 * said it was, so a directory swapped for a symlink in the middle of a scan --
 * by a user who owns something under /home, say -- cannot steer a scan running
 * as root into reading somewhere else and recording it under their name.
 *
 * Files are opened with O_NOATIME where the system has it, so reading a file
 * to hash or store it does not change the access time the index records.
 */
#ifndef RESTATE_SCAN_H
#define RESTATE_SCAN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include "index.h"
#include "pkgdb.h"
#include "rules.h"

/*
 * How many directories deep a scan goes. A real system is a few dozen deep at
 * most; this is far beyond that, and close to where each level's open
 * descriptor would exhaust the default limit anyway.
 */
#define RS_SCAN_MAX_DEPTH 1000

/*
 * Where an image's content goes. Called once for every entry whose content is
 * to be kept, in walk order, before the entry is added to the index. For a
 * regular file `fd` is open on it and the callback must read it to the end,
 * filling e->hash and e->hash_state as it goes -- one read serves both the
 * digest and the copy, so the digest describes exactly the bytes stored. For
 * anything else `fd` is -1. The callback sets e->stored.
 *
 * Returning false stops the scan: the destination failed (a full disk), and
 * an image with a hole in it is worse than none.
 */
typedef bool (*rs_store_fn)(void *ctx, struct rs_entry *e, int fd,
                            const struct stat *st, struct rs_buf *err);

struct rs_scan_opts {
    const char            *root;      /* the directory to treat as "/" */
    const struct rs_rules *rules;
    bool                   hash;      /* compute content digests */
    bool                   all;       /* record expendable paths too */
    bool                   one_fs;    /* do not descend into other filesystems */
    bool                   verbose;   /* report every skipped path */
    unsigned               max_depth; /* 0: RS_SCAN_MAX_DEPTH */
    rs_store_fn            store;     /* NULL: an index only, no content */
    void                  *store_ctx;
    bool                   store_baseline; /* keep baseline content too */
    /* Walk and classify only, recording nothing and reading no file: the
     * bytes the same walk would read are added up in stats->bytes_hashed,
     * which is what lets a progress bar show a percentage. */
    bool                   count_only;
    /* Files recorded and kept as state whatever the rules say, even under a
     * directory the walk leaves out: the packages no repository has, from
     * apt's and snapd's caches. Each is reached as the walk reaches anything,
     * one directory at a time, never through a symlink. */
    const char *const     *keep;
    size_t                 nkeep;
    /* The package manager's record of the files it installed (pkgdb.h), or
     * NULL to classify by the rules alone. With it, every regular file the
     * rules call baseline or state is checked against its package:
     *
     *   - one that still matches what its package installed is baseline,
     *     with the package named, wherever it is -- an unchanged conffile in
     *     /etc, a vendor's files in /opt
     *   - one that does not is state, "modified", and kept
     *   - one in a baseline tree -- /usr, /boot -- that no package installed
     *     is state, and kept: it was put there by hand
     *
     * so the rules' "baseline" comes to mean "where only packages put
     * files", and a scan no longer takes that on trust. */
    const struct rs_pkgdb *pkgdb;
};

struct rs_scan_stats {
    uint64_t recorded;
    uint64_t by_class[4];     /* indexed by enum rs_class */
    uint64_t skipped_ephemeral;
    uint64_t skipped_expendable;
    uint64_t skipped_sockets;
    uint64_t skipped_mounts;
    uint64_t unreadable;
    uint64_t grew;            /* kept as they were when their copy began */
    uint64_t pkg_unmodified;  /* files as their package installed them */
    uint64_t pkg_modified;    /* files changed since their package installed them */
    uint64_t unpackaged;      /* files in a baseline tree no package installed */
    uint64_t bytes_hashed;
    uint64_t stored;
};

/*
 * Returns true if the walk completed -- possibly with unreadable paths, which
 * are counted in stats->unreadable and warned about -- and false if it could
 * not start at all or the store callback failed, with the reason in `err`.
 */
bool rs_scan(const struct rs_scan_opts *opts, struct rs_index *out,
             struct rs_scan_stats *stats, struct rs_buf *err);

/*
 * Opens the regular file `name` relative to `dirfd` for reading, refusing to
 * follow a symlink and refusing anything that is not, once open, the same
 * regular file `expect` describes (NULL: any regular file). -1 with errno set
 * on failure; ESTALE means it changed between the stat and the open.
 */
int rs_open_regular_at(int dirfd, const char *name, const struct stat *expect);

/* Reads `fd` to the end, hashing it. */
bool rs_hash_fd(int fd, char hex[RS_SHA256_HEX_SIZE], uint64_t *bytes);

/* rs_open_regular_at and rs_hash_fd together. */
bool rs_hash_file_at(int dirfd, const char *name, const struct stat *expect,
                     char hex[RS_SHA256_HEX_SIZE], uint64_t *bytes);

#endif /* RESTATE_SCAN_H */
