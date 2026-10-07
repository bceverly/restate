/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Putting an image's files back.
 *
 * tar can unpack an image by hand, and the build sheet used to say so; this
 * is what tar does not do. The image is distrusted: every member has to be
 * an entry the index lists, a regular file's content has to hash to the
 * index's digest before it is put in place -- it is written beside its
 * destination first and renamed over it only then, so a file that does not
 * match never lands -- and a member the index does not list is refused.
 * Nothing it writes can be steered by the tree it writes into: every path is
 * reached from the root one directory at a time with O_NOFOLLOW, a symlink
 * where a directory should be is replaced rather than followed, and every
 * file is created beside its destination and renamed.
 *
 * Then what tar does loosely: owners, modes and times (to the nanosecond)
 * from the index, a directory's set only once its contents are in, so
 * writing them does not undo them; hard links made links again; device
 * nodes, which an image records but does not archive, made from the index.
 *
 * Owners are restored by name. The image's /etc/passwd, /etc/group and
 * their shadows, from its kit, are merged with the system's own (see
 * accounts.h) -- whose packages may have numbered their users differently,
 * and whose installer made an account of its own -- every file's owner is
 * mapped by the names the index records, through the merged accounts, and
 * the merged files are what is written for those four. With numeric_owner,
 * or from an image with no kit (one from before 1.1), the numbers the index
 * records, and the image's own account files, as `tar --numeric-owner`
 * would put them back.
 */
#ifndef RESTATE_RESTORE_H
#define RESTATE_RESTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "index.h"
#include "util.h"

struct rs_restore_opts {
    const char        *root;       /* where the image's "/" goes */
    const char *const *exclude;    /* patterns (as rules use them) left out */
    size_t             nexclude;
    bool               dry_run;    /* check everything, write nothing */
    bool               verbose;    /* name everything put back */
    bool               numeric_owner; /* the index's numbers, not names */
};

struct rs_restore_stats {
    uint64_t files;
    uint64_t directories;
    uint64_t symlinks;
    uint64_t links;       /* hard links made */
    uint64_t other;       /* FIFOs and device nodes */
    uint64_t bytes;
    uint64_t excluded;
    uint64_t refused;     /* not in the index, or not what it says */
    uint64_t failed;      /* could not be written */
    uint64_t missing;     /* the index says stored; the image does not have it */
    uint64_t owners;      /* owners that could not be set (not root) */
    bool     merged;      /* the accounts were merged, owners mapped by name */
};

/*
 * Restores the files of the image at `path`, whose index is `ix`. True if it
 * read the whole image; the stats say what was put back, and what was not.
 */
bool rs_restore(const char *path, const struct rs_index *ix, const struct rs_restore_opts *o,
                struct rs_restore_stats *st, struct rs_buf *err);

#endif /* RESTATE_RESTORE_H */
