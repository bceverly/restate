/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * What changed between two indexes.
 *
 * One merge pass over two sorted lists. A path present only in the new one is
 * Added, only in the old one Deleted, and in both but different Modified --
 * with the kinds of difference named, because "the mode changed" and "the
 * contents changed" call for very different responses.
 *
 * Timestamps alone are not a change when both sides carry a digest: a file
 * whose bytes, mode and owner are the same is the same file, whatever touch(1)
 * or a reader did to its times. Without digests (a scan run with --no-hash)
 * size and mtime are the only evidence there is, so then they count.
 */
#ifndef RESTATE_DIFF_H
#define RESTATE_DIFF_H

#include <stdio.h>

#include "index.h"
#include "json.h"

enum {
    RS_DIFF_TYPE    = 1u << 0,
    RS_DIFF_MODE    = 1u << 1,
    RS_DIFF_OWNER   = 1u << 2,
    RS_DIFF_CONTENT = 1u << 3,
    RS_DIFF_TARGET  = 1u << 4,
    RS_DIFF_XATTRS  = 1u << 5
};

struct rs_diff_stats {
    size_t added;
    size_t deleted;
    size_t modified;
    size_t packages;    /* packages installed, removed or changed (by_packages) */
    size_t explained;   /* file changes a package's change accounts for */
};

/* The RS_DIFF_* bits that differ between two entries for the same path. */
unsigned rs_diff_entries(const struct rs_entry *old, const struct rs_entry *new_);

/* Writes one line per change and fills `stats`. Returns false on an output
 * error. */
bool rs_diff_write(const struct rs_index *old, const struct rs_index *new_,
                   FILE *out, struct rs_diff_stats *stats);

/*
 * The same, by package (diff --packages). First a line for each package
 * whose installation changed between the two inventories -- apt's and
 * snap's -- "I" installed, "R" removed, "U" another version:
 *
 *   U  apt:nginx   1.24.0-1 -> 1.24.0-2, 37 files
 *   I  apt:htop    3.3.0-4, 12 files
 *   R  snap:hello  29
 *
 * (the columns separated by tabs, as rs_diff_write's are)
 *
 * then the file changes that none of those accounts for, as rs_diff_write
 * writes them. A change is accounted for when the file is the changed
 * package's and is what the package put there: added by a package installed
 * or changed, deleted with one removed or changed, or modified as the
 * package's new version has it. A file someone edited is still listed,
 * whatever happened to its package. Without an inventory on both sides,
 * there are no package lines and every file is listed.
 */
bool rs_diff_write_packages(const struct rs_index *old, const struct rs_index *new_,
                            FILE *out, struct rs_diff_stats *stats);

/*
 * Changes as JSON rather than lines: each file change an object appended to
 * `changes` -- {"change": "M", "path": ..., "what": "content,mode"} -- and,
 * by package, each package's to `packages` -- {"change": "U", "manager":
 * "apt", "name": ..., "from": ..., "to": ..., "files": N}. Both made empty
 * arrays here. NULL, NULL goes back to lines.
 */
void rs_diff_json(struct rs_jval *changes, struct rs_jval *packages);

/* "content,mode" and so on, into `out`. */
void rs_diff_describe(unsigned what, struct rs_buf *out);

#endif /* RESTATE_DIFF_H */
