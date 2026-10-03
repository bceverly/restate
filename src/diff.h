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

enum {
    RS_DIFF_TYPE    = 1u << 0,
    RS_DIFF_MODE    = 1u << 1,
    RS_DIFF_OWNER   = 1u << 2,
    RS_DIFF_CONTENT = 1u << 3,
    RS_DIFF_TARGET  = 1u << 4
};

struct rs_diff_stats {
    size_t added;
    size_t deleted;
    size_t modified;
};

/* The RS_DIFF_* bits that differ between two entries for the same path. */
unsigned rs_diff_entries(const struct rs_entry *old, const struct rs_entry *new_);

/* Writes one line per change and fills `stats`. Returns false on an output
 * error. */
bool rs_diff_write(const struct rs_index *old, const struct rs_index *new_,
                   FILE *out, struct rs_diff_stats *stats);

/* "content,mode" and so on, into `out`. */
void rs_diff_describe(unsigned what, struct rs_buf *out);

#endif /* RESTATE_DIFF_H */
