/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The build sheet: a plain-text runbook for rebuilding a machine.
 *
 * It is written for a person at a console with the installer booted: what
 * hardware is needed, the commands that recreate the partitions, encryption,
 * RAID, LVM, filesystems and swap -- with the same UUIDs, so the /etc/fstab
 * and /etc/crypttab that come back with the files still name the right
 * volumes -- then how to point the installer at that layout, what to do after
 * it, how to install the packages again -- repositories and keys first,
 * then each package at the version that was installed -- and how to put the
 * files back.
 *
 * Nothing is run. Every command is printed for the person to read, check
 * against `lsblk`, and run, because every one of them destroys data.
 */
#ifndef RESTATE_BUILDSHEET_H
#define RESTATE_BUILDSHEET_H

#include <stdbool.h>

#include "json.h"
#include "layout.h"
#include "util.h"

struct rs_sheet_opts {
    enum rs_target        target;
    const char           *image;      /* the image the sheet was made from, or NULL */
    const char           *version;    /* restate's, for the heading */
    const struct rs_jval *packages;   /* the package inventory (packages.h), or NULL */
    bool                  old_image;  /* the image is one stream, from before 1.1 */
};

/* Writes the build sheet for `machine` (a machine.h description) to `out`. */
bool rs_buildsheet(const struct rs_jval *machine, const struct rs_sheet_opts *o,
                   struct rs_buf *out, struct rs_buf *err);

#endif /* RESTATE_BUILDSHEET_H */
