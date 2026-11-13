/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The build sheet's first half on the BSDs: from what is needed to the first
 * boot of the new system, in each one's own terms.
 *
 *   FreeBSD  gpart, with the GPT labels kept; GELI; newfs, or the ZFS pool
 *            and the datasets that were mounted, the boot environment its
 *            bootfs; the distribution sets unpacked from the memstick, the
 *            boot code or the EFI loader, and enough of /etc to boot
 *   OpenBSD  fdisk, and the disklabel from an autoallocation template of the
 *            sizes it had; then the installer, keeping that label, given
 *            each partition's mount point -- it makes the filesystems, the
 *            sets and the boot code. The restore keeps the new /etc/fstab,
 *            which names the disk by its new DUID
 *   NetBSD   gpt, with the wedges' names kept; newfs; the sets unpacked
 *            from the install image, the boot code or the EFI loader, and
 *            enough of /etc to boot
 *
 * And the same layout, unattended, for `restate autoinstall` (below).
 *
 * The layout code (layout.h) is Linux's: it takes the BSDs' partitions for
 * another system's, never rebuilt, so this reads the machine description
 * itself. The packages and the restore that follow are the build sheet's own
 * (buildsheet.c), the same on every system.
 */
#ifndef RESTATE_BSDSHEET_H
#define RESTATE_BSDSHEET_H

#include <stdbool.h>

#include "autoinstall.h"
#include "buildsheet.h"
#include "json.h"
#include "util.h"

/* Whether `kernel` -- uname's name for the system -- is a BSD this writes
 * sheets for. */
bool rs_bsdsheet_for(const char *kernel);

/*
 * Writes the sheet's steps up to the first boot of the new system to `out`,
 * numbered from `*step` + 1 (and `*step` the last one's after), and adds what
 * is to be noted to `notes` as "  - TEXT\n" lines. False, and why into `err`,
 * if there is nothing to rebuild.
 */
bool rs_bsdsheet_build(const struct rs_jval *machine, const struct rs_sheet_opts *o,
                       struct rs_buf *out, unsigned *step, struct rs_buf *notes,
                       struct rs_buf *err);

/* Whether the restore keeps the new system's /etc/fstab rather than putting
 * the old one back: OpenBSD's names the disk by a DUID that is new. */
bool rs_bsdsheet_keeps_fstab(const struct rs_jval *machine, const struct rs_sheet_opts *o);

/*
 * The BSDs' answer to `restate autoinstall`: an install that asks nothing.
 *
 *   FreeBSD  a bsdinstall script -- /etc/installerconfig on the installer's
 *            media, or `bsdinstall script FILE` -- partitioning by PARTITIONS
 *            for UFS, or by bsdinstall's zfsboot for a pool, its datasets
 *            the ones that were mounted; the sets; and, after, the host
 *            name, network, SSH server, time zone and keymap
 *   OpenBSD  an install.conf response file for autoinstall(8), with the
 *            disklabel template it fetches written into its comments, to be
 *            served beside it
 *
 * Each installs the system and stops: the restore is the build sheet's,
 * from "Put restate on the new system". NetBSD's sysinst reads no answers,
 * and is refused, as are --clones, --firmware and --image-at, which are
 * Ubuntu's. False, and why into `err`, if it cannot be written.
 */
bool rs_bsdsheet_autoinstall(const struct rs_jval *machine, const struct rs_auto_opts *ao,
                             struct rs_buf *out, struct rs_buf *err);

#endif /* RESTATE_BSDSHEET_H */
