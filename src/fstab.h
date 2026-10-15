/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Whether an image's /etc/fstab and /etc/crypttab fit the machine it is put
 * back on.
 *
 * They name disks: UUID=, PARTUUID=, LABEL=, PARTLABEL=, or a path in /dev.
 * Put back onto the machine they came from, or onto one the build sheet laid
 * out with the old UUIDs, every one is there. Put back onto a machine laid
 * out afresh -- by an installer, as a test VM is -- they name the old
 * machine's disks, and it does not boot cleanly: a filesystem it has to
 * mount cannot be found, so systemd stops in emergency mode, and the next
 * initramfs takes in a crypttab that unlocks nothing.
 *
 * Read from the image's machine description, which records both tables, so
 * nothing has to be read out of the image first. Only what is needed at boot
 * counts: an entry marked noauto or nofail does not stop it, and a network
 * filesystem, a bind mount or a swap file names no disk.
 */
#ifndef RESTATE_FSTAB_H
#define RESTATE_FSTAB_H

#include <stdbool.h>

#include "json.h"
#include "util.h"

/*
 * Whether the image's tables, from its machine description `machine`, name
 * a disk that `dev` (the machine's /dev) does not have; each such entry is
 * added to `why`, as "UUID=D01E-8437 (/boot/efi)", separated by ", ".
 * False when every disk is there, or the description records neither table.
 */
bool rs_fstab_foreign(const struct rs_jval *machine, const char *dev, struct rs_buf *why);

#endif /* RESTATE_FSTAB_H */
