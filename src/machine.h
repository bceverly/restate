/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The machine underneath the files: what it is, and how its disks are laid out.
 *
 * A file-level image is half a restore. The other half is the machine it goes
 * back onto -- the partition table, the encrypted volumes, the LVM volume
 * groups, the filesystems and the UUIDs that /etc/fstab and /etc/crypttab
 * name -- and this records it, so `restate buildsheet` can say how to rebuild
 * it and `restate autoinstall` can rebuild it unattended.
 *
 * Everything is read from files rather than from tools: sysfs and the udev
 * database for disks, partitions and filesystems, /proc for mounts and swap,
 * LVM's own text backups under /etc/lvm/backup, and the LUKS header for the
 * cipher -- the one part that needs root. What cannot be read is recorded as
 * unknown, never guessed.
 *
 * The description is a JSON object, kept in the index as "machine":
 *
 *   system    os-release identity, kernel, architecture, hostname, and the
 *             media the machine was first installed from
 *   hardware  vendor, product, CPU, memory, network interfaces
 *   firmware  UEFI or BIOS, Secure Boot, the boot loaders installed
 *   disks     each disk, its partition table and partitions, and what is on
 *             each: a filesystem, LUKS, an LVM physical volume, a RAID member
 *   mapped    device-mapper devices: LUKS mappings and LVM logical volumes
 *   lvm       each volume group, from its metadata backup
 *   raid      software RAID arrays
 *   mounts    the persistent filesystems mounted now
 *   fstab, crypttab, swap
 *
 * Linux in this version. On another system the description holds the system
 * section and says the rest is not yet supported there.
 */
#ifndef RESTATE_MACHINE_H
#define RESTATE_MACHINE_H

#include <stdbool.h>

#include "json.h"
#include "util.h"

/*
 * Describes the machine into `out` (an object). `sysroot` is where /sys,
 * /proc and /run are -- "/" for the running system; the unit tests point it at
 * a fake tree -- and `root` is the filesystem whose /etc is read. Things that
 * could not be read are noted in out's "notes" array rather than failing.
 */
void rs_machine_describe(const char *sysroot, const char *root, struct rs_jval *out);

/*
 * Parses LVM's text metadata (an /etc/lvm/backup file) into a JSON tree:
 * sections become objects, "key = value" members, and lists arrays. False on
 * malformed input, with a reason in `err`. Exposed for the unit tests and the
 * fuzzer; LVM metadata is input like any other.
 */
bool rs_lvm_parse(const char *text, size_t len, struct rs_jval *out, struct rs_buf *err);

/*
 * Reads the cipher and key size out of a LUKS1 or LUKS2 header in `hdr`
 * (`len` bytes from the start of the device) into `out`. False if it is not a
 * LUKS header or is malformed.
 */
bool rs_luks_parse(const unsigned char *hdr, size_t len, struct rs_jval *out);

#endif /* RESTATE_MACHINE_H */
