/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The machine underneath, on the BSDs and macOS.
 *
 * Linux puts its whole storage picture in files (sysfs, the udev database),
 * which machine.c reads. The BSDs keep theirs in the kernel, behind sysctl
 * and ioctl, and each in its own shape:
 *
 *   FreeBSD  GEOM's configuration, as text (sysctl kern.geom.conftxt): disks,
 *            GPT and MBR partitions, GELI providers
 *   OpenBSD  a disklabel per disk (DIOCGDINFO), named by hw.disknames
 *   NetBSD   wedges (DIOCGWEDGEINFO) for GPT disks, a disklabel otherwise
 *   macOS    the hardware, interfaces and mounts only: its disks are
 *            described through frameworks, not libc
 *
 * Each is turned into the same JSON as on Linux -- "disks" with their
 * partitions, "mapped", "mounts", "hardware" -- so an index reads the same
 * whatever made it. The parts that turn what the kernel said into JSON take
 * plain strings and structures, and are tested on every system; the parts
 * that ask the kernel are compiled only where the interface exists.
 */
#ifndef RESTATE_BSD_H
#define RESTATE_BSD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json.h"

/* FreeBSD's kern.geom.conftxt, added to the description's disks and mapped
 * devices. */
void rs_geom_parse(const char *conftxt, struct rs_jval *machine);

/* A partition as a disklabel or a wedge reports it. */
struct rs_bsd_part {
    const char *name;     /* sd0a, dk1 */
    unsigned    number;
    uint64_t    offset;   /* bytes */
    uint64_t    size;     /* bytes */
    const char *type;     /* "4.2BSD", "swap", "ffs", a GPT GUID ... */
    const char *label;    /* a wedge's name, or NULL */
};

/* A disk and its partitions, added to the description's disks. */
void rs_bsd_add_disk(struct rs_jval *machine, const char *name, uint64_t size, uint64_t sector,
                     const char *table, const struct rs_bsd_part *parts, size_t n);

/* One mounted filesystem, added to the description's mounts if it is one
 * that holds data (not devfs, procfs, a tmpfs ...). */
void rs_bsd_add_mount(struct rs_jval *machine, const char *on, const char *from,
                      const char *type, uint64_t size, uint64_t used);

/*
 * What the running BSD or macOS system can say: hardware, firmware, network
 * interfaces, disks and mounts. False where there is nothing to ask -- on
 * Linux, which machine.c describes from its own files.
 */
bool rs_bsd_describe(struct rs_jval *machine);

#endif /* RESTATE_BSD_H */
