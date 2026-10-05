/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The storage layout of a machine description, as something to rebuild.
 *
 * machine.h records what is there in the shape the system reports it: disks
 * with partitions, device-mapper devices, md arrays, LVM metadata, mounts and
 * fstab, each in its own list. To put the layout back, those have to be one
 * graph -- this LUKS mapping sits on that partition, this volume group on
 * these two mappings, this filesystem is mounted at /home -- and every block
 * device a node in it, with what is on it and where it is mounted.
 *
 * Both `restate buildsheet` and `restate autoinstall` are made from this, so
 * the runbook a person follows and the file an installer follows describe the
 * same layout, and the decisions -- what belongs to another operating system,
 * how big a volume needs to be in a virtual machine -- are made once.
 *
 * Every string points into the machine description, which has to outlive the
 * layout.
 */
#ifndef RESTATE_LAYOUT_H
#define RESTATE_LAYOUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json.h"

enum rs_vol_kind {
    RS_VOL_DISK,      /* a whole disk, used without a partition table */
    RS_VOL_PART,      /* a partition */
    RS_VOL_LUKS,      /* an open LUKS mapping */
    RS_VOL_CRYPT,     /* another dm-crypt mapping (plain, or a tool's own) */
    RS_VOL_MD,        /* a software RAID array */
    RS_VOL_LV,        /* an LVM logical volume */
    RS_VOL_OTHER      /* another device-mapper device */
};

/* Where a machine is being rebuilt. */
enum rs_target {
    RS_TARGET_SAME,   /* the same machine, or one just like it: exact sizes */
    RS_TARGET_VM,     /* a virtual machine: Linux volumes only, sized to use */
    RS_TARGET_METAL   /* other hardware: Linux volumes only, original sizes */
};

struct rs_vol {
    enum rs_vol_kind kind;
    const char      *name;      /* nvme0n1p6, nvme0n1p6_crypt, md0, vg0-root */
    const char      *kname;     /* the kernel's name: dm-0 for a mapping */
    char            *path;      /* /dev/nvme0n1p6, /dev/mapper/..., /dev/md0 */
    uint64_t         size;      /* bytes; 0 if unknown */

    /* What is on it. */
    const char      *fstype;    /* ext4, crypto_LUKS, LVM2_member, swap, ... */
    const char      *usage;     /* filesystem, crypto, raid, other */
    const char      *uuid;
    const char      *label;
    const char      *version;

    /* A partition: its disk, its number and where it lies. */
    size_t           disk;
    unsigned         number;
    uint64_t         start;     /* bytes */
    const char      *ptype;     /* a GPT type GUID, or an MBR type ("0x83") */
    const char      *pname;     /* the GPT partition name */
    const char      *puuid;     /* the GPT partition GUID */
    const char      *pflags;    /* GPT attributes, or MBR flags */

    /* What it is made from: indices into rs_layout.vols. */
    size_t          *parents;
    size_t           nparents;

    /* LUKS. */
    const char      *cipher;
    uint64_t         key_size;  /* bits */
    bool             tpm;       /* a TPM- or network-bound token is enrolled */
    const char      *keyfile;   /* from crypttab, if not "none" */

    /* md. */
    const char      *level;
    const char      *metadata;
    const char      *md_uuid;
    uint64_t         chunk;     /* bytes */

    /* An LVM logical volume: its group and name within it. */
    size_t           vg;
    char            *lvname;

    /* Where it is mounted, from fstab or the mount table. */
    const char      *mountpoint;  /* "/", "/home", "[swap]" */
    const char      *options;     /* the fstab options */
    uint64_t         fs_size;     /* bytes, from statvfs; 0 if not mounted */
    uint64_t         fs_used;
    uint64_t         fs_captured; /* bytes an index records on it, if known */
    bool             captured_known;

    /* Another operating system's: Windows, BitLocker, macOS, a VeraCrypt
     * volume. Never formatted; not carried into a VM or onto new hardware. */
    bool             foreign;
    const char      *foreign_why;
};

struct rs_disk {
    const char *name;
    const char *model;
    const char *serial;
    uint64_t    size;
    uint64_t    sector;      /* the logical block size */
    const char *table;       /* "gpt", "dos", or NULL for none */
    const char *table_uuid;
    bool        rotational;
    bool        removable;
};

struct rs_pv {
    const char *name;        /* pv0 */
    const char *id;
    const char *device;      /* the device LVM recorded */
    size_t      vol;         /* the volume it is, or SIZE_MAX */
};

struct rs_vg {
    char          *name;
    const char    *id;
    const char    *metadata;  /* the text of the /etc/lvm/backup file */
    uint64_t       extent;    /* bytes */
    struct rs_pv  *pvs;
    size_t         npvs;
    struct rs_jval tree;      /* the parsed metadata */
};

struct rs_swapfile {
    const char *file;
    uint64_t    size;
};

struct rs_netmount {
    const char *spec;
    const char *file;
    const char *type;
    const char *options;
};

struct rs_layout {
    struct rs_disk     *disks;
    size_t              ndisks;
    struct rs_vol      *vols;
    size_t              nvols;
    struct rs_vg       *vgs;
    size_t              nvgs;
    struct rs_swapfile *swapfiles;
    size_t              nswapfiles;
    struct rs_netmount *netmounts;
    size_t              nnetmounts;
    const char         *firmware;    /* "uefi", "bios", or NULL */
    bool                secure_boot;
};

/* Builds the layout from a machine description. False if it has no disks. */
bool rs_layout_build(const struct rs_jval *machine, struct rs_layout *out);
void rs_layout_free(struct rs_layout *l);

/* The volume whose kernel name is `name`, or SIZE_MAX. */
size_t rs_layout_find(const struct rs_layout *l, const char *name);

/* The volumes with `parent` among their parents, into `out` (at most `max`);
 * the number found. */
size_t rs_layout_children(const struct rs_layout *l, size_t parent, size_t *out, size_t max);

/* A readable name for a GPT type GUID or MBR type: "EFI system". */
const char *rs_ptype_name(const char *ptype);

/* Whether `ptype` is `type`, ignoring case: GUIDs come in both. */
bool rs_ptype_is(const char *ptype, const char *type);

/*
 * The size a volume should have when rebuilt for `target`: the original size,
 * except in a virtual machine, where a volume holding a filesystem gets what
 * the filesystem uses plus room to grow, and a container the sum of what it
 * holds. 0 means the volume is not rebuilt at all (it is another system's).
 */
uint64_t rs_layout_fit(const struct rs_layout *l, size_t vol, enum rs_target target);

/* "1.2 TiB", "200 MiB": binary units, one decimal place below ten. */
void rs_human_size(uint64_t bytes, char *out, size_t len);

#endif /* RESTATE_LAYOUT_H */
