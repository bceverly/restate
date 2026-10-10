/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * An Ubuntu autoinstall file that rebuilds a machine without anyone at it.
 *
 * Ubuntu's installer reads a YAML file -- from a CIDATA volume, or over HTTP --
 * and installs without asking anything. This writes one from a machine
 * description: the storage layout in curtin's terms (the same graph the build
 * sheet walks: partitions, LUKS, RAID, LVM, filesystems and mounts, with the
 * filesystem UUIDs kept where curtin can keep them), the locale, keyboard and
 * time zone, the host name, the network interfaces, and the SSH server.
 *
 * Two things cannot come from a description and are left as CHANGE-ME for the
 * person to fill in: a LUKS passphrase, which curtin needs in the file, and a
 * password for the first account, which the restore replaces anyway.
 *
 * With a package inventory (packages.h), the snaps go in the installer's own
 * snaps section. With the image's path as the installer will see it, too,
 * the late-commands put the rest back as the build sheet does, packages
 * before files: /etc/apt and the keys outside it, the packages installed by
 * hand at their versions, the ones the image keeps, holds, flatpaks,
 * system-wide pip, npm and gems, the alternatives chosen by hand -- then the
 * image's files, and the initramfs and boot loader rebuilt over them.
 */
#ifndef RESTATE_AUTOINSTALL_H
#define RESTATE_AUTOINSTALL_H

#include <stdbool.h>

#include "json.h"
#include "layout.h"
#include "util.h"

struct rs_auto_opts {
    enum rs_target        target;
    const char           *image;      /* the image it was made from, or NULL */
    const char           *version;    /* restate's, for the header */
    const struct rs_jval *packages;   /* the package inventory, or NULL */
    const char           *image_at;   /* the image as the installer sees it, or NULL */
    bool                  old_image;  /* the image is one stream, from before 1.1 */
    /* restore's say in whom to trust, as it is put on its command line
     * ("--trusted-key /tmp/restate-trusted.gpg", "--allow-unverified"), or
     * NULL for the restate of an image too old to know; and the keyring
     * that --trusted-key names, in base64, written there first. */
    const char           *trust;
    const char           *trust_keyring;
};

/* Where the autoinstall file puts the keyring restore checks the image
 * against, in the installer's own filesystem. */
#define RS_AUTO_TRUSTED_KEYRING "/tmp/restate-trusted.gpg"

/* Writes the autoinstall file for `machine` to `out`. */
bool rs_autoinstall(const struct rs_jval *machine, const struct rs_auto_opts *o,
                    struct rs_buf *out, struct rs_buf *err);

#endif /* RESTATE_AUTOINSTALL_H */
