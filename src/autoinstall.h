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
 * password for the first account, which the restore replaces anyway. The
 * packages installed since the original install are a later version's.
 */
#ifndef RESTATE_AUTOINSTALL_H
#define RESTATE_AUTOINSTALL_H

#include <stdbool.h>

#include "json.h"
#include "layout.h"
#include "util.h"

struct rs_auto_opts {
    enum rs_target target;
    const char    *image;    /* the image it was made from, or NULL */
    const char    *version;  /* restate's, for the header */
};

/* Writes the autoinstall file for `machine` to `out`. */
bool rs_autoinstall(const struct rs_jval *machine, const struct rs_auto_opts *o,
                    struct rs_buf *out, struct rs_buf *err);

#endif /* RESTATE_AUTOINSTALL_H */
