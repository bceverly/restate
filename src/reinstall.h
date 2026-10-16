/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Putting an image's packages back onto a fresh install: restore --packages.
 *
 * What is installed is in the image's inventory (packages.h). Putting it back
 * is apt's work, and snap's and the rest, done as a person would do it at a
 * shell -- so it is written as a POSIX sh script, the one a build sheet
 * prints, and run: restate does not install packages itself, and does not
 * link anything that does.
 *
 * Before the script runs, restore has put the image's kit in place: /etc/apt,
 * with the recorded sources and the keys kept there, and the .deb files no
 * repository has. The script then
 *
 *   writes the keys kept elsewhere (/usr/share/keyrings), from the inventory
 *   copies the baseline cache's packages (baseline.h) into apt's, so apt
 *     installs those exact files rather than downloading them
 *   updates apt's lists, and installs the packages installed by hand -- each
 *     at its version where a repository still has it, from the archive's
 *     snapshot with --exact-versions, or else at the version there is now
 *   installs the kept .deb files, and from the baseline any package apt
 *     could not install at its version (with --exact-versions, any it
 *     installed at another)
 *   sets the holds, and marks each package installed by hand or as a
 *     dependency as the old machine had it
 *   marks what the old machine did not have as a dependency, so that apt
 *     autoremove takes away what nothing it had needs -- never the kernel,
 *     the boot loader, firmware or microcode, which follow the hardware
 *   installs the snaps, the system's flatpaks, and the Python, npm and Ruby
 *     packages installed system-wide, and sets the alternatives chosen by hand
 *
 * Offline, with no network at all, apt is given one repository in place of
 * every source it has: one made in the script's own directory of the
 * baseline cache's packages and the kept .deb files, indexed there by
 * dpkg-deb, with lists of its own, so nothing is fetched and the system's
 * lists are left as they were. Its packages are the ones baseline fetch
 * checked against their vendors' signed indexes, in a cache only root can
 * write, and the kept ones are from the kit restore checked -- so it is
 * marked trusted, unsigned. The snaps, flatpaks and language packages need
 * their stores, so are left out, and said to be; but for a snap the image
 * keeps, installed from its file.
 *
 * Every name and version is checked against what its package manager allows
 * before it goes into the script, and every other word is quoted, so the
 * script runs nothing the captured tree wrote.
 */
#ifndef RESTATE_REINSTALL_H
#define RESTATE_REINSTALL_H

#include <stdbool.h>

#include "json.h"
#include "util.h"

struct rs_reinstall_opts {
    const char *snapshot;   /* --exact-versions: the capture's snapshot ID, or NULL */
    const char *cache;      /* the baseline cache to install from, or NULL */
    bool        offline;    /* --offline: no network (below) */
};

/* The script, into `out`, for the inventory `packages`. */
void rs_reinstall_script(const struct rs_jval *packages, const struct rs_reinstall_opts *o,
                         struct rs_buf *out);

#endif /* RESTATE_REINSTALL_H */
