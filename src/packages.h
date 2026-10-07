/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * What is installed, and where it came from: the package inventory.
 *
 * A reinstall puts back the distribution's own packages. Everything installed
 * since -- by apt from the archive, a PPA or a vendor's repository, by snap,
 * flatpak, pip, npm, cargo -- has to be installed again, and the image does
 * not keep it: the rules leave out what a package manager puts back. This is
 * what lets a restore put it back: the list of what was installed, at which
 * version, from where, and signed with which key.
 *
 * Read from the package managers' own files, never by running them, so it
 * works on a tree mounted from another disk as well as on the running system:
 *
 *   apt      /var/lib/dpkg/status: every package, its version, architecture
 *            and state; /var/lib/apt/extended_states: which were installed by
 *            hand and which as dependencies; /etc/apt/sources.list(.d): every
 *            repository and the key it is signed with; /var/lib/apt/lists:
 *            which repository each installed version can be got from again
 *            -- or that none can, which a restore needs to know first
 *   keys     every key file the repositories name, wherever it is
 *            (/usr/share/keyrings is not kept in an image, and a repository
 *            without its key is one apt refuses), whole
 *   snap     /var/lib/snapd/state.json: each snap, revision, channel and
 *            confinement (root only; otherwise /snap, without channels)
 *   flatpak  each installation, system and per-user: remotes and apps
 *   pip, npm, cargo, pipx, gem
 *            what was installed outside any project: system-wide and in
 *            each home
 *   pkg      OpenBSD's and NetBSD's installed packages
 *   alternatives
 *            the ones chosen by hand (update-alternatives --set), and what
 *            each points at
 *
 * And which other package managers are present at all -- rpm, pacman, apk,
 * Nix, Guix, Homebrew, conda, FreeBSD's pkg, macOS receipts -- so an image
 * says what it has no inventory of rather than leaving it out silently.
 */
#ifndef RESTATE_PACKAGES_H
#define RESTATE_PACKAGES_H

#include <stdbool.h>
#include <stddef.h>

#include "json.h"
#include "util.h"

/*
 * Describes what is installed in the tree at `root` into `out` (an object).
 * What could not be read goes into its "notes" array rather than failing.
 */
void rs_packages_describe(const char *root, struct rs_jval *out);

/*
 * The files that put back what no repository or store can: for each apt
 * package whose installed version is "unavailable", its .deb in apt's cache
 * (/var/cache/apt/archives); for each snap installed from a file, its .snap
 * in snapd's (/var/lib/snapd/snaps). Each one there is marked "kept" in
 * `packages` with its path, and the paths are returned for the capture to
 * keep (the caller frees them). A version no repository has at all that is
 * not there is marked "not_kept" and described in `missing`, a line each; a
 * superseded one is kept if it is there and passed over quietly if not,
 * since a rebuild installs the version that superseded it.
 *
 * `debs` (`ndebs` of them, "NAME=PATH", from capture --deb) name the .deb
 * that is package NAME's where apt's cache does not have it -- the vendor's
 * file in Downloads, say. Each has to be a .deb beneath root, and NAME a
 * package no repository has; one that is not is described in `missing`.
 */
char **rs_packages_keep(const char *root, struct rs_jval *packages, const char *const *debs,
                        size_t ndebs, size_t *n, struct rs_buf *missing);

/* The paths an inventory says were kept ("kept"), for a walk that should
 * keep them again -- verify's, of the tree an image was taken from. The
 * caller frees them. */
char **rs_packages_kept(const struct rs_jval *packages, size_t *n);

/*
 * What `apt-get install` is given to put back the apt packages installed by
 * hand, from an inventory (`packages`): NAME=VERSION where the version
 * installed can still be had and `pinned` is set, so it comes from the
 * repository it came from; NAME where it cannot be, or without `pinned`.
 * ":ARCH" follows the name where it is not the machine's own architecture.
 * None installed from a .deb (those are installed from the file), none
 * named in `skip` (an array of names, or NULL), and no boot loader or kernel,
 * which the installer chooses for the machine it installs onto. The caller
 * frees the words.
 */
char **rs_packages_apt_words(const struct rs_jval *packages, const struct rs_jval *skip,
                             bool pinned, size_t *n);

/*
 * A POSIX sh script that installs the apt packages installed by hand (as
 * rs_packages_apt_words chooses them) as nearly as it can, because one
 * package that cannot be had must not sink all the others, as it does in a
 * single apt-get install. Each is looked up first: at the version recorded
 * where a repository still has it, at the version a repository has now where
 * not -- a vendor that keeps only its newest release -- and passed over, and
 * said so, where none has it at all. Those found are installed together, and
 * if apt refuses even that, one at a time, each failure said. Names and
 * versions that are not what Debian allows them to be are left out, so the
 * script runs nothing the captured tree wrote.
 */
void rs_packages_apt_script(const struct rs_jval *packages, const struct rs_jval *skip,
                            struct rs_buf *out);

/*
 * apt's name for the files it keeps a repository's indexes in, as
 * /var/lib/apt/lists names them: the scheme and any user name dropped, a
 * slash made an underscore, and anything else unusual -- an underscore
 * included -- written %xx. Exposed for the unit tests.
 */
void rs_apt_uri_file(struct rs_buf *out, const char *uri);

#endif /* RESTATE_PACKAGES_H */
