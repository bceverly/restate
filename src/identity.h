/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Making a copy of a machine a machine of its own: restore --as NAME.
 *
 * Some of a machine's state names it to everything else -- its machine-id
 * (from which systemd-networkd and NetworkManager make the DHCP client ID,
 * so copies that share one can be handed the same address), its SSH host
 * keys, its host name, the node keys and agent IDs other systems know it by.
 * The rules class those as identity (rules.h). A capture keeps them, and an
 * ordinary restore puts them back, so the same machine comes back as itself.
 *
 * restore --as leaves the image's identity out instead, and then makes sure
 * the machine has an identity that is its own:
 *
 *   - where the machine has its own -- a fresh install made a machine-id, host
 *     keys and the rest when it installed -- that one is kept;
 *   - where what the machine has is the image's very own -- the restore is
 *     onto the machine the image was taken from, or onto a copy of its disk --
 *     a new one is made where restate knows how (the machine-id, D-Bus's copy
 *     of it, the random seed, and the SSH host keys with ssh-keygen -A where
 *     there is an SSH server), and
 *     otherwise it is removed, for the service it belongs to to make anew
 *     when it next starts (a Tailscale node key, MySQL's auto.cnf, an agent's
 *     registration);
 *   - and the host name is NAME, in /etc/hostname and wherever /etc/hosts
 *     gave the image's own.
 *
 * Only regular files are compared, kept, made or removed: a symlink names
 * another file rather than holding an identity, and a directory is left for
 * its service. Every path is reached from the root a directory at a time,
 * never through a symlink, and every file is written beside its destination
 * and renamed over it.
 *
 * What restate cannot make new is said, not hidden: a WireGuard key has to be
 * made known to the peers, and a PostgreSQL cluster's system identifier is
 * fixed when the cluster is made (it matters only to replication).
 */
#ifndef RESTATE_IDENTITY_H
#define RESTATE_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "index.h"
#include "rules.h"
#include "util.h"

/* Whether `name` is a host name: labels of letters, digits and hyphens, each
 * 1 to 63 long and neither starting nor ending with a hyphen, separated by
 * dots, 253 in all at most. */
bool rs_identity_name_ok(const char *name);

/*
 * Sets leave[i] for each entry of `ix` that is identity: recorded as such,
 * or classed so by `rules` (which may be NULL), so an image captured before
 * the class existed, or under other rules, is read as these rules would have
 * it. leave has ix->count elements. Returns how many were set.
 */
size_t rs_identity_mark(const struct rs_index *ix, const struct rs_rules *rules, bool *leave);

/*
 * Appends `text`, an /etc/hosts, to `out` with each host name that is `old`
 * -- or `old` and a domain after it -- given as `name` instead; addresses
 * and comments as they are. Returns how many names it changed.
 */
size_t rs_identity_hosts(const char *text, size_t len, const char *old, const char *name,
                         struct rs_buf *out);

struct rs_identity_stats {
    uint64_t kept;       /* the machine's own, unlike the image's */
    uint64_t made;       /* made new: the machine-id and the random seed */
    uint64_t removed;    /* the image's own, removed for its service to make anew */
    uint64_t hosts;      /* names changed in /etc/hosts */
    uint64_t failed;     /* could not be made or removed */
    bool     host_keys;  /* new SSH host keys made (ssh-keygen -A) */
};

/*
 * After a restore that left out the entries `leave` marks: under `root`,
 * each of the machine's own kept, each of the image's made new or removed,
 * the host name set to `name` and, in /etc/hosts, given for `old` (NULL
 * when the image's is not known). With `dry_run`, says what it would do and
 * does none of it; with `verbose`, says what it does. False, with `err`
 * set, only if it could not start; what fails on the way is warned of and
 * counted.
 */
bool rs_identity_renew(const char *root, const struct rs_index *ix, const bool *leave,
                       const char *name, const char *old, bool dry_run, bool verbose,
                       struct rs_identity_stats *st, struct rs_buf *err);

#endif /* RESTATE_IDENTITY_H */
