/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The package baseline: the exact packages a machine had, fetched.
 *
 * An inventory says which version of each apt package was installed and
 * which repositories had it. A rebuild months later finds many of those
 * versions gone: the archive moves on, a vendor keeps only its newest
 * release. `restate baseline fetch` gets them while they can be had -- every
 * package at the version recorded, as a .deb -- into a cache that
 * `restore --packages` installs from.
 *
 * Nothing fetched is taken on trust. Each repository's index (InRelease, or
 * Release and Release.gpg) is checked with gpgv against the keys the source
 * names, as apt checks it; the Packages list is checked against the index's
 * SHA-256 for it; and each .deb against the list's SHA-256 for it. A version
 * the archive no longer has is looked for in the archive's snapshot as of the
 * capture -- or, for one it had moved on from before then, as of when it was
 * installed -- for Ubuntu's archive and Debian's (snapshot.ubuntu.com,
 * snapshot.debian.org), signed by the same keys.
 *
 * The cache is /var/cache/restate/baseline (/Library/Caches/restate/baseline
 * on macOS), each package named as apt names it in its own cache,
 * NAME_VERSION_ARCH.deb with the epoch's colon as %3a. It is expendable: an
 * image never keeps it.
 */
#ifndef RESTATE_BASELINE_H
#define RESTATE_BASELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json.h"
#include "sha256.h"
#include "util.h"

struct rs_baseline_opts {
    const char *cache;      /* NULL: rs_baseline_default_cache() */
    const char *snapshot;   /* the capture's snapshot ID ("20261011T030000Z"), or NULL */
    bool        quiet;
};

struct rs_baseline_stats {
    size_t   wanted;     /* packages a repository should have */
    size_t   cached;     /* in the cache already, and checked */
    size_t   fetched;    /* downloaded and checked */
    size_t   snapshot;   /* of those, from an archive's snapshot */
    size_t   missing;    /* no repository restate could check had them */
    size_t   local;      /* installed from a .deb: only the image can keep those */
    uint64_t bytes;      /* downloaded */
};

/* Where `restate baseline fetch` keeps packages unless told otherwise. */
const char *rs_baseline_default_cache(void);

/* "name_version_arch.deb", as apt names a package in its cache: the
 * version's epoch colon as "%3a". NULL if any of the three is not what
 * Debian allows. The caller frees it. */
char *rs_baseline_deb_name(const char *name, const char *version, const char *arch);

/*
 * Fetches every apt package in `packages` (an inventory) at its version into
 * the cache. True if it could run at all; the stats say how much it got, and
 * each package it could not get is said on standard error unless quiet.
 */
bool rs_baseline_fetch(const struct rs_jval *packages, const struct rs_baseline_opts *o,
                       struct rs_baseline_stats *st, struct rs_buf *err);

/*
 * What a fetch would do, a line per package into `out`: "NAME VERSION ARCH"
 * and whether the cache has it, a repository should, or no repository has it
 * at all.
 */
void rs_baseline_list(const struct rs_jval *packages, const char *cache, struct rs_buf *out,
                      struct rs_baseline_stats *st);

/* The parts a fetch is made of, exposed for the tests and the fuzzer. */

/* The SHA-256 and size a Release file gives `path` (as "main/binary-amd64/
 * Packages.gz"); false if it lists none. */
bool rs_baseline_release_entry(const char *release, const char *path,
                               char sha[RS_SHA256_HEX_SIZE], uint64_t *size);

/* One package in a Packages list. Every string is NUL-terminated. */
struct rs_baseline_entry {
    const char *name;
    const char *version;
    const char *arch;
    const char *filename;   /* relative to the archive's root */
    const char *sha256;
    uint64_t    size;
};

typedef void (*rs_baseline_fn)(void *ctx, const struct rs_baseline_entry *e);

/* Calls `fn` for each complete entry in a Packages list. */
void rs_baseline_parse_packages(const char *text, size_t len, rs_baseline_fn fn, void *ctx);

/* An origin label from an inventory, "URI SUITE/COMPONENT" -- or "URI SUITE"
 * for a flat repository, whose *component is then "" -- split. */
bool rs_baseline_label(const char *label, char **uri, char **suite, char **component);

/*
 * apt's credentials (`auth`: the text of /etc/apt/auth.conf and the files in
 * auth.conf.d, netrc's format, "machine HOST[/PATH] login L password P") as
 * curl takes them, into `out`: a "machine HOST login L password P" line for
 * each host that `apt`'s sources reach over https and none over plain http,
 * so a password never goes out in the clear. True if there is any.
 */
bool rs_baseline_netrc(const char *auth, const struct rs_jval *apt, struct rs_buf *out);

/* The archive's snapshot as of `id`, for an archive that has one -- Ubuntu's
 * and Debian's -- as the URI to use in place of `uri`; false otherwise. */
bool rs_baseline_snapshot_uri(const char *uri, const char *id, struct rs_buf *out);

#endif /* RESTATE_BASELINE_H */
