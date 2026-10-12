/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Whether apt can still use each of its sources.
 *
 * apt refuses a repository whose index is not signed by a key the source
 * names -- the vendor moved to a new key, the key expired, the key file was
 * never put back -- and says so once, in the middle of an `apt update` nobody
 * reads, and then goes on using the last index it accepted. A machine can run
 * like that for months. A rebuild cannot: it installs from the repositories
 * as they are now, and the packages from one apt refuses do not come back.
 *
 * So each source's index as apt last fetched it -- InRelease, or Release and
 * Release.gpg, in /var/lib/apt/lists -- is checked with gpgv against the keys
 * the source names (its Signed-By, or else apt's trusted.gpg and
 * trusted.gpg.d), from the inventory's copy of them, as apt itself would, and
 * its Valid-Until against the time now. What fails is recorded in the
 * inventory, as the source's "problem", and capture warns of it.
 *
 * That is what apt last fetched. Online, each source that passes is fetched
 * again as its repository serves it now (curl), and checked the same way,
 * so a vendor that moved to a new key since the last `apt update` is caught
 * before the rebuild finds out.
 */
#ifndef RESTATE_SOURCES_H
#define RESTATE_SOURCES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json.h"
#include "util.h"

/*
 * Checks every enabled source in `packages` (rs_packages_describe's
 * inventory of the tree at `root`), as of `now` (seconds since the epoch),
 * and with `online` as its repository serves it now too. Each one apt cannot
 * use gets a "problem" member saying why. Returns how many; none, and
 * nothing recorded, when gpgv is not installed (*checked is then false) or
 * there is no apt.
 */
size_t rs_sources_check(const char *root, struct rs_jval *packages, int64_t now, bool online,
                        bool *checked);

/*
 * A Release file's Valid-Until ("Sat, 17 Oct 2026 08:12:29 UTC"), in seconds
 * since the epoch; false if it has none, or not one in that form. Exposed for
 * the tests and the fuzzer.
 */
bool rs_sources_valid_until(const char *release, int64_t *when);

/*
 * The index a repository serves at `base` (a URL ending in a slash: the
 * suite's directory) -- InRelease, or Release and Release.gpg -- fetched into
 * `home` and checked with gpgv against the keys the source `src` names, from
 * `apt`'s inventory of them, as apt itself would; with `now` > 0, its
 * Valid-Until too (an archive's snapshot is long expired, and is not held to
 * it). Only the text the signature covers goes into `text`, NUL-terminated.
 * False, with why in `why`, if it cannot be had or is not what it should be.
 */
bool rs_sources_release(const struct rs_jval *apt, const struct rs_jval *src, const char *base,
                        const char *home, int64_t now, struct rs_buf *text, struct rs_buf *why);

/*
 * The text an InRelease file's signature covers, into `out`, NUL-terminated:
 * as apt splits a clear-signed file, strictly -- the armor header first, the
 * "Hash:" lines, the text with its dash-escaping undone, the signature, and
 * nothing else -- so nothing outside the signature can be read as part of
 * it. False if it is not in that form. Exposed for the tests and the fuzzer.
 */
bool rs_sources_signed_part(const char *text, size_t len, struct rs_buf *out);

#endif /* RESTATE_SOURCES_H */
