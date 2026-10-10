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
 * It checks what apt last fetched, not what the repository serves today: a
 * vendor that changed keys since then is caught at the next `apt update`,
 * not before.
 */
#ifndef RESTATE_SOURCES_H
#define RESTATE_SOURCES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json.h"

/*
 * Checks every enabled source in `packages` (rs_packages_describe's
 * inventory of the tree at `root`), as of `now` (seconds since the epoch).
 * Each one apt cannot use gets a "problem" member saying why. Returns how
 * many; none, and nothing recorded, when gpgv is not installed (*checked is
 * then false) or there is no apt.
 */
size_t rs_sources_check(const char *root, struct rs_jval *packages, int64_t now, bool *checked);

/*
 * A Release file's Valid-Until ("Sat, 17 Oct 2026 08:12:29 UTC"), in seconds
 * since the epoch; false if it has none, or not one in that form. Exposed for
 * the tests and the fuzzer.
 */
bool rs_sources_valid_until(const char *release, int64_t *when);

#endif /* RESTATE_SOURCES_H */
