/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The installer a machine is rebuilt from: which one, and getting it.
 *
 * Which one follows from the machine description: the distribution and
 * release (os-release), the point release, the architecture, and whether it
 * is a desktop or a server. Ubuntu in this version.
 *
 * Getting it is `restate installer fetch`: the vendor's checksum file and its
 * signature are downloaded, the signature is checked against the vendor's
 * key -- built in and pinned by fingerprint, see keys.h -- and the image is
 * downloaded (resuming an interrupted download) and checked against the
 * signed checksum. Only then is it put where the cache keeps it. curl does
 * the downloading, over HTTPS only, and gpgv the signature check; see run.h.
 */
#ifndef RESTATE_INSTALLER_H
#define RESTATE_INSTALLER_H

#include <stdbool.h>

#include "json.h"
#include "keys.h"
#include "sha256.h"
#include "util.h"

struct rs_installer {
    char                       *vendor;       /* "ubuntu" */
    char                       *release;      /* "26.04" */
    char                       *point;        /* "26.04.1", or NULL */
    char                       *arch;         /* "amd64" */
    char                       *flavor;       /* "desktop" or "live-server" */
    char                       *description;  /* "Ubuntu 26.04 Desktop for amd64" */
    char                       *reason;       /* why this flavor */
    char                       *url;          /* the directory it is published in */
    char                       *fallback_url; /* where it moves at end of life, or NULL */
    char                       *pattern;      /* "ubuntu-26.04[.N]-desktop-amd64.iso" */
    const struct rs_vendor_key *key;
};

/* The installer for the machine `machine` describes (a machine.h object). */
bool rs_installer_resolve(const struct rs_jval *machine, struct rs_installer *out,
                          struct rs_buf *err);
void rs_installer_free(struct rs_installer *in);

/*
 * The image to fetch, from the vendor's SHA256SUMS: the machine's own point
 * release if it is listed, or else the newest of the release's point
 * releases. *name is the caller's to free.
 */
bool rs_installer_pick(const struct rs_installer *in, const char *sums, size_t len, char **name,
                       char hash[RS_SHA256_HEX_SIZE]);

/* Where `restate installer fetch` keeps images unless told otherwise. */
const char *rs_installer_default_cache(void);

struct rs_fetch_opts {
    const char *cache;    /* NULL: rs_installer_default_cache() */
    const char *mirror;   /* a directory URL to fetch from instead, or NULL */
    bool        quiet;    /* no progress */
};

/* Downloads and verifies the image. *path is where it now is (caller frees). */
bool rs_installer_fetch(const struct rs_installer *in, const struct rs_fetch_opts *o,
                        char **path, struct rs_buf *err);

/*
 * Replaces the key every vendor's signature is checked against, for the unit
 * tests, which sign a test mirror with a key of their own. NULL restores the
 * built-in keys. Nothing in restate itself calls it, and no option reaches it.
 */
void rs_installer_set_key(const struct rs_vendor_key *key);

#endif /* RESTATE_INSTALLER_H */
