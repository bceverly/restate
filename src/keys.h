/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The vendors' public signing keys, built in.
 *
 * Built in, rather than read from the keyrings of the machine restate runs
 * on, for two reasons: a machine fetching an installer for another
 * distribution does not have that distribution's keys, and a keyring anyone
 * with root can add to is not a statement of whom to trust. Each key is
 * pinned by its full fingerprint as well: a signature only counts if gpgv
 * reports it was made by exactly that key.
 *
 * Public key material: nothing here is secret or can sign anything.
 */
#ifndef RESTATE_KEYS_H
#define RESTATE_KEYS_H

#include <stddef.h>

struct rs_vendor_key {
    const char          *vendor;       /* "ubuntu" */
    const char          *name;         /* the key's user ID */
    const char          *fingerprint;  /* 40 hex digits, upper case */
    const unsigned char *data;         /* the key, as `gpg --export` writes it */
    size_t               len;
};

/* The key for `vendor`, or NULL. */
const struct rs_vendor_key *rs_vendor_key(const char *vendor);

#endif /* RESTATE_KEYS_H */
