/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * SHA-1 (FIPS 180-4), for one thing only: comparing a file with the digest
 * Alpine's apk recorded for it when its package was installed ("Z:Q1" in
 * /lib/apk/db/installed). apk records SHA-1, so that is the digest there is
 * to compare with.
 *
 * It is not used to protect anything. SHA-1's collisions let someone make
 * two new files with one digest, not a file matching the digest of one that
 * already exists, which is what hiding a change to a packaged file would
 * take; and every digest restate itself records is SHA-256.
 */
#ifndef RESTATE_SHA1_H
#define RESTATE_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define RS_SHA1_SIZE ((size_t)20)

struct rs_sha1 {
    uint64_t      length;    /* bytes fed so far */
    unsigned char block[64];
    size_t        nblock;
    uint32_t      state[5];
};

void rs_sha1_init(struct rs_sha1 *ctx);
void rs_sha1_update(struct rs_sha1 *ctx, const void *data, size_t n);
void rs_sha1_final(struct rs_sha1 *ctx, unsigned char out[RS_SHA1_SIZE]);

#endif /* RESTATE_SHA1_H */
