/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * BLAKE2b-512 (RFC 7693), unkeyed, for one thing only: comparing a file with
 * the digest FreeBSD's pkg recorded for it when its package was installed.
 * pkg 2.8 and later record a file's BLAKE2b ("2$" in pkg query's %Fs) where
 * an older pkg recorded its SHA-256 ("1$"), so that is the digest there is to
 * compare with. Every digest restate itself records is SHA-256.
 */
#ifndef RESTATE_BLAKE2B_H
#define RESTATE_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#define RS_BLAKE2B_SIZE ((size_t)64)

struct rs_blake2b {
    uint64_t      h[8];
    uint64_t      t[2];       /* bytes compressed so far, 128 bits */
    unsigned char block[128];
    size_t        nblock;
};

void rs_blake2b_init(struct rs_blake2b *ctx);
void rs_blake2b_update(struct rs_blake2b *ctx, const void *data, size_t n);
void rs_blake2b_final(struct rs_blake2b *ctx, unsigned char out[RS_BLAKE2B_SIZE]);

#endif /* RESTATE_BLAKE2B_H */
