/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * SHA-256 (FIPS 180-4), for the content digests in an index.
 *
 * Implemented here rather than linked, for the same reason as everything else:
 * restate links libc and nothing more. A tool whose job is to rebuild a broken
 * machine must not itself depend on a library that the broken machine may be
 * missing. The unit tests check it against the published test vectors.
 */
#ifndef RESTATE_SHA256_H
#define RESTATE_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* 64 hex digits and the terminator. */
#define RS_SHA256_HEX_LEN 64
#define RS_SHA256_HEX_SIZE (RS_SHA256_HEX_LEN + 1)

struct rs_sha256 {
    uint64_t      length;    /* bytes fed so far */
    unsigned char block[64];
    size_t        nblock;
    uint32_t      state[8];
};

void rs_sha256_init(struct rs_sha256 *ctx);
void rs_sha256_update(struct rs_sha256 *ctx, const void *data, size_t n);
/* Writes the digest as lowercase hex into `hex`, RS_SHA256_HEX_SIZE bytes. */
void rs_sha256_final(struct rs_sha256 *ctx, char hex[RS_SHA256_HEX_SIZE]);

/* One-shot convenience over a memory buffer. */
void rs_sha256_hex(const void *data, size_t n, char hex[RS_SHA256_HEX_SIZE]);

/* true if `s` is exactly 64 lowercase hex digits. */
int  rs_sha256_valid_hex(const char *s);

#endif /* RESTATE_SHA256_H */
