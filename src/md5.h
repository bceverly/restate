/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * MD5 (RFC 1321), for one thing only: comparing a file with the digest dpkg
 * recorded for it when its package was installed (/var/lib/dpkg/info/
 * *.md5sums, and the conffile digests in /var/lib/dpkg/status). dpkg records
 * MD5 and nothing else, so that is the digest there is to compare with.
 *
 * It is not used to protect anything. MD5's collisions let someone make two
 * new files with one digest, not a file matching the digest of one that
 * already exists, which is what hiding a change to a packaged file would
 * take; and every digest restate itself records is SHA-256.
 */
#ifndef RESTATE_MD5_H
#define RESTATE_MD5_H

#include <stddef.h>
#include <stdint.h>

#define RS_MD5_SIZE ((size_t)16)

struct rs_md5 {
    uint64_t      length;    /* bytes fed so far */
    unsigned char block[64];
    size_t        nblock;
    uint32_t      state[4];
};

void rs_md5_init(struct rs_md5 *ctx);
void rs_md5_update(struct rs_md5 *ctx, const void *data, size_t n);
void rs_md5_final(struct rs_md5 *ctx, unsigned char out[RS_MD5_SIZE]);

/* The `len` characters at `s`, which must be exactly 32 hex digits in either
 * case, into 16 bytes; false if they are not. */
int rs_md5_parse_hex(const char *s, size_t len, unsigned char out[RS_MD5_SIZE]);

#endif /* RESTATE_MD5_H */
