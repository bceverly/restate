/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * BLAKE2b, RFC 7693: unkeyed, with a 64-byte digest.
 *
 * As with SHA-256 and MD5, every multi-byte quantity is assembled byte by
 * byte, so the code has no opinion about the machine's byte order.
 */
#include "blake2b.h"

#include <string.h>

/* SHA-512's initial values: RFC 7693 section 2.6. */
static const uint64_t iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* The message schedule: section 2.7. Rounds 10 and 11 use rows 0 and 1. */
static const unsigned char sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

static uint64_t load_le64(const unsigned char *p)
{
    uint64_t v = 0;
    unsigned i;

    for (i = 0; i < 8; i++)
    {
        v |= (uint64_t)p[i] << (8u * i);
    }
    return v;
}

static uint64_t ror64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64u - n));
}

/* The mixing function G: section 3.1. */
static void mix(uint64_t v[16], unsigned a, unsigned b, unsigned c, unsigned d, uint64_t x,
                uint64_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = ror64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = ror64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = ror64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ror64(v[b] ^ v[c], 63);
}

/* The compression function F: section 3.2. */
static void compress(struct rs_blake2b *ctx, const unsigned char blk[128], int last)
{
    uint64_t v[16];
    uint64_t m[16];
    unsigned i;

    for (i = 0; i < 16; i++)
    {
        m[i] = load_le64(blk + (size_t)i * 8);
    }
    memcpy(v, ctx->h, sizeof(ctx->h));
    memcpy(v + 8, iv, sizeof(iv));
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (last)
    {
        v[14] = ~v[14];
    }
    for (i = 0; i < 12; i++)
    {
        const unsigned char *s = sigma[i];

        mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (i = 0; i < 8; i++)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

/* Counts `n` more bytes compressed. */
static void count(struct rs_blake2b *ctx, size_t n)
{
    ctx->t[0] += (uint64_t)n;
    if (ctx->t[0] < (uint64_t)n)
    {
        ctx->t[1]++;
    }
}

void rs_blake2b_init(struct rs_blake2b *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->h, iv, sizeof(iv));
    /* The parameter block: a 64-byte digest, no key, fanout and depth 1. */
    ctx->h[0] ^= 0x01010000ULL ^ (uint64_t)RS_BLAKE2B_SIZE;
}

void rs_blake2b_update(struct rs_blake2b *ctx, const void *data, size_t n)
{
    const unsigned char *p = data;

    while (n > 0)
    {
        size_t take;

        /* A full block is compressed only once more follows it: the last
         * block, full or not, is the one final() compresses as last. */
        if (ctx->nblock == sizeof(ctx->block))
        {
            count(ctx, sizeof(ctx->block));
            compress(ctx, ctx->block, 0);
            ctx->nblock = 0;
        }
        take = sizeof(ctx->block) - ctx->nblock;
        if (take > n)
        {
            take = n;
        }
        memcpy(ctx->block + ctx->nblock, p, take);
        ctx->nblock += take;
        p += take;
        n -= take;
    }
}

void rs_blake2b_final(struct rs_blake2b *ctx, unsigned char out[RS_BLAKE2B_SIZE])
{
    size_t i;

    count(ctx, ctx->nblock);
    memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - ctx->nblock);
    compress(ctx, ctx->block, 1);
    for (i = 0; i < RS_BLAKE2B_SIZE; i++)
    {
        out[i] = (unsigned char)(ctx->h[i / 8] >> (8u * (i % 8)));
    }
    memset(ctx, 0, sizeof(*ctx));
}
