/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * SHA-256, FIPS 180-4.
 *
 * Every multi-byte quantity is assembled byte by byte, so the code has no
 * opinion about the machine's byte order and no unaligned loads.
 */
#include "sha256.h"

#include <stdio.h>
#include <string.h>

static uint32_t load_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t ror32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

static void sha256_block(uint32_t st[8], const unsigned char blk[64])
{
    /* The first 32 bits of the fractional parts of the cube roots of the
     * first 64 primes, FIPS 180-4 section 4.2.2. */
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t w[64];
    uint32_t v[8];
    unsigned i;

    for (i = 0; i < 16; i++)
    {
        w[i] = load_be32(blk + (size_t)i * 4);
    }
    for (i = 16; i < 64; i++)
    {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, st, sizeof(v));
    for (i = 0; i < 64; i++)
    {
        uint32_t s1 = ror32(v[4], 6) ^ ror32(v[4], 11) ^ ror32(v[4], 25);
        uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint32_t t1 = v[7] + s1 + ch + k[i] + w[i];
        uint32_t s0 = ror32(v[0], 2) ^ ror32(v[0], 13) ^ ror32(v[0], 22);
        uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        uint32_t t2 = s0 + maj;

        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = v[3] + t1;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
    {
        st[i] += v[i];
    }
}

void rs_sha256_init(struct rs_sha256 *ctx)
{
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->state, iv, sizeof(iv));
}

void rs_sha256_update(struct rs_sha256 *ctx, const void *data, size_t n)
{
    const unsigned char *p = data;

    ctx->length += n;
    if (ctx->nblock > 0)
    {
        size_t take = sizeof(ctx->block) - ctx->nblock;

        if (take > n)
        {
            take = n;
        }
        memcpy(ctx->block + ctx->nblock, p, take);
        ctx->nblock += take;
        p += take;
        n -= take;
        if (ctx->nblock < sizeof(ctx->block))
        {
            return;
        }
        sha256_block(ctx->state, ctx->block);
        ctx->nblock = 0;
    }
    while (n >= sizeof(ctx->block))
    {
        sha256_block(ctx->state, p);
        p += sizeof(ctx->block);
        n -= sizeof(ctx->block);
    }
    if (n > 0)
    {
        memcpy(ctx->block, p, n);
        ctx->nblock = n;
    }
}

void rs_sha256_final(struct rs_sha256 *ctx, char hex[RS_SHA256_HEX_SIZE])
{
    static const char digits[] = "0123456789abcdef";
    uint64_t bits = ctx->length * 8u;
    size_t   i;

    /* 0x80, then zeros until 8 bytes short of a block boundary. */
    ctx->block[ctx->nblock++] = 0x80;
    if (ctx->nblock > sizeof(ctx->block) - 8)
    {
        memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - ctx->nblock);
        sha256_block(ctx->state, ctx->block);
        ctx->nblock = 0;
    }
    memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - 8 - ctx->nblock);
    for (i = 0; i < 8; i++)
    {
        ctx->block[sizeof(ctx->block) - 8 + i] =
            (unsigned char)(bits >> ((7 - i) * 8u));
    }
    sha256_block(ctx->state, ctx->block);

    for (i = 0; i < 32; i++)
    {
        unsigned byte = (unsigned)(ctx->state[i / 4] >> ((3 - i % 4) * 8u)) & 0xffu;

        hex[i * 2] = digits[byte >> 4];
        hex[i * 2 + 1] = digits[byte & 0x0fu];
    }
    hex[RS_SHA256_HEX_LEN] = '\0';
    /* The context held the tail of whatever was hashed; do not leave it lying
     * around for the next use of this stack frame to read. */
    memset(ctx, 0, sizeof(*ctx));
}

void rs_sha256_hex(const void *data, size_t n, char hex[RS_SHA256_HEX_SIZE])
{
    struct rs_sha256 ctx;

    rs_sha256_init(&ctx);
    rs_sha256_update(&ctx, data, n);
    rs_sha256_final(&ctx, hex);
}

int rs_sha256_valid_hex(const char *s)
{
    size_t i;

    for (i = 0; i < RS_SHA256_HEX_LEN; i++)
    {
        char c = s[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
            return 0;
        }
    }
    return s[RS_SHA256_HEX_LEN] == '\0';
}
