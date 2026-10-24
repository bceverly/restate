/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * SHA-1, FIPS 180-4.
 *
 * As with SHA-256, every multi-byte quantity is assembled byte by byte, so
 * the code has no opinion about the machine's byte order.
 */
#include "sha1.h"

#include <string.h>

static uint32_t load_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

static void sha1_block(uint32_t st[5], const unsigned char blk[64])
{
    uint32_t w[80];
    uint32_t a = st[0];
    uint32_t b = st[1];
    uint32_t c = st[2];
    uint32_t d = st[3];
    uint32_t e = st[4];
    unsigned i;

    for (i = 0; i < 16; i++)
    {
        w[i] = load_be32(blk + (size_t)i * 4);
    }
    for (i = 16; i < 80; i++)
    {
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    for (i = 0; i < 80; i++)
    {
        uint32_t f;
        uint32_t k;
        uint32_t t;

        /* FIPS 180-4 section 4.1.1 and 4.2.1. */
        if (i < 20)
        {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else
        {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = t;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
}

void rs_sha1_init(struct rs_sha1 *ctx)
{
    static const uint32_t iv[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->state, iv, sizeof(iv));
}

void rs_sha1_update(struct rs_sha1 *ctx, const void *data, size_t n)
{
    const unsigned char *p = data;

    ctx->length += n;
    while (n > 0)
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
        if (ctx->nblock == sizeof(ctx->block))
        {
            sha1_block(ctx->state, ctx->block);
            ctx->nblock = 0;
        }
    }
}

void rs_sha1_final(struct rs_sha1 *ctx, unsigned char out[RS_SHA1_SIZE])
{
    uint64_t bits = ctx->length * 8u;
    size_t   i;

    /* 0x80, then zeros until 8 bytes short of a block boundary. */
    ctx->block[ctx->nblock++] = 0x80;
    if (ctx->nblock > sizeof(ctx->block) - 8)
    {
        memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - ctx->nblock);
        sha1_block(ctx->state, ctx->block);
        ctx->nblock = 0;
    }
    memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - 8 - ctx->nblock);
    for (i = 0; i < 8; i++)
    {
        ctx->block[sizeof(ctx->block) - 8 + i] = (unsigned char)(bits >> ((7 - i) * 8u));
    }
    sha1_block(ctx->state, ctx->block);
    for (i = 0; i < RS_SHA1_SIZE; i++)
    {
        out[i] = (unsigned char)(ctx->state[i / 4] >> ((3 - i % 4) * 8u));
    }
    memset(ctx, 0, sizeof(*ctx));
}
