/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * MD5, RFC 1321.
 *
 * As with SHA-256, every multi-byte quantity is assembled byte by byte, so
 * the code has no opinion about the machine's byte order.
 */
#include "md5.h"

#include <string.h>

static uint32_t load_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

static void md5_block(uint32_t st[4], const unsigned char blk[64])
{
    /* floor(abs(sin(i + 1)) * 2^32), RFC 1321 section 3.4. */
    static const uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const unsigned char r[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    uint32_t m[16];
    uint32_t a = st[0];
    uint32_t b = st[1];
    uint32_t c = st[2];
    uint32_t d = st[3];
    unsigned i;

    for (i = 0; i < 16; i++)
    {
        m[i] = load_le32(blk + (size_t)i * 4);
    }
    for (i = 0; i < 64; i++)
    {
        uint32_t f;
        unsigned g;
        uint32_t t;

        if (i < 16)
        {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32)
        {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48)
        {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else
        {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        t = d;
        d = c;
        c = b;
        b = b + rol32(a + f + k[i] + m[g], r[i]);
        a = t;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
}

void rs_md5_init(struct rs_md5 *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

void rs_md5_update(struct rs_md5 *ctx, const void *data, size_t n)
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
        md5_block(ctx->state, ctx->block);
        ctx->nblock = 0;
    }
    while (n >= sizeof(ctx->block))
    {
        md5_block(ctx->state, p);
        p += sizeof(ctx->block);
        n -= sizeof(ctx->block);
    }
    if (n > 0)
    {
        memcpy(ctx->block, p, n);
        ctx->nblock = n;
    }
}

void rs_md5_final(struct rs_md5 *ctx, unsigned char out[RS_MD5_SIZE])
{
    uint64_t bits = ctx->length * 8u;
    size_t   i;

    ctx->block[ctx->nblock++] = 0x80;
    if (ctx->nblock > sizeof(ctx->block) - 8)
    {
        memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - ctx->nblock);
        md5_block(ctx->state, ctx->block);
        ctx->nblock = 0;
    }
    memset(ctx->block + ctx->nblock, 0, sizeof(ctx->block) - 8 - ctx->nblock);
    for (i = 0; i < 8; i++)
    {
        ctx->block[sizeof(ctx->block) - 8 + i] = (unsigned char)(bits >> (i * 8u));
    }
    md5_block(ctx->state, ctx->block);
    for (i = 0; i < RS_MD5_SIZE; i++)
    {
        out[i] = (unsigned char)(ctx->state[i / 4] >> ((i % 4) * 8u));
    }
    memset(ctx, 0, sizeof(*ctx));
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

int rs_md5_parse_hex(const char *s, size_t len, unsigned char out[RS_MD5_SIZE])
{
    size_t i;

    if (len != RS_MD5_SIZE * 2)
    {
        return 0;
    }
    for (i = 0; i < RS_MD5_SIZE; i++)
    {
        int hi = hex_digit(s[i * 2]);
        int lo = hex_digit(s[i * 2 + 1]);

        if (hi < 0 || lo < 0)
        {
            return 0;
        }
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    return 1;
}
