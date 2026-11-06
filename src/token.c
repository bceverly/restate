/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "token.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define TOKEN_BYTES 32

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Cleared through a volatile pointer, so that clearing what is not read
 * again is not optimized away. */
static void wipe(unsigned char *p, size_t n)
{
    volatile unsigned char *v = p;

    while (n-- > 0)
    {
        *v++ = 0;
    }
}

/* A base64url character's value, or -1. */
static int value_of(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z')
    {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9')
    {
        return c - '0' + 52;
    }
    if (c == '-')
    {
        return 62;
    }
    if (c == '_')
    {
        return 63;
    }
    return -1;
}

bool rs_token_valid(const char *s, size_t len)
{
    size_t plen = sizeof(RS_TOKEN_PREFIX) - 1;
    size_t i;
    int    last;

    if (len != RS_TOKEN_LEN || memcmp(s, RS_TOKEN_PREFIX, plen) != 0)
    {
        return false;
    }
    for (i = plen; i < len; i++)
    {
        if (value_of(s[i]) < 0)
        {
            return false;
        }
    }
    /* 43 characters carry 258 bits, of which 32 bytes use 256: the last
     * character's two low bits are always 0, so that one token has one
     * spelling, and one digest. */
    last = value_of(s[len - 1]);
    return (last & 3) == 0;
}

static const char *random_path;

void rs_token_set_random(const char *path)
{
    random_path = path;
}

bool rs_token_new(char out[RS_TOKEN_SIZE])
{
    unsigned char bytes[TOKEN_BYTES];
    int           fd = open(random_path ? random_path : "/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t        got = 0;
    size_t        i;
    size_t        o = sizeof(RS_TOKEN_PREFIX) - 1;
    unsigned      acc = 0;
    int           bits = 0;

    while (fd >= 0 && got < sizeof(bytes))
    {
        ssize_t n = read(fd, bytes + got, sizeof(bytes) - got);

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            break;
        }
        got += (size_t)n;
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    if (got < sizeof(bytes))
    {
        wipe(bytes, sizeof(bytes));
        return false;
    }
    memcpy(out, RS_TOKEN_PREFIX, o);
    for (i = 0; i < sizeof(bytes); i++)
    {
        acc = (acc << 8 | bytes[i]) & 0xffffu;
        bits += 8;
        while (bits >= 6)
        {
            bits -= 6;
            out[o++] = alphabet[(acc >> bits) & 63];
        }
    }
    /* 256 bits are 42 characters and 4 bits over: the 43rd has them, and
     * two 0 bits after. */
    out[o++] = alphabet[(acc << (6 - bits)) & 63];
    out[o] = '\0';
    wipe(bytes, sizeof(bytes));
    return true;
}

void rs_token_digest(const char *s, size_t len, unsigned char out[RS_SHA256_SIZE])
{
    struct rs_sha256 sha;

    rs_sha256_init(&sha);
    rs_sha256_update(&sha, s, len);
    rs_sha256_final_raw(&sha, out);
}

bool rs_digest_equal(const unsigned char a[RS_SHA256_SIZE],
                     const unsigned char b[RS_SHA256_SIZE])
{
    volatile unsigned char diff = 0;
    size_t                 i;

    for (i = 0; i < RS_SHA256_SIZE; i++)
    {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}
