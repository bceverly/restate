/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A restate-proxy token: what a client gives the proxy to say who it is
 * (docs/proxy-protocol.md, "Authentication").
 *
 * "rsp_" and 32 random bytes in base64url, without padding: 47 characters.
 * The prefix is for secret scanners, which then know one when they see it.
 * What the proxy keeps of a token is only its digest -- the SHA-256 of the
 * token exactly as written, prefix and all, so that
 *
 *   printf %s "$TOKEN" | sha256sum
 *
 * gives what a grant's token_sha256 says -- and digests are compared in a
 * time that does not depend on where they differ.
 */
#ifndef RESTATE_TOKEN_H
#define RESTATE_TOKEN_H

#include <stdbool.h>
#include <stddef.h>

#include "sha256.h"

#define RS_TOKEN_PREFIX "rsp_"
#define RS_TOKEN_LEN    47          /* "rsp_" and 43 characters */
#define RS_TOKEN_SIZE   (RS_TOKEN_LEN + 1)

/* Whether the `len` bytes at `s` are a token: the prefix, then 43 base64url
 * characters that are the one way of writing 32 bytes. */
bool rs_token_valid(const char *s, size_t len);

/* A new token, from the kernel's random source, into `out`: false, and
 * nothing made, if there is no such source. */
bool rs_token_new(char out[RS_TOKEN_SIZE]);

/* The digest a grant keeps of the token at `s`. */
void rs_token_digest(const char *s, size_t len, unsigned char out[RS_SHA256_SIZE]);

/* Whether two digests are the same, in a time that depends on neither. */
bool rs_digest_equal(const unsigned char a[RS_SHA256_SIZE],
                     const unsigned char b[RS_SHA256_SIZE]);

/* Replaces where rs_token_new reads its random bytes from, for the unit
 * tests' benefit: NULL restores /dev/urandom. Nothing in restate itself
 * calls it. */
void rs_token_set_random(const char *path);

#endif /* RESTATE_TOKEN_H */
