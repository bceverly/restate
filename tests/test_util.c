/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <unistd.h>

#include "sha256.h"
#include "test.h"
#include "util.h"

static int warn_then_error(const void *arg)
{
    (void)arg;
    rs_warn("first %d", 1);
    rs_quiet = true;
    rs_warn("never shown");
    rs_error("an error is shown even when quiet: %s", "yes");
    rs_quiet = false;
    return 7;
}

void test_util(void)
{
    struct rs_buf b;
    char         *s;
    char         *out;
    char         *err;
    void         *p;

    TEST_CASE("util: buffers grow and stay terminated");
    rs_buf_init(&b);
    CHECK(b.data == NULL);
    s = rs_buf_detach(&b);
    CHECK_STR(s, "");
    free(s);
    rs_buf_addstr(&b, "abc");
    rs_buf_addc(&b, '-');
    rs_buf_addf(&b, "%d/%s", 42, "x");
    CHECK_STR(b.data, "abc-42/x");
    CHECK_INT(b.len, 8);
    for (int i = 0; i < 1000; i++)
    {
        rs_buf_addc(&b, 'z');
    }
    CHECK_INT(b.len, 1008);
    CHECK_INT(b.data[b.len], '\0');
    rs_buf_reset(&b);
    CHECK_STR(b.data, "");
    rs_buf_add(&b, "", 0);
    CHECK_INT(b.len, 0);
    s = rs_buf_detach(&b);
    CHECK_STR(s, "");
    CHECK(b.data == NULL);
    free(s);
    rs_buf_free(&b);

    TEST_CASE("util: string helpers");
    s = rs_xstrndup("hello", 3);
    CHECK_STR(s, "hel");
    free(s);
    s = rs_xstrndup("hi", 10);
    CHECK_STR(s, "hi");
    free(s);
    s = rs_xasprintf("%s-%04d", "v", 7);
    CHECK_STR(s, "v-0007");
    free(s);
    CHECK(rs_starts_with("/etc/passwd", "/etc"));
    CHECK(!rs_starts_with("/et", "/etc"));
    p = rs_xcalloc(0, 0);
    CHECK(p != NULL);
    free(p);
    p = rs_xreallocarray(NULL, 4, 8);
    CHECK(p != NULL);
    free(p);
    p = rs_xmalloc(0);
    CHECK(p != NULL);
    free(p);

    TEST_CASE("util: warnings respect --quiet, errors do not");
    CHECK_INT(rs_test_capture(warn_then_error, NULL, &out, &err), 7);
    CHECK_STR(out, "");
    CHECK_CONTAINS(err, "restate: warning: first 1");
    CHECK(strstr(err, "never shown") == NULL);
    CHECK_CONTAINS(err, "restate: an error is shown even when quiet: yes");
    free(out);
    free(err);
}

void test_sha256(void)
{
    char             hex[RS_SHA256_HEX_SIZE];
    struct rs_sha256 ctx;
    char             million[1000];
    int              i;

    TEST_CASE("sha256: the FIPS 180-4 test vectors");
    rs_sha256_hex("", 0, hex);
    CHECK_STR(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    rs_sha256_hex("abc", 3, hex);
    CHECK_STR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    rs_sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, hex);
    CHECK_STR(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    TEST_CASE("sha256: a million 'a's, fed in uneven pieces");
    memset(million, 'a', sizeof(million));
    rs_sha256_init(&ctx);
    for (i = 0; i < 1000; i++)
    {
        /* 1000 bytes at a time, split 7 + 993 so the buffering path runs. */
        rs_sha256_update(&ctx, million, 7);
        rs_sha256_update(&ctx, million + 7, sizeof(million) - 7);
    }
    rs_sha256_final(&ctx, hex);
    CHECK_STR(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    TEST_CASE("sha256: recognizing a digest");
    CHECK(rs_sha256_valid_hex(hex));
    CHECK(!rs_sha256_valid_hex("abc"));
    hex[10] = 'G';
    CHECK(!rs_sha256_valid_hex(hex));
    CHECK(!rs_sha256_valid_hex(
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"));
    CHECK(!rs_sha256_valid_hex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550"));
}
