/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>

#include "json.h"
#include "test.h"

static bool parse(const char *text, struct rs_jval *v, struct rs_buf *err)
{
    struct rs_json_parser jp;
    bool                  ok;

    rs_buf_reset(err);
    rs_json_init(&jp, text, strlen(text), err);
    ok = rs_json_value(&jp, v) && rs_json_at_end(&jp);
    return ok;
}

/* Inputs a strict parser must refuse, and why. */
static const char *const bad_json[][2] = {
    { "",                    "unexpected end" },
    { "{",                   "expected" },
    { "[1,]",                "unexpected character" },
    { "{\"a\":1,}",          "expected" },
    { "{\"a\":1,\"a\":2}",   "duplicate key" },
    { "01",                  "bad number" },
    { "1.5",                 "only integers" },
    { "1e3",                 "only integers" },
    { "-",                   "bad number" },
    { "18446744073709551616", "too large" },
    { "\"abc",               "unterminated string" },
    { "\"a\x01\"",           "control character" },
    { "\"\\q\"",             "bad escape" },
    { "\"\\u12\"",           "bad \\u escape" },
    { "\"\\ud800\"",         "unpaired surrogate" },
    { "\"\\udc00\"",         "unpaired surrogate" },
    { "\"\\u0000\"",         "NUL" },
    { "\"\xff\"",            "invalid UTF-8" },
    { "\"\xc0\x80\"",        "invalid UTF-8" },
    { "\"\xed\xa0\x80\"",    "invalid UTF-8" },
    { "tru",                 "unexpected character" },
    { "nul",                 "unexpected character" },
    { "@",                   "unexpected character" },
    { "{1:2}",               "expected" },
    { "{\"a\" 1}",           "expected" },
    { "\"\\",                "unterminated escape" },
};

void test_json(void)
{
    struct rs_jval v;
    struct rs_buf  err;
    struct rs_buf  b;
    size_t         i;
    uint64_t       u;
    int64_t        s;

    rs_buf_init(&err);
    rs_buf_init(&b);

    TEST_CASE("json: every kind of value");
    CHECK(parse(" {\"s\": \"h\\u00e9\\n\\t\\\"\\\\\\/\\b\\f\\r\", \"n\": -42, \"z\": 0, "
                "\"big\": 18446744073709551615, \"t\": true, \"f\": false, \"x\": null, "
                "\"a\": [1, [2, {}], []], \"emoji\": \"\\ud83d\\ude00\"} ", &v, &err));
    CHECK_INT(v.type, RS_JOBJECT);
    CHECK_STR(rs_jobject_get(&v, "s")->s, "h\xc3\xa9\n\t\"\\/\b\f\r");
    CHECK(rs_jval_i64(rs_jobject_get(&v, "n"), &s) && s == -42);
    CHECK(!rs_jval_u64(rs_jobject_get(&v, "n"), &u));
    CHECK(rs_jval_u64(rs_jobject_get(&v, "z"), &u) && u == 0);
    CHECK(rs_jval_u64(rs_jobject_get(&v, "big"), &u) && u == UINT64_MAX);
    CHECK(!rs_jval_i64(rs_jobject_get(&v, "big"), &s));
    CHECK(rs_jobject_get(&v, "t")->b);
    CHECK(!rs_jobject_get(&v, "f")->b);
    CHECK_INT(rs_jobject_get(&v, "x")->type, RS_JNULL);
    CHECK_INT(rs_jobject_get(&v, "a")->n, 3);
    CHECK_STR(rs_jobject_get(&v, "emoji")->s, "\xf0\x9f\x98\x80");
    CHECK(rs_jobject_get(&v, "missing") == NULL);
    CHECK(rs_jobject_get(rs_jobject_get(&v, "a"), "x") == NULL);
    CHECK(!rs_jval_u64(NULL, &u));
    CHECK(!rs_jval_i64(rs_jobject_get(&v, "s"), &s));
    rs_jval_free(&v);
    CHECK(parse("-9223372036854775808", &v, &err) && rs_jval_i64(&v, &s) && s == INT64_MIN);
    rs_jval_free(&v);
    CHECK(parse("-9223372036854775809", &v, &err) && !rs_jval_i64(&v, &s));
    rs_jval_free(&v);
    CHECK(parse("-0", &v, &err) && rs_jval_u64(&v, &u) && u == 0);
    rs_jval_free(&v);

    TEST_CASE("json: what a strict parser refuses");
    for (i = 0; i < sizeof(bad_json) / sizeof(bad_json[0]); i++)
    {
        rs_test_case = bad_json[i][1];
        CHECK(!parse(bad_json[i][0], &v, &err));
        CHECK_CONTAINS(err.data, bad_json[i][1]);
        rs_jval_free(&v);
    }
    CHECK(!parse("1 2", &v, &err));
    rs_jval_free(&v);

    TEST_CASE("json: nesting is bounded");
    {
        struct rs_buf deep;

        rs_buf_init(&deep);
        for (i = 0; i < 1000; i++)
        {
            rs_buf_addc(&deep, '[');
        }
        CHECK(!parse(deep.data, &v, &err));
        CHECK_CONTAINS(err.data, "nested too deeply");
        rs_jval_free(&v);
        rs_buf_free(&deep);
    }

    TEST_CASE("json: the cursor");
    {
        struct rs_json_parser jp;

        rs_buf_reset(&err);
        rs_json_init(&jp, "  {\"k\"", 6, &err);
        CHECK(rs_json_peek(&jp, '{'));
        CHECK(rs_json_expect(&jp, '{'));
        CHECK(!rs_json_expect(&jp, ':'));
        CHECK_CONTAINS(err.data, "expected ':'");
        CHECK(rs_json_string(&jp, &b));
        CHECK_STR(b.data, "k");
        CHECK(rs_json_at_end(&jp));
    }

    TEST_CASE("json: writing escapes exactly what it must");
    rs_buf_reset(&b);
    {
        const char *raw = "a\"b\\c\nd\te\rf\x01g\x7fh/\xc3\xa9";

        rs_json_put_string(&b, raw, strlen(raw));
    }
    CHECK_STR(b.data, "\"a\\\"b\\\\c\\nd\\te\\rf\\u0001g\x7fh/\xc3\xa9\"");
    CHECK(parse(b.data, &v, &err));
    CHECK_STR(v.s, "a\"b\\c\nd\te\rf\x01g\x7fh/\xc3\xa9");
    rs_jval_free(&v);

    TEST_CASE("json: UTF-8, valid and otherwise");
    CHECK(rs_utf8_valid("plain", 5));
    CHECK(rs_utf8_valid("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9));
    CHECK(!rs_utf8_valid("\xff", 1));
    CHECK(!rs_utf8_valid("\xc3", 1));
    CHECK(!rs_utf8_valid("\xe0\x80\x80", 3));        /* overlong */
    CHECK(!rs_utf8_valid("\xf4\x90\x80\x80", 4));    /* past U+10FFFF */
    CHECK(!rs_utf8_valid("\xc3\x28", 2));
    {
        char *lossy = rs_utf8_lossy("a\xff" "b\xc3", 4);

        CHECK_STR(lossy, "a\xef\xbf\xbd" "b\xef\xbf\xbd");
        free(lossy);
    }

    TEST_CASE("json: base64 round trips");
    {
        const char *samples[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar",
                                  "\xff\xfe\x00" };
        size_t        lens[] = { 0, 1, 2, 3, 4, 5, 6, 3 };
        struct rs_buf back;

        rs_buf_init(&back);
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
        {
            rs_buf_reset(&b);
            rs_base64_encode(&b, samples[i], lens[i]);
            CHECK(rs_base64_decode(b.data, b.len, &back));
            CHECK_INT(back.len, lens[i]);
            CHECK(memcmp(back.data, samples[i], lens[i]) == 0);
        }
        rs_buf_reset(&b);
        rs_base64_encode(&b, "foobar", 6);
        CHECK_STR(b.data, "Zm9vYmFy");
        CHECK(!rs_base64_decode("Zm9", 3, &back));
        CHECK(!rs_base64_decode("Zm9!", 4, &back));
        CHECK(!rs_base64_decode("=m9v", 4, &back));
        CHECK(!rs_base64_decode("Zm=v", 4, &back));
        CHECK(!rs_base64_decode("Zg==Zg==", 8, &back));
        rs_buf_free(&back);
    }

    rs_buf_free(&err);
    rs_buf_free(&b);
}
