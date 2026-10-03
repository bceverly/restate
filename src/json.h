/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Just enough JSON for the index, written here rather than linked.
 *
 * The writer escapes what RFC 8259 requires and nothing more, so the index
 * stays readable. The parser is strict: no comments, no trailing commas, no
 * duplicate keys in an object (two "path" keys would mean whichever reader
 * you asked), no NUL in a string, and numbers are integers -- the index has no
 * use for a fraction, and refusing one is simpler than deciding what 1e400
 * should mean. Nesting is limited, so a hostile index of ten thousand '['
 * costs an error rather than the stack.
 *
 * The parser is a cursor rather than a whole-document reader. The index is
 * one object holding an array that may have a million entries; reading it all
 * into a tree first would cost gigabytes. The index reader walks the outer
 * object itself and parses one entry at a time into a small tree.
 */
#ifndef RESTATE_JSON_H
#define RESTATE_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define RS_JSON_MAX_DEPTH 32

enum rs_jtype {
    RS_JNULL = 0,
    RS_JBOOL,
    RS_JINT,
    RS_JSTRING,
    RS_JARRAY,
    RS_JOBJECT
};

struct rs_jval {
    enum rs_jtype   type;
    bool            b;       /* RS_JBOOL */
    bool            neg;     /* RS_JINT: negative; the magnitude is in u */
    uint64_t        u;
    char           *s;       /* RS_JSTRING: UTF-8, NUL-free */
    size_t          slen;
    struct rs_jval *items;   /* RS_JARRAY and RS_JOBJECT values */
    char          **keys;    /* RS_JOBJECT only */
    size_t          n;
};

void rs_jval_free(struct rs_jval *v);
/* The member called `key`, or NULL. */
const struct rs_jval *rs_jobject_get(const struct rs_jval *obj, const char *key);
/* Typed accessors: false if `v` is NULL or of another type or out of range. */
bool rs_jval_u64(const struct rs_jval *v, uint64_t *out);
bool rs_jval_i64(const struct rs_jval *v, int64_t *out);

struct rs_json_parser {
    const char    *p;
    size_t         len;
    size_t         pos;
    struct rs_buf *err;
};

void rs_json_init(struct rs_json_parser *jp, const char *text, size_t len,
                  struct rs_buf *err);
/* Skips whitespace and reports whether the next byte is `c`, without
 * consuming it. */
bool rs_json_peek(struct rs_json_parser *jp, char c);
/* Skips whitespace and consumes `c`, or fails with a message. */
bool rs_json_expect(struct rs_json_parser *jp, char c);
bool rs_json_string(struct rs_json_parser *jp, struct rs_buf *out);
bool rs_json_value(struct rs_json_parser *jp, struct rs_jval *out);
/* Nothing but whitespace remains. */
bool rs_json_at_end(struct rs_json_parser *jp);

/* Appends `s` (`len` bytes of valid UTF-8) as a quoted JSON string. */
void rs_json_put_string(struct rs_buf *out, const char *s, size_t len);

bool  rs_utf8_valid(const char *s, size_t len);
/* `s` with every invalid UTF-8 sequence replaced by U+FFFD. */
char *rs_utf8_lossy(const char *s, size_t len);

void rs_base64_encode(struct rs_buf *out, const void *data, size_t len);
bool rs_base64_decode(const char *s, size_t len, struct rs_buf *out);

#endif /* RESTATE_JSON_H */
