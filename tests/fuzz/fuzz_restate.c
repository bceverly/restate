/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The fuzz target: everything in restate that reads bytes somebody else wrote.
 *
 * Three things are input. An image -- a tar stream with a JSON index at the
 * front -- is read back by `diff` and `verify`, and it may have been carried
 * on a USB stick, copied off a dead machine, or edited by hand. A rules file
 * is written by an administrator, but it is still a parser. And the patterns
 * in it are run against every path on the machine, so a pattern that makes
 * the matcher allocate, loop or recurse without bound is a denial of service
 * on the scan.
 *
 * The first byte of each input chooses which of them it is fed to, so one
 * corpus and one run cover all of them:
 *
 *   0  an index (JSON): parsed, written back out, parsed again and diffed
 *      against itself -- the round trip must be lossless
 *   1  a rules file: parsed, then used to classify a fixed set of paths
 *   2  a pattern and a path, separated by a NUL: matched both ways
 *   3  a tar stream: its first member read, and fed to the index parser
 *   4  a timestamp: parsed, and if it parses, formatted back identically
 *   5  base64: decoded, re-encoded, and compared
 *
 * It is reached two ways:
 *
 *   libFuzzer (clang)  LLVMFuzzerTestOneInput, coverage-guided
 *   the built-in loop  a mutation fuzzer over a seed corpus, in-process, which
 *                      needs nothing but the compiler already in use
 *
 * Either way it runs under AddressSanitizer and UndefinedBehaviorSanitizer,
 * and they do the judging. The round-trip checks below abort() on their own
 * when an invariant fails, which both engines treat as a crash.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "diff.h"
#include "glob.h"
#include "index.h"
#include "json.h"
#include "meta.h"
#include "rules.h"
#include "tar.h"
#include "util.h"

/* Patterns and paths longer than this say nothing a shorter one does not, and
 * the matcher is O(pattern x path), so cap them to keep the run fast. */
#define GLOB_MAX 2048

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void fuzz_index(const char *text, size_t len)
{
    struct rs_index ix;
    struct rs_buf   err;

    rs_index_init(&ix);
    rs_buf_init(&err);
    if (rs_index_parse(&ix, text, len, "fuzz", &err))
    {
        /* Whatever parses must write out and parse back to the same thing. */
        char  *copy = NULL;
        size_t n = 0;
        FILE  *fp = open_memstream(&copy, &n);

        if (fp)
        {
            struct rs_index      back;
            struct rs_diff_stats st;
            FILE                *sink = fopen("/dev/null", "w");

            (void)rs_index_write(&ix, fp);
            (void)fclose(fp);
            rs_index_init(&back);
            rs_buf_reset(&err);
            if (!rs_index_parse(&back, copy, n, "back", &err))
            {
                abort();   /* we wrote something we cannot read */
            }
            if (back.count != ix.count)
            {
                abort();
            }
            if (sink)
            {
                if (!rs_diff_write(&ix, &back, sink, &st) ||
                    st.added || st.deleted || st.modified)
                {
                    abort();   /* the round trip lost something */
                }
                (void)fclose(sink);
            }
            rs_index_free(&back);
            free(copy);
        }
    }
    rs_index_free(&ix);
    rs_buf_free(&err);
}

static void fuzz_rules(const char *text, size_t len)
{
    static const char *const paths[] = {
        "/", "/etc/passwd", "/usr/local/bin/x", "/var/lib/a/b.pid", "/tmp",
        "/home/u/.cache/z", "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"
    };
    struct rs_rules rs;
    struct rs_buf   err;

    rs_rules_init(&rs);
    rs_buf_init(&err);
    (void)rs_rules_parse(&rs, text, len, "fuzz", &err);
    /* Only a handful of rules: classification is rules x depth x pattern, and
     * a ten-thousand-rule input is a slow input, not an interesting one. */
    if (rs.count <= 64)
    {
        size_t i;

        for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        {
            long          which;
            enum rs_class cls = rs_rules_classify(&rs, paths[i], &which);

            if (which >= (long)rs.count || (which >= 0 && rs.rules[which].cls != cls))
            {
                abort();
            }
        }
    }
    rs_rules_free(&rs);
    rs_buf_free(&err);
}

static void fuzz_glob(const char *text, size_t len)
{
    const char *nul = memchr(text, '\0', len);
    char       *pattern;
    char       *path;

    if (!nul)
    {
        return;
    }
    pattern = rs_xstrndup(text, (size_t)(nul - text));
    path = rs_xstrndup(nul + 1, len - (size_t)(nul - text) - 1);
    if (strlen(pattern) <= GLOB_MAX && strlen(path) <= GLOB_MAX)
    {
        bool matched = rs_glob_match(pattern, path);
        bool covered = rs_glob_covers(pattern, path);

        /* Covering is matching the path or an ancestor, so it can only add. */
        if (matched && !covered)
        {
            abort();
        }
    }
    free(pattern);
    free(path);
}

struct mem_reader {
    const char *p;
    size_t      len;
    size_t      pos;
};

static ssize_t mem_read(void *ctx, void *data, size_t n)
{
    struct mem_reader *r = ctx;

    if (n > r->len - r->pos)
    {
        n = r->len - r->pos;
    }
    memcpy(data, r->p + r->pos, n);
    r->pos += n;
    return (ssize_t)n;
}

static void fuzz_tar(const char *text, size_t len)
{
    struct mem_reader r = { text, len, 0 };
    struct rs_buf     name;
    struct rs_buf     content;
    struct rs_buf     err;

    rs_buf_init(&name);
    rs_buf_init(&content);
    rs_buf_init(&err);
    if (rs_tar_read_first(mem_read, &r, 1u << 20, &name, &content, &err))
    {
        fuzz_index(content.data, content.len);
    }
    rs_buf_free(&name);
    rs_buf_free(&content);
    rs_buf_free(&err);
}

static void fuzz_time(const char *text, size_t len)
{
    char           *s = rs_xstrndup(text, len < 64 ? len : 64);
    struct rs_time  t;

    if (rs_time_parse(s, &t))
    {
        struct rs_time again;
        char           back[RS_TIME_STR_MAX];

        rs_time_format(&t, back);
        if (!rs_time_parse(back, &again) || !rs_time_equal(&t, &again))
        {
            abort();
        }
    }
    free(s);
}

static void fuzz_base64(const char *text, size_t len)
{
    struct rs_buf raw;
    struct rs_buf enc;

    rs_buf_init(&raw);
    rs_buf_init(&enc);
    if (rs_base64_decode(text, len, &raw))
    {
        rs_base64_encode(&enc, raw.data, raw.len);
        /* Decoding then encoding may only normalize unused padding bits. */
        if (enc.len != len)
        {
            abort();
        }
    }
    rs_buf_free(&raw);
    rs_buf_free(&enc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *text;

    if (size < 1)
    {
        return 0;
    }
    text = (const char *)(data + 1);
    switch (data[0] % 6)
    {
    case 0:
        fuzz_index(text, size - 1);
        break;
    case 1:
        fuzz_rules(text, size - 1);
        break;
    case 2:
        fuzz_glob(text, size - 1);
        break;
    case 3:
        fuzz_tar(text, size - 1);
        break;
    case 4:
        fuzz_time(text, size - 1);
        break;
    default:
        fuzz_base64(text, size - 1);
        break;
    }
    return 0;
}

#ifndef RESTATE_LIBFUZZER
/* ------------------------------------------------------------------------- */
/* The built-in mutation loop                                                */
/* ------------------------------------------------------------------------- */

static uint64_t rng_state;

static uint64_t rng(void)
{
    /* xorshift64*: small, fast, and reproducible from a seed, which is all a
     * fuzzer's dice need to be. */
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}

static size_t rnd(size_t n)
{
    return n ? (size_t)(rng() % n) : 0;
}

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE          *fp = fopen(path, "rb");
    struct rs_buf  b;
    char           chunk[4096];
    size_t         n;

    *len = 0;
    if (!fp)
    {
        return NULL;
    }
    rs_buf_init(&b);
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
    {
        rs_buf_add(&b, chunk, n);
    }
    (void)fclose(fp);
    *len = b.len;
    return (unsigned char *)rs_buf_detach(&b);
}

static void save(const char *path, const unsigned char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");

    if (fp)
    {
        (void)fwrite(data, 1, len, fp);
        (void)fclose(fp);
    }
}

/* Interesting bytes: JSON syntax, escapes, pattern syntax, digits. */
static const char magic[] = "{}[]\":,\\u/*?#-.0f7Z@=\n";

static void mutate(struct rs_buf *b, const unsigned char *other, size_t other_len)
{
    size_t rounds = 1 + rnd(8);

    while (rounds-- > 0)
    {
        size_t pos = rnd(b->len + 1);

        switch (rnd(7))
        {
        case 0:   /* flip a bit */
            if (b->len > 1)
            {
                pos = 1 + rnd(b->len - 1);
                b->data[pos] = (char)(b->data[pos] ^ (char)(1u << rnd(8)));
            }
            break;
        case 1:   /* a random byte */
            if (b->len > 1)
            {
                b->data[1 + rnd(b->len - 1)] = (char)rnd(256);
            }
            break;
        case 2:   /* an interesting byte, inserted */
        {
            struct rs_buf n;

            rs_buf_init(&n);
            rs_buf_add(&n, b->data, pos);
            rs_buf_addc(&n, magic[rnd(sizeof(magic) - 1)]);
            rs_buf_add(&n, b->data + pos, b->len - pos);
            rs_buf_free(b);
            *b = n;
            break;
        }
        case 3:   /* delete a run */
            if (b->len > 2)
            {
                size_t at = 1 + rnd(b->len - 1);
                size_t n = 1 + rnd(b->len - at < 16 ? b->len - at : 16);

                memmove(b->data + at, b->data + at + n, b->len - at - n);
                b->len -= n;
                b->data[b->len] = '\0';
            }
            break;
        case 4:   /* duplicate a run */
            if (b->len > 2 && b->len < 1u << 16)
            {
                size_t at = 1 + rnd(b->len - 1);
                size_t n = 1 + rnd(b->len - at < 64 ? b->len - at : 64);
                char  *copy = rs_xmalloc(n);

                /* Copied out first: the add may move the buffer it reads. */
                memcpy(copy, b->data + at, n);
                rs_buf_add(b, copy, n);
                free(copy);
            }
            break;
        case 5:   /* splice in a piece of another input */
            if (other_len > 1)
            {
                size_t at = 1 + rnd(other_len - 1);
                size_t n = 1 + rnd(other_len - at < 128 ? other_len - at : 128);

                rs_buf_add(b, other + at, n);
            }
            break;
        default:  /* change which parser it goes to */
            if (b->len > 0)
            {
                b->data[0] = (char)rnd(6);
            }
            break;
        }
    }
}

int main(int argc, char **argv)
{
    const char     *replay = NULL;
    const char     *crash = ".fuzz/crash.bin";
    unsigned        seconds = 30;
    uint64_t        seed = 0;
    unsigned char **corpus = NULL;
    size_t         *lens = NULL;
    size_t          ncorpus = 0;
    unsigned long   cases = 0;
    time_t          deadline;
    int             i;

    for (i = 1; i < argc; i++)
    {
        if (strncmp(argv[i], "--seconds=", 10) == 0)
        {
            seconds = (unsigned)strtoul(argv[i] + 10, NULL, 10);
        } else if (strncmp(argv[i], "--seed=", 7) == 0)
        {
            seed = strtoull(argv[i] + 7, NULL, 10);
        } else if (strncmp(argv[i], "--crash-file=", 13) == 0)
        {
            crash = argv[i] + 13;
        } else if (strncmp(argv[i], "--replay=", 9) == 0)
        {
            replay = argv[i] + 9;
        } else
        {
            size_t         len;
            unsigned char *d = read_file(argv[i], &len);

            if (d)
            {
                corpus = rs_xreallocarray(corpus, ncorpus + 1, sizeof(*corpus));
                lens = rs_xreallocarray(lens, ncorpus + 1, sizeof(*lens));
                corpus[ncorpus] = d;
                lens[ncorpus] = len;
                ncorpus++;
            }
        }
    }

    if (replay)
    {
        size_t         len;
        unsigned char *d = read_file(replay, &len);

        if (!d)
        {
            (void)fprintf(stderr, "cannot read %s\n", replay);
            return 2;
        }
        (void)LLVMFuzzerTestOneInput(d, len);
        free(d);
        (void)printf("replayed %s without a crash\n", replay);
        return 0;
    }
    if (ncorpus == 0)
    {
        (void)fprintf(stderr, "no seed corpus given\n");
        return 2;
    }

    rng_state = seed ? seed : (uint64_t)time(NULL) ^ 0x9E3779B97F4A7C15ULL;
    (void)printf("  seed %llu; reproduce with --seed=%llu\n",
                 (unsigned long long)rng_state, (unsigned long long)rng_state);
    deadline = time(NULL) + (time_t)seconds;

    /* Every seed once as it is, then mutations until the time is up. */
    for (i = 0; i < (int)ncorpus; i++)
    {
        save(crash, corpus[i], lens[i]);
        (void)LLVMFuzzerTestOneInput(corpus[i], lens[i]);
        cases++;
    }
    while (time(NULL) < deadline)
    {
        int k;

        for (k = 0; k < 256; k++)
        {
            size_t        pick = rnd(ncorpus);
            size_t        other = rnd(ncorpus);
            struct rs_buf b;

            rs_buf_init(&b);
            rs_buf_add(&b, corpus[pick], lens[pick]);
            if (b.len == 0)
            {
                rs_buf_addc(&b, (char)rnd(6));
            }
            mutate(&b, corpus[other], lens[other]);
            /* Written before it runs: if this one kills the process, the file
             * left behind is the input that did it. */
            save(crash, (const unsigned char *)b.data, b.len);
            (void)LLVMFuzzerTestOneInput((const uint8_t *)b.data, b.len);
            rs_buf_free(&b);
            cases++;
        }
    }
    (void)remove(crash);
    for (i = 0; i < (int)ncorpus; i++)
    {
        free(corpus[i]);
    }
    free(corpus);
    free(lens);
    (void)printf("  %lu cases, no crashes\n", cases);
    return 0;
}
#endif /* RESTATE_LIBFUZZER */
