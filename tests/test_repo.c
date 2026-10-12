/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "image.h"
#include "pgp.h"
#include "repo.h"
#include "rules.h"
#include "run.h"
#include "scan.h"
#include "sha256.h"
#include "tar.h"
#include "test.h"

/* rs_test_write, making the directories on the way. */
static void put(const char *dir, const char *name, const char *text, unsigned mode)
{
    char  *path = rs_xasprintf("%s/%s", dir, name);
    char  *slash;

    for (slash = strchr(path + 1, '/'); slash; slash = strchr(slash + 1, '/'))
    {
        *slash = '\0';
        (void)mkdir(path, 0755);
        *slash = '/';
    }
    free(path);
    rs_test_write(dir, name, text, mode);
}

/* The whole of a file, into `out`. */
static bool slurp(const char *path, struct rs_buf *out)
{
    FILE  *fp = fopen(path, "rb");
    char   chunk[4096];
    size_t n;

    rs_buf_add(out, "", 0);
    if (!fp)
    {
        return false;
    }
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
    {
        rs_buf_add(out, chunk, n);
    }
    (void)fclose(fp);
    return true;
}

/* A file of `size` bytes no other file in the tests has, made from `seed`. */
static void big_file(const char *dir, const char *name, size_t size, unsigned seed)
{
    char  *path = rs_xasprintf("%s/%s", dir, name);
    FILE  *fp = fopen(path, "w");
    size_t i;

    for (i = 0; fp && i < size; i++)
    {
        seed = seed * 1103515245u + 12345u;
        (void)fputc((int)(seed >> 16 & 0xff), fp);
    }
    if (fp)
    {
        (void)fclose(fp);
    }
    free(path);
}

/* A capture of `tree` into `r`, as capture makes one, at `created`; with
 * `prev`, incremental. The snapshot's name into *name. */
static bool snap(struct rs_repo *r, const char *tree, const char *created,
                 const struct rs_index *prev, struct rs_scan_stats *st, char **name)
{
    static const char *const kit[] = { "/etc/", "/etc" };
    struct rs_rules          rules;
    struct rs_scan_opts      so;
    struct rs_index          ix;
    struct rs_repo_writer   *w;
    struct rs_repo_written   done;
    struct rs_buf            err;
    bool                     ok;

    rs_rules_init(&rules);
    memset(&so, 0, sizeof(so));
    so.root = tree;
    so.rules = &rules;
    so.hash = true;
    so.prev = prev;
    rs_index_init(&ix);
    rs_buf_init(&err);
    w = rs_repo_writer_begin(r, &err);
    rs_repo_writer_kit(w, kit, 2);
    so.store = rs_repo_store;
    so.store_ctx = w;
    so.have = rs_repo_have;
    ok = rs_scan(&so, &ix, st, &err);
    if (!ok)
    {
        rs_repo_writer_abort(w);
    } else
    {
        ix.created = rs_xstrdup(created);
        ix.root = rs_xstrdup(tree);
        ix.host = rs_xstrdup("test");
        ix.version = rs_xstrdup("x");
        ix.content = rs_xstrdup("state");
        ix.hashed = true;
        ok = rs_repo_writer_finish(w, &ix, NULL, &done, &err);
        *name = ok ? done.name : NULL;
    }
    CHECK_STR(err.data ? err.data : "", "");
    rs_buf_free(&err);
    rs_index_free(&ix);
    rs_rules_free(&rules);
    return ok;
}

static ssize_t stream_read(void *ctx, void *data, size_t n)
{
    return rs_repo_stream_read(ctx, data, n);
}

/* What a stream of a snapshot's content holds: each member's name, and a
 * file's digest, one per line, into `out`. */
static bool read_stream(struct rs_repo_stream *s, struct rs_buf *out, struct rs_buf *err)
{
    struct rs_tar_reader r;
    struct rs_tar_entry  m;
    int                  more;

    rs_tar_reader_init(&r, stream_read, s);
    rs_tar_entry_init(&m);
    while ((more = rs_tar_next(&r, &m, err)) == 1)
    {
        rs_buf_addf(out, "%s %c", m.name.data, m.typeflag);
        if (m.typeflag == '0')
        {
            struct rs_sha256 sha;
            char             hex[RS_SHA256_HEX_SIZE];
            char             chunk[4096];
            ssize_t          n;

            rs_sha256_init(&sha);
            while ((n = rs_tar_read(&r, chunk, sizeof(chunk), err)) > 0)
            {
                rs_sha256_update(&sha, chunk, (size_t)n);
            }
            rs_sha256_final(&sha, hex);
            rs_buf_addf(out, " %s", hex);
        }
        rs_buf_addc(out, '\n');
    }
    rs_tar_entry_free(&m);
    return more == 0;
}

/* How many of the index's kept files the stream `seen` holds with the
 * content the index says. */
static size_t matching(const struct rs_index *ix, const char *seen)
{
    size_t n = 0;
    size_t i;

    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];

        if (e->type == 'f' && e->stored && e->hash_state == RS_HASH_PRESENT)
        {
            char *want = rs_xasprintf("%s 0 %s\n", e->stored, e->hash);

            n += seen && strstr(seen, want) ? 1 : 0;
            free(want);
        }
    }
    return n;
}

static size_t lines(const char *text, const char *needle)
{
    size_t      n = 0;
    const char *p = text;

    while (p && (p = strstr(p, needle)) != NULL)
    {
        n++;
        p += strlen(needle);
    }
    return n;
}

static void test_pure(void)
{
    struct rs_repo_idx x;
    char              *name;
    char              *idx;
    static const char  hash[] =
        "a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6";
    static const char  other[] =
        "b0f66adc83641586656866813fd9dd0b8ebb63796075661ba45d1aa8089e1d44";

    TEST_CASE("repo: names, and the names snapshots are given");
    CHECK(rs_repo_name_valid("20261011T030000Z"));
    CHECK(rs_repo_name_valid("20261011T030000Z-2"));
    CHECK(rs_repo_name_valid("a_b.c"));
    CHECK(!rs_repo_name_valid(""));
    CHECK(!rs_repo_name_valid(NULL));
    CHECK(!rs_repo_name_valid(".hidden"));
    CHECK(!rs_repo_name_valid("a/b"));
    CHECK(!rs_repo_name_valid("a b"));
    CHECK(!rs_repo_name_valid("0123456789012345678901234567890123456789012345678901234567890123x"));
    name = rs_repo_snapshot_name("2026-10-11T03:04:05.123456789Z");
    CHECK_STR(name, "20261011T030405Z");
    free(name);
    name = rs_repo_snapshot_name(NULL);
    CHECK(strlen(name) == 16 && name[8] == 'T' && name[15] == 'Z');
    free(name);
    name = rs_repo_snapshot_name("not a time");
    CHECK(strlen(name) == 16);
    free(name);

    TEST_CASE("repo: a pack's index, and what is not one");
    idx = rs_xasprintf("restate-pack 1\n1 %s 5\n2 - 9\n10 %s 0\n", hash, hash);
    CHECK(rs_repo_parse_idx(idx, strlen(idx), &x));
    CHECK_INT(x.nmembers, 3);
    CHECK(x.nmembers == 3 && x.members[0].live && x.members[0].member == 1 &&
          x.members[0].size == 5);
    CHECK_STR(x.nmembers == 3 ? x.members[0].hash : "", hash);
    CHECK(x.nmembers == 3 && !x.members[1].live && x.members[1].size == 9);
    CHECK(x.nmembers == 3 && x.members[2].member == 10);
    rs_repo_idx_free(&x);
    free(idx);
    CHECK(rs_repo_parse_idx("restate-pack 1\n", 15, &x) && x.nmembers == 0);
    rs_repo_idx_free(&x);
    CHECK(rs_repo_parse_idx("restate-pack 2\n", 15, &x) && x.nmembers == 0);
    rs_repo_idx_free(&x);
    /* Version 2: a file of more than one chunk, listed. */
    idx = rs_xasprintf("restate-pack 2\n1 %s 5\n= %s 12 %s %s\n2 %s 7\n= %s 3 %s %s %s\n",
                       hash, other, hash, hash, other, other, hash, other, hash);
    CHECK(rs_repo_parse_idx(idx, strlen(idx), &x));
    CHECK_INT(x.nmembers, 2);
    CHECK_INT(x.nlists, 2);
    CHECK_INT(x.nchunks, 5);
    CHECK(x.nlists == 2 && x.lists[0].size == 12 && x.lists[0].first == 0 && x.lists[0].n == 2);
    CHECK(x.nlists == 2 && x.lists[1].first == 2 && x.lists[1].n == 3);
    CHECK_STR(x.nlists == 2 ? x.lists[0].hash : "", other);
    CHECK_STR(x.nchunks == 5 ? x.chunks[3] : "", other);
    rs_repo_idx_free(&x);
    free(idx);
    {
        char  *bad[16];
        size_t nbad = 0;
        size_t i;

        bad[nbad++] = rs_xstrdup("restate-pack 3\n");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n1 - 5");                /* no newline */
        bad[nbad++] = rs_xstrdup("restate-pack 1\n2 - 5\n1 - 5\n");     /* not numbered upward */
        bad[nbad++] = rs_xstrdup("restate-pack 1\n01 - 5\n");            /* a leading zero */
        bad[nbad++] = rs_xstrdup("restate-pack 1\n-1 - 5\n");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n1  - 5\n");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n1 xyz 5\n");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n1 - 99999999999999999999999\n");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n1 - \n");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n1");
        bad[nbad++] = rs_xstrdup("restate-pack 1\n4294967296 - 5\n");   /* past 32 bits */
        bad[nbad++] = rs_xstrdup("restate");
        /* Lists: only in version 2, of two chunks or more, ended by a newline. */
        bad[nbad++] = rs_xasprintf("restate-pack 1\n= %s 1 %s %s\n", hash, hash, hash);
        bad[nbad++] = rs_xasprintf("restate-pack 2\n= %s 1 %s\n", hash, hash);
        bad[nbad++] = rs_xasprintf("restate-pack 2\n= %s 1 %s %s", hash, hash, hash);
        bad[nbad++] = rs_xasprintf("restate-pack 2\n= %s 1 %s %.63sx\n", hash, hash, hash);
        for (i = 0; i < nbad; i++)
        {
            CHECK(!rs_repo_parse_idx(bad[i], strlen(bad[i]), &x));
            CHECK(x.members == NULL && x.nmembers == 0 && x.lists == NULL && x.chunks == NULL);
            free(bad[i]);
        }
        idx = rs_xasprintf("restate-pack 1\n1 %.63sG 5\n", hash);
        CHECK(!rs_repo_parse_idx(idx, strlen(idx), &x));
        free(idx);
    }

    TEST_CASE("repo: a repository's marker");
    {
        int  version;
        bool enc;
        bool newer;

        CHECK(rs_repo_parse_marker("restate-repository 1\n", &version, &enc, &newer));
        CHECK(version == 1 && !enc && !newer);
        CHECK(rs_repo_parse_marker("restate-repository 2\nid 0123456789abcdef0123456789abcdef\n",
                                   &version, &enc, &newer));
        CHECK(version == 2 && !enc);
        CHECK(rs_repo_parse_marker("restate-repository 2\nid 0123456789abcdef0123456789abcdef\n"
                                   "encrypted\n", &version, &enc, &newer));
        CHECK(version == 2 && enc);
        /* No identity, a line a later restate knows, a later version. */
        CHECK(!rs_repo_parse_marker("restate-repository 2\n", &version, &enc, &newer) && !newer);
        CHECK(!rs_repo_parse_marker("restate-repository 2\nid 0123456789abcdef0123456789abcdef\n"
                                    "sharded\n", &version, &enc, &newer) && newer);
        CHECK(!rs_repo_parse_marker("restate-repository 2\nid 0123456789abcdef0123456789abcdef",
                                    &version, &enc, &newer));
        CHECK(!rs_repo_parse_marker("restate-repository 3\n", &version, &enc, &newer) && newer);
        CHECK(!rs_repo_parse_marker("restate-repository 2\nid 0123456789ABCDEF0123456789abcdef\n",
                                    &version, &enc, &newer));
        CHECK(!rs_repo_parse_marker("other\n", &version, &enc, &newer) && !newer);
        CHECK(version == 0 && !enc);
    }

    TEST_CASE("repo: chunks are cut where the content says");
    {
        size_t         size = 12 * 1024 * 1024;
        unsigned char *data = rs_xmalloc(size + 100);
        unsigned       seed = 7;
        size_t         i;
        size_t         at;
        size_t         n1 = 0;
        size_t         shared = 0;
        size_t         cuts1[64];

        for (i = 0; i < size + 100; i++)
        {
            seed = seed * 1103515245u + 12345u;
            data[i] = (unsigned char)(seed >> 16);
        }
        CHECK_INT(rs_repo_chunk_cut(data, 0), 0);
        CHECK_INT(rs_repo_chunk_cut(data, 10), 10);
        CHECK_INT(rs_repo_chunk_cut(data, RS_REPO_CHUNK_MIN), RS_REPO_CHUNK_MIN);
        /* A run of one byte value never matches: cut at the maximum. */
        {
            unsigned char *same = rs_xcalloc(RS_REPO_CHUNK_MAX + 10, 1);

            CHECK_INT(rs_repo_chunk_cut(same, RS_REPO_CHUNK_MAX + 10), RS_REPO_CHUNK_MAX);
            free(same);
        }
        /* The cuts of the data, then of the same with 100 bytes before it:
         * after the first, they fall at the same places in the content. */
        for (at = 100; at < size + 100 && n1 < 64; )
        {
            size_t cut = rs_repo_chunk_cut(data + at, size + 100 - at);

            CHECK(cut > RS_REPO_CHUNK_MIN || at + cut == size + 100);
            CHECK(cut <= RS_REPO_CHUNK_MAX);
            at += cut;
            cuts1[n1++] = at;
        }
        CHECK(n1 >= 4 && n1 <= 40);
        for (at = 0; at < size + 100; )
        {
            size_t k;

            at += rs_repo_chunk_cut(data + at, size + 100 - at);
            for (k = 0; k < n1; k++)
            {
                shared += cuts1[k] == at;
            }
        }
        CHECK(shared + 2 >= n1);

        /* With a key: cut somewhere else, the same for the same key, and
         * still where the content says. */
        {
            unsigned char key[32];
            unsigned char key2[32];
            size_t        same = 0;
            size_t        moved = 0;
            size_t        n = 0;

            memset(key, 7, sizeof(key));
            memset(key2, 8, sizeof(key2));
            for (at = 100; at < size + 100 && n < 64; n++)
            {
                size_t cut = rs_repo_chunk_cut_keyed(key, data + at, size + 100 - at);

                CHECK_INT(rs_repo_chunk_cut_keyed(key, data + at, size + 100 - at), cut);
                CHECK(cut > RS_REPO_CHUNK_MIN || at + cut == size + 100);
                same += cut == rs_repo_chunk_cut(data + at, size + 100 - at);
                moved += cut != rs_repo_chunk_cut_keyed(key2, data + at, size + 100 - at);
                at += cut;
            }
            CHECK(n >= 4 && same + 2 < n && moved + 2 >= n);
        }
        free(data);
    }

    TEST_CASE("repo: which snapshots prune keeps");
    {
        /* 2025-12-28 is a Sunday, the end of ISO week 2025-W52; 2025-12-29
         * a Monday, and already in 2026-W01, as is 2026-01-04. */
        char *names[] = { "20251228T120000Z", "20251229T010000Z", "20251229T020000Z",
                          "20260104T000000Z", "20260201T000000Z", "20260202T000000Z",
                          "odd-name" };
        bool                kept[7];
        struct rs_repo_keep k;

        memset(&k, 0, sizeof(k));
        k.daily = 2;
        rs_repo_choose(names, 7, &k, kept);
        CHECK(kept[5] && kept[4] && !kept[3] && !kept[2] && !kept[1] && !kept[0]);
        CHECK(kept[6]);
        memset(&k, 0, sizeof(k));
        k.weekly = 3;
        rs_repo_choose(names, 7, &k, kept);
        /* 2026-W06 (02-02), 2026-W05 (02-01), 2026-W01's newest (01-04). */
        CHECK(kept[5] && kept[4] && kept[3] && !kept[2] && !kept[1] && !kept[0]);
        k.weekly = 4;
        rs_repo_choose(names, 7, &k, kept);
        CHECK(kept[0] && !kept[1] && !kept[2]);
        memset(&k, 0, sizeof(k));
        k.monthly = 3;
        rs_repo_choose(names, 7, &k, kept);
        CHECK(kept[5] && !kept[4] && kept[3] && kept[2] && !kept[1] && !kept[0]);
        memset(&k, 0, sizeof(k));
        k.last = 2;
        rs_repo_choose(names, 7, &k, kept);
        CHECK(kept[5] && kept[4] && !kept[3]);
        memset(&k, 0, sizeof(k));
        rs_repo_choose(names, 7, &k, kept);
        CHECK(!kept[5] && kept[6]);
        /* A date that is not one is kept, as is anything not a time. */
        {
            char *odd[] = { "20261341T000000Z", "2026101XT000000Z", "20261011X000000Z" };
            bool  ok[3];

            rs_repo_choose(odd, 3, &k, ok);
            CHECK(ok[0] && ok[1] && ok[2]);
        }
    }
}

static void test_made(const char *dir)
{
    char           *repo = rs_xasprintf("%s/repo", dir);
    char           *full = rs_xasprintf("%s/full", dir);
    char           *empty = rs_xasprintf("%s/empty", dir);
    char           *ref = rs_xasprintf("%s::x", repo);
    char           *d;
    char           *n;
    struct rs_buf   err;
    struct rs_repo *a;
    struct rs_repo *b;
    bool            busy;

    rs_buf_init(&err);
    TEST_CASE("repo: made, and found");
    CHECK(!rs_repo_is(repo));
    CHECK(rs_repo_init(repo, false, &err));
    CHECK(rs_repo_is(repo));
    CHECK(!rs_repo_init(repo, false, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "a repository already");
    rs_buf_reset(&err);
    put(full, "file", "x", 0644);
    CHECK(!rs_repo_init(full, false, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "not an empty directory");
    rs_buf_reset(&err);
    CHECK(mkdir(empty, 0755) == 0);
    CHECK(rs_repo_init(empty, false, &err));
    CHECK(!rs_repo_init("/nonexistent/restate/repo", false, &err));
    rs_buf_reset(&err);
    CHECK(rs_repo_ref(repo, &d, &n));
    CHECK_STR(d ? d : "", repo);
    CHECK(n == NULL);
    free(d);
    CHECK(rs_repo_ref(ref, &d, &n));
    CHECK_STR(n ? n : "", "x");
    free(d);
    free(n);
    CHECK(!rs_repo_ref("/nonexistent::x", &d, &n));
    CHECK(!rs_repo_ref(full, &d, &n));
    CHECK(d == NULL && n == NULL);

    TEST_CASE("repo: opened, and what is not one");
    CHECK(rs_repo_open(full, RS_REPO_LOOK, &busy, &err) == NULL);
    CHECK(!busy);
    rs_buf_reset(&err);
    put(full, RS_REPO_MARKER, "restate-repository 3\n", 0600);
    CHECK(rs_repo_open(full, RS_REPO_LOOK, &busy, &err) == NULL);
    CHECK_CONTAINS(err.data ? err.data : "", "made by a newer restate");
    rs_buf_reset(&err);
    put(full, RS_REPO_MARKER, "something else\n", 0600);
    CHECK(rs_repo_open(full, RS_REPO_LOOK, &busy, &err) == NULL);
    CHECK_CONTAINS(err.data ? err.data : "", "not a restate repository");
    rs_buf_reset(&err);

    TEST_CASE("repo: one capture or prune at a time, and no prune while it is read");
    a = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    CHECK(a != NULL);
    CHECK_STR(a ? rs_repo_dir(a) : "", repo);
    b = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    CHECK(b == NULL && busy);
    CHECK_CONTAINS(err.data ? err.data : "", "another capture or prune");
    rs_buf_reset(&err);
    b = rs_repo_open(repo, RS_REPO_READ, &busy, &err);
    CHECK(b != NULL);
    rs_repo_close(a);
    a = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
    CHECK(a == NULL && busy);
    CHECK_CONTAINS(err.data ? err.data : "", "a prune is running on it");
    rs_buf_reset(&err);
    rs_repo_close(b);
    a = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
    CHECK(a != NULL);
    CHECK(a && !rs_repo_encrypted(a));
    rs_repo_close(a);
    rs_repo_close(NULL);
    CHECK(!rs_repo_dir_encrypted(repo));
    CHECK(!rs_repo_dir_encrypted(full));

    TEST_CASE("repo: version 1, read as it is and made version 2 by a write");
    {
        char         *marker = rs_xasprintf("%s/%s", repo, RS_REPO_MARKER);
        struct rs_buf text;

        CHECK(unlink(marker) == 0);
        put(repo, RS_REPO_MARKER, "restate-repository 1\n", 0600);
        a = rs_repo_open(repo, RS_REPO_READ, &busy, &err);
        CHECK(a != NULL);
        rs_repo_close(a);
        rs_buf_init(&text);
        CHECK(slurp(marker, &text) && strcmp(text.data, "restate-repository 1\n") == 0);
        rs_buf_free(&text);
        a = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
        CHECK(a != NULL);
        rs_repo_close(a);
        rs_buf_init(&text);
        CHECK(slurp(marker, &text) &&
              rs_starts_with(text.data, "restate-repository 2\nid ") && text.len == 21 + 36);
        rs_buf_free(&text);
        free(marker);
    }
    {
        char *lock = rs_xasprintf("%s/readers", empty);

        CHECK(unlink(lock) == 0);
        CHECK(rs_repo_open(empty, RS_REPO_READ, &busy, &err) == NULL && !busy);
        rs_buf_reset(&err);
        free(lock);
    }

    rs_buf_free(&err);
    free(repo);
    free(full);
    free(empty);
    free(ref);
}

static void test_written(const char *dir)
{
    char                  *repo = rs_xasprintf("%s/repo2", dir);
    char                  *tree = rs_xasprintf("%s/tree", dir);
    char                  *first = NULL;
    char                  *second = NULL;
    char                  *third = NULL;
    char                  *found;
    char                 **names;
    char                 **kit;
    size_t                 n;
    struct rs_buf          err;
    struct rs_buf          gz;
    struct rs_buf          sig;
    struct rs_buf          seen;
    struct rs_repo        *r;
    struct rs_index        ix;
    struct rs_index        ix2;
    char                  *snapdir;
    struct rs_scan_stats   st;
    struct rs_jval         info;
    struct rs_repo_stream *s;
    bool                   busy;

    rs_buf_init(&err);
    rs_buf_init(&gz);
    rs_buf_init(&sig);
    rs_buf_init(&seen);
    CHECK(rs_repo_init(repo, false, &err));
    put(tree, "etc/conf", "conf\n", 0644);
    put(tree, "etc/dup1", "same\n", 0644);
    put(tree, "etc/dup2", "same\n", 0600);
    put(tree, "home/u/notes", "notes\n", 0644);
    big_file(tree, "big", 3 * 1024 * 1024, 1);
    big_file(tree, "bigdup", 3 * 1024 * 1024, 1);
    big_file(tree, "other", 2500 * 1024, 2);
    {
        char *link = rs_xasprintf("%s/etc/link", tree);
        char *fifo = rs_xasprintf("%s/fifo", tree);

        CHECK(symlink("conf", link) == 0);
        CHECK(mkfifo(fifo, 0600) == 0);
        free(link);
        free(fifo);
    }
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);

    TEST_CASE("repo: a snapshot written, its content once");
    rs_repo_set_pack_size(1024 * 1024);
    CHECK(snap(r, tree, "2026-01-01T00:00:00.000000000Z", NULL, &st, &first));
    CHECK_STR(first ? first : "", "20260101T000000Z");
    CHECK_INT(st.reused, 0);
    names = rs_repo_snapshots(r, &n);
    CHECK_INT(n, 1);
    rs_repo_free_names(names, n);
    {
        char  *packs = rs_xasprintf("%s/packs", repo);
        char  *cmd = rs_xasprintf("cat '%s'/*.idx", packs);
        FILE  *fp = popen(cmd, "r");
        char   line[256];
        size_t live = 0;
        size_t dead = 0;
        size_t heads = 0;

        while (fp && fgets(line, sizeof(line), fp))
        {
            heads += strcmp(line, "restate-pack 2\n") == 0;
            dead += strstr(line, " - ") != NULL;
            live += line[0] == '=';
        }
        if (fp)
        {
            (void)pclose(fp);
        }
        /* Lists for big and other, each more than one chunk; the second copy
         * of big costs nothing, its chunks there already; a pack for each
         * mebibyte or so. */
        CHECK_INT(live, 2);
        CHECK_INT(dead, 0);
        CHECK(heads >= 3);
        free(cmd);
        free(packs);
    }

    TEST_CASE("repo: a snapshot read back");
    rs_index_init(&ix);
    rs_index_init(&ix2);
    snapdir = rs_xasprintf("%s/snapshots/%s", repo, first ? first : "?");
    CHECK(rs_repo_load_index(r, first, &ix, &err));
    CHECK(ix.in_parts && rs_sha256_valid_hex(ix.part_sha256));
    CHECK(rs_index_find(&ix, "/etc/dup2") && rs_index_find(&ix, "/etc/dup2")->stored);
    CHECK(rs_repo_index_bytes(r, first, &gz, &sig, &err) && gz.len > 0 && sig.len == 0);
    CHECK(rs_repo_kit(r, first, &kit, &n, &err));
    CHECK_INT(n, 2);
    CHECK_STR(n == 2 ? kit[0] : "", "/etc/");
    rs_repo_free_names(kit, n);
    CHECK(rs_repo_info(r, first, &info, &err));
    CHECK_STR(rs_jobject_str(&info, "name") ? rs_jobject_str(&info, "name") : "", first);
    CHECK_STR(rs_jobject_str(&info, "host") ? rs_jobject_str(&info, "host") : "", "test");
    rs_jval_free(&info);
    CHECK(!rs_repo_load_index(r, "nope", &ix2, &err));
    CHECK(!rs_repo_index_bytes(r, "../x", &gz, &sig, &err));
    CHECK(!rs_repo_kit(r, "../x", &kit, &n, &err));
    CHECK(!rs_repo_kit(r, "nope", &kit, &n, &err));
    CHECK(!rs_repo_info(r, "../x", &info, &err));
    CHECK(!rs_repo_info(r, "nope", &info, &err));
    rs_buf_reset(&err);
    {
        char *bad = rs_xasprintf("%s/snapshots/%s/info", repo, first);

        CHECK(unlink(bad) == 0);
        put(snapdir, "info", "[1, 2]", 0600);
        CHECK(!rs_repo_info(r, first, &info, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "not a summary restate wrote");
        rs_buf_reset(&err);
        free(bad);
    }

    TEST_CASE("repo: what is unchanged is not read again");
    CHECK(snap(r, tree, "2026-01-01T00:00:00.000000000Z", &ix, &st, &second));
    CHECK_STR(second ? second : "", "20260101T000000Z-2");
    /* Every file: conf, dup1, dup2, notes, big, bigdup, other. */
    CHECK_INT(st.reused, 7);
    CHECK_INT(st.bytes_hashed, 0);
    found = rs_repo_resolve(r, NULL, &err);
    CHECK_STR(found ? found : "", second ? second : "?");
    free(found);
    CHECK(rs_repo_resolve(r, "nope", &err) == NULL);
    CHECK_CONTAINS(err.data ? err.data : "", "no snapshot \"nope\"");
    rs_buf_reset(&err);

    TEST_CASE("repo: a snapshot signed afterwards, once");
    CHECK(rs_repo_add_signature(r, first, "sig", 3, &err));
    CHECK(!rs_repo_add_signature(r, first, "sig", 3, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "signed already");
    CHECK(!rs_repo_add_signature(r, "../x", "sig", 3, &err));
    rs_buf_reset(&err);
    CHECK(rs_repo_index_bytes(r, first, &gz, &sig, &err) && sig.len == 3);

    TEST_CASE("repo: a snapshot's content, as a tar stream");
    s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
    CHECK(read_stream(s, &seen, &err));
    CHECK(rs_repo_stream_close(s, &err));
    CHECK_CONTAINS(seen.data ? seen.data : "", "restate/files/etc/link 2");
    CHECK_CONTAINS(seen.data ? seen.data : "", "restate/files/fifo 6");
    CHECK_CONTAINS(seen.data ? seen.data : "", "restate/files/etc 5");
    {
        size_t i;

        /* Every kept file, once, with the content the index says. */
        for (i = 0; i < ix.count; i++)
        {
            const struct rs_entry *e = &ix.entries[i];

            if (e->type == 'f')
            {
                char *want = rs_xasprintf("%s 0 %s\n", e->stored, e->hash);

                CHECK_INT(lines(seen.data, want), 1);
                free(want);
            }
        }
    }
    rs_buf_reset(&seen);

    TEST_CASE("repo: the kit alone, or nothing");
    {
        static const char *const etc[] = { "/etc/" };

        s = rs_repo_stream_open(r, &ix, etc, 1, &err);
        CHECK(read_stream(s, &seen, &err));
        CHECK(rs_repo_stream_close(s, &err));
        CHECK_CONTAINS(seen.data ? seen.data : "", "restate/files/etc/dup1 0");
        CHECK(strstr(seen.data ? seen.data : "", "restate/files/big") == NULL);
        rs_buf_reset(&seen);
        s = rs_repo_stream_open(r, &ix, etc, 0, &err);
        CHECK(read_stream(s, &seen, &err));
        CHECK(rs_repo_stream_close(s, &err));
        CHECK_INT(seen.len, 0);
        CHECK(rs_repo_stream_close(NULL, &err));
    }

    TEST_CASE("repo: a file that could not be read is zeros, for restore to refuse");
    {
        struct rs_entry *e = (struct rs_entry *)rs_index_find(&ix, "/home/u/notes");

        e->hash_state = RS_HASH_UNREADABLE;
        s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
        CHECK(read_stream(s, &seen, &err));
        CHECK(rs_repo_stream_close(s, &err));
        /* Six zero bytes. */
        CHECK_CONTAINS(seen.data ? seen.data : "", "restate/files/home/u/notes 0 "
                       "b0f66adc83641586656866813fd9dd0b8ebb63796075661ba45d1aa8089e1d44");
        e->hash_state = RS_HASH_PRESENT;
        rs_buf_reset(&seen);
    }

    TEST_CASE("repo: a pack gone, or cut short, loses only its own files");
    {
        char  *cmd = rs_xasprintf("cd '%s/packs' && ls *.tar.gz | head -1", repo);
        FILE  *fp = popen(cmd, "r");
        char   pack[256] = "";
        char  *path;
        char  *aside;
        size_t got;

        if (fp && fgets(pack, sizeof(pack), fp))
        {
            pack[strcspn(pack, "\n")] = '\0';
        }
        if (fp)
        {
            (void)pclose(fp);
        }
        path = rs_xasprintf("%s/packs/%s", repo, pack);
        aside = rs_xasprintf("%s/aside", dir);
        CHECK(rename(path, aside) == 0);
        s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
        CHECK(read_stream(s, &seen, &err));
        CHECK(rs_repo_stream_close(s, &err));
        got = matching(&ix, seen.data);
        CHECK(got > 0 && got < 7);
        rs_buf_reset(&seen);
        /* Cut short: the stream fails, or leaves out what it could not read. */
        {
            char *trunc = rs_xasprintf("dd if='%s' of='%s' bs=2000 count=1 2> /dev/null", aside,
                                       path);

            CHECK(system(trunc) == 0);
            free(trunc);
        }
        s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
        (void)read_stream(s, &seen, &err);
        (void)rs_repo_stream_close(s, &err);
        CHECK(matching(&ix, seen.data) < 7);
        rs_buf_reset(&seen);
        rs_buf_reset(&err);
        CHECK(rename(aside, path) == 0);
        free(path);
        free(aside);
        free(cmd);
    }

    TEST_CASE("repo: a capture abandoned leaves nothing behind");
    {
        struct rs_repo_writer *w = rs_repo_writer_begin(r, &err);
        struct rs_entry        e;
        struct stat            sb;
        char                  *path = rs_xasprintf("%s/other", tree);
        int                    fd = open(path, O_RDONLY);
        size_t                 before;

        names = rs_repo_snapshots(r, &before);
        rs_repo_free_names(names, before);
        big_file(tree, "fresh", 1100 * 1024, 9);
        CHECK(w != NULL);
        memset(&e, 0, sizeof(e));
        e.type = 'f';
        e.path = rs_xstrdup("/other");
        CHECK(fd >= 0 && fstat(fd, &sb) == 0);
        CHECK(rs_repo_store(w, &e, fd, &sb, &err));
        (void)close(fd);
        rs_repo_writer_abort(w);
        rs_repo_writer_abort(NULL);
        rs_entry_free(&e);
        free(path);
        names = rs_repo_snapshots(r, &n);
        CHECK_INT(n, before);
        rs_repo_free_names(names, n);
    }

    TEST_CASE("repo: a third snapshot, of what changed");
    put(tree, "etc/conf", "changed\n", 0644);
    big_file(tree, "other", 2500 * 1024, 3);
    rs_index_free(&ix);
    rs_index_init(&ix);
    CHECK(rs_repo_load_index(r, second, &ix, &err));
    CHECK(snap(r, tree, "2026-02-01T00:00:00.000000000Z", &ix, &st, &third));
    /* The two changed, and the one new since: fresh. */
    CHECK_INT(st.reused, 5);
    rs_index_free(&ix);
    rs_repo_close(r);

    TEST_CASE("repo: prune drops what is not kept, and the content only it had");
    {
        struct rs_repo_keep   keep;
        struct rs_repo_pruned pr;

        r = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
        memset(&keep, 0, sizeof(keep));
        keep.last = 1;
        CHECK(rs_repo_prune(r, &keep, true, &pr, &err));
        CHECK_INT(pr.ndropped, 2);
        rs_repo_pruned_free(&pr);
        names = rs_repo_snapshots(r, &n);
        CHECK_INT(n, 3);
        rs_repo_free_names(names, n);
        /* What an interrupted capture leaves, which prune clears. */
        put(repo, "packs/.20260101T000000Z-1-0001.tar.gz.tmp", "x", 0600);
        put(repo, "packs/orphan.tar.gz", "x", 0600);
        put(repo, "snapshots/.20260301T000000Z.abc/index.json.gz", "x", 0600);
        CHECK(rs_repo_prune(r, &keep, false, &pr, &err));
        CHECK_STR(err.data ? err.data : "", "");
        CHECK_INT(pr.ndropped, 2);
        CHECK(pr.packs_removed + pr.packs_rewritten > 0);
        CHECK(pr.bytes_freed > 0);
        rs_repo_pruned_free(&pr);
        names = rs_repo_snapshots(r, &n);
        CHECK_INT(n, 1);
        CHECK_STR(n == 1 ? names[0] : "", third ? third : "?");
        rs_repo_free_names(names, n);
        {
            struct stat sb;
            char       *p = rs_xasprintf("%s/packs/orphan.tar.gz", repo);
            char       *q = rs_xasprintf("%s/snapshots/.20260301T000000Z.abc", repo);

            CHECK(lstat(p, &sb) != 0);
            CHECK(lstat(q, &sb) != 0);
            free(p);
            free(q);
        }
        /* What is left is whole. */
        rs_index_init(&ix);
        CHECK(rs_repo_load_index(r, third, &ix, &err));
        s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
        CHECK(read_stream(s, &seen, &err));
        CHECK(rs_repo_stream_close(s, &err));
        CHECK_INT(lines(seen.data, " 0 "), 8);
        CHECK_INT(matching(&ix, seen.data), 8);
        rs_buf_reset(&seen);
        /* A snapshot that cannot be read stops prune before any content goes. */
        {
            char *index = rs_xasprintf("%s/snapshots/%s/index.json.gz", repo, third);
            char *where = rs_xasprintf("%s/snapshots/%s", repo, third);

            CHECK(unlink(index) == 0);
            put(where, "index.json.gz", "not gzip", 0600);
            free(where);
            CHECK(!rs_repo_prune(r, &keep, false, &pr, &err));
            CHECK(err.len > 0);
            rs_repo_pruned_free(&pr);
            rs_buf_reset(&err);
            free(index);
        }
        rs_index_free(&ix);
        rs_repo_close(r);
    }
    rs_repo_set_pack_size(0);

    rs_index_free(&ix2);
    free(snapdir);
    free(first);
    free(second);
    free(third);
    rs_buf_free(&err);
    rs_buf_free(&gz);
    rs_buf_free(&sig);
    rs_buf_free(&seen);
    free(repo);
    free(tree);
}

/* A file like big_file's, with `insert` put in at `at`. */
static void big_file_with(const char *dir, const char *name, size_t size, unsigned seed,
                          size_t at, const char *insert)
{
    char  *path = rs_xasprintf("%s/%s", dir, name);
    FILE  *fp = fopen(path, "w");
    size_t i;

    for (i = 0; fp && i < size; i++)
    {
        if (i == at)
        {
            (void)fputs(insert, fp);
        }
        seed = seed * 1103515245u + 12345u;
        (void)fputc((int)(seed >> 16 & 0xff), fp);
    }
    if (fp)
    {
        (void)fclose(fp);
    }
    free(path);
}

/* What a snapshot's summary says was new. */
static uint64_t new_bytes(const struct rs_repo *r, const char *name)
{
    struct rs_jval info;
    struct rs_buf  err;
    uint64_t       n = 0;

    rs_buf_init(&err);
    if (rs_repo_info(r, name, &info, &err))
    {
        const struct rs_jval *v = rs_jobject_get(&info, "new_bytes");

        (void)(v && rs_jval_u64(v, &n));
        rs_jval_free(&info);
    }
    rs_buf_free(&err);
    return n;
}

static void test_chunks(const char *dir)
{
    char                  *repo = rs_xasprintf("%s/repo3", dir);
    char                  *tree = rs_xasprintf("%s/tree3", dir);
    size_t                 size = 16 * 1024 * 1024;
    char                  *a = NULL;
    char                  *b = NULL;
    struct rs_buf          err;
    struct rs_buf          seen;
    struct rs_index        ix;
    struct rs_scan_stats   st;
    struct rs_repo        *r;
    struct rs_repo_stream *s;
    bool                   busy;

    rs_buf_init(&err);
    rs_buf_init(&seen);
    CHECK(rs_repo_init(repo, false, &err));
    CHECK(mkdir(tree, 0755) == 0);
    big_file(tree, "disk", size, 5);
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    rs_repo_set_pack_size(4 * 1024 * 1024);

    TEST_CASE("repo: a big file changed in the middle costs the chunks around the change");
    CHECK(snap(r, tree, "2026-03-01T00:00:00.000000000Z", NULL, &st, &a));
    CHECK(new_bytes(r, a) >= size);
    big_file_with(tree, "disk", size, 5, size / 2, "a hundred bytes or so, put in the middle");
    rs_index_init(&ix);
    CHECK(rs_repo_load_index(r, a, &ix, &err));
    CHECK(snap(r, tree, "2026-03-02T00:00:00.000000000Z", &ix, &st, &b));
    CHECK(new_bytes(r, b) > 0 && new_bytes(r, b) < size / 2);
    rs_index_free(&ix);

    TEST_CASE("repo: a file put together from chunks in old packs and new");
    rs_index_init(&ix);
    CHECK(rs_repo_load_index(r, b, &ix, &err));
    s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
    CHECK(read_stream(s, &seen, &err));
    CHECK(rs_repo_stream_close(s, &err));
    CHECK_INT(matching(&ix, seen.data), 1);
    rs_buf_reset(&seen);
    rs_index_free(&ix);
    rs_repo_close(r);

    TEST_CASE("repo: prune keeps the chunks a file still needs");
    {
        struct rs_repo_keep   keep;
        struct rs_repo_pruned pr;

        r = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
        memset(&keep, 0, sizeof(keep));
        keep.last = 1;
        CHECK(rs_repo_prune(r, &keep, false, &pr, &err));
        CHECK_STR(err.data ? err.data : "", "");
        CHECK_INT(pr.ndropped, 1);
        CHECK(pr.packs_removed + pr.packs_rewritten > 0);
        rs_repo_pruned_free(&pr);
        rs_index_init(&ix);
        CHECK(rs_repo_load_index(r, b, &ix, &err));
        s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
        CHECK(read_stream(s, &seen, &err));
        CHECK(rs_repo_stream_close(s, &err));
        CHECK_INT(matching(&ix, seen.data), 1);
        rs_buf_reset(&seen);
        rs_index_free(&ix);
        rs_repo_close(r);
    }
    rs_repo_set_pack_size(0);
    free(a);
    free(b);
    rs_buf_free(&err);
    rs_buf_free(&seen);
    free(repo);
    free(tree);
}

static int quiet_system(const char *cmd)
{
    char *q = rs_xasprintf("%s > /dev/null 2>&1", cmd);
    int   rc = system(q);

    free(q);
    return rc;
}

/* Whether the first bytes of every file `pattern` matches are an OpenPGP
 * message's; and that there is at least one. */
static bool all_sealed(const char *pattern)
{
    char  *cmd = rs_xasprintf("ls %s 2> /dev/null", pattern);
    FILE  *fp = popen(cmd, "r");
    char   line[1024];
    size_t n = 0;
    bool   ok = true;

    while (fp && fgets(line, sizeof(line), fp))
    {
        int           fd;
        unsigned char head[16];
        ssize_t       got;

        line[strcspn(line, "\n")] = '\0';
        fd = open(line, O_RDONLY);
        got = fd >= 0 ? read(fd, head, sizeof(head)) : -1;
        ok = ok && got > 0 && rs_pgp_detect(head, (size_t)got);
        if (fd >= 0)
        {
            (void)close(fd);
        }
        n++;
    }
    if (fp)
    {
        (void)pclose(fp);
    }
    free(cmd);
    return ok && n > 0;
}

static size_t count(const char *pattern)
{
    char  *cmd = rs_xasprintf("ls %s 2> /dev/null | wc -l", pattern);
    FILE  *fp = popen(cmd, "r");
    size_t n = 0;

    if (fp)
    {
        if (fscanf(fp, "%zu", &n) != 1)
        {
            n = 0;
        }
        (void)pclose(fp);
    }
    free(cmd);
    return n;
}

/* The chunking key this machine's cache holds for the one repository in it. */
static char *cached_key(const char *cache)
{
    char  *cmd = rs_xasprintf("cat '%s'/*/keys/chunks 2> /dev/null", cache);
    FILE  *fp = popen(cmd, "r");
    char   line[128];
    char  *key = NULL;

    if (fp && fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\n")] = '\0';
        key = rs_xstrdup(line);
    }
    if (fp)
    {
        (void)pclose(fp);
    }
    free(cmd);
    return key;
}

static void test_encrypted(const char *dir)
{
    char                  *home = rs_xasprintf("%s/gnupg", dir);
    char                  *empty = rs_xasprintf("%s/gnupg-empty", dir);
    char                  *pub = rs_xasprintf("%s/pub.gpg", dir);
    char                  *repo = rs_xasprintf("%s/erepo", dir);
    char                  *tree = rs_xasprintf("%s/etree", dir);
    char                  *cache = rs_xasprintf("%s/cache", dir);
    char                  *key1 = NULL;
    char                  *key2 = NULL;
    char                  *old_home = getenv("GNUPGHOME") ? rs_xstrdup(getenv("GNUPGHOME")) : NULL;
    const char            *recips[1];
    char                  *first = NULL;
    char                  *second = NULL;
    char                  *third = NULL;
    char                  *pattern;
    char                  *cmd;
    struct rs_buf          err;
    struct rs_buf          seen;
    struct rs_index        ix;
    struct rs_scan_stats   st;
    struct rs_repo        *r;
    struct rs_repo_stream *s;
    struct rs_repo_keep    keep;
    struct rs_repo_pruned  pr;
    bool                   busy;

    if (!rs_program_path(RS_PROG_GPG) || access("/usr/bin/gpgconf", X_OK) != 0)
    {
        (void)printf("  (encrypted repository tests skipped: they need gpg)\n");
        goto done;
    }
    rs_buf_init(&err);
    rs_buf_init(&seen);
    (void)mkdir(home, 0700);
    (void)mkdir(empty, 0700);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --pinentry-mode loopback --passphrase '' "
                       "--quick-gen-key 'restate test <test@example.invalid>' default default never",
                       home);
    CHECK(quiet_system(cmd) == 0);
    free(cmd);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpg --batch --export > '%s' 2>/dev/null", home, pub);
    CHECK(system(cmd) == 0);
    free(cmd);
    (void)setenv("GNUPGHOME", home, 1);
    rs_repo_set_cache_dir(cache);
    recips[0] = pub;
    put(tree, "etc/conf", "conf\n", 0644);
    big_file(tree, "big", 3 * 1024 * 1024, 11);

    TEST_CASE("repo: an encrypted repository, and the keys it needs");
    CHECK(rs_repo_init(repo, true, &err));
    CHECK(rs_repo_dir_encrypted(repo));
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    CHECK(r != NULL);
    if (!r)
    {
        goto out;
    }
    CHECK(rs_repo_encrypted(r));
    CHECK(rs_repo_writer_begin(r, &err) == NULL);
    CHECK_CONTAINS(err.data ? err.data : "", "give the public keys");
    rs_buf_reset(&err);
    rs_repo_set_recipients(r, recips, 1);
    rs_repo_set_pack_size(1024 * 1024);
    CHECK(snap(r, tree, "2026-04-01T00:00:00.000000000Z", NULL, &st, &first));

    TEST_CASE("repo: everything in it encrypted, and this machine's copy of what it wrote");
    pattern = rs_xasprintf("'%s'/packs/*.idx", repo);
    CHECK(all_sealed(pattern));
    free(pattern);
    pattern = rs_xasprintf("'%s'/packs/*.tar.gz", repo);
    CHECK(all_sealed(pattern));
    free(pattern);
    pattern = rs_xasprintf("'%s'/snapshots/*/*", repo);
    CHECK(all_sealed(pattern));
    free(pattern);
    pattern = rs_xasprintf("'%s'/*/packs/*.idx", cache);
    CHECK(count(pattern) >= 2);
    free(pattern);
    /* The chunking key: in the repository, encrypted, and here in the clear. */
    pattern = rs_xasprintf("'%s'/" RS_REPO_CHUNK_KEY, repo);
    CHECK(all_sealed(pattern));
    free(pattern);
    pattern = rs_xasprintf("'%s'/*/keys/chunks", cache);
    CHECK_INT(count(pattern), 1);
    free(pattern);
    key1 = cached_key(cache);
    CHECK(key1 && strlen(key1) == 64);
    pattern = rs_xasprintf("'%s'/*/snapshots/*.json.gz", cache);
    CHECK_INT(count(pattern), 1);
    free(pattern);

    TEST_CASE("repo: an encrypted repository read back with its secret key");
    rs_index_init(&ix);
    CHECK(rs_repo_load_index(r, first, &ix, &err));
    s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
    CHECK(read_stream(s, &seen, &err));
    CHECK(rs_repo_stream_close(s, &err));
    CHECK_INT(matching(&ix, seen.data), 2);
    CHECK(new_bytes(r, first) > 0);
    rs_buf_reset(&seen);
    rs_index_free(&ix);
    rs_repo_close(r);

    TEST_CASE("repo: captured into, and pruned, without the secret key");
    (void)setenv("GNUPGHOME", empty, 1);
    rs_quiet = true;
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    rs_repo_set_recipients(r, recips, 1);
    rs_index_init(&ix);
    CHECK(!rs_repo_load_index(r, first, &ix, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "could not be decrypted");
    rs_buf_reset(&err);
    rs_index_free(&ix);
    rs_index_init(&ix);
    CHECK(rs_repo_load_index_cached(r, first, &ix, &err));
    put(tree, "etc/conf", "changed\n", 0644);
    CHECK(snap(r, tree, "2026-04-02T00:00:00.000000000Z", &ix, &st, &second));
    CHECK_INT(st.reused, 1);
    CHECK(new_bytes(r, second) == 0);   /* its summary cannot be read */
    rs_index_free(&ix);
    rs_repo_close(r);
    r = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
    memset(&keep, 0, sizeof(keep));
    keep.last = 1;
    CHECK(rs_repo_prune(r, &keep, false, &pr, &err));
    CHECK_STR(err.data ? err.data : "", "");
    CHECK_INT(pr.ndropped, 1);
    rs_repo_pruned_free(&pr);
    rs_repo_close(r);

    TEST_CASE("repo: without the cache or the key, a capture stores what it cannot see again, "
              "and prune removes nothing");
    rs_test_rmtree(cache);
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    rs_repo_set_recipients(r, recips, 1);
    CHECK(snap(r, tree, "2026-04-03T00:00:00.000000000Z", NULL, &st, &third));
    rs_repo_close(r);
    /* A key of its own, since it cannot read the repository's; which stays. */
    key2 = cached_key(cache);
    CHECK(key2 && key1 && strcmp(key1, key2) != 0);
    r = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
    CHECK(!rs_repo_prune(r, &keep, false, &pr, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "could not be read");
    rs_buf_reset(&err);
    rs_repo_pruned_free(&pr);
    rs_repo_close(r);
    rs_quiet = false;

    TEST_CASE("repo: with the key again, the repository's chunking key is read back");
    (void)setenv("GNUPGHOME", home, 1);
    rs_test_rmtree(cache);
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    rs_repo_set_recipients(r, recips, 1);
    {
        struct rs_repo_writer *w = rs_repo_writer_begin(r, &err);

        CHECK(w != NULL);
        rs_repo_writer_abort(w);
    }
    rs_repo_close(r);
    free(key2);
    key2 = cached_key(cache);
    CHECK(key2 && key1 && strcmp(key1, key2) == 0);

    TEST_CASE("repo: with the key again, prune rewrites, and what is left is whole");
    r = rs_repo_open(repo, RS_REPO_PRUNE, &busy, &err);
    CHECK(rs_repo_prune(r, &keep, false, &pr, &err));
    CHECK_STR(err.data ? err.data : "", "");
    CHECK(pr.packs_left > 0 || pr.packs_removed > 0);
    rs_repo_pruned_free(&pr);
    rs_repo_set_recipients(r, recips, 1);
    CHECK(rs_repo_prune(r, &keep, false, &pr, &err));
    rs_repo_pruned_free(&pr);
    rs_index_init(&ix);
    CHECK(rs_repo_load_index(r, third, &ix, &err));
    s = rs_repo_stream_open(r, &ix, NULL, 0, &err);
    CHECK(read_stream(s, &seen, &err));
    CHECK(rs_repo_stream_close(s, &err));
    CHECK_INT(matching(&ix, seen.data), 2);
    rs_buf_reset(&seen);
    rs_index_free(&ix);
    rs_repo_close(r);

out:
    rs_quiet = false;
    rs_repo_set_pack_size(0);
    rs_repo_set_cache_dir(NULL);
    cmd = rs_xasprintf("GNUPGHOME='%s' gpgconf --kill gpg-agent", home);
    (void)quiet_system(cmd);
    free(cmd);
    rs_buf_free(&err);
    rs_buf_free(&seen);
    free(key1);
    free(key2);
    free(first);
    free(second);
    free(third);

done:
    if (old_home)
    {
        (void)setenv("GNUPGHOME", old_home, 1);
    } else
    {
        (void)unsetenv("GNUPGHOME");
    }
    free(old_home);
    free(home);
    free(empty);
    free(pub);
    free(repo);
    free(tree);
    free(cache);
}

void test_repo(void)
{
    char *dir = rs_test_tmpdir();

    test_pure();
    test_made(dir);
    test_written(dir);
    test_chunks(dir);
    test_encrypted(dir);
    rs_test_rmtree(dir);
    free(dir);
}
