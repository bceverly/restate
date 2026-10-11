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
#include "repo.h"
#include "rules.h"
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
    struct rs_repo_member *m = NULL;
    size_t                 n = 0;
    char                  *name;
    char                  *idx;
    static const char      hash[] =
        "a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6";

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
    CHECK(rs_repo_parse_idx(idx, strlen(idx), &m, &n));
    CHECK_INT(n, 3);
    CHECK(n == 3 && m[0].live && m[0].member == 1 && m[0].size == 5);
    CHECK_STR(n == 3 ? m[0].hash : "", hash);
    CHECK(n == 3 && !m[1].live && m[1].size == 9);
    CHECK(n == 3 && m[2].member == 10);
    free(m);
    free(idx);
    CHECK(rs_repo_parse_idx("restate-pack 1\n", 15, &m, &n) && n == 0);
    free(m);
    {
        static const char *const bad[] = {
            "restate-pack 2\n",
            "restate-pack 1\n1 - 5",                /* no newline */
            "restate-pack 1\n2 - 5\n1 - 5\n",       /* not numbered upward */
            "restate-pack 1\n01 - 5\n",             /* a leading zero */
            "restate-pack 1\n-1 - 5\n",
            "restate-pack 1\n1  - 5\n",
            "restate-pack 1\n1 xyz 5\n",
            "restate-pack 1\n1 - 99999999999999999999999\n",
            "restate-pack 1\n1 - \n",
            "restate-pack 1\n1",
            "restate-pack 1\n1 ",
            "restate",
        };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        {
            CHECK(!rs_repo_parse_idx(bad[i], strlen(bad[i]), &m, &n));
            CHECK(m == NULL && n == 0);
        }
        idx = rs_xasprintf("restate-pack 1\n1 %.63sG 5\n", hash);
        CHECK(!rs_repo_parse_idx(idx, strlen(idx), &m, &n));
        free(idx);
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
    CHECK(rs_repo_init(repo, &err));
    CHECK(rs_repo_is(repo));
    CHECK(!rs_repo_init(repo, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "a repository already");
    rs_buf_reset(&err);
    put(full, "file", "x", 0644);
    CHECK(!rs_repo_init(full, &err));
    CHECK_CONTAINS(err.data ? err.data : "", "not an empty directory");
    rs_buf_reset(&err);
    CHECK(mkdir(empty, 0755) == 0);
    CHECK(rs_repo_init(empty, &err));
    CHECK(!rs_repo_init("/nonexistent/restate/repo", &err));
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
    put(full, RS_REPO_MARKER, "restate-repository 2\n", 0600);
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
    rs_repo_close(a);
    rs_repo_close(NULL);
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
    CHECK(rs_repo_init(repo, &err));
    put(tree, "etc/conf", "conf\n", 0644);
    put(tree, "etc/dup1", "same\n", 0644);
    put(tree, "etc/dup2", "same\n", 0600);
    put(tree, "home/u/notes", "notes\n", 0644);
    big_file(tree, "big", 1500 * 1024, 1);
    big_file(tree, "bigdup", 1500 * 1024, 1);
    big_file(tree, "other", 1200 * 1024, 2);
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
            heads += strcmp(line, "restate-pack 1\n") == 0;
            dead += strstr(line, " - ") != NULL;
            live += strlen(line) > 66 && strstr(line, " - ") == NULL;
        }
        if (fp)
        {
            (void)pclose(fp);
        }
        /* conf, same, notes, big, other; the second copy of big written and
         * marked dead; three packs at a mebibyte each. */
        CHECK_INT(live, 5);
        CHECK_INT(dead, 1);
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
        got = lines(seen.data, " 0 ");
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
        CHECK(lines(seen.data, " 0 ") < 7);
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
    big_file(tree, "other", 1200 * 1024, 3);
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

void test_repo(void)
{
    char *dir = rs_test_tmpdir();

    test_pure();
    test_made(dir);
    test_written(dir);
    rs_test_rmtree(dir);
    free(dir);
}
