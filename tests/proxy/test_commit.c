/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * proxy/commit.c, against repositories restate's own writer made; and
 * proxy/confine.c, in a process of its own that confines itself and says
 * what it could still do.
 */
#include "test.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "commit.h"
#include "confine.h"
#include "gzip.h"
#include "repo.h"
#include "rules.h"
#include "scan.h"
#include "store.h"
#include "util.h"

/* A file of `size` bytes no two runs of which compress alike, at DIR/NAME. */
static void noise(const char *dir, const char *name, size_t size, unsigned seed)
{
    char    *path = rs_xasprintf("%s/%s", dir, name);
    FILE    *fp = fopen(path, "wb");
    uint32_t x = seed * 2654435761u + 1;
    size_t   i;

    CHECK(fp != NULL);
    for (i = 0; fp && i < size; i++)
    {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        (void)fputc((int)(x & 0xff), fp);
    }
    if (fp)
    {
        (void)fclose(fp);
    }
    free(path);
}

/* A snapshot of `tree` into the repository at `repo`: its name. */
static char *snapshot_of(const char *repo, const char *tree)
{
    static const char *const kit[] = { "/etc/", "/etc" };
    struct rs_rules          rules;
    struct rs_scan_opts      so;
    struct rs_scan_stats     st;
    struct rs_index          ix;
    struct rs_repo_writer   *w;
    struct rs_repo_written   done;
    struct rs_buf            err;
    struct rs_repo          *r;
    char                    *name = NULL;
    bool                     busy = false;

    rs_buf_init(&err);
    r = rs_repo_open(repo, RS_REPO_WRITE, &busy, &err);
    CHECK(r != NULL);
    if (!r)
    {
        rs_buf_free(&err);
        return NULL;
    }
    rs_rules_init(&rules);
    memset(&so, 0, sizeof(so));
    memset(&st, 0, sizeof(st));
    so.root = tree;
    so.rules = &rules;
    so.hash = true;
    rs_index_init(&ix);
    w = rs_repo_writer_begin(r, &err);
    rs_repo_writer_kit(w, kit, 2);
    so.store = rs_repo_store;
    so.store_ctx = w;
    so.have = rs_repo_have;
    if (rs_scan(&so, &ix, &st, &err))
    {
        ix.created = rs_xstrdup("2026-10-20T03:00:00.000000000Z");
        ix.root = rs_xstrdup(tree);
        ix.host = rs_xstrdup("test");
        ix.version = rs_xstrdup("x");
        ix.content = rs_xstrdup("state");
        ix.hashed = true;
        if (rs_repo_writer_finish(w, &ix, NULL, &done, &err))
        {
            name = done.name;
        }
    } else
    {
        rs_repo_writer_abort(w);
    }
    CHECK_STR(err.data ? err.data : "", "");
    rs_index_free(&ix);
    rs_rules_free(&rules);
    rs_repo_close(r);
    rs_buf_free(&err);
    return name;
}

/* The packs of `repo`, by name, oldest first: at most `max`, how many. */
static size_t packs_of(const char *repo, char **names, size_t max)
{
    struct rs_store *st = rs_store_local(repo);
    size_t           n = 0;
    size_t           i;
    size_t           got = 0;
    char           **all = rs_store_list(st, "packs", rs_store_keep_all, NULL, &n);

    for (i = 0; i < n; i++)
    {
        size_t len = strlen(all[i]);

        if (got < max && len > 4 && strcmp(all[i] + len - 4, ".idx") == 0 && all[i][0] != '.')
        {
            names[got++] = rs_xstrndup(all[i], len - 4);
        }
        free(all[i]);
    }
    free(all);
    rs_store_free(st);
    return got;
}

/* `cmd`, quietly: its status. */
static int sh(const char *cmd)
{
    char *quiet = rs_xasprintf("%s > /dev/null 2>&1", cmd);
    int   rc = system(quiet);

    free(quiet);
    return rc;
}

/* The pack `name` of `from` uploaded into `staging`, as an upload puts it. */
static void stage_pack(const char *from, const char *name, const char *staging)
{
    char *cmd = rs_xasprintf("mkdir -p '%s/packs' && cp '%s/packs/%s'.* '%s/packs/'", staging,
                             from, name, staging);

    CHECK_INT(sh(cmd), 0);
    free(cmd);
}

static void commit_of(const char *repo, const char *staging, const char *name,
                      struct rs_proxy_committed *out)
{
    rs_proxy_committed_free(out);
    rs_proxy_committed_init(out);
    rs_proxy_commit(repo, staging, name, out);
}

void test_commit(void)
{
    char                     *dir = rs_test_tmpdir();
    char                     *a = rs_xasprintf("%s/a", dir);
    char                     *b = rs_xasprintf("%s/b", dir);
    char                     *enc = rs_xasprintf("%s/enc", dir);
    char                     *tree = rs_xasprintf("%s/tree", dir);
    char                     *staging = rs_xasprintf("%s/staging", dir);
    char                     *packs[8];
    char                     *snap;
    char                     *cmd;
    char                     *name;
    struct rs_proxy_committed out;
    struct rs_buf             err;
    struct rs_repo           *r;
    size_t                    np;
    size_t                    i;
    bool                      busy = false;

    rs_buf_init(&err);
    rs_proxy_committed_init(&out);
    CHECK(rs_repo_init(a, false, &err));
    CHECK(rs_repo_init(b, false, &err));
    CHECK(rs_repo_init(enc, true, &err));
    CHECK(mkdir(tree, 0755) == 0 && mkdir(staging, 0700) == 0);
    rs_test_write(tree, "conf", "conf\n", 0644);
    noise(tree, "big", (size_t)3 * 1024 * 1024, 7);
    rs_repo_set_pack_size(1024 * 1024);
    snap = snapshot_of(a, tree);
    rs_repo_set_pack_size(0);
    np = packs_of(a, packs, 8);
    CHECK(snap != NULL && np >= 2);
    if (!snap || np < 2)
    {
        goto out;
    }

    TEST_CASE("commit: what was not uploaded is not there to commit");
    commit_of(b, staging, "packs/P-1", &out);
    CHECK_INT(out.status, 422);
    CHECK_STR(out.reason, "invalid");
    CHECK_STR(out.message.data, "packs/P-1.tar.gz: not uploaded in this session");

    TEST_CASE("commit: a snapshot before the packs it needs is not one this repository can hold");
    cmd = rs_xasprintf("mkdir -p '%s/snapshots' && cp -R '%s/snapshots/%s' '%s/snapshots/'",
                       staging, a, snap, staging);
    CHECK_INT(sh(cmd), 0);
    free(cmd);
    name = rs_xasprintf("snapshots/%s", snap);
    commit_of(b, staging, name, &out);
    CHECK_INT(out.status, 422);
    CHECK_CONTAINS(out.message.data, "it needs the pack");
    /* Named as the protocol names it, with no path of the host's in it. */
    CHECK(strstr(out.message.data, dir) == NULL);
    CHECK_CONTAINS(out.message.data, "which the repository has not got");

    TEST_CASE("commit: a pack, put in, its staging cleared; again, there already");
    for (i = 0; i < np; i++)
    {
        char *p = rs_xasprintf("packs/%s", packs[i]);
        char *left = rs_xasprintf("%s/packs/%s.tar.gz", staging, packs[i]);

        stage_pack(a, packs[i], staging);
        commit_of(b, staging, p, &out);
        CHECK_INT(out.status, 201);
        CHECK(out.pack_added && !out.snapshot_added && out.reason == NULL);
        CHECK(out.bytes > 0);
        CHECK(access(left, F_OK) != 0);
        free(left);
        free(p);
    }
    {
        char *p = rs_xasprintf("packs/%s", packs[0]);

        stage_pack(a, packs[0], staging);
        commit_of(b, staging, p, &out);
        CHECK_INT(out.status, 200);
        CHECK(!out.pack_added);
        free(p);
    }

    TEST_CASE("commit: another pack by a name that is there is in the way");
    {
        char *p = rs_xasprintf("packs/%s", packs[0]);

        stage_pack(a, packs[0], staging);
        cmd = rs_xasprintf("cp '%s/packs/%s.sum' '%s/packs/%s.sum'", a, packs[1], staging,
                           packs[0]);
        CHECK_INT(sh(cmd), 0);
        free(cmd);
        commit_of(b, staging, p, &out);
        CHECK_INT(out.status, 409);
        CHECK_STR(out.reason, "name-taken");
        CHECK_CONTAINS(out.message.data, "not the same pack");
        CHECK(strstr(out.message.data, b) == NULL);
        free(p);
    }

    TEST_CASE("commit: a pack that is not what its .sum says is refused, and not put in");
    {
        char *pa = rs_xasprintf("packs/%s", packs[0]);

        /* A fresh repository, so that the name is not already there. */
        rs_test_rmtree(b);
        CHECK(rs_repo_init(b, false, &err));
        stage_pack(a, packs[0], staging);
        cmd = rs_xasprintf("%s/packs/%s.tar.gz", staging, packs[0]);
        {
            FILE *fp = fopen(cmd, "ab");

            CHECK(fp != NULL && fputc('x', fp) == 'x');
            if (fp)
            {
                (void)fclose(fp);
            }
        }
        free(cmd);
        commit_of(b, staging, pa, &out);
        CHECK_INT(out.status, 422);
        CHECK_CONTAINS(out.message.data, "it is not what its .sum says");
        CHECK_INT((long long)packs_of(b, packs + np, 1), 0);
        free(pa);
        for (i = 0; i < np; i++)
        {
            char *p = rs_xasprintf("packs/%s", packs[i]);

            stage_pack(a, packs[i], staging);
            commit_of(b, staging, p, &out);
            CHECK_INT(out.status, 201);
            free(p);
        }
    }

    TEST_CASE("commit: the snapshot, last, once its packs are there; again, there already");
    commit_of(b, staging, name, &out);
    CHECK_INT(out.status, 201);
    CHECK(out.snapshot_added && !out.pack_added);
    cmd = rs_xasprintf("%s/snapshots/%s", staging, snap);
    CHECK(access(cmd, F_OK) != 0);
    free(cmd);
    cmd = rs_xasprintf("cp -R '%s/snapshots/%s' '%s/snapshots/'", a, snap, staging);
    CHECK_INT(sh(cmd), 0);
    free(cmd);
    commit_of(b, staging, name, &out);
    CHECK_INT(out.status, 200);
    free(name);

    TEST_CASE("commit: a pack taken out again, .idx first, and gone from the list");
    r = rs_repo_open(b, RS_REPO_WRITE, &busy, &err);
    CHECK(r != NULL);
    if (r)
    {
        CHECK(rs_repo_remove_pack(r, packs[0], &err));
        CHECK(!rs_repo_remove_pack(r, "../x", &err));
        rs_repo_close(r);
    }
    cmd = rs_xasprintf("%s/packs/%s.tar.gz", b, packs[0]);
    CHECK(access(cmd, F_OK) != 0);
    free(cmd);
    CHECK_INT((long long)packs_of(b, packs + np, 8), (long long)np - 1);
    for (i = np; i < np + np - 1; i++)
    {
        free(packs[i]);
    }

    TEST_CASE("commit: a chunk key, only an encrypted repository's, and the first kept");
    rs_test_write(staging, "chunk-key", "\xc1\x10 not really, but it begins as one does", 0600);
    commit_of(b, staging, "chunk-key", &out);
    CHECK_INT(out.status, 422);
    CHECK_CONTAINS(out.message.data, "not encrypted has no chunk key");
    commit_of(enc, staging, "chunk-key", &out);
    CHECK_INT(out.status, 201);
    rs_test_write(staging, "chunk-key", "\xc1\x10 another", 0600);
    commit_of(enc, staging, "chunk-key", &out);
    CHECK_INT(out.status, 200);
    cmd = rs_xasprintf("%s/chunk-key", enc);
    {
        char *kept = rs_test_slurp(cmd);

        CHECK_CONTAINS(kept ? kept : "", "not really");
        free(kept);
    }
    free(cmd);
    rs_test_write(staging, "chunk-key.20261020T030000Z-001", "plain text", 0600);
    commit_of(enc, staging, "chunk-key.20261020T030000Z-001", &out);
    CHECK_INT(out.status, 422);
    CHECK_CONTAINS(out.message.data, "not a chunk key restate wrote");
    {
        struct rs_repo_ingested in;
        bool                    placed;

        memset(&in, 0, sizeof(in));
        r = rs_repo_open(enc, RS_REPO_WRITE, &busy, &err);
        CHECK(r != NULL);
        if (r)
        {
            rs_buf_reset(&err);
            CHECK(!rs_repo_ingest_chunk_key(r, staging, "chunk-key", &placed, &in, &err));
            CHECK_CONTAINS(err.data, "not a regular file");
            rs_buf_reset(&err);
            CHECK(!rs_repo_ingest_chunk_key(r, "/nonexistent/x", "chunk-key", &placed, &in,
                                            &err));
            rs_buf_reset(&err);
            CHECK(!rs_repo_ingest_chunk_key(r, staging, "chunk-keys", &placed, &in, &err));
            CHECK_CONTAINS(err.data, "not a name a chunk key has");
            rs_repo_close(r);
        }
    }

    TEST_CASE("commit: a repository that cannot be opened is the proxy's failure");
    rs_test_write(staging, "chunk-key", "\xc1\x10", 0600);
    commit_of("/nonexistent/repo", staging, "chunk-key", &out);
    CHECK_INT(out.status, 500);
    CHECK_STR(out.reason, "proxy-failed");

    TEST_CASE("commit: a version 1 repository is never opened without its lock to write");
    rs_test_write(enc, "restate-repository", "restate-repository 1\n", 0644);
    rs_buf_reset(&err);
    r = rs_repo_open(enc, RS_REPO_HELD, &busy, &err);
    CHECK(r == NULL);
    CHECK_CONTAINS(err.data, "1.3 or older");

out:
    rs_proxy_committed_free(&out);
    for (i = 0; i < np; i++)
    {
        free(packs[i]);
    }
    free(snap);
    rs_buf_free(&err);
    rs_test_rmtree(dir);
    free(a);
    free(b);
    free(enc);
    free(tree);
    free(staging);
    free(dir);
}

/* ------------------------------------------------------------------------ */
/* Confinement                                                              */
/* ------------------------------------------------------------------------ */

/* What one try came to, as a word: "ok" or "no". */
static const char *yes(bool ok)
{
    return ok ? "ok" : "no";
}

/*
 * `unittests --confine-test ROLE REPO STAGING OTHER`: this process confined
 * as ROLE ("connection" or "committer") to REPO and STAGING, and then a line
 * of what it could still do, each "WHAT=ok" or "WHAT=no", for test_confine
 * to hold to what the system promises.
 */
int test_confine_run(char **args)
{
    enum rs_confine_role role = strcmp(args[0], "committer") == 0 ? RS_CONFINE_COMMITTER
                                                                  : RS_CONFINE_CONNECTION;
    struct rs_store     *repo = rs_store_local(args[1]);
    struct rs_store     *staging = rs_store_local(args[2]);
    struct rs_store     *other = rs_store_local(args[3]);
    struct rs_buf        why;
    struct rs_buf        text;
    bool                 read_repo;
    bool                 write_repo;
    bool                 write_staging;
    bool                 read_other;
    bool                 run = false;
    bool                 try_run = true;
    int                  p[2];

    rs_buf_init(&why);
    if (!rs_confine(role, args[1], args[2], &why))
    {
        (void)printf("confine=no why=%s\n", why.data ? why.data : "");
        rs_buf_free(&why);
        rs_store_free(repo);
        rs_store_free(staging);
        rs_store_free(other);
        return 1;
    }
    rs_buf_free(&why);
    rs_buf_init(&why);
    read_repo = rs_store_read(repo, "restate-repository", 4096, &text, &why);
    rs_buf_free(&text);
    /* Each role's own name, so that one run's file is not in the next's way. */
    write_repo = rs_store_write_new(repo, args[0], "x", 1, &why);
    write_staging = rs_store_write_new(staging, args[0], "x", 1, &why);
    read_other = rs_store_read(other, "restate-repository", 4096, &text, &why);
    rs_buf_free(&text);
    /* gzip, as a commit runs it: started or not. Not tried by a connection
     * on OpenBSD, which pledge ends for a fork it did not promise. */
#ifdef __OpenBSD__
    try_run = role != RS_CONFINE_CONNECTION;
#endif
    rs_buf_free(&why);
    rs_buf_init(&why);
    if (try_run && pipe(p) == 0)
    {
        struct rs_gzip gz;

        run = rs_gzip_decompress(p[0], &gz, &why);
        (void)close(p[1]);
        (void)close(p[0]);
        if (run)
        {
            (void)rs_gzip_finish(&gz, true, &why);
        }
    }
    /* With why gzip did not start, for a failure to say. */
    (void)printf("confine=ok read-repo=%s write-repo=%s write-staging=%s read-other=%s "
                 "run=%s%s%s\n",
                 yes(read_repo), yes(write_repo), yes(write_staging), yes(read_other), yes(run),
                 !run && why.data ? " run-why=" : "", !run && why.data ? why.data : "");
    rs_buf_free(&why);
    rs_store_free(repo);
    rs_store_free(staging);
    rs_store_free(other);
    rs_store_unconfine();
    return 0;
}

/* What `unittests --confine-test ROLE ...` said, run in a process of its
 * own: its line, the caller's to free. */
static char *confined(const char *role, const char *repo, const char *staging, const char *other)
{
    char *cmd = rs_xasprintf("'%s' --confine-test %s '%s' '%s' '%s' 2>&1", rs_test_argv0, role,
                             repo, staging, other);
    FILE *fp;
    char  line[1024] = "";

    (void)fflush(NULL);
    fp = popen(cmd, "r");
    if (fp)
    {
        if (!fgets(line, sizeof(line), fp))
        {
            line[0] = '\0';
        }
        (void)pclose(fp);
    }
    free(cmd);
    line[strcspn(line, "\n")] = '\0';
    return rs_xstrdup(line);
}

void test_confine(void)
{
    char         *dir = rs_test_tmpdir();
    char         *repo = rs_xasprintf("%s/repo", dir);
    char         *staging = rs_xasprintf("%s/staging", dir);
    char         *other = rs_xasprintf("%s/other", dir);
    const char   *how = rs_confine_how();
    struct rs_buf err;
    char         *said;

    rs_buf_init(&err);
    CHECK(rs_repo_init(repo, false, &err) && rs_repo_init(other, false, &err));
    CHECK(mkdir(staging, 0700) == 0);

    TEST_CASE("confine: the system says how it confines");
    CHECK(how[0] != '\0');

    TEST_CASE("confine: the store reaches a confined directory through its descriptor");
    {
        const char      *dirs[] = { staging };
        struct rs_store *st = rs_store_local(staging);
        char            *made;
        size_t           n = 0;
        char           **names;
        struct rs_buf    text;

        CHECK(rs_store_confine(dirs, 1, &err));
        CHECK(rs_store_write_new(st, "f", "abc", 3, &err));
        CHECK(rs_store_make_dir(st, "d", 0700, false) == 0);
        CHECK(rs_store_rename(st, "f", "d/g", false) == 0);
        CHECK(rs_store_read(st, "d/g", 16, &text, &err));
        CHECK_STR(text.data, "abc");
        rs_buf_free(&text);
        made = rs_store_make_temp_dir(st, "d/.t.");
        CHECK(made != NULL && rs_starts_with(made ? made : "", "d/.t."));
        CHECK(made && rs_store_remove_dir(st, made, false) == 0);
        free(made);
        CHECK_INT(rs_store_place_new(st, "d/g", "h"), 1);
        CHECK_INT(rs_store_place_new(st, "d/g", "h"), 0);
        names = rs_store_list(st, "", rs_store_keep_all, NULL, &n);
        CHECK_INT((long long)n, 2);
        while (n > 0)
        {
            free(names[--n]);
        }
        free(names);
        CHECK(rs_store_stat(st, "", &(struct rs_store_stat){ 0 }) == 0);
        CHECK(rs_store_remove(st, "h", false) == 0 && rs_store_remove(st, "d/g", false) == 0);
        CHECK(rs_store_remove_dir(st, "d", false) == 0);
        {
            const char *gone[] = { "/nonexistent/dir" };

            CHECK(!rs_store_confine(gone, 1, &err));
            CHECK_CONTAINS(err.data, "/nonexistent/dir");
        }
        rs_store_unconfine();
        rs_store_free(st);
    }

    if (!rs_test_argv0)
    {
        (void)printf("  - confine: this program cannot be found to run again; not run\n");
        goto out;
    }
    TEST_CASE("confine: a connection reads its repository and writes its staging, and no more");
    said = confined("connection", repo, staging, other);
    CHECK_CONTAINS(said, "confine=ok read-repo=ok");
    CHECK_CONTAINS(said, "write-staging=ok");
#if defined(__linux__)
    if (rs_starts_with(how, "landlock"))
    {
        CHECK_CONTAINS(said, "write-repo=no write-staging=ok read-other=no run=no");
    } else if (strcmp(how, "seccomp") == 0)
    {
        CHECK_CONTAINS(said, "run=no");
    }
#elif defined(__OpenBSD__)
    CHECK_CONTAINS(said, "write-repo=no write-staging=ok read-other=no");
#elif defined(__FreeBSD__)
    CHECK_CONTAINS(said, "read-other=no run=no");
#endif
    free(said);

    TEST_CASE("confine: a committer writes its repository, and runs gzip");
    said = confined("committer", repo, staging, other);
    CHECK_CONTAINS(said, "confine=ok read-repo=ok write-repo=ok write-staging=ok");
    CHECK_CONTAINS(said, "run=ok");
#if defined(__linux__)
    if (rs_starts_with(how, "landlock"))
    {
        CHECK_CONTAINS(said, "read-other=no");
    }
#elif defined(__OpenBSD__)
    CHECK_CONTAINS(said, "read-other=no");
#endif
    free(said);

    TEST_CASE("confine: one that cannot be is said to be, and nothing more is done");
    said = confined("connection", "/nonexistent/repo", staging, other);
    if (!rs_starts_with(how, "none") && strcmp(how, "seccomp") != 0)
    {
        CHECK_CONTAINS(said, "confine=no why=");
    }
    free(said);

out:
    rs_buf_free(&err);
    rs_test_rmtree(dir);
    free(repo);
    free(staging);
    free(other);
    free(dir);
}
