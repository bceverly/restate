/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "remote.h"
#include "repo.h"
#include "store.h"
#include "test.h"
#include "util.h"

#define TOKEN "rsp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SID   "6f1c0a9d2e7b4c35a8f0e1d2c3b4a596"
#define URL   "https://proxy.example:8443/v1/web01"

/* A proxy, as far as the tests need one: a repository's directory, and what
 * it has been asked. */
struct fake {
    const char *repo;
    bool        busy;       /* sessions are refused, 423 */
    bool        silent;     /* nothing is answered, as with no proxy there */
    int         runs;       /* how many curls */
    int         requests;   /* and requests in them */
    int         renews;
    int         ends;
    char        kind[16];   /* the last session's */
    char        last_range[64];
};

/* How the fake answers from now on: refusing sessions as busy, or saying
 * nothing at all. */
static void fake_set(struct fake *f, bool busy, bool silent)
{
    f->busy = busy;
    f->silent = silent;
}

/* `line`'s value, if it is `key = "VALUE"`: unquoted, the caller's to free. */
static char *value_of(const char *line, const char *key)
{
    size_t        n = strlen(key);
    const char   *p;
    struct rs_buf b;

    if (strncmp(line, key, n) != 0 || strncmp(line + n, " = \"", 4) != 0)
    {
        return NULL;
    }
    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (p = line + n + 4; *p && *p != '"'; p++)
    {
        if (*p == '\\' && p[1])
        {
            p++;
        }
        rs_buf_addc(&b, *p);
    }
    return rs_buf_detach(&b);
}

/* The listing of `dir` in the repository, as the proxy writes one. */
static bool list_dir(const char *path, struct rs_buf *out)
{
    DIR                 *d = opendir(path);
    const struct dirent *de;
    char               **names = NULL;
    size_t               n = 0;
    size_t               i;

    if (!d)
    {
        return false;
    }
    while ((de = readdir(d)) != NULL)
    {
        if (de->d_name[0] != '.')
        {
            names = rs_xreallocarray(names, n + 1, sizeof(*names));
            names[n++] = rs_xstrdup(de->d_name);
        }
    }
    (void)closedir(d);
    rs_buf_addstr(out, "restate-list 1\n");
    for (i = 0; i < n; i++)
    {
        char       *p = rs_xasprintf("%s/%s", path, names[i]);
        struct stat st;

        if (lstat(p, &st) == 0)
        {
            char kind = S_ISREG(st.st_mode) ? 'f' : S_ISDIR(st.st_mode) ? 'd' : 'o';

            rs_buf_addf(out, "%c %lld %lld %s\n", kind, (long long)st.st_size,
                        (long long)st.st_mtime, names[i]);
        }
        free(p);
        free(names[i]);
    }
    free(names);
    return true;
}

/* One request answered: headers into `hdr`, a body into `out`. */
static void answer(struct fake *f, const char *url, const char *auth, const char *range,
                   const char *method, const char *data, const char *hdr, const char *out)
{
    const char   *path = url + strlen(URL);
    struct rs_buf head;
    struct rs_buf body;
    int           status = 200;
    const char   *reason = NULL;

    rs_buf_init(&head);
    rs_buf_init(&body);
    rs_buf_add(&body, "", 0);
    f->requests++;
    if (!auth || strcmp(auth, "Authorization: Bearer " TOKEN) != 0)
    {
        status = 401;
        reason = "unauthorized";
        rs_buf_addstr(&body, "no good token\n");
    } else if (method && strcmp(path, "/sessions") == 0)
    {
        (void)snprintf(f->kind, sizeof(f->kind), "%s", data ? data : "");
        status = f->busy ? 423 : 201;
        reason = f->busy ? "busy" : NULL;
        rs_buf_addstr(&body, f->busy ? "the repository is busy\n" : SID "\n");
    } else if (method && strcmp(path, "/sessions/" SID "/renew") == 0)
    {
        f->renews++;
        status = 204;
    } else if (method && strcmp(path, "/sessions/" SID "/end") == 0)
    {
        f->ends++;
        status = 204;
    } else if (rs_starts_with(path, "/list/"))
    {
        char  *dir = rs_xasprintf("%s/%s", f->repo, path + 6);
        size_t len = strlen(dir);

        if (len > 0 && dir[len - 1] == '/')
        {
            dir[len - 1] = '\0';
        }
        if (!list_dir(dir, &body))
        {
            status = 404;
            reason = "not-found";
        }
        free(dir);
    } else if (rs_starts_with(path, "/f/"))
    {
        char       *file = rs_xasprintf("%s/%s", f->repo, path + 3);
        struct stat st;
        char       *text = lstat(file, &st) == 0 && S_ISREG(st.st_mode) ? rs_test_slurp(file)
                                                                          : NULL;

        if (!text)
        {
            status = 404;
            reason = "not-found";
        } else if (range)
        {
            unsigned long long first = strtoull(range, NULL, 10);
            const char        *dash = strchr(range, '-');
            unsigned long long last = dash && dash[1] ? strtoull(dash + 1, NULL, 10)
                                                      : (unsigned long long)strlen(text);
            size_t             size = strlen(text);

            (void)snprintf(f->last_range, sizeof(f->last_range), "%s", range);
            if (first >= size)
            {
                status = 416;
                reason = "bad-request";
            } else
            {
                if (last >= size)
                {
                    last = size - 1;
                }
                status = 206;
                rs_buf_add(&body, text + first, (size_t)(last - first + 1));
            }
        } else
        {
            rs_buf_addstr(&body, text);
        }
        free(text);
        free(file);
    } else
    {
        status = 404;
        reason = "not-found";
    }
    if (method && status == 201)
    {
        rs_buf_addstr(&head, "HTTP/1.1 100 Continue\r\n\r\n");
    }
    rs_buf_addf(&head, "HTTP/1.1 %d Whatever\r\nContent-Length: %zu\r\n", status, body.len);
    if (reason)
    {
        rs_buf_addf(&head, "Restate-Reason: %s\r\n", reason);
    }
    if (status == 201 || (method && status == 204))
    {
        rs_buf_addstr(&head, "restate-session: " SID "\r\nRestate-Lease:  60 \r\n");
    }
    rs_buf_addstr(&head, "\r\n");
    rs_test_write("/", hdr + 1, head.data, 0600);
    rs_test_write("/", out + 1, body.data, 0600);
    rs_buf_free(&head);
    rs_buf_free(&body);
}

/* A curl that answers from the fake: reads the config file it was given. */
static int fake_curl(const char *conf, void *ctx)
{
    struct fake *f = ctx;
    char        *text = rs_test_slurp(conf);
    char        *line;
    char        *next;
    char        *url = NULL;
    char        *auth = NULL;
    char        *range = NULL;
    char        *method = NULL;
    char        *data = NULL;
    char        *hdr = NULL;
    char        *out = NULL;

    f->runs++;
    if (f->silent || !text)
    {
        free(text);
        return 7;
    }
    for (line = text; line && *line; line = next)
    {
        char *nl = strchr(line, '\n');
        char *v;

        next = nl ? nl + 1 : NULL;
        if (nl)
        {
            *nl = '\0';
        }
        if (strcmp(line, "next") == 0 && url)
        {
            answer(f, url, auth, range, method, data, hdr, out);
            free(url), free(auth), free(range), free(method), free(data), free(hdr), free(out);
            url = auth = range = method = data = hdr = out = NULL;
        } else if ((v = value_of(line, "url")) != NULL)
        {
            url = v;
        } else if ((v = value_of(line, "header")) != NULL)
        {
            if (rs_starts_with(v, "Authorization:"))
            {
                auth = v;
            } else
            {
                free(v);
            }
        } else if ((v = value_of(line, "range")) != NULL)
        {
            range = v;
        } else if ((v = value_of(line, "request")) != NULL)
        {
            method = v;
        } else if ((v = value_of(line, "data-binary")) != NULL)
        {
            data = v;
        } else if ((v = value_of(line, "dump-header")) != NULL)
        {
            hdr = v;
        } else if ((v = value_of(line, "output")) != NULL)
        {
            out = v;
        }
    }
    if (url)
    {
        answer(f, url, auth, range, method, data, hdr, out);
    }
    free(url), free(auth), free(range), free(method), free(data), free(hdr), free(out);
    free(text);
    return 0;
}

static void remote_names(void)
{
    static const char *const good[] = {
        "https://proxy.example/v1/web01", "https://proxy.example:8443/v1/web01/",
        "https://10.0.0.1:1/v1/a", "https://[::1]:8443/v1/web-01.x_y",
        "https://[fe80::1]/v1/C",
    };
    static const char *const bad[] = {
        "http://proxy.example/v1/web01", "https:///v1/web01", "https://proxy.example/v2/web01",
        "https://proxy.example/v1/", "https://proxy.example/v1/.web",
        "https://proxy.example/v1/-web", "https://proxy.example:0/v1/web01",
        "https://proxy.example:65536/v1/web01", "https://proxy.example:/v1/web01",
        "https://proxy.example/v1/web01/x", "https://proxy.example/v1/web01?x",
        "https://[]/v1/web01", "https://[::1/v1/web01", "https://user@host/v1/web01",
        "https://proxy.example/v1/"
        "a123456789b123456789c123456789d123456789e123456789f123456789g12345",
    };
    size_t i;

    TEST_CASE("remote: names");
    CHECK(rs_remote_is("https://x"));
    CHECK(!rs_remote_is("/srv/restate"));
    CHECK(!rs_remote_is(NULL));
    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
    {
        struct rs_buf err;

        rs_buf_init(&err);
        CHECK(rs_remote_url_ok(good[i], &err));
        CHECK(err.len == 0);
        rs_buf_free(&err);
    }
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        struct rs_buf err;

        rs_buf_init(&err);
        CHECK(!rs_remote_url_ok(bad[i], &err));
        CHECK_CONTAINS(err.data, "https://HOST[:PORT]/v1/CLIENT");
        rs_buf_free(&err);
    }
    CHECK(rs_remote_pin_ok("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
    CHECK(!rs_remote_pin_ok("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"));
    CHECK(!rs_remote_pin_ok("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSu.U="));
    CHECK(!rs_remote_pin_ok(NULL));
}

static void remote_answers(void)
{
    static const char two[] = "HTTP/1.1 100 Continue\r\n\r\n"
                              "HTTP/1.1 201 Created\r\n"
                              "restate-session:  " SID " \r\n"
                              "Restate-Lease: 300\r\n"
                              "Restate-Reason: name-taken\r\n"
                              "\r\n";
    struct rs_remote_answer a;
    struct rs_remote_entry *e;
    size_t                  n;
    const char             *list = "restate-list 1\n"
                                   "f 2130 1761120000 P.idx\n"
                                   "d 0 1761120400 20261020T030000Z\n"
                                   "o 7 1 odd\n";

    TEST_CASE("remote: answers and listings");
    CHECK(rs_remote_parse_headers(two, strlen(two), &a));
    CHECK_INT(a.status, 201);
    CHECK_STR(a.session, SID);
    CHECK_INT(a.lease, 300);
    CHECK_STR(a.reason, "name-taken");
    CHECK(rs_remote_parse_headers("HTTP/2 404\nRestate-Reason: Not Found\n", 37, &a));
    CHECK_INT(a.status, 404);
    CHECK_STR(a.reason, "");
    CHECK(!rs_remote_parse_headers("", 0, &a));
    CHECK(!rs_remote_parse_headers("HTTP/1.1 OK\r\n", 13, &a));
    CHECK(rs_remote_parse_headers("HTTP/1.1 204 x\r\nRestate-Session: abc\r\n"
                                  "Restate-Lease: 9x\r\n", 56, &a));
    CHECK_STR(a.session, "");
    CHECK_INT(a.lease, 0);

    CHECK(rs_remote_parse_list(list, strlen(list), &e, &n));
    CHECK_INT(n, 3);
    if (n == 3)
    {
        CHECK_STR(e[0].name, "P.idx");
        CHECK(e[0].st.kind == RS_STORE_FILE);
        CHECK_INT(e[0].st.size, 2130);
        CHECK_INT(e[0].st.mtime, 1761120000);
        CHECK(e[1].st.kind == RS_STORE_DIR);
        CHECK(e[2].st.kind == RS_STORE_OTHER);
    }
    rs_remote_entries_free(e, n);
    CHECK(rs_remote_parse_list("restate-list 1\n", 15, &e, &n) && n == 0);
    CHECK(!rs_remote_parse_list("restate-list 2\n", 15, &e, &n));
    CHECK(!rs_remote_parse_list("restate-list 1\nx 1 1 a\n", 23, &e, &n));
    CHECK(!rs_remote_parse_list("restate-list 1\nf 1 1 a/b\n", 25, &e, &n));
    CHECK(!rs_remote_parse_list("restate-list 1\nf 1 1 \n", 22, &e, &n));
    CHECK(!rs_remote_parse_list("restate-list 1\nf -1 1 a\n", 24, &e, &n));
    CHECK(!rs_remote_parse_list("restate-list 1\nf 99999999999999999999 1 a\n", 42, &e, &n));
}

/* A fake proxy's repository, and a token file for it. */
static char *setup(struct fake *f, char **token)
{
    char *dir = rs_test_tmpdir();
    char *repo = rs_xasprintf("%s/repo", dir);

    memset(f, 0, sizeof(*f));
    (void)mkdir(repo, 0700);
    {
        char *packs = rs_xasprintf("%s/packs", repo);
        char *snaps = rs_xasprintf("%s/snapshots", repo);
        char *snap = rs_xasprintf("%s/snapshots/S", repo);

        (void)mkdir(packs, 0700);
        (void)mkdir(snaps, 0700);
        (void)mkdir(snap, 0700);
        free(packs);
        free(snaps);
        free(snap);
    }
    rs_test_write(repo, "restate-repository", "restate repository 2\n", 0600);
    rs_test_write(repo, "packs/P.idx", "the index\n", 0600);
    rs_test_write(repo, "packs/P.tar.gz", "0123456789", 0600);
    rs_test_write(repo, "packs/Q.idx", "another\n", 0600);
    rs_test_write(repo, "snapshots/S/info", "a summary\n", 0600);
    rs_test_write(repo, "empty", "", 0600);
    rs_test_write(dir, "token", TOKEN "\n", 0600);
    *token = rs_xasprintf("%s/token", dir);
    f->repo = repo;
    rs_remote_set_transport(fake_curl, f);
    rs_remote_configure(*token, NULL, NULL, 0);
    return dir;
}

static void teardown(char *dir, struct fake *f, char *token)
{
    rs_remote_set_transport(NULL, NULL);
    rs_remote_configure(NULL, NULL, NULL, 0);
    free((char *)f->repo);
    free(token);
    rs_test_rmtree(dir);
    free(dir);
}

static void remote_tokens(void)
{
    struct fake       f;
    char             *token;
    char             *dir = setup(&f, &token);
    struct rs_remote *rm;
    struct rs_buf     err;
    bool              busy;

    TEST_CASE("remote: the token file");
    rs_buf_init(&err);
    rs_remote_configure(NULL, NULL, NULL, 0);
    rm = rs_remote_new(URL "/");
    CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
    CHECK_CONTAINS(err.data, "--repository-token-file");
    rs_remote_free(rm);

    rs_buf_reset(&err);
    (void)chmod(token, 0640);
    rs_remote_configure(token, NULL, NULL, 0);
    rm = rs_remote_new(URL);
    CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
    CHECK_CONTAINS(err.data, "no one else can read or write");
    rs_remote_free(rm);

    rs_buf_reset(&err);
    rs_test_write(dir, "bad", "rsp_short\n", 0600);
    {
        char *bad = rs_xasprintf("%s/bad", dir);

        rs_remote_configure(bad, NULL, NULL, 0);
        rm = rs_remote_new(URL);
        CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
        CHECK_CONTAINS(err.data, "not a restate-proxy token");
        rs_remote_free(rm);
        free(bad);
    }

    rs_buf_reset(&err);
    {
        char *none = rs_xasprintf("%s/none", dir);

        rs_remote_configure(none, NULL, NULL, 0);
        rm = rs_remote_new(URL);
        CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
        CHECK_CONTAINS(err.data, strerror(ENOENT));
        rs_remote_free(rm);
        free(none);
    }
    CHECK_INT(f.runs, 0);
    rs_buf_free(&err);
    teardown(dir, &f, token);
}

/* A keep that, as rs_repo_snapshots' does, stats in another directory for
 * each entry -- so listings are fetched while one is being walked. */
static bool keep_stat_within(const struct rs_store *st, const char *dir, const char *name,
                             void *ctx, char **out)
{
    struct rs_store_stat sb;
    char                *within = rs_xasprintf("%s%s%s/x/y", dir, *dir ? "/" : "", name);

    (void)st;
    (void)rs_remote_stat(ctx, within, &sb);
    free(within);
    *out = rs_xstrdup(name);
    return true;
}

static void remote_reading(void)
{
    static const char *const pins[] = { "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                                        "ZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2U=" };
    struct fake          f;
    char                *token;
    char                *dir = setup(&f, &token);
    char                *ca = rs_xasprintf("%s/ca \"quoted\".pem", dir);
    struct rs_remote    *rm = rs_remote_new(URL);
    struct rs_store     *any = rs_store_local("");
    struct rs_store_stat st;
    struct rs_buf        out;
    struct rs_buf        err;
    char               **names;
    char                 buf[16];
    size_t               n;
    int                  fd;

    TEST_CASE("remote: reading");
    rs_remote_configure(token, ca, pins, 2);
    rs_buf_init(&err);
    CHECK_INT(rs_remote_stat(rm, "", &st), 0);
    CHECK(st.kind == RS_STORE_DIR);
    CHECK_INT(f.runs, 0);

    /* A stat is answered from its directory's listing, fetched once. */
    CHECK_INT(rs_remote_stat(rm, "packs/P.idx", &st), 0);
    CHECK(st.kind == RS_STORE_FILE);
    CHECK_INT(st.size, 10);
    CHECK_STR(f.kind, "look");
    CHECK_INT(rs_remote_stat(rm, "packs/Q.idx", &st), 0);
    CHECK_INT(rs_remote_stat(rm, "packs/R.idx", &st), -1);
    CHECK_INT(errno, ENOENT);
    CHECK_INT(f.requests, 2);
    CHECK_INT(rs_remote_stat(rm, "snapshots/S", &st), 0);
    CHECK(st.kind == RS_STORE_DIR);
    CHECK_INT(rs_remote_stat(rm, "nothing/x", &st), -1);
    CHECK_INT(errno, ENOENT);
    CHECK_INT(rs_remote_stat(rm, "nothing/y", &st), -1);
    CHECK_INT(f.requests, 4);

    names = rs_remote_list(rm, any, "packs", rs_store_keep_all, NULL, &n);
    CHECK_INT(n, 3);
    if (n == 3)
    {
        CHECK_STR(names[0], "P.idx");
        CHECK_STR(names[2], "Q.idx");
    }
    rs_repo_free_names(names, n);
    CHECK_INT(f.requests, 4);
    CHECK(!rs_remote_list(rm, any, "nothing", rs_store_keep_all, NULL, &n));
    CHECK_INT(errno, ENOENT);

    /* Listings fetched while one is walked leave it where it was. */
    names = rs_remote_list(rm, any, "", keep_stat_within, rm, &n);
    CHECK_INT(n, 4);
    if (n == 4)
    {
        CHECK_STR(names[0], "empty");
        CHECK_STR(names[1], "packs");
        CHECK_STR(names[3], "snapshots");
    }
    rs_repo_free_names(names, n);

    CHECK(rs_remote_read(rm, "restate-repository", 4096, &out, &err));
    CHECK_STR(out.data, "restate repository 2\n");
    rs_buf_free(&out);
    CHECK(!rs_remote_read(rm, "packs/P.tar.gz", 4, &out, &err));
    CHECK_CONTAINS(err.data, "packs/P.tar.gz");
    rs_buf_free(&out);
    rs_buf_reset(&err);
    CHECK(!rs_remote_read(rm, "packs/X.idx", 4096, &out, &err));
    CHECK_INT(errno, ENOENT);
    CHECK_STR(err.data, URL "/packs/X.idx: No such file or directory");
    CHECK(rs_remote_reason() == NULL);
    rs_buf_free(&out);

    CHECK_INT(rs_remote_peek(rm, "packs/P.tar.gz", buf, 4), 4);
    CHECK(memcmp(buf, "0123", 4) == 0);
    CHECK_STR(f.last_range, "0-3");
    CHECK_INT(rs_remote_peek(rm, "empty", buf, 4), 0);
    CHECK_INT(rs_remote_peek(rm, "empty", buf, 0), 0);
    CHECK_INT(rs_remote_peek(rm, "gone", buf, 4), -1);

    fd = rs_remote_open_at(rm, "packs/P.tar.gz", 6);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 4);
        CHECK(memcmp(buf, "6789", 4) == 0);
        (void)close(fd);
    }
    CHECK_STR(f.last_range, "6-");
    fd = rs_remote_open_at(rm, "packs/P.tar.gz", 10);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 0);
        (void)close(fd);
    }
    fd = rs_remote_open_at(rm, "packs/P.tar.gz", 0);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 10);
        (void)close(fd);
    }
    CHECK_INT(rs_remote_open_at(rm, "packs/X.tar.gz", 0), -1);
    CHECK_INT(errno, ENOENT);

    /* Many files in one curl; each read afterwards asks nothing more. */
    {
        static const char *const want[] = { "packs/P.idx", "packs/Q.idx", "packs/Z.idx" };
        int                      runs;

        rs_remote_prefetch(rm, want, 3);
        runs = f.runs;
        CHECK(rs_remote_read(rm, "packs/Q.idx", 4096, &out, &err));
        CHECK_STR(out.data, "another\n");
        rs_buf_free(&out);
        CHECK(rs_remote_read(rm, "packs/P.idx", 4096, &out, &err));
        rs_buf_free(&out);
        CHECK_INT(f.runs, runs);
        CHECK(!rs_remote_read(rm, "packs/Z.idx", 4096, &out, &err));
        CHECK_INT(f.runs, runs + 1);
        rs_buf_free(&out);
        rs_remote_prefetch(rm, want, 0);
        CHECK_INT(f.runs, runs + 1);
    }

    CHECK_INT(rs_remote_renew(rm), 1);
    CHECK_INT(f.renews, 1);
    rs_remote_free(rm);
    CHECK_INT(f.ends, 1);
    rs_buf_free(&err);
    rs_store_free(any);
    free(ca);
    teardown(dir, &f, token);
}

static void remote_sessions(void)
{
    struct fake       f;
    char             *token;
    char             *dir = setup(&f, &token);
    struct rs_remote *rm = rs_remote_new(URL);
    struct rs_buf     err;
    bool              busy;

    TEST_CASE("remote: sessions and their locks");
    rs_buf_init(&err);
    CHECK(rs_remote_begin(rm, RS_REMOTE_READ, &busy, &err));
    CHECK_STR(f.kind, "read");
    CHECK(rs_remote_begin(rm, RS_REMOTE_READ, &busy, &err));
    CHECK_INT(f.runs, 1);
    CHECK_INT(rs_remote_lock(rm, "readers", true, &busy, &err), 1);
    CHECK_INT(rs_remote_lock(rm, "lock", false, &busy, &err), -1);
    CHECK_CONTAINS(err.data, "run on the storage host");
    rs_buf_reset(&err);

    /* Another kind ends the one open first. */
    CHECK(rs_remote_begin(rm, RS_REMOTE_APPEND, &busy, &err));
    CHECK_STR(f.kind, "append");
    CHECK_INT(f.ends, 1);
    CHECK_INT(rs_remote_lock(rm, "lock", false, &busy, &err), 1);
    CHECK_INT(rs_remote_lock(rm, "readers", true, &busy, &err), -1);
    rs_remote_free(rm);
    CHECK_INT(f.ends, 2);

    /* Busy, and nothing there to answer. */
    rs_buf_reset(&err);
    fake_set(&f, true, false);
    rm = rs_remote_new(URL);
    CHECK(!rs_remote_begin(rm, RS_REMOTE_APPEND, &busy, &err));
    CHECK(busy);
    CHECK_CONTAINS(err.data, "the repository is busy (423 busy)");
    CHECK_STR(rs_remote_reason(), "busy");
    CHECK(rs_remote_busy());
    rs_remote_free(rm);
    CHECK_INT(f.ends, 2);

    rs_buf_reset(&err);
    fake_set(&f, false, true);
    rm = rs_remote_new(URL);
    CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
    CHECK(!busy);
    CHECK_CONTAINS(err.data, "the proxy did not answer");
    rs_remote_free(rm);

    /* The wrong token: the proxy's own words. */
    rs_buf_reset(&err);
    fake_set(&f, false, false);
    rs_test_write(dir, "other", "rsp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA\n", 0600);
    {
        char *other = rs_xasprintf("%s/other", dir);

        rs_remote_configure(other, NULL, NULL, 0);
        rm = rs_remote_new(URL);
        CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
        CHECK_CONTAINS(err.data, "no good token (401 unauthorized)");
        CHECK_INT(errno, EACCES);
        rs_remote_free(rm);
        free(other);
    }
    rs_buf_free(&err);
    teardown(dir, &f, token);
}

void test_remote(void)
{
    remote_names();
    remote_answers();
    remote_tokens();
    remote_reading();
    remote_sessions();
}
