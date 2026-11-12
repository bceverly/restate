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
#include "rules.h"
#include "scan.h"
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
    int         unreached;  /* the next runs that cannot connect, curl's 7 */
    int         drop_first; /* the next runs whose first request cannot */
    int         dropped;
    int         runs;       /* how many curls */
    int         requests;   /* and requests in them */
    int         renews;
    int         ends;
    char        kind[16];   /* the last session's */
    char        last_range[64];
    char       *staging;    /* where uploads go, until committed */
    int         uploads;
    int         commits;
    int         pack_status; /* what a pack's commit is answered, if not 0 */
    bool        take_once;  /* the next snapshot's name is taken as it commits */
};

/* `from` moved to `to`, making the directory it goes in. */
static bool move_in(const char *from, const char *to)
{
    char *dir = rs_xstrdup(to);
    char *slash = strrchr(dir, '/');

    if (slash)
    {
        *slash = '\0';
        (void)mkdir(dir, 0700);
    }
    free(dir);
    return rename(from, to) == 0;
}

/* An upload, into staging: 201. */
static int fake_upload(struct fake *f, const char *name, const char *from)
{
    char *to = rs_xasprintf("%s/%s", f->staging, name);
    char *text = rs_test_slurp(from);
    char *dir = rs_xstrdup(to);
    char *p;

    f->uploads++;
    for (p = strchr(dir + strlen(f->staging) + 1, '/'); p; p = strchr(p + 1, '/'))
    {
        *p = '\0';
        (void)mkdir(dir, 0700);
        *p = '/';
    }
    rs_test_write("/", to + 1, text, 0600);
    free(dir);
    free(text);
    free(to);
    return 201;
}

/* A commit, from staging into the repository, as the proxy makes one; its
 * status and reason. */
static int fake_commit(struct fake *f, const char *name, const char **reason)
{
    char *from = rs_xasprintf("%s/%s", f->staging, name);
    char *to = rs_xasprintf("%s/%s", f->repo, name);
    int   status = 201;

    f->commits++;
    if (rs_starts_with(name, "packs/"))
    {
        static const char *const ext[] = { "tar.gz", "sum", "seek", "idx" };
        size_t                   i;

        status = f->pack_status ? f->pack_status : 201;
        for (i = 0; status == 201 && i < 4; i++)
        {
            char *a = rs_xasprintf("%s.%s", from, ext[i]);
            char *b = rs_xasprintf("%s.%s", to, ext[i]);

            (void)move_in(a, b);
            free(a);
            free(b);
        }
        *reason = status == 201 ? NULL : "invalid";
    } else if (rs_starts_with(name, "snapshots/"))
    {
        struct stat st;

        if (f->take_once)
        {
            f->take_once = false;
            (void)mkdir(to, 0700);
        }
        if (lstat(to, &st) == 0)
        {
            status = 409;
            *reason = "name-taken";
        } else
        {
            (void)move_in(from, to);
        }
    } else
    {
        struct stat st;

        status = lstat(to, &st) == 0 ? 200 : 201;
        if (status == 201)
        {
            (void)move_in(from, to);
        }
    }
    free(from);
    free(to);
    return status;
}

/* How the fake answers from now on: refusing sessions as busy, or saying
 * nothing at all. */
static void fake_set(struct fake *f, bool busy, bool silent)
{
    f->busy = busy;
    f->silent = silent;
}

/* What the fake answers a pack's commit from now on: 0 for as it should. */
static void fake_pack_status(struct fake *f, int status)
{
    f->pack_status = status;
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
                   const char *method, const char *data, const char *upload, const char *hdr,
                   const char *out)
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
    } else if (upload && rs_starts_with(path, "/sessions/" SID "/files/"))
    {
        status = fake_upload(f, path + strlen("/sessions/" SID "/files/"), upload);
    } else if (method && rs_starts_with(path, "/sessions/" SID "/commit/"))
    {
        status = fake_commit(f, path + strlen("/sessions/" SID "/commit/"), &reason);
        if (reason)
        {
            rs_buf_addf(&body, "the commit of %s was refused\n",
                        path + strlen("/sessions/" SID "/commit/"));
        }
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
    if ((status == 201 && !upload && strstr(path, "/commit/") == NULL) ||
        (method && status == 204))
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
/* A request curl could not connect for: no answer, and curl's words. */
static void drop(struct fake *f)
{
    f->dropped++;
    rs_remote_transport_said("curl: (7) Failed to connect to proxy.example port 8443 after 0 ms: "
                             "Could not connect to server");
}

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
    char        *upload = NULL;
    char        *hdr = NULL;
    char        *out = NULL;
    bool         dropping = f->drop_first > 0;
    int          nth = 0;

    f->runs++;
    if (dropping)
    {
        f->drop_first--;
    }
    if (f->unreached > 0)
    {
        f->unreached--;
        free(text);
        return 7;
    }
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
            if (dropping && nth++ == 0)
            {
                drop(f);
            } else
            {
                answer(f, url, auth, range, method, data, upload, hdr, out);
            }
            free(url), free(auth), free(range), free(method), free(data), free(hdr), free(out);
            free(upload);
            url = auth = range = method = data = upload = hdr = out = NULL;
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
        } else if ((v = value_of(line, "upload-file")) != NULL)
        {
            upload = v;
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
        /* The last request: nth is not counted on past it. */
        if (dropping && nth == 0)
        {
            drop(f);
        } else
        {
            answer(f, url, auth, range, method, data, upload, hdr, out);
        }
    }
    free(url), free(auth), free(range), free(method), free(data), free(hdr), free(out);
    free(upload);
    free(text);
    return 0; /* curl's exit status is the last request's */
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
        /* A client's name one longer than there can be. */
        ("https://proxy.example/v1/"
         "a123456789b123456789c123456789d123456789e123456789f123456789g12345"),
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

/* What the client paused for, in all: never slept. */
static unsigned paused;

static void fake_pause(unsigned seconds)
{
    paused += seconds;
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
    f->staging = rs_xasprintf("%s/staging", dir);
    (void)mkdir(f->staging, 0700);
    rs_remote_set_transport(fake_curl, f);
    rs_remote_set_pause(fake_pause);
    paused = 0;
    rs_remote_configure(*token, NULL, NULL, 0);
    return dir;
}

static void teardown(char *dir, struct fake *f, char *token)
{
    rs_remote_set_transport(NULL, NULL);
    rs_remote_set_pause(NULL);
    rs_remote_configure(NULL, NULL, NULL, 0);
    free((char *)f->repo);
    free(f->staging);
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

    /* Fetched whole by the read above that it was too long for, and kept:
     * a part of it is read from there, asking nothing. */
    n = (size_t)f.requests;
    fd = rs_remote_open_at(rm, "packs/P.tar.gz", 6);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 4);
        CHECK(memcmp(buf, "6789", 4) == 0);
        (void)close(fd);
    }
    CHECK_STR(f.last_range, "0-3");
    CHECK_INT(f.requests, (int)n);
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

/* What a session fetches once, it has again without asking: whole, a part
 * of it from where a whole copy is, a part asked for at the same place; and
 * no more of it than its budget, the oldest let go first. */
static void remote_keeping(void)
{
    struct fake       f;
    char             *token;
    char             *dir = setup(&f, &token);
    struct rs_remote *rm = rs_remote_new(URL);
    struct rs_buf     out;
    struct rs_buf     err;
    char              buf[16];
    int               asked;
    int               fd;

    TEST_CASE("remote: what is fetched is kept");
    rs_buf_init(&err);
    rs_test_write(f.repo, "snapshots/S/kit", "the kit...\n", 0600);

    /* A part, from where it begins: asked for once, then had again. */
    fd = rs_remote_open_at(rm, "snapshots/S/info", 2);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 8);
        CHECK(memcmp(buf, "summary\n", 8) == 0);
        (void)close(fd);
    }
    CHECK_STR(f.last_range, "2-");
    asked = f.requests;
    fd = rs_remote_open_at(rm, "snapshots/S/info", 2);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 8);
        (void)close(fd);
    }
    CHECK_INT(f.requests, asked);
    /* A part from elsewhere in it is asked for. */
    fd = rs_remote_open_at(rm, "snapshots/S/info", 4);
    if (fd >= 0)
    {
        (void)close(fd);
    }
    CHECK_INT(f.requests, asked + 1);
    CHECK_STR(f.last_range, "4-");

    /* Whole, read twice: fetched once; and every part of it from there. */
    CHECK(rs_remote_read(rm, "snapshots/S/kit", 4096, &out, &err));
    rs_buf_free(&out);
    asked = f.requests;
    CHECK(rs_remote_read(rm, "snapshots/S/kit", 4096, &out, &err));
    CHECK_STR(out.data, "the kit...\n");
    rs_buf_free(&out);
    fd = rs_remote_open_at(rm, "snapshots/S/kit", 4);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 7);
        CHECK(memcmp(buf, "kit...\n", 7) == 0);
        (void)close(fd);
    }
    fd = rs_remote_open_at(rm, "snapshots/S/kit", 0);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK_INT(read(fd, buf, sizeof(buf)), 11);
        (void)close(fd);
    }
    CHECK_INT(f.requests, asked);

    /* A peek stops short of the end, and is not kept. */
    CHECK_INT(rs_remote_peek(rm, "packs/Q.idx", buf, 3), 3);
    asked = f.requests;
    CHECK_INT(rs_remote_peek(rm, "packs/Q.idx", buf, 3), 3);
    CHECK_INT(f.requests, asked + 1);
    rs_remote_free(rm);

    /* A budget of 21 bytes holds two of these files (10, 10 and 11 bytes),
     * so the third lets the oldest go. */
    rs_remote_set_kept_bytes(21);
    rm = rs_remote_new(URL);
    CHECK(rs_remote_read(rm, "snapshots/S/info", 4096, &out, &err));
    rs_buf_free(&out);
    CHECK(rs_remote_read(rm, "packs/P.idx", 4096, &out, &err));
    rs_buf_free(&out);
    CHECK(rs_remote_read(rm, "snapshots/S/kit", 4096, &out, &err));
    rs_buf_free(&out);
    asked = f.requests;
    CHECK(rs_remote_read(rm, "snapshots/S/kit", 4096, &out, &err));
    rs_buf_free(&out);
    CHECK(rs_remote_read(rm, "packs/P.idx", 4096, &out, &err));
    rs_buf_free(&out);
    CHECK_INT(f.requests, asked);
    CHECK(rs_remote_read(rm, "snapshots/S/info", 4096, &out, &err));
    CHECK_STR(out.data, "a summary\n");
    rs_buf_free(&out);
    CHECK_INT(f.requests, asked + 1);
    /* One larger than the whole budget is not kept at all. */
    rs_remote_set_kept_bytes(4);
    CHECK(rs_remote_read(rm, "packs/Q.idx", 4096, &out, &err));
    rs_buf_free(&out);
    asked = f.requests;
    CHECK(rs_remote_read(rm, "packs/Q.idx", 4096, &out, &err));
    rs_buf_free(&out);
    CHECK_INT(f.requests, asked + 1);
    rs_remote_free(rm);

    /* And with none, each read is asked for. */
    rs_remote_set_kept_bytes(0);
    rm = rs_remote_new(URL);
    CHECK(rs_remote_read(rm, "snapshots/S/kit", 4096, &out, &err));
    rs_buf_free(&out);
    {
        int before = f.requests;

        CHECK(rs_remote_read(rm, "snapshots/S/kit", 4096, &out, &err));
        rs_buf_free(&out);
        CHECK_INT(f.requests, before + 1);
    }
    rs_remote_free(rm);
    rs_remote_set_kept_bytes((uint64_t)512 * 1024 * 1024);
    rs_buf_free(&err);
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
    f.runs = 0;
    paused = 0;
    rm = rs_remote_new(URL);
    CHECK(!rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
    CHECK(!busy);
    CHECK_CONTAINS(err.data, "the proxy did not answer");
    /* Asked again for a minute first, and then given up on. */
    CHECK_INT(f.runs, 7);
    CHECK_INT(paused, 60);
    rs_remote_free(rm);

    /* A proxy unreachable for a moment -- a lapsed ARP entry on a busy
     * link -- is asked again, and the session opens. */
    rs_buf_reset(&err);
    fake_set(&f, false, false);
    f.unreached = 2;
    f.runs = 0;
    paused = 0;
    rm = rs_remote_new(URL);
    CHECK(rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, &err));
    CHECK_INT(f.runs, 3);
    CHECK_INT(paused, 3);
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

/* Whether `name` is a file under `dir`. */
static bool there(const char *dir, const char *name)
{
    char       *path = rs_xasprintf("%s/%s", dir, name);
    struct stat st;
    bool        yes = lstat(path, &st) == 0;

    free(path);
    return yes;
}

/* `text` into the new file `name` in the store, through rs_store_create. */
static bool made(const struct rs_store *st, const char *name, const char *text)
{
    int  fd = rs_store_create(st, name);
    bool ok = fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text);

    if (fd >= 0)
    {
        ok = close(fd) == 0 && ok;
    }
    return ok;
}

static void remote_writing(void)
{
    struct fake          f;
    char                *token;
    char                *dir = setup(&f, &token);
    struct rs_store     *st = rs_store_at(URL);
    struct rs_store_stat ss;
    struct rs_buf        err;
    const char          *said;
    char                *path;
    char                *tmp;
    bool                 busy;
    int                  before;

    TEST_CASE("remote: writing");
    rs_buf_init(&err);
    /* Outside an append session, nothing is written. */
    CHECK(rs_store_create(st, "packs/.P2.tar.gz.tmp") < 0);
    CHECK_INT(errno, EROFS);
    CHECK(!rs_store_write_new(st, "packs/.x.tmp", "x", 1, &err));
    CHECK_CONTAINS(err.data, "only by a capture or a copy");
    rs_buf_reset(&err);
    CHECK(rs_store_make_temp_dir(st, "snapshots/.S.") == NULL);
    CHECK(rs_store_rename(st, "packs/.a", "packs/a", false) < 0);
    CHECK(rs_store_place_new(st, "packs/.a", "chunk-key") < 0);
    CHECK(rs_store_remove(st, "packs/P.idx", false) < 0);
    CHECK(rs_store_remove_dir(st, "snapshots/S", false) < 0);
    CHECK(rs_store_said(st) == NULL);

    CHECK(rs_store_begin(st, RS_STORE_APPEND, &busy, &err));
    CHECK_STR(f.kind, "append");
    /* The packs' listing, so that a commit is seen in it with nothing asked. */
    CHECK_INT(rs_store_stat(st, "packs/P.idx", &ss), 0);

    /* A pack: made here, and nothing sent until its .idx is in place. */
    CHECK(made(st, "packs/.P2.tar.gz.tmp", "the content"));
    CHECK_INT(rs_store_rename(st, "packs/.P2.tar.gz.tmp", "packs/P2.tar.gz", false), 0);
    CHECK(rs_store_replace(st, "packs/P2.sum", "a sum\n", 6, &err));
    CHECK(rs_store_write_new(st, "packs/.P2.idx.tmp", "an index\n", 9, &err));
    CHECK_STR(err.data ? err.data : "", "");
    path = rs_store_path(st, "packs/.P2.idx.tmp");
    CHECK(!rs_starts_with(path, URL));
    free(path);
    path = rs_store_path(st, "packs/P.idx");
    CHECK_STR(path, URL "/packs/P.idx");
    free(path);
    CHECK_INT(rs_store_stat(st, "packs/P2.tar.gz", &ss), 0);
    CHECK_INT(ss.size, 11);
    {
        char buf[8];

        CHECK_INT(rs_store_peek(st, "packs/P2.tar.gz", buf, 3), 3);
    }
    CHECK_INT(f.uploads, 0);
    before = f.requests;
    CHECK_INT(rs_store_rename(st, "packs/.P2.idx.tmp", "packs/P2.idx", false), 0);
    CHECK_INT(f.requests - before, 4);
    CHECK_INT(f.uploads, 3);
    CHECK_INT(f.commits, 1);
    CHECK(there(f.repo, "packs/P2.idx") && there(f.repo, "packs/P2.tar.gz") &&
          there(f.repo, "packs/P2.sum"));
    before = f.requests;
    CHECK_INT(rs_store_stat(st, "packs/P2.idx", &ss), 0);
    CHECK_INT(ss.size, 9);
    CHECK_INT(f.requests, before);
    path = rs_store_path(st, "packs/P2.idx");
    CHECK_STR(path, URL "/packs/P2.idx");
    free(path);

    /* One the proxy will not have: what it said is what the rename says. */
    fake_pack_status(&f, 422);
    CHECK(made(st, "packs/.Q2.tar.gz.tmp", "more"));
    CHECK_INT(rs_store_rename(st, "packs/.Q2.tar.gz.tmp", "packs/Q2.tar.gz", false), 0);
    CHECK(rs_store_replace(st, "packs/Q2.sum", "a sum\n", 6, &err));
    CHECK(made(st, "packs/.Q2.idx.tmp", "x"));
    CHECK(rs_store_rename(st, "packs/.Q2.idx.tmp", "packs/Q2.idx", false) < 0);
    said = rs_store_said(st) ? rs_store_said(st) : "";
    CHECK_CONTAINS(said, "the commit of packs/Q2 was refused");
    CHECK_CONTAINS(said, "422 invalid");
    CHECK(!there(f.repo, "packs/Q2.idx"));
    /* Taken out of the stage again, as a failed capture does. */
    CHECK_INT(rs_store_remove(st, "packs/Q2.idx", false), 0);
    CHECK_INT(rs_store_remove(st, "packs/Q2.tar.gz", false), 0);
    fake_pack_status(&f, 0);
    /* A pack with no .sum is not sent at all. */
    CHECK(made(st, "packs/.R2.idx.tmp", "x"));
    CHECK(rs_store_rename(st, "packs/.R2.idx.tmp", "packs/R2.idx", false) < 0);
    CHECK_CONTAINS(rs_store_said(st) ? rs_store_said(st) : "", "not made here");

    /* A snapshot: sent with its directory; one whose name is taken is
     * EEXIST, and that name is seen as taken from then on. */
    tmp = rs_store_make_temp_dir(st, "snapshots/.S.");
    CHECK(tmp != NULL);
    path = tmp ? rs_xasprintf("%s/info", tmp) : rs_xstrdup("x");
    CHECK(rs_store_write_new(st, path, "a summary\n", 10, &err));
    free(path);
    CHECK(rs_store_rename(st, tmp ? tmp : "x", "snapshots/S", false) < 0);
    CHECK_INT(errno, EEXIST);
    CHECK_CONTAINS(rs_store_said(st) ? rs_store_said(st) : "", "another snapshot has that name");
    free(tmp);
    tmp = rs_store_make_temp_dir(st, "snapshots/.T.");
    path = tmp ? rs_xasprintf("%s/info", tmp) : rs_xstrdup("x");
    CHECK(rs_store_write_new(st, path, "a summary\n", 10, &err));
    free(path);
    CHECK_INT(rs_store_rename(st, tmp ? tmp : "x", "snapshots/T", false), 0);
    CHECK(there(f.repo, "snapshots/T/info"));
    CHECK_INT(rs_store_stat(st, "snapshots/T", &ss), 0);
    CHECK(ss.kind == RS_STORE_DIR);
    free(tmp);

    /* A chunk key: put there only if there is none. */
    CHECK(rs_store_write_new(st, "packs/.ck.tmp", "a key\n", 6, &err));
    CHECK_INT(rs_store_place_new(st, "packs/.ck.tmp", "chunk-key"), 1);
    CHECK_INT(rs_store_place_new(st, "packs/.ck.tmp", "chunk-key"), 0);
    CHECK(rs_store_place_new(st, "packs/.ck.tmp", "packs/other") < 0);
    CHECK(rs_store_place_new(st, "packs/.none", "chunk-key.x") < 0);
    CHECK_INT(rs_store_remove(st, "packs/.ck.tmp", false), 0);
    CHECK(made(st, "packs/.ck2.tmp", "another key\n"));
    CHECK_INT(rs_store_rename(st, "packs/.ck2.tmp", "chunk-key.20261109T000000Z-000", false), 0);
    CHECK(there(f.repo, "chunk-key.20261109T000000Z-000"));

    /* Nothing else goes there, nor is anything there removed or made. */
    CHECK(made(st, "packs/.m.tmp", "x"));
    CHECK(rs_store_rename(st, "packs/.m.tmp", "restate-repository", false) < 0);
    CHECK_INT(errno, EROFS);
    CHECK(rs_store_remove(st, "packs/P.idx", false) < 0);
    CHECK(there(f.repo, "packs/P.idx"));
    CHECK(rs_store_make_dir(st, "packs/x", 0700, false) < 0);
    CHECK(!rs_store_write_new_thawed(st, "snapshots/S/index.sig", "x", 1, &err));

    rs_buf_free(&err);
    rs_store_free(st);
    CHECK_INT(f.ends, 1);
    teardown(dir, &f, token);
}

/* A whole capture through the fake: its packs, then its snapshot, under the
 * next name where the first is taken as it is committed. */
static void remote_capturing(void)
{
    static const char *const kit[] = { "/etc/" };
    struct fake              f;
    char                    *token;
    char                    *dir = setup(&f, &token);
    const char              *real = rs_xasprintf("%s/real", dir);
    char                    *tree = rs_xasprintf("%s/tree", dir);
    char                    *cache = rs_xasprintf("%s/cache", dir);
    struct rs_rules          rules;
    struct rs_scan_opts      so;
    struct rs_scan_stats     stats;
    struct rs_index          ix;
    struct rs_repo          *r;
    struct rs_repo_writer   *w;
    struct rs_repo_written   done;
    struct rs_buf            err;
    bool                     busy;

    TEST_CASE("remote: capturing");
    rs_buf_init(&err);
    CHECK(rs_repo_init(real, false, &err));
    free((char *)f.repo);
    f.repo = real;
    (void)mkdir(tree, 0700);
    rs_test_write(tree, "one.conf", "one\n", 0644);
    rs_repo_set_cache_dir(cache);
    r = rs_repo_open(URL, RS_REPO_WRITE, &busy, &err);
    CHECK(r != NULL);
    CHECK_STR(f.kind, "append");
    memset(&done, 0, sizeof(done));
    w = r ? rs_repo_writer_begin(r, &err) : NULL;
    CHECK(w != NULL);
    if (w)
    {
        bool ok;

        rs_rules_init(&rules);
        memset(&so, 0, sizeof(so));
        memset(&stats, 0, sizeof(stats));
        so.root = tree;
        so.rules = &rules;
        so.hash = true;
        rs_index_init(&ix);
        rs_repo_writer_kit(w, kit, 1);
        so.store = rs_repo_store;
        so.store_ctx = w;
        so.have = rs_repo_have;
        /* The first request of the next run cannot connect, and curl goes
         * on to the rest (a pack's commit then finds its upload missing)
         * and exits 0: the run is asked again whole. */
        f.drop_first = 1;
        paused = 0;
        ok = rs_scan(&so, &ix, &stats, &err);
        CHECK(ok);
        ix.created = rs_xstrdup("2026-11-09T01:02:03.000000000Z");
        ix.root = rs_xstrdup(tree);
        ix.host = rs_xstrdup("test");
        ix.version = rs_xstrdup("x");
        ix.content = rs_xstrdup("state");
        ix.hashed = true;
        f.take_once = true;
        if (ok)
        {
            ok = rs_repo_writer_finish(w, &ix, NULL, &done, &err);
        } else
        {
            rs_repo_writer_abort(w);
        }
        CHECK(ok);
        CHECK_STR(err.data ? err.data : "", "");
        CHECK_STR(done.name ? done.name : "", "20261109T010203Z-2");
        CHECK(there(real, "snapshots/20261109T010203Z-2/index.json.gz"));
        CHECK(there(real, "snapshots/20261109T010203Z-2/packs"));
        CHECK(f.commits >= 3);
        CHECK_INT(f.dropped, 1);
        CHECK_INT(paused, 1);
        free(done.name);
        rs_index_free(&ix);
        rs_rules_free(&rules);
    }
    rs_repo_close(r);
    CHECK_INT(f.ends, 1);
    rs_repo_set_cache_dir(NULL);
    rs_buf_free(&err);
    free(tree);
    free(cache);
    teardown(dir, &f, token);
}

void test_remote(void)
{
    remote_names();
    remote_answers();
    remote_tokens();
    remote_reading();
    remote_keeping();
    remote_sessions();
    remote_writing();
    remote_capturing();
}
