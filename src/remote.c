/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "remote.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "run.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* The most one curl is asked for at once, so a config file stays small. */
#define BATCH_MAX     512u
/* The most of a token file read: a token is 47 bytes and a newline. */
#define TOKEN_FILE_MAX 4096
/* The most of an error's body shown. */
#define SAID_MAX      200
/* The most of a directory's listing read: a line is under 100 bytes, and a
 * repository has few more than a hundred thousand packs. */
#define LIST_MAX      ((size_t)64 * 1024 * 1024)
/* How long curl waits for a connection to the proxy, in seconds. */
#define CONNECT_TIMEOUT "30"

/* One directory's entries, as the proxy listed them: or, with `gone`, a
 * directory that is not there. */
struct listing {
    char                   *dir;
    struct rs_remote_entry *entries;
    size_t                  n;
    bool                    gone;
};

/* A file fetched already, by rs_remote_prefetch: its name, and where it is. */
struct fetched {
    char *name;
    char *path;
};

struct rs_remote {
    char                *url;       /* https://HOST[:PORT]/v1/CLIENT, no '/' after */
    char                *tmp;       /* this process's directory for curl, or NULL */
    char                 token[48]; /* read from the token file once it is needed */
    char                 session[33];
    enum rs_remote_kind  kind;
    pid_t                renewer;   /* the child renewing the lease, or 0 */
    int                  renew_fd;  /* the pipe whose closing tells it to end, or -1 */
    unsigned             lease;
    unsigned             seq;
    struct listing      *lists;
    size_t               nlists;
    struct fetched      *got;
    size_t               ngot;
};

/* One request in a batch, and what came of it. */
struct req {
    const char             *method;   /* NULL for GET, else "POST" */
    char                   *target;   /* after the client's URL: "/f/packs/NAME.idx" */
    const char             *data;     /* a POST's body */
    bool                    session;  /* sent in the session */
    bool                    ranged;
    uint64_t                first;
    uint64_t                last;     /* UINT64_MAX for to the end */
    char                   *hdr;      /* where curl writes the headers */
    char                   *out;      /* and the body */
    bool                    answered; /* a status line came back */
    struct rs_remote_answer ans;
};

static const char         *token_file;
static const char         *ca_file;
static const char *const  *pins;
static size_t              npins;
static rs_remote_transport transport;
static void               *transport_ctx;
static char                last_reason[64];
static bool                was_busy;
static struct rs_buf       curl_said;

/* ------------------------------------------------------------------------- */
/* Names                                                                     */
/* ------------------------------------------------------------------------- */

bool rs_remote_is(const char *where)
{
    return where && rs_starts_with(where, "https://");
}

static bool client_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

static bool host_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '-';
}

static bool v6_char(char c)
{
    return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') ||
           c == ':' || c == '.';
}

bool rs_remote_url_ok(const char *url, struct rs_buf *err)
{
    const char *p;
    const char *start;
    unsigned    port = 0;
    size_t      len;

    if (!rs_remote_is(url))
    {
        rs_buf_addf(err, "%s: a repository behind restate-proxy is https://HOST[:PORT]/v1/CLIENT",
                    url);
        return false;
    }
    p = url + strlen("https://");
    start = p;
    if (*p == '[')
    {
        for (p++; v6_char(*p); p++)
        {
        }
        if (*p != ']' || p == start + 1)
        {
            goto bad;
        }
        p++;
    } else
    {
        for (; host_char(*p); p++)
        {
        }
        if (p == start)
        {
            goto bad;
        }
    }
    if (*p == ':')
    {
        const char *digits = ++p;

        for (; *p >= '0' && *p <= '9' && port <= 65535; p++)
        {
            port = port * 10 + (unsigned)(*p - '0');
        }
        if (p == digits || port == 0 || port > 65535)
        {
            goto bad;
        }
    }
    if (strncmp(p, "/v1/", 4) != 0)
    {
        goto bad;
    }
    p += 4;
    start = p;
    for (; client_char(*p); p++)
    {
    }
    len = (size_t)(p - start);
    if (len == 0 || len > 64 || *start == '.' || *start == '-')
    {
        goto bad;
    }
    if (*p == '/')
    {
        p++;
    }
    if (*p == '\0')
    {
        return true;
    }
bad:
    rs_buf_addf(err, "%s: not a repository behind restate-proxy, which is "
                "https://HOST[:PORT]/v1/CLIENT and nothing more", url);
    return false;
}

const char *rs_remote_sep_from(const char *ref)
{
    const char *close;

    if (!rs_remote_is(ref) || ref[strlen("https://")] != '[')
    {
        return ref;
    }
    close = strchr(ref, ']');
    return close ? close : ref + strlen(ref);
}

bool rs_remote_pin_ok(const char *pin)
{
    size_t i;

    if (!pin || strlen(pin) != 44 || pin[43] != '=')
    {
        return false;
    }
    for (i = 0; i < 43; i++)
    {
        char c = pin[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '+' || c == '/'))
        {
            return false;
        }
    }
    return true;
}

void rs_remote_configure(const char *token, const char *ca, const char *const *keys, size_t nkeys)
{
    token_file = token;
    ca_file = ca;
    pins = keys;
    npins = nkeys;
    /* What a run learns is its own. */
    was_busy = false;
    last_reason[0] = '\0';
}

void rs_remote_set_transport(rs_remote_transport fn, void *ctx)
{
    transport = fn;
    transport_ctx = ctx;
}

bool rs_remote_busy(void)
{
    return was_busy;
}

const char *rs_remote_reason(void)
{
    return last_reason[0] ? last_reason : NULL;
}

/* ------------------------------------------------------------------------- */
/* What comes back                                                           */
/* ------------------------------------------------------------------------- */

/* Whether the header line `line`, `len` long, is `name`; its value, trimmed,
 * into *value and *vlen if it is. */
static bool header_is(const char *line, size_t len, const char *name, const char **value,
                      size_t *vlen)
{
    size_t n = strlen(name);

    if (len <= n || line[n] != ':' || strncasecmp(line, name, n) != 0)
    {
        return false;
    }
    *value = line + n + 1;
    *vlen = len - n - 1;
    while (*vlen > 0 && (**value == ' ' || **value == '\t'))
    {
        (*value)++;
        (*vlen)--;
    }
    while (*vlen > 0 && ((*value)[*vlen - 1] == ' ' || (*value)[*vlen - 1] == '\t'))
    {
        (*vlen)--;
    }
    return true;
}

static bool token_like(const char *v, size_t len, size_t max, bool hex)
{
    size_t i;

    if (len == 0 || len > max)
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        char c = v[i];

        if (hex ? !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
                : !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
        {
            return false;
        }
    }
    return true;
}

bool rs_remote_parse_headers(const char *text, size_t len, struct rs_remote_answer *out)
{
    const char *p = text;
    const char *end = text + len;
    bool        seen = false;

    memset(out, 0, sizeof(*out));
    while (p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        const char *v;
        size_t      vlen;
        size_t      n;

        if (eol > p && eol[-1] == '\r')
        {
            eol--;
        }
        n = (size_t)(eol - p);
        if (n > 9 && strncmp(p, "HTTP/", 5) == 0)
        {
            const char *sp = memchr(p, ' ', n);

            memset(out, 0, sizeof(*out));
            if (sp && (size_t)(sp - p) + 4 <= n && sp[1] >= '1' && sp[1] <= '5' &&
                sp[2] >= '0' && sp[2] <= '9' && sp[3] >= '0' && sp[3] <= '9')
            {
                out->status = (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
                seen = true;
            }
        } else if (header_is(p, n, "Restate-Reason", &v, &vlen))
        {
            if (token_like(v, vlen, sizeof(out->reason) - 1, false))
            {
                memcpy(out->reason, v, vlen);
                out->reason[vlen] = '\0';
            }
        } else if (header_is(p, n, "Restate-Session", &v, &vlen))
        {
            if (vlen == 32 && token_like(v, vlen, 32, true))
            {
                memcpy(out->session, v, vlen);
                out->session[vlen] = '\0';
            }
        } else if (header_is(p, n, "Restate-Lease", &v, &vlen))
        {
            unsigned lease = 0;
            size_t   i;

            for (i = 0; i < vlen && i < 7 && v[i] >= '0' && v[i] <= '9'; i++)
            {
                lease = lease * 10 + (unsigned)(v[i] - '0');
            }
            out->lease = i == vlen ? lease : 0;
        }
        p = nl ? nl + 1 : end;
    }
    return seen && out->status > 0;
}

static bool digits(const char **p, uint64_t *out)
{
    const char *s = *p;
    uint64_t    v = 0;

    if (*s < '0' || *s > '9')
    {
        return false;
    }
    for (; *s >= '0' && *s <= '9'; s++)
    {
        if (v > (UINT64_MAX - 9) / 10)
        {
            return false;
        }
        v = v * 10 + (uint64_t)(*s - '0');
    }
    *p = s;
    *out = v;
    return true;
}

void rs_remote_entries_free(struct rs_remote_entry *e, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(e[i].name);
    }
    free(e);
}

bool rs_remote_parse_list(const char *text, size_t len, struct rs_remote_entry **out, size_t *n)
{
    static const char       head[] = "restate-list 1\n";
    char                   *copy;
    char                   *line;
    char                   *next;
    struct rs_remote_entry *e = NULL;
    size_t                  count = 0;
    bool                    ok = true;

    *out = NULL;
    *n = 0;
    if (len < sizeof(head) - 1 || memcmp(text, head, sizeof(head) - 1) != 0 ||
        memchr(text, '\0', len))
    {
        return false;
    }
    copy = rs_xstrndup(text + sizeof(head) - 1, len - (sizeof(head) - 1));
    for (line = copy; ok && *line; line = next)
    {
        const char *p = line;
        uint64_t    size;
        uint64_t    mtime;
        char       *nl = strchr(line, '\n');

        next = nl ? nl + 1 : line + strlen(line);
        if (nl)
        {
            *nl = '\0';
        }
        ok = (p[0] == 'f' || p[0] == 'd' || p[0] == 'o') && p[1] == ' ';
        if (ok)
        {
            p += 2;
            ok = digits(&p, &size) && *p == ' ';
        }
        if (ok)
        {
            p++;
            ok = digits(&p, &mtime) && *p == ' ' && mtime <= INT64_MAX;
        }
        if (ok)
        {
            p++;
            ok = *p != '\0' && !strchr(p, '/');
        }
        if (ok)
        {
            e = rs_xreallocarray(e, count + 1, sizeof(*e));
            e[count].name = rs_xstrdup(p);
            e[count].st.kind = line[0] == 'f' ? RS_STORE_FILE : line[0] == 'd' ? RS_STORE_DIR
                                                                                : RS_STORE_OTHER;
            e[count].st.size = size;
            e[count].st.mtime = (int64_t)mtime;
            count++;
        }
    }
    free(copy);
    if (!ok)
    {
        rs_remote_entries_free(e, count);
        return false;
    }
    *out = e;
    *n = count;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Running curl                                                              */
/* ------------------------------------------------------------------------- */

struct rs_remote *rs_remote_new(const char *url)
{
    struct rs_remote *rm = rs_xcalloc(1, sizeof(*rm));
    size_t            len = strlen(url);

    while (len > 0 && url[len - 1] == '/')
    {
        len--;
    }
    rm->url = rs_xstrndup(url, len);
    rm->renew_fd = -1;
    return rm;
}

/* The token, from the token file: a regular file, the user's or root's, that
 * no one else can read or write. */
static bool read_token(struct rs_remote *rm, struct rs_buf *err)
{
    char        buf[TOKEN_FILE_MAX];
    struct stat st;
    ssize_t     got;
    size_t      len;
    size_t      i;
    int         fd;

    if (!token_file)
    {
        rs_buf_addf(err, "%s: a repository behind restate-proxy needs its token: "
                    "--repository-token-file FILE (repository_token_file, in a job)", rm->url);
        return false;
    }
    fd = open(token_file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", token_file, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 077) != 0 ||
        (st.st_uid != geteuid() && st.st_uid != 0))
    {
        (void)close(fd);
        rs_buf_addf(err, "%s: a token file has to be a regular file, root's (or yours), that "
                    "no one else can read or write", token_file);
        return false;
    }
    got = read(fd, buf, sizeof(buf) - 1);
    (void)close(fd);
    len = got > 0 ? (size_t)got : 0;
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' '))
    {
        len--;
    }
    buf[len] = '\0';
    if (len != 47 || strncmp(buf, "rsp_", 4) != 0)
    {
        len = 0;
    }
    for (i = 4; len && i < 47; i++)
    {
        char c = buf[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_'))
        {
            len = 0;
        }
    }
    if (!len)
    {
        rs_buf_addf(err, "%s: not a restate-proxy token (rsp_ and 43 characters more)",
                    token_file);
        return false;
    }
    memcpy(rm->token, buf, 48);
    return true;
}

/* The token, and the directory curl's files go in, once. */
static bool ready(struct rs_remote *rm, struct rs_buf *err)
{
    const char *dir = getenv("TMPDIR"); /* Flawfinder: ignore -- only where a file is made */
    char       *tmp;

    if (rm->tmp)
    {
        return true;
    }
    if (!rs_remote_url_ok(rm->url, err) || !read_token(rm, err))
    {
        return false;
    }
    tmp = rs_xasprintf("%s/restate-remote.XXXXXX", dir && dir[0] == '/' ? dir : "/tmp");
    if (!mkdtemp(tmp))
    {
        rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
        free(tmp);
        return false;
    }
    rm->tmp = tmp;
    return true;
}

/* `key = "value"` into a curl config, the value quoted as curl reads it. */
static void conf(struct rs_buf *b, const char *key, const char *value)
{
    const char *p;

    rs_buf_addf(b, "%s = \"", key);
    for (p = value; *p; p++)
    {
        if (*p == '"' || *p == '\\')
        {
            rs_buf_addc(b, '\\');
        }
        rs_buf_addc(b, *p);
    }
    rs_buf_addstr(b, "\"\n");
}

/* `len` bytes as the new file `path`, 0600. */
static bool write_private(const char *path, const char *data, size_t len)
{
    int  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok = fd >= 0;

    while (ok && len > 0)
    {
        ssize_t n = write(fd, data, len);

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        ok = n > 0;
        data += ok ? (size_t)n : 0;
        len -= ok ? (size_t)n : 0;
    }
    if (fd >= 0 && close(fd) != 0)
    {
        ok = false;
    }
    return ok;
}

/* The whole of the file `path`, up to `max` bytes (false past it); always
 * initialized and NUL-terminated. */
static bool slurp(const char *path, size_t max, struct rs_buf *out)
{
    int  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char chunk[65536];
    bool ok = fd >= 0;

    rs_buf_init(out);
    rs_buf_add(out, "", 0);
    while (ok)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            ok = n == 0;
            break;
        }
        if (out->len + (size_t)n > max)
        {
            errno = EFBIG;
            ok = false;
            break;
        }
        rs_buf_add(out, chunk, (size_t)n);
    }
    if (fd >= 0)
    {
        int saved = errno;

        (void)close(fd);
        errno = saved;
    }
    return ok;
}

static int run_curl(const char *path, void *ctx)
{
    char         *argv[] = { rs_xstrdup("curl"), rs_xstrdup("-q"), rs_xstrdup("-K"),
                             rs_xstrdup(path), NULL };
    struct rs_buf err;
    int           code = 0;
    bool          ok;
    size_t        i;

    (void)ctx;
    rs_buf_init(&err);
    rs_buf_reset(&curl_said);
    ok = rs_run(RS_PROG_CURL, argv, NULL, &curl_said, &code, &err);
    if (!ok)
    {
        rs_buf_reset(&curl_said);
        rs_buf_addstr(&curl_said, err.data ? err.data : "curl could not be run");
        code = -1;
    }
    /* Its first line: what follows is advice for curl's own users. */
    if (curl_said.data && memchr(curl_said.data, '\n', curl_said.len))
    {
        curl_said.len = (size_t)((char *)memchr(curl_said.data, '\n', curl_said.len) -
                                 curl_said.data);
        curl_said.data[curl_said.len] = '\0';
    }
    while (curl_said.data && curl_said.len > 0 && curl_said.data[curl_said.len - 1] == '\r')
    {
        curl_said.data[--curl_said.len] = '\0';
    }
    rs_buf_free(&err);
    for (i = 0; argv[i]; i++)
    {
        free(argv[i]);
    }
    return code;
}

/* A request for `target`, with its files' names, in rm's directory. */
static void req_init(struct rs_remote *rm, struct req *q, const char *target)
{
    memset(q, 0, sizeof(*q));
    q->target = rs_xstrdup(target);
    q->session = true;
    q->last = UINT64_MAX;
    rm->seq++;
    q->hdr = rs_xasprintf("%s/%ld-%u.h", rm->tmp, (long)getpid(), rm->seq);
    q->out = rs_xasprintf("%s/%ld-%u.o", rm->tmp, (long)getpid(), rm->seq);
}

/* Done with: its files removed, unless *keep_out, which keeps the body. */
static void req_free(struct req *q, bool keep_out)
{
    (void)unlink(q->hdr);
    if (!keep_out)
    {
        (void)unlink(q->out);
    }
    free(q->hdr);
    free(q->out);
    free(q->target);
}

/* The requests asked of curl in one run, over one connection; each one's
 * answer read back. False only if curl could not be run at all. */
static bool run_batch(struct rs_remote *rm, struct req *q, size_t n, struct rs_buf *err)
{
    struct rs_buf b;
    char         *path;
    size_t        i;
    int           code;

    rs_buf_init(&b);
    for (i = 0; i < n; i++)
    {
        char *url = rs_xasprintf("%s%s", rm->url, q[i].target);
        char *h;

        if (i > 0)
        {
            rs_buf_addstr(&b, "next\n");
        }
        conf(&b, "url", url);
        free(url);
        h = rs_xasprintf("Authorization: Bearer %s", rm->token);
        conf(&b, "header", h);
        free(h);
        if (q[i].session && rm->session[0])
        {
            h = rs_xasprintf("Restate-Session: %s", rm->session);
            conf(&b, "header", h);
            free(h);
        }
        conf(&b, "dump-header", q[i].hdr);
        conf(&b, "output", q[i].out);
        rs_buf_addstr(&b, "proto = \"=https\"\nproto-redir = \"=https\"\ntlsv1.2\nhttp1.1\n"
                          "silent\nshow-error\nconnect-timeout = " CONNECT_TIMEOUT "\n");
        if (ca_file)
        {
            conf(&b, "cacert", ca_file);
        }
        if (npins > 0)
        {
            struct rs_buf pin;
            size_t        k;

            rs_buf_init(&pin);
            for (k = 0; k < npins; k++)
            {
                rs_buf_addf(&pin, "%ssha256//%s", k ? ";" : "", pins[k]);
            }
            conf(&b, "pinnedpubkey", pin.data);
            rs_buf_free(&pin);
        }
        if (q[i].ranged)
        {
            char *range = q[i].last == UINT64_MAX
                              ? rs_xasprintf("%llu-", (unsigned long long)q[i].first)
                              : rs_xasprintf("%llu-%llu", (unsigned long long)q[i].first,
                                             (unsigned long long)q[i].last);

            conf(&b, "range", range);
            free(range);
        }
        if (q[i].method)
        {
            conf(&b, "request", q[i].method);
            conf(&b, "data-binary", q[i].data ? q[i].data : "");
        }
    }
    rm->seq++;
    path = rs_xasprintf("%s/%ld-%u.conf", rm->tmp, (long)getpid(), rm->seq);
    if (!write_private(path, b.data ? b.data : "", b.len))
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        (void)unlink(path);
        free(path);
        rs_buf_free(&b);
        return false;
    }
    /* The token was in it. */
    if (b.data)
    {
        memset(b.data, 0, b.len);
    }
    rs_buf_free(&b);
    code = transport ? transport(path, transport_ctx) : run_curl(path, NULL);
    (void)unlink(path);
    free(path);
    if (code < 0)
    {
        rs_buf_addf(err, "%s: %s", rm->url, curl_said.len ? curl_said.data : "curl failed");
        return false;
    }
    for (i = 0; i < n; i++)
    {
        struct rs_buf text;

        q[i].answered = slurp(q[i].hdr, 65536, &text) &&
                        rs_remote_parse_headers(text.data, text.len, &q[i].ans);
        rs_buf_free(&text);
        /* Not what a run asks of a file that may not be there, or past a
         * file's end, which are no refusal: what is left is what a failed
         * run's result gives as its proxy_reason. */
        if (q[i].answered && q[i].ans.status >= 300 && q[i].ans.status != 404 &&
            q[i].ans.status != 416 && q[i].ans.reason[0])
        {
            memcpy(last_reason, q[i].ans.reason, sizeof(last_reason));
        }
    }
    return true;
}

/* Why `q` failed, for a message about `what`: the proxy's own words, or
 * curl's; errno set to match. */
static void say_failed(const struct rs_remote *rm, const struct req *q, const char *what,
                       struct rs_buf *err)
{
    struct rs_buf body;

    if (!q->answered)
    {
        rs_buf_addf(err, "%s: the proxy did not answer (%s)", what,
                    curl_said.len ? curl_said.data : "curl failed");
        errno = EIO;
        return;
    }
    (void)rm;
    errno = q->ans.status == 404 ? ENOENT : q->ans.status == 401 || q->ans.status == 403
                                               ? EACCES : EIO;
    if (q->ans.status == 404 && (!q->ans.reason[0] || strcmp(q->ans.reason, "not-found") == 0))
    {
        rs_buf_addf(err, "%s: %s", what, strerror(ENOENT));
        return;
    }
    (void)slurp(q->out, 4096, &body);
    while (body.len > 0 && (body.data[body.len - 1] == '\n' || body.data[body.len - 1] == '\r'))
    {
        body.data[--body.len] = '\0';
    }
    if (body.len > SAID_MAX || memchr(body.data, '\n', body.len))
    {
        body.len = 0;
    }
    rs_buf_addf(err, "%s: %s (%d%s%s)", what,
                body.len ? body.data : "the proxy refused it", q->ans.status,
                q->ans.reason[0] ? " " : "", q->ans.reason);
    rs_buf_free(&body);
}

/* ------------------------------------------------------------------------- */
/* The session                                                               */
/* ------------------------------------------------------------------------- */

static const char *kind_name(enum rs_remote_kind kind)
{
    return kind == RS_REMOTE_APPEND ? "append" : kind == RS_REMOTE_READ ? "read" : "look";
}

/* A request in the session, alone: true if it was answered `want`. */
static bool ask_session(struct rs_remote *rm, const char *what)
{
    struct req    q[1];
    struct rs_buf err;
    char         *target = rs_xasprintf("/sessions/%s/%s", rm->session, what);
    bool          ok;

    rs_buf_init(&err);
    req_init(rm, q, target);
    q->method = "POST";
    q->session = false;
    ok = run_batch(rm, q, 1, &err) && q->answered && q->ans.status == 204;
    if (ok && q->ans.lease > 0)
    {
        rm->lease = q->ans.lease;
    }
    req_free(q, false);
    rs_buf_free(&err);
    free(target);
    return ok;
}

bool rs_remote_renew(struct rs_remote *rm)
{
    return rm->session[0] && ask_session(rm, "renew");
}

void rs_remote_end(struct rs_remote *rm)
{
    if (rm->session[0])
    {
        (void)ask_session(rm, "end");
        memset(rm->session, 0, sizeof(rm->session));
    }
}

/* Its directory and what is in it removed: the files curl wrote. */
static void remove_tmp(struct rs_remote *rm)
{
    DIR                 *d;
    const struct dirent *de;

    if (!rm->tmp)
    {
        return;
    }
    d = opendir(rm->tmp);
    while (d && (de = readdir(d)) != NULL)
    {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
        {
            char *path = rs_xasprintf("%s/%s", rm->tmp, de->d_name);

            (void)unlink(path);
            free(path);
        }
    }
    if (d)
    {
        (void)closedir(d);
    }
    (void)rmdir(rm->tmp);
}

/*
 * The child that keeps the session: it renews the lease while this process
 * holds the pipe's other end open, and when it is closed -- by
 * rs_remote_free, or by this process ending, however it ends -- ends the
 * session and removes the directory. It outlives a Ctrl-C to the process
 * group, which it ignores, so as to end the session after it.
 */
static void renewer(struct rs_remote *rm, int fd)
{
    static const int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE };
    unsigned         every = rm->lease / 5 > 5 ? rm->lease / 5 : 5;
    long             max = sysconf(_SC_OPEN_MAX);
    int              k;
    size_t           i;

    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
    {
        (void)signal(sigs[i], SIG_IGN);
    }
    /* Nothing of its parent's but the pipe: held open here, another child's
     * pipe would never see its end. */
    for (k = 3; k < (max > 0 && max < 65536 ? (int)max : 65536); k++)
    {
        if (k != fd)
        {
            (void)close(k);
        }
    }
    for (;;)
    {
        struct pollfd p = { fd, POLLIN, 0 };
        int           r = poll(&p, 1, (int)every * 1000);
        char          c;

        if (r < 0 && errno == EINTR)
        {
            continue;
        }
        if (r == 0)
        {
            (void)rs_remote_renew(rm);
            continue;
        }
        if (r > 0 && read(fd, &c, 1) > 0)
        {
            continue;
        }
        break;
    }
    rs_remote_end(rm);
    remove_tmp(rm);
    _exit(0);
}

static void start_renewer(struct rs_remote *rm)
{
    int   p[2];
    pid_t pid;

    if (transport || pipe(p) != 0)
    {
        return;
    }
    pid = fork();
    if (pid == 0)
    {
        (void)close(p[1]);
        renewer(rm, p[0]);
    }
    (void)close(p[0]);
    if (pid < 0)
    {
        (void)close(p[1]);
        return;
    }
    (void)fcntl(p[1], F_SETFD, FD_CLOEXEC);
    rm->renewer = pid;
    rm->renew_fd = p[1];
}

/* The files rs_remote_prefetch fetched, forgotten -- and removed, if they are
 * still there. */
static void forget_fetched(struct rs_remote *rm)
{
    size_t i;

    for (i = 0; i < rm->ngot; i++)
    {
        (void)unlink(rm->got[i].path);
        free(rm->got[i].path);
        free(rm->got[i].name);
    }
    free(rm->got);
    rm->got = NULL;
    rm->ngot = 0;
}

/* The child gone, having ended the session and removed the directory, or
 * the session ended here; either way, the directory is made again when it is
 * next needed. */
static void stop_session(struct rs_remote *rm)
{
    forget_fetched(rm);
    if (rm->renewer > 0)
    {
        int status;

        (void)close(rm->renew_fd);
        while (waitpid(rm->renewer, &status, 0) < 0 && errno == EINTR)
        {
        }
        rm->renewer = 0;
        rm->renew_fd = -1;
        memset(rm->session, 0, sizeof(rm->session));
    } else
    {
        rs_remote_end(rm);
    }
    remove_tmp(rm);
    free(rm->tmp);
    rm->tmp = NULL;
}

bool rs_remote_begin(struct rs_remote *rm, enum rs_remote_kind kind, bool *busy,
                     struct rs_buf *err)
{
    struct req q[1];
    bool       ok;

    *busy = false;
    if (rm->session[0] && rm->kind == kind)
    {
        return true;
    }
    if (!ready(rm, err))
    {
        return false;
    }
    if (rm->session[0])
    {
        stop_session(rm);
        if (!ready(rm, err))
        {
            return false;
        }
    }
    req_init(rm, q, "/sessions");
    q->method = "POST";
    q->data = kind_name(kind);
    q->session = false;
    if (!run_batch(rm, q, 1, err))
    {
        req_free(q, false);
        return false;
    }
    ok = q->answered && q->ans.status == 201 && q->ans.session[0];
    if (ok)
    {
        memcpy(rm->session, q->ans.session, sizeof(rm->session));
        rm->kind = kind;
        rm->lease = q->ans.lease ? q->ans.lease : 300;
        start_renewer(rm);
    } else
    {
        char *what;

        *busy = q->answered && (q->ans.status == 423 || q->ans.status == 503);
        was_busy = was_busy || *busy;
        what = rs_xasprintf("%s: %s %s session", rm->url, kind == RS_REMOTE_APPEND ? "an" : "a",
                            kind_name(kind));
        say_failed(rm, q, what, err);
        free(what);
    }
    req_free(q, false);
    if (!ok)
    {
        /* Nothing open, so nothing to keep it for: gone now, not only when
         * the store is freed, which a caller ending at once may never do. */
        remove_tmp(rm);
        free(rm->tmp);
        rm->tmp = NULL;
    }
    return ok;
}

/* A `look` session, if none is open. */
static bool session(struct rs_remote *rm, struct rs_buf *err)
{
    bool busy;

    return rm->session[0] || rs_remote_begin(rm, RS_REMOTE_LOOK, &busy, err);
}

void rs_remote_free(struct rs_remote *rm)
{
    size_t i;

    if (!rm)
    {
        return;
    }
    stop_session(rm);
    for (i = 0; i < rm->nlists; i++)
    {
        rs_remote_entries_free(rm->lists[i].entries, rm->lists[i].n);
        free(rm->lists[i].dir);
    }
    free(rm->lists);
    memset(rm->token, 0, sizeof(rm->token));
    free(rm->url);
    free(rm);
}

int rs_remote_lock(struct rs_remote *rm, const char *name, bool shared, bool *busy,
                   struct rs_buf *err)
{
    *busy = false;
    if ((strcmp(name, "lock") == 0 && !shared && rm->kind == RS_REMOTE_APPEND) ||
        (strcmp(name, "readers") == 0 && shared && rm->kind == RS_REMOTE_READ))
    {
        return rm->session[0] ? 1 : -1;
    }
    rs_buf_addf(err, "%s: what would take %s%s here is run on the storage host, not through "
                "restate-proxy", rm->url, shared ? "a shared " : "", name);
    return -1;
}

/* ------------------------------------------------------------------------- */
/* Reading                                                                   */
/* ------------------------------------------------------------------------- */

/* The listing of `dir`, fetched once; NULL with errno if it could not be. */
static const struct listing *listing_of(struct rs_remote *rm, const char *dir)
{
    struct listing *l;
    struct req      q[1];
    struct rs_buf   err;
    struct rs_buf   text;
    char           *target;
    size_t          i;

    for (i = 0; i < rm->nlists; i++)
    {
        if (strcmp(rm->lists[i].dir, dir) == 0)
        {
            errno = ENOENT;
            return rm->lists[i].gone ? NULL : &rm->lists[i];
        }
    }
    rs_buf_init(&err);
    if (!session(rm, &err))
    {
        rs_buf_free(&err);
        errno = EIO;
        return NULL;
    }
    target = *dir ? rs_xasprintf("/list/%s/", dir) : rs_xstrdup("/list/");
    req_init(rm, q, target);
    free(target);
    if (!run_batch(rm, q, 1, &err) || !q->answered ||
        (q->ans.status != 200 && q->ans.status != 404))
    {
        int saved = EIO;

        if (q->answered || err.len == 0)
        {
            say_failed(rm, q, rm->url, &err);
            saved = errno;
        }
        rs_warn("%s", err.data);
        rs_buf_free(&err);
        req_free(q, false);
        errno = saved;
        return NULL;
    }
    rm->lists = rs_xreallocarray(rm->lists, rm->nlists + 1, sizeof(*rm->lists));
    l = &rm->lists[rm->nlists++];
    memset(l, 0, sizeof(*l));
    l->dir = rs_xstrdup(dir);
    l->gone = q->ans.status == 404;
    if (!l->gone)
    {
        bool read = slurp(q->out, LIST_MAX, &text);

        if (!read || !rs_remote_parse_list(text.data, text.len, &l->entries, &l->n))
        {
            rs_warn("%s/%s: not a listing restate-proxy wrote", rm->url, dir);
            l->gone = true;
        }
        rs_buf_free(&text);
    }
    req_free(q, false);
    rs_buf_free(&err);
    errno = l->gone ? ENOENT : 0;
    return l->gone ? NULL : l;
}

int rs_remote_stat(struct rs_remote *rm, const char *name, struct rs_store_stat *out)
{
    const char           *slash = strrchr(name, '/');
    char                 *dir;
    const struct listing *l;
    size_t                i;

    if (!*name)
    {
        out->kind = RS_STORE_DIR;
        out->size = 0;
        out->mtime = 0;
        return 0;
    }
    dir = slash ? rs_xstrndup(name, (size_t)(slash - name)) : rs_xstrdup("");
    l = listing_of(rm, dir);
    free(dir);
    if (!l)
    {
        return -1;
    }
    for (i = 0; i < l->n; i++)
    {
        if (strcmp(l->entries[i].name, slash ? slash + 1 : name) == 0)
        {
            *out = l->entries[i].st;
            return 0;
        }
    }
    errno = ENOENT;
    return -1;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

char **rs_remote_list(struct rs_remote *rm, const struct rs_store *st, const char *name,
                      rs_store_keep keep, void *ctx, size_t *n)
{
    const struct listing *l = listing_of(rm, name);
    char                **names = NULL;
    size_t                i;

    *n = 0;
    if (!l)
    {
        return NULL;
    }
    for (i = 0; i < l->n; i++)
    {
        char *out = NULL;

        if (keep(st, name, l->entries[i].name, ctx, &out))
        {
            names = rs_xreallocarray(names, *n + 1, sizeof(*names));
            names[(*n)++] = out;
        }
    }
    if (names && *n > 1)
    {
        qsort(names, *n, sizeof(*names), by_name);
    }
    errno = 0;
    return names;
}

/* Where a fetch of `name` already put it, taken from the list; NULL if none. */
static char *take_fetched(struct rs_remote *rm, const char *name)
{
    size_t i;

    for (i = 0; i < rm->ngot; i++)
    {
        if (strcmp(rm->got[i].name, name) == 0)
        {
            char *path = rm->got[i].path;

            free(rm->got[i].name);
            rm->got[i] = rm->got[--rm->ngot];
            return path;
        }
    }
    return NULL;
}

/*
 * `name` fetched -- from `first` on, to `last`, if `ranged` -- into a file of
 * its own: its path, the caller's to remove and free, and the answer's
 * status into *status (200, 206, or 416 for a range past the end). NULL, with
 * `err` and errno saying why, if it is not there or could not be fetched.
 */
static char *fetch(struct rs_remote *rm, const char *name, bool ranged, uint64_t first,
                   uint64_t last, int *status, struct rs_buf *err)
{
    struct req q[1];
    char      *target;
    char      *what;
    char      *path;

    *status = 0;
    path = ranged ? NULL : take_fetched(rm, name);
    if (path)
    {
        *status = 200;
        return path;
    }
    if (!session(rm, err))
    {
        errno = EIO;
        return NULL;
    }
    target = rs_xasprintf("/f/%s", name);
    req_init(rm, q, target);
    free(target);
    q->ranged = ranged;
    q->first = first;
    q->last = last;
    if (run_batch(rm, q, 1, err) && q->answered &&
        (q->ans.status == 200 || q->ans.status == 206 || (ranged && q->ans.status == 416)))
    {
        *status = q->ans.status;
        path = rs_xstrdup(q->out);
        req_free(q, true);
        return path;
    }
    what = rs_xasprintf("%s/%s", rm->url, name);
    if (q->answered || err->len == 0)
    {
        say_failed(rm, q, what, err);
    }
    free(what);
    req_free(q, false);
    return NULL;
}

/* An empty file, already removed, open for reading: what reading past a
 * file's end gives. */
static int empty_fd(struct rs_remote *rm)
{
    char *path = rs_xasprintf("%s/%ld-%u.empty", rm->tmp, (long)getpid(), ++rm->seq);
    int   fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);

    (void)unlink(path);
    free(path);
    return fd;
}

int rs_remote_open_at(struct rs_remote *rm, const char *name, uint64_t offset)
{
    struct rs_buf err;
    int           status;
    int           fd = -1;
    int           saved;
    char         *path;

    rs_buf_init(&err);
    path = fetch(rm, name, offset > 0, offset, UINT64_MAX, &status, &err);
    saved = errno;
    if (path)
    {
        fd = status == 416 ? empty_fd(rm) : open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        saved = errno;
        (void)unlink(path);
        free(path);
    } else if (saved != ENOENT)
    {
        rs_warn("%s", err.data);
    }
    rs_buf_free(&err);
    errno = saved;
    return fd;
}

ssize_t rs_remote_peek(struct rs_remote *rm, const char *name, void *buf, size_t max)
{
    struct rs_buf err;
    struct rs_buf text;
    int           status;
    ssize_t       got = -1;
    int           saved;
    char         *path;

    if (max == 0)
    {
        return 0;
    }
    rs_buf_init(&err);
    path = fetch(rm, name, true, 0, (uint64_t)max - 1, &status, &err);
    saved = errno;
    if (path && status == 416)
    {
        got = 0;
    } else if (path)
    {
        bool ok = slurp(path, max, &text);

        saved = errno;
        if (ok)
        {
            memcpy(buf, text.data, text.len);
            got = (ssize_t)text.len;
        }
        rs_buf_free(&text);
    }
    if (path)
    {
        (void)unlink(path);
        free(path);
    }
    rs_buf_free(&err);
    errno = saved;
    return got;
}

bool rs_remote_read(struct rs_remote *rm, const char *name, size_t max, struct rs_buf *out,
                    struct rs_buf *err)
{
    int   status;
    char *path = fetch(rm, name, false, 0, UINT64_MAX, &status, err);
    bool  ok;

    if (!path)
    {
        int saved = errno;

        rs_buf_init(out);
        rs_buf_add(out, "", 0);
        errno = saved;
        return false;
    }
    ok = slurp(path, max, out);
    if (!ok)
    {
        int saved = errno;

        rs_buf_addf(err, "%s/%s: %s", rm->url, name, strerror(saved));
        errno = saved;
    }
    (void)unlink(path);
    free(path);
    return ok;
}

void rs_remote_prefetch(struct rs_remote *rm, const char *const *names, size_t n)
{
    struct rs_buf err;
    size_t        done = 0;

    rs_buf_init(&err);
    if (n == 0 || !session(rm, &err))
    {
        rs_buf_free(&err);
        return;
    }
    while (done < n)
    {
        size_t      count = n - done < BATCH_MAX ? n - done : BATCH_MAX;
        struct req *q = rs_xcalloc(count, sizeof(*q));
        bool        ran;
        size_t      i;

        for (i = 0; i < count; i++)
        {
            char *target = rs_xasprintf("/f/%s", names[done + i]);

            req_init(rm, &q[i], target);
            free(target);
        }
        ran = run_batch(rm, q, count, &err);
        for (i = 0; i < count; i++)
        {
            bool keep = ran && q[i].answered && q[i].ans.status == 200;

            if (keep)
            {
                rm->got = rs_xreallocarray(rm->got, rm->ngot + 1, sizeof(*rm->got));
                rm->got[rm->ngot].name = rs_xstrdup(names[done + i]);
                rm->got[rm->ngot].path = rs_xstrdup(q[i].out);
                rm->ngot++;
            }
            req_free(&q[i], keep);
        }
        free(q);
        done += count;
    }
    rs_buf_free(&err);
}
