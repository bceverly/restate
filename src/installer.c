/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "installer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "run.h"

/* A checksum file larger than this is not one. */
#define SUMS_MAX ((size_t)1024 * 1024)

static const struct rs_vendor_key *key_override;

void rs_installer_set_key(const struct rs_vendor_key *key)
{
    key_override = key;
}

void rs_installer_free(struct rs_installer *in)
{
    free(in->vendor);
    free(in->release);
    free(in->point);
    free(in->arch);
    free(in->flavor);
    free(in->description);
    free(in->reason);
    free(in->url);
    free(in->fallback_url);
    free(in->pattern);
    memset(in, 0, sizeof(*in));
}

/* Digits and dots only: a version number, and nothing that could be a path. */
static bool version_like(const char *s)
{
    size_t i;

    if (!s || !*s)
    {
        return false;
    }
    for (i = 0; s[i] != '\0'; i++)
    {
        if (!((s[i] >= '0' && s[i] <= '9') || s[i] == '.'))
        {
            return false;
        }
    }
    return true;
}

/* The kernel's name for an architecture, in Debian's spelling. */
static const char *debian_arch(const char *machine)
{
    static const char *const map[][2] = {
        { "x86_64", "amd64" },  { "amd64", "amd64" },     { "aarch64", "arm64" },
        { "arm64", "arm64" },   { "ppc64le", "ppc64el" }, { "s390x", "s390x" },
        { "riscv64", "riscv64" },
    };
    size_t i;

    for (i = 0; machine && i < sizeof(map) / sizeof(map[0]); i++)
    {
        if (strcmp(map[i][0], machine) == 0)
        {
            return map[i][1];
        }
    }
    return NULL;
}

bool rs_installer_resolve(const struct rs_jval *machine, struct rs_installer *out,
                          struct rs_buf *err)
{
    const struct rs_jval *sys = rs_jobject_get(machine, "system");
    const char           *id = rs_jobject_str(sys, "id");
    const char           *release = rs_jobject_str(sys, "version_id");
    const char           *version = rs_jobject_str(sys, "version");
    const char           *type = rs_jobject_str(sys, "type");
    const char           *arch = debian_arch(rs_jobject_str(sys, "architecture"));
    bool                  desktop;

    memset(out, 0, sizeof(*out));
    if (!id)
    {
        rs_buf_addstr(err, "the machine description does not say what system this is");
        return false;
    }
    if (strcmp(id, "ubuntu") != 0)
    {
        rs_buf_addf(err, "installers for %s are not supported yet; Ubuntu is, and the "
                    "others are on the roadmap", id);
        return false;
    }
    if (!version_like(release))
    {
        rs_buf_addstr(err, "the machine description has no Ubuntu release number");
        return false;
    }
    if (!arch)
    {
        rs_buf_addf(err, "Ubuntu publishes no installer for the %s architecture",
                    rs_jobject_str(sys, "architecture") ? rs_jobject_str(sys, "architecture")
                                                        : "(unknown)");
        return false;
    }
    out->vendor = rs_xstrdup("ubuntu");
    out->release = rs_xstrdup(release);
    out->arch = rs_xstrdup(arch);
    /* "26.04.1 LTS (Resolute Raccoon)" -> "26.04.1", if it is a point release
     * of this version at all. */
    if (version)
    {
        size_t n = strcspn(version, " ");
        char  *first = rs_xstrndup(version, n);

        if (version_like(first) && rs_starts_with(first, release) &&
            first[strlen(release)] == '.')
        {
            out->point = first;
        } else
        {
            free(first);
        }
    }

    desktop = type && strcmp(type, "desktop") == 0;
    if (desktop && strcmp(arch, "amd64") != 0 && strcmp(arch, "arm64") != 0)
    {
        out->reason = rs_xasprintf("this is a desktop, but Ubuntu publishes desktop installers "
                                   "only for amd64 and arm64: the server installer, then the "
                                   "desktop packages, is the way to rebuild it");
        desktop = false;
    } else if (type)
    {
        const char *why = rs_jobject_str(sys, "type_evidence");

        out->reason = rs_xasprintf("this is a %s: %s", type, why ? why : "so the description says");
    } else
    {
        out->reason = rs_xstrdup("the machine description does not say whether this is a "
                                 "desktop or a server, so the server installer");
    }
    out->flavor = rs_xstrdup(desktop ? "desktop" : "live-server");
    out->description = rs_xasprintf("Ubuntu %s %s for %s", release, desktop ? "Desktop" : "Server",
                                    arch);
    out->pattern = rs_xasprintf("ubuntu-%s[.N]-%s-%s.iso", release, out->flavor, arch);
    if (strcmp(arch, "amd64") == 0)
    {
        /* releases.ubuntu.com carries each supported release's current point
         * release; at end of life it moves to old-releases. */
        out->url = rs_xasprintf("https://releases.ubuntu.com/%s/", release);
        out->fallback_url = rs_xasprintf("https://old-releases.ubuntu.com/releases/%s/", release);
    } else
    {
        out->url = rs_xasprintf("https://cdimage.ubuntu.com/releases/%s/release/", release);
    }
    out->key = key_override ? key_override : rs_vendor_key("ubuntu");
    return true;
}

/* The point number of a name like "ubuntu-26.04.1-...": 1; "ubuntu-26.04-": 0.
 * -1 if the name is not one of this installer's images at all. */
static long image_point(const struct rs_installer *in, const char *name)
{
    char       *prefix = rs_xasprintf("ubuntu-%s", in->release);
    char       *suffix = rs_xasprintf("-%s-%s.iso", in->flavor, in->arch);
    size_t      plen = strlen(prefix);
    size_t      slen = strlen(suffix);
    size_t      nlen = strlen(name);
    long        point = -1;

    if (nlen > plen + slen && strncmp(name, prefix, plen) == 0 &&
        strcmp(name + nlen - slen, suffix) == 0)
    {
        const char *mid = name + plen;
        size_t      mlen = nlen - plen - slen;

        if (mlen == 0)
        {
            point = 0;
        } else if (mid[0] == '.' && mlen >= 2 && mlen <= 4)
        {
            size_t i;

            point = 0;
            for (i = 1; i < mlen; i++)
            {
                if (mid[i] < '0' || mid[i] > '9')
                {
                    point = -1;
                    break;
                }
                point = point * 10 + (mid[i] - '0');
            }
        }
    } else if (nlen == plen + slen && strncmp(name, prefix, plen) == 0 &&
               strcmp(name + plen, suffix) == 0)
    {
        point = 0;
    }
    free(prefix);
    free(suffix);
    return point;
}

bool rs_installer_pick(const struct rs_installer *in, const char *sums, size_t len, char **name,
                       char hash[RS_SHA256_HEX_SIZE])
{
    const char *p = sums;
    const char *end = sums + len;
    long        best = -1;
    long        want = -1;

    *name = NULL;
    if (in->point)
    {
        /* resolve made point "<release>.<digits>", so this cannot fail. */
        want = strtol(in->point + strlen(in->release) + 1, NULL, 10);
    }
    while (p < end)
    {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t      llen = nl ? (size_t)(nl - p) : (size_t)(end - p);

        /* "<64 hex digits> *<name>" (binary mode) or "<64 hex>  <name>". */
        if (llen > 66 && (p[64] == ' ') && (p[65] == '*' || p[65] == ' '))
        {
            char  digest[RS_SHA256_HEX_SIZE];
            char *file = rs_xstrndup(p + 66, llen - 66);
            long  point;

            memcpy(digest, p, RS_SHA256_HEX_LEN);
            digest[RS_SHA256_HEX_LEN] = '\0';
            if (file[0] != '\0' && file[strlen(file) - 1] == '\r')
            {
                file[strlen(file) - 1] = '\0';
            }
            point = image_point(in, file);
            /* A name with a slash, or "..", is not an image in that directory
             * -- and would be written somewhere other than the cache. */
            if (point >= 0 && rs_sha256_valid_hex(digest) && !strchr(file, '/') &&
                !strstr(file, "..") &&
                (point == want || (!(*name && best == want) && point > best)))
            {
                free(*name);
                *name = rs_xstrdup(file);
                memcpy(hash, digest, RS_SHA256_HEX_SIZE);
                best = point;
            }
            free(file);
        }
        p = nl ? nl + 1 : end;
    }
    return *name != NULL;
}

const char *rs_installer_default_cache(void)
{
#if defined(__APPLE__)
    return "/Library/Caches/restate/installers";
#else
    return "/var/cache/restate/installers";
#endif
}

/*
 * Sets the mode of what is at `path` -- through a descriptor, opened without
 * following a symbolic link, so nothing put in its place between its making
 * and this can take the change somewhere else.
 */
static void set_mode(const char *path, mode_t mode)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);

    if (fd >= 0)
    {
        (void)fchmod(fd, mode);
        (void)close(fd);
    }
}

/*
 * mkdir -p, each new directory mode 0755 (0700 if `private`) -- set with
 * chmod, since restate's umask of 077 would otherwise make every one private,
 * and an installer image is public data a hypervisor running as someone else
 * has to read.
 */
static bool make_dirs(const char *path, bool private_dir, struct rs_buf *err)
{
    char  *p = rs_xstrdup(path);
    size_t i;

    for (i = 1; p[i] != '\0'; i++)
    {
        if (p[i] == '/')
        {
            p[i] = '\0';
            if (mkdir(p, 0755) == 0)
            {
                set_mode(p, 0755);
            } else if (errno != EEXIST)
            {
                rs_buf_addf(err, "%s: %s", p, strerror(errno));
                free(p);
                return false;
            }
            p[i] = '/';
        }
    }
    if (mkdir(p, private_dir ? 0700 : 0755) == 0)
    {
        set_mode(p, private_dir ? 0700 : 0755);
    } else if (errno != EEXIST)
    {
        rs_buf_addf(err, "%s: %s", p, strerror(errno));
        free(p);
        return false;
    }
    free(p);
    return true;
}

/*
 * Opens up the default cache, which a version of restate before this one
 * created readable by root alone: its directories 0755. Only the default's,
 * which restate owns; a --cache directory is left as its owner made it.
 */
static void open_default_cache(const struct rs_installer *in)
{
    const char *root = rs_installer_default_cache();
    char       *parent = rs_xstrdup(root);
    char       *slash = strrchr(parent, '/');
    char       *vendor = rs_xasprintf("%s/%s", root, in->vendor);
    char       *release = rs_xasprintf("%s/%s/%s", root, in->vendor, in->release);

    if (slash && slash != parent)
    {
        *slash = '\0';
        set_mode(parent, 0755);   /* /var/cache/restate */
    }
    set_mode(root, 0755);
    set_mode(vendor, 0755);
    set_mode(release, 0755);
    free(parent);
    free(vendor);
    free(release);
}

/*
 * curl, HTTPS only (or file:, for a mirror that is a local directory). Without
 * a progress bar its complaints are captured, and a failure's go in `why`
 * rather than onto the terminal ahead of restate's own message.
 */
static bool curl(const char *url, const char *dest, bool resume, bool progress, int *code,
                 struct rs_buf *why, struct rs_buf *err)
{
    struct rs_buf errtext;
    bool          local = rs_starts_with(url, "file://");
    char         *argv[24];
    int           n = 0;
    int           i;
    bool          ok;

    argv[n++] = rs_xstrdup("curl");
    argv[n++] = rs_xstrdup("-q");   /* first: ignore ~/.curlrc */
    argv[n++] = rs_xstrdup("--fail");
    argv[n++] = rs_xstrdup("--location");
    argv[n++] = rs_xstrdup("--show-error");
    argv[n++] = rs_xstrdup("--proto");
    argv[n++] = rs_xstrdup(local ? "=file" : "=https");
    argv[n++] = rs_xstrdup("--proto-redir");
    argv[n++] = rs_xstrdup(local ? "=file" : "=https");
    if (!local)
    {
        argv[n++] = rs_xstrdup("--tlsv1.2");
        argv[n++] = rs_xstrdup("--retry");
        argv[n++] = rs_xstrdup("3");
    }
    argv[n++] = rs_xstrdup(progress ? "--progress-bar" : "--silent");
    if (resume)
    {
        argv[n++] = rs_xstrdup("--continue-at");
        argv[n++] = rs_xstrdup("-");
    }
    argv[n++] = rs_xstrdup("--output");
    argv[n++] = rs_xstrdup(dest);
    argv[n++] = rs_xstrdup(url);
    argv[n] = NULL;
    rs_buf_init(&errtext);
    ok = rs_run(RS_PROG_CURL, argv, NULL, progress ? NULL : &errtext, code, err);
    for (i = 0; i < n; i++)
    {
        free(argv[i]);
    }
    if (ok && *code != 0)
    {
        while (errtext.len > 0 && (errtext.data[errtext.len - 1] == '\n' ||
                                   errtext.data[errtext.len - 1] == '\r'))
        {
            errtext.data[--errtext.len] = '\0';
        }
        rs_buf_reset(why);
        rs_buf_addf(why, "curl exit %d%s%s", *code, errtext.len ? ": " : "",
                    errtext.len ? errtext.data : "");
    }
    rs_buf_free(&errtext);
    return ok;
}

static bool hash_file(const char *path, char hex[RS_SHA256_HEX_SIZE])
{
    struct rs_sha256 ctx;
    unsigned char    chunk[65536];
    int              fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t          n;

    if (fd < 0)
    {
        return false;
    }
    rs_sha256_init(&ctx);
    while ((n = read(fd, chunk, sizeof(chunk))) > 0)
    {
        rs_sha256_update(&ctx, chunk, (size_t)n);
    }
    (void)close(fd);
    if (n < 0)
    {
        return false;
    }
    rs_sha256_final(&ctx, hex);
    return true;
}

static void progress(const struct rs_fetch_opts *o, const char *msg)
{
    if (!o->quiet)
    {
        (void)fprintf(stderr, "restate: %s\n", msg);
    }
}

/* Writes the pinned key where gpgv can read it. */
static char *write_keyring(const char *dir, const struct rs_vendor_key *key, struct rs_buf *err)
{
    char   *path = rs_xasprintf("%s/.%s.gpg", dir, key->fingerprint);
    char   *tmp = rs_xasprintf("%s.XXXXXX", path);
    int     fd = mkstemp(tmp);
    ssize_t w;

    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", tmp, strerror(errno));
        free(tmp);
        free(path);
        return NULL;
    }
    w = write(fd, key->data, key->len);
    (void)close(fd);
    if (w != (ssize_t)key->len || rename(tmp, path) != 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        (void)unlink(tmp);
        free(tmp);
        free(path);
        return NULL;
    }
    free(tmp);
    return path;
}

/*
 * gpgv's verdict on `sig` over `data`, required to be a good signature by
 * exactly the pinned key. gpgv exiting 0 is not enough on its own: that says
 * some key in the keyring made it, and the keyring is ours, but the status
 * line naming the key is what this check is actually about.
 */
static bool verify(const char *dir, const struct rs_vendor_key *key, const char *sig,
                   const char *data, struct rs_buf *err)
{
    char         *keyring = write_keyring(dir, key, err);
    char         *home = rs_xasprintf("%s/.gnupg", dir);
    struct rs_buf out;
    struct rs_buf errtext;
    int           code = -1;
    bool          ok;
    bool          valid = false;
    const char   *p;

    if (!keyring || !make_dirs(home, true, err))
    {
        free(keyring);
        free(home);
        return false;
    }
    rs_buf_init(&out);
    rs_buf_init(&errtext);
    {
        char *argv[10];
        char  a0[] = "gpgv";
        char  a1[] = "--homedir";
        char  a3[] = "--status-fd";
        char  a4[] = "1";
        char  a5[] = "--keyring";
        char *sigc = rs_xstrdup(sig);
        char *datac = rs_xstrdup(data);

        argv[0] = a0;
        argv[1] = a1;
        argv[2] = home;
        argv[3] = a3;
        argv[4] = a4;
        argv[5] = a5;
        argv[6] = keyring;
        argv[7] = sigc;
        argv[8] = datac;
        argv[9] = NULL;
        ok = rs_run(RS_PROG_GPGV, argv, &out, &errtext, &code, err);
        free(sigc);
        free(datac);
    }
    for (p = out.data; ok && p && *p; )
    {
        const char *nl = strchr(p, '\n');
        size_t      llen = nl ? (size_t)(nl - p) : strlen(p);

        /* [GNUPG:] VALIDSIG <signing key fpr> <date> <ts> <exp> <ver> <res>
         *          <algo> <hash> <class> <primary key fpr> */
        if (llen > 18 && strncmp(p, "[GNUPG:] VALIDSIG ", 18) == 0)
        {
            char       *line = rs_xstrndup(p, llen);
            const char *last = strrchr(line, ' ');

            if (strncmp(line + 18, key->fingerprint, 40) == 0 ||
                (last && strcmp(last + 1, key->fingerprint) == 0))
            {
                valid = true;
            }
            free(line);
        }
        p = nl ? nl + 1 : NULL;
    }
    if (ok && (code != 0 || !valid))
    {
        rs_buf_addf(err, "%s is not a valid signature of %s by %s (%s)", sig, data, key->name,
                    errtext.len ? errtext.data : "gpgv said nothing");
        ok = false;
    }
    rs_buf_free(&out);
    rs_buf_free(&errtext);
    free(keyring);
    free(home);
    return ok;
}

/* Fetches url/name to dest, trying the fallback directory if there is one. */
static bool fetch_meta(const char *base, const char *fallback, const char *name, const char *dest,
                       struct rs_buf *err)
{
    char         *url = rs_xasprintf("%s%s", base, name);
    struct rs_buf why;
    int           code = -1;
    bool          ok;

    rs_buf_init(&why);
    ok = curl(url, dest, false, false, &code, &why, err) && code == 0;
    if (!ok && fallback && err->len == 0)
    {
        free(url);
        url = rs_xasprintf("%s%s", fallback, name);
        ok = curl(url, dest, false, false, &code, &why, err) && code == 0;
    }
    if (!ok && err->len == 0)
    {
        rs_buf_addf(err, "could not download %s (%s)", url, why.len ? why.data : "curl failed");
    }
    rs_buf_free(&why);
    free(url);
    return ok;
}

static char *slurp(const char *path, size_t *len)
{
    struct rs_buf b;
    char          chunk[8192];
    int           fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t       n;

    *len = 0;
    if (fd < 0)
    {
        return NULL;
    }
    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    while ((n = read(fd, chunk, sizeof(chunk))) > 0 && b.len < SUMS_MAX)
    {
        rs_buf_add(&b, chunk, (size_t)n);
    }
    (void)close(fd);
    *len = b.len;
    return rs_buf_detach(&b);
}

bool rs_installer_fetch(const struct rs_installer *in, const struct rs_fetch_opts *o,
                        char **path, struct rs_buf *err)
{
    const char *cache = o->cache ? o->cache : rs_installer_default_cache();
    char       *dir = rs_xasprintf("%s/%s/%s", cache, in->vendor, in->release);
    char       *base;
    const char *fallback = NULL;
    char       *sums = rs_xasprintf("%s/SHA256SUMS", dir);
    char       *sig = rs_xasprintf("%s/SHA256SUMS.gpg", dir);
    char       *text = NULL;
    size_t      len = 0;
    char       *name = NULL;
    char       *final = NULL;
    char       *part = NULL;
    char        want[RS_SHA256_HEX_SIZE];
    char        got[RS_SHA256_HEX_SIZE];
    char       *msg;
    bool        ok = false;
    int         code = -1;

    *path = NULL;
    if (o->mirror)
    {
        size_t n = strlen(o->mirror);

        base = (n > 0 && o->mirror[n - 1] == '/') ? rs_xstrdup(o->mirror)
                                                  : rs_xasprintf("%s/", o->mirror);
    } else
    {
        base = rs_xstrdup(in->url);
        fallback = in->fallback_url;
    }
    if (!in->key)
    {
        rs_buf_addf(err, "restate has no signing key for %s", in->vendor);
        goto done;
    }
    if (!rs_program_path(RS_PROG_CURL) || !rs_program_path(RS_PROG_GPGV))
    {
        rs_buf_addf(err, "fetching an installer needs curl and gpgv (%s is not installed)",
                    !rs_program_path(RS_PROG_CURL) ? "curl" : "gpgv");
        goto done;
    }
    if (!make_dirs(dir, false, err))
    {
        goto done;
    }
    if (!o->cache)
    {
        open_default_cache(in);
    }

    msg = rs_xasprintf("fetching the checksums from %s", base);
    progress(o, msg);
    free(msg);
    if (!fetch_meta(base, fallback, "SHA256SUMS", sums, err) ||
        !fetch_meta(base, fallback, "SHA256SUMS.gpg", sig, err) ||
        !verify(dir, in->key, sig, sums, err))
    {
        goto done;
    }
    set_mode(sums, 0644);
    set_mode(sig, 0644);
    msg = rs_xasprintf("SHA256SUMS is signed by %s", in->key->name);
    progress(o, msg);
    free(msg);

    text = slurp(sums, &len);
    if (!text || !rs_installer_pick(in, text, len, &name, want))
    {
        rs_buf_addf(err, "SHA256SUMS lists no %s", in->pattern);
        goto done;
    }
    final = rs_xasprintf("%s/%s", dir, name);
    part = rs_xasprintf("%s.part", final);

    if (hash_file(final, got) && strcmp(got, want) == 0)
    {
        set_mode(final, 0644);
        msg = rs_xasprintf("%s is already downloaded and matches the signed checksum", name);
        progress(o, msg);
        free(msg);
        ok = true;
        goto done;
    }
    msg = rs_xasprintf("downloading %s", name);
    progress(o, msg);
    free(msg);
    {
        char         *url = rs_xasprintf("%s%s", base, name);
        struct rs_buf why;
        bool          fresh = false;

        rs_buf_init(&why);
        /* Resume first -- a .part left by an interrupted download is most of
         * the work -- and if what results does not match, start again from
         * nothing once. */
        for (;;)
        {
            rs_buf_reset(&why);
            if (!curl(url, part, !fresh, o->progress || (!o->quiet && isatty(STDERR_FILENO)),
                      &code, &why, err))
            {
                break;
            }
            if (hash_file(part, got) && strcmp(got, want) == 0)
            {
                ok = true;
                break;
            }
            if (fresh)
            {
                rs_buf_addf(err, "%s does not match the signed checksum%s%s%s", name,
                            why.len ? " (" : "", why.len ? why.data : "", why.len ? ")" : "");
                break;
            }
            (void)unlink(part);
            fresh = true;
        }
        rs_buf_free(&why);
        free(url);
    }
    if (ok)
    {
        set_mode(part, 0644);   /* public data: a hypervisor reads it */
    }
    if (ok && rename(part, final) != 0)
    {
        rs_buf_addf(err, "%s: %s", final, strerror(errno));
        ok = false;
    }
    if (!ok)
    {
        (void)unlink(part);
    }

done:
    if (ok)
    {
        *path = final;
        final = NULL;
    }
    free(dir);
    free(base);
    free(sums);
    free(sig);
    free(text);
    free(name);
    free(final);
    free(part);
    return ok;
}
