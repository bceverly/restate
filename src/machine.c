/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "machine.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "bsd.h"

/* Text files read here are small; anything larger is not what it claims. */
#define TEXT_MAX ((size_t)4 * 1024 * 1024)
/* A LUKS2 header, binary part and JSON area together, is at most 4 MiB. */
#define LUKS_MAX ((size_t)4 * 1024 * 1024)

/* ------------------------------------------------------------------------- */
/* Files                                                                     */
/* ------------------------------------------------------------------------- */

static char *path_join(const char *a, const char *b)
{
    size_t n = strlen(a);

    while (n > 1 && a[n - 1] == '/')
    {
        n--;
    }
    if (n == 1 && a[0] == '/')
    {
        return rs_xstrdup(b);
    }
    return rs_xasprintf("%.*s%s", (int)n, a, b);
}

/* The whole of a small file, NUL-terminated, or NULL. */
static char *read_text(const char *path)
{
    struct rs_buf b;
    char          chunk[8192];
    int           fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);

    if (fd < 0)
    {
        return NULL;
    }
    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            break;
        }
        if (b.len + (size_t)n > TEXT_MAX)
        {
            break;
        }
        rs_buf_add(&b, chunk, (size_t)n);
    }
    (void)close(fd);
    if (strlen(b.data) != b.len)
    {
        /* A NUL inside: not a text file, whatever its name says. */
        rs_buf_free(&b);
        return NULL;
    }
    return rs_buf_detach(&b);
}

/* read_text of root + rel, with surrounding whitespace removed. */
static char *read_line(const char *root, const char *rel)
{
    char  *path = path_join(root, rel);
    char  *s = read_text(path);
    size_t n;
    size_t start = 0;

    free(path);
    if (!s)
    {
        return NULL;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
    {
        s[--n] = '\0';
    }
    while (s[start] == ' ' || s[start] == '\t')
    {
        start++;
    }
    if (start > 0)
    {
        memmove(s, s + start, n - start + 1);
    }
    if (s[0] == '\0')
    {
        free(s);
        return NULL;
    }
    return s;
}

static bool exists(const char *root, const char *rel)
{
    char       *path = path_join(root, rel);
    struct stat st;
    bool        ok = lstat(path, &st) == 0;

    free(path);
    return ok;
}

static bool read_u64(const char *root, const char *rel, uint64_t *out)
{
    char *s = read_line(root, rel);
    char *end = NULL;
    bool  ok = false;

    if (s)
    {
        errno = 0;
        *out = strtoull(s, &end, 10);
        ok = errno == 0 && end != s && *end == '\0';
        free(s);
    }
    return ok;
}

static int compare_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The entries of a directory, sorted, without "." and "..". */
static char **list_dir(const char *root, const char *rel, size_t *count)
{
    char                *path = path_join(root, rel);
    DIR                 *d = opendir(path);
    const struct dirent *de;
    char               **names = NULL;
    size_t               n = 0;

    free(path);
    *count = 0;
    if (!d)
    {
        return NULL;
    }
    while ((de = readdir(d)) != NULL)
    {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
        {
            continue;
        }
        names = rs_xreallocarray(names, n + 1, sizeof(*names));
        names[n++] = rs_xstrdup(de->d_name);
    }
    (void)closedir(d);
    if (n > 1)
    {
        qsort(names, n, sizeof(*names), compare_names);
    }
    *count = n;
    return names;
}

static void free_list(char **names, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(names[i]);
    }
    free(names);
}

/* The member `key` of `obj`, writable, or NULL. */
static struct rs_jval *member(struct rs_jval *obj, const char *key)
{
    size_t i;

    for (i = 0; i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    return NULL;
}

/* Something that could not be read, said in the description itself. */
static void note(struct rs_jval *machine, const char *text)
{
    struct rs_jval *notes = member(machine, "notes");

    if (notes)
    {
        rs_jval_set_string(rs_jarr_add(notes), text);
    }
}

/* ------------------------------------------------------------------------- */
/* The udev database                                                         */
/* ------------------------------------------------------------------------- */

/* udev writes some values with \xNN escapes ("Basic\x20data\x20partition"). */
static char *udev_decode(const char *s)
{
    struct rs_buf b;
    size_t        i;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (i = 0; s[i] != '\0'; i++)
    {
        static const char hex[] = "0123456789abcdef";
        const char       *h1 = NULL;
        const char       *h2 = NULL;

        if (s[i] == '\\' && s[i + 1] == 'x' && s[i + 2] != '\0' && s[i + 3] != '\0')
        {
            h1 = strchr(hex, s[i + 2] | 0x20);
            h2 = strchr(hex, s[i + 3] | 0x20);
        }
        if (h1 && h2 && (h1 != hex || h2 != hex))
        {
            rs_buf_addc(&b, (char)(unsigned char)((h1 - hex) * 16 + (h2 - hex)));
            i += 3;
        } else
        {
            rs_buf_addc(&b, s[i]);
        }
    }
    return rs_buf_detach(&b);
}

/* The udev property `key` of block device maj:min, decoded, or NULL. */
static char *udev_get(const char *udev_text, const char *key)
{
    size_t      klen = strlen(key);
    const char *p = udev_text;

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      llen = nl ? (size_t)(nl - p) : strlen(p);

        if (llen > klen + 3 && strncmp(p, "E:", 2) == 0 &&
            strncmp(p + 2, key, klen) == 0 && p[2 + klen] == '=')
        {
            char *raw = rs_xstrndup(p + 3 + klen, llen - 3 - klen);
            char *out = udev_decode(raw);

            free(raw);
            return out;
        }
        p = nl ? nl + 1 : NULL;
    }
    return NULL;
}

static char *udev_load(const char *sysroot, const char *devnum)
{
    char *rel = rs_xasprintf("/run/udev/data/b%s", devnum);
    char *path = path_join(sysroot, rel);
    char *text = read_text(path);

    free(rel);
    free(path);
    return text;
}

/* Copies udev property `key` into obj[name], if there is one. */
static void udev_member(struct rs_jval *obj, const char *udev, const char *key, const char *name)
{
    char *v = udev ? udev_get(udev, key) : NULL;

    if (v && v[0] != '\0')
    {
        rs_jobj_str(obj, name, v);
    }
    free(v);
}

/* What is on a block device, from its udev properties. */
static void describe_content(struct rs_jval *dev, const char *udev)
{
    char           *type = udev ? udev_get(udev, "ID_FS_TYPE") : NULL;
    struct rs_jval *c;

    if (!type || type[0] == '\0')
    {
        free(type);
        return;
    }
    c = rs_jobj_add(dev, "content");
    rs_jval_set_object(c);
    rs_jobj_str(c, "type", type);
    udev_member(c, udev, "ID_FS_USAGE", "usage");
    udev_member(c, udev, "ID_FS_UUID", "uuid");
    udev_member(c, udev, "ID_FS_LABEL", "label");
    udev_member(c, udev, "ID_FS_VERSION", "version");
    free(type);
}

/* ------------------------------------------------------------------------- */
/* LUKS                                                                      */
/* ------------------------------------------------------------------------- */

static uint64_t be64(const unsigned char *p)
{
    uint64_t v = 0;
    int      i;

    for (i = 0; i < 8; i++)
    {
        v = (v << 8) | p[i];
    }
    return v;
}

static uint32_t be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* A fixed-width, NUL-padded header field as a string. */
static char *field(const unsigned char *p, size_t width)
{
    size_t n = 0;

    while (n < width && p[n] != '\0')
    {
        n++;
    }
    return rs_xstrndup((const char *)p, n);
}

bool rs_luks_parse(const unsigned char *hdr, size_t len, struct rs_jval *out)
{
    static const unsigned char magic[6] = { 'L', 'U', 'K', 'S', 0xba, 0xbe };
    unsigned                   version;
    char                      *s;

    if (len < 592 || memcmp(hdr, magic, sizeof(magic)) != 0)
    {
        return false;
    }
    version = ((unsigned)hdr[6] << 8) | hdr[7];
    rs_jval_set_object(out);
    rs_jobj_u64(out, "version", version);
    s = field(hdr + 168, 40);
    rs_jobj_str(out, "uuid", s);
    free(s);
    if (version == 1)
    {
        char *name = field(hdr + 8, 32);
        char *mode = field(hdr + 40, 32);
        char *cipher = rs_xasprintf("%s-%s", name, mode);

        rs_jobj_str(out, "cipher", cipher);
        rs_jobj_u64(out, "key_size", (uint64_t)be32(hdr + 108) * 8);
        s = field(hdr + 72, 32);
        rs_jobj_str(out, "hash", s);
        free(s);
        free(name);
        free(mode);
        free(cipher);
        return true;
    }
    if (version == 2)
    {
        uint64_t              hdr_size = be64(hdr + 8);
        size_t                jlen;
        struct rs_json_parser jp;
        struct rs_buf         err;
        struct rs_jval        meta;
        const struct rs_jval *seg;
        const struct rs_jval *slots;
        bool                  ok;

        s = field(hdr + 24, 48);
        if (s[0] != '\0')
        {
            rs_jobj_str(out, "label", s);
        }
        free(s);
        if (hdr_size <= 4096 || hdr_size > len)
        {
            /* The binary header alone: the JSON area was not read, or is
             * not where the header says. */
            return true;
        }
        jlen = 0;
        while (4096 + jlen < hdr_size && hdr[4096 + jlen] != '\0')
        {
            jlen++;
        }
        rs_buf_init(&err);
        rs_json_init(&jp, (const char *)hdr + 4096, jlen, &err);
        memset(&meta, 0, sizeof(meta));
        ok = rs_json_value(&jp, &meta) && meta.type == RS_JOBJECT;
        if (ok)
        {
            seg = rs_jobject_get(rs_jobject_get(&meta, "segments"), "0");
            if (rs_jobject_str(seg, "encryption"))
            {
                rs_jobj_str(out, "cipher", rs_jobject_str(seg, "encryption"));
            }
            if (rs_jobject_get(seg, "sector_size"))
            {
                uint64_t ss = 0;

                if (rs_jval_u64(rs_jobject_get(seg, "sector_size"), &ss))
                {
                    rs_jobj_u64(out, "sector_size", ss);
                }
            }
            /* Tokens say how the volume unlocks besides a passphrase: a
             * "systemd-tpm2" or "clevis" token ties it to this machine's TPM
             * or to a network server, and it will not unlock that way
             * anywhere else. */
            {
                const struct rs_jval *tokens = rs_jobject_get(&meta, "tokens");

                if (tokens && tokens->type == RS_JOBJECT && tokens->n > 0)
                {
                    struct rs_jval *list = rs_jobj_add(out, "tokens");
                    size_t          t;

                    rs_jval_set_array(list);
                    for (t = 0; t < tokens->n; t++)
                    {
                        const char *type = rs_jobject_str(&tokens->items[t], "type");

                        rs_jval_set_string(rs_jarr_add(list), type ? type : "unknown");
                    }
                }
            }
            slots = rs_jobject_get(&meta, "keyslots");
            if (slots && slots->type == RS_JOBJECT && slots->n > 0)
            {
                const struct rs_jval *slot = &slots->items[0];
                uint64_t              ks = 0;

                if (rs_jval_u64(rs_jobject_get(rs_jobject_get(slot, "area"), "key_size"), &ks))
                {
                    rs_jobj_u64(out, "key_size", ks * 8);
                }
                if (rs_jobject_str(rs_jobject_get(slot, "kdf"), "type"))
                {
                    rs_jobj_str(out, "pbkdf", rs_jobject_str(rs_jobject_get(slot, "kdf"), "type"));
                }
            }
        }
        rs_jval_free(&meta);
        rs_buf_free(&err);
        return true;
    }
    return true;
}

/* The LUKS header of block device `name`, if it can be read; root only. */
static bool read_luks(const char *sysroot, const char *name, struct rs_jval *out)
{
    char          *rel = rs_xasprintf("/dev/%s", name);
    char          *path = path_join(sysroot, rel);
    int            fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    unsigned char *hdr;
    size_t         have = 0;
    size_t         want = 4096;
    bool           ok = false;

    free(rel);
    free(path);
    if (fd < 0)
    {
        return false;
    }
    hdr = rs_xmalloc(LUKS_MAX);
    for (;;)
    {
        ssize_t n = pread(fd, hdr + have, want - have, (off_t)have);

        if (n <= 0)
        {
            break;
        }
        have += (size_t)n;
        if (have == want && want == 4096 && hdr[7] == 2)
        {
            /* LUKS2: the header says how much more to read. */
            uint64_t hs = be64(hdr + 8);

            want = hs > 4096 && hs <= LUKS_MAX ? (size_t)hs : 4096;
        }
        if (have >= want)
        {
            break;
        }
    }
    (void)close(fd);
    ok = have >= 592 && rs_luks_parse(hdr, have, out);
    free(hdr);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* LVM metadata                                                              */
/* ------------------------------------------------------------------------- */

struct lvm_lexer {
    const char    *p;
    size_t         len;
    size_t         pos;
    struct rs_buf *err;
};

static void lvm_skip(struct lvm_lexer *lx)
{
    while (lx->pos < lx->len)
    {
        char c = lx->p[lx->pos];

        if (c == '#')
        {
            while (lx->pos < lx->len && lx->p[lx->pos] != '\n')
            {
                lx->pos++;
            }
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        {
            lx->pos++;
        } else
        {
            break;
        }
    }
}

static bool lvm_fail(struct lvm_lexer *lx, const char *what)
{
    if (lx->err->len == 0)
    {
        rs_buf_addf(lx->err, "%s at byte %zu", what, lx->pos);
    }
    return false;
}

static bool lvm_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '.' || c == '+' || c == '-';
}

static bool lvm_scalar(struct lvm_lexer *lx, struct rs_jval *out)
{
    char c = lx->p[lx->pos];

    if (c == '"')
    {
        struct rs_buf s;

        rs_buf_init(&s);
        rs_buf_add(&s, "", 0);
        lx->pos++;
        while (lx->pos < lx->len && lx->p[lx->pos] != '"')
        {
            if (lx->p[lx->pos] == '\\' && lx->pos + 1 < lx->len)
            {
                lx->pos++;
            }
            if (lx->p[lx->pos] == '\0')
            {
                rs_buf_free(&s);
                return lvm_fail(lx, "NUL in a string");
            }
            rs_buf_addc(&s, lx->p[lx->pos++]);
        }
        if (lx->pos >= lx->len)
        {
            rs_buf_free(&s);
            return lvm_fail(lx, "unterminated string");
        }
        lx->pos++;
        rs_jval_set_string(out, s.data);
        rs_buf_free(&s);
        return true;
    }
    if (c == '-' || (c >= '0' && c <= '9'))
    {
        bool     neg = c == '-';
        uint64_t v = 0;
        size_t   start;

        if (neg)
        {
            lx->pos++;
        }
        start = lx->pos;
        while (lx->pos < lx->len && lx->p[lx->pos] >= '0' && lx->p[lx->pos] <= '9')
        {
            unsigned d = (unsigned)(lx->p[lx->pos] - '0');

            if (v > (UINT64_MAX - d) / 10)
            {
                return lvm_fail(lx, "number too large");
            }
            v = v * 10 + d;
            lx->pos++;
        }
        if (lx->pos == start)
        {
            return lvm_fail(lx, "bad number");
        }
        rs_jval_set_u64(out, v);
        out->neg = neg && v != 0;
        return true;
    }
    return lvm_fail(lx, "expected a value");
}

static bool lvm_items(struct lvm_lexer *lx, struct rs_jval *obj, int depth, bool top);

static bool lvm_value(struct lvm_lexer *lx, struct rs_jval *out)
{
    lvm_skip(lx);
    if (lx->pos >= lx->len)
    {
        return lvm_fail(lx, "expected a value");
    }
    if (lx->p[lx->pos] != '[')
    {
        return lvm_scalar(lx, out);
    }
    lx->pos++;
    rs_jval_set_array(out);
    for (;;)
    {
        lvm_skip(lx);
        if (lx->pos < lx->len && lx->p[lx->pos] == ']')
        {
            lx->pos++;
            return true;
        }
        if (lx->pos >= lx->len)
        {
            return lvm_fail(lx, "unterminated list");
        }
        if (out->n >= 100000)
        {
            return lvm_fail(lx, "list too long");
        }
        if (!lvm_scalar(lx, rs_jarr_add(out)))
        {
            return false;
        }
        lvm_skip(lx);
        if (lx->pos < lx->len && lx->p[lx->pos] == ',')
        {
            lx->pos++;
        }
    }
}

static bool lvm_items(struct lvm_lexer *lx, struct rs_jval *obj, int depth, bool top) /* NOLINT(misc-no-recursion) */
{
    if (depth > 16)
    {
        return lvm_fail(lx, "nested too deeply");
    }
    for (;;)
    {
        size_t start;
        char  *name;

        lvm_skip(lx);
        if (lx->pos >= lx->len)
        {
            return top ? true : lvm_fail(lx, "unterminated section");
        }
        if (lx->p[lx->pos] == '}')
        {
            if (top)
            {
                return lvm_fail(lx, "unexpected '}'");
            }
            lx->pos++;
            return true;
        }
        start = lx->pos;
        while (lx->pos < lx->len && lvm_name_char(lx->p[lx->pos]))
        {
            lx->pos++;
        }
        if (lx->pos == start)
        {
            return lvm_fail(lx, "expected a name");
        }
        name = rs_xstrndup(lx->p + start, lx->pos - start);
        /* LVM never writes a name twice in one section, and a JSON object
         * cannot hold one twice, so the tree could not be written back out. */
        if (rs_jobject_get(obj, name))
        {
            free(name);
            return lvm_fail(lx, "a name appears twice in one section");
        }
        lvm_skip(lx);
        if (lx->pos < lx->len && lx->p[lx->pos] == '=')
        {
            struct rs_jval *v;

            lx->pos++;
            v = rs_jobj_add(obj, name);
            free(name);
            if (!lvm_value(lx, v))
            {
                return false;
            }
        } else if (lx->pos < lx->len && lx->p[lx->pos] == '{')
        {
            struct rs_jval *v;

            lx->pos++;
            v = rs_jobj_add(obj, name);
            free(name);
            rs_jval_set_object(v);
            if (!lvm_items(lx, v, depth + 1, false))
            {
                return false;
            }
        } else
        {
            free(name);
            return lvm_fail(lx, "expected '=' or '{'");
        }
    }
}

bool rs_lvm_parse(const char *text, size_t len, struct rs_jval *out, struct rs_buf *err)
{
    struct lvm_lexer lx;

    lx.p = text;
    lx.len = len;
    lx.pos = 0;
    lx.err = err;
    rs_jval_set_object(out);
    return lvm_items(&lx, out, 0, true);
}

/* ------------------------------------------------------------------------- */
/* The sections                                                              */
/* ------------------------------------------------------------------------- */

/* KEY=VALUE, KEY="VALUE" -- os-release's format. */
static void os_release(struct rs_jval *sys, const char *text)
{
    static const char *const keys[] = { "ID", "ID_LIKE", "NAME", "VERSION", "VERSION_ID",
                                        "VERSION_CODENAME", "PRETTY_NAME", "VARIANT_ID" };
    const char              *p = text;

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      llen = nl ? (size_t)(nl - p) : strlen(p);
        const char *eq = memchr(p, '=', llen);

        if (eq)
        {
            size_t klen = (size_t)(eq - p);
            size_t vlen = llen - klen - 1;
            char  *value;
            size_t k;

            for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
            {
                if (strlen(keys[k]) == klen && strncmp(keys[k], p, klen) == 0)
                {
                    const char *v = eq + 1;
                    char       *lower;
                    size_t      i;

                    if (vlen >= 2 && (v[0] == '"' || v[0] == '\'') && v[vlen - 1] == v[0])
                    {
                        v++;
                        vlen -= 2;
                    }
                    value = rs_xstrndup(v, vlen);
                    lower = rs_xstrdup(keys[k]);
                    for (i = 0; lower[i] != '\0'; i++)
                    {
                        if (lower[i] >= 'A' && lower[i] <= 'Z')
                        {
                            lower[i] = (char)(lower[i] - 'A' + 'a');
                        }
                    }
                    rs_jobj_str(sys, lower, value);
                    free(lower);
                    free(value);
                }
            }
        }
        p = nl ? nl + 1 : NULL;
    }
}

/* Whether dpkg's status file says package `name` is installed. */
static bool dpkg_installed(const char *status, const char *name)
{
    char       *needle = rs_xasprintf("Package: %s\n", name);
    const char *p = status;
    bool        found = false;

    while (p && (p = strstr(p, needle)) != NULL)
    {
        if (p == status || p[-1] == '\n')
        {
            const char *end = strstr(p, "\n\n");
            const char *st = strstr(p, "\nStatus: install ok installed");

            found = st && (!end || st < end);
            break;
        }
        p++;
    }
    free(needle);
    return found;
}

/*
 * Desktop or server. A desktop install is a server install with a graphical
 * session on top, so a desktop sign anywhere wins: one of the desktop
 * metapackages, or a graphical login session installed. The evidence goes in
 * the description beside the answer, because this is an inference, and the
 * installer chosen from it should be checkable.
 */
static void describe_type(const char *root, struct rs_jval *sys)
{
    static const char *const metas[] = {
        "ubuntu-desktop", "ubuntu-desktop-minimal", "kubuntu-desktop", "xubuntu-desktop",
        "lubuntu-desktop", "ubuntu-mate-desktop", "ubuntucinnamon-desktop",
        "ubuntustudio-desktop", "ubuntu-budgie-desktop", "edubuntu-desktop",
        "ubuntu-unity-desktop", "ubuntu-server", "ubuntu-server-minimal", "ubuntu-cloud-minimal"
    };
    char          *path = path_join(root, "/var/lib/dpkg/status");
    char          *status = read_text(path);
    struct rs_buf  why;
    bool           desktop = false;
    size_t         i;
    char         **sessions;
    size_t         nsessions;

    free(path);
    rs_buf_init(&why);
    for (i = 0; status && i < sizeof(metas) / sizeof(metas[0]); i++)
    {
        if (dpkg_installed(status, metas[i]))
        {
            rs_buf_addf(&why, "%sthe %s package is installed", why.len ? "; " : "", metas[i]);
            desktop = desktop || strstr(metas[i], "desktop") != NULL;
        }
    }
    free(status);
    sessions = list_dir(root, "/usr/share/wayland-sessions", &nsessions);
    if (nsessions == 0)
    {
        free_list(sessions, nsessions);
        sessions = list_dir(root, "/usr/share/xsessions", &nsessions);
    }
    if (nsessions > 0)
    {
        rs_buf_addf(&why, "%sa graphical session is installed (%s)", why.len ? "; " : "",
                    sessions[0]);
        desktop = true;
    }
    free_list(sessions, nsessions);
    if (why.len == 0)
    {
        rs_buf_addstr(&why, "no desktop package or graphical session is installed");
    }
    rs_jobj_str(sys, "type", desktop ? "desktop" : "server");
    rs_jobj_str(sys, "type_evidence", why.data);
    rs_buf_free(&why);
}

/*
 * Bare metal, or a virtual machine, and on what. From DMI first -- a
 * hypervisor names itself there -- then the CPU's hypervisor flag, which every
 * hypervisor sets and no real CPU does.
 */
static void describe_virtualization(const char *sysroot, const char *root, struct rs_jval *sys)
{
    static const struct {
        const char *field;
        const char *contains;
        const char *name;
    } signs[] = {
        { "sys_vendor", "QEMU", "kvm" },
        { "product_name", "KVM", "kvm" },
        { "sys_vendor", "VMware", "vmware" },
        { "product_name", "Virtual Machine", "hyperv" },
        { "sys_vendor", "innotek", "virtualbox" },
        { "product_name", "VirtualBox", "virtualbox" },
        { "sys_vendor", "Xen", "xen" },
        { "product_name", "HVM domU", "xen" },
        { "sys_vendor", "Amazon EC2", "amazon" },
        { "product_name", "Google Compute Engine", "google" },
        { "sys_vendor", "DigitalOcean", "digitalocean" },
        { "sys_vendor", "OpenStack", "openstack" },
        { "product_name", "OpenStack", "openstack" },
        { "sys_vendor", "Parallels", "parallels" },
        { "sys_vendor", "Bochs", "bochs" },
    };
    const char *found = NULL;
    size_t      i;
    char       *s;

    for (i = 0; !found && i < sizeof(signs) / sizeof(signs[0]); i++)
    {
        char *rel = rs_xasprintf("/sys/class/dmi/id/%s", signs[i].field);

        s = read_line(sysroot, rel);
        if (s && strstr(s, signs[i].contains))
        {
            found = signs[i].name;
        }
        free(s);
        free(rel);
    }
    if (!found)
    {
        s = read_line(sysroot, "/sys/hypervisor/type");
        if (s && strcmp(s, "xen") == 0)
        {
            found = "xen";
        }
        free(s);
    }
    if (!found)
    {
        char *path = path_join(sysroot, "/proc/cpuinfo");
        char *cpu = read_text(path);

        if (cpu && strstr(cpu, " hypervisor"))
        {
            found = "unknown";
        }
        free(cpu);
        free(path);
    }
    rs_jobj_str(sys, "virtualization", found ? found : "none");
    if (exists(root, "/.dockerenv"))
    {
        rs_jobj_str(sys, "container", "docker");
    } else if (exists(root, "/run/.containerenv"))
    {
        rs_jobj_str(sys, "container", "podman");
    }
}

/*
 * The value of KEY=value in a shell-style file such as /etc/default/locale,
 * unquoted, or NULL. The last assignment wins, as it does when the file is
 * sourced.
 */
static char *shell_var(const char *text, const char *key)
{
    size_t      klen = strlen(key);
    const char *p = text;
    char       *found = NULL;

    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);

        while (len > 0 && (*p == ' ' || *p == '\t'))
        {
            p++;
            len--;
        }
        if (len > klen && strncmp(p, key, klen) == 0 && p[klen] == '=')
        {
            const char *v = p + klen + 1;
            size_t      vlen = len - klen - 1;

            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\r'))
            {
                vlen--;
            }
            if (vlen >= 2 && (v[0] == '"' || v[0] == '\'') && v[vlen - 1] == v[0])
            {
                v++;
                vlen -= 2;
            }
            free(found);
            found = vlen > 0 ? rs_xstrndup(v, vlen) : NULL;
        }
        p = nl ? nl + 1 : NULL;
    }
    return found;
}

/*
 * The locale, keyboard and time zone: what an installer asks first, and what
 * an unattended install has to be told.
 */
static void describe_locale(const char *root, struct rs_jval *sys)
{
    char *path = path_join(root, "/etc/default/locale");
    char *text = read_text(path);
    char *v;

    free(path);
    if (!text)
    {
        path = path_join(root, "/etc/locale.conf");
        text = read_text(path);
        free(path);
    }
    v = text ? shell_var(text, "LANG") : NULL;
    rs_jobj_str(sys, "locale", v);
    free(v);
    free(text);

    path = path_join(root, "/etc/default/keyboard");
    text = read_text(path);
    free(path);
    v = text ? shell_var(text, "XKBLAYOUT") : NULL;
    rs_jobj_str(sys, "keyboard_layout", v);
    free(v);
    v = text ? shell_var(text, "XKBVARIANT") : NULL;
    rs_jobj_str(sys, "keyboard_variant", v);
    free(v);
    free(text);

    /* /etc/timezone where Debian still writes it; otherwise the zone the
     * /etc/localtime link points into. */
    v = read_line(root, "/etc/timezone");
    if (!v)
    {
        char    target[512];
        ssize_t n;

        path = path_join(root, "/etc/localtime");
        /* Only parsed as text for the zone's name, never followed, and
         * terminated by hand below. */
        n = readlink(path, target, sizeof(target) - 1); /* Flawfinder: ignore */
        free(path);
        if (n > 0)
        {
            const char *zone;

            target[n] = '\0';
            zone = strstr(target, "zoneinfo/");
            if (zone && zone[9] != '\0')
            {
                v = rs_xstrdup(zone + 9);
            }
        }
    }
    rs_jobj_str(sys, "timezone", v);
    free(v);
}

/*
 * Installed packages that matter when a machine moves between hardware and a
 * hypervisor: the ones that only make sense on real hardware, the ones that
 * only make sense in a guest, and the SSH server an unattended install should
 * put back. The full package inventory is a later version's; this is the part
 * `--target` needs now.
 */
static void describe_packages(const char *root, struct rs_jval *sys)
{
    static const char *const hardware[] = {
        "intel-microcode", "amd64-microcode", "ipmitool", "freeipmi-tools", "lm-sensors",
        "thermald", "tlp", "fwupd", "smartmontools", "nvme-cli", "mdadm", "nvidia-driver-*",
        "bolt", "fprintd", "iio-sensor-proxy"
    };
    static const char *const guest[] = {
        "qemu-guest-agent", "spice-vdagent", "open-vm-tools", "open-vm-tools-desktop",
        "hyperv-daemons", "linux-cloud-tools-virtual", "virtualbox-guest-utils",
        "virtualbox-guest-x11", "xe-guest-utilities", "linux-image-virtual"
    };
    char           *path = path_join(root, "/var/lib/dpkg/status");
    char           *status = read_text(path);
    struct rs_jval *hw;
    struct rs_jval *gu;
    const char     *p;

    free(path);
    if (!status)
    {
        return;
    }
    rs_jobj_bool(sys, "ssh_server", dpkg_installed(status, "openssh-server"));
    hw = rs_jobj_add(sys, "hardware_packages");
    rs_jval_set_array(hw);
    gu = rs_jobj_add(sys, "guest_packages");
    rs_jval_set_array(gu);
    /* One pass over the stanzas: a pattern such as nvidia-driver-* needs every
     * package name, not a lookup of one. */
    for (p = status; p && *p; )
    {
        const char *end = strstr(p, "\n\n");
        size_t      slen = end ? (size_t)(end - p) : strlen(p);
        char       *stanza = rs_xstrndup(p, slen);
        char       *name = NULL;

        if (strncmp(stanza, "Package: ", 9) == 0)
        {
            name = rs_xstrndup(stanza + 9, strcspn(stanza + 9, "\n"));
        }
        if (name && strstr(stanza, "\nStatus: install ok installed"))
        {
            size_t i;

            for (i = 0; i < sizeof(hardware) / sizeof(hardware[0]); i++)
            {
                size_t n = strlen(hardware[i]);
                bool   prefix = hardware[i][n - 1] == '*';

                if (prefix ? strncmp(name, hardware[i], n - 1) == 0
                           : strcmp(name, hardware[i]) == 0)
                {
                    rs_jval_set_string(rs_jarr_add(hw), name);
                    break;
                }
            }
            for (i = 0; i < sizeof(guest) / sizeof(guest[0]); i++)
            {
                if (strcmp(name, guest[i]) == 0)
                {
                    rs_jval_set_string(rs_jarr_add(gu), name);
                    break;
                }
            }
        }
        free(name);
        free(stanza);
        p = end ? end + 2 : NULL;
    }
    free(status);
}

static void describe_system(const char *sysroot, const char *root, struct rs_jval *machine)
{
    struct rs_jval *sys = rs_jobj_add(machine, "system");
    char           *path;
    char           *text;
    char           *s;
    struct utsname  u;

    rs_jval_set_object(sys);
    path = path_join(root, "/etc/os-release");
    text = read_text(path);
    free(path);
    if (!text)
    {
        path = path_join(root, "/usr/lib/os-release");
        text = read_text(path);
        free(path);
    }
    if (text)
    {
        os_release(sys, text);
        free(text);
    }
    if (uname(&u) == 0)
    {
        rs_jobj_str(sys, "kernel_name", u.sysname);
        rs_jobj_str(sys, "architecture", u.machine);
        /* OpenBSD, NetBSD and macOS have no os-release: the kernel's name and
         * release are the system's. */
        if (!rs_jobject_str(sys, "id"))
        {
            char  *id = rs_xstrdup(u.sysname);
            size_t i;

            for (i = 0; id[i] != '\0'; i++)
            {
                unsigned char c = (unsigned char)id[i];

                id[i] = (char)((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
            }
            rs_jobj_str(sys, "id", id);
            rs_jobj_str(sys, "name", u.sysname);
            rs_jobj_str(sys, "version_id", u.release);
            free(id);
        }
    }
    s = read_line(sysroot, "/proc/sys/kernel/osrelease");
    rs_jobj_str(sys, "kernel", s);
    free(s);
    s = read_line(root, "/etc/hostname");
    rs_jobj_str(sys, "hostname", s);
    free(s);
    s = read_line(root, "/var/log/installer/media-info");
    rs_jobj_str(sys, "install_media", s);
    free(s);
    describe_locale(root, sys);
    describe_type(root, sys);
    describe_packages(root, sys);
    describe_virtualization(sysroot, root, sys);
}

static void describe_hardware(const char *sysroot, struct rs_jval *machine)
{
    static const char *const dmi[] = { "sys_vendor", "product_name", "product_version",
                                       "board_vendor", "board_name", "bios_vendor",
                                       "bios_version" };
    struct rs_jval          *hw = rs_jobj_add(machine, "hardware");
    char                    *text;
    char                    *path;
    size_t                   i;
    char                   **nets;
    size_t                   nnet;
    struct rs_jval          *net;

    rs_jval_set_object(hw);
    for (i = 0; i < sizeof(dmi) / sizeof(dmi[0]); i++)
    {
        char *rel = rs_xasprintf("/sys/class/dmi/id/%s", dmi[i]);
        char *s = read_line(sysroot, rel);

        rs_jobj_str(hw, dmi[i], s);
        free(s);
        free(rel);
    }
    path = path_join(sysroot, "/proc/cpuinfo");
    text = read_text(path);
    free(path);
    if (text)
    {
        uint64_t    cpus = 0;
        const char *p = text;
        char       *model = NULL;

        while (p && *p)
        {
            const char *nl = strchr(p, '\n');
            size_t      llen = nl ? (size_t)(nl - p) : strlen(p);

            if (strncmp(p, "processor", 9) == 0)
            {
                cpus++;
            } else if (!model && strncmp(p, "model name", 10) == 0 && memchr(p, ':', llen))
            {
                const char *c = memchr(p, ':', llen);

                c++;
                while (*c == ' ' || *c == '\t')
                {
                    c++;
                }
                model = rs_xstrndup(c, llen - (size_t)(c - p));
            }
            p = nl ? nl + 1 : NULL;
        }
        rs_jobj_str(hw, "cpu", model);
        if (cpus > 0)
        {
            rs_jobj_u64(hw, "cpus", cpus);
        }
        free(model);
        free(text);
    }
    path = path_join(sysroot, "/proc/meminfo");
    text = read_text(path);
    free(path);
    if (text)
    {
        const char *m = strstr(text, "MemTotal:");

        if (m)
        {
            unsigned long long kb = strtoull(m + 9, NULL, 10);

            rs_jobj_u64(hw, "memory", (uint64_t)kb * 1024);
        }
        free(text);
    }
    /* Physical interfaces only: a bridge or a container's veth is created by
     * the software that needs it, and recreated by it too. */
    net = rs_jobj_add(hw, "network");
    rs_jval_set_array(net);
    nets = list_dir(sysroot, "/sys/class/net", &nnet);
    for (i = 0; i < nnet; i++)
    {
        char           *rel = rs_xasprintf("/sys/class/net/%s/device", nets[i]);
        char           *arel = rs_xasprintf("/sys/class/net/%s/address", nets[i]);

        if (exists(sysroot, rel))
        {
            struct rs_jval *iface = rs_jarr_add(net);
            char           *mac;

            rs_jval_set_object(iface);
            rs_jobj_str(iface, "name", nets[i]);
            mac = read_line(sysroot, arel);
            rs_jobj_str(iface, "mac", mac);
            free(mac);
        }
        free(rel);
        free(arel);
    }
    free_list(nets, nnet);
}

static void describe_firmware(const char *sysroot, const char *root, struct rs_jval *machine)
{
    struct rs_jval *fw = rs_jobj_add(machine, "firmware");
    bool            uefi = exists(sysroot, "/sys/firmware/efi");
    struct rs_jval *loaders;
    char          **efi;
    size_t          nefi;

    rs_jval_set_object(fw);
    rs_jobj_str(fw, "mode", uefi ? "uefi" : "bios");
    if (uefi)
    {
        char *path = path_join(sysroot, "/sys/firmware/efi/efivars/"
                                        "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        int   fd = open(path, O_RDONLY | O_CLOEXEC);

        free(path);
        if (fd >= 0)
        {
            unsigned char v[5];

            /* Four bytes of attributes, then the value. */
            if (read(fd, v, sizeof(v)) == (ssize_t)sizeof(v))
            {
                rs_jobj_bool(fw, "secure_boot", v[4] == 1);
            }
            (void)close(fd);
        }
    }
    loaders = rs_jobj_add(fw, "boot_loaders");
    rs_jval_set_array(loaders);
    if (exists(root, "/boot/grub/grub.cfg"))
    {
        rs_jval_set_string(rs_jarr_add(loaders), "grub");
    }
    if (exists(root, "/boot/efi/loader/loader.conf") || exists(root, "/efi/loader/loader.conf"))
    {
        rs_jval_set_string(rs_jarr_add(loaders), "systemd-boot");
    }
    /* What is installed on the EFI system partition: ubuntu, Microsoft, BOOT,
     * and so on -- which says, among other things, that this is dual boot. */
    efi = list_dir(root, "/boot/efi/EFI", &nefi);
    if (nefi > 0)
    {
        struct rs_jval *dirs = rs_jobj_add(fw, "efi_directories");
        size_t          i;

        rs_jval_set_array(dirs);
        for (i = 0; i < nefi; i++)
        {
            rs_jval_set_string(rs_jarr_add(dirs), efi[i]);
        }
    }
    free_list(efi, nefi);
}

/* Disks are what is left of /sys/block once the virtual devices are gone. */
static bool is_disk_name(const char *name)
{
    static const char *const virt[] = { "loop", "ram", "zram", "sr", "fd", "nbd", "md", "dm-" };
    size_t                   i;

    for (i = 0; i < sizeof(virt) / sizeof(virt[0]); i++)
    {
        if (rs_starts_with(name, virt[i]))
        {
            return false;
        }
    }
    return true;
}

static void holders(struct rs_jval *dev, const char *sysroot, const char *base)
{
    char  *rel = rs_xasprintf("%s/holders", base);
    char **names;
    size_t n;

    names = list_dir(sysroot, rel, &n);
    if (n > 0)
    {
        struct rs_jval *h = rs_jobj_add(dev, "holders");
        size_t          i;

        rs_jval_set_array(h);
        for (i = 0; i < n; i++)
        {
            rs_jval_set_string(rs_jarr_add(h), names[i]);
        }
    }
    free_list(names, n);
    free(rel);
}

/* The LUKS details of a device whose content is crypto_LUKS. */
static void luks_details(const char *sysroot, struct rs_jval *machine, struct rs_jval *dev,
                         const char *name)
{
    const struct rs_jval *content = rs_jobject_get(dev, "content");
    struct rs_jval        luks;

    if (!content || !rs_jobject_str(content, "type") ||
        strcmp(rs_jobject_str(content, "type"), "crypto_LUKS") != 0)
    {
        return;
    }
    memset(&luks, 0, sizeof(luks));
    if (read_luks(sysroot, name, &luks))
    {
        rs_jval_copy(rs_jobj_add(dev, "luks"), &luks);
    } else
    {
        char *msg = rs_xasprintf("%s: the LUKS header could not be read (it needs root), "
                                 "so its cipher and key size are not recorded", name);

        note(machine, msg);
        free(msg);
    }
    rs_jval_free(&luks);
}

static void describe_disks(const char *sysroot, struct rs_jval *machine)
{
    struct rs_jval *disks = rs_jobj_add(machine, "disks");
    char          **names;
    size_t          n;
    size_t          i;

    rs_jval_set_array(disks);
    names = list_dir(sysroot, "/sys/block", &n);
    for (i = 0; i < n; i++)
    {
        char           *base = rs_xasprintf("/sys/block/%s", names[i]);
        char           *rel;
        char           *devnum;
        char           *udev;
        char           *s;
        uint64_t        v;
        uint64_t        sectors = 0;
        struct rs_jval *disk;
        struct rs_jval *parts;
        char          **ents;
        size_t          nents;
        size_t          k;

        rel = rs_xasprintf("%s/size", base);
        if (!is_disk_name(names[i]) || !read_u64(sysroot, rel, &sectors) || sectors == 0)
        {
            free(rel);
            free(base);
            continue;
        }
        free(rel);
        disk = rs_jarr_add(disks);
        rs_jval_set_object(disk);
        rs_jobj_str(disk, "name", names[i]);
        /* sysfs counts in 512-byte units whatever the real sector size. */
        rs_jobj_u64(disk, "size", sectors * 512);
        rel = rs_xasprintf("%s/queue/logical_block_size", base);
        if (read_u64(sysroot, rel, &v))
        {
            rs_jobj_u64(disk, "logical_block_size", v);
        }
        free(rel);
        rel = rs_xasprintf("%s/queue/physical_block_size", base);
        if (read_u64(sysroot, rel, &v))
        {
            rs_jobj_u64(disk, "physical_block_size", v);
        }
        free(rel);
        rel = rs_xasprintf("%s/queue/rotational", base);
        if (read_u64(sysroot, rel, &v))
        {
            rs_jobj_bool(disk, "rotational", v != 0);
        }
        free(rel);
        rel = rs_xasprintf("%s/removable", base);
        if (read_u64(sysroot, rel, &v))
        {
            rs_jobj_bool(disk, "removable", v != 0);
        }
        free(rel);
        rel = rs_xasprintf("%s/dev", base);
        devnum = read_line(sysroot, rel);
        free(rel);
        udev = devnum ? udev_load(sysroot, devnum) : NULL;
        s = udev ? udev_get(udev, "ID_MODEL") : NULL;
        if (!s)
        {
            rel = rs_xasprintf("%s/device/model", base);
            s = read_line(sysroot, rel);
            free(rel);
        }
        rs_jobj_str(disk, "model", s);
        free(s);
        udev_member(disk, udev, "ID_SERIAL_SHORT", "serial");
        udev_member(disk, udev, "ID_WWN", "wwn");
        s = udev ? udev_get(udev, "ID_PART_TABLE_TYPE") : NULL;
        if (s)
        {
            struct rs_jval *table = rs_jobj_add(disk, "table");

            rs_jval_set_object(table);
            rs_jobj_str(table, "type", s);
            udev_member(table, udev, "ID_PART_TABLE_UUID", "uuid");
            free(s);
        } else
        {
            describe_content(disk, udev);
            luks_details(sysroot, machine, disk, names[i]);
            holders(disk, sysroot, base);
        }
        free(udev);
        free(devnum);

        parts = rs_jobj_add(disk, "partitions");
        rs_jval_set_array(parts);
        ents = list_dir(sysroot, base, &nents);
        for (k = 0; k < nents; k++)
        {
            char           *pbase = rs_xasprintf("%s/%s", base, ents[k]);
            char           *prel = rs_xasprintf("%s/partition", pbase);
            uint64_t        number;
            uint64_t        start = 0;
            uint64_t        size = 0;
            struct rs_jval *part;
            char           *pdev;
            char           *pudev;

            if (!read_u64(sysroot, prel, &number))
            {
                free(prel);
                free(pbase);
                continue;
            }
            free(prel);
            part = rs_jarr_add(parts);
            rs_jval_set_object(part);
            rs_jobj_str(part, "name", ents[k]);
            rs_jobj_u64(part, "number", number);
            prel = rs_xasprintf("%s/start", pbase);
            if (read_u64(sysroot, prel, &start))
            {
                rs_jobj_u64(part, "start", start * 512);
            }
            free(prel);
            prel = rs_xasprintf("%s/size", pbase);
            if (read_u64(sysroot, prel, &size))
            {
                rs_jobj_u64(part, "size", size * 512);
            }
            free(prel);
            prel = rs_xasprintf("%s/dev", pbase);
            pdev = read_line(sysroot, prel);
            free(prel);
            pudev = pdev ? udev_load(sysroot, pdev) : NULL;
            udev_member(part, pudev, "ID_PART_ENTRY_TYPE", "type");
            udev_member(part, pudev, "ID_PART_ENTRY_UUID", "uuid");
            udev_member(part, pudev, "ID_PART_ENTRY_NAME", "label");
            udev_member(part, pudev, "ID_PART_ENTRY_FLAGS", "flags");
            describe_content(part, pudev);
            luks_details(sysroot, machine, part, ents[k]);
            holders(part, sysroot, pbase);
            free(pudev);
            free(pdev);
            free(pbase);
        }
        free_list(ents, nents);
        free(base);
    }
    free_list(names, n);
}

static void slaves(struct rs_jval *dev, const char *sysroot, const char *base)
{
    char           *rel = rs_xasprintf("%s/slaves", base);
    char          **names;
    size_t          n;
    size_t          i;
    struct rs_jval *s = rs_jobj_add(dev, "devices");

    rs_jval_set_array(s);
    names = list_dir(sysroot, rel, &n);
    for (i = 0; i < n; i++)
    {
        rs_jval_set_string(rs_jarr_add(s), names[i]);
    }
    free_list(names, n);
    free(rel);
}

/* Device-mapper devices, and md RAID arrays. */
static void describe_virtual(const char *sysroot, struct rs_jval *machine)
{
    struct rs_jval *mapped = rs_jobj_add(machine, "mapped");
    struct rs_jval *raid;
    char          **names;
    size_t          n;
    size_t          i;

    rs_jval_set_array(mapped);
    names = list_dir(sysroot, "/sys/block", &n);
    for (i = 0; i < n; i++)
    {
        char           *base = rs_xasprintf("/sys/block/%s", names[i]);
        char           *rel;
        char           *s;
        char           *devnum;
        char           *udev;
        struct rs_jval *dev;

        if (!rs_starts_with(names[i], "dm-"))
        {
            free(base);
            continue;
        }
        dev = rs_jarr_add(mapped);
        rs_jval_set_object(dev);
        rs_jobj_str(dev, "device", names[i]);
        rel = rs_xasprintf("%s/dm/name", base);
        s = read_line(sysroot, rel);
        rs_jobj_str(dev, "name", s);
        free(s);
        free(rel);
        rel = rs_xasprintf("%s/dm/uuid", base);
        s = read_line(sysroot, rel);
        if (s && rs_starts_with(s, "CRYPT-LUKS"))
        {
            rs_jobj_str(dev, "kind", "luks");
        } else if (s && rs_starts_with(s, "CRYPT-"))
        {
            rs_jobj_str(dev, "kind", "crypt");
        } else if (s && rs_starts_with(s, "LVM-"))
        {
            rs_jobj_str(dev, "kind", "lvm");
        } else
        {
            rs_jobj_str(dev, "kind", "other");
        }
        rs_jobj_str(dev, "uuid", s);
        free(s);
        free(rel);
        slaves(dev, sysroot, base);
        rel = rs_xasprintf("%s/dev", base);
        devnum = read_line(sysroot, rel);
        free(rel);
        udev = devnum ? udev_load(sysroot, devnum) : NULL;
        describe_content(dev, udev);
        free(udev);
        free(devnum);
        free(base);
    }

    raid = rs_jobj_add(machine, "raid");
    rs_jval_set_array(raid);
    for (i = 0; i < n; i++)
    {
        char           *base = rs_xasprintf("/sys/block/%s", names[i]);
        char           *rel;
        char           *devnum;
        char           *udev;
        uint64_t        v;
        struct rs_jval *md;

        if (!rs_starts_with(names[i], "md"))
        {
            free(base);
            continue;
        }
        md = rs_jarr_add(raid);
        rs_jval_set_object(md);
        rs_jobj_str(md, "device", names[i]);
        rel = rs_xasprintf("%s/dev", base);
        devnum = read_line(sysroot, rel);
        free(rel);
        udev = devnum ? udev_load(sysroot, devnum) : NULL;
        udev_member(md, udev, "MD_LEVEL", "level");
        udev_member(md, udev, "MD_DEVICES", "raid_devices");
        udev_member(md, udev, "MD_METADATA", "metadata");
        udev_member(md, udev, "MD_UUID", "uuid");
        udev_member(md, udev, "MD_DEVNAME", "name");
        rel = rs_xasprintf("%s/md/chunk_size", base);
        if (read_u64(sysroot, rel, &v) && v > 0)
        {
            rs_jobj_u64(md, "chunk_size", v);
        }
        free(rel);
        slaves(md, sysroot, base);
        describe_content(md, udev);
        free(udev);
        free(devnum);
        free(base);
    }
    free_list(names, n);
}

static void describe_lvm(const char *root, struct rs_jval *machine)
{
    struct rs_jval *lvm = rs_jobj_add(machine, "lvm");
    char          **names;
    size_t          n;
    size_t          i;

    rs_jval_set_array(lvm);
    names = list_dir(root, "/etc/lvm/backup", &n);
    for (i = 0; i < n; i++)
    {
        char          *rel = rs_xasprintf("/etc/lvm/backup/%s", names[i]);
        char          *path = path_join(root, rel);
        char          *text = read_text(path);
        struct rs_jval parsed;
        struct rs_buf  err;

        memset(&parsed, 0, sizeof(parsed));
        rs_buf_init(&err);
        if (text && rs_lvm_parse(text, strlen(text), &parsed, &err))
        {
            struct rs_jval *vg = rs_jarr_add(lvm);

            rs_jval_set_object(vg);
            rs_jobj_str(vg, "name", names[i]);
            rs_jobj_str(vg, "file", rel);
            rs_jobj_str(vg, "metadata", text);
        } else if (text)
        {
            char *msg = rs_xasprintf("%s: not LVM metadata (%s)", rel, err.data);

            note(machine, msg);
            free(msg);
        }
        rs_jval_free(&parsed);
        rs_buf_free(&err);
        free(text);
        free(path);
        free(rel);
    }
    free_list(names, n);
}

/* Undo the octal escapes mountinfo and fstab use for spaces and the like. */
static char *unoctal(const char *s, size_t len)
{
    struct rs_buf b;
    size_t        i;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (i = 0; i < len; i++)
    {
        if (s[i] == '\\' && i + 3 < len &&
            s[i + 1] >= '0' && s[i + 1] <= '3' && s[i + 2] >= '0' && s[i + 2] <= '7' &&
            s[i + 3] >= '0' && s[i + 3] <= '7')
        {
            rs_buf_addc(&b, (char)(((s[i + 1] - '0') << 6) | ((s[i + 2] - '0') << 3) |
                                   (s[i + 3] - '0')));
            i += 3;
        } else
        {
            rs_buf_addc(&b, s[i]);
        }
    }
    return rs_buf_detach(&b);
}

/* Splits a line on runs of spaces and tabs into at most `max` fields. */
static size_t split_ws(const char *line, size_t len, const char **f, size_t *flen, size_t max)
{
    size_t n = 0;
    size_t i = 0;

    while (i < len && n < max)
    {
        while (i < len && (line[i] == ' ' || line[i] == '\t'))
        {
            i++;
        }
        if (i >= len)
        {
            break;
        }
        f[n] = line + i;
        while (i < len && line[i] != ' ' && line[i] != '\t')
        {
            i++;
        }
        flen[n] = (size_t)(line + i - f[n]);
        n++;
    }
    return n;
}

/* The filesystems that hold data, as opposed to the ones the kernel makes up. */
static bool persistent_fs(const char *type)
{
    static const char *const keep[] = { "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat",
                                        "ntfs", "ntfs3", "f2fs", "zfs", "jfs", "reiserfs",
                                        "nfs", "nfs4", "cifs", "smb3", "fuseblk" };
    size_t                   i;

    for (i = 0; i < sizeof(keep) / sizeof(keep[0]); i++)
    {
        if (strcmp(type, keep[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

/*
 * The size of a mounted filesystem and the space used on it: what a
 * replacement disk -- or a virtual one -- actually has to hold, which may be
 * a small part of the drive it lives on now. Network filesystems are skipped:
 * their space is the server's, and asking can hang on a server that is gone.
 */
static void usage(struct rs_jval *m, const char *mountpoint)
{
    struct statvfs sv;
    const char    *type = rs_jobject_str(m, "type");

    if (!mountpoint || (type && (rs_starts_with(type, "nfs") || strcmp(type, "cifs") == 0 ||
                                 strcmp(type, "smb3") == 0)))
    {
        return;
    }
    if (statvfs(mountpoint, &sv) == 0 && sv.f_frsize > 0)
    {
        uint64_t unit = (uint64_t)sv.f_frsize;

        rs_jobj_u64(m, "size", (uint64_t)sv.f_blocks * unit);
        rs_jobj_u64(m, "used", ((uint64_t)sv.f_blocks - (uint64_t)sv.f_bfree) * unit);
    }
}

static void describe_mounts(const char *sysroot, struct rs_jval *machine)
{
    struct rs_jval *mounts = rs_jobj_add(machine, "mounts");
    char           *path = path_join(sysroot, "/proc/self/mountinfo");
    char           *text = read_text(path);
    const char     *p = text;

    free(path);
    rs_jval_set_array(mounts);
    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      llen = nl ? (size_t)(nl - p) : strlen(p);
        const char *f[16];
        size_t      fl[16];
        size_t      nf = split_ws(p, llen, f, fl, 16);
        size_t      dash;

        /* id parent maj:min root mountpoint options [optional...] - type source super */
        for (dash = 6; dash < nf; dash++)
        {
            if (fl[dash] == 1 && f[dash][0] == '-')
            {
                break;
            }
        }
        if (nf >= 5 && dash + 2 < nf)
        {
            char *type = rs_xstrndup(f[dash + 1], fl[dash + 1]);

            if (persistent_fs(type))
            {
                struct rs_jval *m = rs_jarr_add(mounts);
                char           *s;

                rs_jval_set_object(m);
                s = unoctal(f[4], fl[4]);
                rs_jobj_str(m, "mountpoint", s);
                free(s);
                rs_jobj_str(m, "type", type);
                s = unoctal(f[dash + 2], fl[dash + 2]);
                rs_jobj_str(m, "source", s);
                free(s);
                s = rs_xstrndup(f[2], fl[2]);
                rs_jobj_str(m, "device", s);
                free(s);
                s = rs_xstrndup(f[5], fl[5]);
                rs_jobj_str(m, "options", s);
                free(s);
                usage(m, rs_jobject_str(m, "mountpoint"));
            }
            free(type);
        }
        p = nl ? nl + 1 : NULL;
    }
    free(text);
}

/* fstab and crypttab: whitespace-separated fields, '#' comments. */
static void describe_table(const char *root, const char *rel, const char *key,
                           const char *const *names, size_t nnames, struct rs_jval *machine)
{
    struct rs_jval *arr = rs_jobj_add(machine, key);
    char           *path = path_join(root, rel);
    char           *text = read_text(path);
    const char     *p = text;

    free(path);
    rs_jval_set_array(arr);
    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      llen = nl ? (size_t)(nl - p) : strlen(p);
        const char *f[8];
        size_t      fl[8];
        size_t      nf = split_ws(p, llen, f, fl, nnames);

        if (nf >= 2 && f[0][0] != '#')
        {
            struct rs_jval *row = rs_jarr_add(arr);
            size_t          k;

            rs_jval_set_object(row);
            for (k = 0; k < nf; k++)
            {
                char *s = unoctal(f[k], fl[k]);

                rs_jobj_str(row, names[k], s);
                free(s);
            }
        }
        p = nl ? nl + 1 : NULL;
    }
    free(text);
}

static void describe_swap(const char *sysroot, struct rs_jval *machine)
{
    struct rs_jval *swap = rs_jobj_add(machine, "swap");
    char           *path = path_join(sysroot, "/proc/swaps");
    char           *text = read_text(path);
    /* The first line is the column headings. */
    const char     *p = text ? strchr(text, '\n') : NULL;

    free(path);
    rs_jval_set_array(swap);
    if (p)
    {
        p++;
    }
    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      llen = nl ? (size_t)(nl - p) : strlen(p);
        const char *f[5];
        size_t      fl[5];

        if (split_ws(p, llen, f, fl, 5) >= 3)
        {
            struct rs_jval *s = rs_jarr_add(swap);
            char           *v;

            rs_jval_set_object(s);
            v = unoctal(f[0], fl[0]);
            rs_jobj_str(s, "file", v);
            free(v);
            v = rs_xstrndup(f[1], fl[1]);
            rs_jobj_str(s, "type", v);
            free(v);
            rs_jobj_u64(s, "size", (uint64_t)strtoull(f[2], NULL, 10) * 1024);
        }
        p = nl ? nl + 1 : NULL;
    }
    free(text);
}

void rs_machine_describe(const char *sysroot, const char *root, struct rs_jval *out)
{
    static const char *const fstab_names[] = { "spec", "file", "type", "options", "freq",
                                               "passno" };
    static const char *const crypttab_names[] = { "name", "device", "keyfile", "options" };

    rs_jval_set_object(out);
    rs_jval_set_array(rs_jobj_add(out, "notes"));
    describe_system(sysroot, root, out);
    describe_hardware(sysroot, out);
    if (!exists(sysroot, "/sys/block"))
    {
        /* Not Linux: ask the kernel the BSD way, where there is one to ask. */
        if (!rs_bsd_describe(out))
        {
            note(out, "no /sys/block: the disk layout is read on Linux and the BSDs, and this "
                      "is neither");
            return;
        }
        describe_table(root, "/etc/fstab", "fstab", fstab_names, 6, out);
        return;
    }
    describe_firmware(sysroot, root, out);
    describe_disks(sysroot, out);
    describe_virtual(sysroot, out);
    describe_lvm(root, out);
    describe_mounts(sysroot, out);
    describe_table(root, "/etc/fstab", "fstab", fstab_names, 6, out);
    describe_table(root, "/etc/crypttab", "crypttab", crypttab_names, 4, out);
    describe_swap(sysroot, out);
}
