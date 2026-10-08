/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "xattr.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/xattr.h>
#define RS_XATTR_NAMES 1
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/extattr.h>
#define RS_XATTR_EXTATTR 1
#endif

#include "util.h"

#define VALUE_MAX ((size_t)64 * 1024)
#define FILE_MAX  ((size_t)256 * 1024)
#define LIST_MAX  ((size_t)64 * 1024)

void rs_xattr_free(struct rs_xattr *x, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(x[i].name);
        free(x[i].value);
    }
    free(x);
}

bool rs_xattr_kept(const char *name)
{
    /* The target's policy and keys say what these are, not the image. */
    static const char *const machine[] = { "security.selinux", "security.SMACK64",
                                           "security.ima", "security.evm" };
    size_t                   i;

    if (name[0] == '\0')
    {
        return false;
    }
    for (i = 0; i < sizeof(machine) / sizeof(machine[0]); i++)
    {
        if (rs_starts_with(name, machine[i]))
        {
            return false;
        }
    }
    return true;
}

bool rs_xattr_is_acl(const char *name)
{
    return strcmp(name, "system.posix_acl_access") == 0 ||
           strcmp(name, "system.posix_acl_default") == 0;
}

#if defined(RS_XATTR_NAMES) || defined(RS_XATTR_EXTATTR)

/* Whether errno says this filesystem, or this system, has no attributes. */
static bool none_here(int err)
{
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    if (err == EOPNOTSUPP)
    {
        return true;
    }
#endif
    return err == ENOTSUP || err == ENOSYS;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct rs_xattr *)a)->name, ((const struct rs_xattr *)b)->name);
}

/* Appends one attribute; false if the file's total is already spent. */
static bool add(struct rs_xattr **out, size_t *n, size_t *total, const char *name,
                const void *value, size_t len)
{
    struct rs_xattr *x;

    if (len > VALUE_MAX || *total + len > FILE_MAX)
    {
        return false;
    }
    *out = rs_xreallocarray(*out, *n + 1, sizeof(**out));
    x = &(*out)[(*n)++];
    x->name = rs_xstrdup(name);
    x->value = rs_xmalloc(len ? len : 1);
    if (len)
    {
        memcpy(x->value, value, len);
    }
    x->len = len;
    *total += len;
    return true;
}

#endif

#if defined(RS_XATTR_NAMES)

static ssize_t list_names(int fd, char *buf, size_t n)
{
#if defined(__APPLE__)
    return flistxattr(fd, buf, n, 0);
#else
    return flistxattr(fd, buf, n);
#endif
}

static ssize_t get_value(int fd, const char *name, void *buf, size_t n)
{
#if defined(__APPLE__)
    return fgetxattr(fd, name, buf, n, 0, 0);
#else
    return fgetxattr(fd, name, buf, n);
#endif
}

static bool set_value(int fd, const char *name, const void *value, size_t n)
{
#if defined(__APPLE__)
    return fsetxattr(fd, name, value, n, 0, 0) == 0;
#else
    return fsetxattr(fd, name, value, n, 0) == 0;
#endif
}

bool rs_xattr_read(int fd, struct rs_xattr **out, size_t *n)
{
    char          *names = NULL;
    unsigned char *value = rs_xmalloc(VALUE_MAX);
    ssize_t        len = -1;
    size_t         total = 0;
    size_t         at;
    int            tries;

    *out = NULL;
    *n = 0;
    /* Sized, then read; an attribute added between the two is ERANGE, and
     * tried again. */
    for (tries = 0; tries < 3; tries++)
    {
        ssize_t want = list_names(fd, NULL, 0);

        if (want <= 0)
        {
            len = want;
            break;
        }
        if ((size_t)want > LIST_MAX)
        {
            want = (ssize_t)LIST_MAX;
        }
        free(names);
        names = rs_xmalloc((size_t)want + 1);
        len = list_names(fd, names, (size_t)want);
        if (len >= 0 || errno != ERANGE)
        {
            break;
        }
    }
    if (len < 0)
    {
        int saved = errno;

        free(names);
        free(value);
        errno = saved;
        return none_here(saved);
    }
    /* The names, each NUL-terminated, one after another. */
    for (at = 0; names != NULL && at < (size_t)len; at += strlen(names + at) + 1)
    {
        const char *name = names + at;
        ssize_t     got;

        names[len] = '\0';
        if (!rs_xattr_kept(name))
        {
            continue;
        }
        got = get_value(fd, name, value, VALUE_MAX);
        /* Removed since it was listed, or too large to keep: passed over. */
        if (got >= 0)
        {
            (void)add(out, n, &total, name, value, (size_t)got);
        }
    }
    free(names);
    free(value);
    if (*n > 1)
    {
        qsort(*out, *n, sizeof(**out), by_name);
    }
    return true;
}

size_t rs_xattr_write(int fd, const struct rs_xattr *x, size_t n)
{
    size_t i;
    size_t failed = 0;

    for (i = 0; i < n; i++)
    {
        if (!rs_xattr_kept(x[i].name) || !set_value(fd, x[i].name, x[i].value, x[i].len))
        {
            failed++;
        }
    }
    return failed;
}

#elif defined(RS_XATTR_EXTATTR)

static const struct {
    int         ns;
    const char *prefix;
} spaces[] = {
    { EXTATTR_NAMESPACE_USER,   "user." },
    { EXTATTR_NAMESPACE_SYSTEM, "system." },
};

bool rs_xattr_read(int fd, struct rs_xattr **out, size_t *n)
{
    unsigned char *list = rs_xmalloc(LIST_MAX);
    unsigned char *value = rs_xmalloc(VALUE_MAX);
    size_t         total = 0;
    size_t         s;

    *out = NULL;
    *n = 0;
    for (s = 0; s < sizeof(spaces) / sizeof(spaces[0]); s++)
    {
        ssize_t len = extattr_list_fd(fd, spaces[s].ns, list, LIST_MAX);
        size_t  at = 0;

        /* The system namespace is root's to read; a user reads none. */
        if (len < 0)
        {
            if (errno == EPERM || errno == EACCES || none_here(errno))
            {
                continue;
            }
            free(list);
            free(value);
            return false;
        }
        /* Each name is a length byte and that many bytes, no terminator. */
        while (at < (size_t)len)
        {
            size_t nlen = list[at];
            char  *name;

            if (at + 1 + nlen > (size_t)len)
            {
                break;
            }
            name = rs_xasprintf("%s%.*s", spaces[s].prefix, (int)nlen, (const char *)list + at + 1);
            if (rs_xattr_kept(name))
            {
                const char *bare = name + strlen(spaces[s].prefix);
                ssize_t     got = extattr_get_fd(fd, spaces[s].ns, bare, value, VALUE_MAX);
                if (got >= 0)
                {
                    (void)add(out, n, &total, name, value, (size_t)got);
                }
            }
            free(name);
            at += 1 + nlen;
        }
    }
    free(list);
    free(value);
    if (*n > 1)
    {
        qsort(*out, *n, sizeof(**out), by_name);
    }
    return true;
}

size_t rs_xattr_write(int fd, const struct rs_xattr *x, size_t n)
{
    size_t i;
    size_t failed = 0;

    for (i = 0; i < n; i++)
    {
        size_t s;
        bool   ok = false;

        for (s = 0; s < sizeof(spaces) / sizeof(spaces[0]) && !ok; s++)
        {
            if (rs_starts_with(x[i].name, spaces[s].prefix))
            {
                ok = rs_xattr_kept(x[i].name) &&
                     extattr_set_fd(fd, spaces[s].ns, x[i].name + strlen(spaces[s].prefix),
                                    x[i].value, x[i].len) >= 0;
            }
        }
        if (!ok)
        {
            failed++;
        }
    }
    return failed;
}

#else

/* No extended attributes on this system (OpenBSD): every file has none. */
bool rs_xattr_read(int fd, struct rs_xattr **out, size_t *n)
{
    (void)fd;
    *out = NULL;
    *n = 0;
    return true;
}

size_t rs_xattr_write(int fd, const struct rs_xattr *x, size_t n)
{
    (void)fd;
    (void)x;
    return n;
}

#endif

/* Little-endian, as Linux writes an ACL whatever the machine. */
static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void put_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

bool rs_xattr_map_acl(unsigned char *value, size_t len,
                      unsigned long (*uid)(const void *ctx, unsigned long id),
                      unsigned long (*gid)(const void *ctx, unsigned long id), const void *ctx)
{
    /* posix_acl_xattr_header, then posix_acl_xattr_entry: version 2, and
     * entries of a 16-bit tag, 16-bit permissions and a 32-bit id. */
    enum { HEADER = 4, ENTRY = 8, VERSION = 2, TAG_USER = 0x02, TAG_GROUP = 0x08 };
    size_t at;

    if (len < HEADER || (len - HEADER) % ENTRY != 0 || le32(value) != VERSION)
    {
        return false;
    }
    for (at = HEADER; at < len; at += ENTRY)
    {
        unsigned tag = (unsigned)value[at] | ((unsigned)value[at + 1] << 8);

        if (tag == TAG_USER)
        {
            put_le32(value + at + 4, (uint32_t)uid(ctx, le32(value + at + 4)));
        } else if (tag == TAG_GROUP)
        {
            put_le32(value + at + 4, (uint32_t)gid(ctx, le32(value + at + 4)));
        }
    }
    return true;
}
