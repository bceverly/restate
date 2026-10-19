/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "clones.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "identity.h"

/* Far more copies than one installer would be asked for. */
#define CLONES_MAX   4096
#define FILE_MAX     ((size_t)1024 * 1024)
#define SERIAL_MAX   64
#define DNS_MAX      8

enum column { COL_NAME, COL_MAC, COL_SERIAL, COL_ADDRESS, COL_GATEWAY, COL_DNS, COL_COUNT };

static const char *const columns[COL_COUNT] = { "name", "mac", "serial", "address", "gateway",
                                                "dns" };

void rs_clones_init(struct rs_clones *c)
{
    c->items = NULL;
    c->count = 0;
}

static void clone_free(struct rs_clone *k)
{
    size_t i;

    free(k->name);
    free(k->mac);
    free(k->serial);
    free(k->address);
    free(k->gateway);
    for (i = 0; i < k->ndns; i++)
    {
        free(k->dns[i]);
    }
    free(k->dns);
}

void rs_clones_free(struct rs_clones *c)
{
    size_t i;

    for (i = 0; i < c->count; i++)
    {
        clone_free(&c->items[i]);
    }
    free(c->items);
    rs_clones_init(c);
}

/* A hex digit's lowercase form, or '\0' if `c` is none. */
static char hex(char c)
{
    static const char digits[] = "0123456789abcdefABCDEF";
    const char       *at = c ? strchr(digits, c) : NULL;

    if (!at)
    {
        return '\0';
    }
    if (at - digits >= 16)
    {
        at -= 6;
    }
    return *at;
}

/* "52:54:00:12:34:56", or with hyphens; lowercase, with colons, in `out`. */
static bool mac_ok(const char *s, char out[18])
{
    size_t i;

    if (strlen(s) != 17)
    {
        return false;
    }
    for (i = 0; i < 17; i++)
    {
        if (i % 3 == 2)
        {
            if (s[i] != ':' && s[i] != '-')
            {
                return false;
            }
            out[i] = ':';
        } else
        {
            out[i] = hex(s[i]);
            if (out[i] == '\0')
            {
                return false;
            }
        }
    }
    out[17] = '\0';
    return true;
}

static bool serial_ok(const char *s)
{
    size_t len = strlen(s);

    return len > 0 && len <= SERIAL_MAX &&
           strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") == len;
}

/* An IPv4 or IPv6 address; *v6 says which. */
static bool ip_ok(const char *s, bool *v6)
{
    unsigned char buf[sizeof(struct in6_addr)];

    if (strlen(s) > 45)
    {
        return false;
    }
    *v6 = strchr(s, ':') != NULL;
    return inet_pton(*v6 ? AF_INET6 : AF_INET, s, buf) == 1;
}

/* address/prefix, the prefix in range for the family. */
static bool cidr_ok(const char *s)
{
    const char *slash = strchr(s, '/');
    char       *ip;
    bool        v6 = false;
    bool        ok;
    size_t      plen;
    unsigned    prefix = 0;
    size_t      i;

    if (!slash)
    {
        return false;
    }
    plen = strlen(slash + 1);
    if (plen == 0 || plen > 3 || strspn(slash + 1, "0123456789") != plen ||
        (plen > 1 && slash[1] == '0'))
    {
        return false;
    }
    for (i = 0; i < plen; i++)
    {
        prefix = prefix * 10 + (unsigned)(slash[1 + i] - '0');
    }
    ip = rs_xstrndup(s, (size_t)(slash - s));
    ok = ip_ok(ip, &v6) && prefix >= 1 && prefix <= (v6 ? 128u : 32u);
    free(ip);
    return ok;
}

static bool blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

/* One field, trimmed, into a new string. */
static char *field(const char *s, size_t len)
{
    while (len > 0 && blank(*s))
    {
        s++;
        len--;
    }
    while (len > 0 && blank(s[len - 1]))
    {
        len--;
    }
    return rs_xstrndup(s, len);
}

/* A line split at its commas: NULL, with *why set, if it holds a quote or
 * a NUL. */
static char **split(const char *s, size_t len, size_t *n, const char **why)
{
    char **out = NULL;
    size_t start = 0;
    size_t i;

    *n = 0;
    for (i = 0; i <= len; i++)
    {
        if (i < len && (s[i] == '"' || s[i] == '\'' || s[i] == '\0'))
        {
            size_t k;

            *why = s[i] == '\0' ? "a NUL byte; this is not a CSV file"
                                : "a quote: nothing in this file needs one, and none is read";
            for (k = 0; k < *n; k++)
            {
                free(out[k]);
            }
            free(out);
            return NULL;
        }
        if (i == len || s[i] == ',')
        {
            out = rs_xreallocarray(out, *n + 1, sizeof(*out));
            out[(*n)++] = field(s + start, i - start);
            start = i + 1;
        }
    }
    return out;
}

static void free_fields(char **f, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(f[i]);
    }
    free(f);
}

/* The header: which column each field is. */
static bool header(char **f, size_t n, int *which, const char **why)
{
    bool   seen[COL_COUNT];
    size_t i;
    int    k;

    memset(seen, 0, sizeof(seen));
    for (i = 0; i < n; i++)
    {
        which[i] = -1;
        for (k = 0; k < COL_COUNT; k++)
        {
            if (strcmp(f[i], columns[k]) == 0 || (k == COL_NAME && strcmp(f[i], "hostname") == 0))
            {
                which[i] = k;
            }
        }
        if (which[i] < 0)
        {
            *why = "a column that is not name, mac, serial, address, gateway or dns";
            return false;
        }
        if (seen[which[i]])
        {
            *why = "a column named twice";
            return false;
        }
        seen[which[i]] = true;
    }
    if (!seen[COL_NAME] || (!seen[COL_MAC] && !seen[COL_SERIAL]))
    {
        *why = "the header needs a name column, and a mac or serial column to find each copy by";
        return false;
    }
    return true;
}

/* Name servers, separated by spaces or semicolons. */
static bool name_servers(struct rs_clone *k, const char *s, const char **why)
{
    const char *p = s;

    while (*p)
    {
        size_t len;
        char  *ip;
        bool   v6;

        p += strspn(p, " ;\t");
        len = strcspn(p, " ;\t");
        if (len == 0)
        {
            break;
        }
        ip = rs_xstrndup(p, len);
        if (!ip_ok(ip, &v6) || k->ndns == DNS_MAX)
        {
            *why = k->ndns == DNS_MAX ? "more name servers than a copy needs"
                                      : "a name server that is not an IP address";
            free(ip);
            return false;
        }
        k->dns = rs_xreallocarray(k->dns, k->ndns + 1, sizeof(*k->dns));
        k->dns[k->ndns++] = ip;
        p += len;
    }
    return true;
}

/* One copy's fields, checked. */
static bool row(struct rs_clone *k, char **f, size_t n, const int *which, const char **why)
{
    char   mac[18];
    bool   v6;
    size_t i;

    memset(k, 0, sizeof(*k));
    for (i = 0; i < n; i++)
    {
        const char *v = f[i];

        if (v[0] == '\0')
        {
            continue;
        }
        switch (which[i])
        {
        case COL_NAME:
            if (!rs_identity_name_ok(v))
            {
                *why = "a name that is not a host name";
                return false;
            }
            k->name = rs_xstrdup(v);
            break;
        case COL_MAC:
            if (!mac_ok(v, mac))
            {
                *why = "a MAC address that is not six pairs of hex digits";
                return false;
            }
            k->mac = rs_xstrdup(mac);
            break;
        case COL_SERIAL:
            if (!serial_ok(v))
            {
                *why = "a disk serial of other than letters, digits, '.', '_' and '-'";
                return false;
            }
            k->serial = rs_xstrdup(v);
            break;
        case COL_ADDRESS:
            if (!cidr_ok(v))
            {
                *why = "an address that is not ADDRESS/PREFIX (10.0.0.11/24, fd00::11/64)";
                return false;
            }
            k->address = rs_xstrdup(v);
            break;
        case COL_GATEWAY:
            if (!ip_ok(v, &v6))
            {
                *why = "a gateway that is not an IP address";
                return false;
            }
            k->gateway = rs_xstrdup(v);
            break;
        default:
            if (!name_servers(k, v, why))
            {
                return false;
            }
            break;
        }
    }
    if (!k->name)
    {
        *why = "a copy with no name";
        return false;
    }
    if (!k->mac && !k->serial)
    {
        *why = "a copy with neither a MAC address nor a disk serial to find it by";
        return false;
    }
    if (k->gateway && !k->address)
    {
        *why = "a gateway with no address: a copy on DHCP is given its route";
        return false;
    }
    return true;
}

static bool same(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

/* Whether copy `k` repeats any copy before it, and in what. */
static const char *repeated(const struct rs_clones *c, const struct rs_clone *k)
{
    size_t i;
    size_t alen = k->address ? strcspn(k->address, "/") : 0;

    for (i = 0; i < c->count; i++)
    {
        const struct rs_clone *o = &c->items[i];

        if (same(o->name, k->name))
        {
            return "a name given to another copy already";
        }
        if (same(o->mac, k->mac))
        {
            return "a MAC address given to another copy already";
        }
        if (same(o->serial, k->serial))
        {
            return "a disk serial given to another copy already";
        }
        if (o->address && k->address && strcspn(o->address, "/") == alen &&
            strncmp(o->address, k->address, alen) == 0)
        {
            return "an address given to another copy already";
        }
    }
    return NULL;
}

bool rs_clones_parse(struct rs_clones *c, const char *text, size_t len, const char *name,
                     struct rs_buf *err)
{
    size_t      pos = 0;
    size_t      lineno = 0;
    int         which[COL_COUNT];
    size_t      ncols = 0;
    const char *why = NULL;

    rs_clones_init(c);
    while (pos < len && !why)
    {
        size_t end = pos;
        size_t start = pos;
        char **f;
        size_t n;

        lineno++;
        while (end < len && text[end] != '\n')
        {
            end++;
        }
        pos = end + 1;
        while (start < end && blank(text[start]))
        {
            start++;
        }
        if (start == end || text[start] == '#')
        {
            continue;
        }
        f = split(text + start, end - start, &n, &why);
        if (!f)
        {
            break;
        }
        if (ncols == 0)
        {
            if (n > COL_COUNT)
            {
                why = "more columns than name, mac, serial, address, gateway and dns";
            } else if (header(f, n, which, &why))
            {
                ncols = n;
            }
        } else if (n != ncols)
        {
            why = "a different number of fields from the header";
        } else if (c->count == CLONES_MAX)
        {
            why = "more copies than one installer is for";
        } else
        {
            struct rs_clone k;

            if (row(&k, f, n, which, &why))
            {
                why = repeated(c, &k);
            }
            if (!why)
            {
                c->items = rs_xreallocarray(c->items, c->count + 1, sizeof(*c->items));
                c->items[c->count++] = k;
            } else
            {
                clone_free(&k);
            }
        }
        free_fields(f, n);
    }
    if (!why && c->count == 0)
    {
        why = ncols ? "no copies, only the header" : "no header, and no copies";
        lineno = 0;
    }
    if (why)
    {
        if (lineno > 0)
        {
            rs_buf_addf(err, "%s:%zu: %s", name, lineno, why);
        } else
        {
            rs_buf_addf(err, "%s: %s", name, why);
        }
        rs_clones_free(c);
        return false;
    }
    return true;
}

bool rs_clones_load_file(struct rs_clones *c, const char *path, struct rs_buf *err)
{
    struct rs_buf text;
    struct stat   st;
    char          chunk[8192];
    int           fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    bool          ok;

    rs_clones_init(c);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        rs_buf_addf(err, "%s: not a regular file", path);
        (void)close(fd);
        return false;
    }
    rs_buf_init(&text);
    rs_buf_add(&text, "", 0);
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n < 0)
        {
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            rs_buf_free(&text);
            (void)close(fd);
            return false;
        }
        if (n == 0)
        {
            break;
        }
        rs_buf_add(&text, chunk, (size_t)n);
        if (text.len > FILE_MAX)
        {
            rs_buf_addf(err, "%s: larger than %zu bytes; is this really a list of copies?", path,
                        FILE_MAX);
            rs_buf_free(&text);
            (void)close(fd);
            return false;
        }
    }
    (void)close(fd);
    ok = rs_clones_parse(c, text.data, text.len, path, err);
    rs_buf_free(&text);
    return ok;
}
