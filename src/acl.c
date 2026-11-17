/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "acl.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__NetBSD__)
#include <sys/param.h>
#endif

#if defined(__FreeBSD__) || (defined(__NetBSD__) && __NetBSD_Version__ >= 1000000000)
#include <sys/acl.h>
#define RS_ACL_NFS4 1
#elif defined(__APPLE__)
#include <membership.h>
#include <sys/acl.h>
#include <uuid/uuid.h>
#define RS_ACL_DARWIN 1
#endif

#include "json.h"
#include "meta.h"

/* Restate's names, and its bits; each system's own are below. */
static const struct {
    const char *name;
    unsigned    bit;
} perm_names[] = {
    { "read_data", RS_ACE_READ_DATA },
    { "write_data", RS_ACE_WRITE_DATA },
    { "append_data", RS_ACE_APPEND_DATA },
    { "read_xattr", RS_ACE_READ_XATTR },
    { "write_xattr", RS_ACE_WRITE_XATTR },
    { "execute", RS_ACE_EXECUTE },
    { "delete_child", RS_ACE_DELETE_CHILD },
    { "read_attributes", RS_ACE_READ_ATTRIBUTES },
    { "write_attributes", RS_ACE_WRITE_ATTRIBUTES },
    { "delete", RS_ACE_DELETE },
    { "read_acl", RS_ACE_READ_ACL },
    { "write_acl", RS_ACE_WRITE_ACL },
    { "write_owner", RS_ACE_WRITE_OWNER },
    { "synchronize", RS_ACE_SYNCHRONIZE },
};

static const struct {
    const char *name;
    unsigned    bit;
} flag_names[] = {
    { "file_inherit", RS_ACE_FILE_INHERIT },
    { "dir_inherit", RS_ACE_DIR_INHERIT },
    { "inherit_only", RS_ACE_INHERIT_ONLY },
    { "no_propagate", RS_ACE_NO_PROPAGATE },
    { "successful_access", RS_ACE_SUCCESSFUL_ACCESS },
    { "failed_access", RS_ACE_FAILED_ACCESS },
    { "inherited", RS_ACE_INHERITED },
};

static const char *const type_names[] = { "allow", "deny", "audit", "alarm" };

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

void rs_acl_free(struct rs_ace *aces, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free(aces[i].name);
        free(aces[i].uuid);
    }
    free(aces);
}

/* A name that reads back as itself: UTF-8, none of the text's separators,
 * nothing unprintable. */
static bool plain_name(const char *s)
{
    const unsigned char *p;

    if (s == NULL || *s == '\0' || !rs_utf8_valid(s, strlen(s)))
    {
        return false;
    }
    for (p = (const unsigned char *)s; *p; p++)
    {
        if (*p <= ' ' || *p == ':' || *p == ',' || *p == '=' || *p == '/' || *p == 0x7f)
        {
            return false;
        }
    }
    return true;
}

static void put_names(struct rs_buf *out, unsigned bits, size_t n, const char *const *names,
                      const unsigned *values)
{
    size_t i;
    bool   first = true;

    for (i = 0; i < n; i++)
    {
        if (bits & values[i])
        {
            if (!first)
            {
                rs_buf_addc(out, '/');
            }
            rs_buf_addstr(out, names[i]);
            first = false;
        }
    }
}

void rs_acl_format(const struct rs_ace *aces, size_t n, struct rs_buf *out)
{
    const char *pn[COUNT(perm_names)];
    unsigned    pv[COUNT(perm_names)];
    const char *fn[COUNT(flag_names)];
    unsigned    fv[COUNT(flag_names)];
    size_t      i;

    for (i = 0; i < COUNT(perm_names); i++)
    {
        pn[i] = perm_names[i].name;
        pv[i] = perm_names[i].bit;
    }
    for (i = 0; i < COUNT(flag_names); i++)
    {
        fn[i] = flag_names[i].name;
        fv[i] = flag_names[i].bit;
    }
    for (i = 0; i < n; i++)
    {
        const struct rs_ace *a = &aces[i];

        if (i > 0)
        {
            rs_buf_addc(out, ',');
        }
        switch (a->tag)
        {
        case RS_ACE_OWNER:
            rs_buf_addstr(out, "owner@:");
            break;
        case RS_ACE_GROUP_OBJ:
            rs_buf_addstr(out, "group@:");
            break;
        case RS_ACE_EVERYONE:
            rs_buf_addstr(out, "everyone@:");
            break;
        case RS_ACE_USER:
        case RS_ACE_GROUP:
            rs_buf_addstr(out, a->tag == RS_ACE_USER ? "user:" : "group:");
            if (plain_name(a->name))
            {
                rs_buf_addstr(out, a->name);
            }
            rs_buf_addf(out, "=%llu", (unsigned long long)a->id);
            break;
        case RS_ACE_UUID:
            rs_buf_addstr(out, "uuid:");
            rs_buf_addstr(out, a->uuid ? a->uuid : "");
            break;
        }
        rs_buf_addc(out, ':');
        put_names(out, a->perms, COUNT(perm_names), pn, pv);
        rs_buf_addc(out, ':');
        put_names(out, a->flags, COUNT(flag_names), fn, fv);
        rs_buf_addc(out, ':');
        rs_buf_addstr(out, (size_t)a->type < COUNT(type_names) ? type_names[a->type] : "allow");
    }
}

/* The '/'-separated names in [p, end) as bits; false for one not known. */
static bool parse_names(const char *p, const char *end, size_t n, const char *const *names,
                        const unsigned *values, unsigned *bits)
{
    *bits = 0;
    while (p < end)
    {
        const char *slash = memchr(p, '/', (size_t)(end - p));
        size_t      len = slash ? (size_t)(slash - p) : (size_t)(end - p);
        size_t      i;
        bool        known = false;

        for (i = 0; i < n; i++)
        {
            if (strlen(names[i]) == len && strncmp(names[i], p, len) == 0)
            {
                *bits |= values[i];
                known = true;
            }
        }
        if (!known)
        {
            return false;
        }
        p = slash ? slash + 1 : end;
    }
    return true;
}

/* One entry, [p, end), into `a`. */
static bool parse_one(const char *p, const char *end, struct rs_ace *a)
{
    const char *field[5];
    size_t      len[5];
    const char *pn[COUNT(perm_names)];
    unsigned    pv[COUNT(perm_names)];
    const char *fn[COUNT(flag_names)];
    unsigned    fv[COUNT(flag_names)];
    size_t      i;

    memset(a, 0, sizeof(*a));
    for (i = 0; i < 5; i++)
    {
        const char *colon = i < 4 ? memchr(p, ':', (size_t)(end - p)) : NULL;

        if (i < 4 && colon == NULL)
        {
            return false;
        }
        field[i] = p;
        len[i] = colon ? (size_t)(colon - p) : (size_t)(end - p);
        p = colon ? colon + 1 : end;
    }
    if (memchr(field[4], ':', len[4]) != NULL)
    {
        return false;
    }
#define IS(k, s) (len[k] == strlen(s) && strncmp(field[k], s, len[k]) == 0)
    if (IS(0, "owner@") || IS(0, "group@") || IS(0, "everyone@"))
    {
        if (len[1] != 0)
        {
            return false;
        }
        a->tag = IS(0, "owner@") ? RS_ACE_OWNER : IS(0, "group@") ? RS_ACE_GROUP_OBJ
                                                                   : RS_ACE_EVERYONE;
    } else if (IS(0, "user") || IS(0, "group"))
    {
        const char *eq = memchr(field[1], '=', len[1]);
        const char *num;
        char       *stop;
        char       *digits;

        if (eq == NULL || eq + 1 == field[1] + len[1])
        {
            return false;
        }
        num = eq + 1;
        for (i = 0; num + i < field[1] + len[1]; i++)
        {
            if (num[i] < '0' || num[i] > '9')
            {
                return false;
            }
        }
        digits = rs_xstrndup(num, (size_t)(field[1] + len[1] - num));
        errno = 0;
        a->id = (uint64_t)strtoull(digits, &stop, 10);
        free(digits);
        if (errno != 0)
        {
            return false;
        }
        a->tag = IS(0, "user") ? RS_ACE_USER : RS_ACE_GROUP;
        if (eq > field[1])
        {
            a->name = rs_xstrndup(field[1], (size_t)(eq - field[1]));
        }
    } else if (IS(0, "uuid"))
    {
        if (len[1] == 0)
        {
            return false;
        }
        a->tag = RS_ACE_UUID;
        a->uuid = rs_xstrndup(field[1], len[1]);
    } else
    {
        return false;
    }
    for (i = 0; i < COUNT(perm_names); i++)
    {
        pn[i] = perm_names[i].name;
        pv[i] = perm_names[i].bit;
    }
    for (i = 0; i < COUNT(flag_names); i++)
    {
        fn[i] = flag_names[i].name;
        fv[i] = flag_names[i].bit;
    }
    if (!parse_names(field[2], field[2] + len[2], COUNT(perm_names), pn, pv, &a->perms) ||
        !parse_names(field[3], field[3] + len[3], COUNT(flag_names), fn, fv, &a->flags))
    {
        return false;
    }
    for (i = 0; i < COUNT(type_names); i++)
    {
        if (IS(4, type_names[i]))
        {
            a->type = (enum rs_ace_type)i;
            return true;
        }
    }
#undef IS
    return false;
}

bool rs_acl_parse(const char *text, struct rs_ace **out, size_t *n)
{
    const char *p = text;

    *out = NULL;
    *n = 0;
    if (text == NULL || *text == '\0')
    {
        return false;
    }
    for (;;)
    {
        const char   *comma = strchr(p, ',');
        const char   *end = comma ? comma : p + strlen(p);
        struct rs_ace a;

        if (!parse_one(p, end, &a))
        {
            free(a.name);
            free(a.uuid);
            rs_acl_free(*out, *n);
            *out = NULL;
            *n = 0;
            return false;
        }
        *out = rs_xreallocarray(*out, *n + 1, sizeof(**out));
        (*out)[(*n)++] = a;
        if (comma == NULL)
        {
            return true;
        }
        p = comma + 1;
    }
}

/* The tests' ACLs, by file, while they pretend. */
struct pretended {
    dev_t dev;
    ino_t ino;
    char *text;
};

static bool              pretending;
static struct pretended *pretended;
static size_t            npretended;

void rs_acl_pretend(bool on)
{
    size_t i;

    for (i = 0; i < npretended; i++)
    {
        free(pretended[i].text);
    }
    free(pretended);
    pretended = NULL;
    npretended = 0;
    pretending = on;
}

static struct pretended *pretended_of(int fd, bool make)
{
    struct stat st;
    size_t      i;

    if (fstat(fd, &st) != 0)
    {
        return NULL;
    }
    for (i = 0; i < npretended; i++)
    {
        if (pretended[i].dev == st.st_dev && pretended[i].ino == st.st_ino)
        {
            return &pretended[i];
        }
    }
    if (!make)
    {
        return NULL;
    }
    pretended = rs_xreallocarray(pretended, npretended + 1, sizeof(*pretended));
    pretended[npretended].dev = st.st_dev;
    pretended[npretended].ino = st.st_ino;
    pretended[npretended].text = NULL;
    return &pretended[npretended++];
}

bool rs_acl_supported(void)
{
#if defined(RS_ACL_NFS4) || defined(RS_ACL_DARWIN)
    return true;
#else
    return pretending;
#endif
}

/* The entries' users and groups through `map`. */
static void map_ids(struct rs_ace *aces, size_t n,
                    void (*map)(const void *ctx, bool group, const char *name, uint64_t *id),
                    const void *ctx)
{
    size_t i;

    for (i = 0; map != NULL && i < n; i++)
    {
        if (aces[i].tag == RS_ACE_USER || aces[i].tag == RS_ACE_GROUP)
        {
            map(ctx, aces[i].tag == RS_ACE_GROUP, aces[i].name, &aces[i].id);
        }
    }
}

#if defined(RS_ACL_NFS4) || defined(RS_ACL_DARWIN)
/* The name each user and group has here, for the text. */
static void name_ids(struct rs_ace *aces, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        const char *name = NULL;

        if (aces[i].tag == RS_ACE_USER)
        {
            name = rs_user_name(aces[i].id);
        } else if (aces[i].tag == RS_ACE_GROUP)
        {
            name = rs_group_name(aces[i].id);
        }
        free(aces[i].name);
        aces[i].name = name ? rs_xstrdup(name) : NULL;
    }
}

#endif

/* Hands back the text of `aces`, which it frees. */
static char *text_of(struct rs_ace *aces, size_t n)
{
    struct rs_buf b;

    rs_buf_init(&b);
    rs_acl_format(aces, n, &b);
    rs_acl_free(aces, n);
    return rs_buf_detach(&b);
}

#if defined(RS_ACL_NFS4)

static const struct {
    unsigned   ours;
    acl_perm_t native;
} perms[] = {
    { RS_ACE_READ_DATA, ACL_READ_DATA },
    { RS_ACE_WRITE_DATA, ACL_WRITE_DATA },
    { RS_ACE_APPEND_DATA, ACL_APPEND_DATA },
    { RS_ACE_READ_XATTR, ACL_READ_NAMED_ATTRS },
    { RS_ACE_WRITE_XATTR, ACL_WRITE_NAMED_ATTRS },
    { RS_ACE_EXECUTE, ACL_EXECUTE },
    { RS_ACE_DELETE_CHILD, ACL_DELETE_CHILD },
    { RS_ACE_READ_ATTRIBUTES, ACL_READ_ATTRIBUTES },
    { RS_ACE_WRITE_ATTRIBUTES, ACL_WRITE_ATTRIBUTES },
    { RS_ACE_DELETE, ACL_DELETE },
    { RS_ACE_READ_ACL, ACL_READ_ACL },
    { RS_ACE_WRITE_ACL, ACL_WRITE_ACL },
    { RS_ACE_WRITE_OWNER, ACL_WRITE_OWNER },
    { RS_ACE_SYNCHRONIZE, ACL_SYNCHRONIZE },
};

static const struct {
    unsigned   ours;
    acl_flag_t native;
} flags[] = {
    { RS_ACE_FILE_INHERIT, ACL_ENTRY_FILE_INHERIT },
    { RS_ACE_DIR_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT },
    { RS_ACE_INHERIT_ONLY, ACL_ENTRY_INHERIT_ONLY },
    { RS_ACE_NO_PROPAGATE, ACL_ENTRY_NO_PROPAGATE_INHERIT },
    { RS_ACE_SUCCESSFUL_ACCESS, ACL_ENTRY_SUCCESSFUL_ACCESS },
    { RS_ACE_FAILED_ACCESS, ACL_ENTRY_FAILED_ACCESS },
    { RS_ACE_INHERITED, ACL_ENTRY_INHERITED },
};

static const acl_entry_type_t types[] = { ACL_ENTRY_TYPE_ALLOW, ACL_ENTRY_TYPE_DENY,
                                          ACL_ENTRY_TYPE_AUDIT, ACL_ENTRY_TYPE_ALARM };

/* Whether the filesystem `fd` is on holds NFSv4 ACLs. */
static bool nfs4_here(int fd)
{
    return fpathconf(fd, _PC_ACL_NFS4) > 0;
}

/* One native entry as restate's; false for one it has no words for. */
static bool from_native(acl_entry_t ent, struct rs_ace *a)
{
    acl_tag_t        tag;
    acl_entry_type_t et;
    acl_permset_t    ps;
    acl_flagset_t    fs;
    size_t           i;

    memset(a, 0, sizeof(*a));
    if (acl_get_tag_type(ent, &tag) != 0 || acl_get_entry_type_np(ent, &et) != 0 ||
        acl_get_permset(ent, &ps) != 0 || acl_get_flagset_np(ent, &fs) != 0)
    {
        return false;
    }
    switch (tag)
    {
    case ACL_USER_OBJ:
        a->tag = RS_ACE_OWNER;
        break;
    case ACL_GROUP_OBJ:
        a->tag = RS_ACE_GROUP_OBJ;
        break;
    case ACL_EVERYONE:
        a->tag = RS_ACE_EVERYONE;
        break;
    case ACL_USER:
    case ACL_GROUP:
    {
        uid_t *q = acl_get_qualifier(ent);

        if (q == NULL)
        {
            return false;
        }
        a->tag = tag == ACL_USER ? RS_ACE_USER : RS_ACE_GROUP;
        a->id = (uint64_t)*q;
        (void)acl_free(q);
        break;
    }
    default:
        return false;
    }
    for (i = 0; i < COUNT(perms); i++)
    {
        if (acl_get_perm_np(ps, perms[i].native) == 1)
        {
            a->perms |= perms[i].ours;
        }
    }
    for (i = 0; i < COUNT(flags); i++)
    {
        if (acl_get_flag_np(fs, flags[i].native) == 1)
        {
            a->flags |= flags[i].ours;
        }
    }
    for (i = 0; i < COUNT(types); i++)
    {
        if (types[i] == et)
        {
            a->type = (enum rs_ace_type)i;
            return true;
        }
    }
    return false;
}

static bool read_native(int fd, char **out)
{
    acl_t          acl;
    acl_entry_t    ent;
    int            trivial = 0;
    int            which = ACL_FIRST_ENTRY;
    struct rs_ace *aces = NULL;
    size_t         n = 0;

    if (!nfs4_here(fd))
    {
        return true;
    }
    acl = acl_get_fd_np(fd, ACL_TYPE_NFS4);
    if (acl == NULL)
    {
        return errno == EINVAL || errno == EOPNOTSUPP;
    }
    if (acl_is_trivial_np(acl, &trivial) == 0 && trivial)
    {
        (void)acl_free(acl);
        return true;
    }
    while (acl_get_entry(acl, which, &ent) == 1)
    {
        struct rs_ace a;

        which = ACL_NEXT_ENTRY;
        if (!from_native(ent, &a))
        {
            rs_acl_free(aces, n);
            (void)acl_free(acl);
            errno = EINVAL;
            return false;
        }
        aces = rs_xreallocarray(aces, n + 1, sizeof(*aces));
        aces[n++] = a;
    }
    (void)acl_free(acl);
    if (n > 0)
    {
        name_ids(aces, n);
        *out = text_of(aces, n);
    }
    return true;
}

/* One of restate's entries, appended to `acl`. */
static bool to_native(acl_t *acl, const struct rs_ace *a)
{
    acl_entry_t   ent;
    acl_permset_t ps;
    acl_flagset_t fs;
    acl_tag_t     tag;
    size_t        i;

    switch (a->tag)
    {
    case RS_ACE_OWNER:
        tag = ACL_USER_OBJ;
        break;
    case RS_ACE_GROUP_OBJ:
        tag = ACL_GROUP_OBJ;
        break;
    case RS_ACE_EVERYONE:
        tag = ACL_EVERYONE;
        break;
    case RS_ACE_USER:
        tag = ACL_USER;
        break;
    case RS_ACE_GROUP:
        tag = ACL_GROUP;
        break;
    default:
        errno = ENOTSUP;   /* a macOS identity: nothing here stands for it */
        return false;
    }
    if (acl_create_entry(acl, &ent) != 0 || acl_set_tag_type(ent, tag) != 0)
    {
        return false;
    }
    if (tag == ACL_USER || tag == ACL_GROUP)
    {
        uid_t q = (uid_t)a->id;

        if (acl_set_qualifier(ent, &q) != 0)
        {
            return false;
        }
    }
    if (acl_set_entry_type_np(ent, types[a->type]) != 0 || acl_get_flagset_np(ent, &fs) != 0 ||
        acl_clear_flags_np(fs) != 0 || acl_get_permset(ent, &ps) != 0 || acl_clear_perms(ps) != 0)
    {
        return false;
    }
    for (i = 0; i < COUNT(flags); i++)
    {
        if ((a->flags & flags[i].ours) && acl_add_flag_np(fs, flags[i].native) != 0)
        {
            return false;
        }
    }
    for (i = 0; i < COUNT(perms); i++)
    {
        if ((a->perms & perms[i].ours) && acl_add_perm(ps, perms[i].native) != 0)
        {
            return false;
        }
    }
    return acl_set_flagset_np(ent, fs) == 0 && acl_set_permset(ent, ps) == 0;
}

static int set_native(int fd, const struct rs_ace *aces, size_t n)
{
    acl_t acl;
    int   rc;

    if (!nfs4_here(fd))
    {
        if (n == 0)
        {
            return 0;
        }
        errno = ENOTSUP;
        return -1;
    }
    if (n == 0)
    {
        /* None beyond the mode: whatever the file has, or was given by its
         * directory as it was made, stripped back to what its mode says. */
        acl_t now = acl_get_fd_np(fd, ACL_TYPE_NFS4);
        int   trivial = 1;

        if (now == NULL)
        {
            return 0;
        }
        if (acl_is_trivial_np(now, &trivial) != 0 || trivial)
        {
            (void)acl_free(now);
            return 0;
        }
        acl = acl_strip_np(now, 0);
        (void)acl_free(now);
        if (acl == NULL)
        {
            return -1;
        }
    } else
    {
        size_t i;

        acl = acl_init((int)n);
        if (acl == NULL)
        {
            return -1;
        }
        for (i = 0; i < n; i++)
        {
            if (!to_native(&acl, &aces[i]))
            {
                int saved = errno;

                (void)acl_free(acl);
                errno = saved;
                return -1;
            }
        }
    }
    rc = acl_set_fd_np(fd, acl, ACL_TYPE_NFS4);
    {
        int saved = errno;

        (void)acl_free(acl);
        errno = saved;
    }
    return rc;
}

#elif defined(RS_ACL_DARWIN)

static const struct {
    unsigned   ours;
    acl_perm_t native;
} perms[] = {
    { RS_ACE_READ_DATA, ACL_READ_DATA },
    { RS_ACE_WRITE_DATA, ACL_WRITE_DATA },
    { RS_ACE_APPEND_DATA, ACL_APPEND_DATA },
    { RS_ACE_READ_XATTR, ACL_READ_EXTATTRIBUTES },
    { RS_ACE_WRITE_XATTR, ACL_WRITE_EXTATTRIBUTES },
    { RS_ACE_EXECUTE, ACL_EXECUTE },
    { RS_ACE_DELETE_CHILD, ACL_DELETE_CHILD },
    { RS_ACE_READ_ATTRIBUTES, ACL_READ_ATTRIBUTES },
    { RS_ACE_WRITE_ATTRIBUTES, ACL_WRITE_ATTRIBUTES },
    { RS_ACE_DELETE, ACL_DELETE },
    { RS_ACE_READ_ACL, ACL_READ_SECURITY },
    { RS_ACE_WRITE_ACL, ACL_WRITE_SECURITY },
    { RS_ACE_WRITE_OWNER, ACL_CHANGE_OWNER },
    { RS_ACE_SYNCHRONIZE, ACL_SYNCHRONIZE },
};

static const struct {
    unsigned   ours;
    acl_flag_t native;
} flags[] = {
    { RS_ACE_FILE_INHERIT, ACL_ENTRY_FILE_INHERIT },
    { RS_ACE_DIR_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT },
    { RS_ACE_INHERIT_ONLY, ACL_ENTRY_ONLY_INHERIT },
    { RS_ACE_NO_PROPAGATE, ACL_ENTRY_LIMIT_INHERIT },
    { RS_ACE_INHERITED, ACL_ENTRY_INHERITED },
};

/* The everyone group's identity, which is how macOS says everyone@. */
static const char everyone_uuid[] = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C";

static bool from_native(acl_entry_t ent, struct rs_ace *a)
{
    acl_tag_t     tag;
    acl_permset_t ps;
    acl_flagset_t fs;
    guid_t       *g;
    id_t          id;
    int           idtype;
    uuid_string_t s;
    size_t        i;

    memset(a, 0, sizeof(*a));
    if (acl_get_tag_type(ent, &tag) != 0 || acl_get_permset(ent, &ps) != 0 ||
        acl_get_flagset_np(ent, &fs) != 0)
    {
        return false;
    }
    if (tag == ACL_EXTENDED_ALLOW)
    {
        a->type = RS_ACE_ALLOW;
    } else if (tag == ACL_EXTENDED_DENY)
    {
        a->type = RS_ACE_DENY;
    } else
    {
        return false;
    }
    g = acl_get_qualifier(ent);
    if (g == NULL)
    {
        return false;
    }
    uuid_unparse_upper(g->g_guid, s);
    if (strcmp(s, everyone_uuid) == 0)
    {
        /* A group to macOS, everyone@ to every other system. */
        a->tag = RS_ACE_EVERYONE;
    } else if (mbr_uuid_to_id(g->g_guid, &id, &idtype) == 0 &&
               (idtype == ID_TYPE_UID || idtype == ID_TYPE_GID))
    {
        a->tag = idtype == ID_TYPE_UID ? RS_ACE_USER : RS_ACE_GROUP;
        a->id = (uint64_t)id;
    } else
    {
        a->tag = RS_ACE_UUID;
        a->uuid = rs_xstrdup(s);
    }
    (void)acl_free(g);
    for (i = 0; i < COUNT(perms); i++)
    {
        if (acl_get_perm_np(ps, perms[i].native) == 1)
        {
            a->perms |= perms[i].ours;
        }
    }
    for (i = 0; i < COUNT(flags); i++)
    {
        if (acl_get_flag_np(fs, flags[i].native) == 1)
        {
            a->flags |= flags[i].ours;
        }
    }
    return true;
}

static bool read_native(int fd, char **out)
{
    acl_t          acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    acl_entry_t    ent;
    int            which = ACL_FIRST_ENTRY;
    struct rs_ace *aces = NULL;
    size_t         n = 0;

    if (acl == NULL)
    {
        /* None, or none on this filesystem. */
        return errno == ENOENT || errno == ENOTSUP || errno == EINVAL;
    }
    while (acl_get_entry(acl, which, &ent) == 0)
    {
        struct rs_ace a;

        which = ACL_NEXT_ENTRY;
        if (!from_native(ent, &a))
        {
            free(a.uuid);
            rs_acl_free(aces, n);
            (void)acl_free(acl);
            errno = EINVAL;
            return false;
        }
        aces = rs_xreallocarray(aces, n + 1, sizeof(*aces));
        aces[n++] = a;
    }
    (void)acl_free(acl);
    if (n > 0)
    {
        name_ids(aces, n);
        *out = text_of(aces, n);
    }
    return true;
}

static bool to_native(acl_t *acl, const struct rs_ace *a)
{
    acl_entry_t   ent;
    acl_permset_t ps;
    acl_flagset_t fs;
    acl_tag_t     tag;
    uuid_t        uu;
    size_t        i;

    if (a->type != RS_ACE_ALLOW && a->type != RS_ACE_DENY)
    {
        errno = ENOTSUP;   /* audit and alarm: macOS has neither */
        return false;
    }
    switch (a->tag)
    {
    case RS_ACE_USER:
        if (mbr_uid_to_uuid((uid_t)a->id, uu) != 0)
        {
            return false;
        }
        break;
    case RS_ACE_GROUP:
        if (mbr_gid_to_uuid((gid_t)a->id, uu) != 0)
        {
            return false;
        }
        break;
    case RS_ACE_EVERYONE:
        if (uuid_parse(everyone_uuid, uu) != 0)
        {
            return false;
        }
        break;
    case RS_ACE_UUID:
        if (a->uuid == NULL || uuid_parse(a->uuid, uu) != 0)
        {
            errno = EINVAL;
            return false;
        }
        break;
    default:
        errno = ENOTSUP;   /* owner@ and group@: macOS has neither */
        return false;
    }
    tag = a->type == RS_ACE_ALLOW ? ACL_EXTENDED_ALLOW : ACL_EXTENDED_DENY;
    if (acl_create_entry(acl, &ent) != 0 || acl_set_tag_type(ent, tag) != 0 ||
        acl_set_qualifier(ent, uu) != 0 || acl_get_permset(ent, &ps) != 0 ||
        acl_clear_perms(ps) != 0 || acl_get_flagset_np(ent, &fs) != 0 ||
        acl_clear_flags_np(fs) != 0)
    {
        return false;
    }
    if (a->flags & (RS_ACE_SUCCESSFUL_ACCESS | RS_ACE_FAILED_ACCESS))
    {
        errno = ENOTSUP;
        return false;
    }
    for (i = 0; i < COUNT(perms); i++)
    {
        if ((a->perms & perms[i].ours) && acl_add_perm(ps, perms[i].native) != 0)
        {
            return false;
        }
    }
    for (i = 0; i < COUNT(flags); i++)
    {
        if ((a->flags & flags[i].ours) && acl_add_flag_np(fs, flags[i].native) != 0)
        {
            return false;
        }
    }
    return acl_set_permset(ent, ps) == 0 && acl_set_flagset_np(ent, fs) == 0;
}

static int set_native(int fd, const struct rs_ace *aces, size_t n)
{
    acl_t  acl;
    size_t i;
    int    rc;
    int    saved;

    if (n == 0)
    {
        acl_t now = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);

        if (now == NULL)
        {
            return 0;   /* none to take off */
        }
        (void)acl_free(now);
    }
    acl = acl_init((int)(n > 0 ? n : 1));
    if (acl == NULL)
    {
        return -1;
    }
    for (i = 0; i < n; i++)
    {
        if (!to_native(&acl, &aces[i]))
        {
            saved = errno;
            (void)acl_free(acl);
            errno = saved;
            return -1;
        }
    }
    /* An empty one takes off what is there, inherited or not. */
    rc = acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED);
    saved = errno;
    (void)acl_free(acl);
    errno = saved;
    return rc;
}

#endif

bool rs_acl_read(int fd, char **out)
{
    *out = NULL;
    if (pretending)
    {
        const struct pretended *p = pretended_of(fd, false);

        *out = p && p->text ? rs_xstrdup(p->text) : NULL;
        return true;
    }
#if defined(RS_ACL_NFS4) || defined(RS_ACL_DARWIN)
    return read_native(fd, out);
#else
    (void)fd;
    return true;
#endif
}

int rs_acl_set(int fd, const char *text,
               void (*map)(const void *ctx, bool group, const char *name, uint64_t *id),
               const void *ctx)
{
    struct rs_ace *aces = NULL;
    size_t         n = 0;
    int            rc;
    int            saved;

    if (text != NULL && !rs_acl_parse(text, &aces, &n))
    {
        errno = EINVAL;
        return -1;
    }
    map_ids(aces, n, map, ctx);
    if (pretending)
    {
        struct pretended *p = pretended_of(fd, true);

        if (p == NULL)
        {
            rs_acl_free(aces, n);
            return -1;
        }
        free(p->text);
        p->text = n > 0 ? text_of(aces, n) : NULL;
        if (n == 0)
        {
            rs_acl_free(aces, n);
        }
        return 0;
    }
#if defined(RS_ACL_NFS4) || defined(RS_ACL_DARWIN)
    rc = set_native(fd, aces, n);
#else
    /* None of these here: none is what every file has already. */
    rc = 0;
    if (n > 0)
    {
        errno = ENOTSUP;
        rc = -1;
    }
#endif
    saved = errno;
    rs_acl_free(aces, n);
    errno = saved;
    return rc;
}
