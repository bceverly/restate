/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The ACLs that are not extended attributes: NFSv4 ACLs, on FreeBSD (ZFS,
 * and UFS where tunefs -N turned them on) and NetBSD (FFS), and macOS's
 * extended ACLs, on APFS and HFS+. Linux's POSIX ACLs are extended
 * attributes, and kept with them (xattr.h).
 *
 * Both are lists of entries evaluated in order -- allow or deny, who, which
 * permissions, how they are inherited -- so one text records either, in the
 * names FreeBSD's setfacl(1) uses, an entry to each comma-separated part:
 *
 *   TAG:WHO:PERMISSIONS:FLAGS:TYPE
 *
 *   TAG          owner@, group@ or everyone@, with WHO empty; user or group,
 *                with WHO the name and the number, "alice=1001" (the number
 *                alone, "=1001", where it has no name or one that would not
 *                read back); uuid, with WHO a macOS identity no user or group
 *                stands for
 *   PERMISSIONS  read_data, write_data, append_data, read_xattr,
 *                write_xattr, execute, delete_child, read_attributes,
 *                write_attributes, delete, read_acl, write_acl, write_owner,
 *                synchronize -- '/'-separated
 *   FLAGS        file_inherit, dir_inherit, inherit_only, no_propagate,
 *                successful_access, failed_access, inherited -- the same
 *   TYPE         allow, deny, audit or alarm
 *
 *   "user:alice=1001:read_data/execute::allow,everyone@::write_data::deny"
 *
 * Only an ACL that says more than the mode is recorded. The order is kept:
 * it is what decides. Users and groups are put back by name, through the
 * merged accounts, as owners are, and by number where there is no name.
 *
 * An ACL from one kind of system is set on the other where it can be said
 * there: macOS has no owner@ or group@, nor audit or alarm entries, and the
 * BSDs no uuid. One that cannot be is counted, and left off whole -- part of
 * an ACL can grant what the whole did not.
 */
#ifndef RESTATE_ACL_H
#define RESTATE_ACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

enum rs_ace_tag {
    RS_ACE_OWNER = 0,   /* owner@ */
    RS_ACE_GROUP_OBJ,   /* group@ */
    RS_ACE_EVERYONE,    /* everyone@ */
    RS_ACE_USER,
    RS_ACE_GROUP,
    RS_ACE_UUID         /* a macOS identity with no user or group behind it */
};

enum {
    RS_ACE_READ_DATA = 1u << 0,
    RS_ACE_WRITE_DATA = 1u << 1,
    RS_ACE_APPEND_DATA = 1u << 2,
    RS_ACE_READ_XATTR = 1u << 3,
    RS_ACE_WRITE_XATTR = 1u << 4,
    RS_ACE_EXECUTE = 1u << 5,
    RS_ACE_DELETE_CHILD = 1u << 6,
    RS_ACE_READ_ATTRIBUTES = 1u << 7,
    RS_ACE_WRITE_ATTRIBUTES = 1u << 8,
    RS_ACE_DELETE = 1u << 9,
    RS_ACE_READ_ACL = 1u << 10,
    RS_ACE_WRITE_ACL = 1u << 11,
    RS_ACE_WRITE_OWNER = 1u << 12,
    RS_ACE_SYNCHRONIZE = 1u << 13
};

enum {
    RS_ACE_FILE_INHERIT = 1u << 0,
    RS_ACE_DIR_INHERIT = 1u << 1,
    RS_ACE_INHERIT_ONLY = 1u << 2,
    RS_ACE_NO_PROPAGATE = 1u << 3,
    RS_ACE_SUCCESSFUL_ACCESS = 1u << 4,
    RS_ACE_FAILED_ACCESS = 1u << 5,
    RS_ACE_INHERITED = 1u << 6
};

enum rs_ace_type {
    RS_ACE_ALLOW = 0,
    RS_ACE_DENY,
    RS_ACE_AUDIT,
    RS_ACE_ALARM
};

struct rs_ace {
    enum rs_ace_tag  tag;
    char            *name;    /* a user's or group's, or NULL */
    uint64_t         id;      /* a user's or group's number */
    char            *uuid;    /* RS_ACE_UUID's, as text */
    unsigned         perms;
    unsigned         flags;
    enum rs_ace_type type;
};

/* Whether this system has ACLs of this kind: FreeBSD, NetBSD, macOS, or the
 * tests pretending. */
bool rs_acl_supported(void);

/* The ACL of what `fd` is open on, as text, into *out: NULL where it has
 * none beyond its mode, or the filesystem has none. False, with errno, only
 * where one is there and could not be read. */
bool rs_acl_read(int fd, char **out);

/* Gives what `fd` is open on exactly the ACL `text` says, or none beyond
 * its mode for NULL. Each user's and group's number is passed through `map`
 * first, where given, with its name (NULL if none): it changes *id to this
 * system's, and returns false to leave it. 0, or -1 with errno: EINVAL for
 * text that is not an ACL, ENOTSUP for one this system cannot hold. */
int rs_acl_set(int fd, const char *text,
               void (*map)(const void *ctx, bool group, const char *name, uint64_t *id),
               const void *ctx);

/* `text` as entries, into *out and *n; false, and none, if it is not one. */
bool rs_acl_parse(const char *text, struct rs_ace **out, size_t *n);

/* The entries as text, added to `out`. */
void rs_acl_format(const struct rs_ace *aces, size_t n, struct rs_buf *out);

void rs_acl_free(struct rs_ace *aces, size_t n);

/* For the tests: ACLs kept in memory, by file, in place of the
 * filesystem's -- on Linux, which has none of these. Off again with
 * false. */
void rs_acl_pretend(bool on);

#endif /* RESTATE_ACL_H */
