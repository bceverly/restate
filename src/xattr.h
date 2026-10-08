/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Extended attributes: the name-value pairs a file carries beside its
 * content, and, on Linux, where two other things live as well -- POSIX ACLs
 * (system.posix_acl_access, and a directory's system.posix_acl_default) and
 * file capabilities (security.capability, what lets ping open a raw socket
 * without being set-uid). Recording a file's attributes records all three.
 *
 * Read and written through an open descriptor, never a path, like everything
 * else the walk and the restore touch. Each system has its own calls:
 *
 *   Linux          flistxattr / fgetxattr / fsetxattr; names as the kernel
 *                  gives them, "user.x", "security.capability"
 *   macOS          the same names, with an offset and options argument;
 *                  "com.apple.quarantine" and the like
 *   FreeBSD,       extattr_list_fd / extattr_get_fd / extattr_set_fd, in a
 *   NetBSD         user and a system namespace; named here "user.x" and
 *                  "system.x", so the index reads alike everywhere
 *   OpenBSD        none: every file has none
 *
 * Left out, because they describe the machine rather than the file and a
 * restore onto another would be wrong to set them: SELinux and Smack labels,
 * which the target's policy assigns, and IMA and EVM signatures, which its
 * keys verify. Every other attribute is kept, up to 64 KiB each and 256 KiB
 * a file.
 */
#ifndef RESTATE_XATTR_H
#define RESTATE_XATTR_H

#include <stdbool.h>
#include <stddef.h>

struct rs_xattr {
    char          *name;
    unsigned char *value;
    size_t         len;
};

/*
 * The attributes of the open file or directory `fd` that are kept, sorted by
 * name, into *out (NULL when there are none) and *n. Returns false, with
 * errno set, if they could not be read; a filesystem that has none is not an
 * error.
 */
bool rs_xattr_read(int fd, struct rs_xattr **out, size_t *n);

/* Sets each of them on `fd`. Returns how many could not be set. */
size_t rs_xattr_write(int fd, const struct rs_xattr *x, size_t n);

void rs_xattr_free(struct rs_xattr *x, size_t n);

/* Whether an attribute of this name is one restate keeps. */
bool rs_xattr_kept(const char *name);

/*
 * A POSIX ACL as Linux stores it in system.posix_acl_access or
 * system.posix_acl_default -- a version, then (tag, permissions, id) for
 * each entry -- with every named user's id passed through `uid` and every
 * named group's through `gid`, each of which returns the id to use. False,
 * and nothing changed, if `value` is not an ACL in that form.
 */
bool rs_xattr_map_acl(unsigned char *value, size_t len,
                      unsigned long (*uid)(const void *ctx, unsigned long id),
                      unsigned long (*gid)(const void *ctx, unsigned long id), const void *ctx);

/* Whether `name` is one of those two. */
bool rs_xattr_is_acl(const char *name);

#endif /* RESTATE_XATTR_H */
