/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "mounts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/types.h>
#if defined(__NetBSD__)
#include <sys/statvfs.h>
#endif
#define RS_MOUNTS_GETMNTINFO 1
#endif

#include "util.h"

/* Larger than any mountinfo there is: a few thousand mounts at most. */
#define MOUNTINFO_MAX ((size_t)16 << 20)

static const char *test_mountinfo;

void rs_mounts_set_mountinfo(const char *path)
{
    test_mountinfo = path;
}

bool rs_mount_remote_type(const char *type)
{
    /* Linux's names, and the BSDs' and macOS's where theirs differ. */
    static const char *const remote[] = {
        "nfs",       "nfs4",   "cifs",     "smb3",  "smbfs",  "9p",       "ceph",
        "glusterfs", "lustre", "afs",      "davfs", "webdav", "afpfs",    "ncpfs",
        "coda",      "gpfs",   "beegfs",   "orangefs", "autofs", "virtiofs",
    };
    /* Through FUSE, as fuse.sshfs on Linux and fusefs.sshfs on FreeBSD. */
    static const char *const fused[] = {
        "sshfs", "rclone", "s3fs", "gcsfuse", "glusterfs", "davfs2", "curlftpfs", "juicefs",
        "goofys", "blobfuse", "blobfuse2", "cephfs", "ceph-fuse", "mfs", "moosefs", "lizardfs",
        "seaweedfs", "geesefs",
    };
    const char *sub = NULL;
    size_t      i;

    for (i = 0; i < sizeof(remote) / sizeof(remote[0]); i++)
    {
        if (strcmp(type, remote[i]) == 0)
        {
            return true;
        }
    }
    if (strncmp(type, "fuse.", 5) == 0)
    {
        sub = type + 5;
    } else if (strncmp(type, "fusefs.", 7) == 0)
    {
        sub = type + 7;
    }
    for (i = 0; sub && i < sizeof(fused) / sizeof(fused[0]); i++)
    {
        if (strcmp(sub, fused[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

char *rs_mount_unescape(const char *s, size_t len)
{
    struct rs_buf b;
    size_t        i;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (i = 0; i < len; i++)
    {
        if (s[i] == '\\' && i + 3 < len && s[i + 1] >= '0' && s[i + 1] <= '3' &&
            s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7')
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

static void add(struct rs_mount **out, size_t *n, char *path, const char *type, char *source,
                bool part)
{
    *out = rs_xreallocarray(*out, *n + 1, sizeof(**out));
    (*out)[*n].path = path;
    (*out)[*n].type = rs_xstrdup(type);
    (*out)[*n].source = source ? source : rs_xstrdup("");
    (*out)[*n].part = part;
    (*n)++;
}

/* The next field of the line [*p, end), split on spaces; false at its end. */
static bool field(const char **p, const char *end, const char **f, size_t *len)
{
    while (*p < end && **p == ' ')
    {
        (*p)++;
    }
    if (*p >= end)
    {
        return false;
    }
    *f = *p;
    while (*p < end && **p != ' ')
    {
        (*p)++;
    }
    *len = (size_t)(*p - *f);
    return true;
}

/* The mounts in mountinfo's `text`: every one, or only the remote ones. */
static void parse(const char *text, size_t len, bool all, struct rs_mount **out, size_t *n)
{
    const char *line = text;
    const char *stop = text ? text + len : NULL;

    *out = NULL;
    *n = 0;
    while (line && line < stop)
    {
        const char *nl = memchr(line, '\n', (size_t)(stop - line));
        const char *end = nl ? nl : stop;
        const char *p = line;
        const char *f = NULL;
        const char *mountpoint = NULL;
        const char *type = NULL;
        const char *source = NULL;
        size_t      flen = 0;
        size_t      mlen = 0;
        size_t      tlen = 0;
        size_t      slen = 0;
        size_t      k = 0;
        size_t      after = 0;   /* fields past the "-" */
        bool        dash = false;
        bool        part = false;

        /* id parent maj:min root mountpoint options [optional...] - type
         * source superoptions */
        while (field(&p, end, &f, &flen))
        {
            if (k == 3)
            {
                part = !(flen == 1 && f[0] == '/');
            } else if (k == 4)
            {
                mountpoint = f;
                mlen = flen;
            } else if (dash && ++after == 1)
            {
                type = f;
                tlen = flen;
            } else if (dash && after == 2)
            {
                source = f;
                slen = flen;
                break;
            } else if (k > 5 && flen == 1 && f[0] == '-')
            {
                dash = true;
            }
            k++;
        }
        if (type && mountpoint && mountpoint[0] == '/')
        {
            char *t = rs_xstrndup(type, tlen);

            if (all || rs_mount_remote_type(t))
            {
                add(out, n, rs_mount_unescape(mountpoint, mlen), t,
                    source ? rs_mount_unescape(source, slen) : NULL, part);
            }
            free(t);
        }
        line = nl ? nl + 1 : NULL;
    }
}

void rs_mounts_parse_mountinfo(const char *text, size_t len, struct rs_mount **out, size_t *n)
{
    parse(text, len, false, out, n);
}

void rs_mounts_parse_all(const char *text, size_t len, struct rs_mount **out, size_t *n)
{
    parse(text, len, true, out, n);
}

static int by_path(const void *a, const void *b)
{
    return strcmp(((const struct rs_mount *)a)->path, ((const struct rs_mount *)b)->path);
}

static void free_one(struct rs_mount *m)
{
    free(m->path);
    free(m->type);
    free(m->source);
}

/* Sorted, and each path once: an automount's trigger and what it mounted
 * there are both remote, at the same place. */
static void sort_unique(struct rs_mount *m, size_t *n)
{
    size_t i;
    size_t k = 0;

    if (*n == 0)
    {
        return;
    }
    qsort(m, *n, sizeof(*m), by_path);
    for (i = 1; i < *n; i++)
    {
        if (strcmp(m[i].path, m[k].path) == 0)
        {
            free_one(&m[i]);
        } else
        {
            m[++k] = m[i];
        }
    }
    *n = k + 1;
}

static bool read_mountinfo(const char *path, bool all, struct rs_mount **out, size_t *n)
{
    FILE         *fp = fopen(path, "r");
    struct rs_buf b;
    char          chunk[8192];
    size_t        got;

    if (!fp)
    {
        return false;
    }
    rs_buf_init(&b);
    while (b.len < MOUNTINFO_MAX && (got = fread(chunk, 1, sizeof(chunk), fp)) > 0)
    {
        rs_buf_add(&b, chunk, got);
        if (got < sizeof(chunk))
        {
            break;
        }
    }
    (void)fclose(fp);
    parse(b.data, b.len, all, out, n);
    rs_buf_free(&b);
    return true;
}

/* This host's mounts, every one or the remote ones, in the order they were
 * mounted. */
static void host_mounts(bool all, struct rs_mount **out, size_t *n)
{
    *out = NULL;
    *n = 0;
    if (test_mountinfo)
    {
        (void)read_mountinfo(test_mountinfo, all, out, n);
    } else
    {
#ifdef RS_MOUNTS_GETMNTINFO
#if defined(__NetBSD__)
        struct statvfs *mnt = NULL;
#else
        struct statfs *mnt = NULL;
#endif
        /* MNT_NOWAIT: what the kernel has already, asking no server. */
        int count = getmntinfo(&mnt, MNT_NOWAIT);
        int i;

        for (i = 0; i < count; i++)
        {
            if (mnt[i].f_mntonname[0] == '/' &&
                (all || rs_mount_remote_type(mnt[i].f_fstypename)))
            {
                add(out, n, rs_xstrdup(mnt[i].f_mntonname), mnt[i].f_fstypename,
                    rs_xstrdup(mnt[i].f_mntfromname), false);
            }
        }
#else
        (void)read_mountinfo("/proc/self/mountinfo", all, out, n);
#endif
    }
}

void rs_mounts_remote(struct rs_mount **out, size_t *n)
{
    host_mounts(false, out, n);
    sort_unique(*out, n);
}

void rs_mounts_all(struct rs_mount **out, size_t *n)
{
    size_t i;
    size_t j;
    size_t k = 0;

    host_mounts(true, out, n);
    /* The later of two at one place is the one there: the earlier goes
     * first, so that sorting cannot choose between them. */
    for (i = 0; i < *n; i++)
    {
        bool hidden = false;

        for (j = i + 1; j < *n && !hidden; j++)
        {
            hidden = strcmp((*out)[i].path, (*out)[j].path) == 0;
        }
        if (hidden)
        {
            free_one(&(*out)[i]);
        } else
        {
            (*out)[k++] = (*out)[i];
        }
    }
    *n = k;
    if (k > 0)
    {
        qsort(*out, k, sizeof(**out), by_path);
    }
}

void rs_mounts_free(struct rs_mount *m, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        free_one(&m[i]);
    }
    free(m);
}
