/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "identity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "packages.h"
#include "run.h"
#include "scan.h"

#define MACHINE_ID      "/etc/machine-id"
#define DBUS_MACHINE_ID "/var/lib/dbus/machine-id"
#define RANDOM_SEED     "/var/lib/systemd/random-seed"
#define HOSTNAME        "/etc/hostname"
#define HOSTS           "/etc/hosts"
#define HOST_KEYS       "/etc/ssh/ssh_host_"

/* As much as systemd saves: its pool's size. */
#define SEED_SIZE 512
/* An /etc/hosts larger than this is not one to edit. */
#define HOSTS_MAX ((size_t)1024 * 1024)

bool rs_identity_name_ok(const char *name)
{
    size_t len = strlen(name);
    size_t label = 0;
    size_t i;

    if (len == 0 || len > 253)
    {
        return false;
    }
    for (i = 0; i <= len; i++)
    {
        char c = name[i];

        if (c == '.' || c == '\0')
        {
            if (label == 0 || label > 63 || name[i - 1] == '-')
            {
                return false;
            }
            label = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   (c == '-' && label > 0))
        {
            label++;
        } else
        {
            return false;
        }
    }
    return true;
}

size_t rs_identity_mark(const struct rs_index *ix, const struct rs_rules *rules, bool *leave)
{
    size_t i;
    size_t n = 0;

    for (i = 0; i < ix->count; i++)
    {
        const struct rs_entry *e = &ix->entries[i];

        leave[i] = e->cls == RS_CLASS_IDENTITY ||
                   (rules && rs_rules_classify(rules, e->path, NULL) == RS_CLASS_IDENTITY);
        n += leave[i] ? 1 : 0;
    }
    return n;
}

static bool blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

size_t rs_identity_hosts(const char *text, size_t len, const char *old, const char *name,
                         struct rs_buf *out)
{
    size_t olen = old ? strlen(old) : 0;
    size_t pos = 0;
    size_t n = 0;

    while (pos < len)
    {
        size_t end = pos;
        size_t p;
        size_t field = 0;

        while (end < len && text[end] != '\n')
        {
            end++;
        }
        for (p = pos; p < end;)
        {
            size_t w = p;

            if (blank(text[p]))
            {
                rs_buf_addc(out, text[p++]);
                continue;
            }
            if (text[p] == '#')
            {
                rs_buf_add(out, text + p, end - p);
                break;
            }
            while (w < end && !blank(text[w]) && text[w] != '#')
            {
                w++;
            }
            /* The first field is the address; the rest are its names. */
            if (field > 0 && olen > 0 && w - p >= olen && memcmp(text + p, old, olen) == 0 &&
                (w - p == olen || text[p + olen] == '.'))
            {
                rs_buf_addstr(out, name);
                rs_buf_add(out, text + p + olen, w - p - olen);
                n++;
            } else
            {
                rs_buf_add(out, text + p, w - p);
            }
            field++;
            p = w;
        }
        if (end < len)
        {
            rs_buf_addc(out, '\n');
        }
        pos = end + 1;
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* Renewing                                                                  */
/* ------------------------------------------------------------------------- */

struct renew {
    int                       root;
    const char               *root_path;
    bool                      dry_run;
    bool                      verbose;
    struct rs_identity_stats *st;
    unsigned long             counter;  /* for temporary names */
};

static void say(const struct renew *r, const char *what, const char *path)
{
    if (r->verbose || r->dry_run)
    {
        struct rs_buf b;

        rs_buf_init(&b);
        rs_escape(&b, path);
        (void)printf("%s%s %s\n", r->dry_run ? "would " : "", what, b.data ? b.data : "");
        rs_buf_free(&b);
    }
}

static void failed(const struct renew *r, const char *path, const char *why)
{
    struct rs_buf b;

    rs_buf_init(&b);
    rs_escape(&b, path);
    rs_warn("%s: %s", b.data ? b.data : "", why);
    rs_buf_free(&b);
    r->st->failed++;
}

/*
 * The directory that holds `path`, opened beneath the root one component at
 * a time and never through a symlink; -1 if the way is not all directories.
 * `*name` points into `path` at its last component.
 */
static int open_parent(const struct renew *r, const char *path, const char **name)
{
    const char *p = path + 1;
    const char *slash;
    int         fd = dup(r->root);

    while (fd >= 0 && (slash = strchr(p, '/')) != NULL)
    {
        char *comp = rs_xstrndup(p, (size_t)(slash - p));
        int   next = openat(fd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

        free(comp);
        (void)close(fd);
        fd = next;
        p = slash + 1;
    }
    *name = p;
    return fd;
}

/* Whether the regular file `name` is the image's own: its digest, or, from
 * an index made without them, its size and modification time. */
static bool is_images(int dirfd, const char *name, const struct stat *sb, const struct rs_entry *e)
{
    char     hex[RS_SHA256_HEX_SIZE];
    uint64_t bytes = 0;

    if ((uint64_t)sb->st_size != e->size)
    {
        return false;
    }
    if (e->hash_state != RS_HASH_PRESENT)
    {
        return e->mtime.set && (int64_t)sb->st_mtime == e->mtime.sec;
    }
    return rs_hash_file_at(dirfd, name, sb, hex, &bytes) && strcmp(hex, e->hash) == 0;
}

static bool random_bytes(unsigned char *buf, size_t n)
{
    int    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t got = 0;

    while (fd >= 0 && got < n)
    {
        ssize_t k = read(fd, buf + got, n - got);

        if (k < 0 && errno == EINTR)
        {
            continue;
        }
        if (k <= 0)
        {
            break;
        }
        got += (size_t)k;
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    return got == n;
}

/* A machine ID as systemd makes one: 128 random bits, marked as a version 4
 * UUID, in lowercase hex, and a newline. */
static bool new_machine_id(char id[34])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char     b[16];
    size_t            i;

    if (!random_bytes(b, sizeof(b)))
    {
        return false;
    }
    b[6] = (unsigned char)((b[6] & 0x0f) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3f) | 0x80);
    for (i = 0; i < sizeof(b); i++)
    {
        id[2 * i] = hex[b[i] >> 4];
        id[2 * i + 1] = hex[b[i] & 0x0f];
    }
    id[32] = '\n';
    id[33] = '\0';
    return true;
}

/*
 * Writes `data` as `name` in `dirfd`: created beside it and renamed over it,
 * with the owner and mode of the file it replaces (`was`), or root's and
 * `mode` where there was none. 0, or the errno of what failed.
 */
static int put(struct renew *r, int dirfd, const char *name, const void *data, size_t len,
               mode_t mode, const struct stat *was)
{
    char  *tmp = rs_xasprintf(".restate-%ld-%lu", (long)getpid(), ++r->counter);
    int    fd = openat(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int    e = fd < 0 ? errno : 0;
    size_t done = 0;

    while (e == 0 && done < len)
    {
        ssize_t k = write(fd, (const char *)data + done, len - done);

        if (k < 0 && errno == EINTR)
        {
            continue;
        }
        if (k <= 0)
        {
            e = k < 0 ? errno : EIO;
        }
        done += k > 0 ? (size_t)k : 0;
    }
    if (e == 0 && was)
    {
        /* Not root, the file stays the restoring user's, as restore's do;
         * it is still written. */
        if (fchown(fd, was->st_uid, was->st_gid) != 0 && geteuid() == 0)
        {
            e = errno;
        }
        mode = was->st_mode & 07777;
    }
    if (e == 0 && fchmod(fd, mode) != 0)
    {
        e = errno;
    }
    if (fd >= 0 && close(fd) != 0 && e == 0)
    {
        e = errno;
    }
    if (e == 0 && renameat(dirfd, tmp, dirfd, name) != 0)
    {
        e = errno;
    }
    if (e != 0 && fd >= 0)
    {
        (void)unlinkat(dirfd, tmp, 0);
    }
    free(tmp);
    return e;
}

/* Makes one of the files restate knows how to make, in place of the image's
 * or where there was none. */
static void make(struct renew *r, int dirfd, const char *name, const char *path,
                 const struct stat *was, const char *machine_id)
{
    int e;

    say(r, "make new", path);
    r->st->made++;
    if (r->dry_run)
    {
        return;
    }
    if (strcmp(path, RANDOM_SEED) == 0)
    {
        unsigned char seed[SEED_SIZE];

        e = random_bytes(seed, sizeof(seed)) ? put(r, dirfd, name, seed, sizeof(seed), 0600, was)
                                             : -1;
    } else
    {
        e = machine_id ? put(r, dirfd, name, machine_id, strlen(machine_id), 0444, was) : -1;
    }
    if (e != 0)
    {
        r->st->made--;
        failed(r, path, e > 0 ? strerror(e) : "no random bytes to make a new one from");
    }
}

/*
 * One entry the restore left out. `machine_id` is the machine-id the
 * machine has now (made new already, if it was the image's), for D-Bus's
 * copy; `*keys` is set where a host key is missing once this is done.
 */
static void renew_one(struct renew *r, const struct rs_entry *e, const char *machine_id,
                      bool *keys)
{
    const char *name;
    struct stat sb;
    int         dirfd;
    bool        key = rs_starts_with(e->path, HOST_KEYS);
    bool        made = strcmp(e->path, MACHINE_ID) == 0 || strcmp(e->path, RANDOM_SEED) == 0 ||
                strcmp(e->path, DBUS_MACHINE_ID) == 0;

    if (e->type != 'f' || strcmp(e->path, HOSTNAME) == 0)
    {
        return;
    }
    dirfd = open_parent(r, e->path, &name);
    if (dirfd < 0 || fstatat(dirfd, name, &sb, AT_SYMLINK_NOFOLLOW) != 0)
    {
        /* None here: the ones restate makes are made, but D-Bus's, which
         * reads the machine's own where it has no copy. */
        *keys = *keys || key;
        if (dirfd >= 0 && made && strcmp(e->path, DBUS_MACHINE_ID) != 0)
        {
            make(r, dirfd, name, e->path, NULL, machine_id);
        }
    } else if (!S_ISREG(sb.st_mode) || !is_images(dirfd, name, &sb, e))
    {
        say(r, "keep this machine's own", e->path);
        r->st->kept++;
    } else if (made)
    {
        make(r, dirfd, name, e->path, &sb, machine_id);
    } else
    {
        say(r, "remove the image's own", e->path);
        r->st->removed++;
        *keys = *keys || key;
        if (!r->dry_run && unlinkat(dirfd, name, 0) != 0)
        {
            r->st->removed--;
            failed(r, e->path, strerror(errno));
        }
    }
    if (dirfd >= 0)
    {
        (void)close(dirfd);
    }
}

/* Writes `text` over the file at `path`, as the file it replaces. */
static void replace(struct renew *r, const char *path, const char *text, size_t len)
{
    const char *base;
    struct stat sb;
    int         dirfd = open_parent(r, path, &base);
    bool        was;
    int         e;

    if (r->dry_run)
    {
        if (dirfd >= 0)
        {
            (void)close(dirfd);
        }
        return;
    }
    if (dirfd < 0)
    {
        failed(r, path, "its directory is not there");
        return;
    }
    was = fstatat(dirfd, base, &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(sb.st_mode);
    e = put(r, dirfd, base, text, len, 0644, was ? &sb : NULL);
    if (e != 0)
    {
        failed(r, path, strerror(e));
    }
    (void)close(dirfd);
}

/* /etc/hostname, and the image's name in /etc/hosts. */
static void host_name(struct renew *r, const char *name, const char *old)
{
    struct rs_buf text;
    struct rs_buf hosts;
    char         *line = rs_xasprintf("%s\n", name);

    say(r, "set the host name in", HOSTNAME);
    replace(r, HOSTNAME, line, strlen(line));
    free(line);
    if (!old || strcmp(old, name) == 0 || !rs_read_beneath(r->root_path, HOSTS, HOSTS_MAX, &text))
    {
        return;
    }
    rs_buf_init(&hosts);
    r->st->hosts = rs_identity_hosts(text.data, text.len, old, name, &hosts);
    if (r->st->hosts > 0)
    {
        uint64_t before = r->st->failed;

        say(r, "give the new host name in", HOSTS);
        replace(r, HOSTS, hosts.data, hosts.len);
        r->st->hosts = r->st->failed > before ? 0 : r->st->hosts;
    }
    rs_buf_free(&hosts);
    rs_buf_free(&text);
}

/* Whether the machine has an SSH server to use host keys. */
static bool has_sshd(const struct renew *r)
{
    const char *name;
    struct stat sb;
    int         dirfd = open_parent(r, "/usr/sbin/sshd", &name);
    bool        yes = dirfd >= 0 && fstatat(dirfd, name, &sb, 0) == 0 && S_ISREG(sb.st_mode);

    if (dirfd >= 0)
    {
        (void)close(dirfd);
    }
    return yes;
}

/* ssh-keygen -A: each default kind of host key the machine has none of. */
static void host_keys(struct renew *r)
{
    struct rs_buf err;
    struct rs_buf out;
    int           code = 0;
    char          a0[] = "ssh-keygen";
    char          all[] = "-A";
    char          prefix[] = "-f";
    char         *root = rs_xstrdup(r->root_path);
    char         *argv[5];
    size_t        n = 0;

    say(r, "make new SSH host keys in", "/etc/ssh");
    if (r->dry_run)
    {
        r->st->host_keys = true;
        free(root);
        return;
    }
    argv[n++] = a0;
    argv[n++] = all;
    if (strcmp(root, "/") != 0)
    {
        argv[n++] = prefix;
        argv[n++] = root;
    }
    argv[n] = NULL;
    rs_buf_init(&err);
    rs_buf_init(&out);
    if (!rs_run(RS_PROG_SSH_KEYGEN, argv, &out, &out, &code, &err) || code != 0)
    {
        failed(r, "/etc/ssh",
               err.len ? err.data
                       : "ssh-keygen -A did not make new host keys; run it before sshd starts");
    } else
    {
        r->st->host_keys = true;
    }
    rs_buf_free(&out);
    rs_buf_free(&err);
    free(root);
}

bool rs_identity_renew(const char *root, const struct rs_index *ix, const bool *leave,
                       const char *name, const char *old, bool dry_run, bool verbose,
                       struct rs_identity_stats *st, struct rs_buf *err)
{
    struct renew  r;
    char          id[34];
    char         *machine_id = NULL;
    struct rs_buf now;
    bool          keys = false;
    size_t        i;

    memset(st, 0, sizeof(*st));
    memset(&r, 0, sizeof(r));
    r.root = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (r.root < 0)
    {
        rs_buf_addf(err, "%s: %s", root, strerror(errno));
        return false;
    }
    r.root_path = root;
    r.dry_run = dry_run;
    r.verbose = verbose;
    r.st = st;
    /* The machine-id first, so D-Bus's copy can be given the new one. */
    if (new_machine_id(id))
    {
        machine_id = id;
    }
    for (i = 0; i < ix->count; i++)
    {
        if (leave[i] && strcmp(ix->entries[i].path, MACHINE_ID) == 0)
        {
            renew_one(&r, &ix->entries[i], machine_id, &keys);
        }
    }
    machine_id = NULL;
    if (rs_read_beneath(root, MACHINE_ID, sizeof(id), &now))
    {
        machine_id = rs_buf_detach(&now);
    } else if (dry_run)
    {
        machine_id = rs_xstrdup(id);
    }
    for (i = 0; i < ix->count; i++)
    {
        if (leave[i] && strcmp(ix->entries[i].path, MACHINE_ID) != 0)
        {
            renew_one(&r, &ix->entries[i], machine_id, &keys);
        }
    }
    free(machine_id);
    host_name(&r, name, old);
    /* Host keys for an SSH server: none to make where there is none. */
    if (keys && has_sshd(&r))
    {
        host_keys(&r);
    }
    (void)close(r.root);
    return true;
}
