/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "live.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "index.h"

/* What is read of any one file under /proc: a command line, a status file. */
#define PROC_MAX ((size_t)64 * 1024)
/* A mongod configuration file is read up to this much. */
#define CONFIG_MAX ((size_t)256 * 1024)

void rs_live_free(struct rs_live *l, size_t n)
{
    size_t i;
    size_t k;

    for (i = 0; i < n; i++)
    {
        free(l[i].name);
        for (k = 0; k < l[i].npaths; k++)
        {
            free(l[i].paths[k]);
        }
        free(l[i].paths);
    }
    free(l);
}

/* ------------------------------------------------------------------------- */
/* What /proc says                                                            */
/* ------------------------------------------------------------------------- */

void rs_live_split_args(const char *buf, size_t len, char ***argv, size_t *argc)
{
    size_t at = 0;

    *argv = NULL;
    *argc = 0;
    while (at < len)
    {
        const char *nul = memchr(buf + at, '\0', len - at);
        size_t      n = nul ? (size_t)(nul - (buf + at)) : len - at;

        *argv = rs_xreallocarray(*argv, *argc + 1, sizeof(**argv));
        (*argv)[(*argc)++] = rs_xstrndup(buf + at, n);
        at += n + 1;
    }
}

/* The number after `key` at the start of a line of `text`. */
static bool field(const char *text, const char *key, unsigned long *out)
{
    size_t      klen = strlen(key);
    const char *p = text;

    while (p && *p)
    {
        if (strncmp(p, key, klen) == 0)
        {
            const char *v = p + klen;
            char       *end;

            v += strspn(v, " \t");
            if (*v < '0' || *v > '9')
            {
                return false;
            }
            errno = 0;
            *out = strtoul(v, &end, 10);
            return errno == 0 && end != v;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return false;
}

bool rs_live_parse_status(const char *text, unsigned long *uid, long *ppid)
{
    unsigned long parent;

    if (!field(text, "Uid:", uid) || !field(text, "PPid:", &parent) || parent > LONG_MAX)
    {
        return false;
    }
    *ppid = (long)parent;
    return true;
}

bool rs_live_parse_fdflags(const char *text, unsigned long *flags)
{
    const char *p = text;

    while (p && *p)
    {
        if (strncmp(p, "flags:", 6) == 0)
        {
            const char *v = p + 6;
            char       *end;

            v += strspn(v, " \t");
            if (*v < '0' || *v > '7')
            {
                return false;
            }
            errno = 0;
            *flags = strtoul(v, &end, 8);
            return errno == 0 && end != v;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return false;
}

char *rs_live_mongo_dbpath(const char *text)
{
    const char *p = text;

    /* YAML, read as far as the one key matters: "dbPath: /x", indented under
     * "storage:", optionally quoted. Anything cleverer is not looked for. */
    while (p && *p)
    {
        const char *line = p + strspn(p, " \t");

        if (strncmp(line, "dbPath:", 7) == 0)
        {
            size_t      n = strcspn(line, "\n");
            const char *v = line + 7;
            size_t      vlen;

            v += strspn(v, " \t");
            vlen = (size_t)(line + n - v);
            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t' || v[vlen - 1] == '\r'))
            {
                vlen--;
            }
            if (vlen >= 2 && (v[0] == '"' || v[0] == '\'') && v[vlen - 1] == v[0])
            {
                v++;
                vlen -= 2;
            }
            return vlen > 0 ? rs_xstrndup(v, vlen) : NULL;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return NULL;
}

/* A file, whole, up to `max`; NULL if it cannot be read. */
static char *slurp(const char *path, size_t max, size_t *len)
{
    struct rs_buf b;
    char          chunk[4096];
    ssize_t       n;
    int           fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0)
    {
        return NULL;
    }
    rs_buf_init(&b);
    while (b.len < max && (n = read(fd, chunk, sizeof(chunk))) > 0)
    {
        rs_buf_add(&b, chunk, (size_t)n);
    }
    (void)close(fd);
    rs_buf_add(&b, "", 0);
    if (len)
    {
        *len = b.len;
    }
    return rs_buf_detach(&b);
}

/* What a symlink in /proc points at -- cwd, fd/N -- if it is a path. */
static char *proc_link(const char *path)
{
    char    buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1); /* Flawfinder: ignore */

    if (n <= 0 || buf[0] != '/')
    {
        return NULL;
    }
    buf[n] = '\0';
    return rs_xstrdup(buf);
}

/* `path` with every symlink resolved, if it is a directory or regular file
 * that exists; else NULL. The walk never follows a link, so it is given the
 * real path, and a container's directory is reached through one. */
static char *real(const char *path)
{
    /* With NULL, realpath allocates what it needs: no PATH_MAX overflow. */
    char       *r = realpath(path, NULL); /* Flawfinder: ignore */
    struct stat st;

    if (!r)
    {
        return NULL;
    }
    if (!rs_path_is_clean(r) || stat(r, &st) != 0 || (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)))
    {
        free(r);
        return NULL;
    }
    return r;
}

/* One process, as far as finding out what it is needs. */
struct proc {
    const char    *dir;     /* "/proc/1234" */
    long           pid;
    long           ppid;
    unsigned long  uid;
    char          *comm;
    char         **argv;
    size_t         argc;
};

static void proc_free(struct proc *p)
{
    size_t i;

    free(p->comm);
    for (i = 0; i < p->argc; i++)
    {
        free(p->argv[i]);
    }
    free(p->argv);
}

static bool proc_read(const char *proc, long pid, struct proc *p, char **dir)
{
    char  *path;
    char  *text;
    size_t len = 0;

    memset(p, 0, sizeof(*p));
    p->pid = pid;
    *dir = rs_xasprintf("%s/%ld", proc, pid);
    p->dir = *dir;
    path = rs_xasprintf("%s/status", *dir);
    text = slurp(path, PROC_MAX, NULL);
    free(path);
    if (!text || !rs_live_parse_status(text, &p->uid, &p->ppid))
    {
        free(text);
        return false;
    }
    free(text);
    path = rs_xasprintf("%s/comm", *dir);
    p->comm = slurp(path, 64, NULL);
    free(path);
    if (!p->comm)
    {
        return false;
    }
    p->comm[strcspn(p->comm, "\n")] = '\0';
    path = rs_xasprintf("%s/cmdline", *dir);
    text = slurp(path, PROC_MAX, &len);
    free(path);
    if (text)
    {
        /* slurp's terminating NUL is not part of the command line. */
        rs_live_split_args(text, len > 0 ? len - 1 : 0, &p->argv, &p->argc);
        free(text);
    }
    return true;
}

/* The value of `opt` in argv: "--datadir=/x", or "--datadir /x" (also "-D
 * /x" and "-D/x" for a one-letter one). NULL if it is not there. */
static const char *arg_value(const struct proc *p, const char *opt)
{
    size_t olen = strlen(opt);
    size_t i;

    for (i = 1; i < p->argc; i++)
    {
        const char *a = p->argv[i];

        if (strcmp(a, opt) == 0)
        {
            return i + 1 < p->argc ? p->argv[i + 1] : NULL;
        }
        if (strncmp(a, opt, olen) == 0 && (a[olen] == '=' || (olen == 2 && a[olen] != '\0')))
        {
            return a + olen + (a[olen] == '=' ? 1 : 0);
        }
    }
    return NULL;
}

static char *cwd_of(const struct proc *p)
{
    char *link = rs_xasprintf("%s/cwd", p->dir);
    char *where = proc_link(link);

    free(link);
    return where;
}

/* ------------------------------------------------------------------------- */
/* Collecting                                                                 */
/* ------------------------------------------------------------------------- */

struct found {
    struct rs_live *l;
    size_t          n;
};

static int by_string(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Whether `path` is `dir` or beneath it. */
static bool within(const char *path, const char *dir)
{
    size_t n = strlen(dir);

    return strncmp(path, dir, n) == 0 && (path[n] == '\0' || path[n] == '/' || strcmp(dir, "/") == 0);
}

static void add_path(struct rs_live *l, const char *path)
{
    char  *r = real(path);
    size_t i;

    if (!r || strcmp(r, "/") == 0)
    {
        free(r);
        return;
    }
    for (i = 0; i < l->npaths; i++)
    {
        if (within(r, l->paths[i]))
        {
            free(r);
            return;
        }
    }
    l->paths = rs_xreallocarray(l->paths, l->npaths + 1, sizeof(*l->paths));
    l->paths[l->npaths++] = r;
}

/* The paths sorted, and any beneath another taken out. */
static void tidy(struct rs_live *l)
{
    size_t i;
    size_t kept = 0;

    if (l->npaths > 1)
    {
        qsort(l->paths, l->npaths, sizeof(*l->paths), by_string);
    }
    for (i = 0; i < l->npaths; i++)
    {
        if (kept > 0 && within(l->paths[i], l->paths[kept - 1]))
        {
            free(l->paths[i]);
            continue;
        }
        l->paths[kept++] = l->paths[i];
    }
    l->npaths = kept;
}

static struct rs_live *add(struct found *f, const char *kind, const char *name,
                           const struct proc *p)
{
    struct rs_live *l;
    size_t          i;

    /* One of each: a database's many processes, found again. */
    for (i = 0; i < f->n; i++)
    {
        if (strcmp(f->l[i].kind, kind) == 0 && strcmp(f->l[i].name, name) == 0)
        {
            return &f->l[i];
        }
    }
    f->l = rs_xreallocarray(f->l, f->n + 1, sizeof(*f->l));
    l = &f->l[f->n++];
    memset(l, 0, sizeof(*l));
    l->kind = kind;
    l->name = rs_xstrdup(name);
    l->pid = p->pid;
    l->uid = p->uid;
    return l;
}

/* The last component of `path`. */
static const char *base(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash && slash[1] ? slash + 1 : path;
}

/* ------------------------------------------------------------------------- */
/* Each kind                                                                  */
/* ------------------------------------------------------------------------- */

#define DEBIAN_PG "/var/lib/postgresql/"

/* Whether `data` is a Debian cluster's data directory: DEBIAN_PG, then a
 * version of digits, then the cluster's name, and nothing more. */
static bool debian_cluster(const char *data)
{
    const char *v = data + strlen(DEBIAN_PG);
    size_t      digits;

    if (!rs_starts_with(data, DEBIAN_PG))
    {
        return false;
    }
    digits = strspn(v, "0123456789");
    return digits > 0 && v[digits] == '/' && v[digits + 1] != '\0' &&
           strchr(v + digits + 1, '/') == NULL;
}

/* A process's parent's comm, to tell a postmaster from its children. */
static char *parent_comm(const char *proc, long ppid)
{
    char *path = rs_xasprintf("%s/%ld/comm", proc, ppid);
    char *comm = slurp(path, 64, NULL);

    free(path);
    if (comm)
    {
        comm[strcspn(comm, "\n")] = '\0';
    }
    return comm;
}

static void postgresql(const char *proc, const struct proc *p, struct found *f)
{
    char       *parent = parent_comm(proc, p->ppid);
    const char *d = arg_value(p, "-D");
    char       *cwd = NULL;
    char       *data;
    char       *name;

    /* The postmaster: every other postgres process is its child. */
    if (parent && strcmp(parent, "postgres") == 0)
    {
        free(parent);
        return;
    }
    free(parent);
    if (!d)
    {
        cwd = cwd_of(p);
        d = cwd;
    }
    data = d ? real(d) : NULL;
    free(cwd);
    if (!data)
    {
        return;
    }
    /* Debian's layout names a cluster VERSION-NAME, as its unit does. */
    if (debian_cluster(data))
    {
        const char *v = data + strlen(DEBIAN_PG);

        name = rs_xstrdup(v);
        name[strcspn(name, "/")] = '-';
    } else
    {
        name = rs_xstrdup(base(data));
    }
    {
        struct rs_live *l = add(f, "postgresql", name, p);
        char           *tblspc = rs_xasprintf("%s/pg_tblspc", data);
        DIR            *dir = opendir(tblspc);
        struct dirent  *de;

        add_path(l, data);
        /* Each tablespace is a symlink here to a directory elsewhere. */
        while (dir && (de = readdir(dir)) != NULL)
        {
            if (de->d_name[0] != '.')
            {
                char *link = rs_xasprintf("%s/%s", tblspc, de->d_name);

                add_path(l, link);
                free(link);
            }
        }
        if (dir)
        {
            (void)closedir(dir);
        }
        free(tblspc);
    }
    free(name);
    free(data);
}

static void mysql(const struct proc *p, struct found *f)
{
    const char *d = arg_value(p, "--datadir");
    char       *cwd = d ? NULL : cwd_of(p);

    if (d || cwd)
    {
        add_path(add(f, "mysql", strcmp(p->comm, "mariadbd") == 0 ? "mariadb" : "mysql", p),
                 d ? d : cwd);
    }
    free(cwd);
}

static void mongodb(const struct proc *p, struct found *f)
{
    const char *d = arg_value(p, "--dbpath");
    const char *conf = arg_value(p, "--config");
    char       *from_conf = NULL;

    if (!conf)
    {
        conf = arg_value(p, "-f");
    }
    if (!d && conf && conf[0] == '/')
    {
        char *text = slurp(conf, CONFIG_MAX, NULL);

        from_conf = text ? rs_live_mongo_dbpath(text) : NULL;
        free(text);
    }
    add_path(add(f, "mongodb", "mongod", p), d ? d : from_conf ? from_conf : "/var/lib/mongodb");
    free(from_conf);
}

static void redis(const struct proc *p, struct found *f)
{
    char *cwd = cwd_of(p);

    /* Its "dir", where it writes dump.rdb and its append-only file, is
     * where it runs; "/" is a redis with no persistence configured. */
    if (cwd && strcmp(cwd, "/") != 0)
    {
        add_path(add(f, "redis", "redis-server", p), cwd);
    }
    free(cwd);
}

/* A regular file a VM holds open for writing: a disk, an NVRAM store, and
 * also its pid file or a log, which the rules leave out of the walk anyway. */
static bool vm_file(const char *path)
{
    static const char *const not[] = { "/dev/", "/proc/", "/sys/" };
    size_t                   i;
    struct stat              st;

    for (i = 0; i < sizeof(not) / sizeof(not[0]); i++)
    {
        if (rs_starts_with(path, not[i]))
        {
            return false;
        }
    }
    return strstr(path, " (deleted)") == NULL && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static void qemu(const struct proc *p, struct found *f)
{
    const char     *n = arg_value(p, "-name");
    char           *name;
    char           *fds;
    DIR            *dir;
    struct dirent  *de;
    struct rs_live *l;

    if (!n)
    {
        return;
    }
    /* "-name guest=NAME,debug-threads=on" as libvirt writes it, or "NAME". */
    if (rs_starts_with(n, "guest="))
    {
        n += 6;
    }
    name = rs_xstrndup(n, strcspn(n, ","));
    if (name[0] == '\0')
    {
        free(name);
        return;
    }
    l = add(f, "libvirt", name, p);
    free(name);
    fds = rs_xasprintf("%s/fd", p->dir);
    dir = opendir(fds);
    while (dir && (de = readdir(dir)) != NULL)
    {
        char         *link;
        char         *info;
        char         *target;
        char         *text;
        unsigned long flags = 0;

        if (de->d_name[0] == '.')
        {
            continue;
        }
        link = rs_xasprintf("%s/%s", fds, de->d_name);
        info = rs_xasprintf("%s/fdinfo/%s", p->dir, de->d_name);
        target = proc_link(link);
        text = target ? slurp(info, PROC_MAX, NULL) : NULL;
        /* Open for writing: O_WRONLY or O_RDWR. A read-only installer ISO
         * does not change under the copy. */
        if (text && rs_live_parse_fdflags(text, &flags) && (flags & 3) != 0 && vm_file(target))
        {
            add_path(l, target);
        }
        free(text);
        free(target);
        free(info);
        free(link);
    }
    if (dir)
    {
        (void)closedir(dir);
    }
    free(fds);
}

static void lxd(const struct proc *p, struct found *f)
{
    /* "[lxc monitor] /var/snap/lxd/common/lxd/containers NAME", as one
     * argument: the monitor renames itself. */
    const char *a = p->argc > 0 ? p->argv[0] : "";
    const char *dir;
    const char *space;
    char       *path;

    if (!rs_starts_with(a, "[lxc monitor] "))
    {
        return;
    }
    dir = a + 14;
    space = strrchr(dir, ' ');
    if (!space || space == dir || space[1] == '\0' || strchr(space + 1, '/'))
    {
        return;
    }
    path = rs_xasprintf("%.*s/%s", (int)(space - dir), dir, space + 1);
    add_path(add(f, "lxd", space + 1, p), path);
    free(path);
}

static void docker(const struct proc *p, struct found *f, bool containers)
{
    const char *root = arg_value(p, "--data-root");
    char       *volumes;

    /* Containers write to their volumes; with none running nothing does. */
    if (!containers)
    {
        return;
    }
    volumes = rs_xasprintf("%s/volumes", root ? root : "/var/lib/docker");
    add_path(add(f, "docker", "docker", p), volumes);
    free(volumes);
}

static bool numeric(const char *s)
{
    return s[0] != '\0' && strspn(s, "0123456789") == strlen(s);
}

/* Whether a docker container is running: its shim, in docker's namespace. */
static bool docker_shim(const struct proc *p)
{
    const char *ns = arg_value(p, "-namespace");

    return rs_starts_with(p->comm, "containerd-shim") && ns && strcmp(ns, "moby") == 0;
}

static int by_kind_name(const void *a, const void *b)
{
    const struct rs_live *x = a;
    const struct rs_live *y = b;
    int                   c = strcmp(x->kind, y->kind);

    return c ? c : strcmp(x->name, y->name);
}

void rs_live_detect(const char *proc, struct rs_live **out, size_t *n)
{
    DIR                 *dir = opendir(proc);
    const struct dirent *de;
    struct found         f;
    struct proc          dockerd;
    char                *dockerd_dir = NULL;
    bool                 have_dockerd = false;
    bool                 containers = false;
    size_t               i;

    memset(&f, 0, sizeof(f));
    memset(&dockerd, 0, sizeof(dockerd));
    while (dir && (de = readdir(dir)) != NULL)
    {
        struct proc p;
        char       *pdir = NULL;
        long        pid;

        if (!numeric(de->d_name) || strlen(de->d_name) > 9)
        {
            continue;
        }
        pid = strtol(de->d_name, NULL, 10);
        if (!proc_read(proc, pid, &p, &pdir))
        {
            proc_free(&p);
            free(pdir);
            continue;
        }
        if (strcmp(p.comm, "postgres") == 0)
        {
            postgresql(proc, &p, &f);
        } else if (strcmp(p.comm, "mysqld") == 0 || strcmp(p.comm, "mariadbd") == 0)
        {
            mysql(&p, &f);
        } else if (strcmp(p.comm, "mongod") == 0)
        {
            mongodb(&p, &f);
        } else if (strcmp(p.comm, "redis-server") == 0)
        {
            redis(&p, &f);
        } else if (rs_starts_with(p.comm, "qemu-system") || strcmp(p.comm, "qemu-kvm") == 0)
        {
            qemu(&p, &f);
        } else if (p.argc > 0 && rs_starts_with(p.argv[0], "[lxc monitor] "))
        {
            lxd(&p, &f);
        } else if (strcmp(p.comm, "dockerd") == 0 && !have_dockerd)
        {
            /* Kept until every process is seen: whether it matters depends
             * on whether any container is running. */
            dockerd = p;
            dockerd_dir = pdir;
            have_dockerd = true;
            continue;
        }
        containers = containers || docker_shim(&p);
        proc_free(&p);
        free(pdir);
    }
    if (dir)
    {
        (void)closedir(dir);
    }
    if (have_dockerd)
    {
        docker(&dockerd, &f, containers);
        proc_free(&dockerd);
        free(dockerd_dir);
    }
    /* Something whose files could not be found is nothing to pause. */
    for (i = 0; i < f.n; )
    {
        tidy(&f.l[i]);
        if (f.l[i].npaths == 0)
        {
            free(f.l[i].name);
            free(f.l[i].paths);
            f.l[i] = f.l[--f.n];
            continue;
        }
        i++;
    }
    if (f.n > 1)
    {
        qsort(f.l, f.n, sizeof(*f.l), by_kind_name);
    }
    *out = f.l;
    *n = f.n;
}

const char *rs_live_what(const struct rs_live *l)
{
    static const struct {
        const char *kind;
        const char *what;
    } names[] = {
        { "postgresql", "PostgreSQL" }, { "mysql", "MySQL" },       { "mongodb", "MongoDB" },
        { "redis", "Redis" },           { "libvirt", "the VM" },    { "lxd", "the LXD container" },
        { "docker", "Docker" },
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        if (strcmp(names[i].kind, l->kind) == 0)
        {
            return strcmp(l->kind, "mysql") == 0 && strcmp(l->name, "mariadb") == 0 ? "MariaDB"
                                                                                     : names[i].what;
        }
    }
    return l->kind;
}

void rs_live_hint(const struct rs_live *l, struct rs_buf *out)
{
    if (strcmp(l->kind, "postgresql") == 0)
    {
        size_t digits = strspn(l->name, "0123456789");

        /* A Debian cluster, VERSION-NAME, has a unit of its own. */
        if (digits > 0 && l->name[digits] == '-' && l->name[digits + 1] != '\0')
        {
            rs_buf_addstr(out, "systemctl stop postgresql@");
            rs_shell_word(out, l->name);
        } else
        {
            rs_buf_addstr(out, "systemctl stop postgresql");
        }
    } else if (strcmp(l->kind, "mysql") == 0)
    {
        rs_buf_addf(out, "systemctl stop %s", l->name);
    } else if (strcmp(l->kind, "mongodb") == 0)
    {
        rs_buf_addstr(out, "systemctl stop mongod");
    } else if (strcmp(l->kind, "redis") == 0)
    {
        rs_buf_addstr(out, "systemctl stop redis-server");
    } else if (strcmp(l->kind, "libvirt") == 0)
    {
        rs_buf_addstr(out, l->uid == 0 ? "virsh suspend " : "virsh -c qemu:///session suspend ");
        rs_shell_word(out, l->name);
    } else if (strcmp(l->kind, "lxd") == 0)
    {
        rs_buf_addstr(out, "lxc pause ");
        rs_shell_word(out, l->name);
    } else
    {
        rs_buf_addstr(out, "docker pause $(docker ps -q)");
    }
}
