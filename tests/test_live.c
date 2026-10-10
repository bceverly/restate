/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hooks.h"
#include "live.h"
#include "run.h"
#include "test.h"

static void mkdirs(const char *base, const char *rel)
{
    char *path = rs_xasprintf("%s/%s", base, rel);
    char *p;

    for (p = path + strlen(base) + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            (void)mkdir(path, 0755);
            *p = '/';
        }
    }
    (void)mkdir(path, 0755);
    free(path);
}

static void link_to(const char *base, const char *rel, const char *target)
{
    char *path = rs_xasprintf("%s/%s", base, rel);

    CHECK(symlink(target, path) == 0);
    free(path);
}

/* A file with embedded NULs, as a cmdline is. */
static void write_bytes(const char *base, const char *rel, const char *data, size_t len)
{
    char *path = rs_xasprintf("%s/%s", base, rel);
    int   fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    CHECK(fd >= 0 && write(fd, data, len) == (ssize_t)len);
    if (fd >= 0)
    {
        (void)close(fd);
    }
    free(path);
}

/* One process under the fake /proc: its status, comm and cmdline. */
static void process(const char *proc, long pid, long ppid, unsigned uid, const char *comm,
                    const char *cmdline, size_t cmdlen)
{
    char *dir = rs_xasprintf("%ld", pid);
    char *rel;
    char *text;

    mkdirs(proc, dir);
    rel = rs_xasprintf("%s/status", dir);
    text = rs_xasprintf("Name:\t%s\nUmask:\t0022\nPPid:\t%ld\nUid:\t%u\t%u\t%u\t%u\n", comm,
                        ppid, uid, uid, uid, uid);
    rs_test_write(proc, rel, text, 0644);
    free(text);
    free(rel);
    rel = rs_xasprintf("%s/comm", dir);
    text = rs_xasprintf("%s\n", comm);
    rs_test_write(proc, rel, text, 0644);
    free(text);
    free(rel);
    rel = rs_xasprintf("%s/cmdline", dir);
    write_bytes(proc, rel, cmdline, cmdlen);
    free(rel);
    free(dir);
}

#define ARGS(s) s, sizeof(s)

/* A command line from its arguments, each NUL-terminated, into `b`. */
static void args(struct rs_buf *b, const char *a0, const char *a1, const char *a2)
{
    rs_buf_init(b);
    rs_buf_add(b, a0, strlen(a0) + 1);
    if (a1)
    {
        rs_buf_add(b, a1, strlen(a1) + 1);
    }
    if (a2)
    {
        rs_buf_add(b, a2, strlen(a2) + 1);
    }
}

static const struct rs_live *find(const struct rs_live *l, size_t n, const char *kind,
                                  const char *name)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        if (strcmp(l[i].kind, kind) == 0 && strcmp(l[i].name, name) == 0)
        {
            return &l[i];
        }
    }
    return NULL;
}

static char *hint_of(const struct rs_live *l)
{
    struct rs_buf b;

    rs_buf_init(&b);
    rs_live_hint(l, &b);
    return rs_buf_detach(&b);
}

static int run_env(const void *arg)
{
    char         *argv[] = { (char *)(uintptr_t)"env", NULL };
    char         *env[] = { (char *)(uintptr_t)"RESTATE_TEST=yes", NULL };
    int           code = -1;
    bool          ok;
    struct rs_buf err;

    (void)arg;
    rs_buf_init(&err);
    ok = rs_run_hook("/usr/bin/env", argv, env, 30, &code, &err);
    rs_buf_free(&err);
    return ok ? code : -1;
}

/*
 * The test directory as realpath() gives it, since that is how detection
 * reports paths: on macOS the temporary directory is under /var, a link to
 * /private/var, and $TMPDIR ends in a slash.
 */
static char *real_tmpdir(void)
{
    char *dir = rs_test_tmpdir();
    char *real = realpath(dir, NULL);

    if (real == NULL)
    {
        return dir;
    }
    free(dir);
    return real;
}

void test_live(void)
{
    char           *dir = real_tmpdir();
    char           *proc = rs_xasprintf("%s/proc", dir);
    struct rs_live *l = NULL;
    size_t          n = 0;

    TEST_CASE("live: what /proc says, piece by piece");
    {
        char        **argv;
        size_t        argc;
        unsigned long uid = 0;
        unsigned long flags = 0;
        long          ppid = 0;
        char         *path;

        rs_live_split_args("a\0bc\0\0d", 7, &argv, &argc);
        CHECK_INT(argc, 4);
        CHECK_STR(argc == 4 ? argv[1] : "", "bc");
        CHECK_STR(argc == 4 ? argv[2] : "x", "");
        CHECK_STR(argc == 4 ? argv[3] : "", "d");
        while (argc > 0)
        {
            free(argv[--argc]);
        }
        free(argv);
        rs_live_split_args("", 0, &argv, &argc);
        CHECK_INT(argc, 0);
        free(argv);

        CHECK(rs_live_parse_status("Name:\tx\nPPid:\t7\nUid:\t133\t133\t133\t133\n", &uid, &ppid));
        CHECK_INT(uid, 133);
        CHECK_INT(ppid, 7);
        CHECK(!rs_live_parse_status("PPid:\t7\n", &uid, &ppid));
        CHECK(!rs_live_parse_status("Uid:\tx\nPPid:\t1\n", &uid, &ppid));
        CHECK(!rs_live_parse_status("Uid:\t1\nPPid:\t99999999999999999999999\n", &uid, &ppid));
        CHECK(rs_live_parse_fdflags("pos:\t0\nflags:\t0100002\nmnt_id:\t9\n", &flags));
        CHECK_INT(flags, 0100002);
        CHECK(!rs_live_parse_fdflags("pos:\t0\n", &flags));
        CHECK(!rs_live_parse_fdflags("flags:\t9\n", &flags));

        path = rs_live_mongo_dbpath("storage:\n  dbPath: /var/lib/mongo  \n");
        CHECK_STR(path ? path : "", "/var/lib/mongo");
        free(path);
        path = rs_live_mongo_dbpath("storage:\n  dbPath: \"/srv/db\"\r\n");
        CHECK_STR(path ? path : "", "/srv/db");
        free(path);
        CHECK(rs_live_mongo_dbpath("storage:\n  dbPath:\n") == NULL);
        CHECK(rs_live_mongo_dbpath("net:\n  port: 1\n") == NULL);
    }

    TEST_CASE("live: no /proc, nothing running");
    rs_live_detect("/nonexistent/proc", &l, &n);
    CHECK_INT(n, 0);
    rs_live_free(l, n);

    TEST_CASE("live: every kind found, with its files, and nothing else");
    mkdirs(dir, "pg/main/pg_tblspc");
    mkdirs(dir, "ts1");
    mkdirs(dir, "mysql");
    mkdirs(dir, "maria");
    mkdirs(dir, "mongo");
    mkdirs(dir, "redis");
    mkdirs(dir, "pool/c1");
    mkdirs(dir, "containers");
    mkdirs(dir, "docker/volumes");
    rs_test_write(dir, "disk.qcow2", "disk", 0644);
    rs_test_write(dir, "vars.fd", "nvram", 0644);
    rs_test_write(dir, "install.iso", "iso", 0644);
    {
        char *t = rs_xasprintf("%s/ts1", dir);
        char *c = rs_xasprintf("%s/pool/c1", dir);
        char *conf = rs_xasprintf("storage:\n  dbPath: %s/mongo\n", dir);

        link_to(dir, "pg/main/pg_tblspc/16384", t);
        link_to(dir, "containers/c1", c);
        rs_test_write(dir, "mongod.conf", conf, 0644);
        free(conf);
        free(c);
        free(t);
    }
    mkdirs(dir, "proc");
    process(proc, 1, 0, 0, "systemd", ARGS("/sbin/init\0splash"));
    {
        struct rs_buf cmd;

        /* The postmaster, by -D; a child of it, passed over. */
        {
            char *d = rs_xasprintf("%s/pg/main", dir);

            args(&cmd, "/usr/lib/postgresql/18/bin/postgres", "-D", d);
            process(proc, 100, 1, 133, "postgres", cmd.data, cmd.len);
            rs_buf_free(&cmd);
            free(d);
        }
        process(proc, 101, 100, 133, "postgres", ARGS("postgres: checkpointer"));

        /* MySQL by where it runs; MariaDB by --datadir=. */
        process(proc, 200, 1, 110, "mysqld", ARGS("/usr/sbin/mysqld"));
        {
            char *target = rs_xasprintf("%s/mysql", dir);

            link_to(proc, "200/cwd", target);
            free(target);
        }
        {
            char *d = rs_xasprintf("--datadir=%s/maria", dir);

            args(&cmd, "/usr/sbin/mariadbd", d, NULL);
            process(proc, 201, 1, 110, "mariadbd", cmd.data, cmd.len);
            rs_buf_free(&cmd);
            free(d);
        }

        /* mongod by the dbPath in its --config. */
        {
            char *d = rs_xasprintf("%s/mongod.conf", dir);

            args(&cmd, "/usr/bin/mongod", "--config", d);
            process(proc, 300, 1, 120, "mongod", cmd.data, cmd.len);
            rs_buf_free(&cmd);
            free(d);
        }

        /* Redis where it runs; one with no "dir" set runs in /. */
        process(proc, 400, 1, 121, "redis-server", ARGS("/usr/bin/redis-server 127.0.0.1:6379"));
        {
            char *target = rs_xasprintf("%s/redis", dir);

            link_to(proc, "400/cwd", target);
            free(target);
        }
        process(proc, 401, 1, 121, "redis-server", ARGS("/usr/bin/redis-server *:6380"));
        link_to(proc, "401/cwd", "/");

        /* A user's VM: its disk and NVRAM open for writing, an ISO read. */
        process(proc, 500, 1, 1000, "qemu-system-x86",
                ARGS("/usr/bin/qemu-system-x86_64\0-name\0guest=vm1,debug-threads=on\0-S"));
        mkdirs(proc, "500/fd");
        mkdirs(proc, "500/fdinfo");
        {
            char *disk = rs_xasprintf("%s/disk.qcow2", dir);
            char *vars = rs_xasprintf("%s/vars.fd", dir);
            char *iso = rs_xasprintf("%s/install.iso", dir);

            link_to(proc, "500/fd/3", disk);
            rs_test_write(proc, "500/fdinfo/3", "pos:\t0\nflags:\t02100002\n", 0644);
            link_to(proc, "500/fd/4", vars);
            rs_test_write(proc, "500/fdinfo/4", "pos:\t0\nflags:\t02100002\n", 0644);
            link_to(proc, "500/fd/5", iso);
            rs_test_write(proc, "500/fdinfo/5", "pos:\t0\nflags:\t02100000\n", 0644);
            link_to(proc, "500/fd/6", "/dev/null");
            rs_test_write(proc, "500/fdinfo/6", "pos:\t0\nflags:\t02\n", 0644);
            link_to(proc, "500/fd/7", "pipe:[1234]");
            free(iso);
            free(vars);
            free(disk);
        }
        /* A QEMU with no name is not one libvirt could pause. */
        process(proc, 501, 1, 0, "qemu-system-x86", ARGS("/usr/bin/qemu-system-x86_64\0-S"));

        /* An LXD container, through the symlink to its storage pool. */
        rs_buf_init(&cmd);
        rs_buf_addf(&cmd, "[lxc monitor] %s/containers c1", dir);
        process(proc, 600, 1, 0, "lxd", cmd.data, cmd.len + 1);
        rs_buf_free(&cmd);
        process(proc, 601, 1, 0, "lxd", ARGS("[lxc monitor] /x/containers a/b"));

        /* dockerd, which matters only with a container running. */
        {
            char *d = rs_xasprintf("%s/docker", dir);

            args(&cmd, "/usr/bin/dockerd", "--data-root", d);
            process(proc, 700, 1, 0, "dockerd", cmd.data, cmd.len);
            rs_buf_free(&cmd);
            free(d);
        }
        process(proc, 701, 1, 0, "containerd-shim",
                ARGS("/usr/bin/containerd-shim-runc-v2\0-namespace\0moby\0-id\0abc"));
    }
    /* A process whose status is not what /proc writes is passed over. */
    mkdirs(proc, "800");
    rs_test_write(proc, "800/status", "nothing\n", 0644);
    mkdirs(proc, "self");

    rs_live_detect(proc, &l, &n);
    CHECK_INT(n, 8);
    {
        const struct rs_live *pg = find(l, n, "postgresql", "main");
        const struct rs_live *my = find(l, n, "mysql", "mysql");
        const struct rs_live *ma = find(l, n, "mysql", "mariadb");
        const struct rs_live *mo = find(l, n, "mongodb", "mongod");
        const struct rs_live *re = find(l, n, "redis", "redis-server");
        const struct rs_live *vm = find(l, n, "libvirt", "vm1");
        const struct rs_live *ct = find(l, n, "lxd", "c1");
        const struct rs_live *dk = find(l, n, "docker", "docker");
        char                 *want;
        char                 *hint;

        CHECK(pg && my && ma && mo && re && vm && ct && dk);
        CHECK_STR(n == 8 ? l[0].kind : "", "docker");
        CHECK_STR(n == 8 ? l[7].kind : "", "redis");
        if (pg)
        {
            CHECK_INT(pg->pid, 100);
            CHECK_INT(pg->uid, 133);
            CHECK_INT(pg->npaths, 2);
            want = rs_xasprintf("%s/pg/main", dir);
            CHECK_STR(pg->npaths == 2 ? pg->paths[0] : "", want);
            free(want);
            want = rs_xasprintf("%s/ts1", dir);
            CHECK_STR(pg->npaths == 2 ? pg->paths[1] : "", want);
            free(want);
            CHECK_STR(rs_live_what(pg), "PostgreSQL");
            hint = hint_of(pg);
            CHECK_STR(hint, "systemctl stop postgresql");
            free(hint);
        }
        if (vm)
        {
            CHECK_INT(vm->npaths, 2);
            CHECK_INT(vm->uid, 1000);
            want = rs_xasprintf("%s/disk.qcow2", dir);
            CHECK_STR(vm->npaths == 2 ? vm->paths[0] : "", want);
            free(want);
            hint = hint_of(vm);
            CHECK_STR(hint, "virsh -c qemu:///session suspend vm1");
            free(hint);
            CHECK_STR(rs_live_what(vm), "the VM");
        }
        if (ct)
        {
            want = rs_xasprintf("%s/pool/c1", dir);
            CHECK_STR(ct->npaths == 1 ? ct->paths[0] : "", want);
            free(want);
            hint = hint_of(ct);
            CHECK_STR(hint, "lxc pause c1");
            free(hint);
        }
        if (dk)
        {
            want = rs_xasprintf("%s/docker/volumes", dir);
            CHECK_STR(dk->npaths == 1 ? dk->paths[0] : "", want);
            free(want);
            hint = hint_of(dk);
            CHECK_STR(hint, "docker pause $(docker ps -q)");
            free(hint);
            CHECK_STR(rs_live_what(dk), "Docker");
        }
        if (mo)
        {
            want = rs_xasprintf("%s/mongo", dir);
            CHECK_STR(mo->npaths == 1 ? mo->paths[0] : "", want);
            free(want);
            hint = hint_of(mo);
            CHECK_STR(hint, "systemctl stop mongod");
            free(hint);
        }
        if (ma && my && re)
        {
            CHECK_STR(rs_live_what(ma), "MariaDB");
            CHECK_STR(rs_live_what(my), "MySQL");
            CHECK_STR(rs_live_what(re), "Redis");
            hint = hint_of(ma);
            CHECK_STR(hint, "systemctl stop mariadb");
            free(hint);
            hint = hint_of(re);
            CHECK_STR(hint, "systemctl stop redis-server");
            free(hint);
        }
    }
    rs_live_free(l, n);

    TEST_CASE("live: a Debian cluster is named as its unit is, a root VM by system");
    {
        struct rs_live one;
        char          *paths[1] = { NULL };
        char          *hint;

        memset(&one, 0, sizeof(one));
        one.kind = "postgresql";
        one.name = (char *)(uintptr_t)"18-main";
        one.paths = paths;
        hint = hint_of(&one);
        CHECK_STR(hint, "systemctl stop postgresql@18-main");
        free(hint);
        one.kind = "libvirt";
        one.name = (char *)(uintptr_t)"my vm";
        hint = hint_of(&one);
        CHECK_STR(hint, "virsh suspend 'my vm'");
        free(hint);
        one.kind = "something";
        CHECK_STR(rs_live_what(&one), "something");
    }

    TEST_CASE("hooks: found only where root alone could have put them");
    {
        static const char *const none[] = { "/nonexistent" };
        static const char *const usr[] = { "/nonexistent", "/usr/bin" };
        char                    *hook;

        rs_hooks_set_dirs(none, 1);
        CHECK(rs_hook_find("true") == NULL);
        rs_hooks_set_dirs(usr, 2);
        hook = rs_hook_find("true");
        CHECK_STR(hook ? hook : "", "/usr/bin/true");
        free(hook);
        CHECK(rs_hook_find("../bin/true") == NULL);
        CHECK(rs_hook_find(".hidden") == NULL);
        CHECK(rs_hook_find("") == NULL);
        rs_hooks_set_dirs(NULL, 0);
        /* The real directories: nothing called this is installed. */
        CHECK(rs_hook_find("restate-no-such-hook") == NULL);
    }

    TEST_CASE("hooks: run, with what they need, and stopped if they hang");
    {
        struct rs_live one;
        char          *paths[2];
        struct rs_buf  err;
        char          *mine = rs_xasprintf("%s/mine", dir);
        char          *out = NULL;
        char          *errs = NULL;

        memset(&one, 0, sizeof(one));
        paths[0] = rs_xstrdup("/var/lib/x");
        paths[1] = rs_xstrdup("/var/lib/y");
        one.kind = "postgresql";
        one.name = rs_xstrdup("18-main");
        one.uid = 0;
        one.pid = 42;
        one.paths = paths;
        one.npaths = 2;
        rs_buf_init(&err);
        CHECK(rs_hook_run("/usr/bin/true", "pause", &one, "/var/lib/restate/dumps/x", &err));
        CHECK(!rs_hook_run("/usr/bin/false", "resume", &one, NULL, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "resume 18-main exited 1");
        rs_buf_reset(&err);
        /* Anyone's file is not run, however executable. */
        rs_test_write(dir, "mine", "#!/bin/sh\nexit 0\n", 0755);
        /* Run as root, as on the BSD runners, the file would be root's. */
        if (geteuid() == 0)
        {
            CHECK(chown(mine, 1, (gid_t)-1) == 0);
        }
        CHECK(!rs_hook_run(mine, "pause", &one, NULL, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "not run");
        rs_buf_reset(&err);
        {
            char *argv[] = { (char *)(uintptr_t)"sleep", (char *)(uintptr_t)"10", NULL };
            int   code = -1;

            /* /bin/sleep on the BSDs and macOS, which have no /usr/bin/sleep. */
            CHECK(!rs_run_hook(rs_hook_usable("/bin/sleep") ? "/bin/sleep" : "/usr/bin/sleep", argv,
                               NULL, 1, &code, &err));
            CHECK_CONTAINS(err.data ? err.data : "", "longer than 1 seconds");
            CHECK_INT(code, 128 + 15);
        }
        rs_buf_reset(&err);
        CHECK_INT(rs_test_capture(run_env, NULL, &out, &errs), 0);
        CHECK_CONTAINS(out, "RESTATE_TEST=yes\n");
        CHECK_CONTAINS(out, "LC_ALL=C\n");
        CHECK_CONTAINS(out, "/snap/bin\n");
        CHECK(strstr(out, "HOME=") == NULL);
        free(out);
        free(errs);
        rs_buf_free(&err);
        free(paths[0]);
        free(paths[1]);
        free(one.name);
        free(mine);
    }

    TEST_CASE("hooks: a dump directory, root's alone, never through a symlink");
    {
        struct rs_live one;
        struct rs_buf  err;
        char          *tree = NULL;
        char          *root = rs_xasprintf("%s/root", dir);
        char          *full;
        struct stat    st;

        memset(&one, 0, sizeof(one));
        one.kind = "libvirt";
        one.name = rs_xstrdup("my vm/1");
        rs_buf_init(&err);
        mkdirs(dir, "root/var/lib");
        CHECK(rs_hook_dump_dir(root, &one, &tree, &err));
        CHECK_STR(tree ? tree : "", "/var/lib/restate/dumps/libvirt-my_vm_1");
        full = rs_xasprintf("%s%s", root, tree ? tree : "");
        CHECK(stat(full, &st) == 0 && (st.st_mode & 07777) == 0700);
        /* Made already: the same again. */
        free(tree);
        tree = NULL;
        CHECK(rs_hook_dump_dir(root, &one, &tree, &err));
        free(tree);
        free(full);
        tree = NULL;
        /* /var a symlink: refused. */
        full = rs_xasprintf("%s/root2", dir);
        mkdirs(dir, "root2");
        link_to(dir, "root2/var", root);
        CHECK(!rs_hook_dump_dir(full, &one, &tree, &err));
        CHECK_CONTAINS(err.data ? err.data : "", "/var/lib/restate/dumps/libvirt-my_vm_1");
        CHECK(tree == NULL);
        free(full);
        rs_buf_free(&err);
        free(one.name);
        free(root);
    }

    free(proc);
    rs_test_rmtree(dir);
    free(dir);
}
