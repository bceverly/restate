/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "identity.h"
#include "index.h"
#include "packages.h"
#include "rules.h"
#include "run.h"
#include "sha256.h"
#include "test.h"

/* Writes `text` to dir/rel, making the directories on the way. */
static void put(const char *dir, const char *rel, const char *text)
{
    char  *path = rs_xasprintf("%s/%s", dir, rel);
    size_t i;
    int    fd;

    (void)mkdir(dir, 0755);
    for (i = strlen(dir) + 1; path[i] != '\0'; i++)
    {
        if (path[i] == '/')
        {
            path[i] = '\0';
            (void)mkdir(path, 0755);
            path[i] = '/';
        }
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    if (fd >= 0)
    {
        CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
        (void)close(fd);
    }
    free(path);
}

/* What dir/rel holds, or NULL. */
static char *got(const char *dir, const char *rel)
{
    struct rs_buf b;
    char         *path = rs_xasprintf("/%s", rel);

    if (!rs_read_beneath(dir, path, 65536, &b))
    {
        free(path);
        return NULL;
    }
    free(path);
    return rs_buf_detach(&b);
}

static bool there(const char *dir, const char *rel)
{
    char       *path = rs_xasprintf("%s/%s", dir, rel);
    struct stat st;
    bool        yes = lstat(path, &st) == 0;

    free(path);
    return yes;
}

/* An entry as a capture of `text` would record it: a regular file, with
 * its digest unless `hashed` is false. */
static void entry(struct rs_index *ix, const char *path, const char *text, bool hashed,
                  enum rs_class cls)
{
    struct rs_entry e;

    memset(&e, 0, sizeof(e));
    e.path = rs_xstrdup(path);
    e.type = 'f';
    e.mode = 0644;
    e.cls = cls;
    e.size = strlen(text);
    e.mtime.set = true;
    e.mtime.sec = 1000;
    if (hashed)
    {
        rs_sha256_hex(text, strlen(text), e.hash);
        e.hash_state = RS_HASH_PRESENT;
    }
    rs_index_add(ix, &e);
}

static void other(struct rs_index *ix, const char *path, char type, const char *target)
{
    struct rs_entry e;

    memset(&e, 0, sizeof(e));
    e.path = rs_xstrdup(path);
    e.type = type;
    e.mode = type == 'd' ? 0755 : 0777;
    e.cls = RS_CLASS_IDENTITY;
    e.target = target ? rs_xstrdup(target) : NULL;
    rs_index_add(ix, &e);
}

struct renew_run {
    const char               *root;
    const struct rs_index    *ix;
    const bool               *leave;
    const char               *name;
    const char               *old;
    bool                      dry_run;
    bool                      verbose;
    struct rs_identity_stats  st;
    bool                      ok;
};

static int run_renew(const void *arg)
{
    struct renew_run *r = (struct renew_run *)(uintptr_t)arg;
    struct rs_buf     err;

    rs_buf_init(&err);
    r->ok = rs_identity_renew(r->root, r->ix, r->leave, r->name, r->old, r->dry_run, r->verbose,
                              &r->st, &err);
    rs_buf_free(&err);
    return r->ok ? 0 : 1;
}

/* What the image recorded, for the renewing cases. */
static void image(struct rs_index *ix)
{
    rs_index_init(ix);
    entry(ix, "/etc/machine-id", "0123456789abcdef0123456789abcdef\n", true, RS_CLASS_IDENTITY);
    entry(ix, "/var/lib/dbus/machine-id", "0123456789abcdef0123456789abcdef\n", true,
          RS_CLASS_IDENTITY);
    entry(ix, "/var/lib/systemd/random-seed", "seed", true, RS_CLASS_IDENTITY);
    entry(ix, "/etc/hostname", "oldbox\n", true, RS_CLASS_IDENTITY);
    entry(ix, "/etc/ssh/ssh_host_ed25519_key", "KEY\n", true, RS_CLASS_IDENTITY);
    entry(ix, "/etc/ssh/ssh_host_ed25519_key.pub", "PUB\n", true, RS_CLASS_IDENTITY);
    entry(ix, "/var/lib/tailscale/tailscaled.state", "node\n", false, RS_CLASS_IDENTITY);
    entry(ix, "/etc/hosts", "127.0.1.1 oldbox\n", true, RS_CLASS_STATE);
    other(ix, "/etc/wireguard", 'd', NULL);
    other(ix, "/var/lib/cloud/instance", 'l', "instances/i-1");
}

/* The image's own files laid down under `root`, as on a copy of its disk. */
static void as_image(const char *root)
{
    char *p;

    put(root, "etc/machine-id", "0123456789abcdef0123456789abcdef\n");
    put(root, "var/lib/dbus/machine-id", "0123456789abcdef0123456789abcdef\n");
    put(root, "var/lib/systemd/random-seed", "seed");
    put(root, "etc/hostname", "oldbox\n");
    put(root, "etc/ssh/ssh_host_ed25519_key", "KEY\n");
    put(root, "etc/ssh/ssh_host_ed25519_key.pub", "PUB\n");
    put(root, "var/lib/tailscale/tailscaled.state", "node\n");
    put(root, "etc/hosts", "127.0.0.1 localhost\n127.0.1.1\toldbox oldbox.lan # me\n");
    put(root, "usr/sbin/sshd", "");
    p = rs_xasprintf("%s/var/lib/tailscale/tailscaled.state", root);
    {
        struct timespec times[2];

        times[0].tv_sec = 1000;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        CHECK(utimensat(AT_FDCWD, p, times, 0) == 0);
    }
    free(p);
}

static void names(void)
{
    TEST_CASE("identity: what a host name can be");
    CHECK(rs_identity_name_ok("web1"));
    CHECK(rs_identity_name_ok("web-1.lab.example"));
    CHECK(rs_identity_name_ok("A1"));
    CHECK(!rs_identity_name_ok(""));
    CHECK(!rs_identity_name_ok("-web"));
    CHECK(!rs_identity_name_ok("web-"));
    CHECK(!rs_identity_name_ok("web..lab"));
    CHECK(!rs_identity_name_ok(".web"));
    CHECK(!rs_identity_name_ok("web."));
    CHECK(!rs_identity_name_ok("web_1"));
    CHECK(!rs_identity_name_ok("web 1"));
    CHECK(!rs_identity_name_ok("we'b"));
    {
        char long_label[70];

        memset(long_label, 'a', 64);
        long_label[64] = '\0';
        CHECK(!rs_identity_name_ok(long_label));
        long_label[63] = '\0';
        CHECK(rs_identity_name_ok(long_label));
    }
    {
        char   too_long[260];
        size_t i;

        for (i = 0; i < 255; i++)
        {
            too_long[i] = (i % 2) ? '.' : 'a';
        }
        too_long[255] = '\0';
        CHECK(!rs_identity_name_ok(too_long));
    }
}

static void hosts(void)
{
    struct rs_buf out;
    static const char text[] = "127.0.0.1 localhost\n"
                               "127.0.1.1\toldbox oldbox.lan  oldboxer # oldbox here\n"
                               "# oldbox in a comment\n"
                               "10.0.0.1 oldbox#tight\n"
                               "oldbox\n"
                               "::1 ip6-localhost";

    TEST_CASE("identity: the image's host name given as the new one in /etc/hosts");
    rs_buf_init(&out);
    CHECK_INT(rs_identity_hosts(text, strlen(text), "oldbox", "web1", &out), 3);
    CHECK_STR(out.data, "127.0.0.1 localhost\n"
                        "127.0.1.1\tweb1 web1.lan  oldboxer # oldbox here\n"
                        "# oldbox in a comment\n"
                        "10.0.0.1 web1#tight\n"
                        "oldbox\n"
                        "::1 ip6-localhost");
    rs_buf_reset(&out);
    CHECK_INT(rs_identity_hosts(text, strlen(text), "", "web1", &out), 0);
    CHECK_STR(out.data, text);
    rs_buf_reset(&out);
    CHECK_INT(rs_identity_hosts(text, strlen(text), NULL, "web1", &out), 0);
    CHECK_STR(out.data, text);
    rs_buf_free(&out);
}

static void marking(void)
{
    struct rs_index ix;
    struct rs_rules rules;
    bool            leave[8];

    TEST_CASE("identity: what the index records as identity, and what the rules class so");
    rs_index_init(&ix);
    entry(&ix, "/etc/machine-id", "x", true, RS_CLASS_STATE);
    entry(&ix, "/etc/app/token", "x", true, RS_CLASS_IDENTITY);
    entry(&ix, "/etc/app/conf", "x", true, RS_CLASS_STATE);
    entry(&ix, "/etc/ssh/ssh_host_rsa_key", "x", true, RS_CLASS_STATE);
    rs_rules_init(&rules);
    CHECK(rs_rules_add_builtin(&rules, "linux"));
    CHECK_INT(rs_identity_mark(&ix, &rules, leave), 3);
    CHECK(leave[0] && leave[1] && !leave[2] && leave[3]);
    CHECK_INT(rs_identity_mark(&ix, NULL, leave), 1);
    CHECK(!leave[0] && leave[1] && !leave[2] && !leave[3]);
    rs_rules_free(&rules);
    rs_index_free(&ix);

    TEST_CASE("identity: the built-in rules, and the class written as rules read it");
    rs_rules_init(&rules);
    CHECK(rs_rules_add_builtin(&rules, "linux"));
    CHECK(rs_rules_classify(&rules, "/etc/machine-id", NULL) == RS_CLASS_IDENTITY);
    CHECK(rs_rules_classify(&rules, "/etc/hostname", NULL) == RS_CLASS_IDENTITY);
    CHECK(rs_rules_classify(&rules, "/etc/ssh/ssh_host_ecdsa_key.pub", NULL) == RS_CLASS_IDENTITY);
    CHECK(rs_rules_classify(&rules, "/etc/ssh/sshd_config", NULL) == RS_CLASS_STATE);
    CHECK(rs_rules_classify(&rules, "/var/lib/cloud/instances/i-1/obj.pkl", NULL) ==
          RS_CLASS_IDENTITY);
    CHECK(rs_rules_classify(&rules, "/var/lib/cloud/scripts/x", NULL) == RS_CLASS_STATE);
    CHECK(rs_rules_classify(&rules, "/etc/wireguard/wg0.conf", NULL) == RS_CLASS_IDENTITY);
    CHECK(rs_rules_classify(&rules, "/var/lib/mysql/auto.cnf", NULL) == RS_CLASS_IDENTITY);
    CHECK(rs_rules_classify(&rules, "/var/lib/mysql/ibdata1", NULL) == RS_CLASS_STATE);
    rs_rules_free(&rules);
    {
        struct rs_buf err;
        enum rs_class cls;

        rs_rules_init(&rules);
        rs_buf_init(&err);
        CHECK(rs_rules_parse(&rules, "identity /etc/app/token\n", 24, "t.rules", &err));
        CHECK(rs_rules_classify(&rules, "/etc/app/token", NULL) == RS_CLASS_IDENTITY);
        CHECK_STR(rs_class_name(RS_CLASS_IDENTITY), "identity");
        CHECK(rs_class_parse("identity", 8, &cls) && cls == RS_CLASS_IDENTITY);
        CHECK(!rs_rules_parse(&rules, "unique /x\n", 10, "t.rules", &err));
        CHECK_CONTAINS(err.data, "baseline, state or identity");
        rs_buf_free(&err);
        rs_rules_free(&rules);
    }
}

/* What a fresh install has: its own machine-id and host key, and nothing of
 * the image's. */
static void fresh(const char *dir)
{
    char            *root = rs_xasprintf("%s/fresh", dir);
    struct rs_index  ix;
    struct renew_run r;
    bool             leave[16];
    char            *out = NULL;
    char            *errs = NULL;
    char            *s;
    static const char *const no_keygen[] = { "/nonexistent/ssh-keygen" };

    TEST_CASE("identity: a fresh install's own kept, what it lacks made, the host name set");
    image(&ix);
    put(root, "etc/machine-id", "ffffffffffffffffffffffffffffffff\n");
    put(root, "etc/ssh/ssh_host_ed25519_key", "MINE\n");
    put(root, "etc/ssh/ssh_host_ed25519_key.pub", "MINE.PUB\n");
    put(root, "var/lib/systemd/.keep", "");
    put(root, "var/lib/dbus/.keep", "");
    put(root, "etc/hosts", "127.0.1.1 oldbox\n");
    (void)rs_identity_mark(&ix, NULL, leave);
    memset(&r, 0, sizeof(r));
    r.root = root;
    r.ix = &ix;
    r.leave = leave;
    r.name = "web1";
    r.old = NULL;
    r.verbose = true;
    rs_program_set_paths(RS_PROG_SSH_KEYGEN, no_keygen, 1);
    (void)rs_test_capture(run_renew, &r, &out, &errs);
    rs_program_set_paths(RS_PROG_SSH_KEYGEN, NULL, 0);
    CHECK(r.ok);
    CHECK_INT(r.st.kept, 3);
    CHECK_INT(r.st.made, 1);
    CHECK_INT(r.st.removed, 0);
    CHECK_INT(r.st.failed, 0);
    CHECK(!r.st.host_keys);
    CHECK_CONTAINS(out, "keep this machine's own /etc/machine-id");
    CHECK_CONTAINS(out, "make new /var/lib/systemd/random-seed");
    s = got(root, "etc/machine-id");
    CHECK_STR(s, "ffffffffffffffffffffffffffffffff\n");
    free(s);
    s = got(root, "etc/hostname");
    CHECK_STR(s, "web1\n");
    free(s);
    s = got(root, "var/lib/systemd/random-seed");
    CHECK(s != NULL && strcmp(s, "seed") != 0);
    free(s);
    /* No copy of D-Bus's: it reads the machine's own. */
    CHECK(!there(root, "var/lib/dbus/machine-id"));
    /* No old name given, so /etc/hosts as it was. */
    s = got(root, "etc/hosts");
    CHECK_STR(s, "127.0.1.1 oldbox\n");
    free(s);
    free(out);
    free(errs);
    rs_index_free(&ix);
    free(root);
}

/* A copy of the image's own disk: everything the image's, so made new or
 * removed. */
static void copied(const char *dir)
{
    char            *root = rs_xasprintf("%s/copied", dir);
    struct rs_index  ix;
    struct renew_run r;
    bool             leave[16];
    char            *out = NULL;
    char            *errs = NULL;
    char            *s;
    char            *t;
    static const char *const no_keygen[] = { "/nonexistent/ssh-keygen" };

    image(&ix);
    as_image(root);
    (void)rs_identity_mark(&ix, NULL, leave);

    TEST_CASE("identity: dry, on a copy of the image's disk, nothing written");
    memset(&r, 0, sizeof(r));
    r.root = root;
    r.ix = &ix;
    r.leave = leave;
    r.name = "web2";
    r.old = "oldbox";
    r.dry_run = true;
    (void)rs_test_capture(run_renew, &r, &out, &errs);
    CHECK(r.ok);
    CHECK_INT(r.st.made, 3);
    CHECK_INT(r.st.removed, 3);
    CHECK_INT(r.st.hosts, 2);
    CHECK(r.st.host_keys);
    CHECK_CONTAINS(out, "would make new /etc/machine-id");
    CHECK_CONTAINS(out, "would remove the image's own /var/lib/tailscale/tailscaled.state");
    CHECK_CONTAINS(out, "would make new SSH host keys in /etc/ssh");
    CHECK_CONTAINS(out, "would give the new host name in /etc/hosts");
    s = got(root, "etc/hostname");
    CHECK_STR(s, "oldbox\n");
    free(s);
    CHECK(there(root, "var/lib/tailscale/tailscaled.state"));
    free(out);
    free(errs);

    TEST_CASE("identity: on a copy of the image's disk, made new or removed");
    r.dry_run = false;
    r.verbose = false;
    rs_program_set_paths(RS_PROG_SSH_KEYGEN, no_keygen, 1);
    (void)rs_test_capture(run_renew, &r, &out, &errs);
    rs_program_set_paths(RS_PROG_SSH_KEYGEN, NULL, 0);
    CHECK(r.ok);
    CHECK_INT(r.st.kept, 0);
    CHECK_INT(r.st.made, 3);
    CHECK_INT(r.st.removed, 3);
    CHECK_INT(r.st.hosts, 2);
    /* ssh-keygen is not there to run: said, and counted. */
    CHECK_INT(r.st.failed, 1);
    CHECK(!r.st.host_keys);
    CHECK_CONTAINS(errs, "/etc/ssh");
    CHECK_STR(out, "");
    s = got(root, "etc/machine-id");
    CHECK(s && strlen(s) == 33 && s[32] == '\n' && s[12] == '4' &&
          strcmp(s, "0123456789abcdef0123456789abcdef\n") != 0);
    t = got(root, "var/lib/dbus/machine-id");
    CHECK_STR(t, s);
    free(t);
    free(s);
    s = got(root, "etc/hostname");
    CHECK_STR(s, "web2\n");
    free(s);
    s = got(root, "etc/hosts");
    CHECK_STR(s, "127.0.0.1 localhost\n127.0.1.1\tweb2 web2.lan # me\n");
    free(s);
    CHECK(!there(root, "etc/ssh/ssh_host_ed25519_key"));
    CHECK(!there(root, "etc/ssh/ssh_host_ed25519_key.pub"));
    CHECK(!there(root, "var/lib/tailscale/tailscaled.state"));
    free(out);
    free(errs);

    TEST_CASE("identity: new host keys made by ssh-keygen -A");
    {
        static const char *const yes[] = { "/bin/true", "/usr/bin/true" };

        put(root, "etc/ssh/ssh_host_ed25519_key", "KEY\n");
        rs_program_set_paths(RS_PROG_SSH_KEYGEN, yes, 2);
        if (rs_program_path(RS_PROG_SSH_KEYGEN))
        {
            (void)rs_test_capture(run_renew, &r, &out, &errs);
            CHECK(r.ok);
            CHECK(r.st.host_keys);
            CHECK_INT(r.st.failed, 0);
            /* Run again: the machine-id, D-Bus's copy and the seed are the
             * machine's own now, and kept. */
            CHECK_INT(r.st.kept, 3);
            free(out);
            free(errs);
        }
        rs_program_set_paths(RS_PROG_SSH_KEYGEN, NULL, 0);
    }
    rs_index_free(&ix);
    free(root);
}

static void cannot(const char *dir)
{
    char                    *root = rs_xasprintf("%s/missing", dir);
    struct rs_index          ix;
    struct rs_identity_stats st;
    struct rs_buf            err;
    bool                     leave[16];

    TEST_CASE("identity: a root that is not there");
    image(&ix);
    (void)rs_identity_mark(&ix, NULL, leave);
    rs_buf_init(&err);
    CHECK(!rs_identity_renew(root, &ix, leave, "web1", NULL, false, false, &st, &err));
    CHECK_CONTAINS(err.data, "missing");
    rs_buf_free(&err);
    rs_index_free(&ix);
    free(root);
}

void test_identity(void)
{
    char *dir = rs_test_tmpdir();

    names();
    hosts();
    marking();
    fresh(dir);
    copied(dir);
    cannot(dir);
    rs_test_rmtree(dir);
    free(dir);
}
