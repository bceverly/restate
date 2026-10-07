/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "image.h"
#include "index.h"
#include "restore.h"
#include "rules.h"
#include "scan.h"
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

static char *at(const char *dir, const char *rel)
{
    return rs_xasprintf("%s/%s", dir, rel);
}

/* Captures `tree` into `img`, and reads its index back as restore will. */
static void capture(const char *tree, const char *img, struct rs_index *ix)
{
    struct rs_rules        rules;
    struct rs_scan_opts    so;
    struct rs_scan_stats   st;
    struct rs_image_writer iw;
    struct rs_index        m;
    struct rs_buf          err;

    rs_rules_init(&rules);
    rs_buf_init(&err);
    rs_index_init(&m);
    memset(&so, 0, sizeof(so));
    so.root = tree;
    so.rules = &rules;
    so.hash = true;
    CHECK(rs_image_begin(&iw, img, &err));
    /* The accounts in the kit, as capture puts them there. */
    {
        static const char *const kit[] = { "/etc/passwd", "/etc/group", "/etc/shadow",
                                           "/etc/gshadow" };

        iw.kit = kit;
        iw.nkit = sizeof(kit) / sizeof(kit[0]);
    }
    so.store = rs_image_store;
    so.store_ctx = &iw;
    CHECK(rs_scan(&so, &m, &st, &err));
    m.root = rs_xstrdup("/");
    CHECK(rs_image_finish(&iw, &m, &err));
    rs_index_free(&m);
    rs_index_init(ix);
    CHECK(rs_index_load(ix, img, &err));
    CHECK_STR(err.data ? err.data : "", "");
    rs_rules_free(&rules);
    rs_buf_free(&err);
}

/* An entry added to a loaded index, kept sorted. */
static struct rs_entry *add(struct rs_index *ix, const char *path, char type)
{
    struct rs_entry e;
    struct rs_buf   err;

    memset(&e, 0, sizeof(e));
    e.path = rs_xstrdup(path);
    e.type = type;
    e.mode = 0644;
    e.uid = (uint64_t)getuid();
    e.gid = (uint64_t)getgid();
    rs_index_add(ix, &e);
    rs_buf_init(&err);
    CHECK(rs_index_sort(ix, &err));
    rs_buf_free(&err);
    return (struct rs_entry *)(uintptr_t)rs_index_find(ix, path);
}

struct run {
    const char             *img;
    const struct rs_index  *ix;
    struct rs_restore_opts  o;
    struct rs_restore_stats st;
    bool                    ok;
    struct rs_buf           err;
};

static int run_restore(const void *arg)
{
    struct run *r = (struct run *)(uintptr_t)arg;

    rs_buf_init(&r->err);
    r->ok = rs_restore(r->img, r->ix, &r->o, &r->st, &r->err);
    return r->ok ? 0 : 1;
}

/* Restores `img` into `root` with `o`, what it printed in `out` and `errs`. */
static void restore_into(struct run *r, const char *img, const struct rs_index *ix,
                         const char *root, char **out, char **errs)
{
    r->img = img;
    r->ix = ix;
    r->o.root = root;
    (void)rs_test_capture(run_restore, r, out, errs);
}

void test_restore(void)
{
    char           *dir = rs_test_tmpdir();
    char           *tree = at(dir, "tree");
    char           *img = at(dir, "img.tar");
    struct rs_index ix;
    struct run      r;
    char           *out = NULL;
    char           *errs = NULL;
    char           *p;

    put(tree, "etc/hosts", "127.0.0.1 localhost\n");
    put(tree, "etc/app/key", "secret\n");
    put(tree, "home/u/doc", "doc\n");
    put(tree, "var/x/one", "shared\n");
    p = at(tree, "var/x/one");
    {
        char *two = at(tree, "var/x/two");

        CHECK(link(p, two) == 0);
        free(two);
    }
    free(p);
    p = at(tree, "home/u/link");
    CHECK(symlink("../../etc/hosts", p) == 0);
    free(p);
    capture(tree, img, &ix);

    TEST_CASE("restore: verbose, into an empty root");
    {
        char *root = at(dir, "a");

        CHECK(mkdir(root, 0755) == 0);
        memset(&r, 0, sizeof(r));
        r.o.verbose = true;
        restore_into(&r, img, &ix, root, &out, &errs);
        CHECK(r.ok);
        CHECK_INT(r.st.files, 5);
        CHECK_INT(r.st.links, 1);
        CHECK_INT(r.st.symlinks, 1);
        CHECK_CONTAINS(out, "restore /etc/app/key\n");
        CHECK_CONTAINS(out, "link /var/x/two\n");
        p = at(root, "etc/app/key");
        CHECK(access(p, F_OK) == 0);
        free(p);
        rs_buf_free(&r.err);
        free(out);
        free(errs);

        TEST_CASE("restore: again, over what is there");
        memset(&r, 0, sizeof(r));
        restore_into(&r, img, &ix, root, &out, &errs);
        CHECK(r.ok);
        CHECK_INT(r.st.files, 5);
        CHECK_INT(r.st.failed, 0);
        rs_buf_free(&r.err);
        free(out);
        free(errs);
        free(root);
    }

    TEST_CASE("restore: a dry run where nothing exists yet");
    {
        char *root = at(dir, "dry");

        CHECK(mkdir(root, 0755) == 0);
        memset(&r, 0, sizeof(r));
        r.o.dry_run = true;
        restore_into(&r, img, &ix, root, &out, &errs);
        CHECK(r.ok);
        CHECK_CONTAINS(out, "would restore /home/u/link\n");
        CHECK_CONTAINS(out, "would link /var/x/two\n");
        CHECK_CONTAINS(out, "would restore /etc\n");
        p = at(root, "etc");
        CHECK(access(p, F_OK) != 0);
        free(p);
        rs_buf_free(&r.err);
        free(out);
        free(errs);
        free(root);
    }

    TEST_CASE("restore: what is in the way");
    {
        char *root = at(dir, "way");
        char *hosts = at(root, "etc/hosts");
        char *home = at(root, "home");

        /* A directory where a file goes stays; a file where a directory
         * goes is replaced. */
        put(root, "etc/hosts/inside", "x");
        CHECK(mkdir(root, 0755) == 0 || access(root, F_OK) == 0);
        put(root, "placeholder", "x");
        {
            int fd = open(home, O_WRONLY | O_CREAT, 0644);

            CHECK(fd >= 0);
            if (fd >= 0)
            {
                (void)close(fd);
            }
        }
        memset(&r, 0, sizeof(r));
        restore_into(&r, img, &ix, root, &out, &errs);
        CHECK(r.ok);
        CHECK_INT(r.st.failed, 1);
        CHECK_CONTAINS(errs, "/etc/hosts: a directory is in the way; left as it is");
        {
            struct stat st;

            CHECK(stat(home, &st) == 0 && S_ISDIR(st.st_mode));
        }
        rs_buf_free(&r.err);
        free(out);
        free(errs);
        free(hosts);
        free(home);
        free(root);
    }

    if (geteuid() != 0)
    {
        TEST_CASE("restore: a directory it cannot write to");
        {
            char *root = at(dir, "ro");
            char *etc = at(root, "etc");

            put(root, "etc/placeholder", "x");
            CHECK(chmod(etc, 0500) == 0);
            memset(&r, 0, sizeof(r));
            restore_into(&r, img, &ix, root, &out, &errs);
            CHECK(r.ok);
            CHECK(r.st.failed >= 1);
            CHECK_CONTAINS(errs, "/etc/hosts: Permission denied");
            CHECK(chmod(etc, 0755) == 0);
            rs_buf_free(&r.err);
            free(out);
            free(errs);
            free(etc);
            free(root);
        }
    }

    TEST_CASE("restore: what the index says that the image does not bear out");
    {
        char            *root = at(dir, "odd");
        struct rs_entry *e;

        CHECK(mkdir(root, 0755) == 0);
        /* Unreadable when it was captured: what is stored is not the file. */
        e = (struct rs_entry *)(uintptr_t)rs_index_find(&ix, "/home/u/doc");
        CHECK(e != NULL);
        if (e)
        {
            e->hash_state = RS_HASH_UNREADABLE;
        }
        /* Stored, says the index; not in the image. */
        e = add(&ix, "/home/u/ghost", 'f');
        e->stored = rs_xstrdup("restate/files/home/u/ghost");
        e->hash_state = RS_HASH_PRESENT;
        /* An owner only root can give, where this is not root. */
        e = (struct rs_entry *)(uintptr_t)rs_index_find(&ix, "/etc/hosts");
        if (e && geteuid() != 0)
        {
            e->uid = 0;
        }
        /* A device node, which only root can make. */
        e = add(&ix, "/home/u/dev", 'c');
        e->rdev = 0x0103;
        memset(&r, 0, sizeof(r));
        restore_into(&r, img, &ix, root, &out, &errs);
        CHECK(r.ok);
        CHECK_INT(r.st.refused, 1);
        CHECK_CONTAINS(errs, "/home/u/doc: it could not be read when it was captured; not put back");
        CHECK_INT(r.st.missing, 1);
        CHECK_CONTAINS(errs, "/home/u/ghost: the index says the image holds it, and it does not");
        if (geteuid() != 0)
        {
            CHECK(r.st.owners >= 1);
            CHECK(r.st.failed >= 1);
        }
        rs_buf_free(&r.err);
        free(out);
        free(errs);

        TEST_CASE("restore: excluded, and an excluded hard link");
        memset(&r, 0, sizeof(r));
        {
            static const char *const ex[] = { "/home/u", "/var/x/two" };

            r.o.exclude = ex;
            r.o.nexclude = 2;
            restore_into(&r, img, &ix, root, &out, &errs);
        }
        CHECK(r.ok);
        CHECK_INT(r.st.links, 0);
        CHECK(r.st.excluded >= 3);
        CHECK_INT(r.st.missing, 0);
        rs_buf_free(&r.err);
        free(out);
        free(errs);
        free(root);
    }

    TEST_CASE("restore: owners by name, through merged accounts");
    {
        char            *atree = at(dir, "atree");
        char            *aimg = at(dir, "aimg.tar");
        char            *root = at(dir, "aroot");
        char            *text;
        char            *doc = at(root, "home/u/doc");
        struct rs_index  aix;
        struct rs_entry *e;
        struct stat      st;
        const char      *me = getenv("USER") ? getenv("USER") : "nobody"; /* Flawfinder: ignore */

        /* The image's accounts give this user 4242; the system's, its own. */
        text = rs_xasprintf("root:x:0:0:root:/root:/bin/sh\n%s:x:4242:4242::/home/u:/bin/sh\n", me);
        put(atree, "etc/passwd", text);
        free(text);
        put(atree, "etc/group", "root:x:0:\n");
        put(atree, "home/u/doc", "doc\n");
        capture(atree, aimg, &aix);
        text = rs_xasprintf("root:x:0:0:root:/root:/bin/sh\n%s:x:%lu:%lu::/home/u:/bin/sh\n", me,
                            (unsigned long)getuid(), (unsigned long)getgid());
        put(root, "etc/passwd", text);
        free(text);
        put(root, "etc/group", "root:x:0:\n");
        e = (struct rs_entry *)(uintptr_t)rs_index_find(&aix, "/home/u/doc");
        CHECK(e != NULL);
        if (e)
        {
            free(e->user);
            e->user = rs_xstrdup(me);
            e->uid = 4242;
        }
        memset(&r, 0, sizeof(r));
        restore_into(&r, aimg, &aix, root, &out, &errs);
        CHECK(r.ok);
        CHECK(r.st.merged);
        CHECK(stat(doc, &st) == 0 && st.st_uid == getuid());
        rs_buf_free(&r.err);
        free(out);
        free(errs);

        /* By number, 4242: only root can give a file to it. */
        if (geteuid() != 0)
        {
            memset(&r, 0, sizeof(r));
            r.o.numeric_owner = true;
            restore_into(&r, aimg, &aix, root, &out, &errs);
            CHECK(r.ok);
            CHECK(!r.st.merged);
            CHECK(r.st.owners >= 1);
            rs_buf_free(&r.err);
            free(out);
            free(errs);
        }
        rs_index_free(&aix);
        free(doc);
        free(root);
        free(aimg);
        free(atree);
    }

    TEST_CASE("restore: images it cannot read");
    {
        char *root = at(dir, "bad");
        char *cut = at(dir, "cut.tar");
        char *bare = at(dir, "bare.tar");
        char *cmd;

        CHECK(mkdir(root, 0755) == 0);
        memset(&r, 0, sizeof(r));
        restore_into(&r, "/nonexistent/img.tar", &ix, root, &out, &errs);
        CHECK(!r.ok);
        CHECK_CONTAINS(r.err.data, "/nonexistent/img.tar");
        rs_buf_free(&r.err);
        free(out);
        free(errs);

        memset(&r, 0, sizeof(r));
        restore_into(&r, img, &ix, "/nonexistent/root", &out, &errs);
        CHECK(!r.ok);
        CHECK_CONTAINS(r.err.data, "/nonexistent/root");
        rs_buf_free(&r.err);
        free(out);
        free(errs);

        /* Cut short in the files part. */
        {
            struct stat st;

            CHECK(stat(img, &st) == 0);
            cmd = rs_xasprintf("head -c %lld '%s' > '%s'", (long long)st.st_size - 2048, img, cut);
            CHECK(system(cmd) == 0);
            free(cmd);
        }
        memset(&r, 0, sizeof(r));
        restore_into(&r, cut, &ix, root, &out, &errs);
        CHECK(!r.ok);
        rs_buf_free(&r.err);
        free(out);
        free(errs);

        /* An outer archive with no files part. */
        cmd = rs_xasprintf("cd '%s' && mkdir -p b && cd b && tar -xf ../img.tar && "
                           "tar -cf ../bare.tar restate/index.json.gz", dir);
        CHECK(system(cmd) == 0);
        free(cmd);
        memset(&r, 0, sizeof(r));
        restore_into(&r, bare, &ix, root, &out, &errs);
        CHECK(!r.ok);
        CHECK_CONTAINS(r.err.data, "there is no restate/files.tar.gz in it");
        rs_buf_free(&r.err);
        free(out);
        free(errs);
        free(cut);
        free(bare);
        free(root);
    }

    rs_index_free(&ix);
    rs_test_rmtree(dir);
    free(tree);
    free(img);
    free(dir);
}
