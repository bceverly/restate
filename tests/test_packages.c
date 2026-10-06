/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "index.h"
#include "json.h"
#include "packages.h"
#include "test.h"

/* Writes `text` to dir/rel, creating the directories on the way; a `rel`
 * ending in a slash makes the directory alone. */
static void put(const char *dir, const char *rel, const char *text)
{
    char       *path = rs_xasprintf("%s/%s", dir, rel);
    const char *slash;
    size_t      i;
    int         fd;

    for (i = strlen(dir) + 1; path[i] != '\0'; i++)
    {
        if (path[i] == '/')
        {
            path[i] = '\0';
            (void)mkdir(path, 0755);
            path[i] = '/';
        }
    }
    slash = strrchr(path, '/');
    if (slash && slash[1] == '\0')
    {
        free(path);
        return;
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

/* The element of array `arr` whose `key` is `value`, or NULL. */
static const struct rs_jval *find(const struct rs_jval *arr, const char *key, const char *value)
{
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const char *v = rs_jobject_str(&arr->items[i], key);

        if (v && strcmp(v, value) == 0)
        {
            return &arr->items[i];
        }
    }
    return NULL;
}

static bool is_true(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return v && v->type == RS_JBOOL && v->b;
}

static uint64_t count_of(const struct rs_jval *obj, const char *key)
{
    uint64_t u = 0;

    (void)rs_jval_u64(rs_jobject_get(obj, key), &u);
    return u;
}

/* Whether any string in array `arr` contains `needle`. */
static bool any_contains(const struct rs_jval *arr, const char *needle)
{
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        if (arr->items[i].type == RS_JSTRING && strstr(arr->items[i].s, needle))
        {
            return true;
        }
    }
    return false;
}

static void test_uri_file(void)
{
    struct rs_buf b;

    TEST_CASE("apt's list file names");
    rs_buf_init(&b);
    rs_apt_uri_file(&b, "https://deb.nodesource.com/node_20.x/dists/nodistro/main/");
    CHECK_STR(b.data, "deb.nodesource.com_node%5f20.x_dists_nodistro_main_");
    rs_buf_reset(&b);
    rs_apt_uri_file(&b, "http://user:secret@example.com/a~b/c d/");
    CHECK_STR(b.data, "example.com_a%7eb_c%20d_");
    rs_buf_reset(&b);
    /* An @ in the path is not a user name. */
    rs_apt_uri_file(&b, "http://example.com/x@y/");
    CHECK_STR(b.data, "example.com_x%40y_");
    rs_buf_reset(&b);
    rs_apt_uri_file(&b, "file:/srv/repo/");
    CHECK_STR(b.data, "file:_srv_repo_");
    rs_buf_free(&b);
}

/* A Debian-family tree: dpkg, apt, keys, lists. */
static void make_apt(const char *t)
{
    put(t, "var/lib/dpkg/status",
        "Package: vim\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 2:9.1-1\n"
        "Description: an editor\n"
        " with a long description\n"
        " .\n"
        " in paragraphs\n"
        "\n"
        "Package: libfoo\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 1.0\n"
        "\n"
        "Package: tzdata\n"
        "Status: install ok installed\n"
        "Architecture: all\n"
        "Version: 2026a\n"
        "\n"
        "Package: pinned\n"
        "Status: hold ok installed\n"
        "Architecture: amd64\n"
        "Version: 3.0\n"
        "\n"
        "Package: broken\n"
        "Status: install ok half-configured\n"
        "Architecture: amd64\n"
        "Version: 0.1\n"
        "\n"
        "Package: gone\n"
        "Status: deinstall ok config-files\n"
        "Architecture: amd64\n"
        "Version: 9\n"
        "\n"
        "\n"
        "Package: nostatus\n"
        "Architecture: amd64\n"
        "\n"
        "Package: zoom\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 6.7\n"
        "\n"
        "Package: oldie\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 1.0\n");
    put(t, "var/lib/dpkg/arch", "amd64\ni386\n");
    put(t, "var/lib/apt/extended_states",
        "Package: libfoo\n"
        "Architecture: amd64\n"
        "Auto-Installed: 1\n"
        "\n"
        "Package: tzdata\n"
        "Architecture: amd64\n"
        "Auto-Installed: 1\n"
        "\n"
        "Package: vim\n"
        "Architecture: amd64\n"
        "Auto-Installed: 0\n"
        "\n"
        "Package: notinstalled\n"
        "Architecture: amd64\n"
        "Auto-Installed: 1\n");
    put(t, "etc/apt/sources.list",
        "# the archive\n"
        "deb [arch=amd64,i386 signed-by=/usr/share/keyrings/archive.gpg trusted=no] "
        "http://archive.example.com/ubuntu stable main universe # trailing\n"
        "deb-src http://archive.example.com/ubuntu stable main\n"
        "deb http://short\n"
        "   \n");
    put(t, "etc/apt/sources.list.d/vendor.sources",
        "# a vendor\n"
        "Types: deb\n"
        "URIs: https://vendor.example.com/apt/\n"
        "Suites: ./\n"
        "Signed-By: /usr/share/keyrings/vendor.gpg /usr/share/keyrings/missing.gpg\n"
        "\n"
        "Types: deb\n"
        "URIs: https://ppa.example.com/owner/name/ubuntu/\n"
        "Suites: stable\n"
        "Components: main\n"
        "Architectures: amd64\n"
        "Signed-By:\n"
        " -----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        " .\n"
        " mQINBGT\n"
        " -----END PGP PUBLIC KEY BLOCK-----\n"
        "\n"
        "Enabled: no\n"
        "Types: deb\n"
        "URIs: cdrom:[Disc]/\n"
        "Suites: stable\n"
        "Components: main\n"
        "\n"
        "Types: deb\n"
        "Components: main\n");
    put(t, "etc/apt/sources.list.d/old.list.bak", "deb http://bak.example.com stable main\n");
    put(t, "usr/share/keyrings/archive.gpg", "archive key");
    put(t, "usr/share/keyrings/vendor.gpg", "vendor key");
    put(t, "etc/apt/trusted.gpg", "legacy keyring");
    put(t, "etc/apt/trusted.gpg.d/extra.asc", "extra key");
    put(t, "etc/apt/keyrings/", "");
    put(t, "var/lib/apt/lists/archive.example.com_ubuntu_dists_stable_main_binary-amd64_Packages",
        "Package: vim\n"
        "Architecture: amd64\n"
        "Version: 2:9.1-1\n"
        "Description: an editor\n"
        " more\n"
        "\n"
        "Package: tzdata\n"
        "Architecture: all\n"
        "Version: 2026a\n"
        "\n"
        "Package: oldie\n"
        "Architecture: amd64\n"
        "Version: 2.0\n"
        "\n"
        "Package: notinstalled\n"
        "Architecture: amd64\n"
        "Version: 1\n");
    put(t, "var/lib/apt/lists/archive.example.com_ubuntu_dists_stable_main_binary-i386_Packages",
        "Package: vim\nArchitecture: i386\nVersion: 2:9.1-1\n");
    put(t, "var/lib/apt/lists/archive.example.com_ubuntu_dists_stable_universe_binary-amd64_"
           "Packages",
        "Package: libfoo\nArchitecture: amd64\nVersion: 1.0\n");
    put(t, "var/lib/apt/lists/vendor.example.com_apt_._Packages",
        "Package: pinned\nArchitecture: amd64\nVersion: 3.0\n");
    put(t, "var/lib/apt/lists/gone.example.com_dists_old_main_binary-amd64_Packages",
        "Package: broken\nArchitecture: amd64\nVersion: 0.1\n");
    put(t, "var/lib/apt/lists/archive.example.com_ubuntu_dists_stable_InRelease", "signed");
    put(t, "var/lib/apt/lists/x.example.com_dists_s_main_binary-amd64_Packages.lz4", "");
}

static void test_apt(void)
{
    char                 *t = rs_test_tmpdir();
    struct rs_jval        out;
    const struct rs_jval *apt;
    const struct rs_jval *pkgs;
    const struct rs_jval *p;
    const struct rs_jval *src;
    const struct rs_jval *keys;
    const struct rs_jval *k;
    const struct rs_jval *origins;

    TEST_CASE("the apt inventory");
    make_apt(t);
    memset(&out, 0, sizeof(out));
    rs_packages_describe(t, &out);
    apt = rs_jobject_get(&out, "apt");
    CHECK(apt != NULL);
    pkgs = rs_jobject_get(apt, "packages");
    CHECK_INT(count_of(apt, "count"), 7);
    CHECK_INT(pkgs ? pkgs->n : 0, 7);
    /* Sorted, and without the removed package or the stanza with no status. */
    CHECK_STR(rs_jobject_str(&pkgs->items[0], "name"), "broken");
    CHECK(find(pkgs, "name", "gone") == NULL);
    CHECK(find(pkgs, "name", "nostatus") == NULL);

    p = find(pkgs, "name", "vim");
    CHECK_STR(rs_jobject_str(p, "version"), "2:9.1-1");
    CHECK_STR(rs_jobject_str(p, "architecture"), "amd64");
    CHECK(is_true(p, "manual"));
    origins = rs_jobject_get(p, "origins");
    CHECK_INT(origins ? origins->n : 0, 1);
    CHECK(any_contains(origins, "http://archive.example.com/ubuntu stable/main"));
    CHECK(rs_jobject_get(p, "unavailable") == NULL);

    p = find(pkgs, "name", "libfoo");
    CHECK(!is_true(p, "manual"));
    CHECK(any_contains(rs_jobject_get(p, "origins"), "stable/universe"));
    /* An Architecture: all package is marked under the native architecture. */
    p = find(pkgs, "name", "tzdata");
    CHECK(!is_true(p, "manual"));
    CHECK_STR(rs_jobject_str(p, "architecture"), "all");

    p = find(pkgs, "name", "pinned");
    CHECK(is_true(p, "hold"));
    CHECK(any_contains(rs_jobject_get(p, "origins"), "https://vendor.example.com/apt/ ./"));
    p = find(pkgs, "name", "broken");
    CHECK_STR(rs_jobject_str(p, "state"), "half-configured");
    /* A list no source names any more is still where the version is. */
    CHECK(any_contains(rs_jobject_get(p, "origins"), "gone.example.com_dists_old_main"));

    p = find(pkgs, "name", "zoom");
    CHECK_STR(rs_jobject_str(p, "unavailable"), "local");
    p = find(pkgs, "name", "oldie");
    CHECK_STR(rs_jobject_str(p, "unavailable"), "superseded");
    CHECK_INT(count_of(apt, "local"), 1);
    CHECK_INT(count_of(apt, "superseded"), 1);
    CHECK_INT(count_of(apt, "manual"), 5);

    CHECK_INT(rs_jobject_get(apt, "architectures")->n, 2);

    src = rs_jobject_get(apt, "sources");
    /* sources.list: deb and deb-src; vendor.sources: three with URIs. */
    CHECK_INT(src ? src->n : 0, 5);
    p = find(src, "file", "/etc/apt/sources.list");
    CHECK_STR(rs_jobject_str(p, "signed_by"), "/usr/share/keyrings/archive.gpg");
    CHECK_INT(rs_jobject_get(p, "architectures")->n, 2);
    CHECK(any_contains(rs_jobject_get(p, "options"), "trusted=no"));
    CHECK_INT(rs_jobject_get(p, "components")->n, 2);
    CHECK(any_contains(rs_jobject_get(&src->items[3], "uris"), "ppa.example.com"));
    CHECK_STR(rs_jobject_str(&src->items[3], "signed_by"), "the key in this file");
    CHECK(rs_jobject_get(&src->items[4], "enabled") != NULL);

    keys = rs_jobject_get(apt, "keys");
    CHECK_INT(keys ? keys->n : 0, 5);
    k = find(keys, "path", "/usr/share/keyrings/archive.gpg");
    CHECK_STR(rs_jobject_str(k, "data"), "YXJjaGl2ZSBrZXk=");
    CHECK_INT(count_of(k, "size"), 11);
    CHECK(rs_jobject_str(k, "sha256") != NULL);
    CHECK(find(keys, "path", "/etc/apt/trusted.gpg") != NULL);
    CHECK(find(keys, "path", "/etc/apt/trusted.gpg.d/extra.asc") != NULL);
    k = find(keys, "path", "/usr/share/keyrings/missing.gpg");
    CHECK(is_true(k, "missing"));

    CHECK(any_contains(rs_jobject_get(&out, "notes"), "missing.gpg could not be read"));
    CHECK(any_contains(rs_jobject_get(&out, "notes"), "compressed"));
    CHECK(find(rs_jobject_get(&out, "managers"), "name", "apt") != NULL);
    rs_jval_free(&out);
    rs_test_rmtree(t);
    free(t);
}

static void test_snap(void)
{
    char                 *t = rs_test_tmpdir();
    struct rs_jval        out;
    const struct rs_jval *snaps;
    const struct rs_jval *s;

    TEST_CASE("the snap inventory, from snapd's state");
    put(t, "var/lib/snapd/state.json",
        "{\"data\": {\"snaps\": {"
        "\"firefox\": {\"type\": \"app\", \"active\": true, \"current\": \"8969\", "
        "\"channel\": \"latest/stable\", \"sequence\": [{\"name\": \"firefox\", "
        "\"snap-id\": \"abc\", \"revision\": \"8000\"}, {\"name\": \"firefox\", "
        "\"snap-id\": \"abc\", \"revision\": \"8969\"}]},"
        "\"code\": {\"type\": \"app\", \"active\": false, \"current\": \"200\", "
        "\"channel\": \"latest/edge\", \"classic\": true, \"devmode\": true, "
        "\"sequence\": [{\"side-info\": {\"name\": \"code\", \"snap-id\": \"def\", "
        "\"revision\": \"200\"}, \"components\": []}]},"
        "\"mine\": {\"type\": \"app\", \"active\": true, \"current\": \"x1\", "
        "\"sequence\": [{\"name\": \"mine\", \"revision\": \"x1\"}]}"
        "}}, \"changes\": {}}");
    memset(&out, 0, sizeof(out));
    rs_packages_describe(t, &out);
    snaps = rs_jobject_get(&out, "snap");
    CHECK_INT(snaps ? snaps->n : 0, 3);
    s = find(snaps, "name", "firefox");
    CHECK_STR(rs_jobject_str(s, "revision"), "8969");
    CHECK_STR(rs_jobject_str(s, "channel"), "latest/stable");
    CHECK(!is_true(s, "local"));
    CHECK(!is_true(s, "classic"));
    s = find(snaps, "name", "code");
    CHECK(is_true(s, "classic"));
    CHECK(is_true(s, "devmode"));
    CHECK(is_true(s, "disabled"));
    CHECK(!is_true(s, "local"));
    s = find(snaps, "name", "mine");
    CHECK(is_true(s, "local"));
    CHECK(find(rs_jobject_get(&out, "managers"), "name", "snap") != NULL);
    CHECK(rs_jobject_get(&out, "apt") == NULL);
    rs_jval_free(&out);
    rs_test_rmtree(t);
    free(t);

    TEST_CASE("the snap inventory, from /snap");
    t = rs_test_tmpdir();
    put(t, "var/lib/snapd/state.json", "{not json");
    put(t, "snap/README", "readme");
    put(t, "snap/bin/", "");
    put(t, "snap/core22/", "");
    put(t, "snap/side/", "");
    {
        char *a = rs_xasprintf("%s/snap/core22/current", t);
        char *b = rs_xasprintf("%s/snap/side/current", t);

        CHECK(symlink("2437", a) == 0);
        CHECK(symlink("x3", b) == 0);
        free(a);
        free(b);
    }
    memset(&out, 0, sizeof(out));
    rs_packages_describe(t, &out);
    snaps = rs_jobject_get(&out, "snap");
    CHECK_INT(snaps ? snaps->n : 0, 2);
    s = find(snaps, "name", "core22");
    CHECK_STR(rs_jobject_str(s, "revision"), "2437");
    CHECK(rs_jobject_get(s, "channel") == NULL);
    CHECK(is_true(find(snaps, "name", "side"), "local"));
    CHECK(any_contains(rs_jobject_get(&out, "notes"), "channels are not recorded"));
    rs_jval_free(&out);
    rs_test_rmtree(t);
    free(t);
}

static void test_flatpak(void)
{
    char                 *t = rs_test_tmpdir();
    struct rs_jval        out;
    const struct rs_jval *fp;
    const struct rs_jval *apps;
    const struct rs_jval *a;
    const struct rs_jval *remotes;

    TEST_CASE("the flatpak inventory");
    put(t, "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "pat:x:1000:1000:Pat:/home/pat:/bin/bash\n"
        "twin:x:1001:1001:Twin:/home/pat:/bin/bash\n"
        "odd:x:1002:1002:Odd:/home/../etc:/bin/sh\n"
        "short:x:1003\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin");
    put(t, "var/lib/flatpak/repo/config",
        "[core]\nrepo_version=1\n\n[remote \"flathub\"]\nurl=https://dl.flathub.org/repo/\n"
        "gpg-verify=true\n[other]\nurl=https://not.a.remote/\n");
    put(t, "var/lib/flatpak/app/org.example.App/x86_64/stable/active/", "");
    put(t, "var/lib/flatpak/app/org.example.App/x86_64/beta/", "");
    put(t, "var/lib/flatpak/repo/refs/remotes/flathub/app/org.example.App/x86_64/stable", "c0ffee");
    put(t, "var/lib/flatpak/app/org.example.Lone/x86_64/stable/active/", "");
    put(t, "home/pat/.local/share/flatpak/repo/config",
        "[remote \"mine\"]\nurl=https://example.com/repo\n");
    put(t, "home/pat/.local/share/flatpak/app/com.example.Mine/aarch64/master/active/", "");
    put(t, "home/pat/.local/share/flatpak/repo/refs/remotes/mine/app/com.example.Mine/aarch64/"
           "master", "beef");
    memset(&out, 0, sizeof(out));
    rs_packages_describe(t, &out);
    fp = rs_jobject_get(&out, "flatpak");
    CHECK(fp != NULL);
    apps = rs_jobject_get(fp, "apps");
    CHECK_INT(apps ? apps->n : 0, 3);
    a = find(apps, "id", "org.example.App");
    CHECK_STR(rs_jobject_str(a, "branch"), "stable");
    CHECK_STR(rs_jobject_str(a, "remote"), "flathub");
    CHECK_STR(rs_jobject_str(a, "scope"), "system");
    a = find(apps, "id", "org.example.Lone");
    CHECK(rs_jobject_get(a, "remote") == NULL);
    a = find(apps, "id", "com.example.Mine");
    CHECK_STR(rs_jobject_str(a, "scope"), "user /home/pat");
    CHECK_STR(rs_jobject_str(a, "remote"), "mine");
    remotes = rs_jobject_get(fp, "remotes");
    CHECK_INT(remotes ? remotes->n : 0, 2);
    CHECK_STR(rs_jobject_str(find(remotes, "name", "flathub"), "url"),
              "https://dl.flathub.org/repo/");
    a = find(rs_jobject_get(&out, "managers"), "name", "flatpak");
    CHECK_INT(a ? rs_jobject_get(a, "where")->n : 0, 2);
    rs_jval_free(&out);
    rs_test_rmtree(t);
    free(t);
}

static void test_languages(void)
{
    char                 *t = rs_test_tmpdir();
    struct rs_jval        out;
    const struct rs_jval *arr;
    const struct rs_jval *e;
    const struct rs_jval *managers;

    TEST_CASE("pip, npm, cargo, pipx, gem and BSD packages");
    put(t, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\npat:x:1000:1000::/home/pat:/bin/sh\n");
    put(t, "usr/local/lib/python3.12/dist-packages/requests-2.31.0.dist-info/", "");
    put(t, "usr/local/lib/python3.12/dist-packages/old_thing-1.0-py3.12.egg-info/", "");
    put(t, "usr/local/lib/python3.12/dist-packages/nodash.dist-info/", "");
    put(t, "usr/local/lib/python3.12/dist-packages/requests/", "");
    put(t, "usr/local/lib/python3.12/site-packages/x-1.dist-info/", "");
    put(t, "usr/local/lib/node_modules/left-pad/package.json", "{\"version\": \"1.3.0\"}");
    put(t, "usr/local/lib/node_modules/@scope/tool/package.json",
        "{\"name\": \"@scope/tool\", \"version\": \"2.0.0\"}");
    put(t, "usr/local/lib/node_modules/broken/package.json", "{\"version\": ");
    put(t, "usr/local/lib/node_modules/noversion/package.json", "{\"name\": \"x\"}");
    put(t, "usr/lib/node_modules/npm/package.json", "{\"version\": \"10.0.0\"}");
    put(t, "home/pat/.local/lib/python3.13/site-packages/httpie-3.2.dist-info/", "");
    put(t, "home/pat/.cargo/.crates2.json",
        "{\"installs\": {\"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)\""
        ": {}, \"local 0.1.0 (path+file:///home/pat/src/local)\": {}, \"bare 1.0\": {}}}");
    put(t, "root/.cargo/.crates2.json", "[]");
    put(t, "home/pat/.local/share/pipx/venvs/black/", "");
    put(t, "var/lib/gems/3.2.0/specifications/rake-13.0.6.gemspec", "");
    put(t, "var/lib/gems/3.2.0/specifications/net-http-0.4.1.gemspec", "");
    put(t, "var/lib/gems/3.2.0/specifications/README", "");
    put(t, "var/db/pkg/curl-8.5.0/+CONTENTS", "");
    put(t, "var/db/pkg/notapkg/", "");
    put(t, "nix/store/", "");
    memset(&out, 0, sizeof(out));
    rs_packages_describe(t, &out);

    arr = rs_jobject_get(&out, "pip");
    CHECK_INT(arr ? arr->n : 0, 4);
    e = find(arr, "name", "requests");
    CHECK_STR(rs_jobject_str(e, "version"), "2.31.0");
    CHECK_STR(rs_jobject_str(e, "where"), "/usr/local/lib/python3.12/dist-packages");
    CHECK_STR(rs_jobject_str(find(arr, "name", "old_thing"), "version"), "1.0-py3.12");
    CHECK_STR(rs_jobject_str(find(arr, "name", "httpie"), "where"),
              "/home/pat/.local/lib/python3.13/site-packages");

    arr = rs_jobject_get(&out, "npm");
    CHECK_INT(arr ? arr->n : 0, 3);
    CHECK_STR(rs_jobject_str(find(arr, "name", "@scope/tool"), "version"), "2.0.0");
    CHECK_STR(rs_jobject_str(find(arr, "name", "npm"), "where"), "/usr/lib/node_modules");

    arr = rs_jobject_get(&out, "cargo");
    CHECK_INT(arr ? arr->n : 0, 3);
    e = find(arr, "name", "ripgrep");
    CHECK_STR(rs_jobject_str(e, "version"), "14.1.0");
    CHECK_STR(rs_jobject_str(e, "source"), "registry+https://github.com/rust-lang/crates.io-index");
    CHECK(rs_jobject_get(find(arr, "name", "bare"), "source") == NULL);

    arr = rs_jobject_get(&out, "pipx");
    CHECK_INT(arr ? arr->n : 0, 1);
    CHECK(rs_jobject_get(&arr->items[0], "version") == NULL);

    arr = rs_jobject_get(&out, "gem");
    CHECK_INT(arr ? arr->n : 0, 2);
    CHECK_STR(rs_jobject_str(find(arr, "name", "net-http"), "version"), "0.4.1");

    arr = rs_jobject_get(&out, "pkg");
    CHECK_INT(arr ? arr->n : 0, 1);
    CHECK_STR(rs_jobject_str(&arr->items[0], "name"), "curl-8.5.0");

    managers = rs_jobject_get(&out, "managers");
    CHECK(find(managers, "name", "pip") != NULL);
    CHECK_INT(rs_jobject_get(find(managers, "name", "pip"), "where")->n, 2);
    CHECK_INT(rs_jobject_get(find(managers, "name", "npm"), "where")->n, 2);
    CHECK(find(managers, "name", "cargo") != NULL);
    CHECK(find(managers, "name", "pipx") != NULL);
    CHECK(find(managers, "name", "gem") != NULL);
    CHECK(find(managers, "name", "pkg") != NULL);
    e = find(managers, "name", "nix");
    CHECK(e != NULL);
    CHECK(!is_true(e, "inventory"));
    CHECK(is_true(find(managers, "name", "pip"), "inventory"));
    CHECK(find(managers, "name", "rpm") == NULL);
    rs_jval_free(&out);
    rs_test_rmtree(t);
    free(t);
}

static void test_empty(void)
{
    char                 *t = rs_test_tmpdir();
    struct rs_jval        out;

    TEST_CASE("a tree with nothing installed");
    memset(&out, 0, sizeof(out));
    rs_packages_describe(t, &out);
    CHECK(out.type == RS_JOBJECT);
    CHECK_INT(rs_jobject_get(&out, "managers")->n, 0);
    CHECK_INT(rs_jobject_get(&out, "notes")->n, 0);
    CHECK(rs_jobject_get(&out, "apt") == NULL);
    CHECK(rs_jobject_get(&out, "snap") == NULL);
    CHECK(rs_jobject_get(&out, "flatpak") == NULL);
    rs_jval_free(&out);
    rs_test_rmtree(t);
    free(t);
}

static void test_in_index(void)
{
    char           *t = rs_test_tmpdir();
    struct rs_index ix;
    struct rs_index back;
    struct rs_buf   err;
    char           *path = rs_xasprintf("%s/index.json", t);
    FILE           *fp;
    char           *text = NULL;
    long            len = 0;

    TEST_CASE("the inventory in an index");
    make_apt(t);
    rs_index_init(&ix);
    ix.root = rs_xstrdup("/");
    rs_packages_describe(t, &ix.packages);
    fp = fopen(path, "w");
    CHECK(fp != NULL);
    if (fp)
    {
        CHECK(rs_index_write(&ix, fp));
        (void)fclose(fp);
    }
    fp = fopen(path, "r");
    CHECK(fp != NULL);
    if (fp)
    {
        (void)fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        (void)fseek(fp, 0, SEEK_SET);
        text = rs_xmalloc((size_t)len + 1);
        CHECK(fread(text, 1, (size_t)len, fp) == (size_t)len);
        text[len] = '\0';
        (void)fclose(fp);
    }
    if (!text)
    {
        text = rs_xstrdup("");
    }
    CHECK_CONTAINS(text, "\n  \"packages\": {");
    rs_index_init(&back);
    rs_buf_init(&err);
    CHECK(rs_index_parse(&back, text, (size_t)len, "index.json", &err));
    CHECK(back.packages.type == RS_JOBJECT);
    CHECK_INT(count_of(rs_jobject_get(&back.packages, "apt"), "count"), 7);
    rs_index_free(&back);
    rs_buf_free(&err);

    /* Something other than an object is refused. */
    {
        static const char bad[] =
            "{\"format\": \"restate-index\", \"version\": 1, \"packages\": [], \"entries\": []}";

        rs_index_init(&back);
        rs_buf_init(&err);
        CHECK(!rs_index_parse(&back, bad, sizeof(bad) - 1, "bad.json", &err));
        CHECK_CONTAINS(err.data, "\"packages\" is not an object");
        rs_index_free(&back);
        rs_buf_free(&err);
    }
    free(text);
    free(path);
    rs_index_free(&ix);
    rs_test_rmtree(t);
    free(t);
}

void test_packages(void)
{
    test_uri_file();
    test_apt();
    test_snap();
    test_flatpak();
    test_languages();
    test_empty();
    test_in_index();
}
