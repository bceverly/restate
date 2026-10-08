/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <time.h>

#include "glob.h"
#include "test.h"
#include "util.h"

void test_glob(void)
{
    TEST_CASE("glob: literals and anchoring");
    CHECK(rs_glob_match("/etc/passwd", "/etc/passwd"));
    CHECK(!rs_glob_match("/etc/passwd", "/etc/passwd2"));
    CHECK(!rs_glob_match("/etc/passwd", "/etc/passw"));
    CHECK(!rs_glob_match("/etc", "/var/etc"));
    CHECK(rs_glob_match("/", "/"));
    CHECK(!rs_glob_match("/", "/etc"));

    TEST_CASE("glob: * does not cross a slash, ** does");
    CHECK(rs_glob_match("/var/*/x", "/var/lib/x"));
    CHECK(!rs_glob_match("/var/*/x", "/var/lib/a/x"));
    CHECK(rs_glob_match("/var/**/x", "/var/lib/a/x"));
    CHECK(rs_glob_match("/var/**/x", "/var/x"));
    CHECK(rs_glob_match("/var/**", "/var/a/b/c"));
    CHECK(rs_glob_match("/var/*", "/var/abc"));
    CHECK(rs_glob_match("/var/a*c", "/var/ac"));
    CHECK(rs_glob_match("/var/a*c", "/var/abbbc"));
    CHECK(!rs_glob_match("/var/a*c", "/var/ab/c"));
    CHECK(rs_glob_match("/a**b", "/a/x/yb"));
    CHECK(rs_glob_match("/**", "/"));

    TEST_CASE("glob: ? and escapes");
    CHECK(rs_glob_match("/tmp/?", "/tmp/a"));
    CHECK(!rs_glob_match("/tmp/?", "/tmp/ab"));
    CHECK(!rs_glob_match("/tmp?x", "/tmp/x"));
    CHECK(rs_glob_match("/a\\*b", "/a*b"));
    CHECK(!rs_glob_match("/a\\*b", "/axb"));
    CHECK(rs_glob_match("/a\\?", "/a?"));
    CHECK(rs_glob_match("/trailing\\", "/trailing\\"));

    TEST_CASE("glob: unanchored patterns match at any depth");
    CHECK(rs_glob_match("*.pid", "/run/sshd.pid"));
    CHECK(rs_glob_match("*.pid", "/a/b/c/d.pid"));
    CHECK(!rs_glob_match("*.pid", "/a/b.pidx"));
    CHECK(rs_glob_match(".cache", "/home/u/.cache"));
    CHECK(!rs_glob_match(".cache", "/home/u/x.cache"));
    CHECK(rs_glob_match("lib/*.so", "/usr/lib/x.so"));

    TEST_CASE("glob: a rule covers a directory and everything under it");
    CHECK(rs_glob_covers("/tmp", "/tmp"));
    CHECK(rs_glob_covers("/tmp", "/tmp/a/b"));
    CHECK(!rs_glob_covers("/tmp", "/tmpfile"));
    CHECK(rs_glob_covers(".cache", "/home/u/.cache/fontconfig/x"));
    CHECK(rs_glob_covers("/var/*/cache", "/var/x/cache/y"));
    CHECK(!rs_glob_covers("/var/log", "/var"));
    CHECK(!rs_glob_covers("/x", ""));          /* found by the fuzzer */
    CHECK(rs_glob_covers("", ""));

    TEST_CASE("glob: no pathological patterns");
    {
        /* Exponential for a backtracking matcher; linear here. Timed loosely:
         * the point is that it finishes, not how fast. */
        struct rs_buf pat;
        struct rs_buf path;
        clock_t       start = clock();
        int           i;

        rs_buf_init(&pat);
        rs_buf_init(&path);
        rs_buf_addc(&pat, '/');
        for (i = 0; i < 40; i++)
        {
            rs_buf_addstr(&pat, "*a");
        }
        rs_buf_addc(&pat, 'b');
        rs_buf_addc(&path, '/');
        for (i = 0; i < 200; i++)
        {
            rs_buf_addc(&path, 'a');
        }
        CHECK(!rs_glob_match(pat.data, path.data));
        rs_buf_reset(&pat);
        for (i = 0; i < 500; i++)
        {
            rs_buf_addstr(&pat, "**/");
        }
        rs_buf_addstr(&pat, "x");
        CHECK(rs_glob_match(pat.data, "/a/b/x"));
        CHECK((double)(clock() - start) / CLOCKS_PER_SEC < 5.0);
        rs_buf_free(&pat);
        rs_buf_free(&path);
    }

    TEST_CASE("glob: covering in one pass is covering an ancestor at a time");
    {
        static const char *const pats[] = {
            "/usr", "/usr/", "/", "/usr/lib/*/gio/modules/giomodule.cache", "/boot/initrd.img*",
            "/usr/share/fonts/**/fonts.dir", "*.pid", ".cache", "**/node_modules",
            "/home/*/Downloads", "/a\\*b", "/**", "a/b", "/usr/lib/modules/*/modules.*", "?",
            "/x*", "**", "*", "/etc/systemd/system/*.wants/snap-*",
        };
        static const char *const paths[] = {
            "/", "/usr", "/usr/lib", "/usrx", "/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache",
            "/boot/initrd.img-7.0", "/boot/initrd.img-7.0/x", "/usr/share/fonts/X11/misc/fonts.dir",
            "/run/sshd.pid", "/run/sshd.pid/x", "/home/u/.cache/a/b", "/home/u/x.cache",
            "/p/node_modules/q/r", "/home/u/Downloads/f", "/a*b/c", "/ab", "/a/b/c", "/x/a/b",
            "//", "//x", "", "a", "/usr/lib/modules/7.0/modules.dep",
            "/etc/systemd/system/multi-user.target.wants/snap-x.mount",
        };
        size_t i;
        size_t j;

        for (i = 0; i < sizeof(pats) / sizeof(pats[0]); i++)
        {
            for (j = 0; j < sizeof(paths) / sizeof(paths[0]); j++)
            {
                /* The definition: the path, or the path up to any '/' after
                 * its first character. */
                bool   want = rs_glob_match(pats[i], paths[j]);
                char  *copy = rs_xstrdup(paths[j]);
                size_t k;

                for (k = 1; copy[0] != '\0' && copy[k] != '\0' && !want; k++)
                {
                    if (copy[k] == '/')
                    {
                        copy[k] = '\0';
                        want = rs_glob_match(pats[i], copy);
                        copy[k] = '/';
                    }
                }
                free(copy);
                if (rs_glob_covers(pats[i], paths[j]) != want)
                {
                    CHECK_STR(pats[i], paths[j]);
                }
            }
        }
        CHECK(rs_glob_covers("/usr", "/usr/lib/x"));
        CHECK(!rs_glob_covers("/usr", "/usrx"));
    }
}
