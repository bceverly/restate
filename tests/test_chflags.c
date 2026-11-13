/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chflags.h"
#include "test.h"

void test_chflags(void)
{
    struct rs_buf b;
    struct rs_buf unknown;
    char         *dir = rs_test_tmpdir();
    char         *path = rs_xasprintf("%s/f", dir);
    struct stat   st;
    int           fd;

    TEST_CASE("chflags: by name, as chflags(1) spells them");
    rs_buf_init(&b);
    rs_chflags_text(0, &b);
    CHECK_INT(b.len, 0);
    rs_chflags_text(RS_CHF_NODUMP | RS_CHF_SCHG | RS_CHF_HIDDEN, &b);
    CHECK_STR(b.data, "schg,nodump,hidden");
    rs_buf_free(&b);
    rs_buf_init(&unknown);
    CHECK_INT(rs_chflags_parse("schg,nodump,hidden", &unknown),
              RS_CHF_NODUMP | RS_CHF_SCHG | RS_CHF_HIDDEN);
    CHECK_INT(unknown.len, 0);
    CHECK_INT(rs_chflags_parse("uchg,,someday,rdonly,x", &unknown),
              RS_CHF_UCHG | RS_CHF_RDONLY);
    CHECK_STR(unknown.data, "someday,x");
    rs_buf_free(&unknown);
    CHECK_INT(rs_chflags_parse("", NULL), 0);
    CHECK_INT(rs_chflags_parse(NULL, NULL), 0);
    CHECK_INT(rs_chflags_parse("bogus", NULL), 0);

    TEST_CASE("chflags: this system's, or none");
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0);
    CHECK(fstat(fd, &st) == 0);
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    CHECK(rs_chflags_supported());
    CHECK((rs_chflags_settable() & (RS_CHF_SCHG | RS_CHF_UCHG | RS_CHF_NODUMP)) ==
          (RS_CHF_SCHG | RS_CHF_UCHG | RS_CHF_NODUMP));
    CHECK_INT(rs_chflags_of(&st), 0);
    /* nodump is the owner's to set, root or not -- where the filesystem the
     * tests run in has flags at all. */
    if (rs_chflags_set(fd, RS_CHF_NODUMP) == 0)
    {
        CHECK(fstat(fd, &st) == 0);
        CHECK_INT(rs_chflags_of(&st), RS_CHF_NODUMP);
        CHECK(rs_chflags_set(fd, 0) == 0);
    } else
    {
        CHECK(errno == EOPNOTSUPP || errno == ENOTSUP);
    }
    CHECK(!rs_chflags_thaw(fd));
#else
    CHECK(!rs_chflags_supported());
    CHECK_INT(rs_chflags_settable(), 0);
    CHECK_INT(rs_chflags_of(&st), 0);
    CHECK(rs_chflags_set(fd, RS_CHF_NODUMP) != 0);
    CHECK(!rs_chflags_thaw(fd));
#endif

    TEST_CASE("chflags: pretending, as the tests do where there are none");
    rs_chflags_pretend(true);
    CHECK(rs_chflags_supported());
    CHECK_INT(rs_chflags_settable(), 0xffff);
    CHECK(fstat(fd, &st) == 0);
    CHECK_INT(rs_chflags_of(&st), 0);
    CHECK(!rs_chflags_thaw(fd));
    CHECK(rs_chflags_set(fd, RS_CHF_SCHG | RS_CHF_NODUMP | (1u << 30)) == 0);
    CHECK_INT(rs_chflags_of(&st), RS_CHF_SCHG | RS_CHF_NODUMP);
    CHECK(rs_chflags_thaw(fd));
    CHECK_INT(rs_chflags_of(&st), RS_CHF_NODUMP);
    CHECK(rs_chflags_set(fd, RS_CHF_UAPPND) == 0);
    CHECK_INT(rs_chflags_of(&st), RS_CHF_UAPPND);
    CHECK(rs_chflags_set(-1, 0) != 0);
    rs_chflags_pretend(false);

    (void)close(fd);
    rs_test_rmtree(dir);
    free(path);
    free(dir);
}
