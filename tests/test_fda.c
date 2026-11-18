/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <string.h>

#include "fda.h"
#include "test.h"
#include "util.h"

static char *warned;

static void keep_warning(const char *msg)
{
    free(warned);
    warned = rs_xstrdup(msg);
}

void test_fda(void)
{
    char *dir = rs_test_tmpdir();
    char *database = rs_xasprintf("%s/TCC.db", dir);
    char *missing = rs_xasprintf("%s/none.db", dir);
    bool  quiet = rs_quiet;

    TEST_CASE("fda: none to ask for off macOS, or of a tree that is not this machine's");
#ifndef __APPLE__
    CHECK_INT(rs_fda_state("/"), RS_FDA_NONE);
#endif
    rs_test_write(dir, "TCC.db", "", 0644);
    rs_fda_pretend(database);
    CHECK_INT(rs_fda_state(dir), RS_FDA_NONE);
    CHECK_INT(rs_fda_state(missing), RS_FDA_NONE);

    TEST_CASE("fda: granted where the privacy database opens");
    CHECK_INT(rs_fda_state("/"), RS_FDA_GRANTED);

    TEST_CASE("fda: unknown where it is not there to open");
    rs_fda_pretend(missing);
    CHECK_INT(rs_fda_state("/"), RS_FDA_UNKNOWN);
    rs_fda_pretend(NULL);

    TEST_CASE("fda: what is said when it has not been granted");
    rs_quiet = true;
    rs_warn_hook = keep_warning;
    rs_fda_warn();
    CHECK_CONTAINS(warned ? warned : "", "has not given restate Full Disk Access");
    CHECK_CONTAINS(warned ? warned : "", "Privacy & Security, Full Disk Access");
    free(warned);
    warned = NULL;
    rs_fda_summary(0);
    CHECK(warned == NULL);
    rs_fda_summary(12);
    CHECK_STR(warned ? warned : "",
              "12 paths were refused by macOS, for want of Full Disk Access (above)");
    free(warned);
    warned = NULL;
    rs_warn_hook = NULL;
    rs_quiet = quiet;

    rs_test_rmtree(dir);
    free(missing);
    free(database);
    free(dir);
}
