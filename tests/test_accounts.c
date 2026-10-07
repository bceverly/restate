/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>

#include "accounts.h"
#include "test.h"

/* The new system: installed, its packages in, before the restore. Its
 * packages numbered postgres 128; its installer made "pat" at 1000. */
static const char now_passwd[] =
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "postgres:x:128:135:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
    "pat:x:1000:1000:Pat (installer):/home/pat:/bin/sh\n"
    "newsvc:x:127:127::/nonexistent:/usr/sbin/nologin\n";
static const char now_group[] =
    "root:x:0:\n"
    "sudo:x:27:pat\n"
    "postgres:x:135:\n"
    "pat:x:1000:\n"
    "newsvc:x:127:\n";
static const char now_shadow[] =
    "root:*:20000:0:99999:7:::\n"
    "pat:!:20000:0:99999:7:::\n";

/* The old machine, from the image: postgres was 125, pat has a real
 * password, and there was a second person and a service the new system
 * does not have, one of whose numbers is taken there. */
static const char old_passwd[] =
    "root:x:0:0:root:/root:/usr/bin/zsh\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "postgres:x:125:131:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
    "pat:x:1000:1000:Pat Smith,,,:/home/pat:/bin/zsh\n"
    "sam:x:1001:1001:Sam:/home/sam:/bin/bash\n"
    "oldsvc:x:127:128::/var/lib/oldsvc:/usr/sbin/nologin\n"
    "# a comment\n"
    "broken line\n"
    "pat:x:1999:1999:duplicate:/x:/y\n";
static const char old_group[] =
    "root:x:0:\n"
    "sudo:x:27:pat,sam\n"
    "postgres:x:131:\n"
    "pat:x:1000:\n"
    "sam:x:1001:\n"
    "oldsvc:x:128:\n"
    "docker:x:999:pat\n";
static const char old_shadow[] =
    "root:$6$rootHash:20100:0:99999:7:::\n"
    "pat:$6$patHash:20100:0:99999:7:::\n"
    "sam:$6$samHash:20100:0:99999:7:::\n";
static const char old_gshadow[] =
    "sudo:*::pat,sam\n"
    "docker:!::pat\n";

void test_accounts(void)
{
    struct rs_account_files now;
    struct rs_account_files old;
    struct rs_accounts      a;
    struct rs_buf           err;
    uint64_t                id = 0;

    TEST_CASE("accounts: the old machine's merged into the new one's");
    now.passwd = now_passwd;
    now.group = now_group;
    now.shadow = now_shadow;
    now.gshadow = NULL;
    old.passwd = old_passwd;
    old.group = old_group;
    old.shadow = old_shadow;
    old.gshadow = old_gshadow;
    rs_buf_init(&err);
    CHECK(rs_accounts_merge(&now, &old, &a, &err));

    /* Both have postgres: the new system's number, which its files carry. */
    CHECK(rs_accounts_uid(&a, "postgres", &id));
    CHECK_INT(id, 128);
    CHECK(rs_accounts_gid(&a, "postgres", &id));
    CHECK_INT(id, 135);
    /* A person both have: the old account's name, home and shell. */
    CHECK_CONTAINS(a.passwd, "pat:x:1000:1000:Pat Smith,,,:/home/pat:/bin/zsh\n");
    CHECK_CONTAINS(a.passwd, "root:x:0:0:root:/root:/usr/bin/zsh\n");
    /* A service both have keeps the new system's line whole. */
    CHECK_CONTAINS(a.passwd, "postgres:x:128:135:PostgreSQL administrator:");
    /* Only the old machine's: its old number where free... */
    CHECK(rs_accounts_uid(&a, "sam", &id));
    CHECK_INT(id, 1001);
    CHECK_CONTAINS(a.passwd, "sam:x:1001:1001:Sam:/home/sam:/bin/bash\n");
    /* ...and the next free one in its range where not: 127 is newsvc's. */
    CHECK(rs_accounts_uid(&a, "oldsvc", &id));
    CHECK_INT(id, 999);
    /* Its group kept 128, free on the new system, and the user says so. */
    CHECK_CONTAINS(a.passwd, "oldsvc:x:999:128::/var/lib/oldsvc:/usr/sbin/nologin\n");
    /* The new system's own are all still there. */
    CHECK(rs_accounts_uid(&a, "newsvc", &id));
    CHECK_INT(id, 127);
    CHECK(strstr(a.passwd, "duplicate") == NULL);
    CHECK(strstr(a.passwd, "comment") == NULL);
    /* Groups: members of both; a group only the old machine had. */
    CHECK_CONTAINS(a.group, "sudo:x:27:pat,sam\n");
    CHECK(rs_accounts_gid(&a, "docker", &id));
    CHECK_INT(id, 999);
    CHECK_CONTAINS(a.group, "docker:x:999:pat\n");
    /* Passwords: the old machine's; a new account the old one lacked keeps
     * its own, and one neither had a line for is locked. */
    CHECK_CONTAINS(a.shadow, "pat:$6$patHash:");
    CHECK_CONTAINS(a.shadow, "root:$6$rootHash:");
    CHECK_CONTAINS(a.shadow, "sam:$6$samHash:");
    CHECK_CONTAINS(a.shadow, "postgres:!:::::::\n");
    CHECK_CONTAINS(a.gshadow, "sudo:*::pat,sam\n");
    CHECK_CONTAINS(a.gshadow, "root:!::\n");
    CHECK(!rs_accounts_uid(&a, "nobody-here", &id));
    CHECK(!rs_accounts_gid(&a, NULL, &id));
    rs_accounts_free(&a);

    TEST_CASE("accounts: onto a system with none, the old ones as they were");
    memset(&now, 0, sizeof(now));
    CHECK(rs_accounts_merge(&now, &old, &a, &err));
    CHECK(rs_accounts_uid(&a, "postgres", &id));
    CHECK_INT(id, 125);
    CHECK(rs_accounts_uid(&a, "oldsvc", &id));
    CHECK_INT(id, 127);
    CHECK(a.gshadow != NULL);
    rs_accounts_free(&a);

    TEST_CASE("accounts: an image without them");
    memset(&old, 0, sizeof(old));
    CHECK(!rs_accounts_merge(&now, &old, &a, &err));
    CHECK_CONTAINS(err.data, "no /etc/passwd or /etc/group");
    rs_buf_free(&err);
}
