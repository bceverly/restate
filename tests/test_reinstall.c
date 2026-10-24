/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "json.h"
#include "packages.h"
#include "reinstall.h"
#include "test.h"

/* An old machine: two packages by hand, one held, one as a dependency, one
 * from a .deb the image kept, one whose name is not one Debian allows; a key
 * outside /etc and one inside it; snaps, a flatpak, pip and an alternative. */
static const char inventory[] =
    "{\"apt\": {\"architectures\": [\"amd64\"],"
    " \"keys\": ["
    "  {\"path\": \"/usr/share/keyrings/vendor.gpg\", \"data\": \"bVFFTmEyVjU=\"},"
    "  {\"path\": \"/etc/apt/trusted.gpg.d/in-etc.gpg\", \"data\": \"bVFFTmEyVjU=\"},"
    "  {\"path\": \"/usr/share/keyrings/../evil.gpg\", \"data\": \"bVFF\"},"
    "  {\"path\": \"/usr/share/keyrings/odd.gpg\", \"data\": \"$(reboot)\"}],"
    " \"packages\": ["
    "  {\"name\": \"jq\", \"architecture\": \"amd64\", \"version\": \"1.7\", \"manual\": true},"
    "  {\"name\": \"libjq1\", \"architecture\": \"amd64\", \"version\": \"1.7\", \"manual\": "
    "false},"
    "  {\"name\": \"tzdata\", \"architecture\": \"all\", \"version\": \"2026a\", \"manual\": "
    "false},"
    "  {\"name\": \"htop\", \"architecture\": \"amd64\", \"version\": \"3.3\", \"manual\": true,"
    "   \"hold\": true},"
    "  {\"name\": \"zoom\", \"architecture\": \"amd64\", \"version\": \"6.0\", \"manual\": true,"
    "   \"unavailable\": \"local\", \"kept\": \"/var/cache/apt/archives/zoom_6.0_amd64.deb\"},"
    "  {\"name\": \"bad;name\", \"architecture\": \"amd64\", \"version\": \"1\", \"manual\": true},"
    "  {\"name\": \"linux-image-6.8.0-1-generic\", \"architecture\": \"amd64\","
    "   \"version\": \"6.8.0-1\", \"manual\": true}]},"
    " \"snap\": ["
    "  {\"name\": \"firefox\", \"revision\": \"1\", \"channel\": \"latest/stable\"},"
    "  {\"name\": \"code\", \"revision\": \"2\", \"classic\": true},"
    "  {\"name\": \"core22\", \"revision\": \"3\"},"
    "  {\"name\": \"mine\", \"revision\": \"x1\", \"local\": true,"
    "   \"kept\": \"/var/lib/snapd/snaps/mine_x1.snap\"},"
    "  {\"name\": \"lost\", \"revision\": \"x2\", \"local\": true},"
    "  {\"name\": \"Bad Snap\", \"revision\": \"4\"}],"
    " \"flatpak\": {\"remotes\": [{\"name\": \"flathub\", \"url\": "
    "\"https://dl.flathub.org/repo/\","
    "   \"scope\": \"system\"}],"
    "  \"apps\": [{\"id\": \"org.gimp.GIMP\", \"branch\": \"stable\", \"remote\": \"flathub\","
    "   \"scope\": \"system\"},"
    "   {\"id\": \"org.home.App\", \"branch\": \"stable\", \"remote\": \"flathub\","
    "   \"scope\": \"user\"}]},"
    " \"pip\": [{\"name\": \"requests\", \"version\": \"2.31\", \"where\": \"/usr/local/lib\"},"
    "  {\"name\": \"mine\", \"version\": \"1\", \"where\": \"/home/pat/.local\"}],"
    " \"npm\": [{\"name\": \"left-pad\", \"version\": \"1.3\", \"where\": "
    "\"/usr/local/lib/node_modules\"},"
    "  {\"name\": \"npm\", \"version\": \"9\", \"where\": \"/usr/lib/node_modules\"}],"
    " \"gem\": [{\"name\": \"rake\", \"version\": \"13\", \"where\": \"/var/lib/gems\"}],"
    " \"alternatives\": [{\"name\": \"editor\", \"path\": \"/usr/bin/vim.basic\"}]}";

/* Each fake logs how it was called; apt-mark and dpkg-query answer as the
 * new machine would: cowsay installed by hand there, and jq at 1.6. */
static const char fake_apt_get[] =
    "#!/bin/sh\n"
    "[ \"$1\" = -s ] || echo \"apt-get $*\" >> \"$LOG\"\n";
static const char fake_apt_mark[] =
    "#!/bin/sh\n"
    "if [ \"$1\" = showmanual ]; then\n"
    "  printf 'jq\\nhtop\\ncowsay\\nlinux-image-generic\\nintel-microcode\\nqemu-guest-agent\\n'\n"
    "  exit 0\n"
    "fi\n"
    "echo \"apt-mark $*\" >> \"$LOG\"\n";
static const char fake_dpkg_query[] =
    "#!/bin/sh\n"
    "case \"$*\" in\n"
    "  *'${Package}'*) printf 'jq:amd64 installed\\nlibjq1:amd64 installed\\n"
    "tzdata:all installed\\nhtop:amd64 installed\\ncowsay:amd64 installed\\n'; exit 0 ;;\n"
    "  *' jq:amd64') printf 'installed 1.6' ;;\n"
    "  *) printf installed ;;\n"
    "esac\n";
static const char fake_dpkg[] = "#!/bin/sh\necho amd64\n";
static const char fake_log[] = "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$LOG\"\n";

static void read_log(const char *dir, struct rs_buf *out)
{
    rs_buf_init(out);
    CHECK(rs_read_beneath(dir, "/log", 65536, out));
}

void test_reinstall(void)
{
    char                    *t = rs_test_tmpdir();
    char                    *cache = rs_xasprintf("%s/cache", t);
    struct rs_jval           pk;
    struct rs_json_parser    jp;
    struct rs_reinstall_opts o;
    struct rs_buf            err;
    struct rs_buf            script;
    struct rs_buf            log;

    TEST_CASE("reinstall: the script restore --packages runs");
    memset(&pk, 0, sizeof(pk));
    rs_buf_init(&err);
    rs_json_init(&jp, inventory, sizeof(inventory) - 1, &err);
    CHECK(rs_json_value(&jp, &pk));
    rs_buf_free(&err);
    (void)mkdir(cache, 0755);
    rs_test_write(cache, "jq_1.7_amd64.deb", "deb", 0644);
    memset(&o, 0, sizeof(o));
    o.cache = cache;
    rs_buf_init(&script);
    rs_reinstall_script(&pk, &o, &script);
    /* The key outside /etc, and none of the others. */
    CHECK_CONTAINS(script.data, "mkdir -p /usr/share/keyrings && echo bVFFTmEyVjU= | base64 -d > "
                                "/usr/share/keyrings/vendor.gpg");
    CHECK(strstr(script.data, "in-etc.gpg") == NULL);
    CHECK(strstr(script.data, "evil") == NULL);
    CHECK(strstr(script.data, "reboot") == NULL);
    /* The baseline: jq is there, and installed from it if apt cannot. */
    CHECK_CONTAINS(script.data, "<<'CACHED'\njq_1.7_amd64.deb\nCACHED\n");
    CHECK_CONTAINS(script.data, "<<'BASELINE'\njq:amd64 1.7 jq_1.7_amd64.deb\nBASELINE\n");
    CHECK_CONTAINS(script.data, "exact=''\n");
    /* The kept .deb, the holds, the kernel and the bad name left to others. */
    CHECK_CONTAINS(script.data, "[ -f /var/cache/apt/archives/zoom_6.0_amd64.deb ] && kept=");
    CHECK_CONTAINS(script.data, "apt-mark hold htop:amd64 >");
    CHECK(strstr(script.data, "bad;name") == NULL);
    CHECK(strstr(script.data, "\nlinux-image-6.8.0-1-generic=") == NULL);
    /* Each one's mark, an Architecture: all one under the machine's own. */
    CHECK_CONTAINS(script.data, "manual jq:amd64\nauto libjq1:amd64\nauto tzdata:amd64\n");
    /* Snaps: by channel, classic, from the kept file; not the bases, not one
     * from a file the image did not keep, not a name snapd does not allow. */
    CHECK_CONTAINS(script.data, "snap install firefox --channel=latest/stable ");
    CHECK_CONTAINS(script.data, "snap install code --classic ");
    CHECK_CONTAINS(script.data, "snap install --dangerous /var/lib/snapd/snaps/mine_x1.snap ");
    CHECK(strstr(script.data, "core22") == NULL);
    CHECK(strstr(script.data, "lost") == NULL);
    CHECK(strstr(script.data, "Bad Snap") == NULL);
    CHECK_CONTAINS(script.data, "flatpak remote-add --if-not-exists flathub "
                                "https://dl.flathub.org/repo/");
    CHECK_CONTAINS(script.data, "flatpak install -y --noninteractive flathub "
                                "org.gimp.GIMP//stable");
    CHECK(strstr(script.data, "org.home.App") == NULL);
    CHECK_CONTAINS(script.data, "pip install --break-system-packages requests==2.31 ");
    CHECK(strstr(script.data, "mine==1") == NULL);
    CHECK_CONTAINS(script.data, "npm install -g left-pad@1.3 ");
    CHECK(strstr(script.data, "npm@9") == NULL);   /* apt's, in npm's own directory */
    CHECK_CONTAINS(script.data, "gem install rake:13 ");
    CHECK_CONTAINS(script.data, "update-alternatives --set editor /usr/bin/vim.basic ");
    CHECK_CONTAINS(script.data, "\nexit 0\n");

    TEST_CASE("reinstall: run, against a new machine's apt");
    {
        static const char *const logged[] = { "snap", "flatpak", "pip", "gem",
                                              "update-alternatives", "base64", "cp" };
        char                    *body;
        char                    *cmd;
        size_t                   i;

        rs_test_write(t, "apt-get", fake_apt_get, 0755);
        rs_test_write(t, "apt-mark", fake_apt_mark, 0755);
        rs_test_write(t, "dpkg-query", fake_dpkg_query, 0755);
        rs_test_write(t, "dpkg", fake_dpkg, 0755);
        for (i = 0; i < sizeof(logged) / sizeof(logged[0]); i++)
        {
            rs_test_write(t, logged[i], fake_log, 0755);
        }
        rs_test_write(t, "log", "", 0644);
        /* The fakes first: the script sets a PATH of its own. */
        body = rs_xstrdup(script.data);
        {
            char *at = strstr(body, "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");

            CHECK(at != NULL);
            if (at)
            {
                char *fixed = rs_xasprintf("%.*sPATH=%s:/usr/bin:/bin\n%s", (int)(at - body), body,
                                           t, at + strlen("PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"));

                free(body);
                body = fixed;
            }
        }
        rs_test_write(t, "packages.sh", body, 0700);
        free(body);
        cmd = rs_xasprintf("cd '%s' && LOG='%s/log' sh packages.sh > out 2>&1", t, t);
        CHECK(system(cmd) == 0);
        free(cmd);
        read_log(t, &log);
        CHECK_CONTAINS(log.data, "apt-get update\n");
        CHECK_CONTAINS(log.data, "apt-get install -y jq=1.7 htop=3.3\n");
        CHECK_CONTAINS(log.data, "apt-mark hold htop:amd64\n");
        CHECK_CONTAINS(log.data, "apt-mark manual jq:amd64 htop:amd64\n");
        CHECK_CONTAINS(log.data, "apt-mark auto libjq1:amd64 tzdata:amd64\n");
        /* Not on the old machine: cowsay; never the kernel, microcode or a
         * virtual machine's guest agent. */
        CHECK_CONTAINS(log.data, "apt-mark auto cowsay:amd64\n");
        CHECK(strstr(log.data, "linux-image-generic") == NULL);
        CHECK(strstr(log.data, "intel-microcode") == NULL);
        CHECK(strstr(log.data, "qemu-guest-agent") == NULL);
        CHECK_CONTAINS(log.data, "apt-get autoremove -y\n");
        /* jq is installed at 1.6, not 1.7: without --exact-versions, kept. */
        CHECK(strstr(log.data, "/var/cache/apt/archives/jq_1.7_amd64.deb") == NULL);
        CHECK_CONTAINS(log.data, "snap install firefox --channel=latest/stable\n");
        CHECK_CONTAINS(log.data, "update-alternatives --set editor /usr/bin/vim.basic\n");
        rs_buf_free(&log);

        /* With --exact-versions, jq goes back to 1.7, from the baseline. */
        rs_buf_reset(&script);
        o.snapshot = "20261010T000000Z";
        rs_reinstall_script(&pk, &o, &script);
        CHECK_CONTAINS(script.data, "exact='yes'\n");
        body = rs_xstrdup(script.data);
        {
            char *at = strstr(body, "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");

            if (at)
            {
                char *fixed = rs_xasprintf("%.*sPATH=%s:/usr/bin:/bin\n%s", (int)(at - body), body,
                                           t, at + strlen("PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"));

                free(body);
                body = fixed;
            }
        }
        rs_test_write(t, "packages.sh", body, 0700);
        free(body);
        rs_test_write(t, "log", "", 0644);
        cmd = rs_xasprintf("cd '%s' && LOG='%s/log' sh packages.sh > out 2>&1", t, t);
        CHECK(system(cmd) == 0);
        free(cmd);
        read_log(t, &log);
        CHECK_CONTAINS(log.data, "apt-get install -y --allow-downgrades "
                                 "/var/cache/apt/archives/jq_1.7_amd64.deb\n");
        rs_buf_free(&log);
    }

    TEST_CASE("reinstall: a machine of another architecture is not marked");
    {
        char *cmd;
        char *body;

        rs_test_write(t, "dpkg", "#!/bin/sh\necho arm64\n", 0755);
        rs_test_write(t, "log", "", 0644);
        body = rs_xstrdup(script.data);
        {
            char *at = strstr(body, "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");

            if (at)
            {
                char *fixed = rs_xasprintf("%.*sPATH=%s:/usr/bin:/bin\n%s", (int)(at - body), body,
                                           t, at + strlen("PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"));

                free(body);
                body = fixed;
            }
        }
        rs_test_write(t, "packages.sh", body, 0700);
        free(body);
        cmd = rs_xasprintf("cd '%s' && LOG='%s/log' sh packages.sh > out 2>&1", t, t);
        CHECK(system(cmd) == 0);
        free(cmd);
        read_log(t, &log);
        CHECK(strstr(log.data, "apt-mark auto cowsay") == NULL);
        CHECK(strstr(log.data, "autoremove") == NULL);
        rs_buf_free(&log);
        CHECK(rs_read_beneath(t, "/out", 65536, &log));
        CHECK_CONTAINS(log.data, "this machine is not amd64");
        rs_buf_free(&log);
    }

    TEST_CASE("reinstall: offline, apt's one repository is the baseline");
    {
        /* apt-get, offline: logs the configuration it was given, and the
         * repository's index, when it is told to update. */
        static const char offline_apt_get[] =
            "#!/bin/sh\n"
            "[ \"$1\" = -s ] && exit 0\n"
            "echo \"apt-get $*\" >> \"$LOG\"\n"
            "if [ \"$1\" = update ] && [ -n \"$APT_CONFIG\" ]; then\n"
            "  cat \"$APT_CONFIG\" \"${APT_CONFIG%/apt.conf}/sources.list\" \\\n"
            "      \"${APT_CONFIG%/apt.conf}/repo/Packages\" "
            "\"${APT_CONFIG%/apt.conf}/repo/Release\" "
            ">> \"$LOG\"\n"
            "fi\n";
        static const char fake_dpkg_deb[] =
            "#!/bin/sh\n"
            "[ \"$1\" = -f ] || exit 2\n"
            "case $2 in\n"
            "  */jq_1.7_amd64.deb) printf 'Package: jq\\nVersion: 1.7\\nArchitecture: amd64\\n"
            "Depends: libjq1\\nFilename: lie\\n' ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n";
        char *body;
        char *cmd;
        char *at;

        memset(&o, 0, sizeof(o));
        o.cache = cache;
        o.offline = true;
        rs_buf_reset(&script);
        rs_reinstall_script(&pk, &o, &script);
        /* The baseline is the repository: not copied into apt's cache, nor
         * installed from after. */
        CHECK_CONTAINS(script.data, "<<'CACHED'\njq_1.7_amd64.deb\nCACHED\n");
        CHECK_CONTAINS(script.data, "<<'KEPT'\n/var/cache/apt/archives/zoom_6.0_amd64.deb\nKEPT\n");
        CHECK(strstr(script.data, "cp \"$cache/$f\"") == NULL);
        CHECK(strstr(script.data, "<<'BASELINE'") == NULL);
        CHECK_CONTAINS(script.data, "export APT_CONFIG\n");
        /* The stores are on the network: only the snap the image keeps. */
        CHECK_CONTAINS(script.data, "snap install --dangerous /var/lib/snapd/snaps/mine_x1.snap ");
        CHECK_CONTAINS(script.data, "offline, so the snap firefox is not put back");
        CHECK(strstr(script.data, "snap install firefox") == NULL);
        CHECK(strstr(script.data, "flatpak install") == NULL);
        CHECK(strstr(script.data, "pip install") == NULL);
        CHECK_CONTAINS(script.data, "offline, so not put back: 1 flatpaks, 1 Python, 1 npm and 1 "
                                    "Ruby packages");
        /* Not even with a snapshot asked for. */
        o.snapshot = "20261010T000000Z";
        rs_buf_reset(&script);
        rs_reinstall_script(&pk, &o, &script);
        CHECK(strstr(script.data, "--snapshot") == NULL);

        /* Run only where it would be: on the PATH the script sets, as an
         * Ubuntu has it. FreeBSD keeps it in /sbin; macOS has it only from
         * Homebrew, which that PATH leaves out. */
        if (system("PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v sha256sum > /dev/null 2>&1") !=
            0)
        {
            (void)printf("  (the offline script is not run: it needs sha256sum)\n");
            goto offline_done;
        }
        rs_test_write(t, "apt-get", offline_apt_get, 0755);
        rs_test_write(t, "dpkg-deb", fake_dpkg_deb, 0755);
        rs_test_write(t, "dpkg", fake_dpkg, 0755);
        rs_test_write(t, "log", "", 0644);
        body = rs_xstrdup(script.data);
        at = strstr(body, "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");
        CHECK(at != NULL);
        if (at)
        {
            char *fixed = rs_xasprintf("%.*sPATH=%s:/usr/sbin:/usr/bin:/sbin:/bin\n%s",
                                       (int)(at - body), body, t,
                                       at + strlen("PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"));

            free(body);
            body = fixed;
        }
        rs_test_write(t, "packages.sh", body, 0700);
        free(body);
        cmd = rs_xasprintf("cd '%s' && LOG='%s/log' sh packages.sh > out 2>&1", t, t);
        CHECK(system(cmd) == 0);
        free(cmd);
        read_log(t, &log);
        /* Its own sources and lists, and the index made from dpkg-deb's
         * fields: the package's own Filename replaced, the size and digest
         * the file's. */
        CHECK_CONTAINS(log.data, "Dir::Etc::SourceParts \"");
        CHECK_CONTAINS(log.data, "APT::Sandbox::User \"root\";\n");
        CHECK_CONTAINS(log.data, "deb [trusted=yes] file:");
        CHECK_CONTAINS(log.data, "Package: jq\nVersion: 1.7\nArchitecture: amd64\nDepends: libjq1\n"
                                 "Filename: ./jq_1.7_amd64.deb\nSize: 3\nSHA256: "
                                 "9cfa1468c93fc18652e34a000f0c6614"
                                 "b0fa18f6f4887477ad9b0d36ca6a7eaa\n");
        CHECK(strstr(log.data, "lie") == NULL);
        CHECK_CONTAINS(log.data, "\nSHA256:\n ");
        CHECK_CONTAINS(log.data, "apt-get install -y jq=1.7 htop=3.3\n");
        rs_buf_free(&log);
        CHECK(rs_read_beneath(t, "/out", 65536, &log));
        CHECK_CONTAINS(log.data, "restate: offline: apt installs from 1 packages, "
                                 "and nothing else");
        rs_buf_free(&log);
    offline_done:;
    }

    TEST_CASE("reinstall: an inventory with no apt, and no cache");
    {
        static const char only_snaps[] = "{\"snap\": [{\"name\": \"hello\", \"revision\": \"1\"}]}";
        struct rs_jval    sp;

        memset(&sp, 0, sizeof(sp));
        rs_buf_init(&err);
        rs_json_init(&jp, only_snaps, sizeof(only_snaps) - 1, &err);
        CHECK(rs_json_value(&jp, &sp));
        rs_buf_free(&err);
        memset(&o, 0, sizeof(o));
        rs_buf_reset(&script);
        rs_reinstall_script(&sp, &o, &script);
        CHECK(strstr(script.data, "apt-get") == NULL);
        CHECK_CONTAINS(script.data, "snap install hello ");
        rs_jval_free(&sp);
    }

    rs_buf_free(&script);
    rs_jval_free(&pk);
    rs_test_rmtree(t);
    free(cache);
    free(t);
}
