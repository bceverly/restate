/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "reinstall.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "baseline.h"
#include "index.h"
#include "packages.h"

#define APT_ARCHIVES "/var/cache/apt/archives"

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static bool flag(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return v && v->type == RS_JBOOL && v->b;
}

static bool only(const char *s, const char *allowed)
{
    return s && s[0] != '\0' && strspn(s, allowed) == strlen(s);
}

/* A Debian package name, or architecture. */
static bool deb_name(const char *s)
{
    return only(s, "abcdefghijklmnopqrstuvwxyz0123456789+.-") && s[0] != '-' && s[0] != '.';
}

static bool deb_version(const char *s)
{
    return only(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+~:-");
}

/* A snap's name or channel. */
static bool snap_word(const char *s)
{
    return only(s, "abcdefghijklmnopqrstuvwxyz0123456789-./_") && s[0] != '-';
}

/* The machine's own architecture: the first dpkg lists, or -- in an
 * inventory from before 1.5 of a machine with one -- dpkg's own. */
static const char *native_arch(const struct rs_jval *apt)
{
    const struct rs_jval *archs = rs_jobject_get(apt, "architectures");
    const struct rs_jval *pkgs = rs_jobject_get(apt, "packages");
    size_t                i;

    if (archs && archs->type == RS_JARRAY && archs->n > 0 && archs->items[0].type == RS_JSTRING)
    {
        return deb_name(archs->items[0].s) ? archs->items[0].s : NULL;
    }
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const char *arch = rs_jobject_str(&pkgs->items[i], "architecture");

        if (eq(rs_jobject_str(&pkgs->items[i], "name"), "dpkg") && deb_name(arch) &&
            strcmp(arch, "all") != 0)
        {
            return arch;
        }
    }
    return NULL;
}

/* "name:arch", the architecture of an Architecture: all package being the
 * machine's own, as apt-mark and dpkg-query are told it below. */
static char *qualified(const struct rs_jval *p, const char *native)
{
    const char *name = rs_jobject_str(p, "name");
    const char *arch = rs_jobject_str(p, "architecture");

    if (!deb_name(name) || !deb_name(arch))
    {
        return NULL;
    }
    return rs_xasprintf("%s:%s", name, strcmp(arch, "all") == 0 ? native : arch);
}

static void header(struct rs_buf *out)
{
    rs_buf_addstr(out,
                  "#!/bin/sh\n"
                  "# Written by restate restore --packages: the old machine's packages put\n"
                  "# back onto this one. Each step goes on whatever the one before it did:\n"
                  "# the files restored after this are worth more than any one package.\n"
                  "set -f\n"
                  "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
                  "export PATH\n"
                  "export DEBIAN_FRONTEND=noninteractive\n"
                  "exec < /dev/null\n"
                  "work=$(mktemp -d) || exit 1\n"
                  "trap 'rm -rf \"$work\"' EXIT\n");
}

/* The keys kept outside /etc, which the kit does not carry. */
static void keys(const struct rs_jval *apt, struct rs_buf *out)
{
    const struct rs_jval *arr = rs_jobject_get(apt, "keys");
    bool                  any = false;
    size_t                i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const char *path = rs_jobject_str(&arr->items[i], "path");
        const char *data = rs_jobject_str(&arr->items[i], "data");
        const char *slash;
        char       *dir;

        if (!path || !data || path[0] != '/' || !rs_path_is_clean(path) ||
            rs_starts_with(path, "/etc/") ||
            !only(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="))
        {
            continue;
        }
        if (!any)
        {
            rs_buf_addstr(out, "# The repositories' keys kept outside /etc.\n");
            any = true;
        }
        slash = strrchr(path, '/');
        dir = slash == path ? rs_xstrdup("/") : rs_xstrndup(path, (size_t)(slash - path));
        rs_buf_addstr(out, "mkdir -p ");
        rs_shell_word(out, dir);
        rs_buf_addf(out, " && echo %s | base64 -d > ", data);
        rs_shell_word(out, path);
        rs_buf_addstr(out, " || echo 'restate: a repository key could not be written' >&2\n");
        free(dir);
    }
}

/* Whether the baseline cache has `deb`. */
static bool cached(const char *cache, const char *deb)
{
    struct stat st;
    char       *path;
    bool        ok;

    if (!cache || !deb)
    {
        return false;
    }
    path = rs_xasprintf("%s/%s", cache, deb);
    ok = lstat(path, &st) == 0 && S_ISREG(st.st_mode);
    free(path);
    return ok;
}

/* The baseline's packages into apt's own cache, where apt finds them by name
 * and checks them against its lists before using them. */
static size_t copy_baseline(const struct rs_jval *pkgs, const char *cache, struct rs_buf *out)
{
    size_t n = 0;
    size_t i;

    for (i = 0; cache && pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        char                 *deb = rs_baseline_deb_name(rs_jobject_str(p, "name"),
                                                         rs_jobject_str(p, "version"),
                                                         rs_jobject_str(p, "architecture"));

        if (cached(cache, deb))
        {
            if (n == 0)
            {
                rs_buf_addstr(out, "# The baseline: the exact packages, fetched before.\n"
                                   "cache=");
                rs_shell_word(out, cache);
                rs_buf_addstr(out, "\nwhile read -r f; do\n"
                                   "  cp \"$cache/$f\" " APT_ARCHIVES "/ 2> /dev/null || true\n"
                                   "done <<'CACHED'\n");
            }
            rs_buf_addf(out, "%s\n", deb);
            n++;
        }
        free(deb);
    }
    if (n > 0)
    {
        rs_buf_addstr(out, "CACHED\n");
    }
    return n;
}

/* Whether `kept`, an inventory's path to a kept .deb, is one the script can
 * name without quoting. */
static bool kept_path(const char *kept)
{
    size_t n = kept ? strlen(kept) : 0;

    return kept && kept[0] == '/' && rs_path_is_clean(kept) && n >= 5 &&
           strcmp(kept + n - 4, ".deb") == 0 &&
           only(kept, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/._+~%:-");
}

/*
 * Offline: apt's only repository, made in "$work/repo" of the baseline's
 * packages and the kept .deb files, and APT_CONFIG naming it alone, with
 * lists of its own -- for every apt-get the script runs after this.
 */
static void offline_repo(const struct rs_jval *pkgs, const char *cache, struct rs_buf *out)
{
    size_t i;

    rs_buf_addstr(out, "# Offline: apt's one repository, made here of the baseline's packages and\n"
                       "# the image's kept .deb files. Trusted unsigned: baseline fetch checked\n"
                       "# each against its vendor's signed index, into a cache only root can\n"
                       "# write, and restore checked the kept ones against the image's index.\n"
                       "repo=\"$work/repo\"\n"
                       "mkdir -p \"$repo\" \"$work/lists/partial\" \"$work/parts\"\n"
                       ": > \"$repo/Packages\"\n"
                       "# Each one's own fields, its Filename the repository's, and its size\n"
                       "# and digest, as apt checks them.\n"
                       "index() {\n"
                       "  fields=$(dpkg-deb -f \"$repo/$1\" 2> /dev/null | grep -v '^Filename:') "
                       "|| return 0\n"
                       "  printf '%s\\nFilename: ./%s\\nSize: %s\\nSHA256: %s\\n\\n' \"$fields\" "
                       "\"$1\" \\\n"
                       "    \"$(wc -c < \"$repo/$1\" | tr -d ' ')\" "
                       "\"$(sha256sum < \"$repo/$1\" | cut -d ' ' -f 1)\" >> \"$repo/Packages\"\n"
                       "}\n"
                       "cache=");
    rs_shell_word(out, cache);
    rs_buf_addstr(out, "\nwhile read -r f; do\n"
                       "  [ -f \"$cache/$f\" ] && ln -s \"$cache/$f\" \"$repo/$f\" 2> /dev/null && "
                       "index \"$f\"\n"
                       "done <<'CACHED'\n");
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        char                 *deb = rs_baseline_deb_name(rs_jobject_str(p, "name"),
                                                         rs_jobject_str(p, "version"),
                                                         rs_jobject_str(p, "architecture"));

        if (cached(cache, deb))
        {
            rs_buf_addf(out, "%s\n", deb);
        }
        free(deb);
    }
    rs_buf_addstr(out, "CACHED\n"
                       "while read -r f; do\n"
                       "  [ -f \"$f\" ] && ln -s \"$f\" \"$repo/${f##*/}\" 2> /dev/null && "
                       "index \"${f##*/}\"\n"
                       "done <<'KEPT'\n");
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const char *kept = rs_jobject_str(&pkgs->items[i], "kept");

        if (kept_path(kept))
        {
            rs_buf_addf(out, "%s\n", kept);
        }
    }
    rs_buf_addstr(out,
                  "KEPT\n"
                  "printf 'Date: %s\\nSHA256:\\n %s %s Packages\\n' \"$(LC_ALL=C date -Ru)\" \\\n"
                  "  \"$(sha256sum < \"$repo/Packages\" | cut -d ' ' -f 1)\" "
                  "\"$(wc -c < \"$repo/Packages\" | tr -d ' ')\" > \"$repo/Release\"\n"
                  "echo \"deb [trusted=yes] file:$repo ./\" > \"$work/sources.list\"\n"
                  "cat > \"$work/apt.conf\" <<CONF\n"
                  "Dir::Etc::SourceList \"$work/sources.list\";\n"
                  "Dir::Etc::SourceParts \"$work/parts\";\n"
                  "Dir::State::Lists \"$work/lists/\";\n"
                  "APT::Sandbox::User \"root\";\n"
                  "Acquire::Languages \"none\";\n"
                  "CONF\n"
                  "APT_CONFIG=\"$work/apt.conf\"\n"
                  "export APT_CONFIG\n"
                  "echo \"restate: offline: apt installs from $(grep -c '^Package:' "
                  "\"$repo/Packages\") packages, and nothing else\" >&2\n");
}

/* The apt script, without its first line, which is the shebang. */
static void apt_install(const struct rs_jval *packages, const char *snapshot, struct rs_buf *out)
{
    struct rs_buf b;
    const char   *body;

    rs_buf_init(&b);
    rs_packages_apt_script(packages, NULL, snapshot, &b);
    body = b.data ? b.data : "";
    if (rs_starts_with(body, "#!"))
    {
        body = strchr(body, '\n') ? strchr(body, '\n') + 1 : "";
    }
    rs_buf_addstr(out, body);
    rs_buf_free(&b);
}

/* "Together if apt will; one at a time if it will not", for $var. */
static void install_list(struct rs_buf *out, const char *var, const char *options)
{
    rs_buf_addf(out,
                "# shellcheck disable=SC2086\n"
                "if [ -n \"$%s\" ] && ! apt-get install -y %s $%s; then\n"
                "  for p in $%s; do\n"
                "    apt-get install -y %s \"$p\" || echo \"restate: $p did not install\" >&2\n"
                "  done\n"
                "fi\n", var, options, var, var, options);
}

/* The .deb files the kit put in apt's cache: what no repository has. */
static void kept_debs(const struct rs_jval *pkgs, struct rs_buf *out)
{
    size_t i;
    bool   any = false;

    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const char *kept = rs_jobject_str(&pkgs->items[i], "kept");

        /* Only names that need no quoting, since they go into a list. */
        if (!kept_path(kept))
        {
            continue;
        }
        if (!any)
        {
            rs_buf_addstr(out, "# The packages no repository has, from the .deb files the image "
                               "kept.\nkept=''\n");
            any = true;
        }
        rs_buf_addf(out, "[ -f %s ] && kept=\"$kept %s\"\n", kept, kept);
    }
    if (any)
    {
        install_list(out, "kept", "--allow-downgrades");
    }
}

/* From the baseline: what apt could not install at the version recorded --
 * or, with `exact`, installed at another. */
static void from_baseline(const struct rs_jval *pkgs, const char *cache, const char *native,
                          bool exact, struct rs_buf *out)
{
    size_t i;
    bool   any = false;

    for (i = 0; native && pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];
        const char           *name = rs_jobject_str(p, "name");
        const char           *version = rs_jobject_str(p, "version");
        const char           *why = rs_jobject_str(p, "unavailable");
        const char           *arch = rs_jobject_str(p, "architecture");
        char                 *deb = rs_baseline_deb_name(name, version, arch);
        /* As dpkg-query names it: an Architecture: all package as ":all". */
        char                 *q = deb_name(name) && deb_name(arch)
                                      ? rs_xasprintf("%s:%s", name, arch)
                                      : NULL;

        if (q && deb && flag(p, "manual") && deb_version(version) && !eq(why, "local") &&
            !rs_packages_installers_choice(name) && cached(cache, deb))
        {
            if (!any)
            {
                rs_buf_addf(out,
                            "# From the baseline: each package installed by hand that apt could "
                            "not\n"
                            "# install at its version%s.\n"
                            "exact='%s'\n"
                            "files=''\n"
                            "while read -r p want f; do\n"
                            "  now=$(dpkg-query -W -f='${db:Status-Status} ${Version}' \"$p\" 2> "
                            "/dev/null)\n"
                            "  case $now in\n"
                            "    \"installed $want\") ;;\n"
                            "    installed\\ *) [ -n \"$exact\" ] && files=\"$files "
                            APT_ARCHIVES "/$f\" ;;\n"
                            "    *) files=\"$files " APT_ARCHIVES "/$f\" ;;\n"
                            "  esac\n"
                            "done <<'BASELINE'\n",
                            exact ? ", or installed at another" : "", exact ? "yes" : "");
                any = true;
            }
            rs_buf_addf(out, "%s %s %s\n", q, version, deb);
        }
        free(deb);
        free(q);
    }
    if (any)
    {
        rs_buf_addstr(out, "BASELINE\n");
        install_list(out, "files", "--allow-downgrades");
    }
}

static void holds(const struct rs_jval *pkgs, const char *native, struct rs_buf *out)
{
    size_t i;
    bool   any = false;

    for (i = 0; native && pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        char *q = flag(&pkgs->items[i], "hold") ? qualified(&pkgs->items[i], native) : NULL;

        if (q)
        {
            if (!any)
            {
                rs_buf_addstr(out, "# The holds.\napt-mark hold");
                any = true;
            }
            rs_buf_addf(out, " %s", q);
        }
        free(q);
    }
    if (any)
    {
        rs_buf_addstr(out, " > /dev/null || echo 'restate: the holds were not all set' >&2\n");
    }
}

/*
 * Each package marked as the old machine had it, by hand or as a dependency;
 * then what it did not have marked a dependency, and apt left to remove what
 * nothing needs. Only on a machine of the same architecture, whose names are
 * the same names.
 */
static void marks(const struct rs_jval *pkgs, const char *native, struct rs_buf *out)
{
    size_t i;

    if (!native || !pkgs || pkgs->type != RS_JARRAY || pkgs->n == 0)
    {
        return;
    }
    rs_buf_addf(out,
                "# Installed by hand, or as a dependency, as on the old machine; and what it\n"
                "# did not have marked a dependency, so that apt removes what nothing needs.\n"
                "# Never the kernel, the boot loader, firmware, microcode or a virtual\n"
                "# machine's guest tools: those follow the hardware, which may not be the old\n"
                "# machine's.\n"
                "if [ \"$(dpkg --print-architecture)\" = %s ]; then\n"
                "  dpkg-query -W -f='${Package}:${Architecture} ${db:Status-Status}\\n' 2> "
                "/dev/null |\n"
                "    awk -v a=%s '$2 == \"installed\" { sub(/:all$/, \":\" a, $1); print $1 }' "
                "> \"$work/now\"\n"
                "  cat > \"$work/old\" <<'MARKS'\n", native, native);
    for (i = 0; i < pkgs->n; i++)
    {
        char *q = qualified(&pkgs->items[i], native);

        if (q)
        {
            rs_buf_addf(out, "%s %s\n", flag(&pkgs->items[i], "manual") ? "manual" : "auto", q);
        }
        free(q);
    }
    rs_buf_addf(out,
                "MARKS\n"
                "  for m in manual auto; do\n"
                "    awk -v m=$m 'NR == FNR { now[$1] = 1; next } $1 == m && ($2 in now) "
                "{ print $2 }' \\\n"
                "      \"$work/now\" \"$work/old\" > \"$work/$m\"\n"
                "    # shellcheck disable=SC2046\n"
                "    [ -s \"$work/$m\" ] && apt-mark $m $(cat \"$work/$m\") > /dev/null\n"
                "  done\n"
                "  apt-mark showmanual | awk -v a=%s '!/:/ { $1 = $1 \":\" a } { print }' |\n"
                "    awk 'NR == FNR { old[$2] = 1; next } !($1 in old)' \"$work/old\" - |\n"
                "    grep -Ev '^(grub|shim|linux-(image|headers|modules|generic|signed|virtual|"
                "oem)|[^:]*(firmware|microcode)|qemu-guest-agent|spice-vdagent|open-vm-tools|"
                "virtualbox-guest|hyperv-daemons|xe-guest-utilities)' > \"$work/extra\" || true\n"
                "  if [ -s \"$work/extra\" ]; then\n"
                "    # shellcheck disable=SC2046\n"
                "    echo \"restate: not on the old machine, so now marked as dependencies:\" "
                "$(cat \"$work/extra\") >&2\n"
                "    # shellcheck disable=SC2046\n"
                "    apt-mark auto $(cat \"$work/extra\") > /dev/null\n"
                "  fi\n"
                "  apt-get autoremove -y || echo 'restate: apt-get autoremove failed' >&2\n"
                "else\n"
                "  echo 'restate: this machine is not %s, as the old one was: its packages are "
                "not marked or removed' >&2\n"
                "fi\n", native, native);
}

static void snaps(const struct rs_jval *arr, bool offline, struct rs_buf *out)
{
    static const char *const implied[] = { "base", "core", "os", "snapd", "gadget", "kernel" };
    size_t                   i;
    size_t                   j;
    bool                     any = false;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const struct rs_jval *sn = &arr->items[i];
        const char           *name = rs_jobject_str(sn, "name");
        const char           *type = rs_jobject_str(sn, "type");
        const char           *channel = rs_jobject_str(sn, "channel");
        const char           *kept = rs_jobject_str(sn, "kept");
        bool                  skip = !snap_word(name);

        for (j = 0; type && j < sizeof(implied) / sizeof(implied[0]); j++)
        {
            skip = skip || eq(type, implied[j]);
        }
        if (!type && name)
        {
            skip = skip || eq(name, "snapd") || eq(name, "bare") ||
                   (rs_starts_with(name, "core") &&
                    strspn(name + 4, "0123456789") == strlen(name + 4));
        }
        if (skip || (flag(sn, "local") && (!kept || kept[0] != '/' || !rs_path_is_clean(kept))))
        {
            continue;
        }
        if (offline && !flag(sn, "local"))
        {
            /* From the store, which offline there is none of. */
            rs_buf_addf(out, "echo 'restate: offline, so the snap %s is not put back' >&2\n",
                        name);
            continue;
        }
        if (!any)
        {
            rs_buf_addstr(out, "# The snaps.\nif command -v snap > /dev/null; then\n"
                               "  snap wait system seed.loaded\n");
            any = true;
        }
        if (flag(sn, "local"))
        {
            rs_buf_addstr(out, "  snap install --dangerous ");
            rs_shell_word(out, kept);
        } else
        {
            rs_buf_addf(out, "  snap install %s", name);
            if (snap_word(channel))
            {
                rs_buf_addf(out, " --channel=%s", channel);
            }
        }
        if (flag(sn, "classic"))
        {
            rs_buf_addstr(out, " --classic");
        }
        if (flag(sn, "devmode"))
        {
            rs_buf_addstr(out, " --devmode");
        }
        rs_buf_addf(out, " || echo 'restate: the snap %s did not install' >&2\n", name);
        if (flag(sn, "disabled"))
        {
            rs_buf_addf(out, "  snap disable %s\n", name);
        }
    }
    if (any)
    {
        rs_buf_addstr(out, "else\n  echo 'restate: snapd is not installed: the snaps are not "
                           "put back' >&2\nfi\n");
    }
}

/* COMMAND WORD..., quoted, or nothing if there are none. */
static void command(struct rs_buf *out, const char *cmd, char *const *words, size_t n,
                    const char *failed)
{
    size_t i;

    if (n == 0)
    {
        return;
    }
    rs_buf_addstr(out, cmd);
    for (i = 0; i < n; i++)
    {
        rs_buf_addc(out, ' ');
        rs_shell_word(out, words[i]);
    }
    rs_buf_addf(out, " || echo 'restate: %s' >&2\n", failed);
}

static void flatpaks(const struct rs_jval *fp, struct rs_buf *out)
{
    const struct rs_jval *remotes = rs_jobject_get(fp, "remotes");
    const struct rs_jval *apps = rs_jobject_get(fp, "apps");
    size_t                i;

    for (i = 0; remotes && remotes->type == RS_JARRAY && i < remotes->n; i++)
    {
        const struct rs_jval *r = &remotes->items[i];
        char                 *w[2];

        if (!eq(rs_jobject_str(r, "scope"), "system") || !rs_jobject_str(r, "name") ||
            !rs_jobject_str(r, "url"))
        {
            continue;
        }
        w[0] = rs_xstrdup(rs_jobject_str(r, "name"));
        w[1] = rs_xstrdup(rs_jobject_str(r, "url"));
        command(out, "flatpak remote-add --if-not-exists", w, 2, "a flatpak remote was not added");
        free(w[0]);
        free(w[1]);
    }
    for (i = 0; apps && apps->type == RS_JARRAY && i < apps->n; i++)
    {
        const struct rs_jval *a = &apps->items[i];
        char                 *w[2];

        if (!eq(rs_jobject_str(a, "scope"), "system") || !rs_jobject_str(a, "remote") ||
            !rs_jobject_str(a, "id") || !rs_jobject_str(a, "branch"))
        {
            continue;
        }
        w[0] = rs_xstrdup(rs_jobject_str(a, "remote"));
        w[1] = rs_xasprintf("%s//%s", rs_jobject_str(a, "id"), rs_jobject_str(a, "branch"));
        command(out, "flatpak install -y --noninteractive", w, 2, "a flatpak app did not install");
        free(w[0]);
        free(w[1]);
    }
}

/* One language package manager's system-wide packages. */
static void language(const struct rs_jval *arr, const char *cmd, const char *sep,
                     const char *not_where, const char *failed, struct rs_buf *out)
{
    char **words = NULL;
    size_t n = 0;
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const char *name = rs_jobject_str(&arr->items[i], "name");
        const char *version = rs_jobject_str(&arr->items[i], "version");
        const char *where = rs_jobject_str(&arr->items[i], "where");

        if (!name || !where || rs_starts_with(where, "/home/") || rs_starts_with(where, "/root") ||
            (not_where && eq(where, not_where)))
        {
            continue;
        }
        words = rs_xreallocarray(words, n + 1, sizeof(*words));
        words[n++] = version ? rs_xasprintf("%s%s%s", name, sep, version) : rs_xstrdup(name);
    }
    if (n > 0)
    {
        rs_buf_addf(out, "if command -v %.*s > /dev/null; then\n  ", (int)strcspn(cmd, " "), cmd);
        command(out, cmd, words, n, failed);
        rs_buf_addstr(out, "fi\n");
    }
    for (i = 0; i < n; i++)
    {
        free(words[i]);
    }
    free(words);
}

/* How many of `arr` the script would install: the system-wide ones. */
static size_t system_wide(const struct rs_jval *arr, const char *not_where)
{
    size_t n = 0;
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const char *where = rs_jobject_str(&arr->items[i], "where");

        if (rs_jobject_str(&arr->items[i], "name") && where && !rs_starts_with(where, "/home/") &&
            !rs_starts_with(where, "/root") && !(not_where && eq(where, not_where)))
        {
            n++;
        }
    }
    return n;
}

/* Offline: what needs a store or an index on the network, said and left. */
static void offline_left_out(const struct rs_jval *packages, struct rs_buf *out)
{
    const struct rs_jval *apps = rs_jobject_get(rs_jobject_get(packages, "flatpak"), "apps");
    size_t                flat = 0;
    size_t                n[3];
    size_t                i;

    for (i = 0; apps && apps->type == RS_JARRAY && i < apps->n; i++)
    {
        flat += eq(rs_jobject_str(&apps->items[i], "scope"), "system") ? 1 : 0;
    }
    n[0] = system_wide(rs_jobject_get(packages, "pip"), NULL);
    n[1] = system_wide(rs_jobject_get(packages, "npm"), "/usr/lib/node_modules");
    n[2] = system_wide(rs_jobject_get(packages, "gem"), NULL);
    if (flat + n[0] + n[1] + n[2] > 0)
    {
        rs_buf_addf(out, "echo 'restate: offline, so not put back: %zu flatpaks, %zu Python, %zu "
                    "npm and %zu Ruby packages' >&2\n", flat, n[0], n[1], n[2]);
    }
}

static void alternatives(const struct rs_jval *alts, struct rs_buf *out)
{
    size_t i;

    for (i = 0; alts && alts->type == RS_JARRAY && i < alts->n; i++)
    {
        char *w[2];

        if (!rs_jobject_str(&alts->items[i], "name") || !rs_jobject_str(&alts->items[i], "path"))
        {
            continue;
        }
        w[0] = rs_xstrdup(rs_jobject_str(&alts->items[i], "name"));
        w[1] = rs_xstrdup(rs_jobject_str(&alts->items[i], "path"));
        command(out, "update-alternatives --set", w, 2, "an alternative was not set");
        free(w[0]);
        free(w[1]);
    }
}

void rs_reinstall_script(const struct rs_jval *packages, const struct rs_reinstall_opts *o,
                         struct rs_buf *out)
{
    const struct rs_jval *apt = rs_jobject_get(packages, "apt");
    const struct rs_jval *pkgs = rs_jobject_get(apt, "packages");
    const char           *native = native_arch(apt);

    header(out);
    if (apt)
    {
        keys(apt, out);
        if (o->offline && o->cache)
        {
            /* The baseline is the repository, so nothing to copy, and
             * nothing left to install from it after. */
            offline_repo(pkgs, o->cache, out);
        } else
        {
            (void)copy_baseline(pkgs, o->cache, out);
        }
        rs_buf_addstr(out, "apt-get update || echo 'restate: apt-get update failed; going on with "
                           "the lists apt has' >&2\n");
        apt_install(packages, o->offline ? NULL : o->snapshot, out);
        kept_debs(pkgs, out);
        if (!o->offline)
        {
            from_baseline(pkgs, o->cache, native, o->snapshot != NULL, out);
        }
        holds(pkgs, native, out);
        marks(pkgs, native, out);
    }
    snaps(rs_jobject_get(packages, "snap"), o->offline, out);
    if (o->offline)
    {
        offline_left_out(packages, out);
    } else
    {
        flatpaks(rs_jobject_get(packages, "flatpak"), out);
        language(rs_jobject_get(packages, "pip"), "pip install --break-system-packages", "==",
                 NULL, "the Python packages did not all install", out);
        language(rs_jobject_get(packages, "npm"), "npm install -g", "@", "/usr/lib/node_modules",
                 "the npm packages did not all install", out);
        language(rs_jobject_get(packages, "gem"), "gem install", ":", NULL,
                 "the gems did not all install", out);
    }
    alternatives(rs_jobject_get(packages, "alternatives"), out);
    rs_buf_addstr(out, "exit 0\n");
}
