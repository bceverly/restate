/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "rules.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "glob.h"

/* A rules file larger than this is a mistake -- the wrong file named on the
 * command line -- and reading it whole would only delay saying so. */
#define RULES_FILE_MAX ((size_t)1024 * 1024)

struct builtin {
    enum rs_class cls;
    const char   *pattern;
    const char   *why;
};

#define E RS_CLASS_EPHEMERAL
#define X RS_CLASS_EXPENDABLE
#define B RS_CLASS_BASELINE
#define S RS_CLASS_STATE

/*
 * The built-in rules.
 *
 * Ordered from general to specific, because the last match wins: "/usr" is
 * baseline, and then "/usr/local" carves itself back out as state. The rules
 * that apply at any depth ("*.pid") come last so nothing can override them by
 * accident.
 *
 * These are a starting point and say so. `restate rules` prints them in the
 * rules-file format, so a site that disagrees can take the output, edit it,
 * and run with `-N -R FILE`.
 */

/* Shared by every Unix-like system. */
static const struct builtin common_rules[] = {
    { E, "/dev",            "device nodes, recreated by the kernel at boot" },
    { E, "/tmp",            "cleared at boot on most systems; never state" },
    { E, "/var/tmp",        "temporary files by definition" },
    { E, "/var/run",        "PID files and sockets from the running system" },
    { E, "/lost+found",     "fsck's salvage area, specific to one filesystem" },
    { S, "/etc",            "system configuration" },
    { S, "/root",           "the administrator's home directory" },
    { S, "/home",           "user data" },
    { S, "/var/db",         "local databases" },
    { S, "/var/spool",      "queued mail, print and cron jobs" },
    { S, "/var/mail",       "local mailboxes" },
    { X, "/var/log",        "useful, but not needed to rebuild the machine" },
    { X, "/var/cache",      "regenerated on demand" },
};

static const struct builtin linux_rules[] = {
    { E, "/proc",                  "kernel pseudo-filesystem" },
    { E, "/sys",                   "kernel pseudo-filesystem" },
    { E, "/run",                   "runtime state, a tmpfs on every modern distribution" },
    { E, "/var/lock",              "lock files from the running system" },
    { E, "/mnt",                   "mount points for other filesystems" },
    { E, "/media",                 "removable media" },
    { E, "/swapfile*",             "swap files: /swapfile, /swapfile2 ... (they can hold secrets)" },
    { E, "/swap.img",              "swap, as the Ubuntu installer names it" },
    { B, "/usr",                   "installed by the distribution and its packages" },
    { B, "/bin",                   "installed by the distribution (often a link into /usr)" },
    { B, "/sbin",                  "installed by the distribution (often a link into /usr)" },
    { B, "/lib",                   "installed by the distribution (often a link into /usr)" },
    { B, "/lib32",                 "installed by the distribution" },
    { B, "/lib64",                 "installed by the distribution" },
    { B, "/libx32",                "installed by the distribution" },
    { B, "/boot",                  "kernels and initramfs images, rebuilt by the package manager" },
    { S, "/usr/local",             "software the administrator installed by hand" },
    { S, "/opt",                   "add-on software and its data" },
    { S, "/srv",                   "data served by this machine" },
    { S, "/var/lib",               "application state: databases, containers, services" },
    { S, "/var/backups",           "the distribution's own copies of critical files" },
    { B, "/var/lib/dpkg",          "the package database, rebuilt by reinstalling packages" },
    { B, "/var/lib/rpm",           "the package database, rebuilt by reinstalling packages" },
    { B, "/var/lib/pacman",        "the package database, rebuilt by reinstalling packages" },
    { X, "/var/lib/apt/lists",     "package indexes, refetched by apt update" },
    { X, "/var/lib/snapd/snaps",   "snap images, refetched from the store" },
    { X, "/var/lib/snapd/cache",   "snapd's download cache" },
    { X, "/snap",                  "mounted snap images, recreated by snapd" },
    { X, "/var/lib/flatpak",       "flatpak apps and runtimes, installed again" },
    { S, "/var/lib/flatpak/repo/config", "flatpak's remotes" },
    { S, "/var/lib/flatpak/overrides", "flatpak permission overrides" },
    { X, "/var/crash",             "crash dumps" },
    { E, "/var/lib/systemd/coredump", "core dumps" },
    { E, "/var/snap/lxd/common/ns", "LXD's namespace handles, bind-mounted while it runs" },
    /* Container images are pulled again; the volumes containers write to
     * are data, and stay state. */
    { X, "/var/lib/containerd",    "container images and snapshots, pulled again" },
    { X, "/var/lib/docker",        "Docker's images and layers, pulled again" },
    { S, "/var/lib/docker/volumes", "Docker volumes: the data containers keep" },
    { X, "/var/lib/containers/storage", "Podman's images and layers, pulled again" },
    { S, "/var/lib/containers/storage/volumes", "Podman volumes: the data containers keep" },
    { X, "/var/lib/libvirt/boot",  "installer images libvirt boots from, downloaded again" },
    { X, "/var/lib/libvirt/qemu/save", "suspended VMs' memory; without it a VM boots afresh" },
    { X, "/var/lib/snapd/seed",    "the snaps the installer seeded, downloaded again" },
    { X, "/var/snap/lxd/common/lxd/images", "LXD's image cache; the containers themselves stay" },
    { X, "/usr/share/ollama/.ollama/models", "Ollama's model weights, pulled again" },
};

static const struct builtin freebsd_rules[] = {
    { E, "/proc",                  "process pseudo-filesystem, when mounted" },
    { E, "/compat/linux/proc",     "the Linux emulation layer's /proc" },
    { E, "/compat/linux/sys",      "the Linux emulation layer's /sys" },
    { E, "/mnt",                   "mount points for other filesystems" },
    { E, "/media",                 "removable media" },
    { B, "/bin",                   "the base system" },
    { B, "/sbin",                  "the base system" },
    { B, "/lib",                   "the base system" },
    { B, "/libexec",               "the base system" },
    { B, "/rescue",                "the base system's static recovery tools" },
    { B, "/usr",                   "the base system" },
    { B, "/boot",                  "the kernel and loader, from the base system" },
    { B, "/usr/local",             "installed by pkg, reconstructible from its database" },
    { B, "/var/db/pkg",            "the package database" },
    { S, "/usr/local/etc",         "configuration for installed packages" },
    { S, "/usr/local/www",         "web content, conventionally local" },
    { S, "/usr/home",              "user data, where older installs put /home" },
    { S, "/boot/loader.conf",      "boot-time tunables" },
    { S, "/boot/loader.conf.d",    "boot-time tunables" },
    { X, "/usr/obj",               "build output from a source build" },
    { X, "/var/cache/pkg",         "downloaded packages" },
    { X, "/var/db/freebsd-update", "freebsd-update's working files" },
    { X, "/var/db/portsnap",       "the ports tree snapshot" },
};

static const struct builtin openbsd_rules[] = {
    { E, "/mnt",                   "mount points for other filesystems" },
    { B, "/bin",                   "the base sets" },
    { B, "/sbin",                  "the base sets" },
    { B, "/usr",                   "the base sets" },
    { B, "/bsd",                   "the kernel" },
    { B, "/bsd.rd",                "the install kernel" },
    { B, "/bsd.sp",                "the single-processor kernel" },
    { B, "/bsd.mp",                "the multiprocessor kernel" },
    { B, "/bsd.booted",            "the kernel relinked at boot" },
    { B, "/usr/local",             "installed by pkg_add, reconstructible from its database" },
    { B, "/var/db/pkg",            "the package database" },
    { S, "/usr/local/etc",         "configuration some packages keep here" },
    { S, "/var/www",               "httpd's chroot and its content" },
    { S, "/var/unbound",           "unbound's chroot and configuration" },
    { S, "/var/nsd",               "nsd's chroot and zones" },
    { X, "/usr/obj",               "build output from a source build" },
    { X, "/usr/xobj",              "build output from a xenocara build" },
    { E, "/var/sysmerge",          "sysmerge's working area" },
};

static const struct builtin netbsd_rules[] = {
    { E, "/proc",                  "process pseudo-filesystem, when mounted" },
    { E, "/kern",                  "kernel pseudo-filesystem" },
    { E, "/mnt",                   "mount points for other filesystems" },
    { B, "/bin",                   "the base sets" },
    { B, "/sbin",                  "the base sets" },
    { B, "/lib",                   "the base sets" },
    { B, "/libexec",               "the base sets" },
    { B, "/rescue",                "the base sets' static recovery tools" },
    { B, "/usr",                   "the base sets" },
    { B, "/netbsd",                "the kernel" },
    { B, "/stand",                 "kernel modules" },
    { B, "/usr/pkg",               "installed by pkgsrc, reconstructible from its database" },
    { B, "/usr/pkg/pkgdb",         "the pkgsrc package database" },
    { B, "/var/db/pkg",            "the package database on older installs" },
    { S, "/usr/pkg/etc",           "configuration for installed packages" },
    { S, "/usr/local",             "software the administrator installed by hand" },
    { X, "/usr/obj",               "build output from a source build" },
    { X, "/var/db/pkgin",          "pkgin's cache" },
};

static const struct builtin darwin_rules[] = {
    { E, "/Volumes",               "mount points for other volumes" },
    { E, "/System/Volumes",        "the data volume, reachable again through firmlinks" },
    { E, "/private/tmp",           "temporary files" },
    { E, "/private/var/tmp",       "temporary files" },
    { E, "/private/var/run",       "runtime state" },
    { E, "/private/var/folders",   "per-user temporary and cache directories" },
    { E, "/private/var/vm",        "swap and the sleep image" },
    { E, "/cores",                 "core dumps" },
    { E, "/.Spotlight-V100",       "the Spotlight index" },
    { E, "/.fseventsd",            "the filesystem event log" },
    { E, "/.DocumentRevisions-V100", "document versions database" },
    { E, "/.vol",                  "volume-by-id pseudo-filesystem" },
    { B, "/System",                "the sealed system volume" },
    { B, "/bin",                   "the sealed system volume" },
    { B, "/sbin",                  "the sealed system volume" },
    { B, "/usr",                   "the sealed system volume" },
    { B, "/Library/Apple",         "Apple-supplied system additions" },
    { S, "/usr/local",             "software the administrator installed (Homebrew on Intel)" },
    { S, "/opt",                   "add-on software (Homebrew on Apple silicon)" },
    { S, "/Users",                 "user data" },
    { S, "/Library",               "system-wide preferences and support files" },
    { S, "/Applications",          "installed applications" },
    { S, "/private/etc",           "system configuration" },
    { S, "/private/var/db",        "local databases" },
    { S, "/private/var/root",      "the administrator's home directory" },
    { X, "/Library/Caches",        "regenerated on demand" },
    { X, "/private/var/log",       "useful, but not needed to rebuild the machine" },
    { X, "/opt/homebrew/Library/Homebrew", "Homebrew's own checkout, refetched on install" },
    { X, "/Library/Logs",          "logs" },
    { X, "/Library/Updates",       "downloaded system updates" },
    { X, "/private/var/db/diagnostics", "the unified log's store" },
};

/*
 * In every user's home, on every system: where homes live (/home on Linux
 * and the BSDs, /usr/home on older FreeBSD installs, /Users on macOS) and
 * root's own. What is here was fetched from somewhere and can be fetched
 * again; a rules file line such as "state /home/alice/Downloads" keeps it.
 */
static const struct builtin home_rules[] = {
    { X, "/home/*/Downloads",          "downloads: fetched once, and fetchable again" },
    { X, "/usr/home/*/Downloads",      "downloads: fetched once, and fetchable again" },
    { X, "/Users/*/Downloads",         "downloads: fetched once, and fetchable again" },
    { X, "/root/Downloads",            "downloads: fetched once, and fetchable again" },
    { X, "/private/var/root/Downloads", "downloads: fetched once, and fetchable again" },
    { X, "/Users/*/.Trash",            "the Finder's trash: deleted already" },
    { X, "/Users/*/Library/Caches",    "per-user caches, regenerated on demand" },
    { X, "/Users/*/Library/Containers/*/Data/Library/Caches", "sandboxed apps' caches" },
    { X, "/Users/*/Library/Developer/Xcode/DerivedData", "Xcode's build output and indexes" },
    { X, "/Users/*/Library/Developer/Xcode/*DeviceSupport", "device symbols, copied again from a device" },
    { X, "/Users/*/Library/Developer/CoreSimulator/Caches", "the simulator's caches" },
    { X, "/Users/*/Library/Logs",      "per-user logs" },
    { E, "/home/*/.xsession-errors",   "the last X session's errors" },
};

/* At any depth, and therefore last. */
static const struct builtin anywhere_rules[] = {
    { E, "*.pid",                  "a process ID, meaningless after a reboot" },
    { E, "*.sock",                 "a socket's name, recreated by its server" },
    { E, ".nfs*",                 "NFS silly-rename placeholders" },
    { X, ".cache",                 "per-user caches (XDG)" },
    { X, "**/.local/share/Trash",  "the desktop's trash: deleted already" },
    { X, "**/.thumbnails",         "thumbnails, made again when the files are shown" },
    /* JavaScript: dependencies come back from the lock file. */
    { X, "**/.npm",                "npm's cache, logs and npx packages, refetched" },
    { X, "**/node_modules",        "JavaScript dependencies, reinstalled from the lock file" },
    { X, "**/.yarn/cache",         "Yarn's package cache" },
    { X, "**/.pnpm-store",         "pnpm's package store" },
    { X, "**/.local/share/pnpm/store", "pnpm's package store" },
    { X, "**/.bun/install/cache",  "Bun's package cache" },
    { X, "**/.next",               "Next.js build output" },
    { X, "**/.nuxt",               "Nuxt build output" },
    { X, "**/.parcel-cache",       "Parcel's build cache" },
    { X, "**/.turbo",              "Turborepo's build cache" },
    /* Python: environments come back from their requirements. */
    { X, "**/__pycache__",         "compiled Python, rebuilt on import" },
    { X, "**/.venv",               "a Python virtual environment, rebuilt from its requirements" },
    { X, "**/venv",                "a Python virtual environment, rebuilt from its requirements" },
    { X, "**/.venvs",              "Python virtual environments, rebuilt from their requirements" },
    { X, "**/.local/share/virtualenvs", "pipenv's environments" },
    { X, "**/.tox",                "tox's environments, rebuilt on the next run" },
    { X, "**/.nox",                "nox's environments, rebuilt on the next run" },
    { X, "**/.pytest_cache",       "pytest's cache" },
    { X, "**/.mypy_cache",         "mypy's cache" },
    { X, "**/.ruff_cache",         "ruff's cache" },
    { X, "**/.hypothesis",         "Hypothesis's example database" },
    { X, "**/.conda/pkgs",         "conda's package cache" },
    { X, "**/miniconda3/pkgs",     "conda's package cache" },
    { X, "**/anaconda3/pkgs",      "conda's package cache" },
    /* Other languages' downloaded dependencies and build caches. */
    { X, "**/.gradle",             "Gradle's caches, daemons and wrapper downloads" },
    { X, "**/.m2/repository",      "Maven's download cache" },
    { X, "**/.ivy2/cache",         "Ivy's download cache" },
    { X, "**/.cargo/registry",     "Cargo's download cache" },
    { X, "**/.cargo/git",          "Cargo's git dependency checkouts" },
    { X, "**/.rustup/toolchains",  "Rust toolchains, reinstalled by rustup" },
    { X, "**/go/pkg/mod",          "Go's module cache" },
    { X, "**/.nuget/packages",     "NuGet's package cache" },
    { X, "**/.pub-cache",          "Dart and Flutter's package cache" },
    { X, "**/.dart_tool",          "Dart's build output" },
    { X, "**/.stack",              "Haskell Stack's snapshots and compilers" },
    { X, "**/.cabal/packages",     "Cabal's package cache" },
    { X, "**/.zig-cache",          "Zig's build cache" },
    { X, "**/zig-cache",           "Zig's build cache" },
    { X, "**/.ccache",             "ccache's compiler cache" },
    { X, "**/.terraform",          "Terraform's providers and modules, fetched by init" },
    { X, "**/.terraform.d/plugin-cache", "Terraform's provider cache" },
    { X, "**/.vagrant.d/boxes",    "Vagrant's downloaded boxes" },
    { X, "**/.minikube/cache",     "minikube's downloaded images" },
    { X, "**/.direnv",             "direnv's per-project environments" },
    { X, "**/.gem",                "installed Ruby gems, reinstalled from the Gemfile" },
    { X, "**/vendor/bundle",       "Bundler's installed gems" },
    { X, "**/CMakeFiles",          "CMake's build files" },
    { X, "*.o",                    "an object file, rebuilt by the compiler" },
    { X, "*.pyc",                  "compiled Python, rebuilt on import" },
    /* Toolchains a version manager installs, and installs again. */
    { X, "**/.nvm/versions",       "Node versions installed by nvm" },
    { X, "**/.pyenv/versions",     "Python versions installed by pyenv" },
    { X, "**/.rbenv/versions",     "Ruby versions installed by rbenv" },
    { X, "**/.asdf/installs",      "tools installed by asdf" },
    { X, "**/.local/share/mise/installs", "tools installed by mise" },
    { X, "**/.volta/tools",        "tools installed by Volta" },
    { X, "**/.sdkman/candidates",  "SDKs installed by SDKMAN!" },
    { X, "**/.ghcup/ghc",          "GHC versions installed by ghcup" },
    { X, "**/.elan/toolchains",    "Lean toolchains installed by elan" },
    { X, "**/.julia/packages",     "Julia packages, reinstalled from the manifest" },
    { X, "**/.julia/artifacts",    "Julia's downloaded artifacts" },
    /* Editors, SDKs and apps that download what they need. */
    { X, "**/.vscode/extensions",  "VS Code extensions, installed again" },
    { X, "**/.vscode-server",      "VS Code's remote server and its extensions" },
    { X, "**/.vscode-oss/extensions", "VSCodium extensions, installed again" },
    { X, "**/.config/*/Cache",     "an Electron app's cache (Code, Slack, Discord ...)" },
    { X, "**/.config/*/CachedData", "an Electron app's cached data" },
    /* Chromium's engine -- Chrome, Chromium, Brave, Edge, Vivaldi and every
     * Electron app -- keeps these inside the profile, at whatever depth.
     * "?" stands for the space in the name, which a pattern cannot hold. */
    { X, "**/.config/**/GPUCache", "a Chromium-based app's shader cache" },
    { X, "**/.config/**/GrShaderCache", "a Chromium-based app's shader cache" },
    { X, "**/.config/**/ShaderCache", "a Chromium-based app's shader cache" },
    { X, "**/.config/**/DawnCache", "a Chromium-based app's WebGPU cache" },
    { X, "**/.config/**/DawnWebGPUCache", "a Chromium-based app's WebGPU cache" },
    { X, "**/.config/**/DawnGraphiteCache", "a Chromium-based app's WebGPU cache" },
    { X, "**/.config/**/Code?Cache", "a Chromium-based app's compiled-script cache" },
    { X, "**/.config/**/Service?Worker/CacheStorage", "web apps' offline caches, refetched" },
    { X, "**/.config/**/Service?Worker/ScriptCache", "web apps' service-worker scripts" },
    { X, "**/Android/Sdk",         "the Android SDK, downloaded again by its manager" },
    { X, "**/.platformio/packages", "PlatformIO's toolchains and frameworks" },
    { X, "**/.arduino15/packages", "Arduino cores and tools" },
    { X, "**/.local/share/JetBrains/Toolbox/apps", "IDEs installed by JetBrains Toolbox" },
    { X, "**/.ollama/models",      "Ollama's model weights, pulled again" },
    { X, "**/.sonar/cache",        "SonarScanner's download cache" },
    { X, "**/.local/share/libvirt/boot", "installer images libvirt boots from, downloaded again" },
    { X, "**/.config/libvirt/qemu/save", "suspended VMs' memory; without it a VM boots afresh" },
    { X, "**/.Trash-*",            "the trash on another drive" },
    /* Installer media and downloads that never finished: fetched again. */
    { X, "*.iso",                  "an installer or disc image, downloaded again" },
    { X, "*-cloudimg-*.img",       "a cloud image, downloaded again" },
    { X, "*.part",                 "a download that never finished" },
    { X, "*.crdownload",           "a Chrome download that never finished" },
    { X, "*.partial",              "a download that never finished" },
    { E, "**/lost+found",          "fsck's salvage area, specific to one filesystem" },
    { X, "**/.local/share/Steam/steamapps", "Steam's games, downloaded again" },
    { X, "**/.local/share/flatpak", "per-user flatpak apps and runtimes, installed again" },
    { S, "**/.local/share/flatpak/repo/config", "per-user flatpak remotes" },
    { S, "**/.local/share/flatpak/overrides", "per-user flatpak permission overrides" },
    { X, "**/.local/share/containers/storage", "rootless Podman's images, pulled again" },
    { S, "**/.local/share/containers/storage/volumes", "rootless Podman's volumes: data" },
};

#undef E
#undef X
#undef B
#undef S

struct os_table {
    const char           *name;
    const struct builtin *rules;
    size_t                count;
};

#define TABLE(n, t) { n, t, sizeof(t) / sizeof((t)[0]) }

static const struct os_table os_tables[] = {
    TABLE("linux",   linux_rules),
    TABLE("freebsd", freebsd_rules),
    TABLE("openbsd", openbsd_rules),
    TABLE("netbsd",  netbsd_rules),
    TABLE("darwin",  darwin_rules),
};

#undef TABLE

static const char *const class_names[] = {
    "ephemeral", "expendable", "baseline", "state"
};

const char *rs_class_name(enum rs_class cls)
{
    if ((size_t)cls < sizeof(class_names) / sizeof(class_names[0]))
    {
        return class_names[cls];
    }
    return "?";
}

bool rs_class_parse(const char *name, size_t len, enum rs_class *out)
{
    size_t i;

    for (i = 0; i < sizeof(class_names) / sizeof(class_names[0]); i++)
    {
        if (strlen(class_names[i]) == len && strncmp(class_names[i], name, len) == 0)
        {
            *out = (enum rs_class)i;
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------- */

void rs_rules_init(struct rs_rules *rs)
{
    rs->rules = NULL;
    rs->count = 0;
    rs->cap = 0;
}

void rs_rules_free(struct rs_rules *rs)
{
    size_t i;

    for (i = 0; i < rs->count; i++)
    {
        free(rs->rules[i].pattern);
        free(rs->rules[i].source);
        free(rs->rules[i].why);
    }
    free(rs->rules);
    rs_rules_init(rs);
}

void rs_rules_add(struct rs_rules *rs, enum rs_class cls, const char *pattern,
                  const char *source, const char *why)
{
    struct rs_rule *r;
    size_t          plen = strlen(pattern);

    if (rs->count == rs->cap)
    {
        rs->cap = rs->cap ? rs->cap * 2 : 64;
        rs->rules = rs_xreallocarray(rs->rules, rs->cap, sizeof(*rs->rules));
    }
    r = &rs->rules[rs->count++];
    r->cls = cls;
    /* "/var/log/" means the same as "/var/log"; the trailing slash would
     * otherwise stop the pattern from matching the directory at all. */
    while (plen > 1 && pattern[plen - 1] == '/')
    {
        plen--;
    }
    r->pattern = rs_xstrndup(pattern, plen);
    r->source = rs_xstrdup(source);
    r->why = why ? rs_xstrdup(why) : NULL;
}

const char *rs_rules_host_os(void)
{
    struct utsname u;
    size_t         i;
    static char    lower[sizeof(u.sysname)];

    if (uname(&u) < 0)
    {
        return NULL;
    }
    for (i = 0; i + 1 < sizeof(lower) && u.sysname[i] != '\0'; i++)
    {
        static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
        char              c = u.sysname[i];

        if (c >= 'A' && c <= 'Z')
        {
            lower[i] = alphabet[c - 'A'];
        } else
        {
            lower[i] = c;
        }
    }
    lower[i] = '\0';
    return rs_rules_known_os(lower) ? lower : NULL;
}

bool rs_rules_known_os(const char *os)
{
    size_t i;

    for (i = 0; i < sizeof(os_tables) / sizeof(os_tables[0]); i++)
    {
        if (strcmp(os_tables[i].name, os) == 0)
        {
            return true;
        }
    }
    return false;
}

static void add_table(struct rs_rules *rs, const struct builtin *t, size_t n,
                      const char *source)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        rs_rules_add(rs, t[i].cls, t[i].pattern, source, t[i].why);
    }
}

bool rs_rules_add_builtin(struct rs_rules *rs, const char *os)
{
    size_t i;

    for (i = 0; i < sizeof(os_tables) / sizeof(os_tables[0]); i++)
    {
        if (strcmp(os_tables[i].name, os) == 0)
        {
            char *source = rs_xasprintf("built-in (%s)", os);

            add_table(rs, common_rules, sizeof(common_rules) / sizeof(common_rules[0]),
                      source);
            add_table(rs, os_tables[i].rules, os_tables[i].count, source);
            add_table(rs, home_rules, sizeof(home_rules) / sizeof(home_rules[0]), source);
            add_table(rs, anywhere_rules,
                      sizeof(anywhere_rules) / sizeof(anywhere_rules[0]), source);
            free(source);
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------- */

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

bool rs_rules_parse(struct rs_rules *rs, const char *text, size_t len,
                    const char *name, struct rs_buf *err)
{
    size_t pos = 0;
    size_t lineno = 0;

    while (pos < len)
    {
        size_t        start = pos;
        size_t        end;
        size_t        word_end;
        size_t        pat_start;
        enum rs_class cls;

        lineno++;
        while (pos < len && text[pos] != '\n')
        {
            if (text[pos] == '\0')
            {
                rs_buf_addf(err, "%s:%zu: a NUL byte; this is not a rules file",
                            name, lineno);
                return false;
            }
            pos++;
        }
        end = pos;
        if (pos < len)
        {
            pos++;   /* the newline */
        }

        while (start < end && is_space(text[start]))
        {
            start++;
        }
        while (end > start && is_space(text[end - 1]))
        {
            end--;
        }
        if (start == end || text[start] == '#')
        {
            continue;
        }

        word_end = start;
        while (word_end < end && !is_space(text[word_end]))
        {
            word_end++;
        }
        if (!rs_class_parse(text + start, word_end - start, &cls))
        {
            rs_buf_addf(err, "%s:%zu: unknown class \"%.*s\" (expected ephemeral, "
                        "expendable, baseline or state)", name, lineno,
                        (int)(word_end - start > 40 ? 40 : word_end - start),
                        text + start);
            return false;
        }
        pat_start = word_end;
        while (pat_start < end && is_space(text[pat_start]))
        {
            pat_start++;
        }
        /* A '#' after whitespace starts a comment, so `restate rules` output
         * -- which explains each rule that way -- reads straight back in. A
         * '#' inside a pattern is still literal. */
        {
            size_t k;

            for (k = pat_start; k < end; k++)
            {
                if (text[k] == '#' && is_space(text[k - 1]))
                {
                    end = k;
                    break;
                }
            }
            while (end > pat_start && is_space(text[end - 1]))
            {
                end--;
            }
        }
        if (pat_start == end)
        {
            rs_buf_addf(err, "%s:%zu: \"%s\" needs a pattern after it", name,
                        lineno, rs_class_name(cls));
            return false;
        }
        {
            char *pattern = rs_xstrndup(text + pat_start, end - pat_start);
            char *source = rs_xasprintf("%s:%zu", name, lineno);

            rs_rules_add(rs, cls, pattern, source, NULL);
            free(pattern);
            free(source);
        }
    }
    return true;
}

bool rs_rules_load_file(struct rs_rules *rs, const char *path, struct rs_buf *err)
{
    struct rs_buf text;
    struct stat   st;
    char          chunk[8192];
    int           fd;
    bool          ok;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
    {
        rs_buf_addf(err, "%s: not a regular file", path);
        (void)close(fd);
        return false;
    }
    rs_buf_init(&text);
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            rs_buf_free(&text);
            (void)close(fd);
            return false;
        }
        if (n == 0)
        {
            break;
        }
        rs_buf_add(&text, chunk, (size_t)n);
        if (text.len > RULES_FILE_MAX)
        {
            rs_buf_addf(err, "%s: larger than %zu bytes; is this really a rules file?",
                        path, RULES_FILE_MAX);
            rs_buf_free(&text);
            (void)close(fd);
            return false;
        }
    }
    (void)close(fd);
    if (!text.data)
    {
        rs_buf_add(&text, "", 0);
    }
    ok = rs_rules_parse(rs, text.data, text.len, path, err);
    rs_buf_free(&text);
    return ok;
}

enum rs_class rs_rules_classify(const struct rs_rules *rs, const char *path,
                                long *which)
{
    size_t i = rs->count;

    /* Backwards, because the last match wins and can stop the search. */
    while (i > 0)
    {
        i--;
        if (rs_glob_covers(rs->rules[i].pattern, path))
        {
            if (which)
            {
                *which = (long)i;
            }
            return rs->rules[i].cls;
        }
    }
    if (which)
    {
        *which = -1;
    }
    return RS_CLASS_STATE;
}

/* The part of a source that names the file: "rules.conf:12" -> "rules.conf". */
static size_t source_group_len(const char *source)
{
    const char *colon = strrchr(source, ':');
    const char *p;

    if (!colon || colon[1] == '\0')
    {
        return strlen(source);
    }
    for (p = colon + 1; *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
        {
            return strlen(source);
        }
    }
    return (size_t)(colon - source);
}

void rs_rules_write(const struct rs_rules *rs, FILE *out)
{
    size_t      i;
    const char *group = NULL;
    size_t      group_len = 0;

    (void)fprintf(out, "# restate rules: CLASS PATTERN, the last match wins.\n"
                       "# A path that no rule covers is state.\n");
    for (i = 0; i < rs->count; i++)
    {
        const struct rs_rule *r = &rs->rules[i];
        size_t                n = source_group_len(r->source);

        if (!group || n != group_len || strncmp(group, r->source, n) != 0)
        {
            (void)fprintf(out, "\n# from %.*s\n", (int)n, r->source);
            group = r->source;
            group_len = n;
        }
        if (r->why)
        {
            (void)fprintf(out, "%-10s  %-28s  # %s\n", rs_class_name(r->cls),
                          r->pattern, r->why);
        } else
        {
            (void)fprintf(out, "%-10s  %s\n", rs_class_name(r->cls), r->pattern);
        }
    }
}
