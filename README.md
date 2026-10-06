<div align="center">

# restate

**Record what makes a machine different from a fresh install of its operating
system — so after a reinstall, the difference can be put back.**

[![CI](https://github.com/bceverly/restate/actions/workflows/ci.yml/badge.svg)](https://github.com/bceverly/restate/actions/workflows/ci.yml)
[![Security](https://github.com/bceverly/restate/actions/workflows/security.yml/badge.svg)](https://github.com/bceverly/restate/actions/workflows/security.yml)
[![CodeQL](https://github.com/bceverly/restate/actions/workflows/codeql.yml/badge.svg)](https://github.com/bceverly/restate/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bceverly/restate/badge)](https://scorecard.dev/viewer/?uri=github.com/bceverly/restate)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15216/badge)](https://www.bestpractices.dev/projects/15216)
[![Coverage](docs/badges/coverage.svg)](#testing)

[![License: BSD 2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-1B4B8F.svg)](LICENSE)
[![Language: C11](https://img.shields.io/badge/language-C11-0A2240.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Links: libc only](https://img.shields.io/badge/links-libc%20only-1e7a46.svg)](#security)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20FreeBSD%20%C2%B7%20OpenBSD%20%C2%B7%20NetBSD%20%C2%B7%20macOS-0A2240.svg)](#installing)
[![Ubuntu 26.04](https://img.shields.io/badge/ubuntu-26.04-E95420.svg)](#installing-on-ubuntu-2604)

[![cppcheck](https://img.shields.io/badge/cppcheck-clean-1e7a46.svg)](#security)
[![clang-tidy](https://img.shields.io/badge/clang--tidy-clean-1e7a46.svg)](#security)
[![gcc -fanalyzer](https://img.shields.io/badge/gcc%20--fanalyzer-clean-1e7a46.svg)](#security)
[![flawfinder](https://img.shields.io/badge/flawfinder-clean-1e7a46.svg)](#security)
[![semgrep](https://img.shields.io/badge/semgrep-clean-1e7a46.svg)](#security)
[![gitleaks](https://img.shields.io/badge/gitleaks-clean-1e7a46.svg)](#security)

[![ASan · UBSan · LSan](https://img.shields.io/badge/asan%20%C2%B7%20ubsan%20%C2%B7%20lsan-clean-1e7a46.svg)](#testing)
[![valgrind](https://img.shields.io/badge/valgrind-clean-1e7a46.svg)](#testing)
[![Fuzzed](https://img.shields.io/badge/fuzzed-libFuzzer%20%2B%20in--process-1e7a46.svg)](#testing)
[![MITRE Lucky 13](https://img.shields.io/badge/MITRE%20Lucky%2013-none%20found-1e7a46.svg)](#security)
[![Hardened](https://img.shields.io/badge/hardened-PIE%20%C2%B7%20RELRO%20%C2%B7%20CET%20%C2%B7%20fortify-1e7a46.svg)](#building)
[![SLSA provenance](https://img.shields.io/badge/releases-SLSA%20provenance-1e7a46.svg)](#releasing)

</div>

---

A full backup copies every file on the disk. Most of them came from the
operating system and its packages, and can be fetched again; what cannot be
fetched again is the configuration, the data, and the local changes. That
difference is usually a small fraction of the disk — and it is what `restate`
records.

```console
# restate capture -o /var/backups/web01.tgz
restate: recorded 41873 paths (40102 state, 1771 baseline, 0 expendable); kept the content of 40102
restate: skipped 2114 ephemeral, 9 expendable, 14 sockets, 0 mount points
restate: hashed 812447112 bytes

# restate verify /var/backups/web01.tgz
M	/etc/ssh/sshd_config	content
A	/etc/nginx/sites-enabled/new-site.conf
restate: 1 added, 0 deleted, 1 modified
```

## Contents

- [What it does](#what-it-does)
- [Use cases](#use-cases)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Images and indexes](#images-and-indexes)
- [Classes and rules](#classes-and-rules)
- [Installing](#installing)
- [Building](#building)
- [Testing](#testing)
- [Security](#security)
- [Make targets](#make-targets)
- [Releasing](#releasing)
- [GitHub configuration](#github-configuration)
- [Project layout](#project-layout)
- [Roadmap](ROADMAP.md)

## What it does

- **Classifies every path.** Each path is *ephemeral* (`/proc`, `/run`, `/tmp`,
  PID files — never kept), *expendable* (caches, logs, downloaded packages,
  snap images — kept only with `--all`), *baseline* (supplied by the OS and its
  packages: `/usr`, the package database) or *state* (`/etc`, `/home`,
  `/var/lib`, `/usr/local` — always kept). Built-in rules for Linux, FreeBSD,
  OpenBSD, NetBSD and macOS; your own rules file overrides any of them.
- **Captures an image**: a `.tgz` holding `index.json` — every recorded path
  with its owner, mode, size, link count, inode, access, modification,
  change and birth times to the nanosecond, and SHA-256 — followed by the
  content of everything kept. It is also an ordinary tarball: `tar -xzpf`
  restores it by hand.
- **Compares.** `diff` two images or indexes, or `verify` one against the
  machine as it is now, and see what was added, deleted and modified — and
  whether a modification was the content, the mode, the owner or a link target.
- **Walks safely, as root, through directories users control.** Nothing is
  opened by a path longer than one component, no symlink is followed, and
  every file is checked against what was stat'ed a moment earlier.

## Use cases

**What changed on this server?** Capture on a schedule, and see exactly what
has been added, deleted or modified since — content, mode, owner or link
target — without the noise of timestamps:

```bash
restate capture -o /var/backups/web01-$(date +%F).tgz
restate verify /var/backups/web01-2026-09-28.tgz          # against the server as it is now
restate diff web01-2026-09-28.tgz web01-2026-10-05.tgz    # between two captures
```

**Why does this one behave differently?** Diff two servers that are supposed
to be identical:

```bash
restate scan -o app1.json      # on app1
restate scan -o app2.json      # on app2
restate diff app1.json app2.json
```

**What did that installer actually do?** Capture before and after installing
a vendor's package, running a configuration-management job or applying an
update, and diff the two.

**What is actually on this box?** Before decommissioning, handing over or
auditing a machine, `restate machine` documents the hardware, firmware, disk
layout, encryption, LVM, RAID and mounts, and an index lists every file with
its owner, mode, times and SHA-256.

**A safety net before an upgrade.** Capture before a release upgrade, keep the
image, and diff afterwards to see what the upgrade changed.

### Coming

These need the pieces still on the [roadmap](ROADMAP.md) — reinstalling the
package inventory, package-aware capture, and `restore`:

- **Bare-metal disaster recovery.** The disk dies: rebuild the machine from
  its build sheet or an unattended autoinstall file, and restore the image.
- **A hardware refresh.** Move a machine onto new hardware, disks of a
  different size included.
- **Bare metal to a virtual machine, and back.** Move a physical server into
  a VM — or a VM onto hardware — with what changes accounted for: the storage
  and network drivers in the initramfs, UEFI or BIOS, device and interface
  names, a disk sized to the data rather than the old drive, hardware tools
  swapped for guest agents (or the reverse), and an encrypted volume that
  was unlocked by the old machine's TPM. For a VM, a ready-to-run definition
  of the virtual machine itself.
- **Stamping out copies.** Build one machine that does the thing — a load
  generator, a lab workstation — and rebuild it as many machines, each with
  its own host name, address, machine-id and SSH host keys, so no two come up
  as the same machine on the network.
- **Turning a hand-built server into code.** The package inventory and the
  autoinstall file are a starting point for automating a machine that was
  only ever configured by hand.
- **Air-gapped rebuilds**, from a downloaded installer and kept packages.
- **A new laptop, set up like the old one**, in one unattended install.

## Quick start

```bash
git clone https://github.com/bceverly/restate.git
cd restate
make build                                    # compiles ./bin/restate and its manpage
sudo ./bin/restate capture -o /tmp/me.tgz     # an image of this machine
sudo ./bin/restate verify /tmp/me.tgz         # what has changed since
```

Building needs a C11 compiler and GNU make, and nothing else. Running it needs
gzip (and uses pigz, if it is installed, to compress on every core), and
`restate installer fetch` also needs curl and gpgv — all three are
in a standard Ubuntu install. For the test suite, the analyzers and the git
hooks:

```bash
make install-dev    # prompts for sudo; installs valgrind, cppcheck, clang-tidy,
                    # shellcheck, actionlint, gcovr, flawfinder, gitleaks, semgrep,
                    # clang and the libFuzzer runtime, and the git hooks
make test           # unit + end-to-end tests, sanitizers, valgrind, 80% coverage gate
```

## Usage

```
Usage: restate [OPTION]... COMMAND [ARGUMENT]...

Records what makes this machine different from a fresh install of its
operating system, so that after a reinstall the difference can be put
back. Every path is classified by a set of rules as ephemeral (never
kept), expendable (kept only with --all), baseline (supplied by the
operating system or its packages) or state (always kept). An image is a
.tgz holding index.json -- every recorded path with its owner, mode,
times and SHA-256 -- and the content of everything kept.

Commands:
  capture                 walk the tree and write an image (-o FILE.tgz):
                          index.json and the content of everything kept
  scan                    walk the tree and write its index alone, as JSON,
                          with no content
  diff OLD NEW            compare two images or indexes: A added, D deleted, M
                          modified, and how
  verify IMAGE            compare an image or index against the tree as it is
                          now
  machine                 describe this machine: hardware, firmware, disks,
                          partitions, encryption, LVM, RAID, mounts
  packages [IMAGE]        list what is installed, and where each package came
                          from -- apt, snap, flatpak, pip, npm, cargo -- here,
                          or on the machine IMAGE was taken from
  installer [fetch] [IMAGE]
                          show the installer that rebuilds this machine, or the
                          one IMAGE was taken from; with fetch, download it and
                          check its signature
  buildsheet [IMAGE]      write a plain-text runbook to rebuild this machine,
                          or the one IMAGE was taken from: disks, encryption,
                          LVM, filesystems, installer, restore
  autoinstall [IMAGE]     write an Ubuntu autoinstall file that rebuilds this
                          machine, or the one IMAGE was taken from, unattended:
                          storage, locale, network, identity
  classify PATH...        show the class each path falls under, and the rule
                          that decided it
  rules                   print the rules in effect, in the format --rules
                          reads

Options:
  -r, --root=DIR          treat DIR as the root of the tree to scan, verify, or
                          list the packages of (default /)
  -o, --output=FILE       write to FILE instead of standard output; created
                          mode 0600, replaced atomically
  -R, --rules=FILE        read more rules from FILE, applied after the built-in
                          ones; repeatable
  -N, --no-default-rules  start from no rules at all rather than the built-in
                          set
      --os=NAME           use the built-in rules for NAME (linux, freebsd,
                          openbsd, netbsd, darwin) rather than this system's
  -a, --all               record expendable paths too: caches, logs, downloaded
                          packages
  -B, --baseline-content  capture: keep the content of baseline files too, not
                          only their digests
      --encrypt-to=KEYFILE
                          capture: encrypt the image to the OpenPGP public key
                          in KEYFILE (gpg --export); repeatable, for more than
                          one recipient
  -x, --one-file-system   record mount points but do not descend into other
                          filesystems
  -n, --no-hash           record metadata only; much faster, but content is
                          then judged by size and mtime
      --cache=DIR         installer fetch: keep installers in DIR rather than
                          the system's cache
      --mirror=URL        installer fetch: download from the directory at URL
                          (https:// or file://) rather than the vendor's
      --target=KIND       buildsheet, autoinstall: rebuild as a virtual machine
                          (vm) or on other hardware (metal) rather than the
                          same machine
  -P, --progress          show progress on standard error: paths and bytes so
                          far while walking, a percentage and time left while
                          writing an image or downloading
  -q, --quiet             no warnings and no summary; errors are still reported
  -v, --verbose           report every path the rules skip, and why
  -h, --help              print this help and exit
  -V, --version           print the version and exit
```

## Progress

A whole-machine capture can read hundreds of gigabytes. `--progress` (`-P`)
shows how far it has got, redrawn in place on the terminal:

```console
$ sudo restate capture --progress -o /backup/web01.tgz
restate: counting  812345 paths  184 GiB to read  0:00:41
restate: walking [#######.............]  35%  64 GiB of 184 GiB  91 MiB/s  0:22:30 left
  .../home/alice/dev/project/src/main.c
```

A quick metadata-only count comes first, so the walk has a real 0-100% with
throughput and time left, and the path being read underneath; writing the
image shows the same; `installer fetch` shows curl's bar. The bar fills the
terminal's width, and is drawn on the terminal even when output is going to
a log through `tee` -- each phase's final line goes to the log as well. With no
terminal (cron), it writes a plain line every ten seconds instead. Off unless
asked for; works alongside `--quiet`.

## Packages

A reinstall puts back the distribution's own packages, and the image leaves
out what a package manager puts back — so every capture and scan records what
was installed since, and from where, and `restate packages` prints it:

- **apt:** every package, version and architecture; installed by hand or as a
  dependency; held, or left half-configured. Every repository, in either
  sources format, and every key apt trusts — whole, wherever it is, because a
  key in `/usr/share/keyrings` is not in the image and apt refuses a
  repository without it. And which repository each installed version can be
  had from again; for the ones none can, `"unavailable": "superseded"` (a
  newer version replaced it) or `"local"` (installed from a `.deb`, and only
  that file puts it back).
- **snap:** revision, channel and confinement (channels need root); snaps
  installed from a file are marked `"local"`.
- **flatpak:** remotes and apps, system-wide and per user.
- **pip, npm, cargo, pipx, gems:** what was installed outside any project,
  system-wide and in each home.
- **OpenBSD and NetBSD packages.** rpm, pacman, apk, Nix, Guix, Homebrew,
  conda, FreeBSD's pkg and macOS receipts are noted as present, without an
  inventory yet.

```console
$ restate packages | jq -c '.apt | {count, manual, superseded, local}'
{"count":3184,"manual":234,"superseded":2,"local":5}
$ restate packages laptop.tgz | jq -r '.apt.packages[] | select(.unavailable == "local") | .name'
chef
osquery
otelcol-contrib
veracrypt
zoom
```

## Installers

`restate installer` names the installation image a machine is rebuilt from:
the distribution, release and point release, the architecture, and whether
it is a desktop or a server, with the evidence. Given an image or index it
names the installer for the machine that was captured. `restate installer
fetch` downloads it into `/var/cache/restate/installers/<vendor>/<release>/`
(`--cache` to change that) and checks it: the vendor's `SHA256SUMS` must be
signed by the vendor key built into restate, pinned by fingerprint, and the
image must match it. Ubuntu is supported now; the others are on the
[roadmap](ROADMAP.md).

```console
$ restate installer
installer   Ubuntu 26.04 Desktop for amd64
for         web01 (Ubuntu 26.04.1 LTS)
because     this is a desktop: the ubuntu-desktop package is installed
from        https://releases.ubuntu.com/26.04/
            or, after end of life, https://old-releases.ubuntu.com/releases/26.04/
file        ubuntu-26.04[.N]-desktop-amd64.iso -- 26.04.1, or the newest listed
checked by  SHA256SUMS, signed by Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>
            8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092
fetch it    restate installer fetch
$ sudo restate installer fetch
/var/cache/restate/installers/ubuntu/26.04/ubuntu-26.04.1-desktop-amd64.iso
```

## Rebuilding

`restate buildsheet` turns a machine description -- this machine's, or the one
inside an image -- into a plain-text runbook for rebuilding it onto a blank
disk: the hardware and installer it needs, then the `sfdisk`, `cryptsetup`,
`mdadm`, LVM (`vgcfgrestore`, from the group's own metadata backup) and
`mkfs` commands that recreate the layout **with the original UUIDs**, so the
restored `/etc/fstab` and `/etc/crypttab` still match; then how to drive the
installer, what to do after it, how to install the packages again, and how to
put the files back. Nothing is run: every command is printed to be checked and
run by a person.

The packages go back before the files, from the image's
[inventory](#packages): `/etc/apt` and the repository keys kept outside it,
then every package installed by hand pinned to its old version (so it comes
from the repository it came from), the snaps by channel, the flatpak apps,
and what pip, npm, pipx, cargo and gem installed. The packages no repository
has are listed with what to do about them.

`restate autoinstall` writes the same layout as an Ubuntu autoinstall file for
an unattended reinstall, with the locale, keyboard, time zone, host name,
network and SSH server. LUKS passphrases and the first account's password are
left as `CHANGE-ME`.

Another operating system's partitions -- Windows, BitLocker, macOS, VeraCrypt
-- are never formatted. For the same machine, both keep them, and the EFI
partition they boot from, in place.

`--target vm` rebuilds as a virtual machine instead: Linux volumes only, each
sized to what the image holds plus room to grow, a ready `virt-install`
command with a modest share of a host (at most 8 GiB and 4 CPUs, never more
than the original), and
the hardware-only packages swapped for `qemu-guest-agent`. `--target metal`
goes the other way, onto other hardware. Both cover what cannot move:
interface names and MACs, TPM-held LUKS keys, Secure Boot keys, the
hibernation resume device.

```console
$ restate buildsheet web01.tgz -o web01-rebuild.txt
$ restate autoinstall --target vm web01.tgz -o user-data
```

The autoinstall file does not install the packages yet; that is next on the
[roadmap](ROADMAP.md).

## Images and indexes

An image is an ordinary gzip'd POSIX tar archive with the index first:

```console
$ tar -tzvf web01.tgz | head -4
-rw------- 0/0       9283117 2026-10-03 14:00 restate/index.json
drwxr-xr-x root/root       0 2026-09-30 08:12 restate/files
drwxr-xr-x root/root       0 2026-10-01 17:40 restate/files/etc
-rw-r--r-- root/root    3279 2026-09-12 10:03 restate/files/etc/ssh/sshd_config
```

`index.json` is one JSON object, with one entry per line, sorted by path:

```json
{
  "format": "restate-index",
  "version": 1,
  "restate": "0.1.0.0",
  "root": "/",
  "os": "linux",
  "host": "web01",
  "created": "2026-10-03T14:00:00.000000000Z",
  "hash": "sha256",
  "hashed": true,
  "content": "state",
  "count": 41873,
  "entries": [
    {"path": "/etc/ssh/sshd_config", "name": "sshd_config", "type": "file", "class": "state", "mode": "0644", "uid": 0, "user": "root", "gid": 0, "group": "root", "size": 3279, "nlink": 1, "device": 2049, "inode": 1835071, "atime": "2026-10-03T13:58:41.120998201Z", "mtime": "2026-09-12T10:03:17.402113883Z", "ctime": "2026-09-12T10:03:17.402113883Z", "btime": "2026-04-23T19:20:02.511472096Z", "sha256": "0f3b2c...", "stored": "restate/files/etc/ssh/sshd_config"}
  ]
}
```

| Field | |
|---|---|
| `path`, `name` | the full path in the scanned tree, and its last component |
| `type`, `class` | file, directory, symlink, char, block or fifo; and the rule class |
| `mode` | permission bits as an octal string |
| `uid`, `user`, `gid`, `group` | owner by number *and* by name — a reinstall may number users differently, so a restore maps by name |
| `size`, `nlink`, `device`, `inode` | two entries with the same device and inode are hard links to one file |
| `rdev` | a device node's device number |
| `atime`, `mtime`, `ctime`, `btime` | access, modification, status-change and birth (creation) time, nanosecond ISO 8601 UTC; `btime` is `null` where the filesystem keeps none |
| `sha256` | a regular file's content digest; `"unreadable": true` where it could not be read |
| `target` | a symlink's target |
| `stored` | where the content is inside the image |
| `path_base64`, `target_base64` | the exact bytes of a name that is not valid UTF-8, which JSON cannot hold directly |

**Why SHA-256 and not MD5:** an MD5 collision can be manufactured, so a planted
file could compare equal to the one it replaced. SHA-256 costs little more, and
is implemented here — restate links nothing but libc.

**Why the index comes first:** `diff` and `verify` read only `index.json`, and
stop. The content is written during the walk to an unlinked temporary file
beside the destination — each file read once, the same bytes hashed and stored
— and the image is assembled afterwards, so the digest always describes
exactly the bytes in the image.

`scan` writes the index alone, without content, for when the question is "what
changed" rather than "keep a copy".


### Encrypted images

An image holds whatever a reinstall would not put back, and that can include
keys -- a LUKS key file, SSH host keys, TLS private keys. Encrypt it to one or
more OpenPGP public keys:

```console
$ gpg --export -o backup-key.gpg backup@example.com
$ sudo restate capture -o web01.tgz.gpg --encrypt-to=backup-key.gpg
$ restate verify web01.tgz.gpg          # decrypts with your own keyring
```

Capturing needs only the public key, so it can run from cron with no
passphrase anywhere. The result is an ordinary OpenPGP message (`gpg -d`
reads it), and `diff`, `verify`, `installer`, `buildsheet` and `autoinstall`
all read it directly. While the tree is walked, the content is staged
unencrypted in an unlinked temporary file beside the image; where that
matters, write the image to encrypted storage or a tmpfs.

## Classes and rules

```console
$ restate classify /etc/passwd /usr/bin/ls /var/cache/apt /run/sshd.pid /home/me/.cache/x
state      /etc/passwd          state /etc (built-in (linux))
baseline   /usr/bin/ls          baseline /usr (built-in (linux))
expendable /var/cache/apt       expendable /var/cache (built-in (linux))
ephemeral  /run/sshd.pid        ephemeral *.pid (built-in (linux))
expendable /home/me/.cache/x    expendable .cache (built-in (linux))
```

A rules file is `CLASS PATTERN` per line; the **last** matching rule wins, as
in `.gitignore`, and a rule covers the path it names and everything below it.
`*` matches within one component, `**` across components, `**/` zero or more
whole directories, and a pattern with no leading `/` matches at any depth.

```
# site.rules
state       /srv
expendable  /srv/cache
ephemeral   *.sock
```

```bash
restate rules > site.rules          # the built-in set, with a reason for each rule
restate -N -R site.rules capture -o web01.tgz   # use only yours
restate -R site.rules capture -o web01.tgz      # or add yours after the built-ins
```

### What is left out by default

An image holds what cannot be had again any other way. Anything that can be
downloaded again, or rebuilt from files the image does keep, is **expendable**
and left out unless you ask for it:

- **Downloads** -- `~/Downloads` in every home, on every system (`/home`,
  FreeBSD's `/usr/home`, macOS's `/Users`, and root's).
- **Caches and the trash** -- `~/.cache`, the desktop trash and other drives'
  `.Trash-*`, thumbnails, the caches Chrome, Brave, Edge and Electron apps
  keep in their profiles (not bookmarks, logins or site data), `/var/cache`,
  SonarScanner's cache, macOS's `Library/Caches`.
- **Dependencies** -- `node_modules`, the npm/Yarn/pnpm/Bun caches, Python
  virtual environments (`.venv`, `venv`, `~/.venvs`, pipenv's), the Gradle,
  Maven, Cargo, Go, NuGet, Dart, Haskell and conda caches, installed gems,
  Terraform providers.
- **Build output** -- `__pycache__`, `*.o`, CMake files, Next.js/Nuxt/Parcel/
  Turborepo/Zig caches, ccache, Xcode's DerivedData.
- **Installed toolchains and apps** -- nvm, pyenv, rbenv, asdf, mise, Volta,
  SDKMAN!, ghcup, rustup; VS Code extensions; the Android SDK, PlatformIO,
  Arduino, JetBrains Toolbox; Steam games; Flatpak apps (remotes and overrides
  are kept); snaps; Ollama models.
- **Images** -- container images and layers (containerd, Docker, Podman, but
  not their volumes), LXD's image cache, snapd's seed, installer and disc
  images (`*.iso`) wherever they are, cloud images, and downloads that never
  finished (`*.part`, `*.crdownload`). VM disks and definitions are data and are kept; a suspended VM's
  saved memory is not (the VM boots afresh).
- **Never at all** -- swap files, PID files, sockets, `lost+found`, `/proc`,
  `/sys`, `/run`, `/tmp`, `/mnt`, `/media`.

Nothing here is gone for good: `--all` keeps all of it, and a rule keeps one
piece, since your rules come after the built-ins and the last match wins:

```
state  /home/alice/Downloads     # keep one user's downloads
state  /srv/app/node_modules     # an app deployed with its dependencies
state  **/.venv                  # every virtual environment
```

`restate classify PATH` says which rule decided a path; `restate rules` lists
them all, each with its reason.

## Installing

Distribution packages come later — a Launchpad PPA for Ubuntu first; see the
[roadmap](ROADMAP.md). For now restate is built from source and installed into
`/usr/local`, which is the place for software the administrator installs by
hand and is never touched by the package manager.

### Installing on Ubuntu 26.04

```bash
sudo apt update
sudo apt install build-essential git      # a compiler, GNU make, and git
git clone https://github.com/bceverly/restate.git
cd restate
make build
sudo make install                         # /usr/local/sbin/restate and its manpage
restate --version
man restate
```

`make install` asks for `sudo` itself if `/usr/local` is not writable, so
plain `make install` works too. To install somewhere else:

```bash
make install prefix=$HOME/.local          # no root needed
make install DESTDIR=/tmp/stage           # staged, as a package build does
```

To remove it:

```bash
sudo make uninstall
```

`restate` lands in `sbin` and its manual in section 8 because it is a system
administration tool: a capture worth having reads every file, so it runs as
root. `/usr/local/sbin` is on root's `PATH` on every Ubuntu release.

### Developing on Ubuntu 26.04

```bash
make install-dev    # every compiler, analyzer and scanner the checks use, and the git hooks
make build          # ./bin/restate
make test           # everything CI runs on every push, locally
```

`./bin/restate` runs straight from the tree; nothing needs installing to try a
change.

### Other systems

The same `make build && sudo make install`, with GNU make:

| System | Install the build tools | Then |
|---|---|---|
| Any Linux | the distribution's C compiler and make | `make build && sudo make install` |
| FreeBSD | `sudo pkg install gmake bash` | `gmake build && sudo gmake install` |
| OpenBSD | `doas pkg_add gmake bash` | `gmake build && doas gmake install` |
| NetBSD | `sudo pkgin install gmake bash` | `gmake build && sudo gmake install` |
| macOS | `xcode-select --install` | `make build && sudo make install` |

The manpage goes where each system's `man` looks for it — `share/man` on Linux,
FreeBSD and macOS, `man` on NetBSD and OpenBSD — and the man database is
refreshed so `man restate` works at once. Every one of these is built, tested
and installed in CI on every push.

## Building

```bash
make build           # ./bin/restate, and the manpage regenerated from --help
make build WERROR=-Werror
make debug           # -O0 -g3, for a debugger
```

`CC`, `CFLAGS`, `CPPFLAGS` and `LDFLAGS` are the caller's; the project's own
warnings and hardening are appended, never substituted. Every hardening flag is
*probed* before use — `-fstack-clash-protection`, `-fcf-protection=full`,
`-ftrivial-auto-var-init=zero`, `_FORTIFY_SOURCE=3` (falling back to 2), and
the ELF `-z relro -z now -z noexecstack` — so the same Makefile builds on every
compiler and every platform, and `make security` reads the built binary to
prove the flags did something.

The version is the `VERSION` file. A build that is not exactly a tagged release
reports itself as `-dev`, so a bug report says which it was.

## Testing

```bash
make test            # all of the below
make test-unit       # the C unit tests
make test-cli        # end-to-end: the built binary, run as a user runs it
make test-memory     # ASan + UBSan + LSan, then valgrind, over both suites and a malformed-input corpus
make coverage        # line coverage, and the README badge; fails below 80%
make fuzz            # libFuzzer (or the built-in mutator) over every parser; FUZZ_SECONDS=30
```

The coverage gate is **80%, for the total and for every source file on its
own** — a well-tested file cannot hide an untested one. Either can be raised
(`COVERAGE_MIN=90`, `COVERAGE_FILE_MIN=90`); asking for less than 80 is
refused. The badge above is generated from the measured number, never typed.

The fuzz target reaches every parser restate has — the JSON index, the tar
reader, rules files, path patterns, timestamps and base64 — and checks
round-trip invariants: an index that parses must write back out and parse to
the same thing.

## Security

```bash
make security        # everything below, the same way CI runs it
make lucky13         # MITRE's thirteen unforgivable vulnerability classes, one by one
```

`make security` checks the built binary's hardening, then runs `gcc
-fanalyzer`, cppcheck with the CERT C rules, the clang static analyzer,
flawfinder, semgrep, the sanitizers, a fuzz run, gitleaks over the whole
history, MITRE's "Lucky 13", and confirms the binary links nothing beyond libc.
CodeQL (`security-extended`) and the OpenSSF Scorecard run in CI.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability privately.

## Make targets

Run `make` with no arguments for the full list.

| | |
|---|---|
| `make build` | compile into `./bin`, regenerating the manpage |
| `make test` | unit, end-to-end, sanitizers, valgrind, and the 80% coverage gate — overall and per file |
| `make lint` | the compiler with `-Werror`, `gcc -fanalyzer`, cppcheck, clang-tidy, shellcheck, actionlint, house style, copyright audit, generated-file freshness |
| `make security` | the security scanners, sanitizers, a fuzz run, gitleaks, Lucky 13 |
| `make fuzz` | fuzz every parser |
| `make install` / `make uninstall` | into / out of `$(prefix)`, default `/usr/local` |
| `make release` | bump the version, tag and push: `make release VERSION=1.2.3.4` |
| `make install-dev` | the development tools and the git hooks |
| `make man` | regenerate the manpage and the README's Usage block |
| `make show-man` | read the manpage from the tree, without installing anything |
| `make clean` | remove everything a build or test produced |

## Releasing

```bash
make release                    # bump the last component of the newest tag
make release VERSION=0.2.0.0    # or choose
```

It confirms, writes `VERSION`, rebuilds so the binary and manpage agree,
commits, pushes, tags and pushes the tag. The tag starts the Release workflow,
which waits for CI, Security and CodeQL to pass on that exact commit, builds
the source tarball with `git archive`, builds and tests *from the tarball* on a
clean runner, and publishes a GitHub release with SHA-256 checksums and a
signed SLSA build-provenance attestation:

```bash
sha256sum -c SHA256SUMS
gh attestation verify restate-0.1.0.0.tar.gz --repo bceverly/restate
```

## GitHub configuration

Settings that live in the repository rather than in it, and that the workflows
and the Scorecard expect:

- **Security → Private vulnerability reporting:** on, so SECURITY.md's link works.
- **Security → Code scanning:** CodeQL and Scorecard upload SARIF here.
- **Branches → `main` protection:** require the CI, Security and CodeQL checks,
  require a pull request, and disallow force pushes. Scorecard scores this.
- **Actions → General → Workflow permissions:** read-only by default; each
  workflow asks for exactly what it needs.
- **Dependabot:** alerts and security updates on; `dependabot.yml` keeps the
  actions current.

## Project layout

```
src/            the program: one module per concern
  main.c        the entry point, and nothing else
  opts.c        the command line; options.def and commands.def define it
  cmd.c         the commands
  rules.c       classification, and the built-in rules per system
  glob.c        path patterns, linear-time
  scan.c        the walk
  index.c       the index, to and from JSON
  image.c       images: assembling and reading back
  tar.c         pax tar, writing and reading the first member
  gzip.c        gzip as a separate process
  run.c         running gzip, curl and gpgv: fixed paths, posix_spawn
  machine.c     the machine description: hardware, disks, encryption
  packages.c    the package inventory: apt, snap, flatpak, pip, npm, cargo
  installer.c   which installer rebuilds a machine, and fetching it
  keys.c        the vendors' signing keys, pinned by fingerprint
  json.c        a strict JSON parser and writer
  meta.c        timestamps, birth times, user and group names
  diff.c        comparing two indexes
  sha256.c      FIPS 180-4
include/        restate.h: the version, copyright and exit statuses
tests/          unit tests; cli/ end-to-end; fuzz/ the fuzz target
scripts/        everything make runs
man/restate.8   generated from --help; do not edit
.github/        CI, security, CodeQL, Scorecard and release workflows
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
