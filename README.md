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
# restate capture -o /var/backups/web01.tar
restate: recorded 41873 paths (40102 state, 1771 baseline, 0 expendable); kept the content of 40102
restate: skipped 2114 ephemeral, 9 expendable, 14 sockets, 0 mount points
restate: hashed 812447112 bytes

# restate verify /var/backups/web01.tar
M	/etc/ssh/sshd_config	content
A	/etc/nginx/sites-enabled/new-site.conf
restate: 1 added, 0 deleted, 1 modified
```

## Contents

- [What it does](#what-it-does)
- [Use cases](#use-cases)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Live services](#live-services)
- [Packages](#packages)
- [Restoring](#restoring)
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
  packages: `/usr`, the kernel) or *state* (`/etc`, `/home`, `/var/lib`,
  `/usr/local` — always kept). Built-in rules for Linux, FreeBSD, OpenBSD,
  NetBSD and macOS; your own rules file overrides any of them.
- **Checks every file against the package that installed it**, where dpkg
  manages the system: a file just as its package left it is that package's
  and is not kept, wherever it lives; an edited one, or one under `/usr` or
  `/boot` that no package installed, is kept.
- **Captures an image**: a tar holding `index.json` — every recorded path
  with its owner, mode, size, link count, inode, access, modification,
  change and birth times to the nanosecond, and SHA-256 — followed by the
  content of everything kept. It is also an ordinary tarball: `tar -xzpf`
  restores it by hand.
- **Compares.** `diff` two images or indexes, or `verify` one against the
  machine as it is now, and see what was added, deleted and modified — and
  whether a modification was the content, the mode, the owner or a link target.
- **Pauses what is running, just in time.** A database, a VM or a container
  found writing to files the image keeps is named, and with `--quiesce`
  paused by a hook while its own files are copied, then resumed.
- **Signs images, and refuses unsigned ones.** `--sign-with` signs an image;
  `restore` checks it against `--trusted-key` before reading anything else.
- **Walks safely, as root, through directories users control.** Nothing is
  opened by a path longer than one component, no symlink is followed, and
  every file is checked against what was stat'ed a moment earlier.

## Use cases

**What changed on this server?** Capture on a schedule, and see exactly what
has been added, deleted or modified since — content, mode, owner or link
target — without the noise of timestamps:

```bash
restate capture -o /var/backups/web01-$(date +%F).tar
restate verify /var/backups/web01-2026-09-28.tar          # against the server as it is now
restate diff web01-2026-09-28.tar web01-2026-10-05.tar    # between two captures
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
sudo ./bin/restate capture -o /tmp/me.tar     # an image of this machine
sudo ./bin/restate verify /tmp/me.tar         # what has changed since
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
.tar holding index.json -- every recorded path with its owner, mode,
times and SHA-256 -- and the content of everything kept.

Commands:
  capture                 walk the tree and write an image (-o FILE.tar):
                          index.json and the content of everything kept
  scan                    walk the tree and write its index alone, as JSON,
                          with no content
  diff OLD NEW            compare two images or indexes: A added, D deleted, M
                          modified, and how
  verify IMAGE            compare an image or index against the tree as it is
                          now
  sign IMAGE              sign an image already written, with --sign-with: so a
                          capture run unattended needs no secret key on the
                          machine
  restore IMAGE           put an image's files back under the root (--root,
                          default /): each checked against the index before it
                          is put in place, with its owner, mode and times
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
      --rules-only        classify by the rules alone, without checking files
                          against the packages that installed them
  -a, --all               record expendable paths too: caches, logs, downloaded
                          packages
  -B, --baseline-content  capture: keep the content of baseline files too, not
                          only their digests
      --encrypt-to=KEYFILE
                          capture: encrypt the image to the OpenPGP public key
                          in KEYFILE (gpg --export); repeatable, for more than
                          one recipient
      --sign-with=KEYFILE
                          capture, sign: sign the image with the OpenPGP secret
                          key in KEYFILE (gpg --export-secret-keys)
      --trusted-key=KEYFILE
                          restore, verify, diff: accept an image only if it is
                          signed by the OpenPGP public key in KEYFILE (gpg
                          --export); autoinstall: have the restore check that;
                          repeatable
      --allow-unverified  restore: restore an image that is unsigned, or not
                          signed by a --trusted-key, warning of it; by default
                          it is refused
      --keep-local-packages
                          capture: keep the .deb and .snap files of installed
                          packages no repository or store has, from apt's and
                          snapd's caches, so a rebuild can install them
      --deb=NAME=FILE     capture, with --keep-local-packages: keep FILE as the
                          .deb of package NAME, which no repository has and
                          apt's cache does not hold; repeatable
      --quiesce           capture: pause each database, VM and container found
                          running while its own files are copied, and resume it
                          after, with the hooks for each (see LIVE SERVICES)
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
      --image-at=PATH     autoinstall: where the installer will find the image
                          (a mounted disk or share); the file then installs the
                          packages and restores the files from it
      --exclude=PATTERN   restore: leave out PATTERN (written as in a rules
                          file, everything beneath it too); repeatable
      --numeric-owner     restore: owners by the numbers the index records, and
                          the image's own account files, rather than by name
                          through the image's accounts merged with the system's
      --dry-run           restore: check the image and say what would be put
                          back, writing nothing
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
$ sudo restate capture --progress -o /backup/web01.tar
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

## Live services

A file copied while something writes to it can come back half old and half
new. So `capture` looks in `/proc` (on Linux) for what is running and writing
to files the image keeps -- PostgreSQL, MySQL and MariaDB, MongoDB, Redis,
QEMU VMs, LXD containers and Docker's containers -- and names each one, with
the command that would stop it:

```console
$ sudo restate capture -o laptop.tar
restate: warning: PostgreSQL 18-main (/var/lib/postgresql/18/main) is running, and its files will be copied as they change: stop it first (systemctl stop postgresql@18-main), or capture with --quiesce
restate: warning: the VM win-msi-lab (/home/me/.local/share/libvirt/images/win-msi-lab.qcow2, ...) is running, and ...
```

With `--quiesce` it pauses each one instead, **just in time**: everything else
is copied first, then each in turn is paused, its own files copied, and
resumed -- down for as long as its own files take, not the whole capture.
While one is paused a Ctrl-C waits until it is resumed again, and every
pause and resume is logged to syslog for a capture run from cron.

restate runs no administration tools itself: a **hook** does the pausing, an
executable named for the kind of thing (`postgresql`, `mysql`, `mongodb`,
`redis`, `libvirt`, `lxd`, `docker`), from `/etc/restate/hooks.d` or else the
ones restate ships in `libexec/restate/hooks`, and only if it and its
directory are root's alone. It is run as `HOOK pause NAME` and then, always,
`HOOK resume NAME`, with `RESTATE_KIND`, `RESTATE_NAME`, `RESTATE_PID`,
`RESTATE_UID`, `RESTATE_USER`, `RESTATE_PATHS` and `RESTATE_DUMP_DIR` in its
environment. The shipped database hooks dump into `RESTATE_DUMP_DIR` (which
goes into the image beside the files) and stop the service; the others
suspend the VM, freeze the container or pause Docker's containers. The
PostgreSQL hook stops the units listed in `/etc/restate/also.d/postgresql`
first -- services that write to the database -- and starts them after. To
change a hook, copy it to `/etc/restate/hooks.d` and edit the copy.

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
- **Alternatives** chosen by hand (`update-alternatives --set`).

Every apt source is **checked**, too, as apt checks it: its index as apt last
fetched it, against the keys the source names, with `gpgv`, and its
`Valid-Until` against the clock. apt refuses a source whose key has gone,
changed or expired once, in an `apt update` nobody reads, and then quietly
uses the last index it accepted -- for months. A rebuild installs from the
source as it is now and gets nothing from it. A source apt cannot use gets a
`"problem"` in the inventory, and `capture` warns:

```console
restate: warning: apt cannot use a source in /etc/apt/sources.list.d/hashicorp.sources -- https://apt.releases.hashicorp.com resolute: signed by a key that is not given (ID FC9CA96ACA026560); a rebuild will not install from it until that is put right
```

`capture --keep-local-packages` also keeps what no repository or store can
give back: the `.deb` of each version no repository has, from apt's cache, and
the `.snap` of each snap installed from a file. A package installed from a
downloaded file is often not in apt's cache; the capture warns of each one,
and `dpkg-repack NAME`, run in `/var/cache/apt/archives`, rebuilds it there --
or `--deb NAME=FILE` names the vendor's file, wherever it is (a package whose
own maintainer scripts dpkg-repack refuses, say):

```console
$ sudo restate capture --keep-local-packages \
      --deb veracrypt=/home/me/Downloads/veracrypt-1.26.24-Ubuntu-24.04-amd64.deb -o laptop.tar
```

A superseded version -- one a repository has a newer version of -- is kept
if it is in the cache and passed over quietly if not: the rebuild installs
the newer one.

```console
$ restate packages | jq -c '.apt | {count, manual, superseded, local}'
{"count":3184,"manual":234,"superseded":2,"local":5}
$ restate packages laptop.tar | jq -r '.apt.packages[] | select(.unavailable == "local") | .name'
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
from the repository it came from) -- but not the boot loader or kernel, which
the installer chose for the new machine. A script looks each package up first,
so one that cannot be had (a vendor that keeps only its newest version, a
repository whose key has expired) does not stop all the others: the recorded
version where it is still there, the current one where not, and a word about
any no repository has. Then the kept `.deb` files, the snaps by
channel, the flatpak apps, what pip, npm, pipx, cargo and gem installed, and
the alternatives chosen by hand. The packages no repository has are listed
with what to do about them.

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
$ restate buildsheet web01.tar -o web01-rebuild.txt
$ restate autoinstall --target vm web01.tar -o user-data
```

Given `--image-at PATH` -- where the installer will find the image -- the
autoinstall file does all of that unattended in its late-commands, then
restores the files and rebuilds the initramfs and boot loader, so the machine
comes up as it was. The snaps go in at its first boot, by a one-time
`restate-firstboot` service: the desktop installer ignores an autoinstall
file's `snaps` section, and snapd does not run during an install.

```console
$ restate autoinstall --target vm --image-at /restate/web01.tar web01.tar -o user-data
```

## Restoring

`restate restore IMAGE` puts an image's files back, and distrusts the image
while it does: every member has to be one the index lists, every file's
content has to hash to the index's digest before it is renamed into place (a
tampered file never lands), and nothing in the tree it writes into -- a
symlink planted where a directory belongs -- can steer it elsewhere. Owners,
modes and nanosecond times come from the index; hard links come back as
links; device nodes are made from the index. Extended attributes come back
too, and with them, on Linux, POSIX ACLs and file capabilities: set after
the owner, since a change of owner clears a file's capabilities, with the
users and groups an ACL names mapped by name, as owners are. SELinux and
Smack labels and IMA and EVM signatures are left to the target's own policy
and keys.

Owners are restored by name. A rebuilt machine's packages numbered their own
users as they went in (postgres may be 128 where it was 125), so the image's
`/etc/passwd`, `/etc/group` and shadows are merged with the new system's
rather than laid over them -- both systems' users, the new numbers where both
have one, the old passwords, homes and shells -- and every file's owner is
mapped through them by name. `--numeric-owner` restores the recorded numbers
instead.

```console
$ sudo restate restore --dry-run web01.tar            # check it all, write nothing
$ sudo restate restore --exclude /etc/fstab web01.tar
$ sudo restate restore --root /target web01.tar       # from an installer
```

**Only a signed image is restored**, unless told otherwise. `restore` checks
the signature before it reads anything else, and refuses -- exit status 4 --
an image that is unsigned, badly signed, or signed by a key not given with
`--trusted-key`. When it accepts one it says who signed it, and when and on
which host it was captured, so an older image signed by the same key is plain
to see. `--allow-unverified` restores one anyway, with a warning; it is a
command-line option and nothing else can set it. `verify` and `diff` check the
same way when given `--trusted-key`.

```console
$ sudo restate restore --trusted-key backup-signing.pub web01.tar
restate: web01.tar is signed by Backups <backup@example.com> (3D71 FE67 ...) on 2026-10-09
restate: captured on web01 at 2026-10-09T02:00:00.000000000Z, by restate 1.2.0.2
```

The image's kit carries the restate that made it, so a rebuilt machine can
restore before restate is installed; the build sheet and autoinstall file do
just that. The autoinstall file makes the old machine's first person the
install's own account, so the merge gives them back their password and
groups with no installer account on their number. Both pass restore
`--allow-unverified`, unless made with `--trusted-key`: then the sheet's
restore names the same key files, and the autoinstall file carries the keys
itself.

## Images and indexes

An image is an ordinary POSIX tar archive of three parts, each compressed on
its own, so each can be read without decompressing the others:

```console
$ tar -tvf web01.tar
-rw------- 0/0      48211337 2026-10-03 14:00 restate/index.json.gz
-rw------- 0/0     412204410 2026-10-03 14:00 restate/kit.tar.gz
-rw------- 0/0  106374598111 2026-10-03 14:00 restate/files.tar.gz
```

| Part | |
|---|---|
| `index.json.gz` | the index: what `verify`, `diff`, `buildsheet` and `autoinstall` read — and all they read |
| `kit.tar.gz` | what a reinstall needs before anything else: `/etc/apt`, and the packages the image keeps that no repository has. A few megabytes to a few hundred, had in seconds |
| `files.tar.gz` | every file kept, with its owner, mode and times (the kit's too) |

The outer archive is not compressed, so tar skips past the parts it is not
asked for instead of reading them, and each part unpacks with plain tar:

```console
$ tar -xOf web01.tar restate/files.tar.gz | sudo tar -xzpf - --numeric-owner -C / --strip-components=2
```

An image made before 1.1 is one gzip'd tar with `restate/index.json` first; it
is still read.

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
| `xattrs` | a file's or directory's extended attributes, `[{"name", "value"}]` with the value base64 — on Linux its POSIX ACLs and file capabilities among them |
| `package`, `modified` | the package a file came from, where dpkg says, and `true` where it no longer matches what that package installed |
| `path_base64`, `target_base64` | the exact bytes of a name that is not valid UTF-8, which JSON cannot hold directly |

**Why SHA-256 and not MD5:** an MD5 collision can be manufactured, so a planted
file could compare equal to the one it replaced. SHA-256 costs little more, and
is implemented here — restate links nothing but libc.

**Why the parts:** `diff` and `verify` read only the index, and a rebuild needs
the kit long before the files; neither should mean decompressing a hundred
gigabytes. The content is written during the walk to an unlinked temporary
file beside the destination — each file read once, the same bytes hashed and
stored — and compressed once, into its part, when the image is assembled, so
the digest always describes exactly the bytes in the image.

`scan` writes the index alone, without content, for when the question is "what
changed" rather than "keep a copy".


### Encrypted images

An image holds whatever a reinstall would not put back, and that can include
keys -- a LUKS key file, SSH host keys, TLS private keys. Encrypt it to one or
more OpenPGP public keys:

```console
$ gpg --export -o backup-key.gpg backup@example.com
$ sudo restate capture -o web01.tar --encrypt-to=backup-key.gpg
$ restate verify web01.tar          # decrypts the index with your own keyring
```

Capturing needs only the public key, so it can run from cron with no
passphrase anywhere. Each part is encrypted on its own, an ordinary OpenPGP
message with `.gpg` after its name (`tar -xOf web01.tar
restate/files.tar.gz.gpg | gpg -d | tar -xzf -` unpacks the files), so reading
the index decrypts only the index; `diff`, `verify`, `installer`, `buildsheet`
and `autoinstall` all read it directly. While the tree is walked, the content is staged
unencrypted in an unlinked temporary file beside the image; where that
matters, write the image to encrypted storage or a tmpfs.

### Signed images

Encryption is not authentication: anyone with the public key can make an
image that decrypts cleanly. So sign it, with an OpenPGP secret key:

```console
$ gpg --export-secret-keys -o signing.key backup@example.com
$ sudo restate capture -o web01.tar --sign-with signing.key
$ restate sign --sign-with signing.key web01.tar        # or later, elsewhere
```

`restate sign` adds the signature to an image already written, so a capture
run from cron needs no secret key on the machine. The signature is the
archive's last member, `restate/index.sig`: a detached OpenPGP signature over
the index part exactly as stored -- compressed, and encrypted if the image is
-- so it covers every kept file's digest, owner, mode and path, and checking
it decrypts nothing.

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

Where dpkg manages the system, the rules are only the start. Every regular
file the rules call baseline or state is checked against the digest dpkg
recorded when its package installed it:

- one that still matches is **baseline**, and the index names its package —
  an untouched conffile in `/etc`, a vendor's files in `/opt` are not kept,
  since reinstalling the package puts them back;
- one that does not is **state**, `"modified": true` in the index, and kept;
- one in a baseline tree (`/usr`, `/boot`) that no package installed is
  **state**, and kept: it was put there by hand.

What packages' own scripts generate there — initramfs images, module
indexes, font and icon caches — no package owns either, and the built-in
rules make it expendable. `--rules-only` turns the check off. On this
project's own test laptop the check stopped keeping 2,013 untouched
conffiles and 2.4 GB under `/opt`, and found 64 files under `/usr` that
the rules alone had been leaving out: hand-made systemd sleep hooks, apt
keyrings, fonts.

```
# site.rules
state       /srv
expendable  /srv/cache
ephemeral   *.sock
```

```bash
restate rules > site.rules          # the built-in set, with a reason for each rule
restate -N -R site.rules capture -o web01.tar   # use only yours
restate -R site.rules capture -o web01.tar      # or add yours after the built-ins
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
  run.c         running gzip, curl, gpg and the hooks: fixed paths, posix_spawn
  live.c        what is running, from /proc: databases, VMs, containers
  hooks.c       finding and running the hooks that pause them
  sources.c     whether apt can still use each of its sources
  pgp.c         encrypting, signing and checking signatures, through gpg
  machine.c     the machine description: hardware, disks, encryption
  packages.c    the package inventory: apt, snap, flatpak, pip, npm, cargo
  installer.c   which installer rebuilds a machine, and fetching it
  keys.c        the vendors' signing keys, pinned by fingerprint
  json.c        a strict JSON parser and writer
  meta.c        timestamps, birth times, user and group names
  diff.c        comparing two indexes
  sha256.c      FIPS 180-4
include/        restate.h: the version, copyright and exit statuses
hooks/          the hooks capture --quiesce runs, installed in libexec/restate/hooks
tests/          unit tests; cli/ end-to-end; fuzz/ the fuzz target
scripts/        everything make runs
man/restate.8   generated from --help; do not edit
.github/        CI, security, CodeQL, Scorecard and release workflows
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
