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
[![Ubuntu 26.04](https://img.shields.io/badge/ubuntu-26.04-E95420.svg)](#installing)

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
- [The package baseline](#the-package-baseline)
- [Restoring](#restoring)
- [Copies](#copies)
- [Repositories](#repositories)
- [Storage on a file server](#storage-on-a-file-server)
- [Jobs](#jobs)
- [Results, for programs](#results-for-programs)
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
  `status` does the same in seconds, reading only what changed, and `diff
  --packages` reports an upgrade as the package that changed rather than as
  the hundreds of files it touched.
- **Keeps captures in a repository**, each piece of content stored once: a
  nightly capture reads only the files that changed since the last one and
  stores only the parts of them that changed -- a VM's disk costs the few
  megabytes it changed, not its size again -- and `prune` keeps the daily,
  weekly and monthly snapshots you ask for. A repository can be encrypted, to
  sit on storage you do not trust.
- **Puts a machine back.** `restore --packages` reinstalls a fresh system's
  packages as the old one had them -- its repositories and keys, each package
  at its version, held or installed as a dependency as it was, and what the
  old machine did not have taken away -- then restores the files. `baseline
  fetch` downloads those exact packages ahead of time, each checked against
  its repository's signed index, so versions the archive drops later are
  still at hand.
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

Or into a [repository](#repositories), which stores only what changed each
night and keeps as many snapshots as you ask it to:

```bash
restate capture --quiesce --syslog -o /var/backups/web01     # from cron, nightly
restate prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6 /var/backups/web01
restate status /var/backups/web01                            # what changed since last night
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
image, and diff afterwards to see what the upgrade changed -- by package, with
the files each one changed folded into its line:

```console
$ restate diff --packages before.tar after.tar
U	apt:openssl	3.5.0-1ubuntu1 -> 3.5.0-1ubuntu2, 14 files
I	apt:htop	3.3.0-4, 12 files
R	snap:hello	29
M	/etc/ssl/openssl.cnf	content
restate: 3 packages changed, accounting for 26 files; otherwise 0 added, 0 deleted, 1 modified
```

**The disk died.** Rebuild the machine from its [build sheet or an unattended
autoinstall file](#rebuilding), then put its packages and files back:

```bash
sudo restate restore --packages --trusted-key backup-signing.pub web01.tar
```

**A new laptop, set up like the old one.** Install the distribution, then
restore the old laptop's image with `--packages`: the same repositories, the
same packages at the same versions, the same files.

**A hardware refresh, or bare metal to a virtual machine and back.** `--target
vm` or `--target metal` rebuild a machine elsewhere, with what changes
accounted for: the storage and network drivers in the initramfs, device and
interface names, a disk sized to the data rather than the old drive, hardware
tools swapped for guest agents (or the reverse), an encrypted volume that was
unlocked by the old machine's TPM -- and, with `--firmware`, UEFI where it
booted by BIOS, or the other way. For a VM, a ready-to-run definition of the
virtual machine itself.

**Stamping out copies.** Build one machine that does the thing — a load
generator, a lab workstation — and [put it back as many](#copies), each with
its own host name, address, machine-id and SSH host keys, so no two come up
as the same machine on the network:

```bash
restate autoinstall --clones lab.csv --target vm --image-at /restate/lab.tar lab.tar -o user-data
sudo restate restore --packages --as lab-07 --trusted-key backup-signing.pub lab.tar   # or by hand
```

**Backups a program runs.** A scheduler or a fleet manager runs one fixed
command per machine -- `restate run` on a [job](#jobs) only root can change,
from a systemd timer -- and reads back [how each run went](#results-for-programs)
as JSON, while the file server the repositories live on [checks and prunes
them without their keys](#storage-on-a-file-server):

```bash
sudo systemctl enable --now restate-job@nightly.timer          # on each machine
restate check --metadata-only --record /var/lib/web01.record /srv/restate/web01   # on the NAS
```

### Coming

These need the pieces still on the [roadmap](ROADMAP.md):

- **Turning a hand-built server into code.** The package inventory and the
  autoinstall file are a starting point for automating a machine that was
  only ever configured by hand.

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
  estimate                walk the tree, reading no file, and say how much a
                          first capture would keep, by directory: what to
                          exclude before a first capture that would not fit
  diff OLD NEW            compare two images or indexes: A added, D deleted, M
                          modified, and how
  verify IMAGE            compare an image or index against the tree as it is
                          now
  status IMAGE            what has changed since a capture, quickly: as verify,
                          but a file whose size, times and inode are unchanged
                          is not read
  list IMAGE [PATH]       list what is directly in the directory PATH (default
                          /) of an image or snapshot, from its index alone:
                          each name's type, mode, owner, size and time, with no
                          content read
  sign IMAGE              sign an image or snapshot already written, with
                          --sign-with: so a capture run unattended needs no
                          secret key on the machine
  init DIR                make an empty repository at DIR: captures into it (-o
                          DIR) are kept as snapshots, each file's content
                          stored once, and only what changed is read
  snapshots REPO          list the snapshots in a repository, oldest first;
                          REPO::NAME names one wherever an image can be named,
                          and REPO alone its newest
  prune REPO              drop the snapshots --keep-last, --keep-daily,
                          --keep-weekly, --keep-monthly and --keep-yearly do
                          not keep, and the content nothing left refers to
  repack REPO             write again each pack an older restate wrote, which
                          can be read only from its start, so that a restore of
                          a few files reads only the parts of each pack that
                          hold them; every snapshot is kept, and what none of
                          them needs is dropped on the way
  protect REPO            run as root on the storage a repository is on, after
                          each capture: make every finished pack and snapshot
                          root's and read-only -- on Linux, immutable too, and
                          the repository append-only; elsewhere its directories
                          sticky, or with NFSv4 ACLs given an ACL that says the
                          same -- so the machines that capture into it can add
                          snapshots but change or remove none that are there
  check REPO              check a repository: read every pack through, each
                          chunk against the digest its index gives, and check
                          that every snapshot's index and kit can be read and
                          the content of each of its files is whole; with
                          --read-all, read every snapshot in full too
  copy SNAPSHOT DEST      copy a snapshot, and the packs it needs that DEST has
                          not got, to the repository DEST -- made if it is not
                          there -- exactly as they are: an encrypted
                          repository's copy is encrypted, and nothing is
                          decrypted
  du REPO                 say how much a repository holds, what each snapshot
                          needs of it, adds to it and would free if it were
                          dropped, and which keys an encrypted one's files are
                          encrypted to, without reading any pack or needing any
                          key
  export SNAPSHOT         write a snapshot as an image (-o FILE.tar) to take
                          elsewhere, encrypted and signed if asked
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
  baseline [fetch] [IMAGE]
                          list the exact packages this machine, or the one
                          IMAGE was taken from, had installed; with fetch,
                          download each at its version, checked against its
                          repository's signed index, into a cache that restore
                          --packages installs from
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
  run JOBFILE             run the job JOBFILE describes -- a capture, prune,
                          check, copy, restore and the rest, with its options
                          -- from a file only its owner can change (see JOBS)
  features                list what this restate can do: its commands, options,
                          job keys, result schema and the hooks here, for a
                          program to check before it asks for any of them

Options:
  -r, --root=DIR          treat DIR as the root of the tree to scan, verify, or
                          list the packages of (default /)
  -o, --output=FILE       write to FILE instead of standard output; created
                          mode 0600, replaced atomically. capture: FILE may be
                          a repository (restate init), which the capture adds a
                          snapshot to
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
                          capture, export: encrypt the image to the OpenPGP
                          public key in KEYFILE (gpg --export); repeatable, for
                          more than one recipient. init: make the repository an
                          encrypted one; capture and prune then need the keys
                          again, each time
      --sign-with=KEYFILE
                          capture, sign, export: sign the image or snapshot
                          with the OpenPGP secret key in KEYFILE (gpg
                          --export-secret-keys)
      --decrypt-with=KEYFILE
                          decrypt with the OpenPGP secret key in KEYFILE (gpg
                          --export-secret-keys), imported into a GnuPG home
                          made for the run and removed after, rather than with
                          this user's own; repeatable, for snapshots encrypted
                          to different keys (see ENCRYPTION)
      --trusted-key=KEYFILE
                          restore, verify, diff, status, list, export: accept
                          an image or snapshot only if it is signed by the
                          OpenPGP public key in KEYFILE (gpg --export);
                          autoinstall: have the restore check that; repeatable
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
      --quiesce-with=NAME
                          capture: also run the hook NAME
                          (/etc/restate/hooks.d/NAME, or one restate ships,
                          such as unifi or nextcloud) around the walk, pausing
                          what it names whether or not it is found running;
                          repeatable (see LIVE SERVICES)
      --append-only       capture: into a repository only by adding files,
                          never changing one already there; refused where that
                          cannot be done (see STORAGE)
      --create            capture: make -o a repository first if it is not one
                          -- a directory not there yet (its parent must be), or
                          an empty one -- as restate init would, encrypted with
                          --encrypt-to; one with anything else in it is
                          refused, and nothing is written
      --syslog            capture, prune, repack, check, copy: say how the run
                          ended in the system log too, as one line of key=value
                          pairs a monitoring system can match on
      --result=FILE       when the command ends, write how it ended and what it
                          did into FILE as one JSON object, replaced atomically
                          (see RESULTS)
      --group=GROUP       protect: the group the machines that write to the
                          repository are in, as the share maps them (default:
                          the group of the repository's directory)
      --report-group=GROUP
                          make the --result and --progress-file files readable
                          by GROUP too (0640), so a monitoring program that is
                          not root can read them
      --json              snapshots, diff, verify, status, list, du, estimate,
                          features: write JSON rather than text (see RESULTS)
      --fetch-sources     capture, packages: also fetch each apt source's index
                          as its repository serves it now (with curl), and
                          check that against the source's keys
  -x, --one-file-system   record mount points but do not descend into other
                          filesystems
  -n, --no-hash           record metadata only; much faster, but content is
                          then judged by size and mtime
      --cache=DIR         installer fetch, baseline fetch: keep what is
                          downloaded in DIR rather than the system's cache;
                          restore --packages: take packages from there
      --mirror=URL        installer fetch: download from the directory at URL
                          (https:// or file://) rather than the vendor's
      --target=KIND       buildsheet, autoinstall: rebuild as a virtual machine
                          (vm) or on other hardware (metal) rather than the
                          same machine
      --firmware=MODE     buildsheet, autoinstall, with --target: boot the
                          rebuilt machine by UEFI (uefi) or BIOS (bios) rather
                          than as the old one did, with the partition that
                          needs
      --exact-versions    buildsheet, autoinstall, restore --packages: each
                          package at the version recorded, from the archive's
                          snapshot (snapshot.ubuntu.com, snapshot.debian.org)
                          where the archive has moved on, rather than the newer
                          one
      --image-at=PATH     autoinstall: where the installer will find the image
                          (a mounted disk or share); the file then installs the
                          packages and restores the files from it
      --clones=FILE       autoinstall: one file for the copies FILE lists, a
                          CSV of name, mac, serial, address, gateway and dns:
                          the installer finds the machine it is on in FILE by a
                          MAC address or disk serial, and installs that copy,
                          with its host name and network, and restores it with
                          --as (see COPIES)
      --include=PATTERN   restore: put back only what PATTERN matches (written
                          as in a rules file, everything beneath it too), and
                          the directories it is in; repeatable
      --exclude=PATTERN   restore: leave out PATTERN (written as in a rules
                          file, everything beneath it too); repeatable
      --as=NAME           restore: put the image back as a copy of its machine
                          with an identity of its own, named NAME: the image's
                          identity (machine-id, SSH host keys, node keys and
                          the rest the rules class as identity) is left out,
                          the machine's own is kept where it has one, and where
                          what it has is the image's own, a new one is made or
                          the old removed for its service to make anew; NAME
                          becomes the host name (see COPIES)
      --numeric-owner     restore: owners by the numbers the index records, and
                          the image's own account files, rather than by name
                          through the image's accounts merged with the system's
      --image-fstab       restore: put back the image's /etc/fstab and
                          /etc/crypttab even where they name disks this machine
                          does not have; by default the machine's own are kept
                          then, so that it still boots
      --offline           restore --packages: with no network at all -- every
                          apt package from the baseline cache (restate baseline
                          fetch) and the image's kept .deb files, which apt is
                          given as its only repository; snaps, flatpaks and the
                          Python, npm and Ruby packages are left out, but for
                          the snaps the image keeps
      --packages          diff: say which packages were installed, removed and
                          upgraded, and leave out the file changes they account
                          for. restore: put the image's packages back first --
                          its repositories and keys, its packages at their
                          versions (from the baseline cache where fetched),
                          what was installed by hand and what as a dependency
                          -- and remove what it did not have; root only, onto
                          the running system
      --check-first       restore: read the whole image first, checking every
                          file against the index and writing nothing, and put
                          it back only if all of it is whole
      --dry-run           restore: check the image and say what would be put
                          back, writing nothing; prune: say which snapshots
                          would be dropped, dropping none; repack: say how many
                          packs would be written again
      --plan              restore: say what would be put back from the index
                          alone, writing nothing and reading no file's content
                          -- a dry run that checks nothing, in seconds
      --read-all          check: read every snapshot in full as well, as
                          restore would, each file checked against its index
                          and nothing written: a test restore of every snapshot
      --metadata-only     check: read no index, so that no key is needed: each
                          pack against the digest written beside it, and each
                          snapshot's files and the packs it lists (see STORAGE)
      --record=FILE       check: compare the repository with what FILE says it
                          held at the last check, saying what has been removed
                          or changed since, then record it as it is now; prune
                          and repack: record what they removed and wrote (see
                          STORAGE)
      --whole-packs       prune: read no index, so that no key is needed:
                          remove only the packs no snapshot kept lists as
                          needing, whole (see STORAGE)
      --keep-last=N       prune: keep the newest N snapshots
      --keep-daily=N      prune: keep the newest snapshot of each of the last N
                          days that have one
      --keep-weekly=N     prune: keep the newest snapshot of each of the last N
                          weeks that have one
      --keep-monthly=N    prune: keep the newest snapshot of each of the last N
                          months that have one
      --keep-yearly=N     prune: keep the newest snapshot of each of the last N
                          years that have one
  -P, --progress[=json]   show progress on standard error: paths and bytes so
                          far while walking, a percentage and time left while
                          writing an image or downloading; with =json, as one
                          JSON object a line (see PROGRESS)
      --progress-file=FILE
                          write progress into FILE as it goes, one JSON object
                          a line (see PROGRESS)
      --tmpdir=DIR        capture, export: stage the image being written in DIR
                          rather than beside it, so an image written to a
                          network share is not staged there (see STORAGE)
      --passphrase-fd=N   read the passphrase of the secret key --sign-with or
                          --decrypt-with gives, or that decrypts, from file
                          descriptor N rather than asking for it (see
                          ENCRYPTION)
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

For a program watching rather than a person, `--progress=json` writes the
same on standard error as one JSON object a line, and `--progress-file FILE`
into a file: a line at each change of phase and every two seconds between.

```json
{"phase": "walk", "paths": 8123, "read_bytes": 1048576, "new_bytes": 4096, "total_bytes": 9437184, "hook": null, "at": "2026-10-20T03:00:02Z"}
```

The phases are `count`, `walk`, `write`, `check`, `copy` and `read`; `hook`
while a hook pauses something, which it names; and `finish` at the end.
`read_bytes` is what has been read of the files themselves, never what
restate writes or reads back of its own. `total_bytes` is `null` where there
is no total; in the walk it is what the count found to read, so it is an
estimate: a file that grows, or appears, after the count is read all the
same. Show a percentage of it no higher than 99 until `finish`.

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
`RESTATE_UID`, `RESTATE_USER`, `RESTATE_PATHS`, `RESTATE_DUMP_DIR` and
`RESTATE_QUIESCE` (`yes` for a capture with `--quiesce`, else `no`) in its
environment. It is also asked `HOOK present NAME`, which only looks and
prints `present` or `absent`: whether what it pauses is on this host. Every
shipped hook answers; one that prints neither is taken to be present. The shipped database hooks dump into `RESTATE_DUMP_DIR` (which
goes into the image beside the files) and stop the service; the others
suspend the VM, freeze the container or pause Docker's containers. The
PostgreSQL hook stops the units listed in `/etc/restate/also.d/postgresql`
first -- services that write to the database -- and starts them after. To
change a hook, copy it to `/etc/restate/hooks.d` and edit the copy. A hook
that fails to pause or to resume makes the capture incomplete (exit status 3),
and its result says which.

What `/proc` does not show as one of these is named instead:
`--quiesce-with NAME` runs the hook `NAME` whether or not anything is found.
It is asked first, as `HOOK paths NAME`, which paths it covers, and those are
copied while it is paused; a hook that names none is paused for the whole
walk. One that answers `absent` to `HOOK present NAME` is not run, with a
notice, so one policy can name it for every host. Anything found running whose
files all lie within the paths it covers is its to pause, not the hook for its
kind's: UniFi's own `mongod` is paused by the `unifi` hook, never by `mongodb`.
Two are shipped for this:

- **`unifi`** -- the UniFi Network application runs a MongoDB of its own,
  started by its own service, which the `mongodb` hook cannot pause. This one
  dumps it (`mongodump --port 27117`, where installed) and stops `unifi` while
  `/var/lib/unifi` is copied: that MongoDB is not a replica set, so a dump
  taken while it runs is not of one moment, and the stopped copy is the one
  that restores reliably. Only the controller is down meanwhile; the access
  points and switches go on forwarding. UniFi's own backups,
  `/var/lib/unifi/backup/autobackup/*.unf`, are in the capture too, and
  restore onto a new UniFi without restate.
- **`nextcloud`** -- maintenance mode on, while Nextcloud's own directory and
  its data directory are copied. It is found as the snap (`nextcloud.occ`) or
  as the first directory holding `occ` and `config/config.php` beneath
  `/var/www`, `/usr/local/www` or `/srv/www`, and `occ` runs as the owner of
  `config/config.php`. Capture with both `--quiesce` and `--quiesce-with
  nextcloud` (in a job, `quiesce = true` and `quiesce_with = nextcloud`):
  `--quiesce` pauses its MySQL, MariaDB or PostgreSQL with that database's
  own hook, and without it the hook warns that the database is copied as it
  runs. The snap's database is its own, and is dumped
  (`nextcloud.mysqldump`) while in maintenance mode.

```bash
sudo restate capture --quiesce --quiesce-with nextcloud -o /mnt/nas/restate/cloud01
```

A Maildir needs neither: every message is its own file, written beside its
name and renamed into place, so a copy taken while mail arrives misses at
most what arrived meanwhile.

**A hook for any program.** With `--quiesce`, a program running that is none
of the kinds above, and has a hook of its own name in `/etc/restate/hooks.d`
-- `/etc/restate/hooks.d/minio` for `/usr/local/bin/minio` -- is paused by it
as one `--quiesce-with` names would be, without naming it: each machine's
`hooks.d` decides, and the job is the same everywhere. The name is that of
the file it runs (`/proc/PID/exe`), not the one it gives itself, which any
user can choose; and that file and its directory have to be root's and
writable by no one else, or any user could run a copy named for a hook to
have root pause the real thing. Only `hooks.d` is looked in, never the hooks
restate ships, and a kind's name or a shipped hook's is never taken for a
program's: the `docker` command is not `dockerd`.

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
  newer version replaced it -- with where the newer one is, and when this one
  was installed, which is when the archive's snapshot has it) or `"local"`
  (installed from a `.deb`, and only that file puts it back).
- **snap:** revision, channel and confinement (channels need root); snaps
  installed from a file are marked `"local"`.
- **flatpak:** remotes and apps, system-wide and per user.
- **pip, npm, cargo, pipx, gems:** what was installed outside any project,
  system-wide and in each home.
- **The other systems' package managers:** rpm (on the running system, as
  `rpm` says), pacman, apk, FreeBSD's pkg (on the running system, as `pkg`
  says), OpenBSD's packages and pkgsrc -- each package's name and version,
  and, where the manager says, whether it was asked for or came as what
  another needs (`"automatic": true`), which a rebuild need not ask for.
- **Homebrew, conda, Nix and Guix:** Homebrew's formulae and casks, conda's
  packages in each environment, and what each Nix and Guix profile holds --
  the default, each user's and each home's.
- **macOS's installer receipts**, by package ID.
- **Alternatives** chosen by hand (`update-alternatives --set`).

Every apt source is **checked**, too, as apt checks it: its index as apt last
fetched it, against the keys the source names, with `gpgv`, and its
`Valid-Until` against the clock -- a PPA whose key is written into its own
`.sources` file included. apt refuses a source whose key has gone,
changed or expired once, in an `apt update` nobody reads, and then quietly
uses the last index it accepted -- for months. A rebuild installs from the
source as it is now and gets nothing from it. A source apt cannot use gets a
`"problem"` in the inventory, and `capture` warns:

```console
restate: warning: apt cannot use a source in /etc/apt/sources.list.d/hashicorp.sources -- https://apt.releases.hashicorp.com resolute: signed by a key that is not given (ID FC9CA96ACA026560); a rebuild will not install from it until that is put right
```

That is the index apt has. With `--fetch-sources`, each source that passes is
fetched again as its repository serves it now (`curl`; plain http too, since
what is fetched is checked by its signature, not its transport) and checked
the same way -- so a vendor that moved to a new key since the last
`apt update`, or a repository that has gone, is caught before a rebuild finds
out:

```console
restate: warning: apt cannot use a source in /etc/apt/sources.list.d/vendor.sources -- https://apt.example.com/deb stable: as its repository serves it now, signed by a key that is not given (ID 4A3B...)
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
the newer one, or, with `--exact-versions`, this one from the archive's
snapshot as of when it was installed.

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

## The package baseline

A rebuild months from now finds many of today's versions gone: the archive
moves on, and a vendor that keeps only its newest release drops the rest.
`restate baseline` lists the exact packages a machine has -- or the one an
image was taken from -- and `restate baseline fetch` downloads each at its
version, as a `.deb`, into `/var/cache/restate/baseline`, where `restore
--packages` installs from:

```console
$ sudo restate baseline fetch --trusted-key backup-signing.pub web01.tar
restate: checking https://archive.ubuntu.com/ubuntu/dists/resolute-updates/
restate: checking https://dl.google.com/linux/chrome-stable/deb/dists/stable/
restate: checking https://snapshot.ubuntu.com/ubuntu/20260901T000000Z/dists/resolute-updates/
restate: 3180 packages in the baseline: 3180 fetched (2914238105 bytes, 25 of them from an archive's snapshot), 0 already in /var/cache/restate/baseline; 0 could not be had
restate: 5 were installed from .deb files no repository has: only an image can keep those (capture --keep-local-packages)
```

Nothing fetched is taken on trust, and nothing comes from a cache that is not
root's alone. Each repository's index -- `InRelease`, or `Release` and
`Release.gpg` -- is checked with `gpgv` against the keys its source names, as
apt checks it, and only the part the signature covers is read; each
`Packages` list against the index's SHA-256 for it; each `.deb` against the
list's SHA-256 for it, before it is renamed into the cache. A version the
archive no longer has is looked for in its snapshot -- as of the capture, or,
for one the archive had already moved on from, as of when it was installed --
on snapshot.ubuntu.com and snapshot.debian.org, signed by the same keys.
Fetching an image's packages is held to restore's rule: the image has to be
signed by a `--trusted-key`, or the fetch given `--allow-unverified`, since
what it fetches is installed as root. Run again, a fetch checks what the
cache has and downloads only what is missing or does not match.

A repository that wants a login -- Ubuntu Pro's, `esm.ubuntu.com` -- gets the
one apt has, from `/etc/apt/auth.conf` and `auth.conf.d`, so the fetch has to
run as root. curl is given only the entries for hosts the sources reach over
HTTPS and never over plain HTTP, in a file of its own that is gone when the
fetch is.

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
any no repository has. One installed already at a newer version than the one
recorded -- a security update since the capture, or the installer's own -- is
left at it: taking it back would have apt take back, or remove, whatever
needs the newer one. With `--exact-versions`, a version the archive has
moved on from comes from the archive's snapshot as of the capture instead
(`apt-get --snapshot`: snapshot.ubuntu.com and snapshot.debian.org), where
apt can reach one -- the machine as it was, rather than with the security
updates since, which is why it is not the default. Then the kept `.deb` files, the snaps by
channel, the flatpak apps, what pip, npm, pipx, cargo and gem installed, the
packages asked for of the other systems' managers (`pkg install`, `pkg_add`,
`pkgin`, `dnf`, `pacman`, `apk`, `brew`, `nix profile`, `guix`, and conda
in each environment), and the alternatives chosen by hand. The packages no repository has are listed
with what to do about them.

`restate autoinstall` writes the same layout as an Ubuntu autoinstall file for
an unattended reinstall, with the locale, keyboard, time zone, host name,
network and SSH server. LUKS passphrases and the first account's password are
left as `CHANGE-ME`.

Another operating system's partitions -- Windows, BitLocker, macOS, VeraCrypt
-- are never formatted. For the same machine, both keep them, and the EFI
partition they boot from, in place.

`--firmware uefi` or `--firmware bios`, with either target, changes how the
rebuilt machine boots: the partition the new mode needs replaces the old
one's on the disk it boots from -- an EFI system partition (512 MiB, mounted
at `/boot/efi`) in place of GRUB's BIOS boot partition, or added in front on
an MBR disk; or a BIOS boot partition in place of the ESP, which an MBR disk
does without -- and the installer puts in the boot loader for that mode.

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
$ restate buildsheet --target metal --firmware uefi old-bios-box.tar -o new-box.txt
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

A file already in place as the image has it -- the same size and
modification time, the same names (a hard-linked file has to have all of the
image's names for it, and no others), and content that hashes to the index's
digest -- is not written again, only given its owner, mode, attributes and
times. A restore run again, or onto a machine that has most of its files
already, then needs no room beside a large file for a second copy and none
of the time to write one.

`/etc/fstab` and `/etc/crypttab` name disks. On the machine they came from,
or one the [build sheet](#rebuilding) laid out with the old UUIDs, every disk
they name is there. On a machine laid out afresh, by an installer, they name
the old machine's: it stops in emergency mode at the next boot, unable to
mount `/boot/efi`, and the next initramfs takes in a crypttab that unlocks
nothing. So when the image's (as its machine description records them) name a
disk this machine does not have -- leaving out what is marked `noauto` or
`nofail`, and what names no disk -- and the root has its own, the root's own
are kept, and restore says which disks were missing. `--image-fstab` puts the
image's back all the same, for when the disks are about to be made to match.

Owners are restored by name. A rebuilt machine's packages numbered their own
users as they went in (postgres may be 128 where it was 125), so the image's
`/etc/passwd`, `/etc/group` and shadows are merged with the new system's
rather than laid over them -- both systems' users, the new numbers where both
have one, the old passwords, homes and shells -- and every file's owner is
mapped through them by name. `--numeric-owner` restores the recorded numbers
instead.

```console
$ sudo restate restore --dry-run web01.tar            # check it all, write nothing
$ sudo restate restore --check-first web01.tar        # check it all, then put it back
$ sudo restate restore --plan --include '/home/bob/**' /mnt/nas/restate/web01
$ sudo restate restore --exclude /etc/fstab web01.tar
$ sudo restate restore --root /target web01.tar       # from an installer
```

A file that does not match its digest is never put in place, but by itself
that leaves a damaged image restored as far as it is whole. `--check-first`
reads the whole image once before writing anything, checking every file, and
refuses it -- exit status 2, nothing written -- if any file is not what the
index says or is missing; then it reads it again to put it back. It costs a
second read, so it is not the default.

`--plan` says what a restore would put back from the index alone -- every
path, how many files and how large -- reading no file's content and writing
nothing, so it takes seconds however large the image is. It checks nothing,
and its result says so (`"content_read": false`); `--dry-run` is the check.
From a repository, `--include` reads only the packs that hold what it
covers, for a restore and a dry run alike: one directory back from a large
snapshot is as quick as that directory is small.

**The packages too.** On a fresh install, `restore --packages` puts the old
machine's packages back before its files, as root, onto the running system:
the image's `/etc/apt` -- its repositories, and the keys kept there -- and the
keys kept elsewhere; every package installed by hand, at its version where a
repository still has it (from the archive's snapshot, with
`--exact-versions`), and from the [baseline](#the-package-baseline) where
none does; the `.deb` files the image kept; the holds; each package marked
installed by hand or as a dependency, as it was. What the old machine did not
have is marked a dependency, so `apt-get autoremove` takes away what nothing
it had needs -- never the kernel, the boot loader, firmware, microcode or a
virtual machine's guest tools (qemu-guest-agent, open-vm-tools and the like),
which follow the hardware. Then the snaps, flatpaks, the Python, npm and Ruby
packages installed system-wide, and the alternatives chosen by hand. It is
all done by a shell script, as a person would do it; `--dry-run` writes the
script out instead of running it, to read first:

```console
$ sudo restate restore --packages --dry-run -o packages.sh --trusted-key backup.pub web01.tar
$ sudo restate restore --packages --trusted-key backup.pub web01.tar
```

**With no network at all**, `restore --packages --offline` installs every apt
package from the [baseline](#the-package-baseline) and the `.deb` files the
image kept, and from nothing else. Fetch the baseline while there is a
network, carry the image and `/var/cache/restate/baseline` across with the
installer, and restore on the far side:

```console
$ sudo restate baseline fetch --trusted-key backup.pub web01.tar     # connected
$ sudo restate restore --packages --offline --trusted-key backup.pub web01.tar
restate: offline: 3180 of the image's 3180 packages from repositories are in /var/cache/restate/baseline; the 5 installed from .deb files come from the image where it keeps them
restate: offline: apt installs from 3185 packages, and nothing else
```

apt is given one repository in place of every source it has: one the script
makes in a directory of its own, of the baseline's packages and the kept
ones, indexed there from each package's own fields with `dpkg-deb`, and with
lists of its own, so nothing is fetched and the system's lists are left as
they were. The repository is unsigned and marked trusted: its packages are
the ones `baseline fetch` checked against their vendors' signed indexes, in a
cache only root can write, and the kept ones are from the image's kit,
checked against its index. Every package is at the version recorded, so
`--exact-versions` has nothing to add, and is refused with it. Snaps,
flatpaks and the Python, npm and Ruby packages come from stores on the
network, so they are left out and said to be -- but for a snap the image
keeps, which is installed from its file.

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

## Copies

One image can be put back as many machines — a lab, a classroom, a test of
how a service scales — as long as each is made a machine of its own rather
than one more of the same. Some of a machine's state is what other machines
know it by: its machine-id (from which systemd-networkd and NetworkManager
make the DHCP client ID, so copies that share one can be handed the same
address), its SSH host keys, its host name, cloud-init's instance, DHCP
leases, Tailscale and WireGuard keys, node certificates (kubelet, k3s, LXD,
Incus, Puppet, Salt, Chef), MySQL's `server_uuid`, the Ubuntu Pro machine
token, monitoring agents' IDs, the SysManage agent's included. The rules
class it as **identity**. A capture keeps it, and an ordinary restore puts
it back, so the same machine comes back as itself.

`restate restore --as NAME` leaves the image's identity out instead, and then
makes sure the machine has one of its own:

- where the machine has its own — a fresh install made a machine-id, host
  keys and the rest as it installed — that one is kept;
- where what it has is the image's very own — the restore is onto the
  machine the image was taken from, or onto a copy of its disk — a new one is
  made where restate knows how (the machine-id and D-Bus's copy of it, the
  random seed, and the SSH host keys with `ssh-keygen -A` where it has an SSH
  server), and otherwise the
  image's is removed, for its service to make anew when it next starts;
- and `NAME` is the host name, in `/etc/hostname` and wherever `/etc/hosts`
  gave the image's.

```console
$ sudo restate restore --packages --as lab-07 --trusted-key backup-signing.pub lab.tar
...
restate: as lab-07: left out the image's identity (31 paths); 6 of this machine's own kept, 1 made new, 2 of the image's own removed for their services to make anew
restate: as lab-07: the host name is now lab-07, in /etc/hosts too
restate: as lab-07: reboot, for every service to take up the new identity
```

Which paths are identity is decided by the rules for the system the image
came from, as well as by the image, so one captured before the class existed
is read as if it had it; an `identity PATTERN` line in a `--rules` file adds
a site's own. Two things restate cannot make new: a WireGuard key has to be
made known to the peers, so a copy has none until it is given one, and a
PostgreSQL cluster's system identifier is fixed when the cluster is made
(it matters only to replication).

`restate autoinstall --clones FILE` writes **one** autoinstall file for every
copy `FILE` lists:

```
# lab.csv
name,mac,serial,address,gateway,dns
lab-01,52:54:00:12:34:01,,10.0.0.11/24,10.0.0.1,10.0.0.2
lab-02,52:54:00:12:34:02,,10.0.0.12/24,10.0.0.1,10.0.0.2
lab-03,,S4EWNX0R123456,,,
```

Each copy has a host name and a MAC address or disk serial (as `lsblk` shows
it) to find the machine by; an address with its prefix length, a gateway and
name servers are optional, and a copy without an address takes DHCP. Every
machine boots the same installer with the same file: its early-command finds
which copy the machine is, writes that copy's configuration — the same as
the others' but for its host name and network — where the installer reads
it again, and a machine that is none of them stops before anything is
written. With `--image-at`, the late-commands restore the image with `--as`
the copy's name, keeping the network the installer gave it.

## Repositories

An image holds everything it keeps, so a capture every night writes the whole
machine every night. A repository keeps captures as snapshots instead, each
piece of content stored once:

```console
$ sudo restate init /var/backups/web01
$ sudo restate capture -o /var/backups/web01
restate: snapshot /var/backups/web01::20261011T030000Z: 156.2 GiB new to the repository, from 455634 files; 0 files unchanged since the last snapshot were not read
$ sudo restate capture -o /var/backups/web01
restate: snapshot /var/backups/web01::20261012T030000Z: 412.0 MiB new to the repository, from 1203 files; 454431 files unchanged since the last snapshot were not read
$ restate snapshots /var/backups/web01
20261011T030000Z  web01  455634 files, 156.2 GiB; 156.2 GiB new
20261012T030000Z  web01  455640 files, 156.3 GiB; 412.0 MiB new
```

**Only what changed is read.** A file whose size, modification time,
change time and inode are what the last snapshot recorded is taken to be
unchanged, as `git status` and `rsync` take it, and is not read at all; its
digest comes from the last snapshot. So the first capture takes as long as an
image does and the ones after it as long as what changed.

**Only what changed is stored.** Files are cut into chunks where their
content says to -- a rolling hash over the bytes, cut where it meets a
pattern, so chunks average a mebibyte and an insertion moves only the cuts
near it -- and a chunk is stored only if the repository does not have it
already. A VM's disk that changed a few blocks overnight costs the chunks
around them, not the whole disk again; a copy of a file, or one that changed
and changed back, costs nothing. A file smaller than a quarter of a mebibyte
is one chunk.

**A snapshot is named `REPO::NAME`**, or `REPO` alone for the newest, and
everything that reads an image reads one: `restore`, `verify`, `diff`,
`status`, `list`, `packages`, `installer` and `sign`. `export` writes one out as an
image, to take elsewhere -- encrypted with `--encrypt-to` and signed with
`--sign-with` -- and to make a build sheet or an autoinstall file from, since
the commands they write unpack an image's file:

```console
$ sudo restate restore --trusted-key backup-signing.pub --root /target /var/backups/web01
$ restate diff /var/backups/web01::20261011T030000Z /var/backups/web01
$ restate export --encrypt-to offsite.pub /var/backups/web01 -o web01-20261012.tar
```

**`status`** says what has changed since a snapshot (or an image), quickly:
`verify`'s comparison, but reading only the files whose size, times or inode
say they changed.

Both classify the tree by the rules the capture was made with, which the
index records -- the built-in ones it ran with and every `--rules` file --
so a path the capture left out on purpose is not reported as added.
`--rules`, `--no-default-rules` or `--os` classify by those instead, and
`--all`, `--one-file-system` and `--rules-only` add to what was recorded. An
index from a restate before this one records no rules, and is classified by
the options alone, as it always was.

**`list`** says what is directly in one directory of a snapshot -- each
name's type, mode, owner, size and time, and a symlink's target -- from its
index alone, reading no pack: to look through what a snapshot holds and pick
what to restore.

```console
$ restate list /var/backups/web01 /etc/nginx
d 0755 root     root                0 2026-10-11T09:12:40.118362511Z  conf.d
f 0644 root     root             1447 2026-10-11T09:12:40.118362511Z  nginx.conf
l 0777 root     root               34 2026-10-11T09:12:40.122362530Z  sites-enabled -> /etc/nginx/sites-available
```

**`prune`** drops the snapshots it is not told to keep -- the newest
`--keep-last N`, and the newest of each of the last `--keep-daily N` days,
`--keep-weekly N` ISO weeks, `--keep-monthly N` months and `--keep-yearly N`
years that have one -- then the chunks no snapshot left needs, rewriting a
pack that is a quarter or more dead. `--dry-run` says which it would drop. A
prune that SIGTERM, SIGINT, SIGHUP or SIGQUIT asks to stop does so between one
snapshot or pack and the next, within a second or so: it updates its
`--record` with what it removed, ends with status 3 (incomplete) and the
signal in its result's `errors`, and then lets the signal end it. The next prune finishes the job.

**`repack`** makes an older repository fast to restore a few files from. A
pack is one gzip file, and gzip reads only forward, so a pack written as one
gzip stream has to be read from its start to reach the last file in it: an
`--include` of a small directory spread over many packs reads most of each.
restate 2.0.0.8 and later begin a new gzip stream every two mebibytes or so,
at a file's boundary, and write a `.seek` beside the pack saying where each
begins, so a restore reads only the stretch of each pack that holds what it
wants. (On a 57 GB repository over NFS, restoring `~/.config` read about
12 GB of packs the old way.) To `gzip`, and to
an older restate, such a pack is still one gzip file read from the start, and
`.seek` is trusted for nothing: what is read where it points is checked to be
the file it should be, and the pack is otherwise read from its start.
`restate repack REPO` writes again every pack an older restate wrote, keeping
every snapshot and dropping on the way what none of them needs, as prune
does; `--dry-run` says how many packs it would write, and a repack stopped by
a signal keeps what it wrote, for the next to go on from. An encrypted
repository's packs are encrypted whole, and gpg reads one only from its
start too, so they are written as before and repack refuses one.

```console
$ sudo restate repack --dry-run /mnt/nas/laptop
would write again 688 packs
$ sudo restate repack /mnt/nas/laptop
restate: wrote again 688 packs, and removed 0 that nothing needed, freeing 3.1 MiB
```

**`check`** reads the whole repository through, as `restic check
--read-data` does: every pack, every chunk checked against the digest its
pack's index gives (the repository's own index, not this machine's cached
copy), every snapshot's index and kit, and that the content of every file
each snapshot needs is whole. What is wrong is named, by pack and by file, and
the exit status is 3. Storage like ZFS finds bit rot; `check` finds a pack
that was written wrong, or a file someone removed. (`--metadata-only` checks
without reading any index, so without any key -- see [Storage on a file
server](#storage-on-a-file-server).) `--read-all` goes on to read
every snapshot in full exactly as a restore would, each file checked against
its index, writing nothing: a test restore of every snapshot. Run both on a
schedule, with `--syslog`:

```console
$ restate check --read-all /var/backups/web01
restate: read 214 packs (6.6 GiB, 9811 chunks checked against their digests): 0 damaged
restate: 30 snapshots, 13650213 files with content: 0 snapshots with something missing, 0 files not whole
restate: read 30 snapshots in full, as restore would: 13650213 files, 0 not as their indexes say
restate: the repository is whole
```

```text
30 4 * * 0   root  restate check --syslog /var/backups/web01
30 5 1 * *   root  restate check --read-all --syslog /var/backups/web01
```

**Run from cron.** One capture, prune or repack runs on a repository at a time (`protect`
takes no lock: it changes only what is finished), and
one `--quiesce` capture on a machine at a time: another that finds the lock
taken does nothing and exits with status 5, a reason to try later rather than
an alarm. `--syslog` puts one line in the system log as the run ends, for a
monitoring system to match on:

```console
restate[48211]: restate capture: status=ok exit=0 seconds=812 output=/var/backups/web01::20261012T030000Z paths=821158 kept=455640 read=2254857216 reused=454431 unreadable=0
```

### Encrypted repositories

`restate init --encrypt-to KEYFILE` makes a repository whose content, the
indexes of what is in it and every snapshot's files are encrypted to the
OpenPGP public keys given -- gpg after gzip, as an encrypted image's parts
are -- so it can live on a NAS, a USB drive or a server you do not trust.
The keys are given again on every capture and prune, and never read from the
repository, where whoever holds the storage could put their own:

```console
$ sudo restate init --encrypt-to backup.pub /mnt/nas/web01
$ sudo restate capture --encrypt-to backup.pub -o /mnt/nas/web01     # from cron
$ sudo restate restore --trusted-key backup-signing.pub /mnt/nas/web01   # needs the secret key
```

A capture needs no secret key, so one run from cron has none to give away. To
know what the repository holds already -- which chunks, and what the last
snapshot recorded, for an incremental run -- it keeps its own copy of what it
wrote in `/var/cache/restate/repositories/` (root's, mode 0700): plain text,
on the machine whose files it describes. A machine without that copy, or a
capture after another machine's, decrypts what it is missing if the secret
key is there, and otherwise stores again what it cannot see, rather than
guess. Restoring, verifying or exporting a snapshot needs the secret key, as
an encrypted image does. `prune` works from the same copy; rewriting a pack
needs the keys to encrypt to, so without `--encrypt-to` it only removes packs
nothing needs at all, and says how many it left. Encryption is not
authentication -- anyone with the public key can write a snapshot that
decrypts -- so sign snapshots, and restore with `--trusted-key`.

The secret key need not live in a GnuPG home on the machine at all.
`--decrypt-with KEYFILE` takes it as a file (`gpg --export-secret-keys`),
imported for the one run into a GnuPG home of restate's own -- in memory
where the system has a place for it, `/run` for root and `/dev/shm` for
anyone else on Linux, else `/tmp` -- and removed, gpg-agent there stopped,
when the run ends or a signal ends it:

```console
$ sudo restate restore --decrypt-with /run/keys/web01.sec /mnt/nas/web01
```

The one thing an encrypted chunk still shows is its size, and with the
boundaries any repository uses, chunk sizes would say which known files a
repository holds. So an encrypted repository cuts its chunks where a key of
its own says: made at the first capture, kept in the repository encrypted to
its keys, and in the machine's cache, where a capture reads it without the
secret key. A machine with neither makes a key of its own, and stores its
large files whole once more. A capture -- `--append-only` too -- that finds
the newest copy sealed to keys other than the ones it is given adds a copy
sealed to its own, `chunk-key.TIME-N`, beside the others; every prune, keyless
and `--whole-packs` included, removes all but the newest, so a retired key
is not needed for it once a prune has run.

**Changing keys.** Give the new public key alone to `--encrypt-to` from then
on: new snapshots are encrypted to it, and the old ones stay encrypted to the
old key, so restoring one takes the old secret key too (`--decrypt-with`, once
for each key). `du` says, with no key at all, which keys the repository's
files are still encrypted to -- read from the session keys at the head of each
file, which name them in the clear -- and a key it no longer names can be
retired:

```console
$ restate du /srv/restate/web01
...
encrypted to 3F2A9C0D81B4E7A6: 412 packs 13 GiB, 30 snapshots
encrypted to C81D05E9F3A2B740: 37 packs 1.1 GiB, 6 snapshots, the chunking key
```

A prune that rewrites a pack needs the secret key that pack was encrypted to,
and writes what it keeps encrypted to the keys it is given; `--whole-packs`
needs no key, and removes only packs nothing needs.

A key given with `--decrypt-with` is imported into a GnuPG home of restate's
own, and libgcrypt 1.12.0 (Ubuntu 26.04's) cannot use an imported cv25519
key -- the default kind -- reliably ([GnuPG T8094](https://dev.gnupg.org/T8094),
fixed in 1.12.1), nor can GnuPG 2.5 with libgcrypt 1.12. restate tries each key
once before it starts and says so if it cannot. An RSA encryption key has
neither problem: `gpg --quick-gen-key NAME rsa3072 cert`, then `gpg
--quick-add-key FINGERPRINT rsa3072 encr`.

On disk a repository is plain files: `packs/` holds the chunks, in gzip'd tar
files of about 32 MiB each beside an index of what is in them, a `.sum`
of the file as written and (but in an encrypted repository) a `.seek` of
where each gzip stream in it begins, and each of `snapshots/` holds a capture's index, its
kit's list, a summary, the list of packs it needs and, if it is signed, the
signature. Everything is written beside its final name and
renamed into place, the snapshot last, so an interrupted capture leaves
nothing that looks finished; `prune` clears what it left. A repository made
by restate 1.3.0, whose packs hold whole files, is read as it is, and the
first capture or prune into it makes it the current kind.

## Storage on a file server

A repository can live on a NAS that each machine mounts over NFS or SMB --
one directory per machine -- and restate opens no network connection of its
own to get there. What it needs of that storage, and what the storage can do
with it on its own:

```bash
# on web01, nightly: only ever adds files
sudo restate capture --append-only --encrypt-to backup.pub -o /mnt/nas/restate/web01

# on the NAS itself, against the same directory: no keys needed for any of it
restate check --metadata-only --record /var/lib/restate/web01.record /srv/restate/web01
restate prune --whole-packs --keep-daily 14 --keep-weekly 8 --record /var/lib/restate/web01.record /srv/restate/web01
restate copy /srv/restate/web01 /mnt/offsite/web01       # a second copy, still encrypted
restate du /srv/restate/web01
```

- **Locks hold between the machine and the NAS.** A capture or prune takes
  both a `flock(2)` and, on Linux, an open file description lock on the
  repository's `lock` file. An NFS client takes either on the server; on the
  server the two are different locks, and a prune run there sees a capture's
  NFS lock only as the second kind -- so restate takes both, and two writers,
  one over NFS and one on the NAS, exclude each other. (NFSv3 mounted
  `nolock` does not lock at all.) A FreeBSD server shows its own programs
  the locks NFS clients take only with `vfs.nfsd.enable_locallocks=1`, and a
  Linux client is told of a lock held on such a server as an I/O error:
  restate asks again twice, a second apart, and then exits 5 (busy), saying
  the connection may be failing if nothing on the server holds it. A
  filesystem with no record locks at all -- a FUSE one, as sshfs's and
  rclone's are -- gets `flock(2)` alone, which only the machine taking it
  sees: one writer at a time there. An SMB share Linux mounts gets the open
  file description lock alone, which its client takes on the server as a
  lock every other client sees.
- **Any filesystem will do.** Every name restate writes is letters, digits,
  `.`, `-` and `_`, short, never differing from another only in case and
  never a name Windows reserves, and every file is a plain file with one
  name; what was captured -- its paths and their case, owners, modes, times,
  symlinks and hard links -- is data inside the indexes. So a repository on
  exFAT, FAT, a USB disk or an SMB share that ignores case reads back bit for
  bit. CI holds it to that on exFAT, FAT and SMB, and `make test-share
  SHARE=DIR` does on whatever DIR is on.
- **Nothing needs to be root's.** A share that maps every user to one of its
  own (`all_squash`) works, as long as that user can write it. Run as root on
  the storage itself -- a prune, a repack or a check there -- restate gives
  every file and directory it makes the owner and group of the directory it
  makes it in, and that group's read where the directory gives its group
  read, so the machines the share maps to the repository's owner, or into its
  group, can still read the packs root wrote.
- **A capture only adds files.** Each pack, its index and `.sum`, and each
  snapshot are written under a name of their own and renamed to a name
  nothing had; nothing already there is changed. `--append-only` refuses the
  one exception, the marker of a repository made by restate 1.3 or older.
  That keeps an honest capture from changing anything; a machine that has
  been taken over is root, and has the share, so only the NAS can stop it --
  with `restate protect`, below, and a ZFS snapshot after each capture.
- **Protected on the NAS.** `restate protect REPO`, run as root on the NAS
  after each capture, makes every finished pack and snapshot root's and the
  repository's group's, and read-only (files 0440, each snapshot's directory
  0550), and the repository, `packs/` and `snapshots/` root's and the
  group's. On Linux they are 0770, with the repository append-only and every
  finished file and snapshot immutable (`chattr +a` and `+i`): the machines
  in the group make files there, and rename and remove what is not finished
  in `packs/` and `snapshots/`, but nothing at the top and nothing
  finished -- root included, until root clears the flag, which prune and
  repack do for what they remove. Only root sets them, so protect run as
  anyone else there, or on a filesystem without them, changes nothing and
  says so. Where the filesystem has NFSv4 ACLs (ZFS on FreeBSD) they are
  0770, with an ACL that says each machine removes only its own; anywhere
  else they are 1770, sticky, which says the same. Not sticky where it can be
  helped: a Linux NFS client with `fs.protected_regular=2` (Ubuntu's and
  systemd's default) refuses a file it has just made in a sticky directory
  that is neither its user's nor the directory owner's -- as every file is,
  in a share that maps every machine to one user -- after making it, so no
  capture could write. A machine that has been taken over can then add
  snapshots and read them, but not change, rename or remove one that is
  there. The marker, `lock` and `readers`, which a capture and a
  restore open as their own, are left as they are, and so is anything being
  written. Only what is not so already is changed, so it is quick after every
  capture; it takes no lock, follows no symlink, and refuses a file with a
  second name, which a machine could plant to have root give away a file
  elsewhere. The group is the repository directory's, or `--group`; root's
  is refused. Prune, repack and check, run as root on the NAS, go on as
  before. A snapshot cannot be signed once it is protected, so sign it as it
  is captured. `capture --create` works into an empty directory made ready
  for it -- root's and the group's, 0770 and append-only on Linux, 0770 with
  that ACL, or 1770 -- and leaves it so. `features --json` says
  `"protect_flags": true` where protect sets Linux's flags.

  ```bash
  # On the NAS, once: a directory for the machine to make its repository in.
  # On ZFS (FreeBSD), 0770 and the ACL protect gives it; on Linux, 0770 and
  # chattr +a /tank/restate/web01 in place of the setfacl lines; elsewhere,
  # 1770.
  install -d -o root -g restate -m 0770 /tank/restate/web01
  setfacl -a 0 group@:D::deny /tank/restate/web01
  setfacl -a 0 owner@:d:f:allow /tank/restate/web01
  setfacl -a 0 owner@:d:d:allow /tank/restate/web01
  setfacl -a 0 owner@:D::allow /tank/restate/web01
  # /etc/exports (FreeBSD): map every machine to the user AND the group, by
  # name -- with the user alone, the group's right to make files was refused.
  /tank/restate -mapall=restate:restate -network 10.0.0.0/24
  # After each capture:
  restate protect --syslog /tank/restate/web01
  ```
- **A machine can make its own repository.** `capture --create` (a job's
  `create = true`) makes the repository first where there is none: a
  directory not there yet, under a parent that is, or an empty one -- as
  `restate init` would, encrypted with `--encrypt-to`. It is the machine's
  own, so over a share that maps it to one user, that user owns it. A
  directory with anything else in it is refused, with nothing written; a
  repository already there is captured into as ever, and the result says
  which with `"created_repository"`.
- **Checked without the keys.** Each pack's `.sum` is the digest of its file
  as written, and each snapshot's `packs` file the packs it needs; neither
  is encrypted, and neither says anything of what is in them. `check
  --metadata-only` checks every pack against its `.sum`, and every snapshot's
  files and packs, and says it could not check inside them. `--record FILE`,
  kept on the NAS where the machine cannot reach it, finds a pack or
  snapshot removed or rewritten since the last check.
- **Pruned without the keys.** `prune --whole-packs` drops snapshots, then
  each pack no snapshot left lists, whole; a prune with the keys rewrites the
  packs that are only partly needed.
- **Copied without the keys.** `copy SNAPSHOT DEST` copies a snapshot and the
  packs it needs that `DEST` lacks, exactly as they are, so an encrypted
  repository's copy is encrypted.
- **Interrupted runs.** A capture cut off leaves only files that do not count
  yet -- a pack with no index, a snapshot directory under a temporary name.
  `check` reports them as left over, not as damage, and the next `prune`
  removes them. A prune stopped by a signal still updates its `--record`, so
  the next check does not take what it removed for tampering.
- **Images too.** `--tmpdir DIR` stages an image's content on the machine
  rather than beside the image on the share.

## Jobs

`restate run JOBFILE` runs what a file says -- which command, on what, with
which options -- so a scheduler or a fleet manager runs one fixed command and
never builds a command line. The file has to be root's (or the user's running
it) and writable by no one else, as must its directory; every key is one
restate knows, of one type, allowed only for the commands it means something
for, and nothing in it can name a program to run.

```ini
# /etc/restate/jobs.d/nightly.conf
command      = capture
repository   = /mnt/nas/restate/web01
quiesce      = true
quiesce_with = unifi
encrypt_to   = /etc/restate/keys/backup.asc
append_only  = true
create       = true
result       = /var/lib/restate/nightly.json
progress     = /var/lib/restate/nightly.progress
report_group = restate-report
```

A job can be a `capture`, `prune`, `check`, `copy`, `snapshots`, `restore`,
`estimate`, `du`, `repack`, `protect`, `status` or `list`; a `status` or `list`
job reads the newest snapshot unless `snapshot` names one, and a `list` job
lists the directory `path` says (`/` if it says none). A `status` job takes
`rules`, `all` and `one_file_system` as a capture does, though it seldom
needs them: it classifies by the capture's own rules unless given others.

Any job but `estimate` and `protect` can read what is encrypted, and takes
`decrypt_with`, the secret key as `--decrypt-with` takes it -- repeatable,
for a repository whose older snapshots are encrypted to a key since replaced
-- and `passphrase_file`, a file whose first line is the passphrase. Both
have to be regular files, root's (or the user's) and readable and writable by
no one else, in a directory only their owner can change. A program that keeps
the key elsewhere writes it there -- under `/run`, root's alone -- for the one
run, and removes it after; the job never needs a GnuPG home of its own.

A job refused -- a key restate does not know or the command has no use for,
a value of the wrong kind -- still writes its `result`, if it names one, as
a failed run's: `"status": "failed"`, exit 2, and why in `errors`. A job file
that is not safely owned is not read at all, so only the command line's
`--result` hears of that.

`restate-job@.service` runs `/etc/restate/jobs.d/NAME.conf` for the instance
`NAME` -- at a low priority and idle I/O, for up to a day, letting restate
resume what it paused if it is stopped -- and `restate-job@.timer` runs it
every night, at a time a little different on each machine:

```bash
sudo systemctl enable --now restate-job@nightly.timer
sudo systemctl start restate-job@nightly         # once, now
journalctl -u restate-job@nightly
```

The keys and the commands that take them are in `restate(8)`, under JOBS.

## Results, for programs

restate's messages are for people. A program reads its exit status -- which
does not change: 0 ok, 1 differences, 2 trouble, 3 incomplete, 4 not signed by
a trusted key, 5 busy -- and, given `--result FILE`, one JSON object written
into `FILE` when the run ends, replaced whole:

```json
{
  "schema": 1, "command": "capture", "status": "ok", "exit": 0,
  "started_at": "2026-10-20T03:00:00Z", "seconds": 812,
  "repository": "/mnt/nas/restate/web01", "created_repository": false,
  "snapshot": "/mnt/nas/restate/web01::20261020T030000Z",
  "paths": 821158, "kept": 455640, "read_bytes": 2254857216,
  "reused": 454431, "reused_bytes": 167503724544, "new_bytes": 431996928,
  "repository_bytes": 178241380352, "cache": null,
  "unreadable": {"count": 0, "first": []},
  "quiesce": [{"kind": "postgresql", "name": "18-main", "paused_at": "2026-10-20T03:12:40Z",
               "resumed_at": "2026-10-20T03:13:02Z", "status": "ok", "message": ""}],
  "warnings": [], "warnings_count": 0, "errors": [], "errors_count": 0
}
```

Every warning is collected, `--quiet` or not, every error -- so a run that
failed says why in its result, not only on standard error -- and every path a
walk could not read with why; prune, repack, protect, check, restore (its plan, in a dry run,
and `"content_read": false` for a `--plan`), copy, du, estimate and diff add
what they did. `diff`, `verify` and `status` give the first 1000 of each kind
of change -- added, deleted, modified -- in `diff.changes`, with
`diff.truncated` if there were more; `list` gives the first 5000 names in
`list.entries`, with `list.truncated`; and `verify`, `status` and `list` name
the `snapshot` they read (a repository's newest as `REPO::NAME`) or the
`image`, and say in `capture_rules` whether they classified by the rules the
capture recorded. A capture into an encrypted repository gives `"cache": {"path":
..., "bytes": ...}`, this machine's cache of it, and `"cache": null` into one
that is not. `--json` writes the output itself as JSON
for `snapshots`, `diff` (and `--packages`), `verify`, `status`, `list`, `du`,
`estimate` and `features`; `restate features --json` lists what this restate
can do -- commands, options, job keys, the commands a job can be and the keys
each takes (`job_command_keys`), schemas,
what results have gained since schema 1 began (`result_members`, such as
`capture.cache`), the hooks here (each hook is
asked `HOOK present NAME`, and one that answers `absent` is left out, so a
host lists only what it has) -- for a program to ask before it asks. The result and progress files are their
owner's alone unless `--report-group GROUP` makes them that group's to read
too. A later restate adds to all of this, and changes what something means
only with a new schema number.

`restate estimate` walks a machine reading no file and says how much a first
capture would keep, by directory -- what to exclude before a first backup
that would not fit.

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

Five classes: **ephemeral** (never recorded), **expendable** (recorded only
with `--all`), **baseline** (recorded with digests, not kept), **state**
(kept), and **identity**, state that must be unique to each machine (kept,
and left out by [`restore --as`](#copies)).

A rules file is `CLASS PATTERN` per line; the **last** matching rule wins, as
in `.gitignore`, and a rule covers the path it names and everything below it,
except a rule for `/` alone, which covers only the root directory itself
(restate warns of it): `/**` covers everything. The walk does not go into an
ephemeral or expendable directory except on the way to what a later rule
keeps below it, so `ephemeral /**` and then `state /srv/app/data` records
just that directory, and the directories on the way to it. A rule with no
leading `/`, or with `**` in its first component, never leads the walk in.
`*` matches within one component, `**` across components, `**/` zero or more
whole directories, and a pattern with no leading `/` matches at any depth.

Where a package manager restate reads manages the system, the rules are only
the start. Every regular file the rules call baseline or state is checked
against the digest its package manager recorded when it installed it:

| Package manager | What restate reads | Digest |
|---|---|---|
| dpkg | `/var/lib/dpkg/info/*.md5sums`, `status`'s conffiles, diversions | MD5 |
| rpm | `rpm -qa`, on the running system (its database is SQLite) | SHA-256, or MD5 from an old rpm |
| pacman | `/var/lib/pacman/local/*/mtree` | SHA-256 |
| apk | `/lib/apk/db/installed` | SHA-1 |
| FreeBSD's pkg | `pkg query`, on the running system (SQLite again) | SHA-256, or BLAKE2b from pkg 2.8 |
| OpenBSD's packages | `/var/db/pkg/*/+CONTENTS` | SHA-256 |
| pkgsrc (NetBSD) | `/usr/pkg/pkgdb/*/+CONTENTS` and `+INSTALL` | MD5 |

restate runs `rpm` and `pkg` the way it runs gzip: from a fixed path, owned
by root, and only for the system it is running on -- a tree mounted from
another disk has no database they can read, and that tree is classified by
its rules. The rest are read as files, beneath the tree scanned.

- one that still matches is **baseline**, and the index names its package —
  an untouched conffile in `/etc`, a vendor's files in `/opt` are not kept,
  since reinstalling the package puts them back;
- one that does not is **state**, `"modified": true` in the index, and kept;
- one in a baseline tree (`/usr`, `/boot`) that no package installed is
  **state**, and kept: it was put there by hand. On the BSDs, whose base
  system no package owns, that is only beneath the packages' own prefix
  (`/usr/local`, `/usr/pkg`).

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

On Ubuntu 22.04, 24.04 and 26.04, from the PPA, which Launchpad builds from
each release for every architecture it has:

```bash
sudo add-apt-repository ppa:bceverly/restate
sudo apt install restate
```

That puts `restate` in `/usr/sbin`, its manual in section 8 and its
[hooks](#live-services) in `/usr/libexec/restate/hooks`, and brings `gpgv`,
which checks an image's signature, with it; `curl`, `gpg` and `pigz` come as
recommendations.

On FreeBSD, OpenBSD and NetBSD, from the binary package attached to each
[release](https://github.com/bceverly/restate/releases) for every release
each system supports -- FreeBSD 14.4, 14.5 and 15.1, OpenBSD 7.9 and 8.0,
NetBSD 10.1 and 11.0 -- each built with that system's own package tool on
that release, and installed, checked and removed there before the release is
published. Check it against the release's `SHA256SUMS` first, then, for
example:

```bash
pkg add restate-VERSION-freebsd-15.1-amd64.pkg               # FreeBSD
cp restate-VERSION-openbsd-8.0-amd64.tgz restate-VERSION.tgz   # OpenBSD
pkg_add -D unsigned ./restate-VERSION.tgz
pkg_add restate-VERSION-netbsd-11.0-amd64.tgz                # NetBSD
```

OpenBSD's `pkg_add` refuses a file whose name is not the package's own
(`restate-VERSION`), hence the copy.

Each puts `restate` in `/usr/local/sbin`, its manual in section 8 and its
hooks in `/usr/local/libexec/restate/hooks`, all of them root's. OpenBSD's
own packages are signed by OpenBSD's means, which these are not -- hence
`-D unsigned`: the release's checksums and its signed attestation vouch for
them instead. `pkg delete restate` (FreeBSD) or `pkg_delete restate` removes
it. `make bsd-pkg` builds the same package on the system it runs on.

On Fedora, RHEL 9 and 10 and their rebuilds (AlmaLinux, Rocky), from
[COPR](https://copr.fedorainfracloud.org/coprs/bceverly/restate/), which
builds each release for every Fedora and EPEL release and architecture it
has; on openSUSE Tumbleweed, Leap and SLE, from the
[openSUSE Build Service](https://software.opensuse.org/download/package?package=restate&project=home%3Abceverly):

```bash
sudo dnf copr enable bceverly/restate && sudo dnf install restate   # Fedora, EL
```

Or from the RPM attached to each release for Fedora, EL 9, EL 10, Leap 16 and
Tumbleweed, x86_64 and aarch64, each built in a bare container of that
distribution from the release's tarball, then installed, used and removed in
a fresh one before the release is published:

```bash
sudo dnf install ./restate-VERSION-1.el10.x86_64.rpm                       # Fedora, EL
sudo zypper install --allow-unsigned-rpm ./restate-VERSION-1.opensuseleap16.0.x86_64.rpm
```

Each puts `restate` in `/usr/sbin` (`/usr/bin` on Fedora 42 and later, where
they are one), its manual in section 8 and its hooks in
`/usr/libexec/restate/hooks`, and brings `gpgv`; `curl`, `gpg` and `pigz` come
as recommendations, and the `restate-job@` systemd units come with it, enabled
for no job until one is written. `make rpm` builds the same package on the
system it runs on.

On Alpine 3.21 to 3.24, from the two packages attached to each release for
each, x86_64 and aarch64 -- the program, and its manual as Alpine splits it
off -- built with `abuild` on that release and installed, used and removed
there first:

```bash
apk add --allow-untrusted restate-VERSION-r0-alpine3.24-x86_64.apk \
    restate-doc-VERSION-r0-alpine3.24-x86_64.apk
```

They are signed by no key Alpine knows -- hence `--allow-untrusted`, as with
OpenBSD's `-D unsigned` -- and the release's checksums and attestation vouch
for them instead. `make apk` builds the same packages, as root in a
throwaway Alpine container.

On macOS, with Homebrew, from the formula each release puts in the
[bceverly/homebrew-tap](https://github.com/bceverly/homebrew-tap) tap, after
installing it from source, testing it and removing it on macOS:

```bash
brew install bceverly/tap/restate
```

restate runs as root, and runs only programs and hooks root owns: Homebrew's
are yours, so the formula's hooks are not run, and an image's signature is
checked only with a `gpgv` that is root's. `brew info restate` says so too.

Everywhere else, and for what is not released yet, restate is built from
source and installed into `/usr/local`, which is the place for software the
administrator installs by hand and is never touched by the package manager.

### Installing on Ubuntu 26.04 from source

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
make test           # the tests, sanitizers, valgrind and the coverage gate
make check          # test, lint and security, whichever has not passed: what a push needs
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
make test-share SHARE=/mnt/usb   # a repository on that storage, read back bit for bit
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

`make security` checks the built binary's hardening, then runs cppcheck with
the CERT C rules, the clang static analyzer, flawfinder, semgrep, the
sanitizers, a fuzz run, gitleaks over the whole history, MITRE's "Lucky 13",
and confirms the binary links nothing beyond libc. `gcc -fanalyzer` runs in
`make lint`, which every push needs. CodeQL (`security-extended`) and the OpenSSF
Scorecard run in CI.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability privately.

## Make targets

Run `make` with no arguments for the full list.

| | |
|---|---|
| `make build` | compile into `./bin`, regenerating the manpage |
| `make test` | unit, end-to-end, sanitizers, valgrind, and the 80% coverage gate — overall and per file |
| `make check` | test, lint and security, each unless it has passed on exactly these files; what the pre-push hook holds every push to (see [CONTRIBUTING.md](CONTRIBUTING.md)) |
| `make lint` | the compiler with `-Werror`, `gcc -fanalyzer`, cppcheck, clang-tidy, shellcheck, actionlint, house style, copyright audit, generated-file freshness |
| `make security` | the security scanners, sanitizers, a fuzz run, gitleaks, Lucky 13 (`gcc -fanalyzer` is `make lint`'s) |
| `make fuzz` | fuzz every parser |
| `make install` / `make uninstall` | into / out of `$(prefix)`, default `/usr/local` |
| `make deb` / `make deb-source` | the binary `.deb`, or the signed source package Launchpad builds from |
| `make deb-sbuild` | build the package in a clean chroot with no network, as a Launchpad builder does |
| `make bsd-pkg` | this BSD's binary package, into `dist/`: FreeBSD's `.pkg`, OpenBSD's or NetBSD's `.tgz` |
| `make rpm` | this distribution's RPM and source RPM, into `dist/`: Fedora, RHEL and its rebuilds, openSUSE |
| `make apk` | this Alpine release's packages, into `dist/`, as root in a throwaway container |
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

Beside it the workflow builds the Debian package, has lintian check it,
installs it with apt on clean Ubuntu 24.04 and 26.04 containers, uses it and
removes it (`scripts/verify-deb.sh`) -- and only then uploads a signed source
package for each LTS series to the [PPA](#installing), where Launchpad builds
it for every architecture. An upload cannot be taken back, so nothing goes
that has not installed. The signing key is pinned by its fingerprint in
`debian/signing-fingerprint`; the workflow refuses a secret holding any
other.

To build the packages by hand:

```bash
make deb             # ../restate_<version>~<series>1_<arch>.deb, unsigned
make deb-source      # the signed source package, and the dput that uploads it
make deb-sbuild      # in a clean chroot with no network, as Launchpad builds it
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
- **Secrets → Actions:** `LAUNCHPAD_GPG_PRIVATE_KEY`, the armored secret key
  `debian/signing-fingerprint` names, registered on the Launchpad account,
  and `LAUNCHPAD_GPG_PASSPHRASE`, its passphrase. The upload runs in the
  `launchpad` environment, which can be given a required reviewer.

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
  image.c       images: assembling and reading back, and exporting snapshots
  repo.c        repositories: packs, snapshots, the content stream, prune, repack, protect, check, copy, du
  tar.c         pax tar, writing and reading the first member
  gzip.c        gzip as a separate process
  run.c         running gzip, curl, gpg, sh, ssh-keygen and the hooks: fixed paths, posix_spawn
  live.c        what is running, from /proc: databases, VMs, containers
  hooks.c       finding and running the hooks that pause them
  sources.c     whether apt can still use each of its sources, and fetching an index
  baseline.c    the package baseline: each package at its version, fetched and checked
  reinstall.c   the script restore --packages runs
  restore.c     putting an image's files back
  identity.c    restore --as: a copy given an identity of its own
  clones.c      the list of copies autoinstall --clones reads
  fstab.c       whether an image's fstab and crypttab fit the machine
  pgp.c         encrypting, signing and checking signatures, through gpg
  machine.c     the machine description: hardware, disks, encryption
  packages.c    the package inventory: apt, snap, flatpak, pip, npm, cargo
  installer.c   which installer rebuilds a machine, and fetching it
  keys.c        the vendors' signing keys, pinned by fingerprint
  jobs.c        restate run: a job file, read and checked
  result.c      --result: how a run ended, as JSON
  json.c        a strict JSON parser and writer
  meta.c        timestamps, birth times, user and group names
  diff.c        comparing two indexes
  sha256.c      FIPS 180-4
include/        restate.h: the version, copyright and exit statuses
hooks/          the hooks capture --quiesce runs, installed in libexec/restate/hooks
systemd/        restate-job@.service and .timer, which run a job
tests/          unit tests; cli/ end-to-end; fuzz/ the fuzz target
scripts/        everything make runs
man/restate.8   generated from --help; do not edit
debian/         the Debian packaging the PPA builds from
.github/        CI, security, CodeQL, Scorecard and release workflows
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
