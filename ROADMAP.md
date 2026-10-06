<!--
Copyright (c) 2026 Bryan C. Everly
SPDX-License-Identifier: BSD-2-Clause
-->

# Roadmap

restate is meant to turn "back up the whole disk" into "record what makes this
machine different from a fresh install, and replay it". This is the order the
pieces arrive in.

## Done — 0.1

- [x] The classification rules: ephemeral, expendable, baseline, state; built-in
      sets for Linux, FreeBSD, OpenBSD, NetBSD and macOS; site rules files
- [x] A walk that cannot be redirected by symlinks or races, and is bounded
- [x] The index: JSON with every path's type, class, mode, owner by id and by
      name, size, link count, device and inode, the four timestamps to the
      nanosecond, the SHA-256 of every file, and exact bytes for non-UTF-8
      names
- [x] Images: a `.tgz` with `index.json` first and the content of everything
      kept, restorable by hand with `tar -xzpf`
- [x] `capture`, `scan`, `diff`, `verify`, `classify`, `rules`
- [x] Dev-mode build and install on Ubuntu 26.04, any Linux, the BSDs and macOS

## How the baseline is decided

The baseline is **not** the installer that originally built the machine. A
machine is upgraded after it is installed — package updates every week,
release upgrades every few years — and a machine installed from 22.04 and now
running 26.04 would differ from its installer in nearly every file. Instead:

- **The baseline is the vendor's files for the packages installed now**, at
  the versions installed now. Every package manager already records those
  digests (dpkg's `md5sums` and conffile digests, rpm's database, FreeBSD
  pkg, OpenBSD and NetBSD `+CONTENTS`); for a base system that is not
  packaged (OpenBSD and NetBSD sets, FreeBSD `base.txz`), it is the release's
  signed sets plus the recorded patch level.
- **The original install is history**, recorded (`/var/log/installer/media-info`,
  `initial-status.gz`) but never compared against.
- **Upgrades are therefore not changes.** A file that matches its package's
  digest is listed as "package X version Y, unmodified" and not stored, before
  an upgrade and after it; `diff` reports `upgraded X 1.2 → 1.3` rather than
  every file the upgrade touched.
- **Getting the exact version back at restore is the hard part.** The regular
  archive serves only the latest version. Ubuntu's snapshot archive can serve
  older states, but only back to when its history begins, so it is a
  convenience, never a dependency. At capture, restate works out — offline,
  from apt's own lists — whether each installed version can still be fetched:
  if not (superseded, from a PPA or third-party source that prunes old builds,
  or installed by hand), it keeps the `.deb`; if even that is gone, the files.
  A capture says plainly what a restore could not reproduce exactly.

## Next — the package baseline (Ubuntu first)

What the first full restore -- this laptop, rebuilt into a VM from its image,
2026-10-06 -- showed this stage has to do. Of 234 packages installed by hand,
156 were missing afterwards (Postgres, Docker, VS Code, Chrome, libvirt and
QEMU, OpenJDK, Node.js, compilers, nordlayer ...), with 1,622 dependencies
under them; the third-party APT sources (Chrome, VS Code, HashiCorp,
NodeSource, Tailscale, a PPA ...) came back with /etc, so the names alone
would bring most of it back. Units enabled for programs no longer installed
fail at boot until their packages return. And two things restored on their
own did harm, and are now left out until this stage puts them back properly:
/etc/alternatives (392 links into missing packages, `awk` among them) and
snapd's database without its snaps (32 snaps listed, 48 mount units failing).

Then the 156 were installed by name, in that VM, from the restored sources:
144 came back. What did not, and what went wrong, is this stage's to-do list:

- Repository keys: five sources (NodeSource, HashiCorp, nordlayer, Tailscale,
  VS Code) name keys under /usr/share/keyrings -- baseline, so not kept --
  and were refused as unsigned. Every source's key has to be recorded, from
  wherever its signed-by points.
- Origins: with NodeSource refused, nodejs quietly came from the Ubuntu
  archive instead, another version. Each package's origin (and version) has
  to be recorded and insisted on.
- Packages from no repository at all -- chef, osquery, otelcol-contrib,
  veracrypt, zoom, installed from downloaded .debs -- cannot be found by
  name: keep the .deb, or where it came from.
- Order: packages first, then the kept files. Laying the files down first
  made three packages fail to configure: a conffile dpkg stopped to ask
  about (fwupd), and a file already where libvirt places a diversion. When a
  package's own conffile and the kept one differ, the kept one wins.
- /etc/alternatives: the manual choices among them have to be put back after
  the packages providing them are installed.

- [x] **System identity:** distribution, release, architecture, the original
      install media, and the type — desktop, server, minimal, cloud — from
      the installed metapackages (the machine description's "system")
- [x] **Every package manager detected:** apt/dpkg, snap, flatpak, rpm,
      pacman, apk, nix, guix, Homebrew, pip, npm, cargo, gem, conda, FreeBSD
      pkg, OpenBSD and NetBSD packages, macOS receipts — which are present
      ("managers" in the inventory, `restate packages`)
- [x] Inventories of apt, snap, flatpak, pip, npm, cargo, pipx, gems, and
      OpenBSD and NetBSD packages
- [ ] Inventories of the rest: rpm, pacman, apk, Nix, Guix, Homebrew, conda,
      FreeBSD pkg (SQLite), macOS receipts
- [x] **The apt inventory:** every package, version and architecture; manual
      or automatic; held or half-configured; the repositories each installed
      version can be had from, or that none can — superseded, or installed
      from a `.deb`; every source definition, in either format, and every key
      apt trusts, whole, from wherever signed-by points
- [x] **The inventory in the build sheet:** /etc/apt and the keys outside
      it, then the packages installed by hand pinned to their versions, holds,
      the ones no repository has; snaps, flatpaks, pip, npm, pipx, cargo, gem
- [ ] **The inventory in the autoinstall file:** the same, as late-commands,
      so an unattended rebuild comes up with its packages
- [ ] **Package-aware capture:** unmodified package files listed, not
      stored; modified ones (including edited conffiles) and files no
      package owns stored
- [ ] **Package-aware diff:** upgrades and removals reported per package
- [ ] **Fetchability:** an option to keep the `.deb` files of the installed
      versions no repository has (from /var/cache/apt/archives, or
      snapshot.ubuntu.com for superseded ones); likewise snaps installed from
      a file
- [x] snap revisions, channels and confinement; flatpak apps, branches and
      remotes
- [ ] /etc/alternatives: the manual choices, put back once the packages
      providing them are installed

## Then — the machine underneath

- [x] **Storage layout** in the index, and `restate machine`: disks,
      partition tables, LVM (from its text metadata), LUKS (cipher, UUID —
      never keys), software RAID, filesystems with UUIDs and labels, mounts,
      `fstab`, `crypttab`, swap, UEFI or BIOS and the boot loaders, hardware
      and network interfaces — on Linux
- [x] The BSD storage equivalents in the machine description: FreeBSD's GEOM
      configuration (GPT, MBR, GELI), OpenBSD's disklabels, NetBSD's wedges
      and disklabels; hardware, interfaces and mounts from sysctl,
      getifaddrs and getmntinfo; a description without disks on macOS
- [ ] Build sheets for the BSDs: `gpart`, `geli`, `newfs` and `zpool` on
      FreeBSD; `disklabel` and `newfs` on OpenBSD; `gpt` and `newfs` on NetBSD
- [x] **`restate installer`**: which installer matches the machine — release,
      architecture and type (server, desktop, …) — with its official download
      URL, its checksum and the vendor's signed checksum file. Ubuntu done;
      the other systems follow their package baselines
- [x] **`restate installer fetch`**: download it into the cache
      (`/var/cache/restate/installers`; `/Library/Caches/restate` on macOS;
      overridable), verify the checksum file's signature against the vendor's
      key and the image against the checksum, resume an interrupted download,
      skip one already verified, and say how to write it to a USB stick.
      Downloads are done by `curl` and signatures checked by `gpgv`, each run
      as a separate process from a fixed system path with no shell — the way
      gzip is — so that restate itself still links only libc and contains no
      TLS or OpenPGP code of its own. Vendors that sign some other way are
      handled in their own terms (OpenBSD signs with `signify`)
- [x] **`restate buildsheet`**: a plain-text runbook to rebuild the machine —
      the hardware it came from and what a replacement needs; the commands to
      recreate partitions, LUKS, RAID, LVM, filesystems and swap with the same
      UUIDs; how to drive the installer onto that layout; then the restore
- [x] **Unattended rebuilds:** a generated Ubuntu autoinstall file — storage,
      locale, keyboard, time zone, identity, network, SSH server
- [ ] The autoinstall file's packages: PPAs and keys, the recorded packages,
      `restate restore` at the end (with the package baseline, above)
- [ ] `bsdinstall` and OpenBSD `install.conf` equivalents
- [x] **Moving between bare metal and a virtual machine**: `buildsheet` and
      `autoinstall` take `--target vm` or `--target metal` and account for
      what changes — the storage and network drivers the initramfs needs
      (virtio, NVMe, RAID controllers); UEFI or BIOS, and the partitions each
      needs (an EFI system partition, a BIOS boot partition); device names
      (`/dev/nvme0n1` becomes `/dev/vda`) and network interface names and MAC
      addresses, with the netplan configuration remapped; a disk sized to the
      space actually used rather than to the old drive; hardware-specific
      software swapped (microcode, RAID and IPMI tools, sensors, GPU drivers
      out; `qemu-guest-agent`, `open-vm-tools`, Hyper-V daemons in — or the
      reverse); LUKS volumes unlocked by the old machine's TPM, which will not
      unlock anywhere else; locally enrolled Secure Boot keys; time sync and
      the hibernation resume device. For a VM, a ready-to-run definition of
      the machine itself (`virt-install`), sized from the captured CPUs,
      memory and used space. The machine description already records whether
      it is virtual and on what, and the space used on each filesystem
- [ ] Changing firmware mode on the way (BIOS to UEFI, or back), which needs an
      EFI system partition or a BIOS boot partition added; both targets keep
      the original's mode for now
- [x] **Image encryption at rest**: an image can hold key files (a LUKS key
      under `/etc`), so `capture --encrypt-to KEYFILE` encrypts it to OpenPGP
      public keys, with gpg in the same pipe as gzip; every command reads an
      encrypted image directly

## Then — putting it back

- [ ] **`restate baseline fetch`**: the exact packages, verified against the
      vendor's signed archive, into `/var/cache/restate` (`/Library/Caches/restate`
      on macOS) — itself expendable, so never inside an image
- [ ] **`restore`**: onto a fresh install, add the recorded sources and keys,
      install the recorded packages at their versions (from the archive, the
      snapshot archive, or kept `.deb` files), remove what the vendor ships
      and the machine did not have, lay down the kept content, and restore
      owners — mapped by name — modes, times and attributes
- [ ] Extended attributes, POSIX ACLs and file capabilities; hard links as
      links; users and groups the image's owners depend on
- [ ] `status`: what has changed since the last capture, quickly

## Then — captures on a schedule

So that a capture can run from cron, unattended, and keep running every
night without the disk filling up.

- [ ] **Detecting what is live** (libc only, from `/proc`): database
      servers (Postgres, MySQL/MariaDB, MongoDB, Redis, ...), QEMU VMs and
      the disk images they hold open, running LXD and Docker containers, and
      services known to write to them. `capture` warns by default, naming the
      command that would pause each one
- [ ] **Quiescing, through hook scripts.** restate itself still runs no
      administration tools: it runs root-owned hooks from
      `/etc/restate/hooks.d` (directory and scripts owned by root and
      writable by no one else, as with the programs it runs now), and ships
      ready-made ones for Postgres, MySQL/MariaDB, libvirt, LXD, Docker and
      systemd services, which a site can add to or replace
- [ ] **Just in time**: the walk leaves each live service's files to the
      end, then for each in turn pauses it, copies its files and resumes it,
      so a service is down for the time its own files take to copy, not for
      the whole capture. Per kind: a database is dumped into the image
      (`pg_dumpall`, `mysqldump --single-transaction`) and stopped, copied
      and started; a VM is suspended (or its filesystems frozen through the
      guest agent), copied and resumed; a container paused and unpaused; a
      service that writes to a database stopped before it and started after
- [ ] **Always put back**: every paused or stopped thing is resumed or
      started again whether the capture succeeds, fails or is interrupted,
      with each step reported (`pausing win-msi-lab ... resumed`) and logged
      to syslog for a cron job's benefit
- [ ] **A repository** instead of a growing pile of `.tgz` files: a
      directory where file content is stored once, by SHA-256, in compressed
      packs, and each capture adds a snapshot -- an index pointing into it
- [ ] **Incremental runs**: a file whose size, mtime, ctime and inode match
      the last snapshot is not read again, its recorded digest is trusted (as
      `git status` and rsync do), so the first capture takes as long as today
      and later ones only as long as what changed
- [ ] `restate snapshots`; `restate prune --keep-daily N --keep-weekly N
      --keep-monthly N`, which drops old snapshots and the content no
      remaining one refers to; `restate export SNAPSHOT -o FILE.tgz` for the
      portable single file; `diff`, `verify`, `buildsheet`, `autoinstall` and
      restore reading a snapshot as they read an image today
- [ ] Encryption per pack with the same `--encrypt-to` keys, so a
      repository can sit on untrusted storage
- [ ] A lock, so two scheduled runs never overlap, and exit statuses and
      log lines a monitoring system can act on

## Then — stamping out copies

A capture of one machine that does "the thing", rebuilt as N machines — for
scalability tests, labs, classrooms. The work is in making each copy its own
machine rather than N copies of one:

- [ ] **An `identity` class**, with built-in rules for what must be unique per
      machine: the hostname; `/etc/machine-id` (systemd-networkd and
      NetworkManager derive the DHCP client identifier from it, so clones
      that share one can be handed the same address); SSH host keys; the
      systemd random seed; cloud-init instance state; Tailscale and WireGuard
      node keys; container runtime and orchestrator node IDs; database
      identities (MySQL `server_uuid`, the PostgreSQL system identifier);
      monitoring-agent IDs, the SysManage agent's included. Sites add their own.
      Identity files are still captured, so an ordinary restore brings the
      same machine back
- [ ] **`restate restore --as NAME`**: regenerate the identity instead of
      restoring it — a new machine-id, new SSH host keys, a new random seed,
      instance state cleared — set the host name, and apply per-copy values
      such as a static address
- [ ] **`restate autoinstall IMAGE --clones clones.csv`**: one autoinstall file
      per copy (host name, address, the MAC address or disk serial to match
      on), so N machines boot one installer and each comes up as itself

## Packaging

- [ ] A Launchpad PPA for Ubuntu (26.04 first), built from signed source
      packages by the release workflow, as `../tmd` does it
- [ ] FreeBSD port, OpenBSD port, NetBSD pkgsrc, Homebrew formula
- [ ] Debian and RPM packages for other Linux distributions

## Later

- [ ] A content-addressed store shared between machines, so identical files on
      a fleet are kept once
- [ ] Integration with SysManage: scheduled captures, a fleet view of drift,
      and bare-metal recovery from a boot image
