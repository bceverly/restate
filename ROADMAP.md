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

- [ ] **System identity:** distribution, release, architecture, the original
      install media, and the type — desktop, server, minimal, cloud — from
      the installed metapackages
- [ ] **Every package manager detected:** apt/dpkg, snap, flatpak, rpm,
      pacman, apk, nix, guix, Homebrew, pip, npm, cargo, gem, conda, FreeBSD
      pkg, OpenBSD and NetBSD packages, macOS receipts — which are present,
      and an inventory of each
- [ ] **The apt inventory:** every package, version and architecture; manual
      or automatic; the source each version came from — the archive, a PPA, a
      third-party repository, or nowhere (installed by hand); every source
      definition and the key it is signed with. A PPA package is not backed
      up: the image records "add `ppa:owner/name` with this key, install
      these versions"
- [ ] **Package-aware capture:** unmodified package files listed, not
      stored; modified ones (including edited conffiles) and files no
      package owns stored
- [ ] **Package-aware diff:** upgrades and removals reported per package
- [ ] **Fetchability:** which installed versions a restore could not get
      back, and an option to keep their `.deb` files
- [ ] snap revisions and channels; flatpak apps, branches and remotes

## Then — the machine underneath

- [x] **Storage layout** in the index, and `restate machine`: disks,
      partition tables, LVM (from its text metadata), LUKS (cipher, UUID —
      never keys), software RAID, filesystems with UUIDs and labels, mounts,
      `fstab`, `crypttab`, swap, UEFI or BIOS and the boot loaders, hardware
      and network interfaces — on Linux
- [ ] The BSD storage equivalents (`gpart`, `disklabel`, NetBSD `gpt`); a
      description only on macOS
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
- [ ] **`restate buildsheet`**: a plain-text runbook to rebuild the machine —
      the hardware it came from and what a replacement needs; the commands to
      recreate partitions, LUKS, RAID, LVM, filesystems and swap with the same
      UUIDs; how to drive the installer onto that layout; then the restore
- [ ] **Unattended rebuilds:** a generated Ubuntu autoinstall file (storage,
      release, type, PPAs and keys, packages, `restate restore` at the end);
      `bsdinstall` and OpenBSD `install.conf` equivalents
- [ ] **Moving between bare metal and a virtual machine**: `buildsheet` and
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
- [ ] **Image encryption at rest**: an image can hold key files (a LUKS key
      under `/etc`), so it must be possible to encrypt one

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
