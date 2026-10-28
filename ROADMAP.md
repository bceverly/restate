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
- [x] **Inventories of the rest:** rpm and FreeBSD pkg (asked of `rpm` and
      `pkg`, on the running system: their databases are SQLite), pacman,
      apk, OpenBSD packages and pkgsrc with what was asked for and what came
      as a dependency, Homebrew formulae and casks, conda environments, Nix
      and Guix profiles, macOS receipts; and each in the build sheet
- [x] **The apt inventory:** every package, version and architecture; manual
      or automatic; held or half-configured; the repositories each installed
      version can be had from, or that none can — superseded, or installed
      from a `.deb`; every source definition, in either format, and every key
      apt trusts, whole, from wherever signed-by points
- [x] **The inventory in the build sheet:** /etc/apt and the keys outside
      it, then the packages installed by hand pinned to their versions, holds,
      the ones no repository has; snaps, flatpaks, pip, npm, pipx, cargo, gem
- [x] **The inventory in the autoinstall file:** snaps in its snaps
      section; with `--image-at`, the rest as late-commands, then the files
      and the boot files, so an unattended rebuild comes up as it was
- [x] **Package-aware capture:** unmodified package files listed, not
      stored; modified ones (including edited conffiles) and files no
      package owns stored -- dpkg's md5sums and conffile digests, with
      diversions and merged /usr; what packages' scripts generate made
      expendable by rule; `--rules-only` to turn it off
- [x] **The same for rpm, FreeBSD pkg, pacman, apk, OpenBSD and NetBSD:**
      rpm's and pkg's digests asked of their tools (SHA-256, MD5, pkg 2.8's
      BLAKE2b), pacman's mtree, apk's SHA-1, `+CONTENTS` and pkgsrc's
      `+INSTALL` copies; on the BSDs only the packages' prefix is theirs
- [x] **Package-aware diff:** `diff --packages` -- each package installed,
      removed or upgraded (apt and snap) a line of its own, with the number of
      files its change accounts for, and only the file changes no package
      accounts for listed besides
- [x] **Fetchability:** `capture --keep-local-packages` keeps the `.deb` of
      each installed version no repository has, from apt's cache (warning,
      with the `dpkg-repack` that puts one there, of each it cannot), and the
      `.snap` of each snap installed from a file
- [x] **Versions the archive has moved on from**, from its snapshot as of
      the capture (`--exact-versions`: `apt-get --snapshot`, which reaches
      snapshot.ubuntu.com and snapshot.debian.org), where apt can; the newer
      version otherwise, and by default, as a security update would
- [x] Versions that had already left the archive when they were captured
      (`"superseded"`), from the snapshot of a time they were in it: the
      inventory records where the newer version is and when this one was
      installed, and `--exact-versions` and `baseline fetch` take it from the
      archive's snapshot as of then
- [x] **Repositories apt can no longer use:** each source's index as apt
      last fetched it (InRelease, or Release and Release.gpg) checked with
      gpgv against the keys the source names -- armored ones too -- and its
      Valid-Until against the clock; each one apt cannot use gets a
      "problem" in the inventory, and capture warns -- the second rebuild
      found HashiCorp and NordLayer refused, as they had been on the laptop
      for months, unnoticed
- [x] **The same against what each source serves today** (`--fetch-sources`,
      with curl): each source that passes is fetched again and checked the
      same way, so a vendor that changed keys since the last `apt update` is
      caught before the rebuild
- [x] **The image in parts:** the index, a kit (/etc/apt and the kept
      packages) and the files, each compressed (and encrypted) on its own in
      an uncompressed tar, so a rebuild has the kit in seconds rather than
      after a pass over the whole image; `--deb NAME=FILE` for a package
      dpkg-repack cannot rebuild
- [x] snap revisions, channels and confinement; flatpak apps, branches and
      remotes
- [x] /etc/alternatives: the manual choices recorded, and set again once the
      packages providing them are installed

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
- [x] The autoinstall file's packages: PPAs and keys, the recorded packages,
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
- [x] Changing firmware mode on the way (BIOS to UEFI, or back):
      `--firmware uefi|bios` with `--target`, an EFI system partition in place
      of GRUB's BIOS boot partition (or added in front, on MBR), or the other
      way
- [x] **Image encryption at rest**: an image can hold key files (a LUKS key
      under `/etc`), so `capture --encrypt-to KEYFILE` encrypts it to OpenPGP
      public keys, with gpg in the same pipe as gzip; every command reads an
      encrypted image directly

## Then — putting it back

- [x] **`restate baseline fetch`**: the exact packages, verified against the
      vendor's signed archive -- the index by gpgv against the source's keys,
      the list by the index's digest, each `.deb` by the list's -- into
      `/var/cache/restate/baseline` (`/Library/Caches/restate` on macOS), from
      the archive's snapshot where it has moved on; itself expendable, so never
      inside an image
- [x] **`restore`, the files:** every member checked against the index -- a
      file renamed into place only if its digest matches, a member the index
      does not list refused -- written beneath the root without following a
      symlink, with owners, modes, nanosecond times, hard links and device
      nodes; `--exclude`, `--dry-run`; the restate binary in the kit, so the
      build sheet and autoinstall file restore with it
- [x] **Owners by name, and the accounts:** the image's /etc/passwd,
      /etc/group and shadows (from the kit) merged with the new system's --
      its numbers where both have a user, the old passwords, homes and
      shells -- every owner mapped by name; `--numeric-owner`; the
      autoinstall file's account is the old machine's first person
- [x] **`restore --packages`**: onto a fresh install, add the recorded sources
      and keys, install the recorded packages at their versions (from the
      archive, the snapshot archive, the baseline or kept `.deb` files), mark
      each installed by hand or as a dependency as it was, remove what the
      vendor ships and the machine did not have (never the kernel, boot
      loader, firmware or microcode), lay down the kept content, and restore
      owners -- mapped by name -- modes, times and attributes
- [x] **Signed images, and a restore that refuses a tampered one.**
      Encryption is not authentication: `--encrypt-to` needs only a public
      key, so anyone holding it can make an image that decrypts cleanly. So:
  - `capture --sign-with KEYFILE` signs the image with an OpenPGP secret
    key (gpg, in its own throwaway home, as encryption does), and `restate
    sign IMAGE` signs one already written, in place, so a capture run from
    cron needs no secret key on the machine. The detached signature is the
    archive's last member, `restate/index.sig`, over the index part exactly
    as stored -- compressed, and encrypted where the image is -- so it covers
    every kept file's digest, owner, mode and path, and checking it decrypts
    nothing.
  - `restore`, and `verify` and `diff` with `--trusted-key KEYFILE`, check it
    with gpgv before reading anything else, and match the index then read
    with the bytes checked. They say who signed the image, and when and on
    which host it was captured.
  - `restore` refuses an image that is unsigned, badly signed or signed by
    a key not trusted, with exit status 4, naming the failure;
    `--allow-unverified` overrides that for one run, on the command line
    only, with a warning. Each file is still checked against its digest as
    it is put in place, and one that does not match is refused.
  - The build sheet and autoinstall file pass restore `--allow-unverified`,
    or with `--trusted-key` the same keys -- the autoinstall file carries
    them itself.
- [x] A restore that reads the whole image before writing anything, so a
      damaged one is refused whole rather than restored as far as it is
      whole: `restore --check-first`, which reads it twice
- [x] Extended attributes, POSIX ACLs and file capabilities (Linux xattrs,
      macOS xattrs, FreeBSD and NetBSD extattrs), set after the owner, with
      an ACL's users and groups mapped by name; hard links as links; users
      and groups the image's owners depend on
- [x] Every ACL Ubuntu has: POSIX ACLs, on ext4, XFS, Btrfs and ZFS
      (`acltype=posix`), all of them extended attributes, above. OpenZFS on
      Linux has no NFSv4 ACLs (`acltype=nfsv4` is FreeBSD's alone)
- [ ] ACLs that are not extended attributes, on the other systems: macOS's,
      and NFSv4 ACLs on ZFS -- FreeBSD's, and Linux's once OpenZFS has them
- [x] **Air-gapped rebuilds:** `restore --packages --offline`, with no network
      at all -- every apt package from the baseline and the kept `.deb`
      files, apt given a repository of them, indexed with `dpkg-deb`, in
      place of every source it has, with lists of its own; the snaps the
      image keeps from their files, and what needs a store said and left out
- [x] **A restore onto a machine laid out afresh:** the machine's own
      `/etc/fstab` and `/etc/crypttab` kept where the image's name disks it
      does not have (`--image-fstab` to put them back all the same); a
      package installed already at a newer version than recorded left at it;
      a hard-linked file already in place under every name left as it is
- [x] `status`: what has changed since the last capture, quickly -- verify's
      comparison, reading only what size, times and inode say changed

## Then — captures on a schedule

So that a capture can run from cron, unattended, and keep running every
night without the disk filling up.

- [x] **Detecting what is live** (libc only, from `/proc`): PostgreSQL,
      MySQL and MariaDB, MongoDB and Redis by their data directories, QEMU
      VMs by the disks and NVRAM they hold open for writing, LXD containers,
      and Docker's volumes while a container runs. `capture` warns of each
      one, naming the command that would stop it
- [x] **Quiescing, through hook scripts** (`capture --quiesce`). restate
      itself still runs no administration tools: it runs root-owned hooks
      from `/etc/restate/hooks.d` (directory and scripts owned by root and
      writable by no one else, as with the programs it runs), and ships
      ready-made ones for PostgreSQL, MySQL/MariaDB, MongoDB, Redis, libvirt,
      LXD and Docker in `libexec/restate/hooks`, which a site can add to or
      replace. A database's hook dumps it into a directory the image keeps
      (`pg_dumpall`, `mysqldump --single-transaction`, `mongodump`) and stops
      it; the PostgreSQL hook stops the services listed in
      `/etc/restate/also.d/postgresql` before it, and starts them after
- [x] **Just in time**: the walk leaves each live thing's files to the end,
      then for each in turn pauses it, copies its files and resumes it, so it
      is down for the time its own files take to copy, not the whole capture
- [x] **Always put back**: resume is run whether pausing worked or not, the
      signals that would end restate are held while a thing is paused (a
      Ctrl-C reaches the hook, and stops what is left), and every pause and
      resume is said and logged to syslog for a cron job's benefit
- [ ] Hooks for other platforms' services, and detection beyond Linux
- [x] **A repository** instead of a growing pile of `.tgz` files
      (`restate init`; `capture -o REPO`): file content stored once, by
      SHA-256, in gzip'd packs, and each capture a snapshot -- an index
      pointing into them, signed like an image's
- [x] **Incremental runs**: a file whose size, mtime, ctime and inode match
      the last snapshot is not read again, its recorded digest is trusted (as
      `git status` and rsync do), so the first capture takes as long as today
      and later ones only as long as what changed
- [x] `restate snapshots`; `restate prune --keep-last N --keep-daily N
      --keep-weekly N --keep-monthly N`, which drops old snapshots and the
      content no remaining one refers to; `restate export SNAPSHOT -o FILE.tar`
      for the portable single file, and the one the build files are made
      from; `REPO::NAME` read wherever an image is -- `restore`, `diff`,
      `verify`, `status`, `packages`, `installer`, `sign`
- [x] Content-defined chunking, so a large file that changes a little -- a VM's
      disk -- is stored as the pieces that changed rather than whole again:
      FastCDC, chunks of a quarter to four mebibytes averaging one, in 32 MiB
      packs read a few at a time, each forward; a 1.3.0 repository's whole-file
      packs read as one-chunk files
- [x] Encryption per pack with the same `--encrypt-to` keys, so a
      repository can sit on untrusted storage: `init --encrypt-to`; packs,
      their indexes and snapshots' files encrypted, gpg after gzip; the keys
      given on each capture and prune, never read from the repository; a
      capture needing no secret key, from the machine's own cache of what it
      wrote
- [x] Chunk boundaries that depend on a key of the repository's, as restic's
      do, so that the sizes of the chunks in an encrypted repository say
      nothing about known files: `chunk-key`, encrypted to the repository's
      keys and kept in the capturing machine's cache
- [x] **Locks**: one capture or prune on a repository at a time, one
      `capture --quiesce` on a machine at a time, and exit status 5 for a run
      that found the lock taken; `--syslog` for one key=value line a
      monitoring system can match on as each capture and prune ends
- [x] **`restate check REPO`**, as `restic check --read-data`: every pack
      read through and every chunk checked against its digest -- against the
      repository's own pack indexes, never this machine's cached copies --
      every snapshot's index and kit read, and every file each needs found
      whole; damage said by pack and by file, exit status 3. `--read-all` reads
      every snapshot in full as restore would, a test restore that writes
      nothing; `--syslog` for cron and monitoring. ZFS finds bit rot on the
      disk; this finds a pack that was written wrong

## Then — stamping out copies

A capture of one machine that does "the thing", rebuilt as N machines — for
scalability tests, labs, classrooms. The work is in making each copy its own
machine rather than N copies of one:

- [x] **An `identity` class**, with built-in rules for what must be unique per
      machine: the hostname; `/etc/machine-id` (systemd-networkd and
      NetworkManager derive the DHCP client identifier from it, so clones
      that share one can be handed the same address); SSH host keys; the
      systemd random seed and credential secret; cloud-init instance state;
      DHCP leases; Tailscale and WireGuard node keys; container runtime and
      orchestrator node IDs (Docker, kubelet, k3s, LXD, Incus); MySQL's
      `server_uuid`; the Ubuntu Pro machine token; configuration-management
      and monitoring-agent IDs (Puppet, Salt, Chef, Wazuh, Netdata, the
      SysManage agent's). Sites add their own with `identity PATTERN`.
      Identity files are still captured, so an ordinary restore brings the
      same machine back; an image records them as state with an `identity`
      mark, so an older restate still reads it
- [x] **`restate restore --as NAME`**: leave the image's identity out, keep
      the machine's own where it has one, and where what it has is the
      image's (the same machine, or a copy of its disk) make a new
      machine-id, random seed and SSH host keys and remove the rest for
      their services to make anew; set the host name, in `/etc/hostname`
      and `/etc/hosts`
- [x] **`restate autoinstall IMAGE --clones clones.csv`**: one autoinstall
      file for every copy (host name, address, gateway, name servers, the MAC
      address or disk serial to match on); its early-command finds which copy
      the machine is, so N machines boot one installer and each comes up as
      itself
- [x] A PostgreSQL cluster's system identifier, which only `initdb` sets:
      `restore --as` says, for each cluster the image keeps (its
      `global/pg_control`), that to replication it is the original's, and an
      autoinstall file of copies says the same -- a copy that is to
      replicate is made a standby with `pg_basebackup`, not restored

## Done — 2.0: run by other programs, stored on other machines

restate is still a tool a person runs by hand or from cron. 2.0 adds what a
program running it on many machines needs, all of it off unless asked for:

- [x] **How a run ended, for a program:** `--result FILE`, one JSON object
      written atomically when any command ends -- the status and exit status,
      what it did, every path it could not read and why, every hook's pause
      and resume, every warning -- and `--json` for `snapshots`, `diff`,
      `verify`, `status`, `du`, `estimate` and `features`; the exit statuses
      written down as a contract
- [x] **Progress for a program:** `--progress=json` and `--progress-file`
- [x] **Jobs:** `restate run JOBFILE`, a typed, root-owned file in place of a
      command line, which can name no program; `restate-job@.service` and
      `.timer` to run one, on a schedule or on demand
- [x] **`restate features --json`:** what this restate can do
- [x] **Repositories on a file server:** locks a capture over NFS and a prune
      on the server both see; nothing required to be root's; a capture that
      only adds files, and `--append-only` to hold it to that;
      `--tmpdir` for an image's staging
- [x] **The storage's own checks:** a `.sum` beside each pack and a list of
      packs in each snapshot, neither saying anything of what is in them;
      `check --metadata-only`, `prune --whole-packs`, `copy` and `du` without
      any key; `check --record` to find what was removed or changed since
- [x] **Quiescing what `/proc` does not show:** `--quiesce-with NAME`, a hook
      asked which paths it covers; hooks for UniFi Network and Nextcloud; a
      failed pause makes the capture incomplete
- [x] **A file back without the whole machine:** `restore --include`, with
      the plan in the result of a dry run
- [x] **Keys, unattended:** `--passphrase-fd`, the passphrase given to each
      gpg on a pipe of its own
- [x] **`restate estimate`:** how much a first capture would keep, by
      directory

## Then — other systems

restate is Linux first, and Ubuntu first of all. The rest of it is the same
program on each system, with what is particular to each kept in its own
place:

- [x] **A repository format free of any system's assumptions**, so one
      repository can hold captures of Linux, the BSDs, macOS and Windows, on
      any storage, a NAS share among them. Packs and snapshots are plain
      files with names restate chooses (digests, sequence numbers and UTC
      times, in letters, digits, `.`, `-` and `_`); paths, their bytes and
      case, owners, modes, times and every other kind of metadata stay data
      inside the index, never left to the filesystem the repository is on.
      Held to by `tests/cli/share.sh`: a repository captured into, pruned,
      repacked and restored from reads back bit for bit, and every name in
      it is short, portable, unique without case and none Windows reserves,
      with nothing but plain files with one name -- run by `make test-cli`
      on the local filesystem (case-insensitive on macOS), and by CI on
      exFAT, FAT and an SMB share that ignores case. Where a filesystem has
      no record locks (FUSE) restate takes `flock` alone, and where it has
      no hard links the chunking key goes in place without one. **Every
      change to what a repository holds keeps to this**
- [ ] **Each system's `--quiesce`**: a capture read from a snapshot of the
      filesystem rather than from services paused one by one -- Volume
      Shadow Copy on Windows, APFS local snapshots on macOS, ZFS and UFS
      snapshots on the BSDs, ZFS on Linux too -- so everything is copied as
      it was at one moment
- [ ] **Each system's metadata**: NTFS ACLs (security descriptors) and
      alternate data streams; macOS extended attributes (read and restored
      already) and Full Disk Access, which restate needs to be granted to read
      what macOS protects, said plainly when it has not been; BSD file flags
      (`chflags`: `schg`, `uchg`, `nodump` and the rest), recorded and set
      again last, since an immutable flag set early would refuse the rest of
      the restore. NFSv4 and macOS ACLs are above, under putting it back
- [ ] **Windows** (on hold): paths compared without case, as NTFS does, so
      two paths captured elsewhere that differ only in case are said to
      collide rather than one overwriting the other; long paths, past
      `MAX_PATH`, through the `\\?\` prefix; and a Windows build of restate
      itself. More a second program than a port: what makes a Windows
      machine different from a fresh install is in the component store, the
      MSI and AppX databases, winget and the registry rather than in package
      managers' file lists; it is rebuilt with unattend.xml and winget rather
      than an autoinstall file; and it has no POSIX owners, modes or
      fork/exec. It shares the repository format (kept free of Unix's
      assumptions for it, above), the tar and gzip code and the index

## Then — other processor architectures

restate is portable C that links only libc, built and tested on amd64 and
aarch64 natively and on the others under QEMU:

- [x] **arm64** (aarch64), **ppc64le**, **riscv64** and **s390x**
      (big-endian): built and the unit and end-to-end tests run on each in
      CI, natively for aarch64 and in an Ubuntu container under QEMU for the
      rest; then `tests/cli/cross.sh` has each read what the amd64 build
      wrote -- an image, a repository both capture into, prune and check, an
      encrypted one -- and the other way round, so s390x proves every
      on-disk format the same bytes whichever byte order wrote it. (QEMU's
      s390x `fstat` drops nanoseconds, where `lstat` and `statx` keep them;
      the tests allow for it there and nowhere else)
- [x] **Each architecture's names**: the kernel's, Debian's (`arm64`,
      `ppc64el`), RPM's and each BSD's, and an ELF header's machine number,
      mapped to one another in one table (`src/arch.c`); a machine
      description records restate's own spelling (`arch`) beside the
      kernel's, and `baseline fetch --arch` fetches each package's build for
      another processor, through the `binary-ARCH` lists of Ubuntu's ports
      archive where that is where they are
- [x] **The installer and the boot underneath**: `installer --arch`; the
      boot each processor uses -- GRUB from the ESP on arm64 and riscv64, a
      PReP partition for POWER's Open Firmware, petitboot's none, zipl on
      s390x -- recorded (the firmware mode, GRUB's platforms, zipl) and
      rebuilt, the partition one needs taking the place of another's; the
      VM QEMU's machine for the processor; and IBM Z's DASD and zFCP disks
      recorded by their addresses, brought online with `chzdev`, a DASD
      formatted with `dasdfmt` and partitioned with `fdasd` (curtin's
      `vtoc`)
- [x] **A capture moved across architectures**: `buildsheet` and
      `autoinstall --arch`, with the packages reinstalled as the new
      processor's builds by name; capture records the processor of every
      ELF program it keeps, the build sheet names those no package installed
      as needing a rebuild, and restore leaves a changed program of a
      package as the new machine's package has it, warning of the rest

## Packaging

- [x] A Launchpad PPA for Ubuntu (`ppa:bceverly/restate`): 22.04, 24.04 and
      26.04, from signed source packages the release workflow uploads once
      the package has installed on clean Ubuntu; `make deb`, `deb-source`
      and `deb-sbuild` by hand
- [x] Binary packages for every supported release of FreeBSD, OpenBSD and
      NetBSD on each release, built in that release's VM with its own package
      tool from the release's tarball, installed, checked and removed there
      first; `make bsd-pkg` by hand
- [x] RPMs for Fedora, RHEL 9 and 10 and their rebuilds, and openSUSE: one
      spec, built for each release and architecture in a bare container,
      installed and removed in a fresh one, and attached to the release;
      Fedora COPR and the openSUSE Build Service build it for every release
      they have; `make rpm` by hand
- [x] Alpine packages for every supported release, built with abuild,
      installed and removed there first; `make apk` by hand
- [x] A Homebrew formula in the `bceverly/homebrew-tap` tap, installed from
      source, tested and audited on macOS before each release's goes there
- [ ] FreeBSD port, OpenBSD port, NetBSD pkgsrc, and Homebrew's own core tap
- [ ] Debian itself, as against Ubuntu's PPA, and Arch (the AUR)

## Later

- [ ] A content-addressed store shared between machines, so identical files on
      a fleet are kept once
- [x] What a fleet manager -- SysManage among them -- needs to drive restate
      (2.0, above); the scheduling, a fleet view of drift and bare-metal
      recovery from a boot image are the fleet manager's to build on it
- [ ] Keyed chunk ids, so that a store shared between machines tells no one
      sharing it what another holds -- for the shared store above
