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

## Next — knowing the baseline

- [ ] **Package-manager comparison.** Read dpkg's md5sums (Debian, Ubuntu),
      `rpm -V` data, `pkg check -s` (FreeBSD), `pkg_check` (OpenBSD) and
      pkgsrc's `+CONTENTS`, and keep a baseline file's content only when it no
      longer matches what its package shipped. This is what makes an image of
      a whole machine small.
- [ ] **The package list.** Record the explicitly installed packages and their
      exact versions (`apt-mark showmanual`, `pkg prime-list`,
      `pkg_info -m`), snaps and their channels, flatpaks.
- [ ] Extended attributes, POSIX ACLs and file capabilities.
- [ ] Hard links kept as links (the index already records device and inode).
- [ ] Users and groups: `passwd`/`group` entries the image's owners depend on.

## Then — putting it back

- [ ] **`restore`**: onto a freshly installed system, reinstall the recorded
      packages at their recorded versions, remove what the baseline had and
      the machine did not, lay down the kept content, and restore owners —
      mapped by *name*, since a reinstall may number them differently — modes,
      times and attributes.
- [ ] `status`: what has changed since the last capture, quickly, from mtimes.
- [ ] Storage layout: partitions, LVM, LUKS, RAID, filesystems and mount
      options, enough to recreate the disk before restoring onto it.
- [ ] Boot configuration: bootloader, kernel parameters, enabled services.

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
