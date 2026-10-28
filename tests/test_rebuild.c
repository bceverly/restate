/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "autoinstall.h"
#include "buildsheet.h"
#include "clones.h"
#include "cmd.h"
#include "json.h"
#include "layout.h"
#include "packages.h"
#include "test.h"

/*
 * A server with everything: UEFI with Secure Boot, a LUKS2 partition (TPM
 * token, key file) holding an LVM group with root and swap, an md RAID1 of
 * two more disks holding XFS, and on the third disk btrfs, exFAT and an
 * unknown filesystem; NFS, a swap file, and a USB stick that is not part of
 * the machine.
 */
/* In pieces: one literal would pass the 4095 characters ISO C promises. */
static const char *const server_json[] = {
    "{\"notes\": [\"something was not readable\"],"
    " \"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\", \"version\": \"26.04.1 LTS\","
    "   \"pretty_name\": \"Ubuntu 26.04.1 LTS\", \"architecture\": \"x86_64\", \"hostname\": "
    "\"web01\","
    "   \"type\": \"server\", \"type_evidence\": \"no desktop\", \"virtualization\": \"none\","
    "   \"locale\": \"en_GB.UTF-8\", \"keyboard_layout\": \"gb\", \"keyboard_variant\": \"extd\","
    "   \"timezone\": \"Europe/London\", \"ssh_server\": true,"
    "   \"users\": [{\"name\": \"sam\", \"uid\": 1001, \"gecos\": \"\"},"
    "     {\"name\": \"Bad Name\", \"uid\": 900},"
    "     {\"name\": \"pat\", \"uid\": 1000, \"gecos\": \"Pat Smith,,,\"}],"
    "   \"hardware_packages\": [\"mdadm\", \"intel-microcode\"], \"guest_packages\": []},"
    " \"hardware\": {\"sys_vendor\": \"Example\", \"product_name\": \"Box 1\", \"cpu\": \"Fast "
    "CPU\","
    "   \"cpus\": 16, \"memory\": 34359738368,"
    "   \"network\": [{\"name\": \"eno1\", \"mac\": \"52:54:00:00:00:01\"},"
    "                {\"name\": \"wlp2s0\", \"mac\": \"52:54:00:00:00:02\"},"
    "                {\"name\": \"eno2\"}]},"
    " \"firmware\": {\"mode\": \"uefi\", \"secure_boot\": true, \"boot_loaders\": [\"grub\"]},"
    " \"disks\": ["
    "  {\"name\": \"sda\", \"size\": 107374182400, \"logical_block_size\": 512, \"model\": \"Disk "
    "A\","
    "   \"serial\": \"SN-A\", \"table\": {\"type\": \"gpt\", \"uuid\": \"table-a\"},"
    "   \"partitions\": ["
    "    {\"name\": \"sda1\", \"number\": 1, \"start\": 1048576, \"size\": 536870912,"
    "     \"type\": \"c12a7328-f81f-11d2-ba4b-00a0c93ec93b\", \"uuid\": \"p-a1\", \"label\": \"EFI "
    "\\\"System\\\"\","
    "     \"flags\": \"0x8000000000000005\","
    "     \"content\": {\"type\": \"vfat\", \"usage\": \"filesystem\", \"uuid\": \"ABCD-1234\", "
    "\"version\": \"FAT32\", \"label\": \"ESP\"}},"
    "    {\"name\": \"sda2\", \"number\": 2, \"start\": 537919488, \"size\": 1073741824,",
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\", \"uuid\": \"p-a2\","
    "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"boot-uuid\", "
    "\"label\": \"boot\"}},"
    "    {\"name\": \"sda3\", \"number\": 3, \"start\": 1611661312, \"size\": 105000000000,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\", \"uuid\": \"p-a3\","
    "     \"content\": {\"type\": \"crypto_LUKS\", \"usage\": \"crypto\", \"uuid\": \"luks-uuid\", "
    "\"version\": \"2\"},"
    "     \"luks\": {\"version\": 2, \"cipher\": \"aes-xts-plain64\", \"key_size\": 512,"
    "               \"tokens\": [{\"type\": \"systemd-tpm2\"}]}}]},"
    "  {\"name\": \"sdb\", \"size\": 21474836480, \"logical_block_size\": 512, \"rotational\": "
    "true,"
    "   \"table\": {\"type\": \"gpt\"},"
    "   \"partitions\": ["
    "    {\"name\": \"sdb1\", \"number\": 1, \"start\": 1048576, \"size\": 10737418240,"
    "     \"type\": \"a19d880f-05fc-4d3b-a006-743f0f84911e\","
    "     \"content\": {\"type\": \"linux_raid_member\", \"usage\": \"raid\"}},"
    "    {\"name\": \"sdb2\", \"number\": 2, \"start\": 10738466816, \"size\": 2147483648,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"btrfs\", \"usage\": \"filesystem\", \"uuid\": \"btrfs-uuid\", "
    "\"label\": \"data\"}},"
    "    {\"name\": \"sdb3\", \"number\": 3, \"start\": 12885950464, \"size\": 1073741824,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"exfat\", \"usage\": \"filesystem\", \"uuid\": \"1063-C485\", "
    "\"label\": \"x\"}},"
    "    {\"name\": \"sdb4\", \"number\": 4, \"start\": 13959692288, \"size\": 1073741824,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"f2fs\", \"usage\": \"filesystem\", \"uuid\": \"f2fs-uuid\"}},",
    "    {\"name\": \"sdb5\", \"number\": 5, \"start\": 15033434112, \"size\": 1073741824,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"xfs\", \"usage\": \"filesystem\", \"uuid\": \"xfs-uuid2\", "
    "\"label\": \"scratch\"}},"
    "    {\"name\": \"sdb6\", \"number\": 6, \"start\": 16107175936, \"size\": 1073741824,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"swap\", \"usage\": \"other\", \"uuid\": \"swap-uuid2\", "
    "\"label\": \"sw\"}},"
    "    {\"name\": \"sdb7\", \"number\": 7, \"start\": 17180917760, \"size\": 1073741824,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"ext3\", \"usage\": \"filesystem\"}}]},"
    "  {\"name\": \"sdc\", \"size\": 10737418240, \"logical_block_size\": 512,"
    "   \"table\": {\"type\": \"gpt\"},"
    "   \"partitions\": ["
    "    {\"name\": \"sdc1\", \"number\": 1, \"start\": 1048576, \"size\": 10737418240,"
    "     \"type\": \"a19d880f-05fc-4d3b-a006-743f0f84911e\","
    "     \"content\": {\"type\": \"linux_raid_member\", \"usage\": \"raid\"}}]},"
    "  {\"name\": \"sdz\", \"size\": 8000000000, \"removable\": true, \"table\": {\"type\": "
    "\"dos\"},"
    "   \"partitions\": [{\"name\": \"sdz1\", \"number\": 1, \"start\": 1048576, \"size\": "
    "7000000000,"
    "     \"type\": \"0x0c\", \"content\": {\"type\": \"vfat\", \"usage\": \"filesystem\"}}]},"
    "  {\"name\": \"nvme9n1\", \"size\": 1000000000, \"content\": {\"type\": \"LVM2_member\", "
    "\"usage\": \"raid\"}},"
    "  {\"size\": 5}],"
    " \"mapped\": ["
    "  {\"device\": \"dm-0\", \"name\": \"sda3_crypt\", \"kind\": \"luks\", \"devices\": "
    "[\"sda3\"],",
    "   \"content\": {\"type\": \"LVM2_member\", \"usage\": \"raid\"}},"
    "  {\"device\": \"dm-1\", \"name\": \"vg0-root\", \"kind\": \"lvm\", \"devices\": [\"dm-0\"],"
    "   \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"root-uuid\"}},"
    "  {\"device\": \"dm-2\", \"name\": \"vg0-swap\", \"kind\": \"lvm\", \"devices\": [\"dm-0\"],"
    "   \"content\": {\"type\": \"swap\", \"usage\": \"other\", \"uuid\": \"swap-uuid\"}},"
    "  {\"device\": \"dm-3\", \"name\": \"plain0\", \"kind\": \"crypt\", \"devices\": [\"sdb7\"]},"
    "  {\"device\": \"dm-4\", \"name\": \"odd-name\", \"kind\": \"lvm\"},"
    "  {\"kind\": \"luks\"}],"
    " \"raid\": [{\"device\": \"md0\", \"level\": \"raid1\", \"metadata\": \"1.2\", \"uuid\": "
    "\"aa:bb:cc:dd\","
    "   \"chunk_size\": 524288, \"devices\": [\"sdb1\", \"sdc1\", 7],"
    "   \"content\": {\"type\": \"xfs\", \"usage\": \"filesystem\", \"uuid\": \"xfs-uuid\"}}, {}],"
    " \"mounts\": ["
    "  {\"mountpoint\": \"/\", \"source\": \"/dev/mapper/vg0-root\", \"size\": 53687091200, "
    "\"used\": 4294967296},"
    "  {\"mountpoint\": \"/srv\", \"source\": \"/dev/md0\", \"size\": 10000000000, \"used\": "
    "1000000000},"
    "  {\"mountpoint\": \"/data\", \"source\": \"/dev/sdb2\", \"size\": 2000000000, \"used\": "
    "100}],"
    " \"fstab\": ["
    "  {\"spec\": \"/dev/mapper/vg0-root\", \"file\": \"/\", \"type\": \"ext4\", \"options\": "
    "\"errors=remount-ro\"},"
    "  {\"spec\": \"UUID=boot-uuid\", \"file\": \"/boot\", \"type\": \"ext4\", \"options\": "
    "\"defaults\"},"
    "  {\"spec\": \"LABEL=ESP\", \"file\": \"/boot/efi\", \"type\": \"vfat\", \"options\": "
    "\"umask=0077\"},"
    "  {\"spec\": \"/dev/disk/by-uuid/xfs-uuid\", \"file\": \"/srv\", \"type\": \"xfs\"},"
    "  {\"spec\": \"UUID=swap-uuid\", \"file\": \"none\", \"type\": \"swap\"},"
    "  {\"spec\": \"PARTUUID=nope\", \"file\": \"/nowhere\", \"type\": \"ext4\"},",
    "  {\"spec\": \"nas:/export\", \"file\": \"/mnt/nas\", \"type\": \"nfs4\", \"options\": "
    "\"_netdev\"},"
    "  {\"spec\": \"//nas/share\", \"file\": \"/mnt/share\", \"type\": \"cifs\"},"
    "  {\"spec\": \"tmpfs\", \"file\": \"/tmp\", \"type\": \"tmpfs\"}],"
    " \"crypttab\": [{\"name\": \"sda3_crypt\", \"device\": \"UUID=luks-uuid\", \"keyfile\": "
    "\"/etc/keys/root.key\"},"
    "               {\"name\": \"plain0\", \"device\": \"/dev/sdb7\", \"keyfile\": \"none\"}],"
    " \"swap\": [{\"file\": \"/swapfile\", \"type\": \"file\", \"size\": 2147483648},"
    "          {\"file\": \"/dev/dm-2\", \"type\": \"partition\", \"size\": 1}]"
    "}",
};

static const char lvm_vg0[] =
    "contents = \"Text Format Volume Group\"\n"
    "vg0 {\n"
    "\tid = \"vg-uuid\"\n"
    "\textent_size = 8192\n"
    "\tphysical_volumes {\n"
    "\t\tpv0 {\n\t\t\tid = \"pv-uuid\"\n\t\t\tdevice = \"/dev/mapper/sda3_crypt\"\n\t\t}\n"
    "\t}\n"
    "\tlogical_volumes {\n"
    "\t\troot {\n\t\t\tsegment1 {\n\t\t\t\textent_count = 12800\n\t\t\t}\n"
    "\t\t\tsegment2 {\n\t\t\t\textent_count = 100\n\t\t\t}\n\t\t}\n"
    "\t\tswap {\n\t\t\tsegment1 {\n\t\t\t\textent_count = 256\n\t\t\t}\n\t\t}\n"
    "\t\told {\n\t\t\tsegment1 {\n\t\t\t\textent_count = 10\n\t\t\t}\n\t\t}\n"
    "\t}\n"
    "}";

/* A group on a PV recorded under a name no device has any more. */
static const char lvm_far[] =
    "far-vg {\n"
    "\textent_size = 8192\n"
    "\tphysical_volumes {\n\t\tpv0 {\n\t\t\tid = \"x\"\n\t\t\tdevice = \"/dev/gone\"\n\t\t}\n\t}\n"
    "\tlogical_volumes {\n\t\tthin-pool {\n\t\t\tsegment1 {\n\t\t\t\textent_count = 1\n"
    "\t\t\t\ttype = \"thin-pool\"\n\t\t\t}\n\t\t}\n\t}\n"
    "}";

/* A BIOS guest on an MBR disk, moving to real hardware. */
static const char guest_json[] =
    "{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"24.04\", \"version\": \"24.04 LTS\","
    "   \"architecture\": \"aarch64\", \"type\": \"server\", \"virtualization\": \"kvm\","
    "   \"guest_packages\": [\"qemu-guest-agent\"], \"hardware_packages\": []},"
    " \"hardware\": {\"network\": [{\"name\": \"enp1s0\", \"mac\": \"52:54:00:aa:bb:cc\"}]},"
    " \"firmware\": {\"mode\": \"bios\"},"
    " \"disks\": [{\"name\": \"vda\", \"size\": 21474836480, \"table\": {\"type\": \"dos\", "
    "\"uuid\": \"12345678\"},"
    "   \"partitions\": ["
    "    {\"name\": \"vda1\", \"number\": 1, \"start\": 1048576, \"size\": 20000000000, \"type\": "
    "\"0x83\","
    "     \"flags\": \"0x80\", \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", "
    "\"uuid\": \"g-root\"}},"
    "    {\"name\": \"vda2\", \"number\": 2, \"start\": 20001048576, \"size\": 1073741824, "
    "\"type\": \"0x82\","
    "     \"content\": {\"type\": \"swap\", \"usage\": \"other\", \"uuid\": \"g-swap\"}}]},"
    "   {\"name\": \"vdb\", \"size\": 10737418240, \"content\": {\"type\": \"ext4\", \"usage\": "
    "\"filesystem\","
    "     \"uuid\": \"g-data\"}}],"
    " \"fstab\": [{\"spec\": \"UUID=g-root\", \"file\": \"/\", \"type\": \"ext4\", \"options\": "
    "\"defaults\"},"
    "            {\"spec\": \"UUID=g-swap\", \"file\": \"none\", \"type\": \"swap\"},"
    "            {\"spec\": \"/dev/vdb\", \"file\": \"/data\", \"type\": \"ext4\"}]"
    "}";

/* Dual boot: Windows, BitLocker, recovery, a VeraCrypt container, macOS. */
static const char dual_json[] =
    "{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\", \"architecture\": \"x86_64\","
    "   \"type\": \"desktop\", \"hostname\": \"lap\"},"
    " \"firmware\": {\"mode\": \"uefi\"},"
    " \"disks\": [{\"name\": \"nvme0n1\", \"size\": 500107862016, \"table\": {\"type\": \"gpt\"},"
    "   \"partitions\": ["
    "    {\"name\": \"nvme0n1p1\", \"number\": 1, \"start\": 1048576, \"size\": 104857600,"
    "     \"type\": \"C12A7328-F81F-11D2-BA4B-00A0C93EC93B\","
    "     \"content\": {\"type\": \"vfat\", \"usage\": \"filesystem\", \"uuid\": \"AAAA-BBBB\"}},"
    "    {\"name\": \"nvme0n1p2\", \"number\": 2, \"start\": 105906176, \"size\": 16777216,"
    "     \"type\": \"e3c9e316-0b5c-4db8-817d-f92df00215ae\"},"
    "    {\"name\": \"nvme0n1p3\", \"number\": 3, \"start\": 122683392, \"size\": 200000000000,"
    "     \"type\": \"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7\","
    "     \"content\": {\"type\": \"BitLocker\", \"usage\": \"crypto\"}},"
    "    {\"name\": \"nvme0n1p4\", \"number\": 4, \"start\": 200122683392, \"size\": 100000000000,"
    "     \"type\": \"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7\"},"
    "    {\"name\": \"nvme0n1p5\", \"number\": 5, \"start\": 300122683392, \"size\": 100000000000,"
    "     \"type\": \"7c3457ef-0000-11aa-aa11-00306543ecac\"},"
    "    {\"name\": \"nvme0n1p6\", \"number\": 6, \"start\": 400122683392, \"size\": 99000000000,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"lap-root\"}}]}],"
    " \"mapped\": [{\"device\": \"dm-0\", \"name\": \"veracrypt1\", \"kind\": \"other\", "
    "\"devices\": [\"nvme0n1p4\"],"
    "   \"content\": {\"type\": \"exfat\", \"usage\": \"filesystem\"}}],"
    " \"fstab\": [{\"spec\": \"UUID=lap-root\", \"file\": \"/\", \"type\": \"ext4\"},"
    "            {\"spec\": \"UUID=AAAA-BBBB\", \"file\": \"/boot/efi\", \"type\": \"vfat\"}]"
    "}";

/* A package inventory with one of everything the build sheet handles. */
static const char *const packages_json[] = {
    "{\"managers\": [{\"name\": \"apt\", \"inventory\": true},"
    "  {\"name\": \"nix\", \"inventory\": false, \"where\": [\"/nix/store\"]}],"
    " \"apt\": {\"architectures\": [\"amd64\", \"i386\"],"
    "  \"keys\": [{\"path\": \"/etc/apt/keyrings/local.gpg\", \"data\": \"AAAA\"},"
    "   {\"path\": \"/usr/share/keyrings/vendor.gpg\", \"data\": \"dmVuZG9yIGtleQ==\"},"
    "   {\"path\": \"/usr/share/keyrings/ubuntu-archive-keyring.gpg\", \"data\": \"AAAA\"},"
    "   {\"path\": \"/usr/share/keyrings/odd.gpg\", \"data\": \"not base64!\"},"
    "   {\"path\": \"/usr/share/keyrings/gone.gpg\", \"missing\": true},"
    "   {\"data\": \"AAAA\"}],",
    "  \"packages\": ["
    "   {\"name\": \"vim\", \"architecture\": \"amd64\", \"version\": \"2:9.1-1\", \"manual\": "
    "true,"
    "    \"origins\": [\"http://archive stable/main\"]},"
    "   {\"name\": \"libfoo\", \"architecture\": \"i386\", \"version\": \"1.0~rc1\", \"manual\": "
    "true,"
    "    \"origins\": [\"x\"], \"hold\": true},"
    "   {\"name\": \"tzdata\", \"architecture\": \"all\", \"version\": \"2026a\", \"manual\": true,"
    "    \"origins\": [\"x\"]},"
    "   {\"name\": \"evil\", \"architecture\": \"amd64\", \"version\": \"1$(reboot)'\", "
    "\"manual\": true,"
    "    \"origins\": [\"x\"]},"
    "   {\"name\": \"dep\", \"architecture\": \"amd64\", \"version\": \"1\", \"manual\": false,"
    "    \"origins\": [\"x\"]},"
    "   {\"name\": \"intel-microcode\", \"architecture\": \"amd64\", \"version\": \"3\","
    "    \"manual\": true, \"origins\": [\"x\"]},"
    "   {\"name\": \"zoom\", \"architecture\": \"amd64\", \"version\": \"6.7\", \"manual\": true,"
    "    \"origins\": [], \"unavailable\": \"local\"},"
    "   {\"name\": \"oldie\", \"architecture\": \"amd64\", \"version\": \"1.0\", \"manual\": true,"
    "    \"origins\": [], \"unavailable\": \"superseded\"},"
    "   {\"name\": \"chef\", \"architecture\": \"amd64\", \"version\": \"18\", \"manual\": true,"
    "    \"origins\": [], \"unavailable\": \"local\","
    "    \"kept\": \"/var/cache/apt/archives/chef_18_amd64.deb\"},"
    "   {\"name\": \"grub-pc\", \"architecture\": \"amd64\", \"version\": \"2\", \"manual\": true,"
    "    \"origins\": [\"x\"]},"
    "   {\"name\": \"noversion\", \"architecture\": \"amd64\", \"manual\": true},"
    "   {\"architecture\": \"amd64\", \"manual\": true}]},",
    " \"snap\": [{\"name\": \"firefox\", \"revision\": \"1\", \"channel\": \"latest/stable\","
    "   \"type\": \"app\"},"
    "  {\"name\": \"code\", \"type\": \"app\", \"classic\": true, \"devmode\": true,"
    "   \"disabled\": true, \"channel\": \"latest/edge\"},"
    "  {\"name\": \"core22\", \"type\": \"base\"}, {\"name\": \"core24\"}, {\"name\": \"bare\"},"
    "  {\"name\": \"lxd\"}, {\"name\": \"mine\", \"revision\": \"x1\", \"local\": true},"
    "  {\"name\": \"what\", \"local\": true}, {\"type\": \"app\"},"
    "  {\"name\": \"asana\", \"revision\": \"x1\", \"local\": true,"
    "   \"kept\": \"/var/lib/snapd/snaps/asana_x1.snap\"}],"
    " \"alternatives\": [{\"name\": \"java\", \"path\": \"/usr/lib/jvm/21/bin/java\"},"
    "  {\"name\": \"nopath\"}],",
    " \"flatpak\": {\"remotes\": [{\"name\": \"flathub\", \"url\": "
    "\"https://dl.flathub.org/repo/\","
    "   \"scope\": \"system\"}, {\"name\": \"mine\", \"url\": \"https://x/repo\","
    "   \"scope\": \"user /home/pat\"}, {\"name\": \"nourl\"}],"
    "  \"apps\": [{\"id\": \"org.example.App\", \"branch\": \"stable\", \"remote\": \"flathub\","
    "   \"scope\": \"system\"}, {\"id\": \"com.example.Mine\", \"branch\": \"master\","
    "   \"remote\": \"mine\", \"scope\": \"user /home/pat\"},"
    "   {\"id\": \"org.example.Lone\", \"branch\": \"stable\"}, {\"id\": \"no.branch\"}]},",
    " \"pip\": [{\"name\": \"requests\", \"version\": \"2.31.0\","
    "   \"where\": \"/usr/local/lib/python3.12/dist-packages\"},"
    "  {\"name\": \"httpie\", \"version\": \"3.2\","
    "   \"where\": \"/home/pat/.local/lib/python3.13/site-packages\"}, {\"name\": \"nowhere\"}],"
    " \"npm\": [{\"name\": \"npm\", \"version\": \"10\", \"where\": \"/usr/lib/node_modules\"},"
    "  {\"name\": \"left-pad\", \"version\": \"1.3.0\", \"where\": "
    "\"/usr/local/lib/node_modules\"}],"
    " \"pipx\": [{\"name\": \"black\", \"where\": \"/home/pat/.local/share/pipx/venvs\"}],"
    " \"cargo\": [{\"name\": \"ripgrep\", \"version\": \"14.1.0\", \"where\": \"/root\","
    "   \"source\": \"registry+https://github.com/rust-lang/crates.io-index\"},"
    "  {\"name\": \"mytool\", \"version\": \"0.1.0\", \"where\": \"/root\","
    "   \"source\": \"git+https://example.com/mytool\"}],"
    " \"gem\": [{\"name\": \"rake\", \"version\": \"13.0.6\","
    "   \"where\": \"/var/lib/gems/3.2.0/specifications\"}], \"notes\": []}",
    NULL
};

static void parse(const char *text, struct rs_jval *out)
{
    struct rs_json_parser jp;
    struct rs_buf         err;

    rs_buf_init(&err);
    memset(out, 0, sizeof(*out));
    rs_json_init(&jp, text, strlen(text), &err);
    if (!rs_json_value(&jp, out))
    {
        rs_test_fail(__FILE__, __LINE__, "fixture does not parse: %s", err.data ? err.data : "");
    }
    rs_buf_free(&err);
}

static void server(struct rs_jval *m)
{
    struct rs_jval *lvm;
    struct rs_jval *vg;

    {
        struct rs_buf text;
        size_t        i;

        rs_buf_init(&text);
        for (i = 0; i < sizeof(server_json) / sizeof(server_json[0]); i++)
        {
            rs_buf_addstr(&text, server_json[i]);
        }
        parse(text.data, m);
        rs_buf_free(&text);
    }
    lvm = rs_jobj_add(m, "lvm");
    rs_jval_set_array(lvm);
    vg = rs_jarr_add(lvm);
    rs_jval_set_object(vg);
    rs_jobj_str(vg, "name", "vg0");
    rs_jobj_str(vg, "metadata", lvm_vg0);
    vg = rs_jarr_add(lvm);
    rs_jval_set_object(vg);
    rs_jobj_str(vg, "name", "notthename");
    rs_jobj_str(vg, "metadata", lvm_far);
    vg = rs_jarr_add(lvm);
    rs_jval_set_object(vg);
    rs_jobj_str(vg, "name", "lost");
    rs_jobj_str(vg, "metadata", "lost {\n\tphysical_volumes {\n\t\tpv0 {\n\t\t\tdevice = "
                                "\"/dev/gone2\"\n"
                                "\t\t}\n\t}\n}\n");
    vg = rs_jarr_add(lvm);
    rs_jval_set_object(vg);
    rs_jobj_str(vg, "name", "broken");
    rs_jobj_str(vg, "metadata", "vg {");
    vg = rs_jarr_add(lvm);
    rs_jval_set_object(vg);
    rs_jobj_str(vg, "name", "nometa");
}

/* Whether the sheets are for an image from before 1.1, in one stream. */
static bool old_layout;

static char *sheet_with(const struct rs_jval *m, enum rs_target t, const char *image,
                        const struct rs_jval *packages)
{
    struct rs_sheet_opts o;
    struct rs_buf        out;
    struct rs_buf        err;

    memset(&o, 0, sizeof(o));
    o.target = t;
    o.image = image;
    o.version = "9.9";
    o.packages = packages;
    o.old_image = old_layout;
    rs_buf_init(&out);
    rs_buf_init(&err);
    CHECK(rs_buildsheet(m, &o, &out, &err));
    rs_buf_free(&err);
    return rs_buf_detach(&out);
}

static char *sheet(const struct rs_jval *m, enum rs_target t, const char *image)
{
    return sheet_with(m, t, image, NULL);
}

static char *autoinst_with(const struct rs_jval *m, enum rs_target t,
                           const struct rs_jval *packages, const char *image_at)
{
    struct rs_auto_opts o;
    struct rs_buf       out;
    struct rs_buf       err;

    memset(&o, 0, sizeof(o));
    o.target = t;
    o.image = NULL;
    o.version = "9.9";
    o.packages = packages;
    o.image_at = image_at;
    o.old_image = old_layout;
    rs_buf_init(&out);
    rs_buf_init(&err);
    CHECK(rs_autoinstall(m, &o, &out, &err));
    rs_buf_free(&err);
    return rs_buf_detach(&out);
}

static char *autoinst(const struct rs_jval *m, enum rs_target t)
{
    return autoinst_with(m, t, NULL, NULL);
}

static void layout_cases(void)
{
    struct rs_jval   m;
    struct rs_layout l;
    size_t           v;
    char             buf[32];

    server(&m);
    TEST_CASE("layout: the graph from a description");
    CHECK(rs_layout_build(&m, &l));
    CHECK_INT(l.ndisks, 6);
    v = rs_layout_find(&l, "vg0-root");
    CHECK(v != SIZE_MAX);
    CHECK_STR(l.vols[v].path, "/dev/vg0/root");
    CHECK_STR(l.vols[v].lvname, "root");
    CHECK_STR(l.vols[v].mountpoint, "/");
    CHECK_INT(l.vols[v].size, (uint64_t)12900 * 8192 * 512);
    CHECK_INT(l.vols[v].nparents, 1);
    CHECK_STR(l.vols[l.vols[v].parents[0]].name, "sda3_crypt");
    v = rs_layout_find(&l, "sda3_crypt");
    CHECK_STR(l.vols[v].cipher, "aes-xts-plain64");
    CHECK(l.vols[v].tpm);
    CHECK_STR(l.vols[v].keyfile, "/etc/keys/root.key");
    CHECK(rs_layout_find(&l, "dm-0") == v);
    v = rs_layout_find(&l, "old");
    CHECK(v != SIZE_MAX && l.vols[v].kind == RS_VOL_LV);
    CHECK_STR(rs_layout_find(&l, "md0") != SIZE_MAX ? l.vols[rs_layout_find(&l, "md0")].mountpoint
                                                    : NULL,
              "/srv");
    CHECK_STR(l.vols[rs_layout_find(&l, "vg0-swap")].mountpoint, "[swap]");
    CHECK_STR(l.vols[rs_layout_find(&l, "sda1")].mountpoint, "/boot/efi");
    CHECK(l.vols[rs_layout_find(&l, "sdz1")].foreign);
    CHECK(l.vols[rs_layout_find(&l, "nvme9n1")].kind == RS_VOL_DISK);
    CHECK_INT(l.nnetmounts, 2);
    CHECK_INT(l.nswapfiles, 1);
    CHECK_INT(l.nvgs, 3);
    CHECK(l.vgs[1].pvs[0].vol == rs_layout_find(&l, "nvme9n1"));
    CHECK(l.vgs[2].pvs[0].vol == SIZE_MAX);
    CHECK_STR(l.vgs[1].name, "far-vg");
    CHECK(l.secure_boot);
    CHECK(rs_layout_find(&l, NULL) == SIZE_MAX);
    CHECK(rs_layout_find(&l, "nonexistent") == SIZE_MAX);

    TEST_CASE("layout: sizes for a virtual machine");
    v = rs_layout_find(&l, "vg0-root");
    CHECK(rs_layout_fit(&l, v, RS_TARGET_VM) == (uint64_t)7 * 1024 * 1024 * 1024);
    CHECK(rs_layout_fit(&l, v, RS_TARGET_SAME) == l.vols[v].size);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sdz1"), RS_TARGET_VM) == 0);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sdz1"), RS_TARGET_SAME) == 7000000000);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sda1"), RS_TARGET_VM) == 536870912);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sda3"), RS_TARGET_VM) < 105000000000);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sdb1"), RS_TARGET_VM) > 0);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sdb2"), RS_TARGET_VM) ==
          (uint64_t)2 * 1024 * 1024 * 1024);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "sdb6"), RS_TARGET_VM) == 1073741824);
    CHECK(rs_layout_fit(&l, rs_layout_find(&l, "nvme9n1"), RS_TARGET_VM) == 12 * 1024 * 1024);

    TEST_CASE("layout: what an index records beats what the disk used");
    {
        struct rs_jval   c;
        struct rs_layout cl;

        parse("{\"disks\": [{\"name\": \"sda\", \"size\": 107374182400, \"table\": {\"type\": "
              "\"gpt\"},"
              " \"partitions\": [{\"name\": \"sda1\", \"number\": 1, \"start\": 1048576, \"size\": "
              "100000000000,"
              " \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"u\"}}]}],"
              " \"mounts\": [{\"mountpoint\": \"/\", \"source\": \"/dev/sda1\", \"size\": "
              "99000000000,"
              " \"used\": 90000000000, \"captured\": 0}]}", &c);
        CHECK(rs_layout_build(&c, &cl));
        CHECK(cl.vols[0].captured_known);
        CHECK(rs_layout_fit(&cl, 0, RS_TARGET_VM) == (uint64_t)2 * 1024 * 1024 * 1024);
        rs_layout_free(&cl);
        rs_jval_free(&c);
    }

    TEST_CASE("layout: names and sizes for people");
    CHECK_STR(rs_ptype_name("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"), "EFI system");
    CHECK_STR(rs_ptype_name("0x83"), "Linux");
    CHECK(rs_ptype_name("nonsense") == NULL);
    CHECK(rs_ptype_name(NULL) == NULL);
    rs_human_size(5, buf, sizeof(buf));
    CHECK_STR(buf, "5 bytes");
    rs_human_size(1536, buf, sizeof(buf));
    CHECK_STR(buf, "1.5 KiB");
    rs_human_size((uint64_t)200 * 1024 * 1024, buf, sizeof(buf));
    CHECK_STR(buf, "200 MiB");
    rs_human_size(1024, buf, sizeof(buf));
    CHECK_STR(buf, "1 KiB");
    rs_layout_free(&l);
    rs_jval_free(&m);

    TEST_CASE("layout: a description with no disks");
    parse("{\"system\": {\"id\": \"ubuntu\"}}", &m);
    CHECK(!rs_layout_build(&m, &l));
    rs_layout_free(&l);
    rs_jval_free(&m);
}

static void sheet_cases(void)
{
    struct rs_jval m;
    char          *s;

    server(&m);
    TEST_CASE("buildsheet: the same machine");
    s = sheet(&m, RS_TARGET_SAME, "web01.tgz");
    CHECK_CONTAINS(s, "restate build sheet: web01");
    CHECK_CONTAINS(s, "UEFI, Secure Boot on");
    CHECK_CONTAINS(s, "restate installer fetch web01.tgz");
    CHECK_CONTAINS(s, "label-id: table-a");
    CHECK_CONTAINS(s, "sda1 : start=2048, size=1048576, type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    CHECK_CONTAINS(s, "name=\"EFI  System \", "
                      "attrs=\"RequiredPartition,LegacyBIOSBootable,GUID:63\"");
    CHECK_CONTAINS(s, "mkfs.vfat -F 32 -i ABCD1234 -n 'ESP' \"$(part \"$DISK1\" 1)\"");
    CHECK_CONTAINS(s, "mkfs.ext4 -F -U boot-uuid -L 'boot'");
    CHECK_CONTAINS(s, "cryptsetup luksFormat --batch-mode --type luks2 --uuid luks-uuid "
                      "--cipher aes-xts-plain64 --key-size 512");
    CHECK_CONTAINS(s, "cryptsetup open \"$(part \"$DISK1\" 3)\" sda3_crypt");
    CHECK_CONTAINS(s, "cat > /tmp/restate-vg0.vg <<'RESTATE_LVM_END'");
    CHECK_CONTAINS(s, "pvcreate --yes --uuid pv-uuid --restorefile /tmp/restate-vg0.vg "
                      "/dev/mapper/sda3_crypt");
    CHECK_CONTAINS(s, "vgcfgrestore -f /tmp/restate-vg0.vg vg0");
    CHECK_CONTAINS(s, "mkfs.ext4 -F -U root-uuid /dev/vg0/root");
    CHECK_CONTAINS(s, "mkswap -U swap-uuid /dev/vg0/swap");
    CHECK_CONTAINS(s, "mdadm --create /dev/md0 --run --level=raid1 --raid-devices=2 --metadata=1.2 "
                      "--uuid=aa:bb:cc:dd \"$(part \"$DISK2\" 1)\" \"$(part \"$DISK3\" 1)\"");
    CHECK_CONTAINS(s, "mkfs.xfs -f -m uuid=xfs-uuid /dev/md0");
    CHECK_CONTAINS(s, "mkfs.xfs -f -m uuid=xfs-uuid2 -L 'scratch'");
    CHECK_CONTAINS(s, "mkfs.btrfs -f -U btrfs-uuid -L 'data'");
    CHECK_CONTAINS(s, "mkfs.exfat -L 'x'");
    CHECK_CONTAINS(s, "mkswap -U swap-uuid2 -L 'sw'");
    CHECK_CONTAINS(s, "mkfs.ext3 -F \"$(part \"$DISK2\" 7)\"");
    CHECK_CONTAINS(s, "holds f2fs, which this sheet does not know how to recreate");
    CHECK_CONTAINS(s, "its subvolumes are not recorded");
    CHECK_CONTAINS(s, "whose volume serial mkfs.exfat cannot set");
    CHECK_CONTAINS(s, "Volume group lost: the devices its physical volumes were on are not in");
    CHECK_CONTAINS(s, "Custom storage layout");
    CHECK_CONTAINS(s, "/srv                   /dev/md0");
    CHECK_CONTAINS(s, "swap                   /dev/vg0/swap");
    CHECK_CONTAINS(s, "apt-get install -y nfs-common cifs-utils");
    CHECK_CONTAINS(s, "fallocate -l 2048M /swapfile");
    CHECK_CONTAINS(s, "systemd-cryptenroll --tpm2-device=auto /dev/disk/by-uuid/luks-uuid");
    CHECK_CONTAINS(s, "cryptsetup luksAddKey /dev/disk/by-uuid/luks-uuid /etc/keys/root.key");
    CHECK_CONTAINS(s, "mokutil --import");
    CHECK_CONTAINS(s, "tar -xOf web01.tgz restate/files.tar.gz | tar -xzpf - --numeric-owner");
    CHECK_CONTAINS(s, "/dev/sdz1 is a removable disk, not part of the machine");
    CHECK_CONTAINS(s, "/mnt/nas is mounted from nas:/export (nfs4)");
    CHECK_CONTAINS(s, "something was not readable");
    CHECK(strstr(s, "DISK4=") == NULL);
    free(s);

    TEST_CASE("buildsheet: as a virtual machine");
    s = sheet(&m, RS_TARGET_VM, NULL);
    CHECK_CONTAINS(s, "virt-install --name web01");
    CHECK_CONTAINS(s, "--machine q35");
    CHECK_CONTAINS(s, "--memory 8192 --vcpus 4");
    CHECK_CONTAINS(s, "The original had 32 GiB of memory and 16 CPUs");
    CHECK_CONTAINS(s, "--boot uefi");
    CHECK_CONTAINS(s, "--graphics none");
    CHECK_CONTAINS(s, "firmware.feature0.name=secure-boot");
    CHECK_CONTAINS(s, "ubuntu-26.04.1-live-server-amd64.iso");
    CHECK_CONTAINS(s, "DISK1=/dev/vda");
    CHECK_CONTAINS(s, "vda1 : size=512MiB");
    CHECK_CONTAINS(s, "pvcreate --yes /dev/mapper/sda3_crypt");
    CHECK_CONTAINS(s, "vgcreate vg0 /dev/mapper/sda3_crypt");
    CHECK_CONTAINS(s, "lvcreate --yes -n root -L 7168M vg0");
    CHECK_CONTAINS(s, "lvcreate --yes -n old -L 40M vg0");
    CHECK_CONTAINS(s, "pvcreate --yes \"$DISK5\"");
    CHECK_CONTAINS(s, "has a thin pool");
    CHECK_CONTAINS(s, "apt-get install -y qemu-guest-agent");
    CHECK_CONTAINS(s, "apt-get purge -y intel-microcode");
    CHECK(strstr(s, "purge -y mdadm") == NULL);
    CHECK_CONTAINS(s, "was eno1 (52:54:00:00:00:01)");
    CHECK_CONTAINS(s, "was eno2 (no MAC recorded)");
    CHECK_CONTAINS(s, "IMAGE.tar");
    free(s);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: a guest onto hardware");
    parse(guest_json, &m);
    s = sheet(&m, RS_TARGET_METAL, NULL);
    CHECK_CONTAINS(s, "a virtual machine (kvm)");
    CHECK_CONTAINS(s, "BIOS (legacy)");
    CHECK_CONTAINS(s, "legacy BIOS (CSM)");
    CHECK_CONTAINS(s, "DISK1=/dev/CHANGE-ME");
    CHECK_CONTAINS(s, "label: dos");
    CHECK_CONTAINS(s, "type=83, bootable");
    CHECK_CONTAINS(s, "mkfs.ext4 -F -U g-data \"$DISK2\"");
    CHECK_CONTAINS(s, "Install the boot loader to $DISK1 itself");
    CHECK_CONTAINS(s, "apt-get purge -y qemu-guest-agent");
    CHECK_CONTAINS(s, "intel-microcode");
    CHECK_CONTAINS(s, "Ubuntu 24.04 Server for arm64");
    free(s);
    s = sheet(&m, RS_TARGET_SAME, NULL);
    CHECK_CONTAINS(s, "label-id: 0x12345678");
    free(s);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: keeping another system on the disk");
    parse(dual_json, &m);
    s = sheet(&m, RS_TARGET_SAME, NULL);
    CHECK_CONTAINS(s, "B. The same disk, keeping the other system");
    CHECK_CONTAINS(s, "# new disk only: it holds the other system's boot loader too");
    CHECK_CONTAINS(s, "nvme0n1p3 is Windows (BitLocker)");
    CHECK_CONTAINS(s, "nvme0n1p4 is a device-mapper volume restate cannot recreate");
    CHECK_CONTAINS(s, "nvme0n1p5 is macOS");
    CHECK_CONTAINS(s, "Manual installation");
    free(s);
    s = sheet(&m, RS_TARGET_VM, NULL);
    CHECK(strstr(s, "B. The same disk") == NULL);
    CHECK_CONTAINS(s, "--memory 4096 --vcpus 2");
    CHECK(strstr(s, "The original had") == NULL);
    CHECK(strstr(s, "Windows") == NULL || strstr(s, "not rebuilt"));
    free(s);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: what it cannot do");
    {
        struct rs_sheet_opts o = { RS_TARGET_SAME, NULL, NULL, NULL, false, NULL, NULL, NULL };
        struct rs_buf        out;
        struct rs_buf        err;

        parse("{\"system\": {\"id\": \"fedora\"}}", &m);
        rs_buf_init(&out);
        rs_buf_init(&err);
        CHECK(!rs_buildsheet(&m, &o, &out, &err));
        CHECK_CONTAINS(err.data, "no disks to rebuild");
        rs_buf_free(&out);
        rs_buf_free(&err);
        rs_jval_free(&m);
        parse("{\"system\": {\"id\": \"fedora\"}, \"disks\": [{\"name\": \"sda\", \"size\": 1,"
              " \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\"}}]}", &m);
        s = sheet(&m, RS_TARGET_SAME, NULL);
        CHECK_CONTAINS(s, "The installer for this system: see");
        CHECK_CONTAINS(s, "(no host name recorded)");
        free(s);
        rs_jval_free(&m);
    }
}

static void system_package_cases(void)
{
    struct rs_jval m;
    struct rs_jval pk;
    char          *s;

    TEST_CASE("buildsheet: the other systems' packages, those asked for");
    server(&m);
    parse("{\"managers\": [],"
          " \"freebsd-pkg\": [{\"name\": \"bash\", \"automatic\": false},"
          "  {\"name\": \"gettext\", \"automatic\": true}],"
          " \"pkg\": [{\"name\": \"curl\"}], \"pkgsrc\": [{\"name\": \"hello\"}],"
          " \"rpm\": [{\"name\": \"httpd\"}], \"pacman\": [{\"name\": \"vim\"}],"
          " \"apk\": [{\"name\": \"busybox\"}],"
          " \"homebrew\": [{\"name\": \"wget\"}, {\"name\": \"firefox\", \"cask\": true}],"
          " \"nix\": [{\"name\": \"hello\"}], \"guix\": [{\"name\": \"coreutils\"}],"
          " \"conda\": [{\"name\": \"python\", \"version\": \"3.12.4\", \"where\": \"/opt/conda\"},"
          "  {\"name\": \"flask\", \"where\": \"/opt/conda/envs/web\"},"
          "  {\"name\": \"numpy\", \"version\": \"2\", \"where\": \"/opt/conda\"}, {\"name\": "
          "\"x\"}],"
          " \"macos-receipts\": [{\"name\": \"com.apple.pkg.Core\"},"
          "  {\"name\": \"com.example.tool\"}]}",
          &pk);
    s = sheet_with(&m, RS_TARGET_VM, NULL, &pk);
    CHECK_CONTAINS(s, "    pkg install -y bash\n");
    CHECK(strstr(s, "gettext") == NULL);
    CHECK_CONTAINS(s, "    pkg_add curl\n");
    CHECK_CONTAINS(s, "    pkgin -y install hello\n");
    CHECK_CONTAINS(s, "    dnf install -y httpd\n");
    CHECK_CONTAINS(s, "    pacman -S --needed vim\n");
    CHECK_CONTAINS(s, "    apk add busybox\n");
    CHECK_CONTAINS(s, "    brew install wget\n");
    CHECK_CONTAINS(s, "    brew install --cask firefox\n");
    CHECK_CONTAINS(s, "    nix profile install hello\n");
    CHECK_CONTAINS(s, "    guix install coreutils\n");
    CHECK_CONTAINS(s, "    conda install -y -p /opt/conda python=3.12.4 numpy=2\n");
    CHECK_CONTAINS(s, "    conda install -y -p /opt/conda/envs/web flask\n");
    CHECK_CONTAINS(s, "1 packages were installed here with macOS's installer");
    free(s);
    rs_jval_free(&pk);
    rs_jval_free(&m);
}

static void package_cases(void)
{
    struct rs_jval m;
    struct rs_jval pk;
    struct rs_buf  text;
    char          *s;
    size_t         i;

    TEST_CASE("buildsheet: installing the packages again");
    server(&m);
    rs_buf_init(&text);
    for (i = 0; packages_json[i]; i++)
    {
        rs_buf_addstr(&text, packages_json[i]);
    }
    parse(text.data, &pk);
    rs_buf_free(&text);
    s = sheet_with(&m, RS_TARGET_VM, "web01.tgz", &pk);
    CHECK_CONTAINS(s, "Install the packages again");
    /* Before the files. */
    CHECK(strstr(s, "Install the packages again") < strstr(s, "Restore the files"));
    CHECK(strstr(s, "no package inventory") == NULL);
    /* The kit by hand, without the accounts restore merges: laid down
     * before the packages, they would take the new system's away. */
    CHECK_CONTAINS(s, "tar -xOf web01.tgz restate/kit.tar.gz | tar -xzpf - --numeric-owner -C / "
                      "--strip-components=2 --exclude=restate/files/etc/passwd "
                      "--exclude=restate/files/etc/group --exclude=restate/files/etc/shadow "
                      "--exclude=restate/files/etc/gshadow\n");
    CHECK_CONTAINS(s, "base64 -d > /usr/share/keyrings/vendor.gpg <<'KEY'\ndmVuZG9yIGtleQ==\nKEY");
    CHECK(strstr(s, "/etc/apt/keyrings/local.gpg <<") == NULL);
    CHECK(strstr(s, "ubuntu-archive-keyring.gpg <<") == NULL);
    CHECK(strstr(s, "odd.gpg") == NULL);
    CHECK_CONTAINS(s, "The key /usr/share/keyrings/gone.gpg was missing");
    CHECK_CONTAINS(s, "apt-get update");
    CHECK_CONTAINS(s, "    cat > /tmp/restate-packages.sh <<'SCRIPT'\n#!/bin/sh\n");
    CHECK_CONTAINS(s, "\nvim=2:9.1-1\nlibfoo:i386=1.0~rc1\ntzdata=2026a\n");
    CHECK_CONTAINS(s, "\nPACKAGES\n");
    CHECK_CONTAINS(s, "\nSCRIPT\n    sh /tmp/restate-packages.sh\n");
    /* Whatever the tree said, the script runs nothing it wrote. */
    CHECK(strstr(s, "$(reboot)") == NULL);
    CHECK_CONTAINS(s, "restate: 1 packages were left out");
    CHECK(strstr(s, " dep=") == NULL);
    CHECK(strstr(s, "intel-microcode=") == NULL);
    CHECK(strstr(s, "zoom=") == NULL);
    CHECK_CONTAINS(s, " oldie");
    CHECK_CONTAINS(s, "\nnoversion\n");
    CHECK_CONTAINS(s, "(1 were installed that way)");
    CHECK_CONTAINS(s, "apt-mark hold libfoo");
    CHECK_CONTAINS(s, "oldie                            was 1.0");
    CHECK_CONTAINS(s, "zoom                             6.7");
    CHECK(strstr(s, "chef                             18") == NULL);
    CHECK_CONTAINS(s, "The kit brought back the ones the image keeps:");
    CHECK(strstr(s, "/tmp/restate/") == NULL);
    CHECK_CONTAINS(s, "apt-get install -y /var/cache/apt/archives/chef_18_amd64.deb");
    CHECK_CONTAINS(s, "dpkg-repack NAME");
    CHECK(strstr(s, "grub-pc=") == NULL);
    CHECK_CONTAINS(s, "    snap install --dangerous /var/lib/snapd/snaps/asana_x1.snap\n");
    CHECK_CONTAINS(s, "tar -xOf web01.tgz restate/files.tar.gz | tar -xzpf - --numeric-owner -C / "
                      "--strip-components=2 --exclude=restate/files/etc/fstab "
                      "--exclude=restate/files/etc/crypttab");
    CHECK_CONTAINS(s, "    r=; for p in ''/usr/local/sbin/restate ''/usr/local/bin/restate "
                      "''/usr/sbin/restate ''/usr/bin/restate; do "
                      "[ -x \"$p\" ] && r=$p && break; done; if [ -n \"$r\" ]; then "
                      "\"$r\" restore --root / --exclude /etc/fstab --exclude /etc/crypttab "
                      "web01.tgz || [ \"$?\" -eq 3 ]; else echo 'restate: no restate in the image "
                      "to "
                      "restore with; tar instead, owners by number' >&2; tar -xOf web01.tgz");
    CHECK_CONTAINS(s, "restate restore reads an encrypted image");
    CHECK_CONTAINS(s, "update-alternatives --set java /usr/lib/jvm/21/bin/java");
    CHECK(strstr(s, "nopath") == NULL);
    CHECK_CONTAINS(s, "snap install firefox --channel=latest/stable\n");
    CHECK_CONTAINS(s, "snap install code --channel=latest/edge --classic --devmode && "
                      "snap disable code");
    CHECK_CONTAINS(s, "snap install lxd\n");
    CHECK(strstr(s, "snap install core") == NULL);
    CHECK(strstr(s, "snap install bare") == NULL);
    CHECK_CONTAINS(s, "mine (revision x1)");
    CHECK_CONTAINS(s, "what (revision ?)");
    CHECK_CONTAINS(s, "flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/");
    CHECK_CONTAINS(s, "flatpak --user remote-add --if-not-exists mine https://x/repo");
    CHECK_CONTAINS(s, "flatpak install -y flathub org.example.App//stable");
    CHECK_CONTAINS(s, "flatpak --user install -y mine com.example.Mine//master");
    CHECK_CONTAINS(s, "org.example.Lone came from a remote that was not recorded");
    CHECK_CONTAINS(s, "Python packages in /usr/local/lib/python3.12/dist-packages:\n\n"
                      "    pip install --break-system-packages requests==2.31.0");
    CHECK_CONTAINS(s, "as the owner of /home/pat:\n\n"
                      "    pip install --user --break-system-packages httpie==3.2");
    CHECK_CONTAINS(s, "npm install -g left-pad@1.3.0");
    CHECK(strstr(s, "npm@10") == NULL);
    CHECK_CONTAINS(s, "pipx install black");
    CHECK_CONTAINS(s, "cargo install ripgrep@14.1.0 mytool@0.1.0");
    CHECK_CONTAINS(s, "mytool was built with cargo from git+https://example.com/mytool");
    CHECK_CONTAINS(s, "gem install rake:13.0.6");
    CHECK_CONTAINS(s, "nix is installed here, and this version takes no inventory of it");
    free(s);

    /* Onto hardware, the guest's packages are left out instead. */
    s = sheet_with(&m, RS_TARGET_METAL, NULL, &pk);
    CHECK_CONTAINS(s, "intel-microcode=3");
    CHECK_CONTAINS(s, "tar -xOf IMAGE.tar restate/files.tar.gz");
    free(s);

    TEST_CASE("buildsheet: the packages from an image from before 1.1");
    old_layout = true;
    s = sheet_with(&m, RS_TARGET_VM, "web01.tgz", &pk);
    CHECK_CONTAINS(s, "tar -xpzf web01.tgz --numeric-owner -C / --strip-components=2 "
                      "restate/files/etc/apt");
    CHECK_CONTAINS(s, "The image keeps these; install them from it:");
    CHECK_CONTAINS(s, "mkdir -p /tmp/restate && tar -xpzf web01.tgz -C /tmp/restate "
                      "--strip-components=2 restate/files/var/cache/apt/archives/"
                      "chef_18_amd64.deb");
    CHECK_CONTAINS(s, "apt-get install -y /tmp/restate/var/cache/apt/archives/chef_18_amd64.deb");
    CHECK_CONTAINS(s, "restate/files/var/lib/snapd/snaps/asana_x1.snap && snap install --dangerous "
                      "/tmp/restate/var/lib/snapd/snaps/asana_x1.snap");
    CHECK_CONTAINS(s, "    tar -xpzf web01.tgz --numeric-owner -C / --strip-components=2 "
                      "restate/files\n");
    CHECK(strstr(s, "kit.tar.gz") == NULL);
    free(s);
    old_layout = false;
    rs_jval_free(&pk);

    TEST_CASE("buildsheet: a long command wraps, and an empty inventory says little");
    rs_buf_init(&text);
    rs_buf_addstr(&text, "{\"apt\": {\"packages\": [");
    for (i = 0; i < 30; i++)
    {
        rs_buf_addf(&text, "%s{\"name\": \"package-number-%zu\", \"version\": \"1.0\","
                    " \"manual\": true, \"origins\": [\"x\"]}", i ? ", " : "", i);
    }
    rs_buf_addstr(&text, "]}, \"snap\": [], \"flatpak\": {\"apps\": []}, \"pip\": [");
    for (i = 0; i < 12; i++)
    {
        rs_buf_addf(&text, "%s{\"name\": \"python-package-%zu\", \"version\": \"1.0\","
                    " \"where\": \"/usr/local/lib/python3/dist-packages\"}", i ? ", " : "", i);
    }
    rs_buf_addstr(&text, "]}");
    parse(text.data, &pk);
    rs_buf_free(&text);
    s = sheet_with(&m, RS_TARGET_SAME, NULL, &pk);
    CHECK_CONTAINS(s, "\npackage-number-0=1.0\npackage-number-1=1.0\n");
    CHECK_CONTAINS(s, "pip install --break-system-packages python-package-0==1.0 \\\n"
                      "        python-package-");
    CHECK(strstr(s, "apt-mark hold") == NULL);
    CHECK(strstr(s, "The snaps") == NULL);
    CHECK(strstr(s, "flatpak") == NULL);
    CHECK_CONTAINS(s, "Python packages in /usr/local/lib/python3/dist-packages");
    free(s);
    rs_jval_free(&pk);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: an image without an inventory");
    server(&m);
    s = sheet(&m, RS_TARGET_SAME, NULL);
    CHECK(strstr(s, "Install the packages again") == NULL);
    CHECK_CONTAINS(s, "has no package inventory");
    free(s);
    rs_jval_free(&m);
}

/* The content of a file the late-commands write into the new system: the
 * base64 between "echo " and " | base64 -d > /target<path>". */
static char *late_file_text(const char *yaml, const char *path)
{
    char         *tail = rs_xasprintf(" | base64 -d > /target%s ", path);
    const char   *end = strstr(yaml, tail);
    const char   *start = end;
    struct rs_buf out;

    free(tail);
    rs_buf_init(&out);
    while (start && start > yaml && strncmp(start, "echo ", 5) != 0)
    {
        start--;
    }
    if (!end || !start || !rs_base64_decode(start + 5, (size_t)(end - start - 5), &out))
    {
        rs_buf_free(&out);
        return rs_xstrdup("");
    }
    rs_buf_add(&out, "", 1);
    return rs_buf_detach(&out);
}

static void autoinstall_package_cases(void)
{
    struct rs_jval m;
    struct rs_jval pk;
    struct rs_buf  text;
    char          *s;
    size_t         i;

    TEST_CASE("autoinstall: the packages, then the files, from the image");
    server(&m);
    rs_buf_init(&text);
    for (i = 0; packages_json[i]; i++)
    {
        rs_buf_addstr(&text, packages_json[i]);
    }
    parse(text.data, &pk);
    rs_buf_free(&text);
    s = autoinst_with(&m, RS_TARGET_VM, &pk, "/media/restate/web 01.tgz");
    CHECK_CONTAINS(s, "# image at /media/restate/web 01.tgz, so it has to be there");
    /* The snaps at the first boot: the desktop installer ignores a snaps
     * section. */
    CHECK(strstr(s, "  snaps:") == NULL);
    {
        char *fb = late_file_text(s, "/usr/local/sbin/restate-firstboot");
        char *unit = late_file_text(s, "/etc/systemd/system/restate-firstboot.service");

        CHECK_CONTAINS(fb, "snap wait system seed.loaded\n");
        CHECK_CONTAINS(fb, "snap install firefox --channel=latest/stable || echo "
                           "'restate: the snap firefox did not install' >&2\n");
        CHECK_CONTAINS(fb, "snap install code --channel=latest/edge --classic --devmode || ");
        CHECK_CONTAINS(fb, "snap disable code\n");
        /* From restate's directory: snapd clears its own of strangers. */
        CHECK_CONTAINS(fb, "snap install --dangerous /var/lib/restate/snaps/asana_x1.snap || ");
        CHECK_CONTAINS(fb, "rm -rf /var/lib/restate/snaps\n");
        CHECK(strstr(fb, "core22") == NULL);
        CHECK(strstr(fb, "snap install core24") == NULL);
        CHECK(strstr(fb, "snap install mine") == NULL);
        CHECK_CONTAINS(fb, "systemctl disable restate-firstboot.service\n");
        CHECK_CONTAINS(unit, "After=network-online.target snapd.seeded.service\n");
        CHECK_CONTAINS(unit, "WantedBy=multi-user.target\n");
        free(fb);
        free(unit);
    }
    CHECK_CONTAINS(s, "ln -sf /etc/systemd/system/restate-firstboot.service "
                      "/target/etc/systemd/system/multi-user.target.wants/");
    CHECK_CONTAINS(s, "test -f '/media/restate/web 01.tgz' || { echo 'restate: the image is not at "
                      "/media/restate/web 01.tgz' >&2; exit 1; }");
    CHECK_CONTAINS(s, "tar -xOf '/media/restate/web 01.tgz' restate/kit.tar.gz | tar -xzpf - "
                      "--numeric-owner -C /target --strip-components=2 "
                      "--exclude=restate/files/etc/passwd --exclude=restate/files/etc/group "
                      "--exclude=restate/files/etc/shadow --exclude=restate/files/etc/gshadow\"");
    CHECK_CONTAINS(s, "mkdir -p /target/var/lib/restate/snaps && { [ ! -f "
                      "/target/var/lib/snapd/snaps/asana_x1.snap ] || cp "
                      "/target/var/lib/snapd/snaps/asana_x1.snap "
                      "/target/var/lib/restate/snaps/; }");
    CHECK_CONTAINS(s, "mkdir -p /target/usr/share/keyrings/ && echo dmVuZG9yIGtleQ== | base64 -d > "
                      "/target/usr/share/keyrings/vendor.gpg");
    CHECK(strstr(s, "local.gpg") == NULL);
    CHECK(strstr(s, "odd.gpg") == NULL);
    CHECK_CONTAINS(s, "curtin in-target -- apt-get update || true");
    {
        char *sh = late_file_text(s, "/var/tmp/restate-packages.sh");

        CHECK_CONTAINS(sh, "\nvim=2:9.1-1\nlibfoo:i386=1.0~rc1\ntzdata=2026a\n");
        CHECK_CONTAINS(sh, "if [ -n \"$ok\" ] && ! apt-get install -y $ok; then\n");
        CHECK(strstr(sh, "reboot") == NULL);
        free(sh);
    }
    CHECK_CONTAINS(s, "curtin in-target -- sh /var/tmp/restate-packages.sh; "
                      "rm -f /target/var/tmp/restate-packages.sh");
    CHECK(strstr(s, "grub-pc") == NULL);
    CHECK(strstr(s, "intel-microcode=") == NULL);
    CHECK(strstr(s, "restate/files/var/cache/apt/archives/chef_18_amd64.deb") == NULL);
    CHECK_CONTAINS(s, "apt-get install -y /var/cache/apt/archives/chef_18_amd64.deb || echo "
                      "'restate: the kept packages did not all install' >&2");
    CHECK_CONTAINS(s, "curtin in-target -- apt-mark hold libfoo");
    CHECK_CONTAINS(s, "curtin in-target -- flatpak remote-add --if-not-exists flathub "
                      "https://dl.flathub.org/repo/");
    CHECK(strstr(s, "remote-add --if-not-exists mine") == NULL);
    CHECK_CONTAINS(s, "curtin in-target -- flatpak install -y --noninteractive flathub "
                      "org.example.App//stable");
    CHECK_CONTAINS(s, "curtin in-target -- pip install --break-system-packages "
                      "requests==2.31.0 ||");
    CHECK(strstr(s, "httpie") == NULL);
    CHECK_CONTAINS(s, "curtin in-target -- npm install -g left-pad@1.3.0 ||");
    CHECK_CONTAINS(s, "curtin in-target -- gem install rake:13.0.6 ||");
    CHECK_CONTAINS(s, "curtin in-target -- update-alternatives --set java "
                      "/usr/lib/jvm/21/bin/java");
    CHECK_CONTAINS(s, "for p in /target/usr/local/sbin/restate /target/usr/local/bin/restate "
                      "/target/usr/sbin/restate /target/usr/bin/restate; do");
    CHECK_CONTAINS(s, "\\\"$r\\\" restore --root /target --exclude /etc/fstab --exclude "
                      "/etc/crypttab '/media/restate/web 01.tgz' || [ \\\"$?\\\" -eq 3 ]; else "
                      "echo 'restate: no restate in the image to restore with; tar instead, "
                      "owners by number' >&2; tar -xOf '/media/restate/web 01.tgz' "
                      "restate/files.tar.gz | tar -xzpf - "
                      "--numeric-owner -C /target --strip-components=2 "
                      "--exclude=restate/files/etc/fstab --exclude=restate/files/etc/crypttab; "
                      "fi\"");
    CHECK_CONTAINS(s, "curtin in-target -- update-grub");
    CHECK(strstr(s, "update-alternatives") < strstr(s, "--exclude=restate/files/etc/fstab"));
    CHECK(strstr(s, "#   snap install --dangerous") == NULL);
    CHECK_CONTAINS(s, "#   the snap mine, from the file it was installed from");
    CHECK_CONTAINS(s, "#   zoom, from its .deb (no repository has it)");
    CHECK_CONTAINS(s, "#   pip's packages in the home directories, each by its owner");
    CHECK_CONTAINS(s, "#   pipx's packages in the home directories");
    CHECK_CONTAINS(s, "#   cargo's packages in the home directories");
    /* One late-commands key, the hardware purges in it too. */
    CHECK(strstr(strstr(s, "late-commands:") + 1, "late-commands:") == NULL);
    CHECK_CONTAINS(s, "apt-get purge -y intel-microcode || true");
    free(s);

    TEST_CASE("autoinstall: from an image from before 1.1");
    old_layout = true;
    s = autoinst_with(&m, RS_TARGET_VM, &pk, "/i.tgz");
    CHECK_CONTAINS(s, "tar -xpzf /i.tgz --numeric-owner -C /target --strip-components=2 "
                      "restate/files/etc/apt");
    CHECK_CONTAINS(s, "--strip-components=2 "
                      "restate/files/var/cache/apt/archives/chef_18_amd64.deb");
    CHECK_CONTAINS(s, "--exclude=restate/files/etc/fstab --exclude=restate/files/etc/crypttab "
                      "restate/files\"");
    CHECK(strstr(s, "kit.tar.gz") == NULL);
    free(s);
    old_layout = false;

    TEST_CASE("autoinstall: an inventory, but nowhere to find the image");
    s = autoinst_with(&m, RS_TARGET_SAME, &pk, NULL);
    CHECK_CONTAINS(s, "make this file with\n# --image-at PATH");
    CHECK(strstr(s, "  snaps:") == NULL);
    CHECK_CONTAINS(s, "restate-firstboot");
    CHECK(strstr(s, "restate-packages.sh") == NULL);
    free(s);
    rs_jval_free(&pk);

    TEST_CASE("autoinstall: an inventory with no apt");
    parse("{\"snap\": [], \"pip\": [{\"name\": \"x\", \"where\": \"/usr/local/lib/p\"}]}", &pk);
    s = autoinst_with(&m, RS_TARGET_SAME, &pk, "/i.tgz");
    CHECK(strstr(s, "restate/files/etc/apt") == NULL);
    CHECK(strstr(s, "snaps:") == NULL);
    CHECK_CONTAINS(s, "curtin in-target -- pip install --break-system-packages x ||");
    CHECK_CONTAINS(s, "curtin in-target -- update-initramfs -u -k all");
    free(s);
    rs_jval_free(&pk);
    rs_jval_free(&m);
}

static void autoinstall_cases(void)
{
    struct rs_jval m;
    char          *s;

    server(&m);
    TEST_CASE("autoinstall: the same machine");
    s = autoinst(&m, RS_TARGET_SAME);
    CHECK_CONTAINS(s, "#cloud-config\n");
    CHECK_CONTAINS(s, "  locale: \"en_GB.UTF-8\"");
    CHECK_CONTAINS(s, "    layout: \"gb\"\n    variant: \"extd\"");
    CHECK_CONTAINS(s, "  timezone: \"Europe/London\"");
    CHECK_CONTAINS(s, "    hostname: \"web01\"");
    /* The old machine's first person, as the install's own account. */
    CHECK_CONTAINS(s, "    realname: \"Pat Smith\"\n    username: \"pat\"\n");
    CHECK_CONTAINS(s, "install-server: true");
    CHECK_CONTAINS(s, "      eno1:\n        match:\n          macaddress: \"52:54:00:00:00:01\"");
    CHECK(strstr(s, "wlp2s0") == NULL);
    CHECK_CONTAINS(s, "        path: \"/dev/sda\"\n        serial: \"SN-A\"");
    CHECK_CONTAINS(s, "        offset: 1048576\n        size: 536870912\n        flag: \"boot\"");
    CHECK_CONTAINS(s, "      - type: dm_crypt\n        id: \"crypt-sda3_crypt\"");
    CHECK_CONTAINS(s, "        key: \"CHANGE-ME\"");
    CHECK_CONTAINS(s, "      - type: lvm_volgroup\n        id: \"vg-vg0\"");
    CHECK_CONTAINS(s, "      - type: lvm_partition\n        id: \"lv-vg0-root\"\n        name: "
                      "\"root\"");
    CHECK_CONTAINS(s, "      - type: raid\n        id: \"md-md0\"");
    CHECK_CONTAINS(s, "        raidlevel: \"raid1\"\n        metadata: \"1.2\"");
    CHECK_CONTAINS(s, "        fstype: \"fat32\"\n        label: \"ESP\"");
    CHECK_CONTAINS(s, "        uuid: \"root-uuid\"");
    CHECK_CONTAINS(s, "        path: \"none\"");
    CHECK_CONTAINS(s, "        options: \"errors=remount-ro\"");
    CHECK_CONTAINS(s, "        flag: \"raid\"");
    CHECK_CONTAINS(s, "    swap:\n      size: 0");
    CHECK(strstr(s, "sdz") == NULL);
    CHECK(strstr(s, "packages:") == NULL);
    free(s);

    TEST_CASE("autoinstall: as a virtual machine");
    s = autoinst(&m, RS_TARGET_VM);
    CHECK_CONTAINS(s, "        path: \"/dev/vda\"");
    CHECK_CONTAINS(s, "        path: \"/dev/vdb\"");
    CHECK_CONTAINS(s, "size: -1    # the rest of the disk");
    CHECK_CONTAINS(s, "      wired:\n        match:\n          name: \"en*\"");
    CHECK_CONTAINS(s, "  packages:\n    - \"qemu-guest-agent\"");
    CHECK_CONTAINS(s, "apt-get purge -y intel-microcode || true");
    CHECK(strstr(s, "purge -y mdadm") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("autoinstall: a guest onto hardware, and BIOS");
    parse(guest_json, &m);
    s = autoinst(&m, RS_TARGET_METAL);
    CHECK_CONTAINS(s, "CHANGE-ME: the new machine's disk");
    CHECK_CONTAINS(s, "        ptable: \"msdos\"");
    CHECK_CONTAINS(s, "        grub_device: true");
    CHECK_CONTAINS(s, "        flag: \"swap\"");
    CHECK_CONTAINS(s, "intel-microcode");
    free(s);
    rs_jval_free(&m);

    TEST_CASE("autoinstall: keeping another system on the disk");
    parse(dual_json, &m);
    s = autoinst(&m, RS_TARGET_SAME);
    CHECK_CONTAINS(s, "Another operating system shares the disk");
    CHECK_CONTAINS(s, "        preserve: true\n        # Windows (BitLocker): left alone");
    CHECK_CONTAINS(s, "not reformatted: the other system boots from it too");
    CHECK_CONTAINS(s, "    renderer: NetworkManager");
    free(s);
    s = autoinst(&m, RS_TARGET_METAL);
    CHECK_CONTAINS(s, "        match:\n          size: largest");
    CHECK(strstr(s, "BitLocker") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("autoinstall: what it refuses");
    {
        struct rs_auto_opts o = { RS_TARGET_SAME, "x.tgz", NULL, NULL, NULL, false,
                                  NULL, NULL, NULL, NULL, NULL, NULL };
        struct rs_buf       out;
        struct rs_buf       err;

        parse("{\"system\": {\"id\": \"fedora\"}}", &m);
        rs_buf_init(&out);
        rs_buf_init(&err);
        CHECK(!rs_autoinstall(&m, &o, &out, &err));
        CHECK_CONTAINS(err.data, "autoinstall files are for Ubuntu; this machine is fedora");
        rs_jval_free(&m);
        parse("{\"system\": {}}", &m);
        rs_buf_reset(&err);
        CHECK(!rs_autoinstall(&m, &o, &out, &err));
        CHECK_CONTAINS(err.data, "of an unknown system");
        rs_jval_free(&m);
        parse("{\"system\": {\"id\": \"ubuntu\"}}", &m);
        rs_buf_reset(&err);
        CHECK(!rs_autoinstall(&m, &o, &out, &err));
        CHECK_CONTAINS(err.data, "no disks to rebuild");
        rs_buf_free(&out);
        rs_buf_free(&err);
        rs_jval_free(&m);
    }
}

/* A BIOS machine on a GPT disk: GRUB's partition first. */
static const char gpt_bios_json[] =
    "{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\", \"architecture\": \"x86_64\","
    "   \"type\": \"server\"},"
    " \"firmware\": {\"mode\": \"bios\"},"
    " \"disks\": [{\"name\": \"sda\", \"size\": 21474836480, \"table\": {\"type\": \"gpt\"},"
    "   \"partitions\": ["
    "    {\"name\": \"sda1\", \"number\": 1, \"start\": 1048576, \"size\": 1048576,"
    "     \"type\": \"21686148-6449-6e6f-744e-656564454649\"},"
    "    {\"name\": \"sda2\", \"number\": 2, \"start\": 2097152, \"size\": 20000000000,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"r\"}}]}],"
    " \"fstab\": [{\"spec\": \"UUID=r\", \"file\": \"/\", \"type\": \"ext4\"}]"
    "}";

/* A UEFI machine on an MBR disk. */
static const char dos_uefi_json[] =
    "{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\", \"architecture\": \"x86_64\","
    "   \"type\": \"server\"},"
    " \"firmware\": {\"mode\": \"uefi\"},"
    " \"disks\": [{\"name\": \"vda\", \"size\": 21474836480, \"table\": {\"type\": \"dos\"},"
    "   \"partitions\": ["
    "    {\"name\": \"vda1\", \"number\": 1, \"start\": 1048576, \"size\": 536870912,"
    "     \"type\": \"0xef\", \"content\": {\"type\": \"vfat\", \"usage\": \"filesystem\"}},"
    "    {\"name\": \"vda2\", \"number\": 2, \"start\": 537919488, \"size\": 20000000000,"
    "     \"type\": \"0x83\", \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", "
    "\"uuid\": \"r\"}}]}],"
    " \"fstab\": [{\"spec\": \"UUID=r\", \"file\": \"/\", \"type\": \"ext4\"},"
    "            {\"spec\": \"/dev/vda1\", \"file\": \"/boot/efi\", \"type\": \"vfat\"}]"
    "}";

static char *sheet_firmware(const struct rs_jval *m, enum rs_target t, const char *fw)
{
    struct rs_sheet_opts o;
    struct rs_buf        out;
    struct rs_buf        err;

    memset(&o, 0, sizeof(o));
    o.target = t;
    o.version = "9.9";
    o.firmware = fw;
    rs_buf_init(&out);
    rs_buf_init(&err);
    CHECK(rs_buildsheet(m, &o, &out, &err));
    rs_buf_free(&err);
    return rs_buf_detach(&out);
}

static char *autoinst_firmware(const struct rs_jval *m, enum rs_target t, const char *fw)
{
    struct rs_auto_opts o;
    struct rs_buf       out;
    struct rs_buf       err;

    memset(&o, 0, sizeof(o));
    o.target = t;
    o.version = "9.9";
    o.firmware = fw;
    rs_buf_init(&out);
    rs_buf_init(&err);
    CHECK(rs_autoinstall(m, &o, &out, &err));
    rs_buf_free(&err);
    return rs_buf_detach(&out);
}

static void firmware_cases(void)
{
    struct rs_jval   m;
    struct rs_layout l;
    char            *s;
    size_t           v;

    TEST_CASE("firmware: a BIOS guest on an MBR disk, rebuilt to boot by UEFI");
    parse(guest_json, &m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "uefi"));
    CHECK_STR(l.firmware, "uefi");
    /* An EFI system partition, added in front of the others. */
    v = rs_layout_find(&l, "esp");
    CHECK(v != SIZE_MAX);
    if (v != SIZE_MAX)
    {
        CHECK_STR(l.vols[v].ptype, "0xef");
        CHECK_STR(l.vols[v].mountpoint, "/boot/efi");
        CHECK_STR(l.vols[v].path, "/dev/vda1");
        CHECK(l.vols[v + 1].kind == RS_VOL_PART && strcmp(l.vols[v + 1].name, "vda1") == 0);
    }
    CHECK(rs_layout_set_firmware(&l, "uefi"));   /* already: nothing more */
    rs_layout_free(&l);
    s = sheet_firmware(&m, RS_TARGET_METAL, "uefi");
    CHECK_CONTAINS(s, "Firmware set to boot UEFI");
    CHECK_CONTAINS(s, "vda1 : size=512MiB, type=ef\n");
    CHECK_CONTAINS(s, "vda2 : size=");
    CHECK_CONTAINS(s, "/boot/efi");
    free(s);
    s = autoinst_firmware(&m, RS_TARGET_METAL, "uefi");
    CHECK_CONTAINS(s, "id: \"part-esp\"");
    CHECK_CONTAINS(s, "path: \"/boot/efi\"");
    CHECK(strstr(s, "        grub_device: true\n      - type: partition") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("firmware: UEFI on GPT, rebuilt to boot by BIOS");
    server(&m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "bios"));
    v = rs_layout_find(&l, "sda1");
    CHECK_STR(l.vols[v].ptype, "21686148-6449-6e6f-744e-656564454649");
    CHECK(l.vols[v].mountpoint == NULL);
    CHECK_INT(l.vols[v].size, 1048576);
    rs_layout_free(&l);
    s = sheet_firmware(&m, RS_TARGET_VM, "bios");
    CHECK_CONTAINS(s, "type=21686148-6449-6e6f-744e-656564454649");
    CHECK(strstr(s, "/boot/efi") == NULL);
    CHECK_CONTAINS(s, "Install the boot loader to $DISK1 itself");
    free(s);
    rs_jval_free(&m);

    TEST_CASE("firmware: GRUB's BIOS partition on GPT becomes the ESP");
    parse(gpt_bios_json, &m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "uefi"));
    v = rs_layout_find(&l, "sda1");
    CHECK_STR(l.vols[v].ptype, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    CHECK_STR(l.vols[v].fstype, "vfat");
    CHECK_INT(l.vols[v].size, (uint64_t)512 * 1024 * 1024);
    CHECK(rs_layout_find(&l, "esp") == SIZE_MAX);
    rs_layout_free(&l);
    rs_jval_free(&m);

    TEST_CASE("firmware: UEFI on MBR to BIOS, and the ESP left out");
    parse(dos_uefi_json, &m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "bios"));
    v = rs_layout_find(&l, "vda1");
    CHECK(l.vols[v].foreign);
    CHECK_CONTAINS(l.vols[v].foreign_why, "BIOS boot does not use");
    CHECK(rs_layout_fit(&l, v, RS_TARGET_VM) == 0);
    rs_layout_free(&l);
    s = sheet_firmware(&m, RS_TARGET_VM, "bios");
    CHECK(strstr(s, "type=ef") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("firmware: UEFI on GPT to Open Firmware, the ESP's place GRUB's PReP partition");
    server(&m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "ieee1275"));
    v = rs_layout_find(&l, "sda1");
    CHECK_STR(l.vols[v].ptype, "9e1a2d38-c612-4316-aa26-8b49521e5a8b");
    CHECK(l.vols[v].mountpoint == NULL && l.vols[v].fstype == NULL);
    CHECK_INT(l.vols[v].size, (uint64_t)8 * 1024 * 1024);
    /* And back: the PReP partition's place is the ESP's again. */
    CHECK(rs_layout_set_firmware(&l, "uefi"));
    CHECK_STR(l.vols[v].ptype, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    CHECK_STR(l.vols[v].mountpoint, "/boot/efi");
    rs_layout_free(&l);
    s = sheet_firmware(&m, RS_TARGET_VM, "ieee1275");
    CHECK_CONTAINS(s, "Firmware   Open Firmware, GRUB in a PReP partition");
    CHECK_CONTAINS(s, "type=9e1a2d38-c612-4316-aa26-8b49521e5a8b");
    CHECK_CONTAINS(s, "The installer puts GRUB in the PReP partition");
    CHECK(strstr(s, "/boot/efi") == NULL);
    free(s);
    s = autoinst_firmware(&m, RS_TARGET_VM, "ieee1275");
    CHECK_CONTAINS(s, "        flag: \"prep\"\n");
    CHECK_CONTAINS(s, "        flag: \"prep\"\n        partition_type: "
                      "\"9e1a2d38-c612-4316-aa26-8b49521e5a8b\"\n        grub_device: true\n");
    free(s);
    rs_jval_free(&m);

    TEST_CASE("firmware: a BIOS guest on MBR to Open Firmware, a PReP partition added");
    parse(guest_json, &m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "ieee1275"));
    v = rs_layout_find(&l, "prep");
    CHECK(v != SIZE_MAX);
    CHECK_STR(v != SIZE_MAX ? l.vols[v].ptype : "", "0x41");
    rs_layout_free(&l);
    s = sheet_firmware(&m, RS_TARGET_VM, "ieee1275");
    CHECK_CONTAINS(s, "vda1 : size=8MiB, type=41\n");
    free(s);
    s = autoinst_firmware(&m, RS_TARGET_VM, "ieee1275");
    CHECK_CONTAINS(s, "        flag: \"prep\"\n        grub_device: true\n");
    free(s);
    rs_jval_free(&m);

    TEST_CASE("firmware: IBM Z's IPL and POWER's petitboot, with no boot partition");
    server(&m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "zipl"));
    v = rs_layout_find(&l, "sda1");
    CHECK(l.vols[v].foreign);
    CHECK_CONTAINS(l.vols[v].foreign_why, "IBM Z's IPL does not use");
    /* A BIOS on GPT, with the ESP set aside: GRUB's partition is added. */
    CHECK(rs_layout_set_firmware(&l, "bios"));
    CHECK(rs_layout_find(&l, "biosboot") != SIZE_MAX);
    rs_layout_free(&l);
    CHECK(rs_layout_build(&m, &l));
    CHECK(rs_layout_set_firmware(&l, "opal"));
    CHECK_CONTAINS(l.vols[rs_layout_find(&l, "sda1")].foreign_why, "petitboot");
    rs_layout_free(&l);
    s = sheet_firmware(&m, RS_TARGET_VM, "zipl");
    CHECK_CONTAINS(s, "Firmware   IBM Z IPL, of what zipl writes");
    CHECK_CONTAINS(s, "The installer writes the boot record with zipl");
    CHECK_CONTAINS(s, "The LPAR or z/VM guest set to IPL");
    free(s);
    s = sheet_firmware(&m, RS_TARGET_VM, "opal");
    CHECK_CONTAINS(s, "Firmware set to boot by OPAL (petitboot), no boot partition.");
    free(s);
    s = autoinst_firmware(&m, RS_TARGET_VM, "zipl");
    CHECK(strstr(s, "grub_device") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("firmware: nothing to boot from");
    parse("{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\"},"
          " \"firmware\": {\"mode\": \"bios\"},"
          " \"disks\": [{\"name\": \"vda\", \"size\": 1000000000,"
          "   \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\"}}]}", &m);
    CHECK(rs_layout_build(&m, &l));
    CHECK(!rs_layout_set_firmware(&l, "uefi"));
    CHECK(rs_layout_set_firmware(&l, NULL));
    rs_layout_free(&l);
    {
        struct rs_sheet_opts o;
        struct rs_auto_opts  a;
        struct rs_buf        out;
        struct rs_buf        err;

        memset(&o, 0, sizeof(o));
        o.target = RS_TARGET_VM;
        o.firmware = "uefi";
        rs_buf_init(&out);
        rs_buf_init(&err);
        CHECK(!rs_buildsheet(&m, &o, &out, &err));
        CHECK_CONTAINS(err.data, "--firmware uefi");
        rs_buf_reset(&err);
        memset(&a, 0, sizeof(a));
        a.target = RS_TARGET_VM;
        a.firmware = "uefi";
        CHECK(!rs_autoinstall(&m, &a, &out, &err));
        CHECK_CONTAINS(err.data, "--firmware uefi");
        rs_buf_free(&out);
        rs_buf_free(&err);
    }
    rs_jval_free(&m);
}

/* The early-command of a file for copies, as the installer gives it to sh:
 * the literal block, less its indentation. */
static char *early_script(const char *s)
{
    const char   *p = s ? strstr(s, "  early-commands:\n    - |\n") : NULL;
    struct rs_buf b;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (p = p ? p + strlen("  early-commands:\n    - |\n") : ""; *p;)
    {
        size_t len = strcspn(p, "\n");

        if (len > 0 && strncmp(p, "      ", 6) != 0)
        {
            break;
        }
        if (len >= 6)
        {
            rs_buf_add(&b, p + 6, len - 6);
        }
        rs_buf_addc(&b, '\n');
        p += len;
        p += *p == '\n' ? 1 : 0;
    }
    return rs_buf_detach(&b);
}

/* Runs the early-command in `dir`, on a machine with the MAC address `mac`
 * and the disk serials lsblk prints as `serials`; its configuration, as it
 * wrote it, or NULL. */
static char *pick(const char *dir, const char *script, const char *mac, const char *serials,
                  int *code)
{
    char         *cmd;
    char         *lsblk = rs_xasprintf("#!/bin/sh\nprintf '%s'\n", serials);
    char         *net = rs_xasprintf("%s/sys/class/net/eth0", dir);
    char         *conf = rs_xasprintf("%s/autoinstall.yaml", dir);
    char         *mkdirs = rs_xasprintf("mkdir -p '%s' '%s/bin'", net, dir);
    char         *text;
    struct rs_buf b;
    int           st;

    st = system(mkdirs);
    CHECK(st == 0);
    free(mkdirs);
    rs_test_write(net, "address", mac, 0644);
    rs_test_write(dir, "bin/lsblk", lsblk, 0755);
    rs_test_write(dir, "pick.sh", script, 0644);
    (void)unlink(conf);
    cmd = rs_xasprintf("cd '%s' && PATH='%s/bin':/usr/bin:/bin RESTATE_SYS='%s/sys' "
                       "RESTATE_AUTOINSTALL='%s' sh pick.sh > out 2>&1",
                       dir, dir, dir, conf);
    st = system(cmd);
    *code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    free(cmd);
    text = NULL;
    {
        FILE *fp = fopen(conf, "r");

        if (fp)
        {
            char   chunk[4096];
            size_t n;

            rs_buf_init(&b);
            while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
            {
                rs_buf_add(&b, chunk, n);
            }
            rs_buf_add(&b, "", 0);
            (void)fclose(fp);
            text = rs_buf_detach(&b);
        }
    }
    free(lsblk);
    free(net);
    free(conf);
    return text;
}

static void clones_cases(void)
{
    struct rs_jval      m;
    struct rs_jval      pk;
    struct rs_clones    c;
    struct rs_buf       text;
    struct rs_buf       err;
    struct rs_auto_opts o;
    char               *s;
    char               *script;
    char               *conf;
    char               *dir = rs_test_tmpdir();
    size_t              i;
    int                 code = 0;
    static const char   list[] = "name,mac,serial,address,gateway,dns\n"
                                 "web1,52:54:00:00:00:01,,10.0.0.11/24,10.0.0.1,10.0.0.2\n"
                                 "web2,,SER-2,,,\n";

    server(&m);
    rs_buf_init(&text);
    for (i = 0; packages_json[i]; i++)
    {
        rs_buf_addstr(&text, packages_json[i]);
    }
    parse(text.data, &pk);
    rs_buf_free(&text);
    rs_buf_init(&err);
    CHECK(rs_clones_parse(&c, list, strlen(list), "lab.csv", &err));
    {
        struct rs_jval *pg = rs_jobj_add(&m, "postgresql_clusters");

        rs_jval_set_array(pg);
        rs_jval_set_string(rs_jarr_add(pg), "/var/lib/postgresql/18/main");
        rs_jval_set_string(rs_jarr_add(pg), "/srv/bad\nname");
    }
    memset(&o, 0, sizeof(o));
    o.target = RS_TARGET_VM;
    o.version = "9.9";
    o.packages = &pk;
    o.image_at = "/cdrom/web.tar";
    o.clones = &c;
    o.clones_from = "lab.csv";
    rs_buf_init(&text);

    TEST_CASE("autoinstall: one file for the copies, which picks this machine's");
    CHECK(rs_autoinstall(&m, &o, &text, &err));
    s = text.data;
    CHECK_CONTAINS(s, "#cloud-config\n");
    CHECK_CONTAINS(s, "# One file for 2 copies of the machine, from lab.csv.");
    CHECK_CONTAINS(s, "#   web1                 52:54:00:00:00:01 -                    "
                      "10.0.0.11/24\n");
    CHECK_CONTAINS(s, "#   web2                 -                 SER-2                DHCP\n");
    CHECK_CONTAINS(s, "# The restore is made with --as");
    CHECK_CONTAINS(s, "# Every copy's PostgreSQL cluster has the original's system identifier,");
    CHECK_CONTAINS(s, "#   /var/lib/postgresql/18/main\n");
    CHECK(strstr(s, "/srv/bad") == NULL);
    CHECK_CONTAINS(s, "\nautoinstall:\n  version: 1\n  early-commands:\n    - |\n");
    /* Nothing of the copies' configuration outside the early-command. */
    CHECK(strstr(s, "\n  storage:") == NULL);
    CHECK(strstr(s, "\n  identity:") == NULL);
    CHECK_CONTAINS(s, "\n      storage:\n");
    CHECK_CONTAINS(s, "        hostname: \"" RS_AUTO_COPY "\"");
    CHECK_CONTAINS(s, "--as " RS_AUTO_COPY " --exclude /etc/netplan");
    script = early_script(s);

    TEST_CASE("autoinstall: the copy found by its MAC address, at its own address");
    conf = pick(dir, script, "52:54:00:00:00:01\n", "OTHER\n", &code);
    CHECK_INT(code, 0);
    CHECK(conf != NULL);
    CHECK(conf && strncmp(conf, "version: 1\n", 11) == 0);
    CHECK_CONTAINS(conf, "\nidentity:\n  hostname: \"web1\"\n");
    CHECK_CONTAINS(conf, "\nnetwork:\n  version: 2\n  ethernets:\n    restate:\n      match:\n"
                         "        macaddress: \"52:54:00:00:00:01\"\n      dhcp4: false\n"
                         "      dhcp6: false\n      addresses:\n        - \"10.0.0.11/24\"\n"
                         "      routes:\n        - to: default\n          via: \"10.0.0.1\"\n"
                         "      nameservers:\n        addresses:\n          - \"10.0.0.2\"\n"
                         "storage:\n");
    CHECK_CONTAINS(conf, "--as web1 --exclude /etc/netplan");
    CHECK(strstr(conf ? conf : "", RS_AUTO_COPY) == NULL);
    CHECK(strstr(conf ? conf : "", "@RESTATE") == NULL);
    free(conf);

    TEST_CASE("autoinstall: the copy found by a disk serial, on DHCP");
    conf = pick(dir, script, "11:22:33:44:55:66\n", "SER-1\nSER-2\n", &code);
    CHECK_INT(code, 0);
    CHECK_CONTAINS(conf, "\nidentity:\n  hostname: \"web2\"\n");
    CHECK_CONTAINS(conf, "      match:\n        name: \"en*\"\n      dhcp4: true\nstorage:\n");
    free(conf);

    TEST_CASE("autoinstall: a machine that is none of the copies");
    conf = pick(dir, script, "11:22:33:44:55:66\n", "SER-9\n", &code);
    CHECK_INT(code, 1);
    CHECK(conf == NULL);
    free(conf);
    {
        struct rs_buf said;

        CHECK(rs_read_beneath(dir, "/out", 65536, &said));
        CHECK_CONTAINS(said.data, "none of the copies this file installs");
        CHECK_CONTAINS(said.data, "11:22:33:44:55:66");
        rs_buf_free(&said);
    }
    free(script);

    TEST_CASE("autoinstall: copies with no image to restore from, on a desktop");
    rs_jval_free(&m);
    parse("{\"system\": {\"id\": \"ubuntu\", \"type\": \"desktop\", \"hostname\": \"d\"},"
          " \"disks\": [{\"name\": \"vda\", \"size\": 21474836480, \"table\": {\"type\": "
          "\"gpt\"}, \"partitions\": [{\"name\": \"vda1\", \"number\": 1, \"start\": 1048576,"
          " \"size\": 20000000000, \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
          " \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"r\"}}]}],"
          " \"fstab\": [{\"spec\": \"UUID=r\", \"file\": \"/\", \"type\": \"ext4\"}]}",
          &m);
    o.image_at = NULL;
    o.clones_from = NULL;
    rs_buf_reset(&text);
    CHECK(rs_autoinstall(&m, &o, &text, &err));
    CHECK_CONTAINS(text.data, "from a list.");
    CHECK_CONTAINS(text.data, "# Restore each with restate restore --as NAME");
    CHECK(strstr(text.data, "--as " RS_AUTO_COPY) == NULL);
    CHECK_CONTAINS(text.data, "  renderer: NetworkManager\n");

    rs_buf_free(&text);
    rs_buf_free(&err);
    rs_clones_free(&c);
    rs_jval_free(&pk);
    rs_jval_free(&m);
    rs_test_rmtree(dir);
    free(dir);
}

/* An IBM Z guest: a DASD with /boot and /, and a SCSI disk over zFCP. */
static const char s390x_json[] =
    "{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\", \"architecture\": \"s390x\","
    "   \"arch\": \"s390x\", \"type\": \"server\", \"hostname\": \"z1\"},"
    " \"firmware\": {\"mode\": \"zipl\", \"boot_loaders\": [\"zipl\"]},"
    " \"disks\": [{\"name\": \"dasda\", \"size\": 7385333760, \"logical_block_size\": 4096,"
    "   \"dasd\": {\"bus_id\": \"0.0.0200\", \"discipline\": \"ECKD\"},"
    "   \"table\": {\"type\": \"dasd\"},"
    "   \"partitions\": ["
    "    {\"name\": \"dasda1\", \"number\": 1, \"start\": 98304, \"size\": 1073741824,"
    "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"b\"}},"
    "    {\"name\": \"dasda2\", \"number\": 2, \"start\": 1073840128, \"size\": 6000000000,"
    "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"r\"}}]},"
    "  {\"name\": \"sda\", \"size\": 10737418240,"
    "   \"zfcp\": {\"bus_id\": \"0.0.1700\", \"wwpn\": \"0x500507630b0b0000\","
    "     \"lun\": \"0x4010400000000000\"},"
    "   \"table\": {\"type\": \"gpt\"},"
    "   \"partitions\": ["
    "    {\"name\": \"sda1\", \"number\": 1, \"start\": 1048576, \"size\": 10000000000,"
    "     \"type\": \"0fc63daf-8483-4772-8e79-3d69d8477de4\","
    "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"d\"}}]}],"
    " \"fstab\": [{\"spec\": \"UUID=r\", \"file\": \"/\", \"type\": \"ext4\"},"
    "            {\"spec\": \"UUID=b\", \"file\": \"/boot\", \"type\": \"ext4\"},"
    "            {\"spec\": \"UUID=d\", \"file\": \"/srv\", \"type\": \"ext4\"}]"
    "}";

static char *sheet_for(const struct rs_jval *m, enum rs_target t)
{
    struct rs_sheet_opts o;
    struct rs_buf        out;
    struct rs_buf        err;

    memset(&o, 0, sizeof(o));
    o.target = t;
    o.version = "9.9";
    rs_buf_init(&out);
    rs_buf_init(&err);
    CHECK(rs_buildsheet(m, &o, &out, &err));
    CHECK_STR(err.data ? err.data : "", "");
    rs_buf_free(&err);
    return rs_buf_detach(&out);
}

static char *autoinst_for(const struct rs_jval *m, enum rs_target t)
{
    return autoinst_firmware(m, t, NULL);
}

static void arch_cases(void)
{
    struct rs_jval m;
    char          *s;

    TEST_CASE("buildsheet: IBM Z's disks, brought online by their addresses and formatted");
    parse(s390x_json, &m);
    s = sheet_for(&m, RS_TARGET_SAME);
    CHECK_CONTAINS(s, "Firmware   IBM Z IPL, of what zipl writes");
    CHECK_CONTAINS(s, "    chzdev -e dasd 0.0.0200\n");
    CHECK_CONTAINS(s, "    chzdev -e zfcp-lun 0.0.1700:0x500507630b0b0000:0x4010400000000000\n");
    CHECK_CONTAINS(s, "    dasdfmt -b 4096 -d cdl -y -p \"$DISK1\"\n");
    CHECK_CONTAINS(s, "    fdasd \"$DISK1\"   # n for each of these, in order, then w:\n");
    CHECK_CONTAINS(s, "    #   partition 2: ");
    CHECK(strstr(s, "sfdisk \"$DISK1\"") == NULL);
    CHECK_CONTAINS(s, "sfdisk \"$DISK2\"");
    free(s);
    s = autoinst_for(&m, RS_TARGET_SAME);
    CHECK_CONTAINS(s, "ptable: \"vtoc\"");
    CHECK(strstr(s, "grub_device") == NULL);
    free(s);

    TEST_CASE("buildsheet: IBM Z rebuilt as a virtual machine, on virtio disks");
    s = sheet_for(&m, RS_TARGET_VM);
    CHECK(strstr(s, "chzdev") == NULL && strstr(s, "dasdfmt") == NULL);
    CHECK_CONTAINS(s, "--machine s390-ccw-virtio");
    CHECK_CONTAINS(s, "sfdisk \"$DISK1\"");
    free(s);
    s = autoinst_for(&m, RS_TARGET_VM);
    CHECK(strstr(s, "vtoc") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: one partition on a DASD, across it");
    parse("{\"system\": {\"id\": \"ubuntu\", \"version_id\": \"26.04\", \"arch\": \"s390x\"},"
          " \"firmware\": {\"mode\": \"zipl\"},"
          " \"disks\": [{\"name\": \"dasda\", \"size\": 7385333760,"
          "   \"table\": {\"type\": \"dasd\"}, \"partitions\": ["
          "    {\"name\": \"dasda1\", \"number\": 1, \"start\": 98304, \"size\": 7000000000,"
          "     \"content\": {\"type\": \"ext4\", \"usage\": \"filesystem\", \"uuid\": \"r\"}}]}],"
          " \"fstab\": [{\"spec\": \"UUID=r\", \"file\": \"/\", \"type\": \"ext4\"}]}", &m);
    s = sheet_for(&m, RS_TARGET_METAL);
    CHECK_CONTAINS(s, "    fdasd -a \"$DISK1\"\n");
    CHECK(strstr(s, "chzdev") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: rebuilt for another processor, what will not run named");
    server(&m);
    {
        struct rs_jval *sys = (struct rs_jval *)(uintptr_t)rs_jobject_get(&m, "system");
        struct rs_jval *progs = rs_jobj_add(&m, "programs");
        struct rs_jval *p;

        rs_jobj_str(sys, "arch", "aarch64");
        rs_jobj_str(sys, "rebuilt_from", "x86_64");
        rs_jval_set_array(progs);
        p = rs_jarr_add(progs);
        rs_jval_set_object(p);
        rs_jobj_str(p, "path", "/usr/local/bin/tool");
        rs_jobj_str(p, "arch", "amd64");
        p = rs_jarr_add(progs);
        rs_jval_set_object(p);
        rs_jobj_str(p, "path", "/usr/bin/patched");
        rs_jobj_str(p, "arch", "x86_64");
        rs_jobj_str(p, "package", "coreutils");
        p = rs_jarr_add(progs);
        rs_jval_set_object(p);
        rs_jobj_str(p, "path", "/opt/already-arm");
        rs_jobj_str(p, "arch", "aarch64");
    }
    s = sheet_for(&m, RS_TARGET_VM);
    CHECK_CONTAINS(s, "Another processor\n");
    CHECK_CONTAINS(s, "The old machine was x86_64; this one is aarch64.");
    CHECK_CONTAINS(s, "    /usr/local/bin/tool\n");
    CHECK(strstr(s, "/opt/already-arm") == NULL && strstr(s, "    /usr/bin/patched") == NULL);
    CHECK_CONTAINS(s, "1 program a package installed, and then changed, is left as this");
    CHECK_CONTAINS(s, "--machine virt");
    if (rs_arch_built() && strcmp(rs_arch_built()->name, "aarch64") == 0)
    {
        CHECK_CONTAINS(s, "--cpu host-passthrough");
    } else
    {
        CHECK_CONTAINS(s, "        --arch aarch64 \\\n");
        CHECK_CONTAINS(s, "QEMU emulates this aarch64 guest");
    }
    free(s);
    s = autoinst_for(&m, RS_TARGET_VM);
    CHECK_CONTAINS(s, "# Rebuilt for aarch64; the old machine was x86_64.");
    CHECK_CONTAINS(s, "#   /usr/local/bin/tool\n");
    CHECK(strstr(s, "/usr/bin/patched") == NULL);
    free(s);
    rs_jval_free(&m);

    TEST_CASE("buildsheet: rebuilt for another processor, with nothing to build again");
    server(&m);
    {
        struct rs_jval *sys = (struct rs_jval *)(uintptr_t)rs_jobject_get(&m, "system");

        rs_jobj_str(sys, "arch", "riscv64");
        rs_jobj_str(sys, "rebuilt_from", "x86_64");
    }
    s = sheet_for(&m, RS_TARGET_VM);
    CHECK_CONTAINS(s, "keeps no program a package did not install");
    free(s);
    s = autoinst_for(&m, RS_TARGET_VM);
    CHECK_CONTAINS(s, "# as its build for riscv64.\n");
    free(s);
    rs_jval_free(&m);
}

void test_rebuild(void)
{
    package_cases();
    system_package_cases();
    firmware_cases();
    autoinstall_package_cases();
    layout_cases();
    sheet_cases();
    autoinstall_cases();
    clones_cases();
    arch_cases();
}
