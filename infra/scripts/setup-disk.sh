#!/usr/bin/env bash
# Mount the data disk (nsm-data) at /data.
# Safety: only a disk with no signature at all (no filesystem, no partition table) is formatted.
#         An existing ext4 filesystem is reused; any other signature stops the script.
source "$(dirname "$0")/lib.sh"
require_root

DATA_DEVICE="${DATA_DEVICE:-/dev/disk/by-id/google-nsm-data}"

[[ -b "$DATA_DEVICE" ]] || die "$DATA_DEVICE not found — attach the nsm-data disk with Terraform first (infra/terraform/README.md)"

dev="$(readlink -f "$DATA_DEVICE")"
root_disk="/dev/$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")"
[[ "$dev" != "$root_disk" ]] || die "$dev is the boot disk. Stopping."
[[ "$(lsblk -dno TYPE "$dev")" == disk ]] || die "$dev is not a disk device."

fstype="$(blkid -o value -s TYPE "$dev" || true)"
if [[ -z "$fstype" ]]; then
  if [[ -n "$(wipefs -n "$dev")" ]] || (($(lsblk -no NAME "$dev" | wc -l) > 1)); then
    die "$dev has partitions or an unknown signature. Check manually: wipefs -n $dev; lsblk $dev"
  fi
  log "formatting empty disk: $dev (ext4, 0% reserved blocks)"
  # Google's recommended options: no lazy init (initial write performance), discard
  mkfs.ext4 -q -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard -L nsm-data "$dev"
elif [[ "$fstype" != ext4 ]]; then
  die "$dev holds a non-ext4 filesystem ($fstype). Stopping."
else
  log "reusing existing ext4 filesystem: $dev"
fi

uuid="$(blkid -o value -s UUID "$dev")"
install -d -m 0755 "$DATA_MOUNT"

# nofail: the VM still boots without the disk (docker/containerd wait for /data via RequiresMountsFor)
ensure_fstab_line "UUID=$uuid $DATA_MOUNT ext4 discard,defaults,noatime,nofail 0 2" || true

if ! mountpoint -q "$DATA_MOUNT"; then
  mount "$DATA_MOUNT"
  log "mounted: $DATA_MOUNT"
fi

# Common directories. Per-service ownership is set by setup-stack.sh and setup-sensor-host.sh.
install -d -m 0755 "$DATA_MOUNT/logs" "$DATA_MOUNT/logs/suricata" "$DATA_MOUNT/logs/zeek" "$DATA_MOUNT/pcap"

findmnt "$DATA_MOUNT"
df -hT "$DATA_MOUNT"
