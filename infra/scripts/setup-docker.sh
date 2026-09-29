#!/usr/bin/env bash
# Install Docker Engine and the Compose plugin from Docker's official repository.
# All images and layers live on /data: the boot disk's 6 GB of free space cannot hold the ClickHouse, Grafana,
# Suricata and Zeek images.
#  - Docker data-root   → /data/docker
#  - containerd storage → /data/containerd (bind-mounted on /var/lib/containerd)
#    Docker versions that use the containerd image store keep layers there, not under data-root.
source "$(dirname "$0")/lib.sh"
require_root
require_data_mount

# shellcheck source=/dev/null
. /etc/os-release

apt_install ca-certificates curl

# --- 1) prepare storage before installing packages (so nothing lands on the default paths) -----------
install -d -m 0711 "$DATA_MOUNT/docker"
install -d -m 0711 "$DATA_MOUNT/containerd" /var/lib/containerd
ensure_fstab_line "$DATA_MOUNT/containerd /var/lib/containerd none bind,nofail,x-systemd.requires-mounts-for=$DATA_MOUNT 0 0" || true
if ! mountpoint -q /var/lib/containerd; then
  mount /var/lib/containerd
  log "bind mount: /var/lib/containerd → $DATA_MOUNT/containerd"
fi

daemon_changed=0
if write_if_changed /etc/docker/daemon.json 0644 <<EOF
{
  "data-root": "$DATA_MOUNT/docker",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true
}
EOF
then
  daemon_changed=1
fi

# If a service starts before /data is mounted it writes into the empty mountpoint directory. Prevent that.
units_changed=0
for unit in docker containerd; do
  if write_if_changed "/etc/systemd/system/$unit.service.d/10-nsm-data-mount.conf" 0644 <<EOF
[Unit]
RequiresMountsFor=$DATA_MOUNT /var/lib/containerd
EOF
  then
    units_changed=1
  fi
done
if ((units_changed)); then
  systemctl daemon-reload
fi

# Transparent huge pages (THP): the Debian cloud image defaults to always.
# With always, ClickHouse (jemalloc) grabs memory in 2 MiB pages and RSS bloats (ClickHouse warns at startup; upstream recommends madvise).
if write_if_changed /etc/tmpfiles.d/nsm-thp.conf 0644 <<'EOF'
# managed by infra/scripts/setup-docker.sh
w /sys/kernel/mm/transparent_hugepage/enabled - - - - madvise
EOF
then
  systemd-tmpfiles --create /etc/tmpfiles.d/nsm-thp.conf
fi
grep -q '\[madvise\]' /sys/kernel/mm/transparent_hugepage/enabled || systemd-tmpfiles --create /etc/tmpfiles.d/nsm-thp.conf
log "THP: $(cat /sys/kernel/mm/transparent_hugepage/enabled)"

# --- 2) Docker's official repository -------------------------------------------------------------------
install -d -m 0755 /etc/apt/keyrings
if [[ ! -s /etc/apt/keyrings/docker.asc ]]; then
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
fi

write_if_changed /etc/apt/sources.list.d/docker.sources 0644 <<EOF || true
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $VERSION_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# --- 3) services -----------------------------------------------------------------------------
systemctl enable --now containerd docker >/dev/null 2>&1
if ((daemon_changed)); then
  systemctl restart docker
  log "docker restarted (daemon.json changed)"
fi

docker version --format 'Docker Engine {{.Server.Version}}'
docker compose version
docker info --format 'DockerRootDir={{.DockerRootDir}} Driver={{.Driver}} Cgroup={{.CgroupVersion}}'
df -h "$DATA_MOUNT" /
