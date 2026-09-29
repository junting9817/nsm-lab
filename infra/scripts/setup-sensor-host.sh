#!/usr/bin/env bash
# Host preparation for the sensors (Suricata, Zeek): capture directories, NIC offloads off, retention timer,
# dummy interface for PCAP replay, ET Open rule update timer.
# Idempotent: writes only changed settings and turns off only offloads that are currently on.
source "$(dirname "$0")/lib.sh"
require_root
require_data_mount

SENSOR_IFACE="${SENSOR_IFACE:-ens4}"
REPLAY_IFACE="${REPLAY_IFACE:-nsm-replay0}"
OFFLOAD_FEATURES=(gro gso tso)

# tcpreplay: PCAP replay, python3-scapy: synthetic PCAPs for validation (testing/)
apt_install ethtool tcpreplay python3-scapy

# --- 1) directories -------------------------------------------------------------------------
# The Suricata container's entrypoint chowns its directories to suricata (uid 998).
# Zeek runs with minimal capabilities (no DAC_OVERRIDE), so its directory must be owned by root.
install -d -m 0755 -o root -g root "$DATA_MOUNT/logs/zeek"
install -d -m 0755 "$DATA_MOUNT/logs/suricata" "$DATA_MOUNT/pcap" "$DATA_MOUNT/suricata"

# --- 2) NIC offloads off ---------------------------------------------------------------------
# With GRO/GSO/TSO on, AF_PACKET delivers coalesced packets larger than the MTU, so Suricata's stream
# reassembly and Zeek's analysis no longer match the packets on the wire. (LRO is off [fixed] on virtio.)
if write_if_changed /etc/systemd/system/nsm-nic-offload.service 0644 <<EOF
[Unit]
Description=Disable NIC offloads on $SENSOR_IFACE for packet capture (NSM)
After=network-online.target
Wants=network-online.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ethtool -K $SENSOR_IFACE ${OFFLOAD_FEATURES[*]/%/ off}

[Install]
WantedBy=multi-user.target
EOF
then
  systemctl daemon-reload
fi
systemctl enable nsm-nic-offload.service >/dev/null 2>&1

declare -A FEATURE_NAME=([gro]=generic-receive-offload [gso]=generic-segmentation-offload [tso]=tcp-segmentation-offload)
to_disable=()
for f in "${OFFLOAD_FEATURES[@]}"; do
  ethtool -k "$SENSOR_IFACE" | grep -qE "^${FEATURE_NAME[$f]}: on" && to_disable+=("$f" off)
done
if ((${#to_disable[@]})); then
  log "turning off offloads: ${to_disable[*]}"
  ethtool -K "$SENSOR_IFACE" "${to_disable[@]}"
fi
systemctl start nsm-nic-offload.service

# --- 3) retention timer ------------------------------------------------------------------------
install -m 0755 -o root -g root "$REPO_ROOT/infra/scripts/nsm-retention.sh" /usr/local/sbin/nsm-retention

units_changed=0
if write_if_changed /etc/systemd/system/nsm-retention.service 0644 <<'EOF'
[Unit]
Description=NSM log/PCAP retention and Suricata EVE rotation
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nsm-retention
EOF
then
  units_changed=1
fi
if write_if_changed /etc/systemd/system/nsm-retention.timer 0644 <<'EOF'
[Unit]
Description=Run NSM retention hourly

[Timer]
OnCalendar=*-*-* *:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
then
  units_changed=1
fi
if ((units_changed)); then
  systemctl daemon-reload
fi
systemctl enable --now nsm-retention.timer >/dev/null 2>&1

# --- 4) dummy interface for PCAP replay --------------------------------------------------------
# Packets sent to a dummy interface go nowhere, so replayed traffic never leaves the VM (no internet, no VPC)
# and only the Suricata capturing that interface sees it. networkd only manages en*/eth*, so it ignores this name.
# IPv6 is disabled so the interface's own RS/MLD packets do not show up in validation results.
if write_if_changed /etc/systemd/system/nsm-replay-iface.service 0644 <<EOF
[Unit]
Description=Dummy interface $REPLAY_IFACE for PCAP replay (NSM validation harness)
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link show $REPLAY_IFACE >/dev/null 2>&1 || ip link add $REPLAY_IFACE type dummy; echo 1 > /proc/sys/net/ipv6/conf/$REPLAY_IFACE/disable_ipv6; ip link set dev $REPLAY_IFACE mtu 9000 up'

[Install]
WantedBy=multi-user.target
EOF
then
  systemctl daemon-reload
fi
systemctl enable nsm-replay-iface.service >/dev/null 2>&1
systemctl start nsm-replay-iface.service

# --- 5) ET Open rule update timer -----------------------------------------------------------------
install -m 0755 -o root -g root "$REPO_ROOT/infra/scripts/nsm-rules-update.sh" /usr/local/sbin/nsm-rules-update
install -d -m 0755 /etc/nsm/suricata-update
for f in disable.conf enable.conf modify.conf; do
  install -m 0644 -o root -g root "$REPO_ROOT/sensors/suricata/update/$f" "/etc/nsm/suricata-update/$f"
done

units_changed=0
if write_if_changed /etc/systemd/system/nsm-rules-update.service 0644 <<'EOF'
[Unit]
Description=Update Suricata ET Open rules (NSM)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nsm-rules-update
EOF
then
  units_changed=1
fi
# 03:30 KST — the sensor restart (a few seconds without capture) happens when nobody is working on the lab
if write_if_changed /etc/systemd/system/nsm-rules-update.timer 0644 <<'EOF'
[Unit]
Description=Update Suricata ET Open rules daily

[Timer]
OnCalendar=*-*-* 18:30:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF
then
  units_changed=1
fi
if ((units_changed)); then
  systemctl daemon-reload
fi
systemctl enable --now nsm-rules-update.timer >/dev/null 2>&1

# Download the rules now if there are none yet (before the sensor exists, validate with the image from the compose file)
if [[ ! -s "$DATA_MOUNT/suricata/rules/suricata.rules" ]]; then
  image="$(awk '/^  suricata:/{f=1} f && /image:/{print $2; exit}' "$REPO_ROOT/docker-compose.yml")"
  log "first ET Open download ($image)"
  SURICATA_IMAGE="$image" /usr/local/sbin/nsm-rules-update
fi

# --- summary --------------------------------------------------------------------------------
ethtool -k "$SENSOR_IFACE" | grep -E '^(generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|large-receive-offload):'
systemctl show nsm-retention.timer nsm-rules-update.timer -p Id -p ActiveState -p NextElapseUSecRealtime
ip -br link show dev "$REPLAY_IFACE"
ls -ld "$DATA_MOUNT"/logs/* "$DATA_MOUNT/pcap" "$DATA_MOUNT/suricata"
