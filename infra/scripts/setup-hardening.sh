#!/usr/bin/env bash
# VM hardening: pinned SSH settings, host firewall (ufw), LLMNR off, automatic security updates, journald size cap.
# Idempotent: converges to the same state on every run and reloads a service only when its settings changed.
source "$(dirname "$0")/lib.sh"
require_root

apt_install ufw unattended-upgrades

# --- 1) SSH ------------------------------------------------------------------
# sshd uses the first value it reads for each keyword, so the 10- prefix makes this drop-in win over later ones.
# KexAlgorithms is left alone: 90_google_keyexchange.conf adds algorithms needed by the console's SSH-in-browser.
SSHD_DROPIN=/etc/ssh/sshd_config.d/10-nsm-hardening.conf
if write_if_changed "$SSHD_DROPIN" 0644 <<'EOF'
# managed by infra/scripts/setup-hardening.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
# only local forwarding (ssh -L, e.g. for remote ClickHouse queries)
AllowTcpForwarding local
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
then
  if ! sshd -t; then
    rm -f "$SSHD_DROPIN"
    die "sshd config test failed — the drop-in was removed again"
  fi
  # reload keeps existing sessions
  systemctl reload ssh
fi

# --- 2) systemd-resolved: LLMNR off -------------------------------------------
# LLMNR listens on 0.0.0.0:5355 and has no use on a cloud VM.
# For resolved drop-ins the last value read wins, hence the 99- prefix.
if write_if_changed /etc/systemd/resolved.conf.d/99-nsm-hardening.conf 0644 <<'EOF'
# managed by infra/scripts/setup-hardening.sh
[Resolve]
LLMNR=no
EOF
then
  systemctl restart systemd-resolved
fi

# --- 3) journald size cap ------------------------------------------------------
# An internet-facing host logs a lot of dropped traffic; protect the 10 GB boot disk.
if write_if_changed /etc/systemd/journald.conf.d/99-nsm.conf 0644 <<'EOF'
# managed by infra/scripts/setup-hardening.sh
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=14day
EOF
then
  systemctl restart systemd-journald
fi

# --- 4) automatic security updates -------------------------------------------------
write_if_changed /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service >/dev/null 2>&1

# --- 5) host firewall (ufw) ------------------------------------------------------
# Order matters: add the SSH allow rule before turning on default deny.
# Ports published by Docker bypass ufw INPUT rules, so container exposure is controlled by
# the bind address and the VPC firewall instead (docs/architecture.md section 5).
ufw allow 22/tcp comment 'ssh - source restricted by VPC firewall' >/dev/null
ufw allow 80/tcp comment 'grafana - D3, docker publish bypasses ufw' >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw logging low >/dev/null
if ! ufw status | grep -q '^Status: active'; then
  ufw --force enable >/dev/null
  log "ufw enabled"
fi

# --- summary -------------------------------------------------------------------
log "effective sshd settings:"
sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication|maxauthtries|allowtcpforwarding|x11forwarding) '
log "resolved LLMNR: $(resolvectl status 2>/dev/null | awk '/Protocols:/{print; exit}' | xargs)"
log "unattended-upgrades: $(systemctl is-active unattended-upgrades), apt-daily-upgrade.timer: $(systemctl is-enabled apt-daily-upgrade.timer)"
ufw status verbose
