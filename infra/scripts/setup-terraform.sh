#!/usr/bin/env bash
# Install the Terraform CLI from HashiCorp's official apt repository.
# The repository signing key is trusted only if it matches the fingerprint published on the official security page:
#   https://www.hashicorp.com/trust/security — "Linux Package Repository Keys"
source "$(dirname "$0")/lib.sh"
require_root

# shellcheck source=/dev/null
. /etc/os-release

# Current key since the rotation on 2026-09-10. The previous key (798A EC65 … A621 E701) is no longer used.
HASHICORP_APT_KEY_FPR="D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"
KEYRING=/etc/apt/keyrings/hashicorp.asc

apt_install ca-certificates curl python3

install -d -m 0755 /etc/apt/keyrings
if [[ ! -s "$KEYRING" ]]; then
  tmp="$(mktemp)"
  curl -fsSL https://apt.releases.hashicorp.com/gpg -o "$tmp"
  install -m 0644 "$tmp" "$KEYRING.new"
  rm -f "$tmp"
  mv "$KEYRING.new" "$KEYRING"
  log "downloaded HashiCorp repository key"
fi

# Re-check the fingerprint on every run (stops here if the key file ever changes)
fpr="$(pgp_primary_fingerprint "$KEYRING")"
if [[ "$fpr" != "$HASHICORP_APT_KEY_FPR" ]]; then
  rm -f "$KEYRING"
  die "HashiCorp key fingerprint mismatch (got $fpr). The key was removed; re-check the fingerprint on the official page."
fi
log "HashiCorp key fingerprint verified: $fpr"

write_if_changed /etc/apt/sources.list.d/hashicorp.sources 0644 <<EOF || true
Types: deb
URIs: https://apt.releases.hashicorp.com
Suites: $VERSION_CODENAME
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: $KEYRING
EOF

apt_install terraform

terraform version
