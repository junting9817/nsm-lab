#!/usr/bin/env bash
# Generates a known set of honeypot events with the stock OpenSSH client: 2 rejected logins, 1 accepted login and one command.
# Targets are restricted to the honeypot this project created (validate.sh passes the Terraform output) or a local test container.
#
#   testing/honeypot/ssh_attempts.sh <host> <port> <run_id> [extra command for the accepted session]
#
# Cowrie's default user database rejects root/root and root/123456 and accepts root with any other password,
# so the events are deterministic: cowrie.login.failed ×2, cowrie.login.success, cowrie.command.input.
set -Eeuo pipefail

host="${1:?usage: $0 <host> <port> <run_id>}"
port="${2:?usage: $0 <host> <port> <run_id>}"
run_id="${3:?usage: $0 <host> <port> <run_id>}"
extra="${4:-}"
[[ "$run_id" =~ ^[A-Za-z0-9-]+$ ]] || { echo "run_id must be alphanumeric/dashes" >&2; exit 2; }

askpass="$(mktemp)"
trap 'rm -f "$askpass"' EXIT
chmod 700 "$askpass"

attempt() {
  local password="$1" command="$2"
  printf '#!/bin/sh\nprintf "%%s\\n" %q\n' "$password" >"$askpass"
  # BatchMode must stay off for SSH_ASKPASS; a throwaway known_hosts avoids trusting or storing the honeypot host key.
  SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none timeout 30 \
    ssh -p "$port" -T \
      -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 \
      "root@$host" "$command" </dev/null
}

if attempt root 'true'; then echo "unexpected: root/root accepted" >&2; fi
if attempt 123456 'true'; then echo "unexpected: root/123456 accepted" >&2; fi
attempt "nsm-validate-$run_id" "echo nsm-validate-$run_id; uname -a${extra:+; $extra}" || true
