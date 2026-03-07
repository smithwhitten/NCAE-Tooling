#!/bin/bash
# add_scoring_pubkeys.sh — Inject scoring pubkey into a list of users
# Rocky Linux 9 | Shell/SMB node
# Usage: sudo ./add_scoring_pubkeys.sh <userlist.txt>

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

if [ -z "${1:-}" ]; then
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

USERLIST=$(readlink -f "$1")
if [ ! -f "$USERLIST" ]; then
    echo "File not found: $USERLIST"
    exit 1
fi

# --- CONFIGURABLE ---
PUBKEY="[INSERT_SCORING_PUBLIC_KEY]"
# --------------------

echo "[*] Injecting scoring pubkey from list: $USERLIST"

while read -r user || [ -n "$user" ]; do
    [[ -z "$user" || "$user" =~ ^# ]] && continue

    if ! id "$user" &>/dev/null; then
        echo "[!] Skipping $user — does not exist."
        continue
    fi

    ssh_dir="/home/$user/.ssh"
    auth_file="$ssh_dir/authorized_keys"

    mkdir -p "$ssh_dir"

    if [ ! -f "$auth_file" ] || ! grep -qF "$PUBKEY" "$auth_file"; then
        echo "$PUBKEY" >> "$auth_file"
        echo "[+] Added key for $user."
    else
        echo "[~] Key already present for $user."
    fi

    chown -R "$user:$user" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_file"

done < "$USERLIST"

echo "[+] Done."
