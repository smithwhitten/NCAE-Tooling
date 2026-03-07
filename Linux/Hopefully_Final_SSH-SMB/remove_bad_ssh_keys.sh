#!/bin/bash
# remove_bad_ssh_keys.sh — Audit and remove unauthorized SSH keys
# Rocky Linux 9 | Shell/SMB node

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# --- CONFIGURABLE ---
# Users whose authorized_keys will NOT be touched
PRESERVE_USERS=("local-admin")

# Keys that must never be removed (e.g. scoring key fingerprint or full key string)
# Add the scoring public key string here so it is never deleted
PROTECTED_KEY="[INSERT_SCORING_PUBLIC_KEY]"
# --------------------

echo "[*] Starting SSH key audit..."

while IFS=: read -r username _ uid _ _ homedir shell; do
    # Skip system accounts (UID < 1000) and nologin shells
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue

    auth_file="$homedir/.ssh/authorized_keys"
    [ -f "$auth_file" ] || continue

    # Skip preserved users entirely
    if [[ " ${PRESERVE_USERS[*]} " =~ " ${username} " ]]; then
        echo "[~] Skipping preserved user: $username"
        continue
    fi

    echo "[*] Auditing keys for: $username"

    # Build a cleaned file: keep only lines containing the protected key
    tmp_file=$(mktemp)
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        if echo "$line" | grep -qF "$PROTECTED_KEY"; then
            echo "$line" >> "$tmp_file"
            echo "  [+] Kept scoring key for $username"
        else
            echo "  [-] Removed unauthorized key: ${line:0:60}..."
        fi
    done < "$auth_file"

    # Replace original with cleaned version
    mv "$tmp_file" "$auth_file"
    chown "${username}:${username}" "$auth_file"
    chmod 600 "$auth_file"

done < /etc/passwd

echo "[+] Key audit complete."
