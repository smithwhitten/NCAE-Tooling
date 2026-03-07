#!/bin/bash
# scoring_ssh_setup.sh — Scoring user creation and pubkey injection
# Rocky Linux 9 | Shell/SMB node

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# --- CONFIGURABLE ---
SCORING_PUBKEY="[INSERT_SCORING_PUBLIC_KEY]"
SCORING_KEYFILE="/etc/scoring.pub"
SCORING_GROUP="pointers"
SCORING_SHELL="/usr/local/bin/rbash"
# --------------------

echo "[*] Creating restricted shell symlink..."
if [ ! -f "$SCORING_SHELL" ]; then
    ln -s /bin/bash "$SCORING_SHELL"
fi

echo "[*] Creating scoring group '$SCORING_GROUP'..."
groupadd "$SCORING_GROUP" 2>/dev/null || echo "Group already exists."

create_scoring_user() {
    local username="$1"
    echo "[*] Setting up scoring user: $username"
    if id "$username" &>/dev/null; then
        usermod -aG "$SCORING_GROUP" "$username"
        usermod -s "$SCORING_SHELL" "$username"
    else
        useradd -G "$SCORING_GROUP" -s "$SCORING_SHELL" -m "$username"
    fi
}

# Add scoring users here — one call per user
# create_scoring_user "[SCORING_USERNAME]"

echo "[*] Writing scoring pubkey to $SCORING_KEYFILE..."
echo "$SCORING_PUBKEY" > "$SCORING_KEYFILE"
chmod 644 "$SCORING_KEYFILE"

echo "[*] Appending Match Group block to sshd_config..."
SSHD_CONFIG="/etc/ssh/sshd_config"

# Remove existing Match Group block for pointers if present
sed -i '/^Match Group '"$SCORING_GROUP"'/,/^Match\|^$/{ /^Match Group '"$SCORING_GROUP"'/d; /AuthorizedKeysFile \/etc\/scoring\.pub/d }' "$SSHD_CONFIG" 2>/dev/null || true

cat >> "$SSHD_CONFIG" <<EOF

Match Group ${SCORING_GROUP}
    AuthorizedKeysFile ${SCORING_KEYFILE}
EOF

echo "[*] Validating sshd config..."
if ! sshd -t; then
    echo "[!] Config invalid — check sshd_config manually."
    exit 1
fi

echo "[*] Restarting sshd..."
systemctl restart sshd

echo "[+] Scoring SSH setup complete."
echo "    Group:     $SCORING_GROUP"
echo "    Key file:  $SCORING_KEYFILE"
echo "    Shell:     $SCORING_SHELL"
