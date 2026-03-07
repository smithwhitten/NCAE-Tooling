#!/bin/bash
# remote_ssh_setup.sh — Team user creation for SSH access
# Rocky Linux 9 | Shell/SMB node

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# --- CONFIGURABLE ---
ADMIN_GROUP="highlanders"
LIMITED_GROUP="highlanderslow"
# --------------------

echo "[*] Creating groups..."
groupadd "$ADMIN_GROUP"    2>/dev/null || true
groupadd "$LIMITED_GROUP"  2>/dev/null || true

echo "[*] Configuring sudoers for $ADMIN_GROUP..."
echo "%${ADMIN_GROUP} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/10-highlanders
chmod 440 /etc/sudoers.d/10-highlanders

create_team_user() {
    local username="$1"
    local group="$2"
    local pubkey="$3"

    echo "[*] Creating user: $username"
    useradd -c "Team user $username" -G "$group" -s "/bin/bash" "$username" 2>/dev/null || \
        usermod -aG "$group" "$username"

    mkdir -p /home/${username}/.ssh
    echo "$pubkey" > /home/${username}/.ssh/authorized_keys
    chown -R "${username}:${username}" /home/${username}/.ssh
    chmod 700 /home/${username}/.ssh
    chmod 600 /home/${username}/.ssh/authorized_keys
    echo "[+] User $username ready."
}

# Add team users below — one call per person
# create_team_user "[USERNAME]" "$ADMIN_GROUP" "[SSH_PUBLIC_KEY]"

echo "[*] Creating local console-only user..."
useradd -c "Local Only" -G "$ADMIN_GROUP" -s "/bin/bash" "local-admin" 2>/dev/null || true
echo "[!] Set password for local-admin now:"
passwd "local-admin"

echo "[*] Locking root password..."
passwd -dl root

echo "[+] Remote SSH setup complete."
echo "    SSH access limited to groups: $ADMIN_GROUP, $LIMITED_GROUP, pointers"
echo "    Run ssh_harden.sh afterward if not already done."
