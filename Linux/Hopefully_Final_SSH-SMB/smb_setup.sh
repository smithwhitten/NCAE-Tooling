#!/bin/bash
# smb_setup.sh — Samba install, configure, and harden
# Rocky Linux 9 | Shell/SMB node

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# --- CONFIGURABLE ---
SHARE_PATH="/srv/samba/share"
SHARE_NAME="share"
SMB_GROUP="smb_users"
BACKUP_DIR="/root/smb-backup-$(date +%Y%m%d-%H%M%S)"
# --------------------

echo "[*] Installing Samba..."
dnf install -y samba samba-client policycoreutils-python-utils 2>/dev/null | tail -3

echo "[*] Backing up existing config to $BACKUP_DIR..."
mkdir -p "$BACKUP_DIR"
[ -f /etc/samba/smb.conf ] && cp /etc/samba/smb.conf "$BACKUP_DIR/smb.conf.bak"

echo "[*] Creating share directory..."
mkdir -p "$SHARE_PATH"

echo "[*] Creating SMB group..."
groupadd "$SMB_GROUP" 2>/dev/null || true

echo "[*] Writing smb.conf..."
cat > /etc/samba/smb.conf <<EOF
[global]
    workgroup = WORKGROUP
    server string = Samba Server
    netbios name = SHELL
    security = user
    passdb backend = tdbsam
    min protocol = SMB2
    max protocol = SMB3
    restrict anonymous = 2
    map to guest = Never
    guest ok = no
    server signing = mandatory
    oplocks = no
    kernel oplocks = no
    log file = /var/log/samba/log.%m
    max log size = 50
    log level = 2

[${SHARE_NAME}]
    comment = Competition Share
    path = ${SHARE_PATH}
    browseable = yes
    read only = no
    create mask = 0660
    directory mask = 2770
    valid users = @${SMB_GROUP}
    write list = @${SMB_GROUP}
    force group = ${SMB_GROUP}
    guest ok = no
    oplocks = no
    vfs objects = full_audit
    full_audit:prefix = %u|%I|%S
    full_audit:success = open read write mkdir rename unlink
    full_audit:failure = all
    full_audit:facility = local5
    full_audit:priority = notice
EOF

echo "[*] Setting share directory ownership and permissions..."
chown root:"$SMB_GROUP" "$SHARE_PATH"
chmod 2770 "$SHARE_PATH"

echo "[*] Applying SELinux context..."
semanage fcontext -a -t samba_share_t "${SHARE_PATH}(/.*)?"
restorecon -Rv "$SHARE_PATH"

echo "[*] Validating smb.conf..."
if ! testparm -s 2>/dev/null | grep -q "\[${SHARE_NAME}\]"; then
    echo "[!] smb.conf validation failed — check config."
    exit 1
fi

echo "[*] Enabling and starting Samba services..."
systemctl enable --now smb nmb

echo "[+] SMB setup complete."
echo "    Share path:  $SHARE_PATH"
echo "    Share name:  $SHARE_NAME"
echo "    SMB group:   $SMB_GROUP"
echo ""
echo "[!] Next steps:"
echo "    1. Create SMB users:  ./smb_add_users.sh <userlist.txt>"
echo "    2. Verify share:      smbclient //localhost/${SHARE_NAME} -U [user]"
echo "    3. Run backup:        ./backup.sh"
