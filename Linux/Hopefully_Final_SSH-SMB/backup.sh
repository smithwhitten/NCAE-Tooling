#!/bin/bash
# backup.sh — Back up SSH and SMB configs/files to backup VM
# Rocky Linux 9 | Shell/SMB node

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# --- CONFIGURABLE ---
BACKUP_VM_USER="[BACKUP_VM_USER]"
BACKUP_VM_HOST="[BACKUP_VM_IP]"
BACKUP_VM_PATH="[BACKUP_VM_DEST_PATH]"
BACKUP_VM_KEY="/root/.ssh/backup_key"
LOCAL_STAGE="/tmp/backup-$(hostname)-$(date +%Y%m%d-%H%M%S)"
# --------------------

echo "[*] Staging backup in $LOCAL_STAGE..."
mkdir -p "$LOCAL_STAGE"

echo "[*] Collecting SSH config and keys..."
mkdir -p "$LOCAL_STAGE/ssh"
cp /etc/ssh/sshd_config                         "$LOCAL_STAGE/ssh/"
cp -r /root/.ssh                                "$LOCAL_STAGE/ssh/root_ssh" 2>/dev/null || true
[ -f /etc/scoring.pub ] && cp /etc/scoring.pub  "$LOCAL_STAGE/ssh/"
[ -f /etc/pointers.pub ] && cp /etc/pointers.pub "$LOCAL_STAGE/ssh/"

echo "[*] Collecting Samba config and data..."
mkdir -p "$LOCAL_STAGE/samba"
cp /etc/samba/smb.conf                          "$LOCAL_STAGE/samba/"
cp -r /srv/samba                                "$LOCAL_STAGE/samba/share_data" 2>/dev/null || true
[ -d /var/lib/samba ] && cp -r /var/lib/samba   "$LOCAL_STAGE/samba/lib"       2>/dev/null || true

echo "[*] Collecting iptables rules..."
mkdir -p "$LOCAL_STAGE/firewall"
iptables-save > "$LOCAL_STAGE/firewall/iptables.rules"
[ -f /etc/sysconfig/iptables ] && \
    cp /etc/sysconfig/iptables "$LOCAL_STAGE/firewall/iptables.saved"

echo "[*] Collecting SELinux state..."
mkdir -p "$LOCAL_STAGE/selinux"
sestatus > "$LOCAL_STAGE/selinux/sestatus.txt"
semanage fcontext -l 2>/dev/null | grep samba > "$LOCAL_STAGE/selinux/samba_fcontext.txt" || true

echo "[*] Compressing archive..."
ARCHIVE="${LOCAL_STAGE}.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname $LOCAL_STAGE)" "$(basename $LOCAL_STAGE)"
echo "    Archive: $ARCHIVE"

echo "[*] Transferring to backup VM..."
if [ -f "$BACKUP_VM_KEY" ]; then
    scp -i "$BACKUP_VM_KEY" -o StrictHostKeyChecking=no \
        "$ARCHIVE" "${BACKUP_VM_USER}@${BACKUP_VM_HOST}:${BACKUP_VM_PATH}/"
else
    echo "[!] No backup key at $BACKUP_VM_KEY — attempting with agent/default key..."
    scp -o StrictHostKeyChecking=no \
        "$ARCHIVE" "${BACKUP_VM_USER}@${BACKUP_VM_HOST}:${BACKUP_VM_PATH}/"
fi

echo "[*] Cleaning up local stage..."
rm -rf "$LOCAL_STAGE"

echo "[+] Backup complete: $(basename $ARCHIVE)"
echo "    Destination: ${BACKUP_VM_USER}@${BACKUP_VM_HOST}:${BACKUP_VM_PATH}/"
