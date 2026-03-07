#!/bin/bash
# smb_add_users.sh — Create system and Samba users from a list
# Rocky Linux 9 | Shell/SMB node
# Usage: sudo ./smb_add_users.sh <userlist.txt>
#
# userlist.txt format (one per line):
#   username:password

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

if [ -z "${1:-}" ]; then
    echo "Usage: sudo $0 <userlist.txt>"
    echo "File format: username:password  (one per line)"
    exit 1
fi

USERLIST=$(readlink -f "$1")
SMB_GROUP="smb_users"

groupadd "$SMB_GROUP" 2>/dev/null || true

while IFS=: read -r username password || [ -n "$username" ]; do
    [[ -z "$username" || "$username" =~ ^# ]] && continue

    echo "[*] Processing user: $username"

    useradd -M -s /sbin/nologin "$username" 2>/dev/null || echo "  User exists."
    usermod -aG "$SMB_GROUP" "$username"

    (echo "$password"; echo "$password") | smbpasswd -a "$username" -s
    smbpasswd -e "$username"

    echo "[+] Done: $username"

done < "$USERLIST"

echo ""
echo "[+] All users processed."
pdbedit -L
