#!/bin/bash
# ssh_harden.sh — SSH daemon hardening
# Rocky Linux 9 | Shell/SMB node

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d-%H%M%S)"

echo "[*] Backing up sshd_config to $BACKUP..."
cp "$SSHD_CONFIG" "$BACKUP"

apply_setting() {
    local key="$1"
    local value="$2"
    # Remove any existing line (commented or active) for this key
    sed -i -E "/^[[:space:]#]*${key}[[:space:]].*/d" "$SSHD_CONFIG"
    echo "${key} ${value}" >> "$SSHD_CONFIG"
}

echo "[*] Applying hardened sshd settings..."
apply_setting "PermitRootLogin"                  "no"
apply_setting "PubkeyAuthentication"             "yes"
apply_setting "AuthorizedKeysFile"               ".ssh/authorized_keys"
apply_setting "PasswordAuthentication"           "yes"
apply_setting "PermitEmptyPasswords"             "no"
apply_setting "ChallengeResponseAuthentication"  "no"
apply_setting "KerberosAuthentication"           "no"
apply_setting "GSSAPIAuthentication"             "no"
apply_setting "MaxAuthTries"                     "3"
apply_setting "MaxSessions"                      "4"
apply_setting "LoginGraceTime"                   "30"
apply_setting "ClientAliveInterval"              "300"
apply_setting "ClientAliveCountMax"              "2"
apply_setting "SyslogFacility"                   "AUTHPRIV"
apply_setting "LogLevel"                         "VERBOSE"

echo "[*] Setting AllowGroups to highlanders and pointers..."
apply_setting "AllowGroups" "highlanders pointers"

echo "[*] Validating config..."
if ! sshd -t; then
    echo "[!] Config invalid — restoring backup."
    cp "$BACKUP" "$SSHD_CONFIG"
    exit 1
fi

echo "[*] Restarting sshd..."
systemctl restart sshd

echo "[+] SSH hardening complete. Key settings:"
grep -E "^(PermitRootLogin|PubkeyAuthentication|PasswordAuthentication|MaxAuthTries|MaxSessions|AllowGroups|LogLevel)" "$SSHD_CONFIG"
