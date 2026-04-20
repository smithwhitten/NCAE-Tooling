#!/bin/bash
# ==============================================================================
# smb_harden.sh
# Samba Hardening Script — Harden smb.conf, audit users/shares, restart safely
#
# Run as root: sudo bash smb_harden.sh
# ==============================================================================

SMB_CONF="/etc/samba/smb.conf"
BACKUP_DIR="/tmp/ncae_backups/smb"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run as root: sudo bash $0"
        exit 1
    fi
}

check_samba_installed() {
    if ! command -v smbd &>/dev/null; then
        echo "[ERROR] Samba not found. Install: sudo apt install samba"
        exit 1
    fi
    echo "[OK] Samba: $(smbd --version)"
}

backup_smb_conf() {
    mkdir -p "$BACKUP_DIR"
    if [[ -f "$SMB_CONF" ]]; then
        local ts; ts=$(date +%H%M%S)
        cp "$SMB_CONF" "$BACKUP_DIR/smb.conf.bak.$ts"
        echo "[OK] Backed up smb.conf → $BACKUP_DIR/smb.conf.bak.$ts"
    else
        echo "[WARN] $SMB_CONF not found — no backup created."
    fi
}

# Set or update a key=value in the [global] section of smb.conf
set_global_option() {
    local key="$1"
    local value="$2"
    if grep -qE "^\s*#?\s*${key}\s*=" "$SMB_CONF" 2>/dev/null; then
        sed -i "s|^\s*#\?\s*${key}\s*=.*|   ${key} = ${value}|" "$SMB_CONF"
    else
        # Insert after [global] line
        sed -i "/^\[global\]/a\\   ${key} = ${value}" "$SMB_CONF"
    fi
    echo "  Set: $key = $value"
}

harden_global() {
    echo "[*] Applying [global] hardening settings..."

    # Disable anonymous access completely
    set_global_option "map to guest"        "Never"
    set_global_option "restrict anonymous"  "2"
    set_global_option "guest account"       "nobody"

    # Enforce minimum SMB2 — disable insecure SMB1 (EternalBlue vector)
    set_global_option "server min protocol" "SMB2"

    # Require SMB signing — prevents NTLM relay attacks
    set_global_option "server signing"      "mandatory"

    # Disable printer sharing (not needed, reduces attack surface)
    set_global_option "load printers"       "no"
    set_global_option "printing"            "bsd"
    set_global_option "printcap name"       "/dev/null"
    set_global_option "disable spoolss"     "yes"

    # Enable logging
    set_global_option "log level"           "2"
    set_global_option "log file"            "/var/log/samba/log.%m"
    set_global_option "max log size"        "1000"
}

check_guest_shares() {
    echo ""
    echo "[*] Checking for guest-accessible shares..."
    local found=0

    if grep -iE "^\s*guest ok\s*=\s*yes" "$SMB_CONF" 2>/dev/null; then
        echo "[WARN] 'guest ok = yes' found — anonymous share access enabled!"
        found=1
    fi
    if grep -iE "^\s*map to guest\s*=\s*(bad user|bad password)" "$SMB_CONF" 2>/dev/null; then
        echo "[WARN] 'map to guest' allows anonymous fallback!"
        found=1
    fi
    [[ $found -eq 0 ]] && echo "[OK] No guest-accessible shares found."
}

audit_samba_users() {
    echo ""
    echo "[*] Samba user database:"
    pdbedit -L 2>/dev/null || echo "  (pdbedit unavailable)"
    echo ""
    echo "[*] Account flags:"
    pdbedit -Lv 2>/dev/null | grep -E "^Unix username:|^Account Flags:|^Password last set" || true
}

audit_shares() {
    echo ""
    echo "[*] Defined shares:"
    testparm -s 2>/dev/null | grep -E "^\[|^\s*path\s*=" | while IFS= read -r line; do echo "  $line"; done \
        || echo "  (testparm unavailable)"

    echo ""
    echo "[*] Share directory permissions:"
    while IFS= read -r line; do
        if [[ "$line" =~ path[[:space:]]*=[[:space:]]*(.+) ]]; then
            local path="${BASH_REMATCH[1]// /}"
            if [[ -d "$path" ]]; then
                echo "  $path"
                ls -ld "$path"
            fi
        fi
    done < "$SMB_CONF"
}

test_and_restart() {
    echo ""
    echo "[*] Testing Samba config with testparm..."
    if testparm -s &>/dev/null; then
        echo "[OK] Config valid. Restarting smbd..."
        systemctl restart smbd

        if systemctl list-units --type=service 2>/dev/null | grep -q "nmbd"; then
            systemctl restart nmbd 2>/dev/null
            systemctl is-active --quiet nmbd && echo "[OK] nmbd running." || echo "[INFO] nmbd not running (may not be installed)."
        fi

        if systemctl is-active --quiet smbd; then
            echo "[OK] smbd is running."
        else
            echo "[ERROR] smbd failed to start! Check: journalctl -xe"
        fi

        echo ""
        echo "[*] Port 445 status:"
        ss -tlnp | grep 445 || echo "  [WARN] Port 445 not listening!"

    else
        echo "[ERROR] Config test failed — restoring backup..."
        local latest_bak; latest_bak=$(ls -t "$BACKUP_DIR"/smb.conf.bak.* 2>/dev/null | head -1)
        if [[ -n "$latest_bak" ]]; then
            cp "$latest_bak" "$SMB_CONF"
            echo "[OK] Backup restored: $latest_bak"
        else
            echo "[ERROR] No backup found — manual recovery required."
        fi
        exit 1
    fi
}

main() {
    echo "=============================="
    echo " Samba Hardening Script"
    echo " $(date)"
    echo "=============================="

    check_root
    check_samba_installed
    backup_smb_conf

    echo ""
    harden_global
    check_guest_shares
    audit_samba_users
    audit_shares
    test_and_restart

    echo ""
    echo "[DONE] Samba hardening complete."
    echo "Backup location: $BACKUP_DIR/"
    echo ""
    echo "IMPORTANT: Verify share access still works after hardening:"
    echo "  smbclient //<this-ip>/sharename -U <username>"
}

main
