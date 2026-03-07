#!/bin/bash
# ==============================================================================
# smb_recover.sh
# Samba Emergency Recovery Script
#
# Use when:
#   - SMB scoring goes red (port 445 not responding)
#   - smbd is masked or won't start
#   - smb.conf was corrupted
#   - Need to reset a Samba user password
#
# Run as root: sudo bash smb_recover.sh [command]
# ==============================================================================

SMB_CONF="/etc/samba/smb.conf"
BACKUP_DIR="/tmp/ncae_backups/smb"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run as root: sudo bash $0"
        exit 1
    fi
}

cmd_restore_config() {
    echo "[*] Restoring smb.conf from most recent backup..."
    local latest_bak; latest_bak=$(ls -t "$BACKUP_DIR"/smb.conf.bak.* 2>/dev/null | head -1)
    if [[ -z "$latest_bak" ]]; then
        echo "[ERROR] No backup found in $BACKUP_DIR"
        echo "        Run smb_harden.sh first to create a backup."
        return 1
    fi
    cp "$latest_bak" "$SMB_CONF"
    echo "[OK] smb.conf restored from: $latest_bak"
}

cmd_restart() {
    echo "[*] Checking smbd mask status..."
    local status; status=$(systemctl is-enabled smbd 2>/dev/null)

    if [[ "$status" == "masked" ]]; then
        echo "[WARN] smbd is masked — unmasking..."
        systemctl unmask smbd
        echo "[OK] smbd unmasked."
    fi

    systemctl enable smbd &>/dev/null

    echo "[*] Testing Samba config..."
    if testparm -s &>/dev/null; then
        echo "[OK] Config valid. Restarting smbd..."
        systemctl restart smbd

        if systemctl list-units --type=service 2>/dev/null | grep -q "nmbd"; then
            systemctl restart nmbd 2>/dev/null
            systemctl is-active --quiet nmbd && echo "[OK] nmbd running." || true
        fi

        sleep 1
        if systemctl is-active --quiet smbd; then
            echo "[OK] smbd is running."
        else
            echo "[ERROR] smbd failed to start. Check: journalctl -xe"
        fi
    else
        echo "[ERROR] smb.conf is invalid."
        echo "        Try: sudo $0 restore-config"
        echo "        Then: sudo $0 restart"
        return 1
    fi
}

cmd_status() {
    echo "[*] Samba service status:"
    systemctl is-active smbd && echo "  smbd: RUNNING" || echo "  smbd: NOT RUNNING"
    local en; en=$(systemctl is-enabled smbd 2>/dev/null)
    echo "  smbd enabled: $en"

    echo ""
    echo "[*] Port 445 status:"
    ss -tlnp | grep 445 || echo "  (nothing listening on port 445)"

    echo ""
    echo "[*] Active connections:"
    smbstatus --shares 2>/dev/null || echo "  (smbstatus unavailable)"

    echo ""
    echo "[*] Samba users:"
    pdbedit -L 2>/dev/null || echo "  (pdbedit unavailable)"
}

cmd_reset_user() {
    local user="$1"
    local password="$2"

    if [[ -z "$user" || -z "$password" ]]; then
        echo "[ERROR] Usage: sudo $0 reset-user <username> <newpassword>"
        return 1
    fi

    if ! id "$user" &>/dev/null; then
        echo "[ERROR] System user '$user' does not exist."
        return 1
    fi

    if ! pdbedit -L 2>/dev/null | grep -q "^${user}:"; then
        echo "[*] '$user' not in Samba DB — adding..."
        printf '%s\n%s\n' "$password" "$password" | smbpasswd -a -s "$user"
        smbpasswd -e "$user" &>/dev/null
        echo "[OK] Added and enabled Samba user: $user"
    else
        printf '%s\n%s\n' "$password" "$password" | smbpasswd -s "$user"
        echo "[OK] Samba password reset for: $user"
    fi
}

cmd_full() {
    echo "=============================="
    echo " Full SMB Recovery"
    echo "=============================="
    cmd_restore_config
    cmd_restart
    cmd_status
    echo ""
    echo "[DONE] Full recovery complete."
    echo "VERIFY: Test share access: smbclient //<this-ip>/sharename -U <username>"
}

usage() {
    echo ""
    echo "Usage: sudo $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  restore-config                 Restore smb.conf from most recent backup"
    echo "  restart                        Unmask and restart smbd"
    echo "  status                         Show Samba service and port 445 status"
    echo "  reset-user <user> <password>   Reset Samba password for a user"
    echo "  full                           Run all recovery steps"
    echo ""
    echo "Examples:"
    echo "  sudo $0 full"
    echo "  sudo $0 reset-user alice NewPass123!"
    echo "  sudo $0 restart"
}

main() {
    check_root
    case "${1:-}" in
        restore-config)  cmd_restore_config ;;
        restart)         cmd_restart ;;
        status)          cmd_status ;;
        reset-user)      cmd_reset_user "$2" "$3" ;;
        full)            cmd_full ;;
        *)               usage ;;
    esac
}

main "$@"
