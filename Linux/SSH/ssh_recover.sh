#!/bin/bash
# ==============================================================================
# ssh_recover.sh
# SSH Emergency Recovery Script
#
# Use when:
#   - SSH scoring goes Yellow or Red
#   - sshd is masked or won't start
#   - sshd_config was corrupted
#   - Scoring key was removed
#
# Run as root: sudo bash ssh_recover.sh [command]
# ==============================================================================

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/tmp/ncae_backups/ssh"

# ── SCORING KEY ───────────────────────────────────────────────────────────────
# Keep this in sync with ssh_harden.sh
SCORING_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCcM4aDj8Y4COv+f8bd2WsrIynlbRGgDj2+q9aBeW1Umj5euxnO1vWsjfkpKnyE/ORsI6gkkME9ojAzNAPquWMh2YG+n11FB1iZl2S6yuZB7dkVQZSKpVYwRvZv2RnYDQdcVnX9oWMiGrBWEAi4jxcYykz8nunaO2SxjEwzuKdW8lnnh2BvOO9RkzmSXIIdPYgSf8bFFC7XFMfRrlMXlsxbG3u/NaFjirfvcXKexz06L6qYUzob8IBPsKGaRjO+vEdg6B4lH1lMk1JQ4GtGOJH6zePfB6Gf7rp31261VRfkpbpaDAznTzh7bgpq78E7SenatNbezLDaGq3Zra3j53u7XaSVipkW0S3YcXczhte2J9kvo6u6s094vrcQfB9YigH4KhXpCErFk08NkYAEJDdqFqXIjvzsro+2/EW1KKB9aNPSSM9EZzhYc+cBAl4+ohmEPej1m15vcpw3k+kpo1NC2rwEXIFxmvTme1A2oIZZBpgzUqfmvSPwLXF0EyfN9Lk= SCORING KEY DO NOT REMOVE"
# ─────────────────────────────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run as root: sudo bash $0"
        exit 1
    fi
}

cmd_restore_config() {
    echo "[*] Restoring sshd_config from most recent backup..."
    local latest_bak; latest_bak=$(ls -t "$BACKUP_DIR"/sshd_config.bak.* 2>/dev/null | head -1)
    if [[ -z "$latest_bak" ]]; then
        echo "[ERROR] No backup found in $BACKUP_DIR"
        echo "       Run ssh_harden.sh first to create a backup."
        echo "       Or manually fix /etc/ssh/sshd_config"
        return 1
    fi
    cp "$latest_bak" "$SSHD_CONFIG"
    echo "[OK] Config restored from: $latest_bak"
}

cmd_restore_key() {
    local user="${1:-root}"
    echo "[*] Restoring scoring key for user: $user"

    if [[ "$SCORING_KEY" == "PLACEHOLDER_REPLACE_WITH_OFFICIAL_KEY_FROM_COMPETITION_DASHBOARD" ]]; then
        echo "[ERROR] SCORING_KEY is still a placeholder in this script."
        echo "        Edit SCORING_KEY at the top of ssh_recover.sh"
        return 1
    fi

    if ! id "$user" &>/dev/null; then
        echo "[ERROR] User '$user' does not exist."
        return 1
    fi

    local home_dir; home_dir=$(eval echo "~$user")
    local ssh_dir="$home_dir/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$user:$user" "$ssh_dir"
    touch "$auth_keys"

    if ! grep -qF "SCORING KEY DO NOT REMOVE" "$auth_keys"; then
        echo "$SCORING_KEY" >> "$auth_keys"
        echo "[OK] Scoring key added for: $user"
    else
        echo "[OK] Scoring key already present for: $user"
    fi

    chmod 600 "$auth_keys"
    chown "$user:$user" "$auth_keys"
}

cmd_restart() {
    echo "[*] Checking sshd mask status..."
    local status; status=$(systemctl is-enabled sshd 2>/dev/null)

    if [[ "$status" == "masked" ]]; then
        echo "[WARN] sshd is masked. Unmasking..."
        systemctl unmask sshd
        echo "[OK] Unmasked."
    fi

    systemctl enable sshd &>/dev/null

    echo "[*] Testing sshd config..."
    if sshd -t; then
        echo "[OK] Config valid. Restarting sshd..."
        systemctl restart sshd
        sleep 1
        if systemctl is-active --quiet sshd; then
            echo "[OK] sshd is running."
        else
            echo "[ERROR] sshd failed to start. Check: journalctl -xe"
        fi
    else
        echo "[ERROR] Config test failed."
        echo "        Try: sudo $0 restore-config"
        echo "        Then: sudo $0 restart"
        return 1
    fi
}

cmd_status() {
    echo "[*] SSH status:"
    systemctl is-active sshd && echo "  sshd: RUNNING" || echo "  sshd: NOT RUNNING"
    local en; en=$(systemctl is-enabled sshd 2>/dev/null)
    echo "  sshd enabled: $en"
    echo ""
    echo "[*] Port 22:"
    ss -tlnp | grep :22 || echo "  (nothing listening on port 22)"
    echo ""
    echo "[*] Current authorized_keys for root:"
    cat /root/.ssh/authorized_keys 2>/dev/null || echo "  (not found)"
}

cmd_full() {
    local user="${1:-root}"
    echo "=============================="
    echo " Full SSH Recovery"
    echo "=============================="
    cmd_restore_config
    cmd_restore_key "$user"
    cmd_restart
    cmd_status
    echo ""
    echo "[DONE] Full recovery complete."
    echo "VERIFY: Test SSH login from external Kali before assuming it works."
}

usage() {
    echo ""
    echo "Usage: sudo $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  restore-config           Restore sshd_config from most recent backup"
    echo "  restore-key [user]       Restore scoring key (default: root)"
    echo "  restart                  Unmask and restart sshd"
    echo "  status                   Show SSH service and port status"
    echo "  full [user]              Run all steps: restore config + key + restart"
    echo ""
    echo "Examples:"
    echo "  sudo $0 full             # Full recovery for root"
    echo "  sudo $0 full ncae        # Full recovery for user 'ncae'"
    echo "  sudo $0 restore-key alice  # Just restore scoring key for alice"
    echo "  sudo $0 restart          # Just restart sshd"
}

main() {
    check_root
    case "${1:-}" in
        restore-config)  cmd_restore_config ;;
        restore-key)     cmd_restore_key "${2:-root}" ;;
        restart)         cmd_restart ;;
        status)          cmd_status ;;
        full)            cmd_full "${2:-root}" ;;
        *)               usage ;;
    esac
}

main "$@"
