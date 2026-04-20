#!/bin/bash
# ==============================================================================
# ssh_harden.sh
# SSH Hardening Script — Harden sshd_config, deploy scoring key, remove bad keys
#
# Run as root: sudo bash ssh_harden.sh
#
# BEFORE RUNNING:
#   1. Set SCORING_KEY below to the real key from the competition dashboard
#   2. Add usernames to ssh_scoring_users_list.txt in this folder
#   3. Run this on every Linux machine that has SSH scored
# ==============================================================================

# ── SCORING KEY ───────────────────────────────────────────────────────────────
# Replace the placeholder below with the ACTUAL scoring key from the competition
# dashboard BEFORE running this script.
#
# The key should look like:
#   ssh-rsa AAAA...very long string... SCORING KEY DO NOT REMOVE
#
# Known key from official NCAE scoring page (verify against competition dashboard
# before competition day — this may change between seasons):
SCORING_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCcM4aDj8Y4COv+f8bd2WsrIynlbRGgDj2+q9aBeW1Umj5euxnO1vWsjfkpKnyE/ORsI6gkkME9ojAzNAPquWMh2YG+n11FB1iZl2S6yuZB7dkVQZSKpVYwRvZv2RnYDQdcVnX9oWMiGrBWEAi4jxcYykz8nunaO2SxjEwzuKdW8lnnh2BvOO9RkzmSXIIdPYgSf8bFFC7XFMfRrlMXlsxbG3u/NaFjirfvcXKexz06L6qYUzob8IBPsKGaRjO+vEdg6B4lH1lMk1JQ4GtGOJH6zePfB6Gf7rp31261VRfkpbpaDAznTzh7bgpq78E7SenatNbezLDaGq3Zra3j53u7XaSVipkW0S3YcXczhte2J9kvo6u6s094vrcQfB9YigH4KhXpCErFk08NkYAEJDdqFqXIjvzsro+2/EW1KKB9aNPSSM9EZzhYc+cBAl4+ohmEPej1m15vcpw3k+kpo1NC2rwEXIFxmvTme1A2oIZZBpgzUqfmvSPwLXF0EyfN9Lk= SCORING KEY DO NOT REMOVE"
# ─────────────────────────────────────────────────────────────────────────────

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/tmp/ncae_backups/ssh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTHORIZED_USERS_FILE="$SCRIPT_DIR/ssh_scoring_users_list.txt"

SKIP_KEY_DEPLOY=0

# ── Root check ────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] This script must be run as root: sudo bash $0"
        exit 1
    fi
}

# ── Validate scoring key was set ─────────────────────────────────────────────
validate_scoring_key() {
    if [[ "$SCORING_KEY" == "PLACEHOLDER_REPLACE_WITH_OFFICIAL_KEY_FROM_COMPETITION_DASHBOARD" ]]; then
        echo "============================================================"
        echo "[WARN] SCORING KEY IS STILL THE PLACEHOLDER"
        echo "       Edit this script and replace SCORING_KEY"
        echo "       with the real key from the competition dashboard."
        echo "       Script will continue WITHOUT deploying the key."
        echo "============================================================"
        SKIP_KEY_DEPLOY=1
    else
        echo "[OK] Scoring key is set."
        SKIP_KEY_DEPLOY=0
    fi
}

# ── Backup sshd_config ────────────────────────────────────────────────────────
backup_config() {
    mkdir -p "$BACKUP_DIR"
    local ts; ts=$(date +%H%M%S)
    cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.bak.$ts"
    echo "[OK] Backed up sshd_config → $BACKUP_DIR/sshd_config.bak.$ts"
}

# ── Add scoring key to a user's authorized_keys ───────────────────────────────
ensure_scoring_key() {
    local user="$1"
    [[ $SKIP_KEY_DEPLOY -eq 1 ]] && return

    if ! id "$user" &>/dev/null; then
        echo "[SKIP] User '$user' not found on this system."
        return
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
        echo "[OK] Scoring key already present: $user"
    fi

    chmod 600 "$auth_keys"
    chown "$user:$user" "$auth_keys"
}

# ── Remove unauthorized keys — keep ONLY the scoring key ─────────────────────
# Inspired by NJIT NCAE removeBadSSHKeys approach
remove_bad_ssh_keys() {
    echo ""
    echo "[*] Scanning all users for unauthorized keys..."
    local total_removed=0

    # Process all users from /etc/passwd
    while IFS=: read -r user _ uid _ _ home_dir shell; do
        # Skip system users with no-login shells
        [[ "$shell" == */nologin || "$shell" == */false || "$shell" == */sync ]] && continue

        local auth_keys="$home_dir/.ssh/authorized_keys"
        [[ ! -f "$auth_keys" ]] && continue

        local tmpfile; tmpfile=$(mktemp)
        local removed_for_user=0

        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && { echo "$line" >> "$tmpfile"; continue; }

            if echo "$line" | grep -qF "SCORING KEY DO NOT REMOVE"; then
                # Keep the scoring key
                echo "$line" >> "$tmpfile"
            else
                echo "[WARN] Unauthorized key removed from $user:"
                echo "       ${line:0:100}..."
                ((removed_for_user++))
                ((total_removed++))
            fi
        done < "$auth_keys"

        if [[ $removed_for_user -gt 0 ]]; then
            mv "$tmpfile" "$auth_keys"
            chmod 600 "$auth_keys"
            chown "$user:$user" "$auth_keys"
        else
            rm -f "$tmpfile"
        fi
    done < /etc/passwd

    # Always check root
    local root_keys="/root/.ssh/authorized_keys"
    if [[ -f "$root_keys" ]]; then
        local tmpfile; tmpfile=$(mktemp)
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && { echo "$line" >> "$tmpfile"; continue; }
            if echo "$line" | grep -qF "SCORING KEY DO NOT REMOVE"; then
                echo "$line" >> "$tmpfile"
            else
                echo "[WARN] Unauthorized key removed from root:"
                echo "       ${line:0:100}..."
                ((total_removed++))
            fi
        done < "$root_keys"
        mv "$tmpfile" "$root_keys"
        chmod 600 "$root_keys"
        chown root:root "$root_keys"
    fi

    echo "[OK] Bad key removal complete. Total keys removed: $total_removed"
}

# ── Apply hardening settings to sshd_config ───────────────────────────────────
harden_sshd() {
    echo ""
    echo "[*] Applying sshd_config hardening settings..."

    declare -A settings=(
        ["PermitRootLogin"]="prohibit-password"  # Key-only root (scoring may need root login)
        ["PasswordAuthentication"]="no"           # Keys only — disables password brute force
        ["PubkeyAuthentication"]="yes"            # MUST stay yes — scoring engine uses this
        ["PermitEmptyPasswords"]="no"             # Never allow blank passwords
        ["X11Forwarding"]="no"                    # Not needed
        ["LoginGraceTime"]="30"                   # Reduce from default 120s
        ["MaxAuthTries"]="3"                      # Limit per-connection auth attempts
        ["ClientAliveInterval"]="300"             # Keepalive every 5 min
        ["ClientAliveCountMax"]="2"               # Drop after 2 missed keepalives
        ["PrintLastLog"]="yes"                    # Show last login info
        ["Banner"]="none"                         # No banner revealing system info
    )

    for key in "${!settings[@]}"; do
        value="${settings[$key]}"
        if grep -qE "^#?\s*${key}\b" "$SSHD_CONFIG"; then
            sed -i "s|^#\?\s*${key}.*|${key} ${value}|" "$SSHD_CONFIG"
        else
            echo "${key} ${value}" >> "$SSHD_CONFIG"
        fi
        echo "  Set: $key = $value"
    done
}

# ── Test config and restart ───────────────────────────────────────────────────
test_and_restart() {
    echo ""
    echo "[*] Testing sshd config validity..."
    if sshd -t; then
        echo "[OK] Config valid. Restarting SSH..."
        systemctl restart sshd
        if systemctl is-active --quiet sshd; then
            echo "[OK] sshd is running."
        else
            echo "[ERROR] sshd failed to start! Check: journalctl -xe"
        fi
    else
        echo "[ERROR] Config test FAILED — restoring most recent backup..."
        local latest_bak; latest_bak=$(ls -t "$BACKUP_DIR"/sshd_config.bak.* 2>/dev/null | head -1)
        if [[ -n "$latest_bak" ]]; then
            cp "$latest_bak" "$SSHD_CONFIG"
            echo "[OK] Backup restored: $latest_bak"
            echo "[INFO] No hardening changes were applied."
        else
            echo "[ERROR] No backup found — cannot auto-restore."
        fi
        exit 1
    fi
}

# ── Print summary of authorized_keys per scored user ─────────────────────────
print_key_summary() {
    echo ""
    echo "=============================="
    echo " authorized_keys Summary"
    echo "=============================="
    local users_to_check=("root")
    [[ -n "$SUDO_USER" && "$SUDO_USER" != "root" ]] && users_to_check+=("$SUDO_USER")

    if [[ -f "$AUTHORIZED_USERS_FILE" ]]; then
        while IFS= read -r user || [[ -n "$user" ]]; do
            [[ -z "$user" || "$user" == \#* ]] && continue
            users_to_check+=("$user")
        done < "$AUTHORIZED_USERS_FILE"
    fi

    # Deduplicate
    local -A seen
    for user in "${users_to_check[@]}"; do
        [[ -n "${seen[$user]}" ]] && continue
        seen[$user]=1
        local home_dir; home_dir=$(eval echo "~$user")
        local auth_keys="$home_dir/.ssh/authorized_keys"
        echo "--- $user ---"
        if [[ -f "$auth_keys" ]]; then
            local count=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                ((count++))
                echo "  Key $count: ${line:0:80}..."
            done < "$auth_keys"
            [[ $count -eq 0 ]] && echo "  (empty file)"
        else
            echo "  (no authorized_keys file)"
        fi
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo "=============================="
    echo " SSH Hardening Script"
    echo " $(date)"
    echo "=============================="

    check_root
    validate_scoring_key
    backup_config

    echo ""
    echo "[*] Deploying scoring key..."
    ensure_scoring_key "root"
    [[ -n "$SUDO_USER" && "$SUDO_USER" != "root" ]] && ensure_scoring_key "$SUDO_USER"

    if [[ -f "$AUTHORIZED_USERS_FILE" ]]; then
        while IFS= read -r user || [[ -n "$user" ]]; do
            [[ -z "$user" || "$user" == \#* ]] && continue
            ensure_scoring_key "$user"
        done < "$AUTHORIZED_USERS_FILE"
    else
        echo "[INFO] No users file found at $AUTHORIZED_USERS_FILE — only root/sudo user processed."
    fi

    remove_bad_ssh_keys
    harden_sshd
    test_and_restart
    print_key_summary

    echo ""
    echo "[DONE] SSH hardening complete."
    echo "Backup location: $BACKUP_DIR/"
    echo ""
    echo "⚠️  IMPORTANT: Test SSH login from ANOTHER terminal BEFORE closing this session."
    echo "    ssh <your-user>@<this-machine-ip>"
}

main
