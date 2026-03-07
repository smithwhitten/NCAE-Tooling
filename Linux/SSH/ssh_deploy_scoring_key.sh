#!/bin/bash
# ==============================================================================
# ssh_deploy_scoring_key.sh
# Deploy the scoring public key to all users in ssh_scoring_users_list.txt
# Also audits for unauthorized keys and reports them (does NOT remove them)
# Use ssh_harden.sh to remove bad keys
#
# Run as root: sudo bash ssh_deploy_scoring_key.sh
# ==============================================================================

# ── SCORING KEY ───────────────────────────────────────────────────────────────
# Known key from official NCAE scoring page.
# VERIFY against the competition dashboard before competition day.
SCORING_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCcM4aDj8Y4COv+f8bd2WsrIynlbRGgDj2+q9aBeW1Umj5euxnO1vWsjfkpKnyE/ORsI6gkkME9ojAzNAPquWMh2YG+n11FB1iZl2S6yuZB7dkVQZSKpVYwRvZv2RnYDQdcVnX9oWMiGrBWEAi4jxcYykz8nunaO2SxjEwzuKdW8lnnh2BvOO9RkzmSXIIdPYgSf8bFFC7XFMfRrlMXlsxbG3u/NaFjirfvcXKexz06L6qYUzob8IBPsKGaRjO+vEdg6B4lH1lMk1JQ4GtGOJH6zePfB6Gf7rp31261VRfkpbpaDAznTzh7bgpq78E7SenatNbezLDaGq3Zra3j53u7XaSVipkW0S3YcXczhte2J9kvo6u6s094vrcQfB9YigH4KhXpCErFk08NkYAEJDdqFqXIjvzsro+2/EW1KKB9aNPSSM9EZzhYc+cBAl4+ohmEPej1m15vcpw3k+kpo1NC2rwEXIFxmvTme1A2oIZZBpgzUqfmvSPwLXF0EyfN9Lk= SCORING KEY DO NOT REMOVE"
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USERS_FILE="$SCRIPT_DIR/ssh_scoring_users_list.txt"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run as root: sudo bash $0"
        exit 1
    fi
}

ensure_scoring_key() {
    local user="$1"
    if ! id "$user" &>/dev/null; then
        echo "[SKIP] User '$user' does not exist — skipping."
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
        echo "[OK] Scoring key ADDED for: $user"
    else
        echo "[OK] Scoring key already present: $user"
    fi

    chmod 600 "$auth_keys"
    chown "$user:$user" "$auth_keys"
}

audit_unauthorized_keys() {
    echo ""
    echo "=============================="
    echo " Unauthorized Key Audit"
    echo " (report only — use ssh_harden.sh to remove)"
    echo "=============================="
    local found=0

    while IFS=: read -r user _ _ _ _ home_dir shell; do
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        local auth_keys="$home_dir/.ssh/authorized_keys"
        [[ ! -f "$auth_keys" ]] && continue

        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            if ! echo "$line" | grep -qF "SCORING KEY DO NOT REMOVE"; then
                echo "[WARN] Unauthorized key found for $user:"
                echo "  ${line:0:100}..."
                found=1
            fi
        done < "$auth_keys"
    done < /etc/passwd

    local root_keys="/root/.ssh/authorized_keys"
    if [[ -f "$root_keys" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            if ! echo "$line" | grep -qF "SCORING KEY DO NOT REMOVE"; then
                echo "[WARN] Unauthorized key found for root:"
                echo "  ${line:0:100}..."
                found=1
            fi
        done < "$root_keys"
    fi

    [[ $found -eq 0 ]] && echo "[OK] No unauthorized keys found."
}

print_summary() {
    echo ""
    echo "=============================="
    echo " authorized_keys Summary"
    echo "=============================="
    if [[ -f "$USERS_FILE" ]]; then
        while IFS= read -r user || [[ -n "$user" ]]; do
            [[ -z "$user" || "$user" == \#* ]] && continue
            local home_dir; home_dir=$(eval echo "~$user")
            local auth_keys="$home_dir/.ssh/authorized_keys"
            echo "--- $user ---"
            if [[ -f "$auth_keys" ]]; then
                cat "$auth_keys" | while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    echo "  ${line:0:80}..."
                done
            else
                echo "  (no authorized_keys)"
            fi
        done < "$USERS_FILE"
    fi
    echo "--- root ---"
    if [[ -f "/root/.ssh/authorized_keys" ]]; then
        cat "/root/.ssh/authorized_keys" | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "  ${line:0:80}..."
        done
    else
        echo "  (no authorized_keys)"
    fi
}

main() {
    echo "=============================="
    echo " SSH Scoring Key Deployment"
    echo " $(date)"
    echo "=============================="
    check_root

    if [[ ! -f "$USERS_FILE" ]]; then
        echo "[ERROR] Users file not found: $USERS_FILE"
        echo "Create it with one username per line."
        exit 1
    fi

    echo "[*] Deploying scoring key from: $USERS_FILE"
    while IFS= read -r user || [[ -n "$user" ]]; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        ensure_scoring_key "$user"
    done < "$USERS_FILE"

    # Always ensure root has the key
    ensure_scoring_key "root"

    print_summary
    audit_unauthorized_keys

    echo ""
    echo "[DONE] Scoring key deployment complete."
}

main
