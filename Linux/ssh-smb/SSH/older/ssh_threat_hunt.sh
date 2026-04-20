#!/bin/bash
# ==============================================================================
# ssh_threat_hunt.sh
# SSH Threat Hunting Script — Detect unauthorized keys, suspicious logins,
# PAM tampering, and configuration changes
#
# Run as root: sudo bash ssh_threat_hunt.sh
# Run continuously: watch -n 60 sudo bash ssh_threat_hunt.sh
# ==============================================================================

LOG_FILE="/var/log/ncae_ssh_hunt.log"
SCORING_KEY_FRAGMENT="SCORING KEY DO NOT REMOVE"

log() {
    local msg="[$(date '+%H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run as root: sudo bash $0"
        exit 1
    fi
}

# ── Hunt 1: Check every user's authorized_keys ────────────────────────────────
hunt_authorized_keys() {
    log ""
    log "=== [1] authorized_keys Audit ==="

    while IFS=: read -r user _ uid _ _ home_dir shell; do
        # Skip system/service accounts
        [[ "$shell" == */nologin || "$shell" == */false || "$shell" == */sync ]] && continue

        local auth_keys="$home_dir/.ssh/authorized_keys"
        [[ ! -f "$auth_keys" ]] && continue

        local key_count=0
        local scoring_found=0
        local bad_keys=0

        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            ((key_count++))
            if echo "$line" | grep -qF "$SCORING_KEY_FRAGMENT"; then
                scoring_found=1
            else
                log "  [WARN] UNAUTHORIZED KEY for $user: ${line:0:80}..."
                ((bad_keys++))
            fi
        done < "$auth_keys"

        if [[ $key_count -eq 0 ]]; then
            log "  [INFO] $user: authorized_keys is empty"
        elif [[ $scoring_found -eq 1 && $bad_keys -eq 0 ]]; then
            log "  [OK] $user: scoring key present, no unauthorized keys"
        elif [[ $scoring_found -eq 0 && $key_count -gt 0 ]]; then
            log "  [CRITICAL] $user: scoring key MISSING! ($key_count keys present but none are scoring key)"
        fi
    done < /etc/passwd

    # Root check
    local root_keys="/root/.ssh/authorized_keys"
    if [[ -f "$root_keys" ]]; then
        local scoring_in_root=0
        local bad_in_root=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            if echo "$line" | grep -qF "$SCORING_KEY_FRAGMENT"; then
                scoring_in_root=1
            else
                log "  [WARN] UNAUTHORIZED KEY for root: ${line:0:80}..."
                ((bad_in_root++))
            fi
        done < "$root_keys"
        [[ $scoring_in_root -eq 1 && $bad_in_root -eq 0 ]] && log "  [OK] root: scoring key present, no unauthorized keys"
        [[ $scoring_in_root -eq 0 ]] && log "  [CRITICAL] root: scoring key MISSING!"
    else
        log "  [INFO] root: no authorized_keys file"
    fi

    # Check for recently modified authorized_keys files (last 2 hours)
    log ""
    log "  [*] Checking for recently modified authorized_keys files (last 2 hours)..."
    find /home /root -name "authorized_keys" -mmin -120 2>/dev/null | while IFS= read -r f; do
        log "  [WARN] RECENTLY MODIFIED: $f ($(stat -c '%y' "$f"))"
    done
}

# ── Hunt 2: SSH login activity ────────────────────────────────────────────────
hunt_logins() {
    log ""
    log "=== [2] SSH Login Activity ==="

    log "  [*] Failed login attempts (last 15):"
    grep -i "Failed password\|Invalid user\|authentication failure" /var/log/auth.log 2>/dev/null \
        | tail -15 | while IFS= read -r line; do log "    $line"; done

    log "  [*] Successful logins (last 15):"
    grep -i "Accepted" /var/log/auth.log 2>/dev/null \
        | tail -15 | while IFS= read -r line; do log "    $line"; done

    log "  [*] Currently logged in users:"
    who | while IFS= read -r line; do log "    $line"; done

    log "  [*] Recent login history (last 10):"
    last 2>/dev/null | head -10 | while IFS= read -r line; do log "    $line"; done
}

# ── Hunt 3: PAM configuration ─────────────────────────────────────────────────
hunt_pam() {
    log ""
    log "=== [3] PAM Configuration Check ==="

    # Red team known attack: insert pam_permit or modify common-auth to bypass passwords
    local suspicious_patterns=("pam_permit.so" "nullok_secure" "debug" "pam_succeed_if.*uid.*0")

    for f in /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/login; do
        [[ ! -f "$f" ]] && continue
        for pattern in "${suspicious_patterns[@]}"; do
            if grep -qiE "$pattern" "$f" 2>/dev/null; then
                log "  [WARN] Suspicious PAM entry in $f: pattern '$pattern'"
                grep -iE "$pattern" "$f" | while IFS= read -r line; do log "    $line"; done
            fi
        done
    done

    log "  [*] Checking for recently modified PAM files (last 2 hours)..."
    find /etc/pam.d -mmin -120 -type f 2>/dev/null | while IFS= read -r f; do
        log "  [WARN] RECENTLY MODIFIED PAM file: $f"
    done

    find /lib/x86_64-linux-gnu/security /lib64/security /usr/lib/x86_64-linux-gnu/security \
        -mmin -120 -type f 2>/dev/null | while IFS= read -r f; do
        log "  [WARN] RECENTLY MODIFIED PAM module: $f"
    done
}

# ── Hunt 4: SSH processes and config ─────────────────────────────────────────
hunt_ssh_config() {
    log ""
    log "=== [4] sshd Configuration Check ==="

    local config="/etc/ssh/sshd_config"
    [[ ! -f "$config" ]] && { log "  [ERROR] sshd_config not found!"; return; }

    # Check port
    local port; port=$(grep -E "^\s*Port\s+" "$config" 2>/dev/null | awk '{print $2}' | head -1)
    [[ -z "$port" ]] && port="22"
    [[ "$port" != "22" ]] && log "  [WARN] SSH port is $port — scoring engine expects port 22!" \
        || log "  [OK] Port = 22"

    # Check PubkeyAuthentication
    local pubkey; pubkey=$(grep -E "^\s*PubkeyAuthentication\s+" "$config" 2>/dev/null | awk '{print $2}' | head -1)
    [[ "$pubkey" == "no" ]] && log "  [CRITICAL] PubkeyAuthentication = no — scoring will FAIL!" \
        || log "  [OK] PubkeyAuthentication = ${pubkey:-yes (default)}"

    # Check PasswordAuthentication
    local pwd_auth; pwd_auth=$(grep -E "^\s*PasswordAuthentication\s+" "$config" 2>/dev/null | awk '{print $2}' | head -1)
    [[ "$pwd_auth" == "yes" ]] && log "  [WARN] PasswordAuthentication = yes — password login enabled" \
        || log "  [OK] PasswordAuthentication = ${pwd_auth:-no}"

    # Check service state
    local masked; masked=$(systemctl is-enabled sshd 2>/dev/null)
    [[ "$masked" == "masked" ]] && log "  [CRITICAL] sshd is MASKED — service cannot start!" \
        || log "  [OK] sshd enabled status: $masked"

    systemctl is-active --quiet sshd && log "  [OK] sshd is RUNNING" \
        || log "  [CRITICAL] sshd is NOT RUNNING!"

    # Check port 22 listening
    ss -tlnp 2>/dev/null | grep -q :22 && log "  [OK] Port 22 is listening" \
        || log "  [WARN] Port 22 is NOT listening!"

    # Check for recently modified sshd_config
    find /etc/ssh -mmin -120 -type f 2>/dev/null | while IFS= read -r f; do
        log "  [WARN] RECENTLY MODIFIED: $f"
    done
}

# ── Hunt 5: Suspicious SSH processes / tunnels ───────────────────────────────
hunt_ssh_processes() {
    log ""
    log "=== [5] SSH Process Check ==="

    log "  [*] All SSH processes:"
    ps -aux 2>/dev/null | grep -i "[s]sh" | while IFS= read -r line; do log "    $line"; done

    log "  [*] Established SSH connections:"
    ss -tnp 2>/dev/null | grep -i ssh | while IFS= read -r line; do log "    $line"; done

    log "  [*] Listening on port 22:"
    ss -tlnp 2>/dev/null | grep :22 | while IFS= read -r line; do log "    $line"; done
}

main() {
    check_root
    mkdir -p "$(dirname "$LOG_FILE")"

    echo "=============================="
    echo " SSH Threat Hunt"
    echo " $(date)"
    echo "=============================="

    log "=============================="
    log " SSH Threat Hunt — $(date)"
    log "=============================="

    hunt_authorized_keys
    hunt_logins
    hunt_pam
    hunt_ssh_config
    hunt_ssh_processes

    log ""
    log "=============================="
    log " Hunt complete."
    log " Full log: $LOG_FILE"
    log "=============================="
    echo ""
    echo "Log saved to: $LOG_FILE"
}

main
