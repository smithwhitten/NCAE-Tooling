#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — Web Content Backup & Restore
# =============================================================================
# Backs up web root content (HTML, PHP, uploads, etc.) with integrity
# hashing to detect defacement or webshell injection.
#
# Usage:
#   sudo ./06_backup_webcontent.sh backup
#   sudo ./06_backup_webcontent.sh restore
#   sudo ./06_backup_webcontent.sh scan    — Scan for webshells / suspicious files
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="webcontent"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

# Common web root locations — script will check which exist
WEB_ROOTS=(
    /var/www/html
    /var/www
    /srv/www
    /usr/share/nginx/html
    /var/www/localhost/htdocs    # Gentoo
)

# Max size for backup (in MB) — warn if exceeded
MAX_SIZE_MB=2048

# ── Logging ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()   { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()  { log "INFO " "${GREEN}$*${NC}"; }
warn()  { log "WARN " "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
alert() { log "ALERT" "${RED}⚠️  $*${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { error "Must run as root."; exit 1; }
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_ROOT"

# Find active web roots
find_active_webroots() {
    local found=()
    for root in "${WEB_ROOTS[@]}"; do
        [[ -d "$root" ]] && found+=("$root")
    done
    echo "${found[@]:-}"
}

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== Web Content Backup: $TIMESTAMP ==="

    mapfile -t active_roots < <(find_active_webroots | tr ' ' '\n')

    if [[ ${#active_roots[@]} -eq 0 ]]; then
        warn "No web roots found. Check WEB_ROOTS array in script configuration."
        exit 0
    fi

    for webroot in "${active_roots[@]}"; do
        info "Processing: $webroot"

        # Check size first
        local size_mb
        size_mb=$(du -sm "$webroot" 2>/dev/null | awk '{print $1}')
        if (( size_mb > MAX_SIZE_MB )); then
            warn "  Web root is ${size_mb}MB (limit: ${MAX_SIZE_MB}MB). Backing up anyway — may be slow."
        fi

        dest="${BACKUP_DIR}${webroot}"
        mkdir -p "$dest"
        # --exclude common cache/temp dirs that inflate size
        rsync -a --quiet \
            --exclude="*.tmp" \
            --exclude="__pycache__" \
            --exclude="*.pyc" \
            --exclude=".git" \
            "$webroot/" "$dest/"
        info "  Backed up: $webroot (${size_mb}MB)"
    done

    # Generate hash manifest
    info "Generating SHA-256 manifest (may take a moment for large sites)..."
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"
    info "✅ Web content backup complete: $BACKUP_DIR"

    # Run scan automatically
    do_scan
}

# ── Webshell / Defacement Scanner ─────────────────────────────────────────────
do_scan() {
    info "=== Web Content Security Scan ==="
    mapfile -t active_roots < <(find_active_webroots | tr ' ' '\n')

    local issues=0

    for webroot in "${active_roots[@]}"; do
        info "Scanning: $webroot"

        # ── PHP Webshell Signatures ───────────────────────────────────────────
        info "  Checking for PHP webshell patterns..."

        # Common webshell functions (eval(base64_decode), system(), passthru(), etc.)
        local php_patterns=(
            'eval\s*\(\s*base64_decode'
            'eval\s*\(\s*gzinflate'
            'eval\s*\(\s*str_rot13'
            'preg_replace\s*\(.*\/e[^"]*,'
            '\$_\(GET\|POST\|REQUEST\|COOKIE\|SERVER\)\[.*\].*eval'
            'passthru\s*\('
            'shell_exec\s*\('
            'proc_open\s*\('
            'popen\s*\('
            'assert\s*\(\s*\$_'
            'move_uploaded_file'
        )

        for pattern in "${php_patterns[@]}"; do
            local matches
            matches=$(grep -rlE "$pattern" "$webroot" --include="*.php" 2>/dev/null || true)
            if [[ -n "$matches" ]]; then
                alert "  WEBSHELL PATTERN '$pattern' found in:"
                echo "$matches" | while read -r f; do
                    alert "    $f"
                    echo "    $(stat -c 'Modified: %y | Owner: %U' "$f")"
                done | tee -a "$LOG_FILE"
                ((issues++))
            fi
        done

        # ── PHP files in upload directories ───────────────────────────────────
        for upload_dir in uploads upload files images img; do
            if [[ -d "${webroot}/${upload_dir}" ]]; then
                local php_in_uploads
                php_in_uploads=$(find "${webroot}/${upload_dir}" -name "*.php" -o -name "*.phtml" 2>/dev/null || true)
                if [[ -n "$php_in_uploads" ]]; then
                    alert "  PHP file(s) in upload directory ${upload_dir}/ — possible webshell:"
                    echo "$php_in_uploads" | tee -a "$LOG_FILE"
                    ((issues++))
                fi
            fi
        done

        # ── Suspicious file extensions ────────────────────────────────────────
        info "  Checking for suspicious file extensions..."
        suspicious_files=$(find "$webroot" \
            \( -name "*.php5" -o -name "*.phtml" -o -name "*.shtml" -o \
               -name "*.cgi" -o -name "*.pl" -o -name "c99.php" -o \
               -name "r57.php" -o -name "shell.php" -o -name "cmd.php" \) \
            2>/dev/null || true)
        if [[ -n "$suspicious_files" ]]; then
            alert "  Suspicious file extensions found:"
            echo "$suspicious_files" | tee -a "$LOG_FILE"
            ((issues++))
        fi

        # ── World-writable files ──────────────────────────────────────────────
        info "  Checking for world-writable files..."
        world_writable=$(find "$webroot" -perm -0002 -type f 2>/dev/null | head -20 || true)
        if [[ -n "$world_writable" ]]; then
            warn "  World-writable files (first 20):"
            echo "$world_writable" | tee -a "$LOG_FILE"
            ((issues++))
        fi

        # ── Recently modified files (last 24 hours) ───────────────────────────
        info "  Files modified in the last 24 hours:"
        recent=$(find "$webroot" -mtime -1 -type f 2>/dev/null || true)
        if [[ -n "$recent" ]]; then
            warn "  Recently modified files:"
            echo "$recent" | tee -a "$LOG_FILE"
        else
            info "  No files modified in last 24h."
        fi

        # ── Integrity check against backup ────────────────────────────────────
        if [[ -L "$LATEST_LINK" && -f "${LATEST_LINK}/sha256sums.txt" ]]; then
            info "  Comparing against backup hashes..."
            local mismatches=0
            while IFS= read -r line; do
                expected_hash=$(echo "$line" | awk '{print $1}')
                backup_path=$(echo "$line" | awk '{print $2}')
                live_path="${backup_path#${LATEST_LINK}}"
                # Only check files within this webroot
                [[ "$live_path" != "$webroot"* ]] && continue
                if [[ -f "$live_path" ]]; then
                    actual_hash=$(sha256sum "$live_path" | awk '{print $1}')
                    if [[ "$expected_hash" != "$actual_hash" ]]; then
                        warn "  CHANGED: $live_path"
                        ((mismatches++))
                    fi
                else
                    warn "  DELETED: $live_path"
                    ((mismatches++))
                fi
            done < "${LATEST_LINK}/sha256sums.txt"
            [[ $mismatches -eq 0 ]] && info "  Integrity check: All files match backup." || \
                alert "  $mismatches file(s) changed or deleted since last backup."
        fi
    done

    echo ""
    if [[ $issues -eq 0 ]]; then
        info "✅ Web content scan complete — no critical issues detected."
    else
        error "❌ $issues issue(s) detected. Review alerts above immediately."
    fi
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== Web Content Restore ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found."
        exit 1
    fi

    mapfile -t active_roots < <(find_active_webroots | tr ' ' '\n')

    warn "This will overwrite web content with backup from: $(readlink "$LATEST_LINK")"
    warn "Active web roots: ${active_roots[*]}"
    read -rp "Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

    for webroot in "${active_roots[@]}"; do
        src="${LATEST_LINK}${webroot}"
        if [[ -d "$src" ]]; then
            # Archive current content
            tar -czf "${webroot}.blueteam_pre_restore_${TIMESTAMP}.tar.gz" "$webroot/" 2>/dev/null || true
            info "  Current content archived: ${webroot}.blueteam_pre_restore_${TIMESTAMP}.tar.gz"

            rsync -a --delete "$src/" "$webroot/"
            info "  Restored: $webroot"
        else
            warn "  No backup found for: $webroot"
        fi
    done

    # Fix ownership (restore may have changed it)
    for webroot in "${active_roots[@]}"; do
        if command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
            chown -R www-data:www-data "$webroot" 2>/dev/null || \
            chown -R apache:apache "$webroot" 2>/dev/null || true
        elif command -v nginx &>/dev/null; then
            chown -R nginx:nginx "$webroot" 2>/dev/null || \
            chown -R www-data:www-data "$webroot" 2>/dev/null || true
        fi
        info "  Ownership reset: $webroot"
    done

    info "✅ Web content restore complete."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
case "${1:-help}" in
    backup)  do_backup ;;
    restore) do_restore ;;
    scan)    do_scan ;;
    *)
        echo "Usage: sudo $0 {backup|restore|scan}"
        exit 1
        ;;
esac
