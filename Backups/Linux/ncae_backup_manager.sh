# Clauded By Yours Truly
# King Snowball

#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 — Regional  |  Team 22
# Universal Backup & Restore Manager — FULLY SELF-CONTAINED
# =============================================================================
# Drop this single script on ANY box and run it. No external scripts required.
# All backup/restore logic is inlined.
#
# Usage:  sudo bash ncae_backup_manager.sh
#
# Covers (all inline, zero dependencies):
#   Database box   — PostgreSQL + /etc + PAM
#   Web box        — Apache/Nginx/Lighttpd config + SSL + web content
#   DNS box        — BIND9 zones + config + /etc + PAM
#   Shell/SMB box  — Samba + SSHD + /etc + PAM
#   Any box        — System configs, PAM, critical binaries, users
#
# Backup destinations:
#   Local  — /opt/blueteam/backups/<service>/  and  /root/.cache/backups/
#   Remote — rsync/scp to backup server (192.168.t.15)
# =============================================================================

set -uo pipefail
# Note: -e omitted intentionally. Arithmetic like (( n+1 )) exits 1 when
# result is 0, causing false failures. All errors are handled explicitly.

# =============================================================================
# GLOBALS
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="/opt/blueteam/backups"
LOCAL_BACKUP_ROOT="/root/.cache/backups"
LOG_FILE="/var/log/blueteam_backup.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# PostgreSQL
PG_SUPERUSER="postgres"
PG_BACKUP_ROOT="${BACKUP_ROOT}/postgres"

# Backup server (set after team number is entered)
BACKUP_SERVER_USER="root"
BACKUP_SERVER_BASE_PATH="/backups"
BACKUP_SERVER=""
BACKUP_SERVER_PATH=""

# Box selection state
SELECTED_BOX=""
SELECTED_BOX_IP=""

# Global return slot — avoids stdout pollution when functions write logs
BACKUP_RESULT=""

# Derived IPs — set by select_team_number
TEAM_NUM=""
INTERNAL_SUBNET=""
IP_DB="" IP_WEB="" IP_DNS="" IP_SHELL="" IP_BACKUP=""

# =============================================================================
# COLORS & LOGGING
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log()    { echo -e "$(date '+%H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()   { log "INFO " "${GREEN}$*${NC}"; }
warn()   { log "WARN " "${YELLOW}$*${NC}"; }
error()  { log "ERROR" "${RED}$*${NC}"; }
alert()  { log "ALERT" "${RED}⚠️  $*${NC}"; }
header() {
    echo -e "\n${BOLD}${CYAN}$*${NC}"
    echo -e "${CYAN}$(printf '─%.0s' {1..60})${NC}"
}

# =============================================================================
# PREFLIGHT
# =============================================================================

[[ $EUID -ne 0 ]] && { echo -e "${RED}[!] Must run as root. Use: sudo bash $0${NC}"; exit 1; }
mkdir -p "$LOCAL_BACKUP_ROOT" "$BACKUP_ROOT"
chmod 700 "$LOCAL_BACKUP_ROOT" "$BACKUP_ROOT"
touch "$LOG_FILE" && chmod 600 "$LOG_FILE"

# =============================================================================
# NETWORK / TEAM SETUP
# =============================================================================

select_team_number() {
    echo ""
    read -rp "  Enter your team number (e.g. 22): " TEAM_NUM
    if ! [[ "$TEAM_NUM" =~ ^[0-9]+$ ]]; then
        warn "Invalid team number — defaulting to 22."
        TEAM_NUM=22
    fi
    INTERNAL_SUBNET="192.168.${TEAM_NUM}"
    IP_DB="${INTERNAL_SUBNET}.7"
    IP_WEB="${INTERNAL_SUBNET}.5"
    IP_DNS="${INTERNAL_SUBNET}.12"
    IP_SHELL="${INTERNAL_SUBNET}.14"
    IP_BACKUP="${INTERNAL_SUBNET}.15"
    info "Team ${TEAM_NUM} — subnet: ${INTERNAL_SUBNET}.0/24"
}

check_backup_server() {
    [[ -z "$BACKUP_SERVER" ]] && { warn "Backup server IP not set."; return 1; }
    if ssh -o ConnectTimeout=5 -o BatchMode=yes \
        "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" "echo ok" &>/dev/null; then
        info "Backup server ${BACKUP_SERVER}: reachable ✅"
        return 0
    else
        warn "Cannot reach backup server ${BACKUP_SERVER} via SSH."
        warn "  Check: ping ${BACKUP_SERVER}"
        return 1
    fi
}

push_to_remote() {
    local src="$1"
    info "Pushing $(basename "$src") → ${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/ ..."
    ssh "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" \
        "mkdir -p ${BACKUP_SERVER_PATH} && chmod 700 ${BACKUP_SERVER_PATH}" 2>/dev/null || true
    if command -v rsync &>/dev/null; then
        rsync -avz --progress "$src" \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            2>>"$LOG_FILE" && info "  Push: OK ✅" || warn "  Push failed — local copy intact."
    else
        scp -r "$src" \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            2>>"$LOG_FILE" && info "  Push: OK ✅" || warn "  Push failed — local copy intact."
    fi
}

pull_from_remote() {
    local dest="$1"
    mkdir -p "$dest"
    info "Pulling from ${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/ ..."
    if command -v rsync &>/dev/null; then
        rsync -avz --progress \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            "$dest/" 2>>"$LOG_FILE" && info "Pull: OK ✅" && return 0
    else
        scp -r \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            "$dest/" 2>>"$LOG_FILE" && info "Pull: OK ✅" && return 0
    fi
    error "Failed to pull from backup server."
    return 1
}

# =============================================================================
# SHARED BACKUP FLOW ORCHESTRATOR
# Pass backup function names as arguments.
# Prompts for local/remote/both then calls each function in order.
# =============================================================================

_do_backup_flow() {
    local fns=("$@")

    header "DESTINATION"
    echo "  1) Local only       (${LOCAL_BACKUP_ROOT}  /  ${BACKUP_ROOT})"
    echo "  2) Remote only      (push to backup server ${BACKUP_SERVER:-not set})"
    echo "  3) Local + Remote   [recommended]"
    echo "  0) Back"
    read -rp $'\nChoice: ' dest_choice
    [[ "$dest_choice" == "0" ]] && return 0

    local collected_paths=()
    for fn in "${fns[@]}"; do
        header "Running: $fn"
        BACKUP_RESULT=""
        if $fn; then
            if [[ -n "$BACKUP_RESULT" ]]; then
                collected_paths+=("$BACKUP_RESULT")
                info "  Saved: $BACKUP_RESULT"
            else
                warn "  $fn completed but no path returned — check $LOG_FILE"
            fi
        else
            error "$fn failed — check $LOG_FILE"
        fi
    done

    if [[ ${#collected_paths[@]} -eq 0 ]]; then
        error "No backups created successfully."
        return 1
    fi

    case "$dest_choice" in
        2|3)
            if check_backup_server; then
                for p in "${collected_paths[@]}"; do push_to_remote "$p"; done
            else
                warn "Remote push skipped. Local backups are safe."
            fi
            ;;
    esac

    if [[ "$dest_choice" == "2" ]]; then
        info "Removing local staging copies ..."
        for p in "${collected_paths[@]}"; do
            [[ -d "$p" ]] && rm -rf "$p" && info "  Removed: $p"
        done
    fi

    header "Backup Summary"
    for p in "${collected_paths[@]}"; do
        if [[ -d "$p" ]]; then
            info "$p:"
            ls -lh "$p"/ 2>/dev/null | sed 's/^/  /'
        fi
    done
    info "Log: $LOG_FILE"
}

_do_restore_flow() {
    local restore_fn="$1"
    local default_root="${2:-$LOCAL_BACKUP_ROOT}"

    header "SOURCE"
    echo "  1) Local  (backups already on this box)"
    echo "  2) Remote (pull from backup server ${BACKUP_SERVER:-not set} first)"
    echo "  0) Back"
    read -rp $'\nChoice: ' src_choice
    [[ "$src_choice" == "0" ]] && return 0

    local restore_root="$default_root"
    if [[ "$src_choice" == "2" ]]; then
        if check_backup_server; then
            local pull_dest="/root/restored_${TIMESTAMP}"
            pull_from_remote "$pull_dest" || { error "Pull failed."; return 1; }
            restore_root="$pull_dest"
        else
            error "Cannot reach backup server."
            return 1
        fi
    fi

    $restore_fn "$restore_root"
}

# =============================================================================
# ─────────────────────────────────────────────────────────────────────────────
# INLINE SERVICE BACKUP/RESTORE FUNCTIONS
# Each service is fully self-contained below.
# ─────────────────────────────────────────────────────────────────────────────
# =============================================================================

# =============================================================================
# POSTGRESQL
# Uses Unix socket peer auth (sudo -u postgres) — same as the competition setup.
# No -h/-p flags to avoid breaking pg_hba.conf TCP auth requirements.
# =============================================================================

run_pg()  { sudo -u "$PG_SUPERUSER" "$@"; }
pg_exec() { run_pg psql -U "$PG_SUPERUSER" -t -A -c "$1" 2>/dev/null; }

check_postgres() {
    if run_pg psql -U "$PG_SUPERUSER" -c "SELECT 1;" &>/dev/null; then
        info "PostgreSQL: connected ✅"
        return 0
    else
        error "Cannot connect to PostgreSQL."
        error "  Check: sudo systemctl status postgresql"
        error "  Test:  sudo -u postgres psql -c 'SELECT 1;'"
        return 1
    fi
}

do_backup_postgres() {
    BACKUP_RESULT=""
    check_postgres || return 1

    local dest="${PG_BACKUP_ROOT}/${TIMESTAMP}"
    mkdir -p "${dest}/per_database"
    chmod 700 "$dest" "${dest}/per_database"

    # 1. Globals (roles, tablespaces)
    info "Dumping globals (roles/tablespaces) ..."
    if run_pg pg_dumpall -U "$PG_SUPERUSER" \
        --globals-only 2>>"$LOG_FILE" \
        > "${dest}/globals_${TIMESTAMP}.sql"; then
        gzip -f "${dest}/globals_${TIMESTAMP}.sql"
        info "  Globals: OK"
    else
        error "Globals dump failed — check $LOG_FILE"
        rm -rf "$dest"; return 1
    fi

    # 2. Full cluster (all DBs in one file — fastest full recovery)
    info "Dumping full cluster ..."
    if run_pg pg_dumpall -U "$PG_SUPERUSER" \
        --clean --if-exists 2>>"$LOG_FILE" \
        > "${dest}/full_cluster_${TIMESTAMP}.sql"; then
        gzip -f "${dest}/full_cluster_${TIMESTAMP}.sql"
        info "  Full cluster: OK"
    else
        error "Full cluster dump failed — check $LOG_FILE"
        rm -rf "$dest"; return 1
    fi

    # 3. Per-database custom-format dumps (allow surgical restore)
    info "Dumping individual databases ..."
    local db_list
    db_list=$(pg_exec "SELECT datname FROM pg_database
                       WHERE datistemplate = false AND datname != 'template0'
                       ORDER BY datname;")
    local count=0
    if [[ -n "$db_list" ]]; then
        while IFS= read -r db; do
            [[ -z "$db" ]] && continue
            local dumpfile="${dest}/per_database/${db}_${TIMESTAMP}.dump"
            if run_pg pg_dump -U "$PG_SUPERUSER" \
                --format=custom --compress=9 \
                --dbname="$db" 2>>"$LOG_FILE" > "$dumpfile"; then
                sha256sum "$dumpfile" >> "${dest}/sha256sums.txt"
                info "  DB '$db': OK"
                count=$(( count + 1 ))
            else
                warn "  DB '$db': failed — check $LOG_FILE"
            fi
        done <<< "$db_list"
    fi
    info "  $count database(s) dumped"

    # 4. Database sizes (useful for triage)
    pg_exec "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size
             FROM pg_database ORDER BY pg_database_size(datname) DESC;" \
        > "${dest}/database_sizes.txt" 2>/dev/null || true

    # 5. PG config files
    if [[ -d "/etc/postgresql" ]]; then
        tar czf "${dest}/pg_conf_${TIMESTAMP}.tar.gz" \
            -C / etc/postgresql 2>>"$LOG_FILE" && info "  pg_conf: OK" || true
    fi

    # Finalise
    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; >> "${dest}/sha256sums.txt" 2>/dev/null || true
    find "$dest" -type f -exec chmod 600 {} \;
    chmod 700 "$dest" "${dest}/per_database"
    ln -sfn "$dest" "${PG_BACKUP_ROOT}/latest"

    info "✅ PostgreSQL backup complete."
    info "   Location: $dest"
    ls -lh "$dest"/ 2>/dev/null | sed 's/^/   /'
    BACKUP_RESULT="$dest"
}

do_restore_postgres() {
    local src="$1"
    check_postgres || return 1

    # If src is the root, find the latest subdir
    if [[ ! -f "${src}/full_cluster_"*.sql.gz ]] 2>/dev/null; then
        local candidate
        candidate=$(find "$src" -maxdepth 2 -name "full_cluster_*.sql.gz" \
            | sort -r | head -1)
        [[ -n "$candidate" ]] && src="$(dirname "$candidate")"
    fi

    header "PostgreSQL Restore Options"
    echo "  1) Full cluster restore (all databases)"
    echo "  2) Single database restore"
    echo "  3) Globals only (roles/tablespaces)"
    echo "  0) Back"
    read -rp $'\nChoice: ' choice

    case "$choice" in
        1)
            local dump
            dump=$(find "$src" -maxdepth 2 -name "full_cluster_*.sql.gz" | sort -r | head -1)
            [[ -z "$dump" ]] && { error "No full_cluster dump in: $src"; return 1; }
            warn "⚠️  FULL RESTORE — drops and recreates ALL databases."
            read -rp "  Type 'FULL RESTORE' to confirm: " confirm
            [[ "$confirm" != "FULL RESTORE" ]] && { info "Cancelled."; return 0; }
            local globals
            globals=$(find "$src" -maxdepth 2 -name "globals_*.sql.gz" | sort -r | head -1)
            if [[ -n "$globals" ]]; then
                info "Restoring globals ..."
                zcat "$globals" | run_pg psql -U "$PG_SUPERUSER" -f - 2>>"$LOG_FILE" || true
            fi
            info "Restoring full cluster ..."
            zcat "$dump" | run_pg psql -U "$PG_SUPERUSER" -f - 2>>"$LOG_FILE"
            info "✅ Full cluster restore complete."
            run_pg psql -U "$PG_SUPERUSER" -c "\l" 2>/dev/null || true
            ;;
        2)
            local db_dir
            db_dir=$(find "$src" -maxdepth 2 -type d -name "per_database" | head -1)
            [[ -z "$db_dir" || ! -d "$db_dir" ]] && { error "No per_database/ in: $src"; return 1; }
            local i=1
            declare -a dump_files=()
            while IFS= read -r -d '' f; do
                dump_files+=("$f")
                echo "  $i) $(basename "$f")"
                i=$(( i + 1 ))
            done < <(find "$db_dir" -type f \( -name "*.dump" -o -name "*.sql.gz" \) \
                       -print0 2>/dev/null | sort -z)
            [[ ${#dump_files[@]} -eq 0 ]] && { error "No dumps in: $db_dir"; return 1; }
            read -rp $'\nSelect number: ' sel
            if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#dump_files[@]} )); then
                error "Invalid selection."; return 1
            fi
            local chosen="${dump_files[$((sel-1))]}"
            local db_name
            db_name=$(basename "$chosen" | sed 's/_[0-9]\{8\}_[0-9]\{6\}.*$//')
            warn "Will DROP and recreate: $db_name"
            read -rp "  Type 'CONFIRM' to proceed: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }
            run_pg psql -U "$PG_SUPERUSER" \
                -c "DROP DATABASE IF EXISTS \"${db_name}\";" 2>>"$LOG_FILE" || true
            run_pg psql -U "$PG_SUPERUSER" \
                -c "CREATE DATABASE \"${db_name}\";" 2>>"$LOG_FILE"
            if [[ "$chosen" == *.dump ]]; then
                run_pg pg_restore -U "$PG_SUPERUSER" \
                    --dbname="$db_name" --verbose --clean --if-exists \
                    "$chosen" 2>>"$LOG_FILE"
            else
                zcat "$chosen" | run_pg psql -U "$PG_SUPERUSER" -d "$db_name" -f - 2>>"$LOG_FILE"
            fi
            info "✅ Database '$db_name' restored."
            ;;
        3)
            local globals
            globals=$(find "$src" -maxdepth 2 -name "globals_*.sql.gz" | sort -r | head -1)
            [[ -z "$globals" ]] && { error "No globals dump in: $src"; return 1; }
            read -rp "  Type 'CONFIRM' to restore globals: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }
            zcat "$globals" | run_pg psql -U "$PG_SUPERUSER" -f - 2>>"$LOG_FILE" || true
            info "✅ Globals restored."
            ;;
        0) return 0 ;;
        *) error "Invalid choice."; return 1 ;;
    esac
}


# =============================================================================
# WEB SERVER (Apache / Nginx / Lighttpd — auto-detected)
# =============================================================================

_detect_webserver() {
    if command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then echo "apache"
    elif command -v nginx &>/dev/null; then echo "nginx"
    elif command -v lighttpd &>/dev/null; then echo "lighttpd"
    else echo "none"
    fi
}

_webserver_vars() {
    local ws="$1"
    case "$ws" in
        apache)
            if [[ -d /etc/apache2 ]]; then
                WS_CONFIG_DIRS=(/etc/apache2)
                WS_SERVICE="apache2"
                WS_TEST_CMD="apache2ctl -t"
                WS_RELOAD_CMD="systemctl reload apache2"
            else
                WS_CONFIG_DIRS=(/etc/httpd)
                WS_SERVICE="httpd"
                WS_TEST_CMD="httpd -t"
                WS_RELOAD_CMD="systemctl reload httpd"
            fi ;;
        nginx)
            WS_CONFIG_DIRS=(/etc/nginx)
            WS_SERVICE="nginx"
            WS_TEST_CMD="nginx -t"
            WS_RELOAD_CMD="systemctl reload nginx" ;;
        lighttpd)
            WS_CONFIG_DIRS=(/etc/lighttpd)
            WS_SERVICE="lighttpd"
            WS_TEST_CMD="lighttpd -t -f /etc/lighttpd/lighttpd.conf"
            WS_RELOAD_CMD="systemctl reload lighttpd" ;;
    esac
}

do_backup_webserver() {
    BACKUP_RESULT=""
    local ws
    ws=$(_detect_webserver)
    if [[ "$ws" == "none" ]]; then
        warn "No supported web server detected (apache2/nginx/lighttpd). Skipping."
        return 0
    fi
    _webserver_vars "$ws"

    local dest="${BACKUP_ROOT}/webserver/${TIMESTAMP}"
    mkdir -p "$dest"
    chmod 700 "$dest"
    echo "$ws" > "${dest}/webserver_type.txt"

    info "Backing up $ws config ..."
    for dir in "${WS_CONFIG_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            local d="${dest}${dir}"
            mkdir -p "$d"
            cp -rp "$dir/." "$d/"
            info "  Config: $dir ✅"
        fi
    done

    # SSL/TLS certs
    for ssl_dir in /etc/ssl /etc/letsencrypt /etc/pki/tls; do
        if [[ -d "$ssl_dir" ]]; then
            local d="${dest}${ssl_dir}"
            mkdir -p "$d"
            cp -rp "$ssl_dir/." "$d/"
            chmod 700 "$d"
            info "  SSL: $ssl_dir ✅"
        fi
    done

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt"
    chmod 400 "${dest}/sha256sums.txt"
    ln -sfn "$dest" "${BACKUP_ROOT}/webserver/latest"

    info "✅ Web server backup complete: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_webserver() {
    local src="$1"
    local ws_file
    ws_file=$(find "$src" -maxdepth 3 -name "webserver_type.txt" | head -1)
    local ws
    if [[ -n "$ws_file" ]]; then ws=$(cat "$ws_file")
    else ws=$(_detect_webserver)
    fi
    [[ "$ws" == "none" ]] && { error "Cannot determine web server type."; return 1; }
    _webserver_vars "$ws"

    # Find backup root if src is too deep
    if [[ -n "$ws_file" ]]; then src="$(dirname "$ws_file")"; fi

    warn "Restoring $ws config from: $src"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    for dir in "${WS_CONFIG_DIRS[@]}"; do
        local bsrc="${src}${dir}"
        if [[ -d "$bsrc" ]]; then
            cp -rp "$dir" "${dir}.pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -rp "$bsrc/." "$dir/"
            info "  Restored: $dir"
        fi
    done

    for ssl_dir in /etc/ssl /etc/letsencrypt /etc/pki/tls; do
        local bsrc="${src}${ssl_dir}"
        [[ -d "$bsrc" ]] && cp -rp "$bsrc/." "$ssl_dir/" && info "  Restored SSL: $ssl_dir"
    done

    info "Testing config syntax ..."
    if eval "$WS_TEST_CMD" 2>&1 | tee -a "$LOG_FILE"; then
        info "  Config test: OK"
        eval "$WS_RELOAD_CMD" 2>>"$LOG_FILE" && info "  $WS_SERVICE reloaded ✅" || \
            systemctl restart "$WS_SERVICE" 2>>"$LOG_FILE" && info "  $WS_SERVICE restarted ✅" || \
            error "  Could not restart $WS_SERVICE — check manually."
    else
        error "Config test FAILED. Service NOT reloaded. Fix errors manually."
    fi
}

# =============================================================================

_find_webroots() {
    local roots=(/var/www/html /var/www /srv/www /usr/share/nginx/html)
    local found=()
    for r in "${roots[@]}"; do [[ -d "$r" ]] && found+=("$r"); done
    [[ ${#found[@]} -gt 0 ]] && printf '%s\n' "${found[@]}" || true
}

do_backup_webcontent() {
    BACKUP_RESULT=""
    local dest="${BACKUP_ROOT}/webcontent/${TIMESTAMP}"
    mkdir -p "$dest"
    chmod 700 "$dest"

    mapfile -t active_roots < <(_find_webroots)
    if [[ ${#active_roots[@]} -eq 0 ]]; then
        warn "No web roots found. Skipping."
        return 0
    fi

    for webroot in "${active_roots[@]}"; do
        info "Backing up: $webroot"
        local d="${dest}${webroot}"
        mkdir -p "$d"
        if command -v rsync &>/dev/null; then
            rsync -a --quiet \
                --exclude="*.tmp" --exclude="__pycache__" \
                --exclude="*.pyc" --exclude=".git" \
                "$webroot/" "$d/" 2>>"$LOG_FILE"
        else
            cp -rp "$webroot/." "$d/" 2>>"$LOG_FILE"
        fi
        info "  $(du -sh "$d" 2>/dev/null | cut -f1) — $webroot ✅"
    done

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt"
    chmod 400 "${dest}/sha256sums.txt"
    ln -sfn "$dest" "${BACKUP_ROOT}/webcontent/latest"

    info "✅ Web content backup complete: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_webcontent() {
    local src="$1"
    # Navigate to backup with actual web content
    if [[ ! -d "${src}/var" && ! -d "${src}/srv" && ! -d "${src}/usr" ]]; then
        local candidate
        candidate=$(find "$src" -maxdepth 3 -type d -name "html" | head -1)
        [[ -n "$candidate" ]] && src="$(dirname "$(dirname "$candidate")")"
    fi

    mapfile -t active_roots < <(_find_webroots)
    warn "This will overwrite web content from: $src"
    warn "Active web roots: ${active_roots[*]:-none found}"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    for webroot in "${active_roots[@]}"; do
        local bsrc="${src}${webroot}"
        if [[ -d "$bsrc" ]]; then
            tar -czf "${webroot}.pre_restore_${TIMESTAMP}.tar.gz" "$webroot/" 2>/dev/null || true
            if command -v rsync &>/dev/null; then
                rsync -a --delete "$bsrc/" "$webroot/"
            else
                cp -rp "$bsrc/." "$webroot/"
            fi
            # Fix ownership
            for user in www-data apache nginx; do
                id "$user" &>/dev/null && chown -R "${user}:${user}" "$webroot" && break
            done
            info "  Restored: $webroot ✅"
        else
            warn "  No backup for: $webroot"
        fi
    done
    info "✅ Web content restore complete."
}

# =============================================================================
# DNS / BIND9
# =============================================================================

do_backup_dns() {
    BACKUP_RESULT=""
    local dest="${BACKUP_ROOT}/dns/${TIMESTAMP}"
    mkdir -p "$dest"
    chmod 700 "$dest"

    # BIND9 config locations (Ubuntu/Debian and RHEL/Rocky)
    local bind_dirs=(/etc/bind /etc/named /etc/named.conf
                     /var/named /var/lib/bind /var/cache/bind)
    local backed_up=0

    for path in "${bind_dirs[@]}"; do
        if [[ -d "$path" ]]; then
            local d="${dest}${path}"
            mkdir -p "$d"
            cp -rp "$path/." "$d/" 2>>"$LOG_FILE"
            info "  BIND9 dir: $path ✅"
            backed_up=$(( backed_up + 1 ))
        elif [[ -f "$path" ]]; then
            local d="${dest}$(dirname "$path")"
            mkdir -p "$d"
            cp -p "$path" "$d/" 2>>"$LOG_FILE"
            info "  BIND9 file: $path ✅"
            backed_up=$(( backed_up + 1 ))
        fi
    done

    if [[ $backed_up -eq 0 ]]; then
        warn "No BIND9 config found. DNS may not be installed."
    fi

    # Capture zone list if named is running
    if systemctl is-active named &>/dev/null || systemctl is-active bind9 &>/dev/null; then
        named-checkconf -p > "${dest}/named_effective_config.txt" 2>>"$LOG_FILE" || true
        info "  Captured effective named config."
    fi

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt"
    ln -sfn "$dest" "${BACKUP_ROOT}/dns/latest"

    info "✅ DNS backup complete: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_dns() {
    local src="$1"
    local candidate
    candidate=$(find "$src" -maxdepth 3 -type d \( -name "bind" -o -name "named" \) | head -1)
    [[ -n "$candidate" ]] && src="$(dirname "$(dirname "$candidate")")"

    warn "Restoring BIND9 config from: $src"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    local bind_dirs=(/etc/bind /etc/named /var/named /var/lib/bind /var/cache/bind)
    for path in "${bind_dirs[@]}"; do
        local bsrc="${src}${path}"
        if [[ -d "$bsrc" ]]; then
            [[ -d "$path" ]] && cp -rp "$path" "${path}.pre_restore_${TIMESTAMP}" 2>/dev/null || true
            mkdir -p "$path"
            cp -rp "$bsrc/." "$path/"
            chown -R named:named "$path" 2>/dev/null || \
                chown -R bind:bind "$path" 2>/dev/null || true
            info "  Restored: $path"
        fi
    done
    local bsrc="${src}/etc/named.conf"
    if [[ -f "$bsrc" ]]; then
        cp -p "$bsrc" /etc/named.conf
        info "  Restored: /etc/named.conf"
    fi

    info "Checking config syntax ..."
    if named-checkconf &>/dev/null; then
        info "  named-checkconf: OK"
        systemctl restart named 2>>"$LOG_FILE" || \
            systemctl restart bind9 2>>"$LOG_FILE" || \
            { error "Could not restart DNS service."; return 1; }
        info "✅ DNS service restarted."
    else
        error "named-checkconf failed — NOT restarting. Fix config manually."
        named-checkconf 2>&1 | tee -a "$LOG_FILE"
    fi
}

# =============================================================================
# SAMBA / SMB
# =============================================================================

do_backup_smb() {
    BACKUP_RESULT=""
    if ! command -v smbd &>/dev/null && [[ ! -f /etc/samba/smb.conf ]]; then
        warn "Samba not detected. Skipping SMB backup."
        return 0
    fi

    local dest="${BACKUP_ROOT}/smb/${TIMESTAMP}"
    mkdir -p "$dest"
    chmod 700 "$dest"

    # Config
    for path in /etc/samba /etc/samba/smb.conf; do
        if [[ -d "$path" || -f "$path" ]]; then
            local d="${dest}$(dirname "$path")"
            mkdir -p "$d"
            [[ -d "$path" ]] && cp -rp "$path/." "${dest}${path}/" 2>>"$LOG_FILE" || \
                cp -p "$path" "$d/" 2>>"$LOG_FILE"
            info "  SMB config: $path ✅"
        fi
    done

    # TDB/database files (user accounts, secrets)
    for path in /var/lib/samba /var/cache/samba; do
        if [[ -d "$path" ]]; then
            local d="${dest}${path}"
            mkdir -p "$d"
            find "$path" \( -name "*.tdb" -o -name "*.ldb" -o -name "passdb.tdb" \
                -o -name "secrets.tdb" \) -exec cp -p {} "$d/" \; 2>/dev/null || true
            info "  SMB databases from $path ✅"
        fi
    done

    # Samba user list
    if command -v pdbedit &>/dev/null; then
        pdbedit -L 2>/dev/null > "${dest}/samba_users.txt" || true
        info "  Samba user list saved."
    fi

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt"
    chmod -R 600 "${dest}"/*.tdb 2>/dev/null || true
    ln -sfn "$dest" "${BACKUP_ROOT}/smb/latest"

    info "✅ SMB backup complete: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_smb() {
    local src="$1"
    local candidate
    candidate=$(find "$src" -maxdepth 3 -name "smb.conf" | head -1)
    [[ -n "$candidate" ]] && src="$(dirname "$(dirname "$candidate")")"

    warn "Restoring Samba config from: $src"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    for path in /etc/samba /var/lib/samba /var/cache/samba; do
        local bsrc="${src}${path}"
        if [[ -d "$bsrc" ]]; then
            cp -rp "$bsrc/." "$path/" 2>>"$LOG_FILE"
            info "  Restored: $path"
        fi
    done

    # Validate config
    if command -v testparm &>/dev/null; then
        testparm -s &>/dev/null && info "  testparm: OK" || \
            warn "  testparm reported issues — check smb.conf"
    fi

    systemctl restart smbd nmbd 2>>"$LOG_FILE" && info "✅ Samba restarted." || \
        systemctl restart smb 2>>"$LOG_FILE" && info "✅ Samba restarted." || \
        error "Could not restart Samba — check manually."
}

# =============================================================================
# SSHD
# =============================================================================

do_backup_sshd() {
    BACKUP_RESULT=""
    local dest="${BACKUP_ROOT}/sshd/${TIMESTAMP}"
    mkdir -p "$dest"
    chmod 700 "$dest"

    # Config files
    for f in /etc/ssh/sshd_config /etc/ssh/ssh_config; do
        if [[ -f "$f" ]]; then
            local d="${dest}$(dirname "$f")"
            mkdir -p "$d"
            cp -p "$f" "$d/"
            info "  SSH config: $f ✅"
        fi
    done

    # Config drop-in dirs
    for dir in /etc/ssh/sshd_config.d /etc/ssh/ssh_config.d; do
        if [[ -d "$dir" ]]; then
            local d="${dest}${dir}"
            mkdir -p "$d"
            cp -rp "$dir/." "$d/"
            info "  SSH config dir: $dir ✅"
        fi
    done

    # Host keys (private + public)
    mkdir -p "${dest}/etc/ssh"
    for key in /etc/ssh/ssh_host_*; do
        [[ -f "$key" ]] || continue
        cp -p "$key" "${dest}/etc/ssh/"
        if [[ "$key" != *.pub ]]; then
            chmod 600 "${dest}/etc/ssh/$(basename "$key")"
        fi
        info "  Host key: $key ✅"
    done

    # authorized_keys for all users
    while IFS=: read -r username _ uid _ _ homedir _; do
        if (( uid >= 1000 )) || [[ "$username" == "root" ]]; then
            local ak="${homedir}/.ssh/authorized_keys"
            if [[ -f "$ak" ]]; then
                local d="${dest}${homedir}/.ssh"
                mkdir -p "$d"
                cp -p "$ak" "$d/"
                info "  authorized_keys: $username ✅"
            fi
        fi
    done < /etc/passwd

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt"
    chmod 400 "${dest}/sha256sums.txt"
    ln -sfn "$dest" "${BACKUP_ROOT}/sshd/latest"

    info "✅ SSHD backup complete: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_sshd() {
    local src="$1"
    local candidate
    candidate=$(find "$src" -maxdepth 4 -name "sshd_config" | head -1)
    [[ -n "$candidate" ]] && src="$(dirname "$(dirname "$candidate")")"

    warn "Restoring SSHD config from: $src"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    for f in /etc/ssh/sshd_config /etc/ssh/ssh_config; do
        local bsrc="${src}${f}"
        if [[ -f "$bsrc" ]]; then
            cp -p "$f" "${f}.pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -p "$bsrc" "$f"
            chmod 600 "$f"; chown root:root "$f"
            info "  Restored: $f"
        fi
    done

    for dir in /etc/ssh/sshd_config.d /etc/ssh/ssh_config.d; do
        local bsrc="${src}${dir}"
        [[ -d "$bsrc" ]] && cp -rp "$bsrc/." "$dir/" && info "  Restored: $dir"
    done

    info "Validating sshd_config ..."
    if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        info "  Config syntax: OK"
        systemctl restart sshd 2>>"$LOG_FILE" || systemctl restart ssh 2>>"$LOG_FILE"
        info "✅ SSHD restarted."
    else
        error "sshd_config has errors — NOT restarting. Fix manually before closing this session."
    fi
}

# =============================================================================
# SYSTEM CONFIGS (/etc, PAM, users)
# =============================================================================

PAM_CONFIG_DIRS=(/etc/pam.d /etc/security)
PAM_LIB_PATHS=(
    /lib/x86_64-linux-gnu/security
    /lib64/security
    /usr/lib/x86_64-linux-gnu/security
    /usr/lib64/security
    /lib/aarch64-linux-gnu/security
)

do_backup_system() {
    BACKUP_RESULT=""
    local dest="${LOCAL_BACKUP_ROOT}/system_${TIMESTAMP}"
    mkdir -p "$dest"

    # /etc
    info "Backing up /etc ..."
    tar czf "${dest}/etc_${TIMESTAMP}.tar.gz" -C / etc 2>>"$LOG_FILE" \
        && info "  /etc: OK ✅" \
        || warn "  /etc: some files may be permission-denied"

    # PAM configs
    info "Backing up PAM config ..."
    for dir in "${PAM_CONFIG_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            local d="${dest}${dir}"
            mkdir -p "$d"
            cp -rp "$dir/." "$d/" 2>/dev/null
            info "  PAM config: $dir ✅"
        fi
    done

    # PAM libraries
    info "Backing up PAM libraries ..."
    for lib_dir in "${PAM_LIB_PATHS[@]}"; do
        if [[ -d "$lib_dir" ]]; then
            local d="${dest}${lib_dir}"
            mkdir -p "$d"
            cp -rp "$lib_dir/." "$d/" 2>/dev/null
            info "  PAM libs: $lib_dir ✅"
        fi
    done

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt" 2>/dev/null || true

    info "✅ System backup: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_system() {
    local src="$1"
    local etc_archive
    etc_archive=$(find "$src" -maxdepth 3 -name "etc_*.tar.gz" | sort -r | head -1)

    if [[ -z "$etc_archive" ]]; then
        error "No etc_*.tar.gz found in: $src"
        return 1
    fi

    warn "Will overwrite /etc from: $(basename "$etc_archive")"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    info "Restoring /etc ..."
    tar -xzf "$etc_archive" -C / 2>>"$LOG_FILE"
    info "  /etc restored ✅"

    # Restore PAM configs
    local bsrc="${src}/etc/pam.d"
    if [[ -d "$bsrc" ]]; then
        cp -rp "$bsrc/." /etc/pam.d/
        info "  PAM config restored ✅"
    fi

    for lib_dir in "${PAM_LIB_PATHS[@]}"; do
        local bsrc="${src}${lib_dir}"
        if [[ -d "$bsrc" ]]; then
            cp -rp "$bsrc/." "$lib_dir/"
            info "  PAM libs restored: $lib_dir ✅"
        fi
    done

    # Restart affected services
    for svc in postgresql nginx apache2 httpd sshd ssh named smbd; do
        if systemctl is-active "$svc" &>/dev/null 2>/dev/null || \
           systemctl is-enabled "$svc" &>/dev/null 2>/dev/null; then
            systemctl restart "$svc" 2>>"$LOG_FILE" \
                && info "  Restarted: $svc ✅" \
                || warn "  Failed to restart: $svc — check: journalctl -xe -u $svc"
        fi
    done
}


do_backup_users() {
    BACKUP_RESULT=""
    local dest="${LOCAL_BACKUP_ROOT}/users_${TIMESTAMP}"
    mkdir -p "$dest"

    # User/group/shadow databases
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow \
             /etc/sudoers /etc/sudoers.d; do
        if [[ -f "$f" ]]; then
            cp -p "$f" "$dest/"
            info "  Users file: $f ✅"
        elif [[ -d "$f" ]]; then
            cp -rp "$f" "$dest/"
            info "  Users dir: $f ✅"
        fi
    done

    # Cron jobs
    for cron_dir in /var/spool/cron /var/spool/cron/crontabs /etc/cron.d \
                    /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$cron_dir" ]]; then
            local d="${dest}${cron_dir}"
            mkdir -p "$d"
            cp -rp "$cron_dir/." "$d/" 2>/dev/null
            info "  Cron: $cron_dir ✅"
        fi
    done
    crontab -l 2>/dev/null > "${dest}/root_crontab.txt" || true

    chmod 600 "${dest}/shadow" "${dest}/gshadow" 2>/dev/null || true
    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt" 2>/dev/null || true

    info "✅ Users/cron backup: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_users() {
    local src="$1"
    local latest
    latest=$(find "$src" -maxdepth 2 -name "passwd" | head -1)
    [[ -n "$latest" ]] && src="$(dirname "$latest")"

    warn "⚠️  Restoring user files can lock you out if done incorrectly."
    warn "    This restores: /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers"
    read -rp "  Type 'CONFIRM': " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    for f in passwd shadow group gshadow sudoers; do
        if [[ -f "${src}/${f}" ]]; then
            cp -p "/etc/${f}" "/etc/${f}.pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -p "${src}/${f}" "/etc/${f}"
            info "  Restored: /etc/${f} ✅"
        fi
    done
    if [[ -d "${src}/sudoers.d" ]]; then
        cp -rp "${src}/sudoers.d/." /etc/sudoers.d/
        info "  Restored: /etc/sudoers.d ✅"
    fi

    info "✅ User accounts restored."
}

# =============================================================================
# CLEANUP
# =============================================================================

menu_cleanup() {
    while true; do
        header "CLEANUP — Delete Old Backups"
        echo "  1) Delete specific backup(s) by number"
        echo "  2) Delete backups older than N days"
        echo "  3) Delete ALL local backups [nuclear]"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice
        case "$choice" in
            1) _cleanup_select ;;
            2) _cleanup_older_than ;;
            3) _cleanup_all ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

_cleanup_select() {
    header "All Local Backup Directories"
    local i=1
    declare -a entries=()
    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        local size label
        size=$(du -sh "$d" 2>/dev/null | cut -f1)
        label=$(echo "$d" | sed "s|${BACKUP_ROOT}/||;s|${LOCAL_BACKUP_ROOT}/||")
        entries+=("$d")
        echo "  $i) ${label}  [${size}]"
        i=$(( i + 1 ))
    done < <(find "$BACKUP_ROOT" "$LOCAL_BACKUP_ROOT" \
        -mindepth 1 -maxdepth 2 -type d 2>/dev/null \
        | grep -v '/latest$' | sort)

    if [[ ${#entries[@]} -eq 0 ]]; then
        info "No backups found."; return
    fi

    echo ""
    read -rp "  Enter numbers to delete (space-separated), or 'all', or 0 to cancel: " selection
    [[ "$selection" == "0" ]] && return 0

    local targets=()
    if [[ "$selection" == "all" ]]; then
        targets=("${entries[@]}")
    else
        for sel in $selection; do
            if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#entries[@]} )); then
                targets+=("${entries[$((sel-1))]}")
            else
                warn "  Invalid: $sel"
            fi
        done
    fi

    [[ ${#targets[@]} -eq 0 ]] && { warn "Nothing selected."; return; }
    echo ""
    warn "Will permanently delete:"
    for t in "${targets[@]}"; do
        echo "  - $t  ($(du -sh "$t" 2>/dev/null | cut -f1))"
    done

    read -rp $'\n  Type \'DELETE\' to confirm: ' confirm
    [[ "$confirm" != "DELETE" ]] && { info "Cancelled."; return; }

    for t in "${targets[@]}"; do
        rm -rf "$t" && info "  Deleted: $t"
        local parent
        parent=$(dirname "$t")
        if [[ -L "${parent}/latest" && ! -e "${parent}/latest" ]]; then
            local newest
            newest=$(find "$parent" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
            if [[ -n "$newest" ]]; then
                ln -sfn "$newest" "${parent}/latest"
                info "  Updated 'latest' → $(basename "$newest")"
            else
                rm -f "${parent}/latest"
                info "  Removed stale 'latest' symlink"
            fi
        fi
    done
    info "✅ Cleanup complete."
}

_cleanup_older_than() {
    read -rp "  Delete backups older than how many days? " days
    if ! [[ "$days" =~ ^[0-9]+$ ]] || (( days < 1 )); then
        warn "Enter a positive number."; return
    fi
    local found=()
    while IFS= read -r d; do
        [[ -n "$d" ]] && found+=("$d")
    done < <(find "$BACKUP_ROOT" "$LOCAL_BACKUP_ROOT" \
        -mindepth 1 -maxdepth 2 -type d -mtime +"$days" 2>/dev/null \
        | grep -v '/latest$' | sort)

    if [[ ${#found[@]} -eq 0 ]]; then
        info "No backups older than $days day(s)."; return
    fi

    warn "Backups older than $days day(s):"
    for d in "${found[@]}"; do
        echo "  - $d  ($(du -sh "$d" 2>/dev/null | cut -f1))"
    done
    read -rp $'\n  Type \'DELETE\' to confirm: ' confirm
    [[ "$confirm" != "DELETE" ]] && { info "Cancelled."; return; }
    for d in "${found[@]}"; do rm -rf "$d" && info "  Deleted: $d"; done
    info "✅ Age-based cleanup complete."
}

_cleanup_all() {
    warn "⚠️  This will delete ALL local backups:"
    echo "  - ${BACKUP_ROOT}   - ${LOCAL_BACKUP_ROOT}"
    warn "  Make sure you have copies on the backup server first!"
    read -rp "  Type 'DELETE ALL' to confirm: " confirm
    [[ "$confirm" != "DELETE ALL" ]] && { info "Cancelled."; return; }
    rm -rf "${BACKUP_ROOT:?}"/* 2>/dev/null || true
    rm -rf "${LOCAL_BACKUP_ROOT:?}"/* 2>/dev/null || true
    info "✅ All local backups deleted."
}

# =============================================================================
# LIST BACKUPS
# =============================================================================

menu_list_backups() {
    header "LOCAL BACKUPS — ${BACKUP_ROOT}"
    if [[ -d "$BACKUP_ROOT" ]]; then
        find "$BACKUP_ROOT" -mindepth 1 -maxdepth 2 -type d \
            | grep -v '/latest$' | sort \
            | while IFS= read -r d; do
                local size
                size=$(du -sh "$d" 2>/dev/null | cut -f1)
                echo -e "  ${CYAN}$(basename "$(dirname "$d")")/$(basename "$d")${NC}  [${size}]"
            done || echo "  (none)"
    else
        echo "  (none)"
    fi

    echo ""
    header "LOCAL BACKUPS — ${LOCAL_BACKUP_ROOT}"
    if [[ -d "$LOCAL_BACKUP_ROOT" ]]; then
        find "$LOCAL_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | \
            while IFS= read -r d; do
                local size
                size=$(du -sh "$d" 2>/dev/null | cut -f1)
                echo -e "  ${CYAN}$(basename "$d")${NC}  [${size}]"
            done || echo "  (none)"
    else
        echo "  (none)"
    fi

    echo ""
    header "REMOTE — ${BACKUP_SERVER:-not set}:${BACKUP_SERVER_PATH:-not set}"
    if [[ -n "$BACKUP_SERVER" ]] && check_backup_server 2>/dev/null; then
        ssh "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" \
            "ls -lh ${BACKUP_SERVER_PATH}/ 2>/dev/null || echo '  (empty)'" \
            | sed 's/^/  /'
    else
        warn "  Backup server unreachable or not set."
    fi
}

# =============================================================================
# BOX MENUS
# =============================================================================

# ── DATABASE BOX ──────────────────────────────────────────────────────────────
menu_db_box() {
    while true; do
        header "Database Box — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Services: PostgreSQL (Ubuntu 24.04) — scored service${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice

        case "$choice" in
            1)
                header "BACKUP — What to back up?"
                echo "  1) PostgreSQL only"
                echo "  2) System configs only (/etc, PAM)"
                echo "  3) Everything [recommended]"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_backup_flow do_backup_postgres ;;
                    2) _do_backup_flow do_backup_system ;;
                    3) _do_backup_flow do_backup_postgres do_backup_system ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            2)
                header "RESTORE — What to restore?"
                echo "  1) PostgreSQL"
                echo "  2) System configs"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_restore_flow do_restore_postgres "$PG_BACKUP_ROOT" ;;
                    2) _do_restore_flow do_restore_system "$LOCAL_BACKUP_ROOT" ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            3) menu_list_backups ;;
            4) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# ── WEB BOX ───────────────────────────────────────────────────────────────────
menu_web_box() {
    while true; do
        header "Web Box — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Services: Apache/Nginx/Lighttpd + web content + SSL${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice

        case "$choice" in
            1)
                header "BACKUP — What to back up?"
                echo "  1) Web server config only"
                echo "  2) Web content only"
                echo "  3) System configs only"
                echo "  4) Everything [recommended]"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_backup_flow do_backup_webserver ;;
                    2) _do_backup_flow do_backup_webcontent ;;
                    3) _do_backup_flow do_backup_system ;;
                    4) _do_backup_flow do_backup_webserver do_backup_webcontent do_backup_system ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            2)
                header "RESTORE — What to restore?"
                echo "  1) Web server config"
                echo "  2) Web content"
                echo "  3) System configs"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_restore_flow do_restore_webserver "${BACKUP_ROOT}/webserver" ;;
                    2) _do_restore_flow do_restore_webcontent "${BACKUP_ROOT}/webcontent" ;;
                    3) _do_restore_flow do_restore_system "$LOCAL_BACKUP_ROOT" ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            3) menu_list_backups ;;
            4) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# ── DNS BOX ───────────────────────────────────────────────────────────────────
menu_dns_box() {
    while true; do
        header "DNS Box — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Services: BIND9 (named) — fwd/rev zones, internal + external${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice

        case "$choice" in
            1)
                header "BACKUP — What to back up?"
                echo "  1) DNS (BIND9) only"
                echo "  2) System configs only"
                echo "  3) Everything [recommended]"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_backup_flow do_backup_dns ;;
                    2) _do_backup_flow do_backup_system ;;
                    3) _do_backup_flow do_backup_dns do_backup_system ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            2)
                header "RESTORE — What to restore?"
                echo "  1) DNS (BIND9)"
                echo "  2) System configs"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_restore_flow do_restore_dns "${BACKUP_ROOT}/dns" ;;
                    2) _do_restore_flow do_restore_system "$LOCAL_BACKUP_ROOT" ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            3) menu_list_backups ;;
            4) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# ── SHELL / SMB BOX ───────────────────────────────────────────────────────────
menu_shell_box() {
    while true; do
        header "Shell / SMB Box — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Services: Samba (SMB), SSH — scored for SSH login + SMB read/write${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice

        case "$choice" in
            1)
                header "BACKUP — What to back up?"
                echo "  1) Samba (SMB) only"
                echo "  2) SSHD config only"
                echo "  3) System configs only"
                echo "  4) Everything [recommended]"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_backup_flow do_backup_smb ;;
                    2) _do_backup_flow do_backup_sshd ;;
                    3) _do_backup_flow do_backup_system ;;
                    4) _do_backup_flow do_backup_smb do_backup_sshd do_backup_system ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            2)
                header "RESTORE — What to restore?"
                echo "  1) Samba (SMB)"
                echo "  2) SSHD config"
                echo "  3) System configs"
                echo "  0) Back"
                read -rp $'\nChoice: ' what
                case "$what" in
                    1) _do_restore_flow do_restore_smb "${BACKUP_ROOT}/smb" ;;
                    2) _do_restore_flow do_restore_sshd "${BACKUP_ROOT}/sshd" ;;
                    3) _do_restore_flow do_restore_system "$LOCAL_BACKUP_ROOT" ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            3) menu_list_backups ;;
            4) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}


# =============================================================================
# BOX SELECTION — main entry
# =============================================================================

select_box() {
    while true; do
        echo ""
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║   NCAE Cyber Games 2026 — Universal Backup Manager       ║${NC}"
        printf "${BOLD}${CYAN}║   Backup server: %-40s║${NC}\n" "${BACKUP_SERVER:-not set}"
        echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Which box are you on?\n"
        echo -e "  ${GREEN}1)${NC} Database Box      (${IP_DB})   — PostgreSQL"
        echo -e "  ${GREEN}2)${NC} Web Box            (${IP_WEB})   — Apache/Nginx + content"
        echo -e "  ${GREEN}3)${NC} DNS Box            (${IP_DNS})  — BIND9"
        echo -e "  ${GREEN}4)${NC} Shell / SMB Box    (${IP_SHELL}) — Samba + SSH"
        echo -e "  ${RED}0)${NC} Exit"
        echo ""
        read -rp "Choice: " choice

        case "$choice" in
            1)
                SELECTED_BOX="Database Box"; SELECTED_BOX_IP="${IP_DB}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/db"
                menu_db_box ;;
            2)
                SELECTED_BOX="Web Box"; SELECTED_BOX_IP="${IP_WEB}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/web"
                menu_web_box ;;
            3)
                SELECTED_BOX="DNS Box"; SELECTED_BOX_IP="${IP_DNS}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/dns"
                menu_dns_box ;;
            4)
                SELECTED_BOX="Shell/SMB Box"; SELECTED_BOX_IP="${IP_SHELL}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/shell"
                menu_shell_box ;;

            0)
                info "Exiting."; exit 0 ;;
            *)
                warn "Invalid — choose 0–4." ;;
        esac
    done
}

# =============================================================================
# ENTRY POINT
# =============================================================================

select_team_number
select_box