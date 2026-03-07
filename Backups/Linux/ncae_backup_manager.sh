#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 — Regional  |  Team 22
# Universal Backup & Restore Manager
# =============================================================================
# Drop this script on any box in the competition network and run it.
# It will ask which service/box you are on, then give you the right
# backup, restore, and cleanup options for that service.
#
# Usage:
#   sudo bash ncae_backup_manager.sh
#
# Supports:
#   Database box    — PostgreSQL + system configs
#   Web box         — Apache/Nginx + web content + system configs
#   DNS box         — BIND9 zones + config + system configs
#   Shell/SMB box   — Samba + SSH + system configs
#   Router          — iptables / firewall rules
#   Any box         — System-only (PAM, SSH, /etc, binaries)
#
# Network topology (t = team number, replace with your team):
#   DB Box          192.168.t.7
#   Web Box         192.168.t.5
#   DNS Box         192.168.t.12
#   Shell/SMB Box   192.168.t.14
#   Router          192.168.t.1  /  172.18.t.1
#   Backup Server   192.168.t.15
#
# All individual backup scripts must live alongside this script in the
# Backups/Linux/ directory of the NCAE-Tooling repo.
# =============================================================================

set -uo pipefail
# Note: set -e is intentionally omitted — arithmetic expressions like
# (( n + 1 )) return exit code 1 when the result is 0, causing false failures.
# All errors are handled explicitly per-function.

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SERVER_USER="root"
BACKUP_SERVER_BASE_PATH="/backups"
BACKUP_ROOT="/opt/blueteam/backups"
LOCAL_BACKUP_ROOT="/root/.cache/backups"
LOG_FILE="/var/log/blueteam_backup.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# PostgreSQL connection (used by DB box functions)
PG_HOST="localhost"
PG_PORT="5432"
PG_SUPERUSER="postgres"
PG_BACKUP_ROOT="${BACKUP_ROOT}/postgres"

# These are set during box selection
SELECTED_BOX=""        # human label, e.g. "Database Box"
SELECTED_BOX_IP=""     # e.g. 192.168.22.7
BACKUP_SERVER=""       # e.g. 192.168.22.15
BACKUP_SERVER_PATH=""  # remote path for this box's backups

# Global result variables (avoids stdout pollution when functions log to stderr)
BACKUP_RESULT=""

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
header() {
    echo -e "\n${BOLD}${CYAN}$*${NC}"
    echo -e "${CYAN}$(printf '─%.0s' {1..60})${NC}"
}

# =============================================================================
# PREFLIGHT
# =============================================================================

[[ $EUID -ne 0 ]] && { echo -e "${RED}[!] Must run as root.${NC}"; exit 1; }
mkdir -p "$LOCAL_BACKUP_ROOT" "$BACKUP_ROOT"
chmod 700 "$LOCAL_BACKUP_ROOT" "$BACKUP_ROOT"
touch "$LOG_FILE" && chmod 600 "$LOG_FILE"

# =============================================================================
# NETWORK HELPERS
# =============================================================================

# Prompt the user to enter their team number and derive all IPs
select_team_number() {
    echo ""
    read -rp "  Enter your team number (e.g. 22): " TEAM_NUM
    if ! [[ "$TEAM_NUM" =~ ^[0-9]+$ ]]; then
        warn "Invalid team number. Defaulting to 22."
        TEAM_NUM=22
    fi

    INTERNAL_SUBNET="192.168.${TEAM_NUM}"
    IP_DB="${INTERNAL_SUBNET}.7"
    IP_WEB="${INTERNAL_SUBNET}.5"
    IP_DNS="${INTERNAL_SUBNET}.12"
    IP_SHELL="${INTERNAL_SUBNET}.14"
    IP_ROUTER="${INTERNAL_SUBNET}.1"
    IP_BACKUP="${INTERNAL_SUBNET}.15"

    info "Team $TEAM_NUM — internal subnet: ${INTERNAL_SUBNET}.0/24"
}

check_backup_server() {
    if ssh -o ConnectTimeout=5 -o BatchMode=yes \
        "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" "echo ok" &>/dev/null; then
        info "Backup server ${BACKUP_SERVER}: reachable"
        return 0
    else
        warn "Cannot reach backup server ${BACKUP_SERVER} via SSH (key auth or password needed)."
        warn "  ping ${BACKUP_SERVER} to check if it's online"
        return 1
    fi
}

ensure_remote_dir() {
    local path="$1"
    ssh "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" \
        "mkdir -p ${path} && chmod 700 ${path}" 2>/dev/null || true
}

push_to_remote() {
    local src="$1"
    local remote_path="${BACKUP_SERVER_PATH}"
    info "Pushing $(basename "$src") to ${BACKUP_SERVER}:${remote_path}/ ..."
    ensure_remote_dir "$remote_path"

    if command -v rsync &>/dev/null; then
        rsync -avz --progress "$src" \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${remote_path}/" \
            2>>"$LOG_FILE"
    else
        scp -r "$src" \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${remote_path}/" \
            2>>"$LOG_FILE"
    fi

    if [[ $? -eq 0 ]]; then
        info "✅ Push to backup server: OK"
    else
        warn "⚠️  Push failed. Your local backup is still intact at: $src"
    fi
}

pull_from_remote() {
    local dest="$1"
    mkdir -p "$dest"
    info "Pulling from ${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/ ..."

    if command -v rsync &>/dev/null; then
        rsync -avz --progress \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            "$dest/" 2>>"$LOG_FILE"
    else
        scp -r \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            "$dest/" 2>>"$LOG_FILE"
    fi

    if [[ $? -eq 0 ]]; then
        info "✅ Pull from backup server: OK"
        return 0
    else
        error "Failed to pull from backup server."
        return 1
    fi
}

# =============================================================================
# DELEGATED SCRIPT RUNNER
# Calls individual Backups/Linux/NN_backup_*.sh scripts that already exist
# in the tooling repo. Falls back with a clear message if not found.
# =============================================================================

run_backup_script() {
    local script_name="$1"   # e.g. "05_backup_webserver.sh"
    local action="$2"         # backup | restore | verify | audit
    local script_path="${SCRIPT_DIR}/${script_name}"

    if [[ ! -f "$script_path" ]]; then
        warn "Script not found: ${script_path}"
        warn "Make sure the Backups/Linux/ directory is present alongside this script."
        return 1
    fi

    info "Running: ${script_name} ${action}"
    bash "$script_path" "$action"
}

# =============================================================================
# POSTGRESQL BACKUP/RESTORE
# (inline — does not depend on 08_backup_postgres.sh so it works standalone)
# =============================================================================

run_pg()  { sudo -u "$PG_SUPERUSER" "$@"; }
pg_exec() { run_pg psql -U "$PG_SUPERUSER" -t -A -c "$1" 2>/dev/null; }

check_postgres() {
    # Use Unix socket (peer auth) — same method as the original backups.sh.
    # Passing -h localhost would force TCP and break peer auth on Ubuntu.
    if run_pg psql -U "$PG_SUPERUSER" -c "SELECT 1;" &>/dev/null; then
        info "PostgreSQL connection: OK"
        return 0
    else
        error "Cannot connect to PostgreSQL."
        error "  Check: sudo systemctl status postgresql"
        error "  Quick test: sudo -u postgres psql -c 'SELECT 1;'"
        return 1
    fi
}

do_backup_postgres() {
    BACKUP_RESULT=""
    check_postgres || return 1

    local dest="${PG_BACKUP_ROOT}/${TIMESTAMP}"
    mkdir -p "${dest}/per_database"
    chmod 700 "$dest"

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

    info "Dumping individual databases ..."
    local db_list
    db_list=$(pg_exec "SELECT datname FROM pg_database \
                       WHERE datistemplate = false AND datname != 'template0' \
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

    # Back up pg config files
    if [[ -d "/etc/postgresql" ]]; then
        tar czf "${dest}/pg_conf_${TIMESTAMP}.tar.gz" \
            -C / etc/postgresql 2>>"$LOG_FILE" && info "  pg_conf: OK" || true
    fi

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; >> "${dest}/sha256sums.txt" 2>/dev/null || true
    chmod -R 600 "$dest"
    ln -sfn "$dest" "${PG_BACKUP_ROOT}/latest"

    info "✅ PostgreSQL backup: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_postgres() {
    local src="$1"
    check_postgres || return 1

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
            [[ -z "$dump" ]] && { error "No full_cluster dump found in: $src"; return 1; }

            warn "⚠️  FULL RESTORE will drop and recreate ALL databases."
            read -rp "  Type 'FULL RESTORE' to confirm: " confirm
            [[ "$confirm" != "FULL RESTORE" ]] && { info "Cancelled."; return 0; }

            local globals
            globals=$(find "$src" -maxdepth 2 -name "globals_*.sql.gz" | sort -r | head -1)
            if [[ -n "$globals" ]]; then
                info "Restoring globals ..."
                zcat "$globals" | run_pg psql -U "$PG_SUPERUSER" \
                    -f - 2>>"$LOG_FILE" || true
            fi

            info "Restoring full cluster ..."
            zcat "$dump" | run_pg psql -U "$PG_SUPERUSER" \
                -f - 2>>"$LOG_FILE"
            info "✅ Full cluster restore complete."
            pg_exec "\l" 2>/dev/null || true
            ;;

        2)
            local db_dir
            db_dir=$(find "$src" -maxdepth 2 -type d -name "per_database" | head -1)
            [[ -z "$db_dir" || ! -d "$db_dir" ]] && { error "No per_database/ dir in: $src"; return 1; }

            local i=1; declare -a dump_files
            while IFS= read -r -d '' f; do
                dump_files+=("$f")
                echo "  $i) $(basename "$f")"
                i=$(( i + 1 ))
            done < <(find "$db_dir" -type f \( -name "*.dump" -o -name "*.sql.gz" \) \
                       -print0 2>/dev/null | sort -z)

            [[ ${#dump_files[@]} -eq 0 ]] && { error "No dump files in: $db_dir"; return 1; }

            read -rp $'\nSelect number: ' sel
            if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#dump_files[@]} )); then
                error "Invalid selection."; return 1
            fi

            local chosen="${dump_files[$((sel-1))]}"
            local db_name
            db_name=$(basename "$chosen" | sed 's/_[0-9]\{8\}_[0-9]\{6\}.*$//')

            warn "Will DROP and recreate database: $db_name"
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
                zcat "$chosen" | run_pg psql -U "$PG_SUPERUSER" \
                    -d "$db_name" -f - 2>>"$LOG_FILE"
            fi
            info "✅ Database '$db_name' restored."
            ;;

        3)
            local globals
            globals=$(find "$src" -maxdepth 2 -name "globals_*.sql.gz" | sort -r | head -1)
            [[ -z "$globals" ]] && { error "No globals dump found in: $src"; return 1; }
            read -rp "  Type 'CONFIRM' to restore globals: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }
            zcat "$globals" | run_pg psql -U "$PG_SUPERUSER" \
                -f - 2>>"$LOG_FILE" || true
            info "✅ Globals restored."
            ;;

        0) return 0 ;;
        *) error "Invalid choice."; return 1 ;;
    esac
}

# =============================================================================
# SYSTEM BACKUP (generic — used by every box)
# =============================================================================

do_backup_system() {
    BACKUP_RESULT=""
    local dest="${LOCAL_BACKUP_ROOT}/system_${TIMESTAMP}"
    mkdir -p "$dest"

    info "Backing up /etc ..."
    tar czf "${dest}/etc_${TIMESTAMP}.tar.gz" -C / etc 2>>"$LOG_FILE" \
        && info "  /etc: OK" || warn "  /etc: errors (some files may be permission-denied)"

    info "Backing up PAM libraries ..."
    mkdir -p "${dest}/pam_libs"
    find /lib /lib64 /usr/lib /usr/lib64 -name "pam*.so" 2>/dev/null \
        | while IFS= read -r f; do
            local rel
            rel=$(dirname "${f#/}")
            mkdir -p "${dest}/pam_libs/${rel}"
            cp -p "$f" "${dest}/pam_libs/${rel}/" 2>/dev/null
        done
    info "  PAM libs: OK"

    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${dest}/sha256sums.txt" 2>/dev/null || true

    info "✅ System backup: $dest"
    BACKUP_RESULT="$dest"
}

do_restore_system() {
    local src="$1"
    local etc_archive
    etc_archive=$(find "$src" -maxdepth 2 -name "etc_*.tar.gz" | sort -r | head -1)

    if [[ -z "$etc_archive" ]]; then
        error "No etc_*.tar.gz found in: $src"
        return 1
    fi

    warn "This will overwrite /etc from: $(basename "$etc_archive")"
    read -rp "  Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    info "Restoring /etc ..."
    tar -xzf "$etc_archive" -C / 2>>"$LOG_FILE"
    info "  /etc restored: OK"

    # Restart services that read from /etc
    for svc in postgresql nginx apache2 sshd ssh named smbd; do
        if systemctl is-active "$svc" &>/dev/null || systemctl is-enabled "$svc" &>/dev/null 2>/dev/null; then
            info "  Restarting $svc ..."
            systemctl restart "$svc" 2>>"$LOG_FILE" \
                && info "  $svc: restarted ✅" \
                || warn "  $svc: failed to restart — check: journalctl -xe -u $svc"
        fi
    done
}

# =============================================================================
# GENERIC BACKUP/RESTORE FLOW
# Shared by all box types — they just pass different backup function names
# =============================================================================

_do_backup_flow() {
    # $1 = array name of backup function names to call (nameref)
    # Handles local/remote/both destination logic
    local -n _fns=$1

    header "DESTINATION"
    echo "  1) Local only       (${LOCAL_BACKUP_ROOT} / ${BACKUP_ROOT})"
    echo "  2) Remote only      (push to backup server ${BACKUP_SERVER})"
    echo "  3) Local + Remote   [recommended]"
    echo "  0) Back"
    read -rp $'\nChoice: ' dest_choice
    [[ "$dest_choice" == "0" ]] && return 0

    local collected_paths=()

    for fn in "${_fns[@]}"; do
        header "Running: $fn"
        if $fn; then
            [[ -n "$BACKUP_RESULT" ]] && collected_paths+=("$BACKUP_RESULT")
        else
            error "$fn failed — check $LOG_FILE"
        fi
    done

    case "$dest_choice" in
        2|3)
            if check_backup_server; then
                for p in "${collected_paths[@]}"; do
                    push_to_remote "$p"
                done
            else
                warn "Remote push skipped — backup server unreachable."
                warn "Local backups are safe. Re-run and choose option 2 to push when available."
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
        [[ -d "$p" ]] && { info "$p:"; ls -lh "$p"/ 2>/dev/null | sed 's/^/  /'; }
    done
    info "Log: $LOG_FILE"
}

_do_restore_flow() {
    # $1 = function to call for restore (e.g. do_restore_postgres)
    local restore_fn="$1"

    header "SOURCE"
    echo "  1) Local  (use backups already on this box)"
    echo "  2) Remote (pull from backup server ${BACKUP_SERVER} first)"
    echo "  0) Back"
    read -rp $'\nChoice: ' src_choice
    [[ "$src_choice" == "0" ]] && return 0

    local restore_root="$LOCAL_BACKUP_ROOT"

    if [[ "$src_choice" == "2" ]]; then
        if check_backup_server; then
            local pull_dest="/root/restored_${TIMESTAMP}"
            pull_from_remote "$pull_dest" || { error "Pull failed. Aborting."; return 1; }
            restore_root="$pull_dest"
        else
            error "Cannot reach backup server."
            return 1
        fi
    fi

    $restore_fn "$restore_root"
}

# =============================================================================
# CLEANUP  (shared across all box types)
# =============================================================================

menu_cleanup() {
    while true; do
        header "CLEANUP — Delete Old Backups"
        echo "  1) Delete specific backup(s) by name"
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
    declare -a entries
    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        local size
        size=$(du -sh "$d" 2>/dev/null | cut -f1)
        entries+=("$d")
        local label
        label=$(echo "$d" | sed "s|${BACKUP_ROOT}/||;s|${LOCAL_BACKUP_ROOT}/||")
        echo "  $i) ${label}  [${size}]"
        i=$(( i + 1 ))
    done < <(
        find "$BACKUP_ROOT" "$LOCAL_BACKUP_ROOT" \
            -mindepth 1 -maxdepth 2 -type d 2>/dev/null \
            | grep -v '/latest$' | sort
    )

    if [[ ${#entries[@]} -eq 0 ]]; then
        info "No backups found."
        return
    fi

    echo ""
    echo "  Enter numbers to delete (space-separated), or 'all', or 0 to cancel:"
    read -rp "  Selection: " selection
    [[ "$selection" == "0" ]] && return 0

    local targets=()
    if [[ "$selection" == "all" ]]; then
        targets=("${entries[@]}")
    else
        for sel in $selection; do
            if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#entries[@]} )); then
                targets+=("${entries[$((sel-1))]}")
            else
                warn "  Invalid selection skipped: $sel"
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
        rm -rf "$t"
        info "  Deleted: $t"
        # Fix any stale 'latest' symlink in the parent dir
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
        warn "Enter a positive number."
        return
    fi

    local found=()
    while IFS= read -r d; do
        [[ -n "$d" ]] && found+=("$d")
    done < <(
        find "$BACKUP_ROOT" "$LOCAL_BACKUP_ROOT" \
            -mindepth 1 -maxdepth 2 -type d -mtime +"$days" 2>/dev/null \
            | grep -v '/latest$' | sort
    )

    if [[ ${#found[@]} -eq 0 ]]; then
        info "No backups older than $days day(s) found."
        return
    fi

    warn "Backups older than $days day(s):"
    for d in "${found[@]}"; do
        echo "  - $d  ($(du -sh "$d" 2>/dev/null | cut -f1))"
    done

    read -rp $'\n  Type \'DELETE\' to confirm: ' confirm
    [[ "$confirm" != "DELETE" ]] && { info "Cancelled."; return; }

    for d in "${found[@]}"; do
        rm -rf "$d" && info "  Deleted: $d"
    done
    info "✅ Age-based cleanup complete."
}

_cleanup_all() {
    warn "⚠️  This will delete ALL local backups:"
    echo "  - ${BACKUP_ROOT}"
    echo "  - ${LOCAL_BACKUP_ROOT}"
    echo ""
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
        ls -lh "$LOCAL_BACKUP_ROOT"/ 2>/dev/null | sed 's/^/  /' || echo "  (none)"
    else
        echo "  (none)"
    fi

    echo ""
    header "REMOTE — ${BACKUP_SERVER}:${BACKUP_SERVER_PATH}"
    if check_backup_server 2>/dev/null; then
        ssh "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" \
            "ls -lh ${BACKUP_SERVER_PATH}/ 2>/dev/null || echo '  (empty)'" \
            | sed 's/^/  /'
    else
        warn "  Backup server unreachable"
    fi
}

# =============================================================================
# BOX-SPECIFIC MENUS
# Each has a backup menu, restore menu, and drops into the shared flow above.
# =============================================================================

# ── DATABASE BOX ──────────────────────────────────────────────────────────────
menu_db_box() {
    while true; do
        header "Database Box — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Services: PostgreSQL${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back to box select"
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
                    1) fns=(do_backup_postgres);               _do_backup_flow fns ;;
                    2) fns=(do_backup_system);                 _do_backup_flow fns ;;
                    3) fns=(do_backup_postgres do_backup_system); _do_backup_flow fns ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            2)
                header "RESTORE — What to restore?"
                echo "  1) PostgreSQL"
                echo "  2) System configs (/etc)"
                echo "  3) Both"
                echo "  0) Back"
                read -rp $'\nChoice: ' what

                case "$what" in
                    1) _do_restore_flow do_restore_postgres ;;
                    2) _do_restore_flow do_restore_system ;;
                    3)
                        _do_restore_flow do_restore_system
                        _do_restore_flow do_restore_postgres
                        ;;
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
        echo -e "  ${DIM}Services: Apache/Nginx, web content, SSL certs${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) Run web server audit"
        echo "  4) Scan for webshells"
        echo "  5) List backups"
        echo "  6) Cleanup"
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

                local fns=()
                case "$what" in
                    1) fns=("run_backup_script 05_backup_webserver.sh backup") ;;
                    2) fns=("run_backup_script 06_backup_webcontent.sh backup") ;;
                    3) fns=(do_backup_system) ;;
                    4)
                        header "Backing up web server config ..."
                        run_backup_script 05_backup_webserver.sh backup
                        header "Backing up web content ..."
                        run_backup_script 06_backup_webcontent.sh backup
                        header "Backing up system configs ..."
                        do_backup_system

                        # Handle remote push separately here since we mix delegate+inline
                        header "DESTINATION"
                        echo "  1) Already saved locally"
                        echo "  2) Also push to backup server ${BACKUP_SERVER}"
                        read -rp $'\nChoice: ' dest
                        if [[ "$dest" == "2" ]] && check_backup_server; then
                            push_to_remote "${BACKUP_ROOT}/webserver/latest"
                            push_to_remote "${BACKUP_ROOT}/webcontent/latest"
                            [[ -n "$BACKUP_RESULT" ]] && push_to_remote "$BACKUP_RESULT"
                        fi
                        continue
                        ;;
                    0) continue ;;
                    *) warn "Invalid option."; continue ;;
                esac

                # For single-item selections, use the standard flow
                if [[ ${#fns[@]} -gt 0 && "$what" != "4" ]]; then
                    fns=(do_backup_system)
                    [[ "$what" == "1" ]] && { run_backup_script 05_backup_webserver.sh backup; }
                    [[ "$what" == "2" ]] && { run_backup_script 06_backup_webcontent.sh backup; }
                    [[ "$what" == "3" ]] && _do_backup_flow fns
                fi
                ;;
            2)
                header "RESTORE — What to restore?"
                echo "  1) Web server config"
                echo "  2) Web content"
                echo "  3) System configs"
                echo "  0) Back"
                read -rp $'\nChoice: ' what

                case "$what" in
                    1) run_backup_script 05_backup_webserver.sh restore ;;
                    2) run_backup_script 06_backup_webcontent.sh restore ;;
                    3) _do_restore_flow do_restore_system ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            3) run_backup_script 05_backup_webserver.sh audit ;;
            4) run_backup_script 06_backup_webcontent.sh scan ;;
            5) menu_list_backups ;;
            6) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# ── DNS BOX ───────────────────────────────────────────────────────────────────
menu_dns_box() {
    while true; do
        header "DNS Box — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Services: BIND9 (named) — forward/reverse zones, internal + external${NC}"
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
                    1)
                        run_backup_script 09_backup_dns.sh backup
                        ;;
                    2)
                        fns=(do_backup_system); _do_backup_flow fns
                        ;;
                    3)
                        run_backup_script 09_backup_dns.sh backup
                        fns=(do_backup_system); _do_backup_flow fns

                        header "Push DNS backup to server?"
                        echo "  1) Yes   2) No"
                        read -rp $'\nChoice: ' dest
                        if [[ "$dest" == "1" ]] && check_backup_server; then
                            push_to_remote "${BACKUP_ROOT}/dns/latest"
                        fi
                        ;;
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
                    1) run_backup_script 09_backup_dns.sh restore ;;
                    2) _do_restore_flow do_restore_system ;;
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
        echo -e "  ${DIM}Services: Samba (SMB), SSH — scored for SSH key login + SMB read/write${NC}"
        echo ""
        echo "  1) Backup"
        echo "  2) Restore"
        echo "  3) Run SMB threat hunt"
        echo "  4) Run SSH threat hunt"
        echo "  5) List backups"
        echo "  6) Cleanup"
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
                    1) run_backup_script 04_backup_smb.sh backup ;;
                    2) run_backup_script 03_backup_sshd.sh backup ;;
                    3) fns=(do_backup_system); _do_backup_flow fns ;;
                    4)
                        run_backup_script 04_backup_smb.sh backup
                        run_backup_script 03_backup_sshd.sh backup
                        fns=(do_backup_system); _do_backup_flow fns

                        header "Push SMB/SSH backups to server?"
                        echo "  1) Yes   2) No"
                        read -rp $'\nChoice: ' dest
                        if [[ "$dest" == "1" ]] && check_backup_server; then
                            push_to_remote "${BACKUP_ROOT}/smb/latest"
                            push_to_remote "${BACKUP_ROOT}/sshd/latest"
                        fi
                        ;;
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
                    1) run_backup_script 04_backup_smb.sh restore ;;
                    2) run_backup_script 03_backup_sshd.sh restore ;;
                    3) _do_restore_flow do_restore_system ;;
                    0) ;;
                    *) warn "Invalid option." ;;
                esac
                ;;
            3) run_backup_script ../SMB/smb_threat_hunt.sh ;;
            4) run_backup_script ../SSH/ssh_threat_hunt.sh ;;
            5) menu_list_backups ;;
            6) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# ── ROUTER ────────────────────────────────────────────────────────────────────
menu_router() {
    while true; do
        header "Router — ${SELECTED_BOX_IP}"
        echo -e "  ${DIM}Saves iptables/nftables rules locally — no PostgreSQL or file services${NC}"
        echo ""
        echo "  1) Backup firewall rules"
        echo "  2) Restore firewall rules"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice

        case "$choice" in
            1)
                run_backup_script 10_backup_firewall.sh backup
                header "Push to backup server?"
                echo "  1) Yes   2) No"
                read -rp $'\nChoice: ' dest
                if [[ "$dest" == "1" ]] && check_backup_server; then
                    push_to_remote "${BACKUP_ROOT}/firewall/latest"
                fi
                ;;
            2) run_backup_script 10_backup_firewall.sh restore ;;
            3) menu_list_backups ;;
            4) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# ── ANY BOX — SYSTEM ONLY ─────────────────────────────────────────────────────
menu_generic_box() {
    while true; do
        header "Generic Box — System Backup"
        echo -e "  ${DIM}Backs up /etc, PAM, SSH config, binaries, and user accounts${NC}"
        echo ""
        echo "  1) Backup (system + SSH + binaries + users)"
        echo "  2) Restore system configs"
        echo "  3) List backups"
        echo "  4) Cleanup"
        echo "  0) Back"
        read -rp $'\nChoice: ' choice

        case "$choice" in
            1)
                run_backup_script 01_backup_binaries.sh backup
                run_backup_script 02_backup_pam.sh backup
                run_backup_script 03_backup_sshd.sh backup
                run_backup_script 11_backup_users.sh backup
                fns=(do_backup_system); _do_backup_flow fns
                ;;
            2) _do_restore_flow do_restore_system ;;
            3) menu_list_backups ;;
            4) menu_cleanup ;;
            0) return 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

# =============================================================================
# BOX SELECTION — entry point
# =============================================================================

select_box() {
    while true; do
        echo ""
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║   NCAE Cyber Games 2026 — Universal Backup Manager       ║${NC}"
        echo -e "${BOLD}${CYAN}║   Backup server: ${BACKUP_SERVER:-not set}                         ║${NC}"
        echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Which box are you on?"
        echo ""
        echo -e "  ${GREEN}1)${NC} Database Box      (${IP_DB:-192.168.t.7})   — PostgreSQL"
        echo -e "  ${GREEN}2)${NC} Web Box            (${IP_WEB:-192.168.t.5})   — Apache/Nginx + web content"
        echo -e "  ${GREEN}3)${NC} DNS Box            (${IP_DNS:-192.168.t.12})  — BIND9"
        echo -e "  ${GREEN}4)${NC} Shell / SMB Box    (${IP_SHELL:-192.168.t.14}) — Samba + SSH"
        echo -e "  ${GREEN}5)${NC} Router             (${IP_ROUTER:-192.168.t.1})  — Firewall rules"
        echo -e "  ${CYAN}6)${NC} Other / Generic    — System configs only"
        echo -e "  ${RED}0)${NC} Exit"
        echo ""
        read -rp "Choice: " choice

        case "$choice" in
            1)
                SELECTED_BOX="Database Box"
                SELECTED_BOX_IP="${IP_DB}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/db"
                menu_db_box
                ;;
            2)
                SELECTED_BOX="Web Box"
                SELECTED_BOX_IP="${IP_WEB}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/web"
                menu_web_box
                ;;
            3)
                SELECTED_BOX="DNS Box"
                SELECTED_BOX_IP="${IP_DNS}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/dns"
                menu_dns_box
                ;;
            4)
                SELECTED_BOX="Shell / SMB Box"
                SELECTED_BOX_IP="${IP_SHELL}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/shell"
                menu_shell_box
                ;;
            5)
                SELECTED_BOX="Router"
                SELECTED_BOX_IP="${IP_ROUTER}"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/router"
                menu_router
                ;;
            6)
                SELECTED_BOX="Generic"
                SELECTED_BOX_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
                BACKUP_SERVER="${IP_BACKUP}"
                BACKUP_SERVER_PATH="${BACKUP_SERVER_BASE_PATH}/misc"
                menu_generic_box
                ;;
            0)
                info "Exiting."
                exit 0
                ;;
            *)
                warn "Invalid option — choose 0–6."
                ;;
        esac
    done
}

# =============================================================================
# ENTRY POINT
# =============================================================================

select_team_number
select_box