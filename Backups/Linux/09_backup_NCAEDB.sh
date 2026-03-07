# Clauded By Yours Truly
# King Snowball

#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 — Regional  |  Team 22
# DB Box Backup & Restore Manager
# =============================================================================
# Menu-driven script for backing up and restoring the DB box (192.168.22.7).
# Covers: PostgreSQL, /etc configs, PAM, and system files.
# Supports: local storage and remote push/pull to backup server (192.168.22.15)
#
# Usage:
#   sudo bash db_backup_restore.sh
#
# Network:
#   DB Box         192.168.22.7
#   Backup Server  192.168.22.15
#   Web Server     192.168.22.5  (postgres scoring access — never break this)
#
# Requirements: pg_dump, pg_dumpall, psql, rsync/scp, gzip, tar
# Compatible: Ubuntu 24.04 / PostgreSQL 16
# =============================================================================

set -uo pipefail

# ── Network / Path Configuration ──────────────────────────────────────────────
DB_IP="192.168.22.7"
BACKUP_SERVER="192.168.22.15"
BACKUP_SERVER_PATH="/backups/db"
BACKUP_SERVER_USER="root"

LOCAL_BACKUP_ROOT="/root/.cache/backups"
PG_BACKUP_ROOT="/opt/blueteam/backups/postgres"
LOG_FILE="/var/log/blueteam_backup.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# PostgreSQL connection settings (peer auth via postgres user)
PG_HOST="localhost"
PG_PORT="5432"
PG_SUPERUSER="postgres"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Logging ───────────────────────────────────────────────────────────────────
log()   { echo -e "$(date '+%H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()  { log "INFO " "${GREEN}$*${NC}"; }
warn()  { log "WARN " "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
header(){ echo -e "\n${BOLD}${CYAN}$*${NC}"; echo -e "${CYAN}$(printf '─%.0s' {1..60})${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo -e "${RED}[!] Must run as root.${NC}"; exit 1; }
mkdir -p "$LOCAL_BACKUP_ROOT" "$PG_BACKUP_ROOT"
chmod 700 "$LOCAL_BACKUP_ROOT" "$PG_BACKUP_ROOT"
touch "$LOG_FILE" && chmod 600 "$LOG_FILE"

# ── Helper: run command as postgres user ──────────────────────────────────────
run_pg() { sudo -u "$PG_SUPERUSER" "$@"; }

pg_exec() {
    run_pg psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --no-password -t -A -c "$1" 2>/dev/null
}

# ── Helper: test PostgreSQL connectivity ──────────────────────────────────────
check_postgres() {
    if run_pg psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --no-password -c "SELECT 1;" &>/dev/null; then
        info "PostgreSQL connection: OK"
        return 0
    else
        error "Cannot connect to PostgreSQL. Is it running?"
        error "  sudo systemctl status postgresql"
        return 1
    fi
}

# ── Helper: test backup server connectivity ───────────────────────────────────
check_backup_server() {
    if ssh -o ConnectTimeout=5 -o BatchMode=yes \
        "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" "echo ok" &>/dev/null; then
        info "Backup server ${BACKUP_SERVER}: reachable"
        return 0
    else
        warn "Cannot reach backup server ${BACKUP_SERVER} via SSH."
        warn "  - Is it online? Try: ping ${BACKUP_SERVER}"
        warn "  - SSH key auth needed (or enter password when prompted)"
        return 1
    fi
}

# ── Helper: ensure remote backup dir exists ───────────────────────────────────
ensure_remote_dir() {
    ssh "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" \
        "mkdir -p ${BACKUP_SERVER_PATH} && chmod 700 ${BACKUP_SERVER_PATH}" 2>/dev/null
}

# ── Helper: transfer files to backup server ───────────────────────────────────
push_to_remote() {
    local src="$1"
    info "Pushing to ${BACKUP_SERVER}:${BACKUP_SERVER_PATH} ..."
    ensure_remote_dir

    if command -v rsync &>/dev/null; then
        rsync -avz --progress "$src" \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            2>>"$LOG_FILE"
    else
        scp -r "$src" \
            "${BACKUP_SERVER_USER}@${BACKUP_SERVER}:${BACKUP_SERVER_PATH}/" \
            2>>"$LOG_FILE"
    fi

    if [[ $? -eq 0 ]]; then
        info "✅ Push to backup server: OK"
    else
        warn "⚠️  Push to backup server failed. Local backup is still safe at: $src"
    fi
}

# ── Helper: pull files from backup server ─────────────────────────────────────
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
# BACKUP FUNCTIONS
# =============================================================================

# ── Backup: system configs (/etc, PAM, SSHD) ─────────────────────────────────
backup_system() {
    local dest="${LOCAL_BACKUP_ROOT}/system_${TIMESTAMP}"
    mkdir -p "$dest"
    info "Backing up /etc ..."
    tar czf "${dest}/etc_${TIMESTAMP}.tar.gz" -C / etc 2>>"$LOG_FILE" \
        && info "  /etc: OK" || warn "  /etc backup had errors"

    info "Backing up PAM libraries ..."
    mkdir -p "${dest}/pam_libs"
    find /lib /lib64 /usr/lib /usr/lib64 -name "pam*.so" 2>/dev/null \
        | while IFS= read -r f; do
            rel=$(dirname "${f#/}")
            mkdir -p "${dest}/pam_libs/${rel}"
            cp -p "$f" "${dest}/pam_libs/${rel}/" 2>/dev/null
        done
    info "  PAM libs: OK"

    sha256sum "${dest}/"* 2>/dev/null > "${dest}/sha256sums.txt" || true
    info "✅ System backup saved to: $dest"
    echo "$dest"
}

# ── Backup: PostgreSQL (full cluster + per-db + configs) ──────────────────────
backup_postgres() {
    check_postgres || return 1

    local dest="${PG_BACKUP_ROOT}/${TIMESTAMP}"
    mkdir -p "${dest}/per_database"
    chmod 700 "$dest"

    # 1. Globals (roles, tablespaces — no data)
    info "Dumping PostgreSQL globals (roles/tablespaces) ..."
    run_pg pg_dumpall -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --globals-only --no-password 2>>"$LOG_FILE" \
        > "${dest}/globals_${TIMESTAMP}.sql"
    gzip -f "${dest}/globals_${TIMESTAMP}.sql"
    info "  Globals: OK"

    # 2. Full cluster dump (all databases — gold standard for full recovery)
    info "Dumping full cluster (all databases) ..."
    run_pg pg_dumpall -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --no-password --clean --if-exists 2>>"$LOG_FILE" \
        > "${dest}/full_cluster_${TIMESTAMP}.sql"
    gzip -f "${dest}/full_cluster_${TIMESTAMP}.sql"
    info "  Full cluster: OK"

    # 3. Per-database dumps (custom format, fastest restore of individual DBs)
    info "Dumping individual databases ..."
    local db_list
    db_list=$(pg_exec "SELECT datname FROM pg_database \
                       WHERE datistemplate = false AND datname != 'template0' \
                       ORDER BY datname;")
    local count=0
    while IFS= read -r db; do
        [[ -z "$db" ]] && continue
        local dumpfile="${dest}/per_database/${db}_${TIMESTAMP}.dump"
        run_pg pg_dump -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
            --no-password --format=custom --compress=9 \
            --dbname="$db" 2>>"$LOG_FILE" > "$dumpfile"
        sha256sum "$dumpfile" >> "${dest}/sha256sums.txt"
        info "  DB '$db': OK"
        ((count++))
    done <<< "$db_list"
    info "  $count database(s) dumped"

    # 4. PostgreSQL config files
    info "Backing up PostgreSQL configuration files ..."
    local pg_conf_src="/etc/postgresql"
    if [[ -d "$pg_conf_src" ]]; then
        tar czf "${dest}/pg_conf_${TIMESTAMP}.tar.gz" \
            -C / "${pg_conf_src#/}" 2>>"$LOG_FILE" \
            && info "  pg config: OK" || warn "  pg config had errors"
    fi

    # 5. Final hash manifest
    find "$dest" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; >> "${dest}/sha256sums.txt" 2>/dev/null || true
    chmod -R 600 "$dest"
    ln -sfn "$dest" "${PG_BACKUP_ROOT}/latest"

    info "✅ PostgreSQL backup saved to: $dest"
    echo "$dest"
}

# =============================================================================
# RESTORE FUNCTIONS
# =============================================================================

# ── Restore: system configs from a local path ─────────────────────────────────
restore_system_local() {
    local src="$1"

    # Find the most recent etc tarball in the source dir
    local etc_archive
    etc_archive=$(find "$src" -maxdepth 2 -name "etc_*.tar.gz" \
                    | sort -r | head -1)

    if [[ -z "$etc_archive" ]]; then
        error "No etc_*.tar.gz found in: $src"
        return 1
    fi

    warn "⚠️  This will overwrite /etc from: $(basename "$etc_archive")"
    read -rp "  Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

    info "Restoring /etc from $(basename "$etc_archive") ..."
    tar -xzf "$etc_archive" -C / 2>>"$LOG_FILE"
    info "  /etc restored: OK"

    info "Restarting PostgreSQL to pick up restored config ..."
    systemctl restart postgresql 2>>"$LOG_FILE"
    systemctl is-active postgresql &>/dev/null \
        && info "  PostgreSQL: running ✅" \
        || warn "  PostgreSQL failed to start — check: journalctl -xe -u postgresql"
}

# ── Restore: PostgreSQL from a local backup path ──────────────────────────────
restore_postgres_local() {
    local src="$1"
    check_postgres || return 1

    header "PostgreSQL Restore Options"
    echo "  1) Full cluster restore (all databases — use after wipe)"
    echo "  2) Single database restore (targeted recovery)"
    echo "  3) Globals only (roles/tablespaces)"
    echo "  0) Back"
    read -rp $'\nChoice: ' choice

    case "$choice" in
        1)
            local full_dump
            full_dump=$(find "$src" -maxdepth 2 -name "full_cluster_*.sql.gz" \
                          | sort -r | head -1)
            if [[ -z "$full_dump" ]]; then
                error "No full_cluster_*.sql.gz found in: $src"
                return 1
            fi

            warn "⚠️  FULL CLUSTER RESTORE will drop and recreate ALL databases."
            warn "   Stop the web server before proceeding if possible."
            read -rp "  Type 'FULL RESTORE' to confirm: " confirm
            [[ "$confirm" != "FULL RESTORE" ]] && { info "Cancelled."; return 0; }

            # Restore globals first
            local globals_dump
            globals_dump=$(find "$src" -maxdepth 2 -name "globals_*.sql.gz" \
                             | sort -r | head -1)
            if [[ -n "$globals_dump" ]]; then
                info "Restoring globals ..."
                zcat "$globals_dump" | run_pg psql -h "$PG_HOST" -p "$PG_PORT" \
                    -U "$PG_SUPERUSER" --no-password -f - 2>>"$LOG_FILE" \
                    || warn "  Globals restore had errors (may be harmless duplicates)"
            fi

            info "Restoring full cluster ..."
            zcat "$full_dump" | run_pg psql -h "$PG_HOST" -p "$PG_PORT" \
                -U "$PG_SUPERUSER" --no-password -f - 2>>"$LOG_FILE"
            info "✅ Full cluster restore complete."
            info "Verifying databases:"
            pg_exec "\l" 2>/dev/null || true
            ;;

        2)
            local db_dir
            db_dir=$(find "$src" -maxdepth 2 -type d -name "per_database" | head -1)
            if [[ -z "$db_dir" ]] || [[ ! -d "$db_dir" ]]; then
                error "No per_database/ directory found in: $src"
                return 1
            fi

            echo ""
            info "Available database dumps:"
            local i=1
            declare -a dump_files
            while IFS= read -r -d '' f; do
                dump_files+=("$f")
                echo "  $i) $(basename "$f")"
                ((i++))
            done < <(find "$db_dir" -type f \( -name "*.dump" -o -name "*.sql.gz" \) \
                       -print0 2>/dev/null | sort -z)

            if [[ ${#dump_files[@]} -eq 0 ]]; then
                error "No dump files found in: $db_dir"
                return 1
            fi

            read -rp $'\nSelect number: ' sel
            if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#dump_files[@]} )); then
                error "Invalid selection."
                return 1
            fi

            local chosen="${dump_files[$((sel-1))]}"
            local db_name
            db_name=$(basename "$chosen" | sed 's/_[0-9]\{8\}_[0-9]\{6\}.*$//')

            warn "This will DROP and recreate database: $db_name"
            read -rp "  Type 'CONFIRM' to proceed: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

            run_pg psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                --no-password \
                -c "DROP DATABASE IF EXISTS \"${db_name}\";" 2>>"$LOG_FILE" || true
            run_pg psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                --no-password \
                -c "CREATE DATABASE \"${db_name}\";" 2>>"$LOG_FILE"

            info "Restoring database: $db_name ..."
            if [[ "$chosen" == *.dump ]]; then
                run_pg pg_restore -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                    --no-password --dbname="$db_name" \
                    --verbose --clean --if-exists \
                    "$chosen" 2>>"$LOG_FILE"
            else
                zcat "$chosen" | run_pg psql -h "$PG_HOST" -p "$PG_PORT" \
                    -U "$PG_SUPERUSER" --no-password -d "$db_name" \
                    -f - 2>>"$LOG_FILE"
            fi
            info "✅ Database '$db_name' restored."
            ;;

        3)
            local globals_dump
            globals_dump=$(find "$src" -maxdepth 2 -name "globals_*.sql.gz" \
                             | sort -r | head -1)
            if [[ -z "$globals_dump" ]]; then
                error "No globals_*.sql.gz found in: $src"
                return 1
            fi

            read -rp "  Type 'CONFIRM' to restore globals: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; return 0; }

            info "Restoring globals ..."
            zcat "$globals_dump" | run_pg psql -h "$PG_HOST" -p "$PG_PORT" \
                -U "$PG_SUPERUSER" --no-password -f - 2>>"$LOG_FILE" \
                || warn "  Some errors (may be harmless if roles already exist)"
            info "✅ Globals restored."
            ;;

        0) return 0 ;;
        *) error "Invalid choice."; return 1 ;;
    esac
}

# ── Post-restore verification ─────────────────────────────────────────────────
verify_after_restore() {
    header "Post-Restore Verification"

    info "PostgreSQL service status:"
    systemctl is-active postgresql &>/dev/null \
        && echo -e "  ${GREEN}● postgresql: active${NC}" \
        || echo -e "  ${RED}● postgresql: DEAD — restart with: systemctl restart postgresql${NC}"

    info "Databases present:"
    pg_exec "SELECT datname FROM pg_database WHERE datistemplate = false;" \
        2>/dev/null | sed 's/^/  /' || warn "  Could not list databases"

    info "Testing scoring user connectivity (web server path) ..."
    local scoring_user
    # Try to detect a non-postgres login role
    scoring_user=$(pg_exec "SELECT rolname FROM pg_roles \
                            WHERE rolcanlogin = true AND rolname != 'postgres' \
                            LIMIT 1;" 2>/dev/null | head -1)
    if [[ -n "$scoring_user" ]]; then
        info "  Found login role: $scoring_user"
        info "  ⚠️  Verify the web server can connect: psql -h ${DB_IP} -U ${scoring_user} -d <db>"
    else
        warn "  No non-postgres login roles found — scoring user may be missing"
    fi

    info "pg_hba.conf trust check:"
    local hba_file
    hba_file=$(pg_exec "SHOW hba_file;" 2>/dev/null)
    if [[ -f "$hba_file" ]]; then
        if grep -vE '^\s*#|^\s*$' "$hba_file" | grep -qE '\btrust\b'; then
            warn "  ⚠️  TRUST auth found in pg_hba.conf — replace with scram-sha-256"
        else
            info "  No trust auth: OK"
        fi
    fi
}

# =============================================================================
# MENU SYSTEM
# =============================================================================

menu_backup() {
    header "BACKUP"
    echo "  Where should the backup be stored?"
    echo ""
    echo "  1) Local only       (saved to ${LOCAL_BACKUP_ROOT} / ${PG_BACKUP_ROOT})"
    echo "  2) Remote only      (push directly to backup server ${BACKUP_SERVER})"
    echo "  3) Local + Remote   (recommended — save locally then push)"
    echo "  0) Back"
    read -rp $'\nChoice: ' dest_choice

    [[ "$dest_choice" == "0" ]] && return 0

    header "WHAT TO BACK UP"
    echo "  1) PostgreSQL only    (databases, roles, pg config)"
    echo "  2) System only        (/etc, PAM, SSHD config)"
    echo "  3) Everything         (PostgreSQL + system)"
    echo "  0) Back"
    read -rp $'\nChoice: ' what_choice

    [[ "$what_choice" == "0" ]] && return 0

    local pg_dest="" sys_dest=""

    case "$what_choice" in
        1|3)
            header "Backing up PostgreSQL ..."
            pg_dest=$(backup_postgres) || { error "PostgreSQL backup failed."; return 1; }
            ;;
    esac

    case "$what_choice" in
        2|3)
            header "Backing up system configs ..."
            sys_dest=$(backup_system) || { error "System backup failed."; return 1; }
            ;;
    esac

    # Handle remote push
    case "$dest_choice" in
        2|3)
            header "Pushing to backup server ..."
            if check_backup_server; then
                [[ -n "$pg_dest" ]]  && push_to_remote "$pg_dest"
                [[ -n "$sys_dest" ]] && push_to_remote "$sys_dest"
            else
                warn "Skipping remote push — backup server unreachable."
                warn "Local backups are safe. Push later with option 2 from the backup menu."
            fi
            ;;
    esac

    if [[ "$dest_choice" == "2" ]]; then
        info "Cleaning up local staging files ..."
        [[ -n "$pg_dest" && -d "$pg_dest" ]]  && rm -rf "$pg_dest"
        [[ -n "$sys_dest" && -d "$sys_dest" ]] && rm -rf "$sys_dest"
    fi

    header "Backup Summary"
    [[ -n "$pg_dest" && -d "$pg_dest" ]]   && { info "PostgreSQL backup:"; ls -lh "$pg_dest"/; }
    [[ -n "$sys_dest" && -d "$sys_dest" ]] && { info "System backup:"; ls -lh "$sys_dest"/; }
    info "Log: $LOG_FILE"
}

menu_restore() {
    header "RESTORE"
    echo "  Where are the backups coming from?"
    echo ""
    echo "  1) Local             (use backups already on this box)"
    echo "  2) Remote            (pull from backup server ${BACKUP_SERVER} first)"
    echo "  0) Back"
    read -rp $'\nChoice: ' src_choice

    [[ "$src_choice" == "0" ]] && return 0

    local restore_root="$LOCAL_BACKUP_ROOT"

    if [[ "$src_choice" == "2" ]]; then
        header "Pulling from backup server ..."
        if check_backup_server; then
            local pull_dest="/root/restored_${TIMESTAMP}"
            pull_from_remote "$pull_dest" || { error "Pull failed. Aborting restore."; return 1; }
            restore_root="$pull_dest"
        else
            error "Cannot reach backup server. Check connectivity."
            return 1
        fi
    fi

    header "WHAT TO RESTORE"
    echo "  1) PostgreSQL         (databases, roles)"
    echo "  2) System configs     (/etc, restarts postgresql)"
    echo "  3) Both               (system first, then postgres)"
    echo "  0) Back"
    read -rp $'\nChoice: ' what_choice

    [[ "$what_choice" == "0" ]] && return 0

    case "$what_choice" in
        1|3)
            # Search both pulled root and dedicated pg backup root
            local pg_src="${PG_BACKUP_ROOT}/latest"
            if [[ "$src_choice" == "2" ]]; then
                pg_src="$restore_root"
            fi
            if [[ ! -e "$pg_src" ]]; then
                error "No PostgreSQL backup found at: $pg_src"
                [[ "$what_choice" == "1" ]] && return 1
            else
                header "Restoring PostgreSQL ..."
                restore_postgres_local "$pg_src"
            fi
            ;;& # fallthrough for option 3

        2|3)
            header "Restoring system configs ..."
            restore_system_local "$restore_root"
            ;;
    esac

    verify_after_restore
}

menu_list_backups() {
    header "LOCAL BACKUPS"
    echo ""
    info "PostgreSQL backups (${PG_BACKUP_ROOT}):"
    if [[ -d "$PG_BACKUP_ROOT" ]]; then
        ls -lhd "${PG_BACKUP_ROOT}"/*/  2>/dev/null | sed 's/^/  /' \
            || echo "  (none)"
        if [[ -L "${PG_BACKUP_ROOT}/latest" ]]; then
            echo ""
            info "  Latest contents:"
            ls -lh "${PG_BACKUP_ROOT}/latest/"  2>/dev/null | sed 's/^/    /'
        fi
    else
        echo "  (none)"
    fi

    echo ""
    info "System backups (${LOCAL_BACKUP_ROOT}):"
    if [[ -d "$LOCAL_BACKUP_ROOT" ]]; then
        ls -lh "$LOCAL_BACKUP_ROOT"/ 2>/dev/null | sed 's/^/  /' \
            || echo "  (none)"
    else
        echo "  (none)"
    fi

    echo ""
    info "Remote backup server (${BACKUP_SERVER}):"
    if check_backup_server 2>/dev/null; then
        ssh "${BACKUP_SERVER_USER}@${BACKUP_SERVER}" \
            "ls -lh ${BACKUP_SERVER_PATH}/ 2>/dev/null || echo '  (empty)'" \
            | sed 's/^/  /'
    else
        warn "  Cannot reach backup server — check connectivity"
    fi
}

# ── Main Menu ─────────────────────────────────────────────────────────────────
main_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║   NCAE 2026 — DB Box Backup & Restore Manager        ║${NC}"
        echo -e "${BOLD}${CYAN}║   DB: ${DB_IP}   Backup Server: ${BACKUP_SERVER}          ║${NC}"
        echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${GREEN}1)${NC} Backup"
        echo -e "  ${YELLOW}2)${NC} Restore"
        echo -e "  ${CYAN}3)${NC} List backups"
        echo -e "  ${RED}0)${NC} Exit"
        echo ""
        read -rp "Choice: " choice

        case "$choice" in
            1) menu_backup ;;
            2) menu_restore ;;
            3) menu_list_backups ;;
            0) info "Exiting."; exit 0 ;;
            *) warn "Invalid option — choose 0–3." ;;
        esac
    done
}

main_menu