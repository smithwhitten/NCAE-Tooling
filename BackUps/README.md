# Blue Team Backup & Restore Scripts
## Quick Reference

---

### LINUX SCRIPTS  (run as root / sudo)
```
linux/
├── 00_master.sh              # Orchestrator — run all backups or restore menu
├── 01_backup_binaries.sh     # Critical system binaries + hash verification
├── 02_backup_pam.sh          # PAM configs, libraries, reinstall option
├── 03_backup_sshd.sh         # sshd_config, host keys, authorized_keys + audit
├── 04_backup_smb.sh          # Samba config, TDB databases, user export
├── 05_backup_webserver.sh    # Apache/Nginx/Lighttpd config (auto-detected)
├── 06_backup_webcontent.sh   # Web root files + webshell scanner
├── 07_backup_mysql.sh        # MySQL/MariaDB dumps, users, grants + audit
└── 08_backup_postgres.sh     # PostgreSQL dumps, globals, config + audit
```

**Setup (one-time):**
```bash
sudo chmod +x linux/*.sh
sudo ./linux/00_master.sh backup     # Full backup
sudo ./linux/00_master.sh restore    # Interactive restore
sudo ./linux/00_master.sh status     # Show inventory
```

**Individual scripts support:**
```bash
sudo ./linux/01_backup_binaries.sh   {backup|restore|verify}
sudo ./linux/02_backup_pam.sh        {backup|restore|reinstall|verify}
sudo ./linux/03_backup_sshd.sh       {backup|restore|audit}
sudo ./linux/04_backup_smb.sh        {backup|restore|verify}
sudo ./linux/05_backup_webserver.sh  {backup|restore|audit}
sudo ./linux/06_backup_webcontent.sh {backup|restore|scan}
sudo ./linux/07_backup_mysql.sh      {backup|restore|verify|audit}
sudo ./linux/08_backup_postgres.sh   {backup|restore|verify|audit}
```

**Backup location:** `/opt/blueteam/backups/<service>/<timestamp>/`
**Logs:** `/var/log/blueteam_<service>.log`

---

### WINDOWS SCRIPTS  (run as Administrator in PowerShell)
```
windows/
├── 00_Master.ps1             # Orchestrator — run all or restore menu
├── 01_Backup-Binaries.ps1    # System32 critical binaries + hash verification
├── 02_Backup-SSH.ps1         # OpenSSH Server config, authorized_keys + audit
├── 03_Backup-SMB.ps1         # SMB shares, ACLs, server config + audit
├── 04_Backup-WebServer.ps1   # IIS config via appcmd + WebAdministration
├── 05_Backup-WebContent.ps1  # IIS web roots + webshell scanner
├── 06_Backup-MySQL.ps1       # MySQL/MariaDB dumps, users, grants + audit
└── 07_Backup-Postgres.ps1    # PostgreSQL dumps, globals, config + audit
```

**Setup (one-time — allow script execution):**
```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```

**Usage:**
```powershell
.\windows\00_Master.ps1 -Action backup
.\windows\00_Master.ps1 -Action restore
.\windows\00_Master.ps1 -Action status
```

**Individual scripts:**
```powershell
.\windows\01_Backup-Binaries.ps1   -Action {backup|restore|verify}
.\windows\02_Backup-SSH.ps1        -Action {backup|restore|audit}
.\windows\03_Backup-SMB.ps1        -Action {backup|restore|audit}
.\windows\04_Backup-WebServer.ps1  -Action {backup|restore|audit}
.\windows\05_Backup-WebContent.ps1 -Action {backup|restore|scan}
.\windows\06_Backup-MySQL.ps1      -Action {backup|restore|verify|audit}
.\windows\07_Backup-Postgres.ps1   -Action {backup|restore|verify|audit}
```

**Backup location:** `C:\BlueteamBackups\<service>\<timestamp>\`
**Logs:** `C:\BlueteamBackups\Logs\`

---

### DATABASE SCRIPT SETUP

#### MySQL / MariaDB — Credential File (REQUIRED before first run)

**Linux** — create `/root/.my.cnf`:
```ini
[client]
user=root
password=yourpassword
```
```bash
chmod 600 /root/.my.cnf
```

**Windows** — create `C:\ProgramData\blueteam\mysql_backup.cnf`:
```ini
[client]
user=root
password=yourpassword
```
```powershell
icacls "C:\ProgramData\blueteam\mysql_backup.cnf" /inheritance:r /grant "Administrators:F"
```

#### PostgreSQL — Credential Setup

**Linux** — scripts run via `sudo -u postgres` using peer authentication.
No extra config needed on most systems. If using a remote host, set:
```bash
export PGPASSWORD="yourpassword"
```
Or create `/root/.pgpass`:
```
localhost:5432:*:postgres:yourpassword
```
```bash
chmod 600 /root/.pgpass
```

**Windows** — set the environment variable before running, OR create the pgpass file:
```powershell
$env:PGPASSWORD = "yourpassword"
.\windows\07_Backup-Postgres.ps1 -Action backup
```
Or create `%APPDATA%\postgresql\pgpass.conf`:
```
localhost:5432:*:postgres:yourpassword
```
```powershell
icacls "$env:APPDATA\postgresql\pgpass.conf" /inheritance:r /grant "$env:USERNAME:F"
```

---

### DATABASE BACKUP — WHAT GETS SAVED

| Item | MySQL | PostgreSQL |
|---|---|---|
| Full instance dump | ✅ `--all-databases` | ✅ `pg_dumpall` |
| Per-database dumps | ✅ One `.sql.gz` per DB | ✅ One `.dump` per DB (custom format) |
| User accounts + grants | ✅ Separate grants file | ✅ Included in globals dump |
| Server config | ✅ `my.cnf` / `my.ini` | ✅ `postgresql.conf`, `pg_hba.conf`, `pg_ident.conf` |
| Binary log position | ✅ Captured in full dump | N/A |
| Roles / tablespaces | N/A | ✅ `pg_dumpall --globals-only` |
| SHA-256 manifest | ✅ | ✅ |

---

### DATABASE RESTORE — OPTIONS

Both database scripts offer an **interactive restore menu**:

```
1) Full instance restore    — Restores EVERYTHING (destructive — stop apps first)
2) Single database restore  — Pick one DB from the per-database backup list
3) Users/grants only        — Restore accounts without touching data
```

PostgreSQL additionally offers:
```
4) Config files only        — Restore pg_hba.conf/postgresql.conf without touching data
```

---

### DATABASE AUDIT — WHAT GETS CHECKED

**MySQL audit** flags:
- Anonymous user accounts (`user=''`)
- Accounts with empty passwords
- `root@%` — root accessible from any host
- Non-root users with `FILE` privilege (OS file read/write via SQL)
- `secure_file_priv` not configured
- `bind-address = 0.0.0.0` (exposed to all interfaces)

**PostgreSQL audit** flags:
- Unexpected superuser accounts (non-`postgres`)
- Login roles with no password set
- `trust` auth entries in `pg_hba.conf` (passwordless access — critical)
- `md5` auth (deprecated — recommend upgrading to `scram-sha-256`)
- `listen_addresses = '*'` (all interfaces exposed)
- SSL disabled
- Tables with `PUBLIC` write grants (`INSERT`/`UPDATE`/`DELETE`)

---

### RECOMMENDED COMPETITION WORKFLOW
1. **As soon as competition begins** → `backup` all services
2. **After any remediation** → `backup` again to capture clean state
3. **After suspected compromise** → Run `audit`/`scan`, then `restore` from known-good
4. **Verify after every restore** → Use `verify` action to confirm hash integrity

---

### IMPORTANT NOTES
- Linux: `02_backup_pam.sh reinstall` is the nuclear option — use if PAM is backdoored
- Windows: After restoring SSH, always verify in a **new session** before closing current
- SMB1 should be disabled — `03_Backup-SMB.ps1 -Action audit` will flag if enabled
- MySQL: **Never run Full Restore** unless all dependent applications are stopped first
- PostgreSQL: Custom format (`.dump`) backups support selective table restore:
  `pg_restore -t tablename -d dbname backup.dump`
- Backups are stored with restricted permissions (root/Administrators only)
- Pre-restore snapshots are always saved before overwriting live files
- Database credential files **must** be `chmod 600` (Linux) or ACL-restricted (Windows)
