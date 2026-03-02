# Blue Team Backup & Restore — Windows
> Run all scripts as **Administrator** in PowerShell 5.1+. Windows Server 2016/2019/2022 or Windows 10/11.

---

## Quick Start

```powershell
# One-time setup — allow local scripts to run
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Full backup of all services
.\00_Master.ps1 -Action backup

# Interactive restore menu
.\00_Master.ps1 -Action restore

# Show backup inventory and sizes
.\00_Master.ps1 -Action status
```

**Backup location:** `C:\BlueteamBackups\<service>\<timestamp>\`
**Logs:** `C:\BlueteamBackups\Logs\`

---

## Script Reference

```
windows/
├── 00_Master.ps1             Orchestrator — runs all backups or restore menu
├── 01_Backup-Binaries.ps1    System32 critical binaries + tamper detection
├── 02_Backup-SSH.ps1         OpenSSH Server config, host keys, authorized_keys
├── 03_Backup-SMB.ps1         SMB shares, ACLs, server config + audit
├── 04_Backup-WebServer.ps1   IIS configuration via appcmd + WebAdministration
├── 05_Backup-WebContent.ps1  IIS web root files + webshell scanner
├── 06_Backup-MySQL.ps1       MySQL/MariaDB dumps, user grants + audit
└── 07_Backup-Postgres.ps1    PostgreSQL dumps, globals, config + audit
```

### Actions per script

| Script | Actions |
|---|---|
| `00_Master.ps1` | `backup` `restore` `status` |
| `01_Backup-Binaries.ps1` | `backup` `restore` `verify` |
| `02_Backup-SSH.ps1` | `backup` `restore` `audit` |
| `03_Backup-SMB.ps1` | `backup` `restore` `audit` |
| `04_Backup-WebServer.ps1` | `backup` `restore` `audit` |
| `05_Backup-WebContent.ps1` | `backup` `restore` `scan` |
| `06_Backup-MySQL.ps1` | `backup` `restore` `verify` `audit` |
| `07_Backup-Postgres.ps1` | `backup` `restore` `verify` `audit` |

---

## What Each Script Backs Up

**01 — Binaries**
Copies critical System32 binaries (`cmd.exe`, `powershell.exe`, `net.exe`, `sc.exe`,
`certutil.exe`, `sshd.exe`, etc.) preserving directory structure. Saves a JSON
SHA-256 manifest. `verify` compares live binaries against the manifest to detect
replacement or tampering.

**02 — SSH (OpenSSH Server)**
Backs up `%ProgramData%\ssh` (sshd_config, host keys, administrators_authorized_keys),
per-user `authorized_keys` in `C:\Users\*\.ssh\`, service start configuration, and
firewall rules. Restricts backup permissions to Administrators only (host keys are
sensitive). Runs a security audit after backup checking for dangerous settings,
suspicious Match blocks, and non-admin ACL entries on `administrators_authorized_keys`.
> ⚠️ Always verify SSH in a **new session** before closing the current one after a restore.

**03 — SMB**
Exports all share definitions, ACLs (`Get-SmbShareAccess`), SMB server configuration,
and NTFS ACL snapshots for share paths. Flags SMB1 (EternalBlue risk) and disabled
SMB signing. Restore recreates missing shares and re-applies server configuration.
> ⚠️ ACL restore is not fully automated — verify share permissions manually after restore.

**04 — Web Server (IIS)**
Uses `appcmd.exe add backup` (the native IIS backup method) plus direct config file
copy of `%SystemRoot%\System32\inetsrv\config`. Also exports site definitions, app
pools, virtual directories, and SSL bindings as JSON via the WebAdministration module.
Audit checks directory browsing, HTTP-only sites, LocalSystem app pools, and the
`X-Powered-By` header.

**05 — Web Content**
Detects IIS site physical paths automatically via `Get-WebSite`. Backs up using
`Robocopy /COPYALL` to preserve timestamps and metadata. After backup, scans for
ASP/ASPX webshell patterns (`eval()`, `ProcessStartInfo`, `net user /add`, etc.),
executables in the web root, PHP files (unusual on IIS — flag as suspicious), and
recently modified files. Integrity checks file hashes against the backup.

**06 — MySQL / MariaDB**
Produces three backup artefacts: a full `--all-databases` dump, per-database dumps
(for surgical single-DB restore), and a separate users/grants file. Uses .NET GZip
compression. Audit checks anonymous users, empty passwords, `root@%`, `FILE`
privilege abuse, and `bind-address` exposure.

**07 — PostgreSQL**
Produces: a globals dump (roles, tablespaces), a full cluster dump, and per-database
`pg_dump` files in custom format (`.dump`). Also backs up `postgresql.conf`,
`pg_hba.conf`, and `pg_ident.conf`. Audit checks superusers, passwordless login
roles, `trust` auth in pg_hba, SSL status, `listen_addresses`, and PUBLIC write grants.

---

## Database Credential Setup

### MySQL / MariaDB
Create `C:\ProgramData\blueteam\mysql_backup.cnf` before running `06_Backup-MySQL.ps1`:
```ini
[client]
user=root
password=yourpassword
```
Then restrict permissions:
```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\blueteam" -Force | Out-Null
icacls "C:\ProgramData\blueteam\mysql_backup.cnf" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
```

### PostgreSQL
Set `PGPASSWORD` in your session before running, or configure `pgpass.conf`:

```powershell
# Option 1: Session variable
$env:PGPASSWORD = "yourpassword"
.\07_Backup-Postgres.ps1 -Action backup
```

Or create `%APPDATA%\postgresql\pgpass.conf`:
```
localhost:5432:*:postgres:yourpassword
```
```powershell
New-Item -ItemType Directory -Path "$env:APPDATA\postgresql" -Force | Out-Null
icacls "$env:APPDATA\postgresql\pgpass.conf" /inheritance:r /grant "${env:USERNAME}:F"
```

---

## Security Notes

- All backup directories are ACL-restricted to Administrators and SYSTEM only at creation time.
- SHA-256 manifests (`sha256_manifest.json`) are written at backup time for tamper detection.
- Pre-restore archives are created before overwriting live files (`.zip` suffix with timestamp).
- SMB1 must be disabled — `03_Backup-SMB.ps1 -Action audit` will flag it if enabled.
- OpenSSH host keys are backed up with restricted ACLs — treat the backup directory as sensitive.

---

## Recommended Competition Workflow

1. **At competition start** → `.\00_Master.ps1 -Action backup`
2. **After any remediation** → Re-run backup to capture clean state
3. **On suspected compromise** → Run `-Action audit` or `-Action scan` on the affected service, then `restore`
4. **After every restore** → Run `-Action verify` to confirm hash integrity

---

## Notes on Specific Restore Risks

- **SSH restore:** Stops and restarts the `sshd` service. Test a new connection before closing the current session.
- **IIS restore:** Prefers `appcmd restore backup` (native IIS method); falls back to file copy if appcmd fails.
- **SMB restore:** Share paths must exist on disk — the script cannot recreate directories, only shares.
- **MySQL full restore:** Stop all applications that use the database first. Full restore is destructive.
- **PostgreSQL custom dumps:** Use `pg_restore -t tablename -d dbname backup.dump` for selective table restore.

---

## PowerShell Compatibility

All scripts are tested and compatible with **both PowerShell 5.1 and PowerShell 7.x** on Windows.

| Feature | PS 5.1 | PS 7.x |
|---|---|---|
| All backup/restore actions | ✅ | ✅ |
| GZip compression (.NET) | ✅ | ✅ |
| SMB / IIS / SSH modules | ✅ | ✅ (Windows only) |
| WMI (`Get-WmiObject`) | ✅ | ❌ removed — scripts use `Get-CimInstance` |
| Null coalescing `??` | ❌ | ✅ — scripts use compatible `if/else` instead |

**Minimum:** PowerShell 5.1 (default on Windows Server 2016+)
**Recommended:** PowerShell 7.x for improved error messages and performance

Install PS7: `winget install Microsoft.PowerShell` or download from [github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell/releases)

The `WebAdministration` module (IIS scripts) requires the IIS Management Tools feature:
```powershell
Install-WindowsFeature -Name Web-Mgmt-Tools
```
The `SmbShare` and `NetFirewall` modules are included in Windows Server by default.
