# Blue Team Backup & Restore Scripts
## Quick Reference

### LINUX SCRIPTS  (run as root / sudo)
```
linux/
├── 00_master.sh              # Orchestrator — run all backups or restore menu
├── 01_backup_binaries.sh     # Critical system binaries + hash verification
├── 02_backup_pam.sh          # PAM configs, libraries, reinstall option
├── 03_backup_sshd.sh         # sshd_config, host keys, authorized_keys + audit
├── 04_backup_smb.sh          # Samba config, TDB databases, user export
├── 05_backup_webserver.sh    # Apache/Nginx/Lighttpd config (auto-detected)
└── 06_backup_webcontent.sh   # Web root files + webshell scanner
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
sudo ./linux/01_backup_binaries.sh  {backup|restore|verify}
sudo ./linux/02_backup_pam.sh       {backup|restore|reinstall|verify}
sudo ./linux/03_backup_sshd.sh      {backup|restore|audit}
sudo ./linux/04_backup_smb.sh       {backup|restore|verify}
sudo ./linux/05_backup_webserver.sh {backup|restore|audit}
sudo ./linux/06_backup_webcontent.sh{backup|restore|scan}
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
└── 05_Backup-WebContent.ps1  # IIS web roots + webshell scanner
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
.\windows\01_Backup-Binaries.ps1  -Action {backup|restore|verify}
.\windows\02_Backup-SSH.ps1       -Action {backup|restore|audit}
.\windows\03_Backup-SMB.ps1       -Action {backup|restore|audit}
.\windows\04_Backup-WebServer.ps1 -Action {backup|restore|audit}
.\windows\05_Backup-WebContent.ps1-Action {backup|restore|scan}
```
**Backup location:** `C:\BlueteamBackups\<service>\<timestamp>\`
**Logs:** `C:\BlueteamBackups\Logs\`

---

### RECOMMENDED COMPETITION WORKFLOW
1. **As soon as competition begins** → `backup` all services
2. **After any remediation** → `backup` again to capture clean state
3. **After suspected compromise** → Run `audit`/`scan`, then `restore` from known-good
4. **Verify after every restore** → Use `verify` action to confirm hash integrity

### IMPORTANT NOTES
- Linux: `02_backup_pam.sh reinstall` is the nuclear option — use if PAM is backdoored
- Windows: After restoring SSH, always verify in a new session before closing current
- SMB1 should be disabled — `03_Backup-SMB.sh audit` will flag if enabled
- Backups are stored with restricted permissions (root/Administrators only)
- Pre-restore snapshots are always created before overwriting live files
