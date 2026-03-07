# SMB / Samba Security Scripts

A collection of bash scripts for hardening, monitoring, and recovering Samba (SMB) file sharing on Linux servers. Designed for defensive blue team operations where maintaining availability and integrity of file shares is critical.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `smb_harden.sh` | Harden smb.conf, disable SMB1, block guest access, audit users and shares, restart safely |
| `smb_threat_hunt.sh` | Detect guest access, unauthorized users, suspicious file drops, and service tampering |
| `smb_recover.sh` | Emergency recovery — restore smb.conf from backup, restart smbd, reset user passwords |
| `smb_audit_passwords.sh` | Audit Samba users and rotate passwords (single user or all users) |

---

## Requirements

- Linux with `bash`
- `systemd`
- Samba (`smbd`, `nmbd`, `testparm`, `pdbedit`, `smbpasswd`)
- Root / sudo access

Install Samba if not already present:
```bash
sudo apt install samba
```

Tested on Ubuntu 22.04 and 24.04.

---

## Quick Start

```bash
# Make scripts executable
chmod +x *.sh

# Harden Samba
sudo bash smb_harden.sh

# Rotate passwords for all Samba users
sudo bash smb_audit_passwords.sh rotateall 'NewStr0ngP@ss!'

# Run threat hunt
sudo bash smb_threat_hunt.sh

# Emergency recovery
sudo bash smb_recover.sh full
```

---

## Critical Samba Fact

**Samba maintains its own password database — separate from the Linux system password.**

Changing a user's password with `passwd` does **not** change their Samba password. You must manage Samba credentials separately with `smbpasswd`:

```bash
# Change Linux password
sudo passwd username -a

# Change Samba password (must be done separately!)
sudo smbpasswd username
```

This is the single most common mistake when securing Samba — rotating the Linux password and assuming Samba is also secured.

---

## What `smb_harden.sh` Does

1. Backs up `/etc/samba/smb.conf` to `/tmp/ncae_backups/smb/` with a timestamp
2. Applies the following hardening settings to the `[global]` section:

| Setting | Value | Reason |
|---------|-------|--------|
| `map to guest` | `Never` | Disables anonymous sessions |
| `restrict anonymous` | `2` | Blocks anonymous enumeration |
| `guest account` | `nobody` | Maps any guest to nobody |
| `server min protocol` | `SMB2` | Disables insecure SMB1 |
| `server signing` | `mandatory` | Prevents NTLM relay attacks |
| `load printers` | `no` | Reduces attack surface |
| `disable spoolss` | `yes` | Reduces attack surface |
| `log level` | `2` | Enables logging |

3. Checks for `guest ok = yes` on any share (anonymous access warning)
4. Audits Samba user database (`pdbedit -L`)
5. Audits share directory permissions
6. Tests config with `testparm` before restarting — auto-restores backup on failure

---

## What `smb_threat_hunt.sh` Checks

- **Guest access** — scans smb.conf for `guest ok = yes`, permissive `map to guest`, and weak `restrict anonymous` settings
- **Samba users** — lists all users, flags disabled accounts and accounts with no password required
- **Active connections** — lists current share connections via `smbstatus`
- **Share file activity** — finds files modified in the last 60 minutes across all share paths
- **Service status** — checks smbd is running and port 445 is listening; flags masked service
- **Protocol version** — flags if SMB1 is enabled (EternalBlue vulnerability)
- **Config file changes** — flags smb.conf or Samba files modified in the last 2 hours

Results are saved to `/var/log/ncae_smb_hunt.log`.

---

## What `smb_recover.sh` Does

```bash
sudo bash smb_recover.sh full                    # Full recovery
sudo bash smb_recover.sh restore-config          # Restore smb.conf from backup
sudo bash smb_recover.sh restart                 # Unmask + restart smbd
sudo bash smb_recover.sh reset-user alice Pass1! # Reset Samba password for alice
sudo bash smb_recover.sh status                  # Show port 445 and service status
```

---

## What `smb_audit_passwords.sh` Does

```bash
# Audit only (default)
sudo bash smb_audit_passwords.sh

# Rotate one user
sudo bash smb_audit_passwords.sh rotate alice 'NewP@ss!'

# Rotate ALL Samba users at once
sudo bash smb_audit_passwords.sh rotateall 'NewP@ss!'
```

---

## Services Protected

These scripts are designed to protect Samba on servers providing:

- File sharing (CIFS/SMB shares for Windows and Linux clients)
- Network file access for services that depend on a shared file store
- Any Linux server where SMB must remain available, authenticated, and tamper-free

---

## Common Vulnerabilities These Scripts Address

| Vulnerability | How These Scripts Help |
|---------------|----------------------|
| SMB1 / EternalBlue (MS17-010) | `smb_harden.sh` sets `server min protocol = SMB2` |
| Anonymous / guest access | `smb_harden.sh` disables guest; hunt detects re-enablement |
| NTLM relay attacks | `smb_harden.sh` sets `server signing = mandatory` |
| Default/unchanged credentials | `smb_audit_passwords.sh` facilitates bulk rotation |
| Malicious file drops on shares | `smb_threat_hunt.sh` finds recently modified share files |
| Service masking (prevents restart) | Hunt and recover scripts detect and fix masked smbd |
| Unauthorized Samba users | Hunt audits pdbedit and flags unexpected accounts |

---

## Safety Notes

- Always verify share access from a client after running `smb_harden.sh`: `smbclient //<ip>/sharename -U username`
- `testparm` is run before every restart — config is auto-restored from backup if the test fails
- Enabling `server signing = mandatory` can break very old SMB clients (Windows XP era). Remove this setting if you have legitimate legacy clients that need access.
- Samba password database is at `/var/lib/samba/private/` — do not delete it.

---

## References

- Samba Documentation — https://samba.org/samba/docs
- man smb.conf — https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html
- CVE-2017-7494 (SambaCry) — https://nvd.nist.gov/vuln/detail/CVE-2017-7494
- MS17-010 (EternalBlue) — https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
