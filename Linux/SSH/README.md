# SSH Security Scripts

A collection of bash scripts for hardening, monitoring, and recovering SSH on Linux servers. Designed for defensive blue team operations where maintaining service availability and integrity is critical.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `ssh_harden.sh` | Harden sshd_config, deploy an authorized public key, and remove unauthorized keys |
| `ssh_deploy_scoring_key.sh` | Deploy a specific public key to a list of users and audit for unauthorized keys |
| `ssh_scoring_users_list.txt` | User list — one username per line, read by the deploy and harden scripts |
| `ssh_threat_hunt.sh` | Detect unauthorized keys, suspicious logins, PAM tampering, and config changes |
| `ssh_recover.sh` | Emergency recovery — restore config from backup, restore a key, unmask and restart sshd |

---

## Requirements

- Linux with `bash`
- `systemd` (for `systemctl`)
- OpenSSH server (`sshd`)
- Root / sudo access

Tested on Ubuntu 22.04 and 24.04. Should work on any Debian-based system.

---

## Quick Start

```bash
# Clone or download the SSH folder to your server
# Make scripts executable
chmod +x *.sh

# 1. Edit ssh_scoring_users_list.txt — add usernames that need the authorized key
# 2. Edit SCORING_KEY in ssh_harden.sh with your authorized public key
# 3. Run the hardening script
sudo bash ssh_harden.sh

# Run the threat hunt
sudo bash ssh_threat_hunt.sh

# Emergency recovery
sudo bash ssh_recover.sh full
```

---

## Configuration

### Setting the Authorized Key

Before running `ssh_harden.sh` or `ssh_deploy_scoring_key.sh`, open the script and set `SCORING_KEY` to the public key you want to deploy:

```bash
# In ssh_harden.sh, find this line and replace with your key:
SCORING_KEY="ssh-rsa AAAA...your-key-here... key-label"
```

The scripts preserve any key containing the text `SCORING KEY DO NOT REMOVE` in `authorized_keys`. All other keys are treated as unauthorized and removed by `ssh_harden.sh`.

### Setting Users

Edit `ssh_scoring_users_list.txt` — one username per line:

```
root
alice
bob
```

`root` is always processed regardless of whether it is listed.

---

## What `ssh_harden.sh` Does

1. Backs up `/etc/ssh/sshd_config` to `/tmp/ncae_backups/ssh/` with a timestamp
2. Deploys the configured public key to `~/.ssh/authorized_keys` for all listed users
3. Removes all keys from `authorized_keys` that are **not** the configured key (the "remove bad keys" step)
4. Applies the following hardening settings to `sshd_config`:

| Setting | Value | Reason |
|---------|-------|--------|
| `PermitRootLogin` | `prohibit-password` | Key-only root access |
| `PasswordAuthentication` | `no` | Disables password brute force |
| `PubkeyAuthentication` | `yes` | Required for key-based auth |
| `PermitEmptyPasswords` | `no` | No blank passwords |
| `X11Forwarding` | `no` | Not needed |
| `LoginGraceTime` | `30` | Reduce from default 120s |
| `MaxAuthTries` | `3` | Limit per-connection attempts |
| `ClientAliveInterval` | `300` | Keepalive interval |
| `ClientAliveCountMax` | `2` | Drop after missed keepalives |

5. Tests config with `sshd -t` before restarting — auto-restores backup if config is invalid

---

## What `ssh_threat_hunt.sh` Checks

- **authorized_keys** — scans all user accounts for unauthorized keys; flags if configured key is missing
- **Login activity** — recent failed attempts, successful logins, currently logged in users
- **PAM configuration** — checks `/etc/pam.d/sshd` and `common-auth` for suspicious entries (e.g. `pam_permit.so`)
- **sshd_config** — checks port, `PubkeyAuthentication` state, service mask status
- **SSH processes** — unexpected processes or port forwards
- **Recently modified files** — flags `authorized_keys` or SSH config files changed in the last 2 hours

Results are printed to stdout and saved to `/var/log/ncae_ssh_hunt.log`.

---

## What `ssh_recover.sh` Does

```bash
sudo bash ssh_recover.sh full            # Full recovery
sudo bash ssh_recover.sh restore-config  # Restore sshd_config from backup
sudo bash ssh_recover.sh restore-key     # Re-add authorized key to root
sudo bash ssh_recover.sh restore-key alice  # Re-add key for specific user
sudo bash ssh_recover.sh restart         # Unmask + restart sshd
sudo bash ssh_recover.sh status          # Show port 22 and service status
```

---

## Services Protected

These scripts are designed to protect SSH on servers running services such as:

- Web servers (Apache2, Nginx)
- File servers (Samba/CIFS)
- Database servers (PostgreSQL, MySQL)
- DNS servers (BIND9)
- Backup services
- Any Linux server where SSH remote access must remain available and authenticated

---

## Safety Notes

- **Always test SSH connectivity** from another terminal before closing your current session after running `ssh_harden.sh`. If the config is broken and you close your session, you lose access.
- The script tests `sshd_config` with `sshd -t` before restarting and **automatically restores the backup** if the test fails.
- Backups are timestamped — multiple runs create multiple backups in `/tmp/ncae_backups/ssh/`.
- `ssh_harden.sh` removes all keys not matching the configured key. If you need additional keys, add them **after** running the harden script, or modify the removal logic.

---

## References

- OpenSSH Documentation — https://openssh.com/manual.html
- man sshd_config — https://man.openbsd.org/sshd_config
- RFC 4251 — SSH Protocol Architecture
- NIST SP 800-53 — Access Control Guidelines
