# Shell / SMB Node — Hardening Scripts

Rocky Linux 9 | SSH + Samba hardening for NCAE Cyber Games.

## Scripts

| Script | Description |
|--------|-------------|
| `smb_iptables.sh` | Applies iptables INPUT/OUTPUT ruleset for SSH and SMB. Disables firewalld. |
| `ssh_harden.sh` | Hardens sshd_config. Backs up original before changes. Validates before restart. |
| `scoring_ssh_setup.sh` | Creates scoring user group with restricted shell and centralized pubkey file. |
| `remote_ssh_setup.sh` | Creates team users with SSH key auth and group-based sudo access. |
| `add_scoring_pubkeys.sh` | Injects scoring public key into a list of users from a file. |
| `remove_bad_ssh_keys.sh` | Audits all user authorized_keys and removes keys not on the whitelist. |
| `smb_setup.sh` | Installs Samba, writes hardened smb.conf, applies SELinux context. |
| `smb_add_users.sh` | Creates system and Samba users from a `username:password` list file. |
| `backup.sh` | Archives SSH/SMB configs and share data, transfers to backup VM over SCP. |

## Usage Order

1. `backup.sh` — snapshot current state first
2. `smb_iptables.sh` — firewall before anything opens
3. `ssh_harden.sh` — harden daemon config
4. `remote_ssh_setup.sh` — create team users
5. `scoring_ssh_setup.sh` — set up scoring access
6. `add_scoring_pubkeys.sh <userlist.txt>` — inject keys
7. `remove_bad_ssh_keys.sh` — clean unauthorized keys
8. `smb_setup.sh` — configure Samba
9. `smb_add_users.sh <userlist.txt>` — create SMB users
10. `backup.sh` — post-hardening backup

## Requirements

- Rocky Linux 9
- Run all scripts as root
- Fill in all `[PLACEHOLDER]` values before running
- `userlist.txt` format: `username:password` (one per line)

## Placeholders

All scripts use clearly marked `[PLACEHOLDER]` variables at the top of each file. Edit these before running:

- `[TEAM_NUMBER]` — your assigned team number
- `[JUMP_HOST_IP]` — Blue Team SSH jump host IP
- `[SMB_SOURCE_SUBNET]` — internal subnet allowed to reach SMB ports
- `[COMP_DNS_IP]` — competition DNS server IP
- `[BACKUP_VM_IP]` / `[BACKUP_VM_USER]` / `[BACKUP_VM_DEST_PATH]` — backup VM details
- `[INSERT_SCORING_PUBLIC_KEY]` — provided at competition start
