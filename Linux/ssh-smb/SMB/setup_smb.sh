#!/bin/bash
# NCAE - CosmicGrace
# Author - Claude (Anthropic) / CosmicGrace
# =============================================================================
# setup_smb.sh — Samba/SMB Service Configuration and Hardening
# =============================================================================
# PURPOSE : Installs Samba, writes a hardened smb.conf, creates the share
#           directory, applies SELinux labels, and opens the firewall.
#
# DOES NOT: Create users or pre-populate share files.
#           Run create_smb_users.sh and create_smb_files.sh separately.
#
# USAGE   : sudo ./setup_smb.sh [users_file]
#           Default users file: users.txt
# =============================================================================

set -uo pipefail

USERS_FILE="${1:-users.txt}"
SHARE_NAME="compshare"                  # Name of the SMB share (\\server\compshare)
SHARE_PATH="/srv/samba/$SHARE_NAME"     # Filesystem path that gets shared
SMB_GROUP="smbgroup"                    # Linux group for share access control
BACKUP_DIR="/root/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }
[[ ! -f "$USERS_FILE" ]] && { error "Users file '$USERS_FILE' not found."; exit 1; }

mkdir -p "$BACKUP_DIR"

# =============================================================================
# DETECT SERVICE NAME: smbd vs smb
# =============================================================================
# On RHEL/Rocky the primary file-sharing daemon unit is "smbd".
# Some setups use a wrapper unit named "smb".
# NOTE: The FIREWALL service name is ALWAYS "samba" (not "smbd" or "smb").
#       Using --add-service=smbd or --add-service=smb in firewall-cmd
#       will FAIL with INVALID_SERVICE, leaving port 445 closed.
# =============================================================================
if systemctl list-unit-files smbd.service &>/dev/null 2>&1 | grep -q smbd; then
    SMB_SERVICE="smbd"      # Standard package name on Rocky/RHEL
    NMB_SERVICE="nmbd"      # NetBIOS name daemon (companion to smbd)
else
    SMB_SERVICE="smb"       # Alternate wrapper unit name
    NMB_SERVICE="nmb"
fi
info "Detected Samba daemon units: $SMB_SERVICE / $NMB_SERVICE"

# ── DEPENDENCIES ─────────────────────────────────────────────────────────────
info "Checking/installing dependencies..."
for pkg in samba samba-client samba-common policycoreutils-python-utils; do
    if ! rpm -q "$pkg" &>/dev/null; then
        info "Installing $pkg..."
        dnf install -y "$pkg"
    else
        info "$pkg already installed."
    fi
done
# samba             = the Samba server itself (smbd, nmbd)
# samba-client      = provides smbclient for testing
# samba-common      = shared config files and utilities (testparm, smbpasswd, pdbedit)
# policycoreutils-python-utils = provides semanage (for SELinux context management)

# ── BACKUP ───────────────────────────────────────────────────────────────────
info "Backing up existing smb.conf..."
[[ -f /etc/samba/smb.conf ]] && cp /etc/samba/smb.conf "$BACKUP_DIR/smb.conf.$TIMESTAMP"

# ── GROUP AND SHARE DIRECTORY ─────────────────────────────────────────────────
info "Creating SMB group ($SMB_GROUP) and share directory..."
groupadd "$SMB_GROUP" 2>/dev/null || info "Group '$SMB_GROUP' already exists."
mkdir -p "$SHARE_PATH"
chown -R root:"$SMB_GROUP" "$SHARE_PATH"   # root owns it, smbgroup has group access
chmod -R 0770 "$SHARE_PATH"
# 0770 = owner (root) rwx | group (smbgroup) rwx | other --- (no access)

# ── BUILD valid users LIST FROM users.txt ─────────────────────────────────────
# "valid users" in smb.conf is a whitelist for each share:
# Only users listed here can connect to the share at all.
info "Building valid users list from $USERS_FILE..."
VALID_USERS=""
while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"
    VALID_USERS="$VALID_USERS $user"
done < "$USERS_FILE"

[[ -z "$VALID_USERS" ]] && { error "No users found in $USERS_FILE. Aborting."; exit 1; }
VALID_USERS_TRIMMED="${VALID_USERS# }"
info "valid users will be: $VALID_USERS_TRIMMED"

# ── WRITE HARDENED smb.conf ───────────────────────────────────────────────────
info "Writing hardened smb.conf..."
chattr -i /etc/samba/smb.conf 2>/dev/null || true   # Remove immutable flag if set

cat > /etc/samba/smb.conf << SMB_EOF
# =============================================================================
# smb.conf — Hardened for NCAE Cyber Games Competition
# =============================================================================
# Structure: [global] section applies to the whole server.
#            [sharename] sections define individual shares.
# Test config: testparm         (basic check)
#              testparm -v      (verbose, shows all settings including defaults)
# =============================================================================

[global]
# ── IDENTITY ──────────────────────────────────────────────────────────────────
   workgroup = WORKGROUP
   # Windows workgroup name. Must match what clients expect.
   # In domain environments this would be the domain name.

   server string = Competition Server
   # Text shown when browsing the server. Cosmetic only.

   netbios name = ROCKYVM
   # NetBIOS hostname — max 15 chars, shown in Windows network discovery.

# ── SECURITY MODEL ────────────────────────────────────────────────────────────
   security = user
   # user  = each connection authenticates with username + password (correct)
   # share = authentication at share level — DEPRECATED and insecure

   map to guest = never
   # never      = failed logins are always rejected (never silently mapped to guest)
   # bad user   = unknown usernames mapped to guest account (dangerous!)
   # bad password = wrong password mapped to guest (extremely dangerous!)

   restrict anonymous = 2
   # 2 = completely deny null/anonymous sessions (strongest)
   # 1 = deny anonymous enumeration of shares
   # 0 = allow anonymous sessions (default, insecure)

# ── PROTOCOL VERSION ──────────────────────────────────────────────────────────
   server min protocol = SMB2
   # SMB1 is exploited by EternalBlue (CVE-2017-0144, used in WannaCry).
   # SMB2 = minimum acceptable (Windows Vista / Server 2008+)
   # SMB2 is REQUIRED — never allow SMB1 in competition.

   server max protocol = SMB3
   # SMB3 supports encryption and is the current standard.
   # Allowing up to SMB3 = maximum client compatibility.

# ── AUTHENTICATION HARDENING ──────────────────────────────────────────────────
   ntlm auth = ntlmv2-only
   # ntlmv2-only = only accept NTLMv2 hashes (more secure)
   # yes         = accept NTLMv1 and v2 (NTLMv1 is relay-attack vulnerable)
   # no          = disable NTLM entirely (use only with Kerberos)

# ── PRINTING — DISABLED ENTIRELY ─────────────────────────────────────────────
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes
   # Printing services are not needed and introduce attack surface.
   # Samba print spooler bugs have been exploited in the past.

# ── LOGGING ───────────────────────────────────────────────────────────────────
   log file = /var/log/samba/log.%m
   # %m = client machine name. Creates one log file per client.
   # e.g. /var/log/samba/log.192.168.1.50

   log level = 2
   # 0 = errors only | 1 = warnings | 2 = notices (good for competition)
   # 3+ = debug (very noisy, only for troubleshooting)

   max log size = 1000
   # Max log file size in KB before rotation. 1000 = ~1MB per client.

[$SHARE_NAME]
# =============================================================================
# SHARE DEFINITION
# =============================================================================
   comment = Competition Share
   # Description shown when browsing. Cosmetic.

   path = $SHARE_PATH
   # Absolute filesystem path being shared.
   # This directory must exist before smbd starts.

   valid users = $VALID_USERS_TRIMMED
   # WHITELIST: Only these users can access this share.
   # Users not listed get NT_STATUS_ACCESS_DENIED even with correct credentials.
   # Use @groupname to allow all members of a group: valid users = @smbgroup

   read only = no
   # no  = users can read AND write (required for SMB Write scoring task)
   # yes = read-only (files can be downloaded but not uploaded)

   writable = yes
   # yes = same as "read only = no" — explicit for clarity

   browseable = yes
   # yes = share appears in \\server\ listing (graders can find it)
   # no  = share is hidden (must know exact name to connect)
   # Keep yes in competition so scoring checks can discover the share.

   create mask = 0664
   # Permissions applied to NEW FILES created in this share.
   # 0664 = owner rw | group rw | other r

   directory mask = 0775
   # Permissions applied to NEW DIRECTORIES created in this share.
   # 0775 = owner rwx | group rwx | other rx

   force group = $SMB_GROUP
   # All files/dirs created here are owned by this group regardless of creator.
   # Ensures all valid users (even different ones) can access each other's files.

SMB_EOF

# ── VALIDATE CONFIG ───────────────────────────────────────────────────────────
info "Testing smb.conf with testparm..."
if ! testparm -s /etc/samba/smb.conf &>/dev/null; then
    error "smb.conf test FAILED. Run 'testparm' manually to see the errors."
    exit 1
fi
info "Config test passed."

# ── SELINUX ───────────────────────────────────────────────────────────────────
# SELinux is mandatory access control built into the kernel.
# Even with correct file permissions, Samba CANNOT access a directory unless
# it has the "samba_share_t" SELinux type label.
# Without this step: authenticated users get NT_STATUS_ACCESS_DENIED — confusing!
info "Applying SELinux context (samba_share_t) to share directory..."

# semanage fcontext: adds a RULE to the SELinux policy
# -a = add a new rule | -t = type | the regex (/.*)? = dir AND everything inside
semanage fcontext -a -t samba_share_t "$SHARE_PATH(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t samba_share_t "$SHARE_PATH(/.*)?"
    # If -a fails (rule already exists), -m modifies the existing rule

# restorecon: APPLIES the policy rules to actual files on disk
# -R = recursive | -v = verbose (shows what changed)
restorecon -Rv "$SHARE_PATH"

# samba_export_all_rw: SELinux boolean allowing Samba to read/write samba_share_t dirs
# -P = make persistent (survives reboot)
setsebool -P samba_export_all_rw on

info "Verifying SELinux context on share:"
ls -Z "$SHARE_PATH"   # Should show samba_share_t in the context column

# ── FIREWALL ──────────────────────────────────────────────────────────────────
# IMPORTANT: firewalld service names ≠ systemd unit names.
#   systemd unit  = "smbd"   (the Samba daemon process)
#   firewalld service = "samba"  (the firewall rule definition)
# Using --add-service=smbd would FAIL with "INVALID_SERVICE" and port 445
# would remain CLOSED — all SMB connections refused!
# The "samba" service opens: TCP 445 (SMB direct), TCP 139 (NetBIOS session),
#                            UDP 137 (NetBIOS name), UDP 138 (NetBIOS datagram)
info "Configuring firewall (using service name 'samba', NOT 'smbd')..."
systemctl is-active firewalld &>/dev/null || systemctl start firewalld
firewall-cmd --permanent --add-service=samba   # CORRECT name for firewalld
firewall-cmd --reload

# ── START / RESTART SERVICES ──────────────────────────────────────────────────
info "Enabling and starting Samba services..."
systemctl enable --now "$SMB_SERVICE" "$NMB_SERVICE"
systemctl restart "$SMB_SERVICE" "$NMB_SERVICE"

# ── LOCK CONFIG ───────────────────────────────────────────────────────────────
info "Locking smb.conf with chattr +i..."
chattr +i /etc/samba/smb.conf

# ── FINAL STATUS ──────────────────────────────────────────────────────────────
echo ""
info "SMB setup complete. Backup: $BACKUP_DIR/smb.conf.$TIMESTAMP"
warn "NEXT STEPS:"
warn "  1. Run create_smb_users.sh to add Samba accounts"
warn "  2. Run create_smb_files.sh to pre-populate share files"
warn "To edit smb.conf later: chattr -i /etc/samba/smb.conf"
echo ""
systemctl status "$SMB_SERVICE" "$NMB_SERVICE" --no-pager -l
