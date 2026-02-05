#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent privilege escalation
#
# Run as root: sudo ./remediation_demo.sh
#

export PATH="/usr/sbin:/sbin:$PATH"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
}

log_section() {
    echo ""
    echo -e "${BLUE}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│ ${BOLD}$1${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────┘${NC}"
}

log_bad() {
    echo -e "  ${RED}✗ VULNERABLE:${NC} $1"
}

log_good() {
    echo -e "  ${GREEN}✓ SECURE:${NC} $1"
}

log_info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

log_code() {
    echo -e "  ${YELLOW}$1${NC}"
}

#######################################
# Check if running as root
#######################################
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

#######################################
# Cleanup from previous runs
#######################################
cleanup() {
    pkill -u developer 2>/dev/null || true
    pkill -u backupuser 2>/dev/null || true
    userdel -r developer 2>/dev/null || true
    userdel -r backupuser 2>/dev/null || true
    groupdel backupusers 2>/dev/null || true
    rm -f /usr/local/bin/backup-shared.sh /usr/local/bin/backup-secure.sh
    rm -f /etc/cron.d/shared-backup /etc/cron.d/secure-backup
    rm -rf /var/backups/shared /var/backups/secure
    rm -f /var/backups/*.tgz
    rm -f /tmp/rootbash /tmp/pwned.txt
}

trap cleanup EXIT
cleanup

log_header "REMEDIATION DEMONSTRATION"
echo ""
echo "  This script shows the VULNERABLE configuration vs SECURE alternatives."
echo "  Each fix is demonstrated and tested against the tar wildcard attack."

#######################################
# Setup test user
#######################################
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd

#######################################
# FIX 1: Don't use wildcards
#######################################
log_section "FIX 1: Don't Use Wildcards — Use Explicit Paths"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    cd \"/var/backups/shared\""
log_code "    tar czf archive.tgz *"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    tar czf archive.tgz /var/backups/shared"
echo ""
log_info "Why it works: No wildcard expansion means filenames stay filenames."
log_info "The path '/var/backups/shared' cannot be manipulated by users."

# Demonstrate
mkdir -p /var/backups/shared
chmod 1777 /var/backups/shared

# Create attacker payload
su - developer -c 'touch "/var/backups/shared/--checkpoint=1"'
su - developer -c 'touch "/var/backups/shared/--checkpoint-action=exec=touch /tmp/pwned_fix1"'
su - developer -c 'echo "legitimate" > /var/backups/shared/data.txt'

echo ""
echo "  Testing SECURE version with attacker payload present..."

# Run secure version
tar czf /var/backups/test_fix1.tgz /var/backups/shared 2>/dev/null

if [[ -f /tmp/pwned_fix1 ]]; then
    log_bad "Payload executed! Fix failed."
else
    log_good "Payload did NOT execute. Attack blocked."
fi

rm -f /tmp/pwned_fix1 /var/backups/test_fix1.tgz
rm -rf /var/backups/shared

#######################################
# FIX 2: Use -- to separate options
#######################################
log_section "FIX 2: Use '--' to Separate Options from Filenames"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    tar czf archive.tgz *"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    tar czf archive.tgz -- *"
echo ""
log_info "Why it works: '--' tells tar 'everything after this is a filename, not an option'."
log_info "Even if a file is named '--checkpoint=1', it's treated as a filename."

# Demonstrate
mkdir -p /var/backups/shared
chmod 1777 /var/backups/shared

su - developer -c 'touch "/var/backups/shared/--checkpoint=1"'
su - developer -c 'touch "/var/backups/shared/--checkpoint-action=exec=touch /tmp/pwned_fix2"'
su - developer -c 'echo "legitimate" > /var/backups/shared/data.txt'

echo ""
echo "  Testing SECURE version with '--' separator..."

cd /var/backups/shared
tar czf /var/backups/test_fix2.tgz -- * 2>/dev/null
cd /

if [[ -f /tmp/pwned_fix2 ]]; then
    log_bad "Payload executed! Fix failed."
else
    log_good "Payload did NOT execute. Attack blocked."
fi

rm -f /tmp/pwned_fix2 /var/backups/test_fix2.tgz
rm -rf /var/backups/shared

#######################################
# FIX 3: Run as non-root user
#######################################
log_section "FIX 3: Run Backup as Non-Root User (Least Privilege)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    # Cron runs as root"
log_code "    */5 * * * * root /usr/local/bin/backup.sh"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    # Create dedicated backup user"
log_code "    useradd -r -s /usr/sbin/nologin backupuser"
log_code "    */5 * * * * backupuser /usr/local/bin/backup.sh"
echo ""
log_info "Why it works: Even if the attacker achieves code execution,"
log_info "it runs as 'backupuser', not root. No privilege escalation."

# Create backup user
useradd -r -s /usr/sbin/nologin backupuser

# Setup directory with proper ownership
mkdir -p /var/backups/shared
chmod 1777 /var/backups/shared

su - developer -c 'touch "/var/backups/shared/--checkpoint=1"'
su - developer -c 'touch "/var/backups/shared/--checkpoint-action=exec=sh -c \"cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash\""'
su - developer -c 'echo "legitimate" > /var/backups/shared/data.txt'

echo ""
echo "  Testing backup run as 'backupuser' instead of root..."

# Run as backupuser (still vulnerable to injection, but limited impact)
cd /var/backups/shared
su -s /bin/bash backupuser -c 'tar czf /tmp/test_fix3.tgz *' 2>/dev/null || true
cd /

if [[ -f /tmp/rootbash ]]; then
    OWNER=$(stat -c '%U' /tmp/rootbash 2>/dev/null || echo "none")
    PERMS=$(stat -c '%a' /tmp/rootbash 2>/dev/null || echo "none")
    if [[ "$OWNER" == "root" && "$PERMS" == "4755" ]]; then
        log_bad "SUID root shell created! (This shouldn't happen)"
    else
        log_good "File created but NOT SUID root. Owned by: $OWNER, perms: $PERMS"
        log_info "Attacker got code execution but NOT root privileges."
    fi
else
    log_good "No /tmp/rootbash created. Limited user cannot create SUID files."
fi

rm -f /tmp/rootbash /tmp/test_fix3.tgz
rm -rf /var/backups/shared

#######################################
# FIX 4: Restrict directory permissions
#######################################
log_section "FIX 4: Restrict Directory Permissions (Group-Based Access)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    chmod 1777 /var/backups/shared   # World-writable"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    groupadd backupusers"
log_code "    usermod -aG backupusers developer"
log_code "    chown root:backupusers /var/backups/shared"
log_code "    chmod 1770 /var/backups/shared   # Group-writable only"
echo ""
log_info "Why it works: Only authorized users in 'backupusers' group can write."
log_info "Combined with input validation, limits attack surface."

groupadd backupusers
usermod -aG backupusers developer

mkdir -p /var/backups/shared
chown root:backupusers /var/backups/shared
chmod 1770 /var/backups/shared

echo ""
echo "  Directory permissions:"
ls -ld /var/backups/shared

log_info "Only members of 'backupusers' can write to the directory."
log_info "This reduces the attack surface but doesn't eliminate the wildcard issue."
log_info "Best combined with Fix 1 or Fix 2."

rm -rf /var/backups/shared
groupdel backupusers 2>/dev/null || true

#######################################
# FIX 5: Use find with -print0
#######################################
log_section "FIX 5: Use find with -print0 (Safe Filename Handling)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    tar czf archive.tgz *"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    find /var/backups/shared -maxdepth 1 -type f -print0 | \\"
log_code "        tar czf archive.tgz --null -T -"
echo ""
log_info "Why it works: find outputs null-delimited paths, tar reads them as paths."
log_info "No shell expansion, no argument injection."

mkdir -p /var/backups/shared
chmod 1777 /var/backups/shared

su - developer -c 'touch "/var/backups/shared/--checkpoint=1"'
su - developer -c 'touch "/var/backups/shared/--checkpoint-action=exec=touch /tmp/pwned_fix5"'
su - developer -c 'echo "legitimate" > /var/backups/shared/data.txt'

echo ""
echo "  Testing find + tar --null method..."

find /var/backups/shared -maxdepth 1 -type f -print0 | tar czf /var/backups/test_fix5.tgz --null -T - 2>/dev/null

if [[ -f /tmp/pwned_fix5 ]]; then
    log_bad "Payload executed! Fix failed."
else
    log_good "Payload did NOT execute. Attack blocked."
fi

rm -f /tmp/pwned_fix5 /var/backups/test_fix5.tgz
rm -rf /var/backups/shared

#######################################
# COMPLETE SECURE IMPLEMENTATION
#######################################
log_section "COMPLETE SECURE IMPLEMENTATION"

echo ""
echo "  Here's what the admin SHOULD have deployed:"
echo ""

cat << 'SECURE_SCRIPT'
  ┌────────────────────────────────────────────────────────────┐
  │ /usr/local/bin/backup-shared-SECURE.sh                     │
  ├────────────────────────────────────────────────────────────┤
  │ #!/bin/bash                                                │
  │ # Secure backup script - IT Operations                     │
  │ # Fixes: wildcard injection, runs as non-root              │
  │                                                            │
  │ BACKUP_DIR="/var/backups/shared"                           │
  │ ARCHIVE="/var/backups/shared_$(date +%Y%m%d_%H%M%S).tgz"   │
  │                                                            │
  │ # FIX 1: Use explicit path, not wildcard                   │
  │ tar czf "$ARCHIVE" "$BACKUP_DIR"                           │
  │                                                            │
  │ # OR FIX 2: Use -- separator if wildcard needed            │
  │ # cd "$BACKUP_DIR" && tar czf "$ARCHIVE" -- *              │
  │                                                            │
  │ # OR FIX 5: Use find with null-delimiter                   │
  │ # find "$BACKUP_DIR" -type f -print0 | \                   │
  │ #     tar czf "$ARCHIVE" --null -T -                       │
  └────────────────────────────────────────────────────────────┘
SECURE_SCRIPT

echo ""
cat << 'SECURE_CRON'
  ┌────────────────────────────────────────────────────────────┐
  │ /etc/cron.d/shared-backup-SECURE                           │
  ├────────────────────────────────────────────────────────────┤
  │ # FIX 3: Run as dedicated non-root user                    │
  │ */5 * * * * backupuser /usr/local/bin/backup-shared.sh     │
  └────────────────────────────────────────────────────────────┘
SECURE_CRON

echo ""
cat << 'SECURE_PERMS'
  ┌────────────────────────────────────────────────────────────┐
  │ Directory Setup Commands                                   │
  ├────────────────────────────────────────────────────────────┤
  │ # FIX 3: Create non-root backup user                       │
  │ useradd -r -s /usr/sbin/nologin backupuser                 │
  │                                                            │
  │ # FIX 4: Group-based access control                        │
  │ groupadd backupusers                                       │
  │ usermod -aG backupusers developer                          │
  │ chown root:backupusers /var/backups/shared                 │
  │ chmod 1770 /var/backups/shared                             │
  └────────────────────────────────────────────────────────────┘
SECURE_PERMS

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. No wildcards            │ ✓ Yes           │ Easy            │"
echo "  │ 2. Use '--' separator      │ ✓ Yes           │ Easy            │"
echo "  │ 3. Non-root user           │ Limits impact   │ Medium          │"
echo "  │ 4. Restrict permissions    │ Limits surface  │ Medium          │"
echo "  │ 5. find + --null           │ ✓ Yes           │ Medium          │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo "  ${GREEN}${BOLD}RECOMMENDED:${NC} Combine Fix 1 (no wildcards) + Fix 3 (non-root user)"
echo ""
echo "  Defense in depth: Even if one control fails, the other limits damage."
echo ""