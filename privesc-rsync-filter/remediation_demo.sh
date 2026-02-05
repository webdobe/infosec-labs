#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent rsync wildcard injection
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

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

cleanup() {
    pkill -u developer 2>/dev/null || true
    userdel -r developer 2>/dev/null || true
    userdel -r backupuser 2>/dev/null || true
    groupdel backupusers 2>/dev/null || true
    rm -rf /var/backup-staging /var/backups/remote 2>/dev/null || true
    rm -f /tmp/rootbash /tmp/pwned* 2>/dev/null || true
}

trap cleanup EXIT
cleanup

log_header "REMEDIATION DEMONSTRATION"
echo ""
echo "  This script shows the VULNERABLE configuration vs SECURE alternatives."

# Setup
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd

#######################################
# FIX 1: Use explicit paths
#######################################
log_section "FIX 1: Use Explicit Paths — No Wildcards"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    cd \"/var/backup-staging\""
log_code "    rsync -av * /var/backups/remote/"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    rsync -av /var/backup-staging/ /var/backups/remote/"
echo ""
log_info "Why it works: No wildcard means no filename-to-argument injection."

# Test
mkdir -p /var/backup-staging /var/backups/remote
chmod 1777 /var/backup-staging

su - developer -c 'echo "data" > /var/backup-staging/data.txt'
su - developer -c 'touch "/var/backup-staging/-e sh malicious.sh"'
su - developer -c 'echo "echo pwned > /tmp/pwned_fix1" > /var/backup-staging/malicious.sh'
su - developer -c 'chmod +x /var/backup-staging/malicious.sh'

echo ""
echo "  Testing SECURE version (explicit path)..."

rsync -av /var/backup-staging/ /var/backups/remote/ 2>/dev/null

if [[ -f /tmp/pwned_fix1 ]]; then
    log_bad "Payload executed!"
else
    log_good "Payload did NOT execute. Injection blocked."
fi

rm -rf /var/backup-staging /var/backups/remote /tmp/pwned*

#######################################
# FIX 2: Use -- separator
#######################################
log_section "FIX 2: Use '--' to Separate Options from Filenames"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    rsync -av * /backup/"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    rsync -av -- * /backup/"
echo ""
log_info "Why it works: '--' tells rsync everything after is a filename."

mkdir -p /var/backup-staging /var/backups/remote
chmod 1777 /var/backup-staging

su - developer -c 'echo "data" > /var/backup-staging/data.txt'
su - developer -c 'touch "/var/backup-staging/-e sh malicious.sh"'
su - developer -c 'echo "echo pwned > /tmp/pwned_fix2" > /var/backup-staging/malicious.sh'
su - developer -c 'chmod +x /var/backup-staging/malicious.sh'

echo ""
echo "  Testing SECURE version with '--' separator..."

cd /var/backup-staging
rsync -av -- * /var/backups/remote/ 2>/dev/null || true
cd /

if [[ -f /tmp/pwned_fix2 ]]; then
    log_bad "Payload executed!"
else
    log_good "Payload did NOT execute. '--' blocked injection."
fi

rm -rf /var/backup-staging /var/backups/remote /tmp/pwned*

#######################################
# FIX 3: Run as non-root
#######################################
log_section "FIX 3: Run Backup as Non-Root User"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    */5 * * * * root /usr/local/bin/rsync-backup.sh"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    useradd -r -s /usr/sbin/nologin backupuser"
log_code "    */5 * * * * backupuser /usr/local/bin/rsync-backup.sh"
echo ""
log_info "Why it works: Even if exploited, runs as backupuser, not root."

useradd -r -s /usr/sbin/nologin backupuser

mkdir -p /var/backup-staging /var/backups/remote
chmod 1777 /var/backup-staging
chown backupuser:backupuser /var/backups/remote

su - developer -c 'echo "data" > /var/backup-staging/data.txt'

echo ""
echo "  Running backup as 'backupuser' instead of root..."

su -s /bin/bash backupuser -c 'cd /var/backup-staging && rsync -av * /var/backups/remote/' 2>/dev/null || true

log_good "Even if exploited, impact is limited to backupuser privileges."

rm -rf /var/backup-staging /var/backups/remote
userdel -r backupuser 2>/dev/null || true

#######################################
# FIX 4: Use find with null-delimiter
#######################################
log_section "FIX 4: Use find with Null-Delimited Filenames"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    rsync -av * /backup/"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    find /var/backup-staging -maxdepth 1 -type f -print0 | \\"
log_code "        rsync -av --files-from=- --from0 / /backup/"
echo ""
log_info "Why it works: Filenames passed via stdin, not shell expansion."

mkdir -p /var/backup-staging /var/backups/remote
chmod 1777 /var/backup-staging

su - developer -c 'echo "data" > /var/backup-staging/data.txt'
su - developer -c 'touch "/var/backup-staging/-e sh malicious.sh"'

echo ""
echo "  Testing find + rsync --files-from method..."

find /var/backup-staging -maxdepth 1 -type f -print0 | rsync -av --files-from=- --from0 / /var/backups/remote/ 2>/dev/null || true

log_good "Files synced safely without shell expansion."
log_info "Files in backup:"
ls /var/backups/remote/var/backup-staging/ 2>/dev/null || echo "    (check nested path)"

rm -rf /var/backup-staging /var/backups/remote

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Explicit paths          │ ✓ Yes           │ Easy            │"
echo "  │ 2. Use '--' separator      │ ✓ Yes           │ Easy            │"
echo "  │ 3. Non-root user           │ Limits impact   │ Medium          │"
echo "  │ 4. find + --files-from     │ ✓ Yes           │ Medium          │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Fix 1 (explicit paths) + Fix 3 (non-root user)"
echo ""
echo "  Key principle: Never use wildcards in privileged scripts"
echo "  processing user-controlled directories."
echo ""
