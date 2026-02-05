#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent PATH injection
#
# Run as root: sudo ./remediation_demo.sh
#

export PATH="/usr/sbin:/sbin:/usr/bin:/bin"

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
    groupdel staff 2>/dev/null || true
    rm -rf /opt/admin 2>/dev/null || true
    rm -f /usr/local/bin/backup-util /usr/bin/backup-util 2>/dev/null || true
    rm -f /tmp/pwned* 2>/dev/null || true
    chmod 755 /usr/local/bin 2>/dev/null || true
    chown root:root /usr/local/bin 2>/dev/null || true
}

trap cleanup EXIT
cleanup

log_header "REMEDIATION DEMONSTRATION"
echo ""
echo "  This script shows the VULNERABLE configuration vs SECURE alternatives."

# Setup
groupadd staff
useradd -m -s /bin/bash -G staff developer
echo "developer:developer123" | chpasswd

#######################################
# FIX 1: Use absolute paths in scripts
#######################################
log_section "FIX 1: Use Absolute Paths in Scripts"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    # Script uses relative command"
log_code "    backup-util --full /var/data"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    # Script uses absolute path"
log_code "    /usr/bin/backup-util --full /var/data"
echo ""
log_info "Why it works: Full path ignores PATH environment variable."
log_info "Command cannot be hijacked regardless of PATH configuration."

#######################################
# FIX 2: Set safe PATH in script
#######################################
log_section "FIX 2: Set Safe PATH at Script Start"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    #!/bin/bash"
log_code "    # Uses inherited PATH (could include writable dirs)"
log_code "    backup-util --full /var/data"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    #!/bin/bash"
log_code "    # Override PATH at script start"
log_code "    export PATH=/usr/bin:/bin"
log_code "    backup-util --full /var/data"
echo ""
log_info "Why it works: Script controls its own PATH, not cron."

#######################################
# FIX 3: Safe cron PATH
#######################################
log_section "FIX 3: Configure Safe PATH in Cron"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    # Cron includes writable directory first"
log_code "    PATH=/usr/local/bin:/usr/bin:/bin"
log_code "    */5 * * * * root /opt/admin/backup.sh"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    # Cron uses only root-controlled directories"
log_code "    PATH=/usr/bin:/bin"
log_code "    */5 * * * * root /opt/admin/backup.sh"
echo ""
log_info "Why it works: PATH only includes root-owned directories."

#######################################
# FIX 4: Protect /usr/local/bin
#######################################
log_section "FIX 4: Protect /usr/local/bin"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    chown root:staff /usr/local/bin"
log_code "    chmod 775 /usr/local/bin"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    chown root:root /usr/local/bin"
log_code "    chmod 755 /usr/local/bin"
echo ""
log_info "Why it works: Only root can write to PATH directories."

# Demonstrate
chown root:staff /usr/local/bin
chmod 775 /usr/local/bin

echo ""
echo "  Testing with VULNERABLE permissions..."
INJECT=$(su - developer -c 'touch /usr/local/bin/test_vuln' 2>&1 && echo "success" || echo "failed")
if [[ "$INJECT" == "success" ]]; then
    log_bad "Developer can create files in /usr/local/bin"
    rm -f /usr/local/bin/test_vuln
fi

echo ""
echo "  Testing with SECURE permissions..."
chown root:root /usr/local/bin
chmod 755 /usr/local/bin

INJECT2=$(su - developer -c 'touch /usr/local/bin/test_sec' 2>&1 || echo "denied")
if echo "$INJECT2" | grep -qi "denied\|permission"; then
    log_good "Developer cannot write to /usr/local/bin"
else
    log_bad "Developer could still write!"
fi

#######################################
# FIX 5: Use env -i
#######################################
log_section "FIX 5: Use env -i to Clear Environment"

echo ""
echo -e "  ${GREEN}SECURE CRON ENTRY:${NC}"
log_code "    # Clear all environment, set only needed variables"
log_code "    */5 * * * * root /usr/bin/env -i PATH=/usr/bin:/bin /opt/admin/backup.sh"
echo ""
log_info "Why it works: Completely controls the execution environment."
log_info "No inherited environment variables that could be manipulated."

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Absolute paths          │ ✓ Yes           │ Easy            │"
echo "  │ 2. Script sets PATH        │ ✓ Yes           │ Easy            │"
echo "  │ 3. Safe cron PATH          │ ✓ Yes           │ Easy            │"
echo "  │ 4. Protect /usr/local/bin  │ ✓ Yes           │ Easy            │"
echo "  │ 5. Use env -i              │ ✓ Yes           │ Easy            │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Fix 1 (absolute paths) + Fix 4 (protect dirs)"
echo ""
echo "  Key principle: Never trust PATH for privileged script execution."
echo "  Always use absolute paths or explicitly set a safe PATH."
echo ""
