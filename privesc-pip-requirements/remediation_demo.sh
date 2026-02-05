#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent pip requirements injection
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
    userdel -r appuser 2>/dev/null || true
    rm -rf /srv/webapp 2>/dev/null || true
    rm -f /tmp/rootbash /tmp/pwned* 2>/dev/null || true
    pip3 uninstall -y evil-package 2>/dev/null || true
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
# FIX 1: Run pip as non-root user
#######################################
log_section "FIX 1: Run pip as Non-Root User"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    */5 * * * * root pip3 install -r requirements.txt"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    useradd -r -s /usr/sbin/nologin appuser"
log_code "    python3 -m venv /srv/webapp/venv"
log_code "    */5 * * * * appuser /srv/webapp/venv/bin/pip install -r requirements.txt"
echo ""
log_info "Why it works: Even if setup.py is malicious, it runs as appuser."
log_info "No privilege escalation possible — same user, same privileges."

# Demonstrate
useradd -r -s /usr/sbin/nologin appuser
mkdir -p /srv/webapp
chown developer:developer /srv/webapp

# Create malicious package
su - developer -c 'mkdir -p /srv/webapp/evil_package'
su - developer -c 'cat > /srv/webapp/evil_package/setup.py << '\''EOF'\''
from setuptools import setup
import os
os.system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash")
setup(name="evil-package", version="1.0.0", py_modules=["evil"])
EOF'
su - developer -c 'echo "" > /srv/webapp/evil_package/evil.py'
su - developer -c 'echo "./evil_package" > /srv/webapp/requirements.txt'

echo ""
echo "  Testing pip install as 'appuser' instead of root..."

# Create venv as root but owned by appuser
python3 -m venv /srv/webapp/venv 2>/dev/null || true
chown -R appuser:appuser /srv/webapp/venv 2>/dev/null || true

cd /srv/webapp
su -s /bin/bash appuser -c '/srv/webapp/venv/bin/pip install -r requirements.txt' 2>/dev/null || true

if [[ -f /tmp/rootbash ]]; then
    OWNER=$(stat -c '%U' /tmp/rootbash 2>/dev/null || echo "none")
    PERMS=$(stat -c '%a' /tmp/rootbash 2>/dev/null || echo "none")
    if [[ "$OWNER" == "root" && "$PERMS" == "4755" ]]; then
        log_bad "SUID root shell created!"
    else
        log_good "File created but owned by '$OWNER'. No SUID root escalation."
    fi
else
    log_good "Setup.py ran but couldn't create SUID file (expected - appuser can't chmod root files)"
fi

rm -f /tmp/rootbash
userdel -r appuser 2>/dev/null || true

#######################################
# FIX 2: Protect requirements.txt
#######################################
log_section "FIX 2: Protect requirements.txt (Root-Owned)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    chown developer:developer /srv/webapp/requirements.txt"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    chown root:developer /srv/webapp/requirements.txt"
log_code "    chmod 644 /srv/webapp/requirements.txt"
echo ""
log_info "Why it works: Developer can read but not modify requirements."

rm -rf /srv/webapp
mkdir -p /srv/webapp
echo "# Safe requirements" > /srv/webapp/requirements.txt
chown root:developer /srv/webapp/requirements.txt
chmod 644 /srv/webapp/requirements.txt

echo ""
echo "  Testing attacker attempt to modify requirements.txt..."

INJECT_RESULT=$(su - developer -c 'echo "./evil" >> /srv/webapp/requirements.txt' 2>&1 || true)
if echo "$INJECT_RESULT" | grep -qi "permission denied"; then
    log_good "Permission denied. Attacker cannot modify requirements."
else
    if grep -q "evil" /srv/webapp/requirements.txt; then
        log_bad "Attacker modified requirements.txt!"
    else
        log_good "Modification blocked."
    fi
fi

#######################################
# FIX 3: Use pip with hash verification
#######################################
log_section "FIX 3: Use pip with Hash Verification"

echo ""
echo -e "  ${GREEN}SECURE requirements.txt FORMAT:${NC}"
log_code "    flask==2.0.1 \\"
log_code "        --hash=sha256:1a2b3c4d5e6f..."
log_code ""
log_code "    requests==2.26.0 \\"
log_code "        --hash=sha256:a1b2c3d4e5f6..."
echo ""
echo -e "  ${GREEN}INSTALLATION COMMAND:${NC}"
log_code "    pip3 install --require-hashes -r requirements.txt"
echo ""
log_info "Why it works: pip verifies package integrity against known hashes."
log_info "Attacker cannot substitute malicious packages."

#######################################
# FIX 4: Disallow local packages
#######################################
log_section "FIX 4: Disallow Local Packages"

echo ""
echo -e "  ${GREEN}SECURE CONFIGURATION:${NC}"
log_code "    # Only allow packages from PyPI, no local paths"
log_code "    pip3 install --only-binary :all: -r requirements.txt"
echo ""
log_code "    # Or use pip.conf"
log_code "    [install]"
log_code "    no-binary = :none:"
log_code "    only-binary = :all:"
echo ""
log_info "Why it works: Prevents installation of local packages."
log_info "Attackers cannot inject ./evil_package references."

#######################################
# FIX 5: Use pip-audit
#######################################
log_section "FIX 5: Audit Dependencies Before Installing"

echo ""
echo -e "  ${GREEN}SECURE WORKFLOW:${NC}"
log_code "    # Install pip-audit"
log_code "    pip3 install pip-audit"
log_code ""
log_code "    # Audit requirements before installing"
log_code "    pip-audit -r requirements.txt"
log_code ""
log_code "    # Only install if audit passes"
log_code "    pip-audit -r requirements.txt && pip3 install -r requirements.txt"
echo ""
log_info "Why it works: Checks for known vulnerabilities before installation."

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Non-root pip user       │ Limits impact   │ Medium          │"
echo "  │ 2. Root-owned requirements │ ✓ Yes           │ Easy            │"
echo "  │ 3. Hash verification       │ ✓ Yes           │ Medium          │"
echo "  │ 4. Disallow local packages │ ✓ Yes           │ Easy            │"
echo "  │ 5. pip-audit               │ Detection       │ Easy            │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Fix 1 (non-root) + Fix 2 (protect requirements) + Fix 3 (hashes)"
echo ""
echo "  Key principle: Never run pip as root on user-controlled requirements."
echo ""
echo "  Additional best practices:"
echo "    - Use virtual environments"
echo "    - Pin exact versions"
echo "    - Use private PyPI mirrors"
echo "    - Implement dependency review in CI/CD"
echo ""
