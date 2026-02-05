#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent logrotate injection
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
    rm -rf /etc/logrotate.d/apps 2>/dev/null || true
    rm -rf /var/log/webapp 2>/dev/null || true
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
mkdir -p /var/log/webapp
echo "Log data" > /var/log/webapp/app.log
chown -R developer:developer /var/log/webapp

#######################################
# FIX 1: Protect logrotate config directory
#######################################
log_section "FIX 1: Protect Logrotate Config Directory"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    mkdir /etc/logrotate.d/apps"
log_code "    chown root:developer /etc/logrotate.d/apps"
log_code "    chmod 775 /etc/logrotate.d/apps"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    mkdir /etc/logrotate.d/apps"
log_code "    chown root:root /etc/logrotate.d/apps"
log_code "    chmod 755 /etc/logrotate.d/apps"
echo ""
log_info "Why it works: Users cannot write to the config directory."

# Demonstrate
mkdir -p /etc/logrotate.d/apps
chown root:root /etc/logrotate.d/apps
chmod 755 /etc/logrotate.d/apps

echo ""
echo "  Testing attacker attempt to create config..."

INJECT_RESULT=$(su - developer -c 'cat > /etc/logrotate.d/apps/evil << EOF
/var/log/webapp/*.log { postrotate touch /tmp/pwned endscript }
EOF' 2>&1 || true)

if [[ -f /etc/logrotate.d/apps/evil ]]; then
    log_bad "Attacker created config file!"
else
    log_good "Permission denied. Attacker cannot create config."
fi

rm -f /etc/logrotate.d/apps/evil 2>/dev/null || true

#######################################
# FIX 2: Remove postrotate from user configs
#######################################
log_section "FIX 2: Centralize postrotate Scripts"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    # Let users define their own postrotate"
log_code "    /var/log/webapp/*.log {"
log_code "        postrotate"
log_code "            user-controlled-script"
log_code "        endscript"
log_code "    }"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    # Central postrotate in root-owned config"
log_code "    /var/log/webapp/*.log {"
log_code "        # No user-defined postrotate"
log_code "        sharedscripts"
log_code "        postrotate"
log_code "            /usr/local/bin/log-notify.sh  # Root-controlled"
log_code "        endscript"
log_code "    }"
echo ""
log_info "Why it works: All postrotate scripts are root-owned and controlled."

#######################################
# FIX 3: Validate config ownership
#######################################
log_section "FIX 3: Validate Config Ownership Before Execution"

echo ""
echo -e "  ${GREEN}PRE-EXECUTION CHECK:${NC}"
log_code '    # In wrapper script, check config ownership'
log_code '    for config in /etc/logrotate.d/apps/*; do'
log_code '        owner=$(stat -c %U "$config")'
log_code '        if [[ "$owner" != "root" ]]; then'
log_code '            echo "ALERT: Non-root config: $config"'
log_code '            exit 1'
log_code '        fi'
log_code '    done'
log_code '    logrotate /etc/logrotate.d/apps/*'
echo ""
log_info "Why it works: Refuses to process configs not owned by root."

# Demonstrate
mkdir -p /etc/logrotate.d/apps
chmod 777 /etc/logrotate.d/apps

# Create user-owned config
su - developer -c 'echo "test" > /etc/logrotate.d/apps/evil' 2>/dev/null || true
touch /etc/logrotate.d/apps/evil
chown developer /etc/logrotate.d/apps/evil 2>/dev/null || true

echo ""
echo "  Testing ownership validation..."

NON_ROOT=$(find /etc/logrotate.d/apps -not -user root 2>/dev/null)
if [[ -n "$NON_ROOT" ]]; then
    log_good "Validation detected non-root configs:"
    echo "$NON_ROOT" | while read f; do
        log_info "  Rejected: $f (owner: $(stat -c %U "$f" 2>/dev/null || echo unknown))"
    done
fi

rm -rf /etc/logrotate.d/apps

#######################################
# FIX 4: Use include directive carefully
#######################################
log_section "FIX 4: Avoid include Directive on Writable Dirs"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    # In /etc/logrotate.conf"
log_code "    include /etc/logrotate.d/apps"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    # Only include root-controlled directories"
log_code "    include /etc/logrotate.d"
log_code "    # Don't include user-writable directories"
echo ""
log_info "Why it works: logrotate only processes root-controlled configs."

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Protect config dir      │ ✓ Yes           │ Easy            │"
echo "  │ 2. Centralize postrotate   │ ✓ Yes           │ Medium          │"
echo "  │ 3. Validate ownership      │ ✓ Yes           │ Medium          │"
echo "  │ 4. Control include dirs    │ ✓ Yes           │ Easy            │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Fix 1 (protect dir) + Fix 2 (centralize postrotate)"
echo ""
echo "  Key principle: Never run logrotate on user-controlled configs."
echo ""
