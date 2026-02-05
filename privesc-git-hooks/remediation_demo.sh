#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent git hook privilege escalation
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

#######################################
# Check if running as root
#######################################
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

#######################################
# Cleanup from previous runs
#######################################
cleanup() {
    pkill -u developer 2>/dev/null || true
    userdel -r developer 2>/dev/null || true
    userdel -r deploy 2>/dev/null || true
    groupdel devteam 2>/dev/null || true
    rm -rf /srv/git 2>/dev/null || true
    rm -rf /var/www/webapp 2>/dev/null || true
    rm -f /usr/local/bin/deploy-webapp.sh 2>/dev/null || true
    rm -f /etc/cron.d/deploy-webapp 2>/dev/null || true
    rm -f /tmp/rootbash /tmp/pwned* 2>/dev/null || true
    rm -f /var/log/deploy.log 2>/dev/null || true
}

trap cleanup EXIT
cleanup

log_header "REMEDIATION DEMONSTRATION"
echo ""
echo "  This script shows the VULNERABLE configuration vs SECURE alternatives."
echo "  Each fix is demonstrated and tested against the git hook attack."

#######################################
# Setup base environment
#######################################
setup_base() {
    groupadd devteam
    useradd -m -s /bin/bash -G devteam developer
    echo "developer:developer123" | chpasswd

    mkdir -p /srv/git/webapp.git
    cd /srv/git/webapp.git
    git init --bare --quiet

    # Initialize with content
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    git clone /srv/git/webapp.git . --quiet 2>/dev/null
    git config user.email "admin@example.com"
    git config user.name "Admin"
    echo "<html>Hello</html>" > index.html
    git add index.html
    git commit -m "Initial" --quiet
    git push origin main --quiet 2>/dev/null || git push origin master --quiet 2>/dev/null || true
    cd /
    rm -rf "$TEMP_DIR"
}

#######################################
# FIX 1: Protect hooks directory
#######################################
log_section "FIX 1: Protect Hooks Directory (Root-Owned)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    chown -R root:devteam /srv/git/webapp.git"
log_code "    chmod -R g+rwX /srv/git/webapp.git"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    # Repository group-writable EXCEPT hooks"
log_code "    chown -R root:devteam /srv/git/webapp.git"
log_code "    chmod -R g+rwX /srv/git/webapp.git"
log_code "    chown -R root:root /srv/git/webapp.git/hooks"
log_code "    chmod 755 /srv/git/webapp.git/hooks"
echo ""
log_info "Why it works: Developers can push code but not modify hooks."

setup_base

# SECURE: Protect hooks
chown -R root:devteam /srv/git/webapp.git
chmod -R g+rwX /srv/git/webapp.git
chown -R root:root /srv/git/webapp.git/hooks
chmod 755 /srv/git/webapp.git/hooks

echo ""
echo "  Testing attacker attempt to create malicious hook..."

INJECT_RESULT=$(su - developer -c 'cat > /srv/git/webapp.git/hooks/post-merge << "EOF"
#!/bin/bash
touch /tmp/pwned_fix1
EOF' 2>&1 || true)

if [[ -f /srv/git/webapp.git/hooks/post-merge ]]; then
    log_bad "Attacker was able to create hook!"
else
    log_good "Permission denied. Attacker cannot create hooks."
fi

cleanup
setup_base

#######################################
# FIX 2: Run as non-root user
#######################################
log_section "FIX 2: Run Deployment as Non-Root User"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    */5 * * * * root /usr/local/bin/deploy-webapp.sh"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    useradd -r -s /usr/sbin/nologin deploy"
log_code "    */5 * * * * deploy /usr/local/bin/deploy-webapp.sh"
echo ""
log_info "Why it works: Even if hooks execute, they run as 'deploy', not root."

# Create deploy user
useradd -r -s /usr/sbin/nologin deploy

# Make repo group-writable (vulnerable)
chown -R root:devteam /srv/git/webapp.git
chmod -R g+rwX /srv/git/webapp.git

# Create malicious hook
su - developer -c 'cat > /srv/git/webapp.git/hooks/post-checkout << '\''EOF'\''
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Executed as: $(id)" > /tmp/pwned_fix2.txt
EOF'
su - developer -c 'chmod +x /srv/git/webapp.git/hooks/post-checkout'

# Create deploy script
cat > /usr/local/bin/deploy-webapp.sh << 'SCRIPT'
#!/bin/bash
mkdir -p /var/www/webapp
if [[ -d /var/www/webapp/.git ]]; then
    cd /var/www/webapp && git pull 2>/dev/null || true
else
    git clone /srv/git/webapp.git /var/www/webapp 2>/dev/null || true
fi
SCRIPT
chmod 755 /usr/local/bin/deploy-webapp.sh

# Give deploy user permissions
mkdir -p /var/www/webapp
chown deploy:deploy /var/www/webapp

echo ""
echo "  Testing deployment run as 'deploy' user..."

su -s /bin/bash deploy -c '/usr/local/bin/deploy-webapp.sh' 2>/dev/null || true

if [[ -f /tmp/rootbash ]]; then
    OWNER=$(stat -c '%U' /tmp/rootbash)
    PERMS=$(stat -c '%a' /tmp/rootbash)
    if [[ "$OWNER" == "root" && "$PERMS" == "4755" ]]; then
        log_bad "SUID root shell created!"
    else
        log_good "File created but owned by '$OWNER', not root. No escalation."
    fi
else
    log_good "No SUID shell created. Hook ran as non-root user."
fi

if [[ -f /tmp/pwned_fix2.txt ]]; then
    log_info "Hook output: $(cat /tmp/pwned_fix2.txt)"
fi

rm -f /tmp/rootbash /tmp/pwned_fix2.txt

cleanup
setup_base

#######################################
# FIX 3: Disable hooks with git config
#######################################
log_section "FIX 3: Disable Hooks in Git Commands"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    git clone /srv/git/webapp.git /var/www/webapp"
log_code "    git pull"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    git -c core.hooksPath=/dev/null clone /srv/git/webapp.git"
log_code "    git -c core.hooksPath=/dev/null pull"
echo ""
log_info "Why it works: Hooks are disabled, even if present."

# Make repo group-writable (vulnerable)
chown -R root:devteam /srv/git/webapp.git
chmod -R g+rwX /srv/git/webapp.git

# Create malicious hook
su - developer -c 'cat > /srv/git/webapp.git/hooks/post-checkout << '\''EOF'\''
#!/bin/bash
touch /tmp/pwned_fix3
EOF'
su - developer -c 'chmod +x /srv/git/webapp.git/hooks/post-checkout'

echo ""
echo "  Testing clone with hooks disabled..."

mkdir -p /var/www/webapp
rm -rf /var/www/webapp/*
git -c core.hooksPath=/dev/null clone /srv/git/webapp.git /var/www/webapp 2>/dev/null

if [[ -f /tmp/pwned_fix3 ]]; then
    log_bad "Hook executed despite core.hooksPath=/dev/null"
else
    log_good "Hooks disabled. Malicious hook did NOT execute."
fi

rm -f /tmp/pwned_fix3

cleanup
setup_base

#######################################
# FIX 4: Hook integrity verification
#######################################
log_section "FIX 4: Hook Integrity Verification"

echo ""
echo -e "  ${GREEN}PRE-DEPLOYMENT CHECK:${NC}"
log_code '    # Check for unauthorized hooks before deployment'
log_code '    HOOKS=$(find /srv/git/webapp.git/hooks -type f ! -name "*.sample")'
log_code '    if [[ -n "$HOOKS" ]]; then'
log_code '        echo "ALERT: Unauthorized hooks detected!"'
log_code '        exit 1'
log_code '    fi'
echo ""
log_info "Why it works: Deployment fails if unauthorized hooks exist."

# Make repo group-writable (vulnerable)
chown -R root:devteam /srv/git/webapp.git
chmod -R g+rwX /srv/git/webapp.git

# Create malicious hook
su - developer -c 'cat > /srv/git/webapp.git/hooks/post-merge << '\''EOF'\''
#!/bin/bash
touch /tmp/pwned_fix4
EOF'
su - developer -c 'chmod +x /srv/git/webapp.git/hooks/post-merge'

echo ""
echo "  Testing integrity check..."

HOOKS=$(find /srv/git/webapp.git/hooks -type f ! -name "*.sample" 2>/dev/null)
if [[ -n "$HOOKS" ]]; then
    log_good "Check detected unauthorized hooks:"
    echo "$HOOKS" | while read hook; do
        log_info "  Found: $hook"
    done
    log_info "Deployment would be aborted."
else
    log_bad "Check failed to detect hooks"
fi

cleanup

#######################################
# COMPLETE SECURE IMPLEMENTATION
#######################################
log_section "COMPLETE SECURE IMPLEMENTATION"

echo ""
echo "  Here's what the DevOps team SHOULD have deployed:"
echo ""

cat << 'SECURE_SCRIPT'
  ┌────────────────────────────────────────────────────────────┐
  │ /usr/local/bin/deploy-webapp-SECURE.sh                     │
  ├────────────────────────────────────────────────────────────┤
  │ #!/bin/bash                                                │
  │ REPO="/srv/git/webapp.git"                                 │
  │ DEPLOY_DIR="/var/www/webapp"                               │
  │                                                            │
  │ # FIX 4: Check for unauthorized hooks                      │
  │ if find "$REPO/hooks" -type f ! -name "*.sample" | grep .; │
  │ then                                                       │
  │     echo "ALERT: Unauthorized hooks!" && exit 1            │
  │ fi                                                         │
  │                                                            │
  │ # FIX 3: Disable hooks in git commands                     │
  │ if [[ -d "$DEPLOY_DIR/.git" ]]; then                       │
  │     cd "$DEPLOY_DIR"                                       │
  │     git -c core.hooksPath=/dev/null pull                   │
  │ else                                                       │
  │     git -c core.hooksPath=/dev/null clone "$REPO" "$DIR"   │
  │ fi                                                         │
  └────────────────────────────────────────────────────────────┘
SECURE_SCRIPT

echo ""
cat << 'SECURE_PERMS'
  ┌────────────────────────────────────────────────────────────┐
  │ Repository Permissions                                     │
  ├────────────────────────────────────────────────────────────┤
  │ # FIX 1: Developers can push, but not modify hooks         │
  │ chown -R root:devteam /srv/git/webapp.git                  │
  │ chmod -R g+rwX /srv/git/webapp.git                         │
  │ chown -R root:root /srv/git/webapp.git/hooks               │
  │ chmod 755 /srv/git/webapp.git/hooks                        │
  └────────────────────────────────────────────────────────────┘
SECURE_PERMS

echo ""
cat << 'SECURE_CRON'
  ┌────────────────────────────────────────────────────────────┐
  │ /etc/cron.d/deploy-webapp-SECURE                           │
  ├────────────────────────────────────────────────────────────┤
  │ # FIX 2: Run as dedicated deploy user, not root            │
  │ */5 * * * * deploy /usr/local/bin/deploy-webapp.sh         │
  └────────────────────────────────────────────────────────────┘
SECURE_CRON

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Root-owned hooks dir    │ ✓ Yes           │ Easy            │"
echo "  │ 2. Non-root deploy user    │ Limits impact   │ Medium          │"
echo "  │ 3. core.hooksPath=/dev/null│ ✓ Yes           │ Easy            │"
echo "  │ 4. Hook integrity check    │ ✓ Yes           │ Medium          │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Combine Fix 1 + Fix 2 + Fix 3"
echo ""
echo "  Defense in depth:"
echo "    - Prevent hook creation: Root-owned hooks directory"
echo "    - Disable hook execution: core.hooksPath=/dev/null"
echo "    - Limit impact: Run as non-root user"
echo ""
