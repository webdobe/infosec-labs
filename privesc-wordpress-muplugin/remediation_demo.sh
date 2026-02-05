#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent WordPress mu-plugin privilege escalation
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
    rm -rf /var/www/html 2>/dev/null || true
    rm -f /usr/local/bin/wp-maintenance*.sh 2>/dev/null || true
    rm -f /etc/cron.d/wp-maintenance* 2>/dev/null || true
    rm -f /tmp/rootbash /tmp/pwned* /tmp/.wp-* 2>/dev/null || true
    rm -f /var/log/wp-maintenance.log 2>/dev/null || true
    userdel -r wpmaint 2>/dev/null || true
}

trap cleanup EXIT
cleanup

log_header "REMEDIATION DEMONSTRATION"
echo ""
echo "  This script shows the VULNERABLE configuration vs SECURE alternatives."
echo "  Each fix is demonstrated and tested against the mu-plugin injection attack."

# Ensure www-data exists
id www-data &>/dev/null || useradd -r -s /usr/sbin/nologin www-data

#######################################
# FIX 1: Run maintenance as www-data
#######################################
log_section "FIX 1: Run Maintenance as www-data (Not Root)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    */5 * * * * root /usr/local/bin/wp-maintenance.sh"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    */5 * * * * www-data /usr/local/bin/wp-maintenance.sh"
echo ""
log_info "Why it works: Even if attacker injects code, it runs as www-data."
log_info "No privilege escalation possible — same user, same privileges."

# Setup
mkdir -p /var/www/html/wp-content/mu-plugins
chown -R www-data:www-data /var/www/html

# Create maintenance script
cat > /usr/local/bin/wp-maintenance.sh << 'SCRIPT'
#!/bin/bash
for plugin in /var/www/html/wp-content/mu-plugins/*.php; do
    [[ -f "$plugin" ]] && php "$plugin" 2>/dev/null
done
SCRIPT
chmod 755 /usr/local/bin/wp-maintenance.sh

# Create attacker payload
su -s /bin/bash www-data -c 'cat > /var/www/html/wp-content/mu-plugins/evil.php << '\''EOF'\''
<?php
copy("/bin/bash", "/tmp/rootbash");
chmod("/tmp/rootbash", 04755);
file_put_contents("/tmp/pwned_fix1.txt", "Executed");
EOF'

echo ""
echo "  Testing maintenance run as www-data (not root)..."

# Run as www-data
su -s /bin/bash www-data -c '/usr/local/bin/wp-maintenance.sh' 2>/dev/null || true

if [[ -f /tmp/rootbash ]]; then
    OWNER=$(stat -c '%U' /tmp/rootbash 2>/dev/null || echo "none")
    PERMS=$(stat -c '%a' /tmp/rootbash 2>/dev/null || echo "none")
    if [[ "$OWNER" == "root" && "$PERMS" == "4755" ]]; then
        log_bad "SUID root shell created!"
    else
        log_good "File created but NOT SUID root (owner: $OWNER, perms: $PERMS)"
        log_info "Code executed but as www-data, not root. No escalation."
    fi
else
    log_good "Payload executed but couldn't create SUID file (expected)."
fi

rm -f /tmp/rootbash /tmp/pwned_fix1.txt
rm -rf /var/www/html

#######################################
# FIX 2: Protect mu-plugins directory
#######################################
log_section "FIX 2: Protect mu-plugins Directory (Root-Owned)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    chown www-data:www-data /var/www/html/wp-content/mu-plugins"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    chown root:root /var/www/html/wp-content/mu-plugins"
log_code "    chmod 755 /var/www/html/wp-content/mu-plugins"
echo ""
log_info "Why it works: www-data cannot write to mu-plugins directory."
log_info "Only root can deploy mu-plugins, so injection is impossible."

# Setup with secure permissions
mkdir -p /var/www/html/wp-content/mu-plugins
mkdir -p /var/www/html/wp-content/plugins
chown -R www-data:www-data /var/www/html
# SECURE: Make mu-plugins owned by root
chown root:root /var/www/html/wp-content/mu-plugins
chmod 755 /var/www/html/wp-content/mu-plugins

echo ""
echo "  Testing attacker attempt to create mu-plugin..."

# Attacker tries to create mu-plugin
INJECT_RESULT=$(su -s /bin/bash www-data -c 'cat > /var/www/html/wp-content/mu-plugins/evil.php << "EOF"
<?php system("id");
EOF' 2>&1 || true)

if [[ -f /var/www/html/wp-content/mu-plugins/evil.php ]]; then
    log_bad "Attacker was able to create mu-plugin!"
else
    log_good "Permission denied. Attacker cannot create mu-plugins."
fi

rm -rf /var/www/html

#######################################
# FIX 3: Dedicated maintenance user
#######################################
log_section "FIX 3: Dedicated Non-Root Maintenance User"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    */5 * * * * root /usr/local/bin/wp-maintenance.sh"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    useradd -r -s /usr/sbin/nologin wpmaint"
log_code "    */5 * * * * wpmaint /usr/local/bin/wp-maintenance.sh"
echo ""
log_info "Why it works: Maintenance runs as 'wpmaint', a low-privilege user."
log_info "Even with code execution, attacker only gets wpmaint privileges."

# Create dedicated user
useradd -r -s /usr/sbin/nologin wpmaint

# Setup
mkdir -p /var/www/html/wp-content/mu-plugins
chown -R www-data:www-data /var/www/html

# Create attacker payload
su -s /bin/bash www-data -c 'cat > /var/www/html/wp-content/mu-plugins/evil.php << '\''EOF'\''
<?php
copy("/bin/bash", "/tmp/rootbash");
chmod("/tmp/rootbash", 04755);
file_put_contents("/tmp/pwned_fix3.txt", posix_getuid() . ":" . posix_geteuid());
EOF'

echo ""
echo "  Testing maintenance run as 'wpmaint' user..."

# Run as wpmaint
su -s /bin/bash wpmaint -c '/usr/local/bin/wp-maintenance.sh' 2>/dev/null || true

if [[ -f /tmp/pwned_fix3.txt ]]; then
    UID_INFO=$(cat /tmp/pwned_fix3.txt)
    log_good "Code executed as UID $UID_INFO (not root:0)"
    if [[ -f /tmp/rootbash ]]; then
        OWNER=$(stat -c '%U' /tmp/rootbash)
        log_good "rootbash created but owned by $OWNER, not root"
    fi
else
    log_good "Execution as wpmaint doesn't grant root privileges."
fi

rm -f /tmp/rootbash /tmp/pwned_fix3.txt
rm -rf /var/www/html
userdel -r wpmaint 2>/dev/null || true

#######################################
# FIX 4: File integrity monitoring
#######################################
log_section "FIX 4: File Integrity Monitoring"

echo ""
echo -e "  ${GREEN}MONITORING APPROACH:${NC}"
log_code "    # Using inotifywait to detect mu-plugin changes"
log_code "    inotifywait -m -e create,modify /var/www/html/wp-content/mu-plugins/"
echo ""
log_code "    # Using AIDE (Advanced Intrusion Detection Environment)"
log_code "    /var/www/html/wp-content/mu-plugins CONTENT_EX"
echo ""
log_code "    # Using auditd"
log_code "    auditctl -w /var/www/html/wp-content/mu-plugins -p wa -k wp_muplugin"
echo ""
log_info "Why it works: Doesn't prevent attack but enables rapid detection."
log_info "Security team alerted when unauthorized mu-plugin is created."

#######################################
# FIX 5: PHP disable_functions
#######################################
log_section "FIX 5: PHP Hardening (disable_functions)"

echo ""
echo -e "  ${GREEN}PHP.INI CONFIGURATION:${NC}"
log_code "    disable_functions = exec,passthru,shell_exec,system,proc_open,popen"
log_code "    disable_functions += pcntl_exec,chmod,chown,posix_setuid"
echo ""
log_info "Why it works: Even if attacker injects PHP, dangerous functions are disabled."
log_info "Cannot execute system commands or change file permissions."
log_info "Note: May break legitimate WordPress functionality. Test thoroughly."

#######################################
# COMPLETE SECURE IMPLEMENTATION
#######################################
log_section "COMPLETE SECURE IMPLEMENTATION"

echo ""
echo "  Here's what the admin SHOULD have deployed:"
echo ""

cat << 'SECURE_PERMS'
  ┌────────────────────────────────────────────────────────────┐
  │ Directory Permissions                                      │
  ├────────────────────────────────────────────────────────────┤
  │ # Regular WordPress directories (www-data writable)        │
  │ chown -R www-data:www-data /var/www/html                   │
  │                                                            │
  │ # SECURE: mu-plugins owned by root only                    │
  │ chown root:root /var/www/html/wp-content/mu-plugins        │
  │ chmod 755 /var/www/html/wp-content/mu-plugins              │
  └────────────────────────────────────────────────────────────┘
SECURE_PERMS

echo ""
cat << 'SECURE_CRON'
  ┌────────────────────────────────────────────────────────────┐
  │ /etc/cron.d/wp-maintenance-SECURE                          │
  ├────────────────────────────────────────────────────────────┤
  │ # SECURE: Run as www-data, not root                        │
  │ */5 * * * * www-data /usr/local/bin/wp-maintenance.sh      │
  └────────────────────────────────────────────────────────────┘
SECURE_CRON

echo ""
cat << 'SECURE_AUDIT'
  ┌────────────────────────────────────────────────────────────┐
  │ Audit Rules (/etc/audit/rules.d/wordpress.rules)           │
  ├────────────────────────────────────────────────────────────┤
  │ # Alert on mu-plugin directory changes                     │
  │ -w /var/www/html/wp-content/mu-plugins -p wa -k wp_muplugin│
  │                                                            │
  │ # Alert on wp-config.php changes                           │
  │ -w /var/www/html/wp-config.php -p wa -k wp_config          │
  └────────────────────────────────────────────────────────────┘
SECURE_AUDIT

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Run as www-data         │ Limits impact   │ Easy            │"
echo "  │ 2. Root-owned mu-plugins   │ ✓ Yes           │ Easy            │"
echo "  │ 3. Dedicated maint user    │ Limits impact   │ Medium          │"
echo "  │ 4. File integrity monitor  │ Detection only  │ Medium          │"
echo "  │ 5. PHP disable_functions   │ Limits impact   │ Medium-Hard     │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Combine Fix 2 (root-owned mu-plugins) + Fix 1 (run as www-data)"
echo ""
echo "  Defense in depth:"
echo "    - Prevent injection: Make mu-plugins root-owned"
echo "    - Limit impact: Run maintenance as www-data"
echo "    - Detect attacks: Monitor for file changes"
echo ""
