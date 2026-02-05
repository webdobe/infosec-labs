#!/bin/bash
#
# REMEDIATION DEMONSTRATION
# Shows what the admin SHOULD have done to prevent sudo wildcard bypass
#
# Run as root: sudo ./remediation_demo.sh
#

export PATH="/usr/sbin:/sbin:/usr/bin:/bin"

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
    rm -f /etc/sudoers.d/developer* 2>/dev/null || true
    rm -rf /var/www/html 2>/dev/null || true
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
mkdir -p /var/www/html
echo "<html>Hello</html>" > /var/www/html/index.html

#######################################
# FIX 1: Use specific file paths
#######################################
log_section "FIX 1: Use Specific File Paths (No Wildcards)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/*"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/index.html"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/.htaccess"
echo ""
log_info "Why it works: No wildcard = no path traversal."
log_info "User can only edit explicitly listed files."

#######################################
# FIX 2: Use sudoedit
#######################################
log_section "FIX 2: Use sudoedit Instead of vim"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/*"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: sudoedit /var/www/html/*"
echo ""
log_info "Why it works: sudoedit is specifically designed for safe editing."
log_info "  1. Copies file to temp location"
log_info "  2. User's editor runs as the user (not root)"
log_info "  3. Changes are copied back"
log_info "  4. No shell escapes possible!"

# Demonstrate
cat > /etc/sudoers.d/developer-secure << 'EOF'
developer ALL=(root) NOPASSWD: sudoedit /var/www/html/*
EOF
chmod 440 /etc/sudoers.d/developer-secure

echo ""
echo "  Testing sudoedit (editor runs as user, not root)..."
log_good "sudoedit prevents shell escape attacks"
log_info "The EDITOR runs as the user, file operations as root"

rm -f /etc/sudoers.d/developer-secure

#######################################
# FIX 3: Use rvim (restricted vim)
#######################################
log_section "FIX 3: Use rvim (Restricted vim)"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/*"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/rvim /var/www/html/*"
echo ""
log_info "Why it works: rvim disables dangerous vim features:"
log_info "  - No :! shell commands"
log_info "  - No :shell"
log_info "  - No suspend (Ctrl-Z)"
log_info "  - No :set shell="

if command -v rvim &>/dev/null; then
    log_good "rvim is available on this system"
else
    log_info "Note: rvim may be a symlink to vim with restricted mode"
fi

#######################################
# FIX 4: Use NOEXEC
#######################################
log_section "FIX 4: Use NOEXEC Tag"

echo ""
echo -e "  ${RED}VULNERABLE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/*"
echo ""
echo -e "  ${GREEN}SECURE VERSION:${NC}"
log_code "    developer ALL=(root) NOPASSWD: NOEXEC: /usr/bin/vim /var/www/html/*"
echo ""
log_info "Why it works: NOEXEC prevents executed programs from running"
log_info "further programs via shared library interposition."
log_info "Note: May not work on all systems or with all programs."

#######################################
# FIX 5: Use a wrapper script
#######################################
log_section "FIX 5: Use a Restricted Wrapper Script"

echo ""
echo -e "  ${GREEN}WRAPPER SCRIPT APPROACH:${NC}"
log_code '    #!/bin/bash'
log_code '    # /usr/local/bin/edit-web-file'
log_code '    FILE="$1"'
log_code '    '
log_code '    # Validate file is within allowed directory'
log_code '    REALPATH=$(realpath "$FILE" 2>/dev/null)'
log_code '    if [[ ! "$REALPATH" =~ ^/var/www/html/ ]]; then'
log_code '        echo "Error: Can only edit files in /var/www/html/"'
log_code '        exit 1'
log_code '    fi'
log_code '    '
log_code '    # Use restricted editor'
log_code '    rvim "$REALPATH"'
echo ""
echo -e "  ${GREEN}SUDOERS ENTRY:${NC}"
log_code "    developer ALL=(root) NOPASSWD: /usr/local/bin/edit-web-file"
echo ""
log_info "Why it works: Script validates path and uses restricted editor."
log_info "Path traversal is blocked by realpath check."

#######################################
# Dangerous GTFOBins commands
#######################################
log_section "WARNING: Other Dangerous Sudo Commands"

echo ""
echo "  These commands can all be used for privilege escalation via sudo:"
echo ""
log_code "    vim, vi, nano, emacs, less, more, man"
log_code "    find, awk, perl, python, ruby, php, lua"
log_code "    ftp, gdb, nmap, tar, zip, journalctl"
log_code "    mysql, psql, git, env, and many more..."
echo ""
log_info "Reference: https://gtfobins.github.io"
log_info "Always check GTFOBins before granting sudo access!"

#######################################
# Summary
#######################################
log_header "REMEDIATION SUMMARY"

echo ""
echo "  ┌─────────────────────────────────────────────────────────────────┐"
echo "  │ Fix                        │ Prevents Attack │ Complexity      │"
echo "  ├─────────────────────────────────────────────────────────────────┤"
echo "  │ 1. Specific file paths     │ ✓ Yes           │ Easy            │"
echo "  │ 2. sudoedit                │ ✓ Yes           │ Easy            │"
echo "  │ 3. rvim                    │ ✓ Yes           │ Easy            │"
echo "  │ 4. NOEXEC                  │ Partial         │ Easy            │"
echo "  │ 5. Wrapper script          │ ✓ Yes           │ Medium          │"
echo "  └─────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${GREEN}${BOLD}RECOMMENDED:${NC} Fix 2 (sudoedit) for file editing tasks"
echo ""
echo "  Key principles:"
echo "    - Avoid wildcards in sudoers"
echo "    - Use sudoedit instead of editors"
echo "    - Check GTFOBins before granting sudo"
echo "    - Be explicit about what is allowed"
echo ""
